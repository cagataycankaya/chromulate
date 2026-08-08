//! The middleware that notices a challenge and hands it to a browser.
//!
//! [`crate::challenge`] is the vocabulary — an observation type, two traits, a
//! policy. This is the one thing in the workspace that speaks it: it builds an
//! [`Observation`] from a finished response, asks the installed
//! [`ChallengeDetector`] what it is, and, when the answer is a challenge, hands
//! the target to the installed [`BrowserFallback`] and re-runs the request with
//! whatever that browser earned.
//!
//! # Where it runs, and why that is enough
//!
//! A [`Middleware`], in the ordinary chain. Middleware runs *outside* the
//! redirect loop (`chromulate-core/src/traits.rs:149-150`), so the layer sees one
//! logical request and reads the hops it took from [`ResponseInfo::hops`] rather
//! than watching them go by. [`Next`] is [`Copy`], which is what makes re-running
//! the whole chain after clearance expressible without new machinery — that
//! `Copy` exists for exactly this shape of middleware and says so in its own
//! documentation.
//!
//! # The five bounds, and what each one is for
//!
//! They are easy to mistake for one another, so:
//!
//! - [`HandoffPolicy::is_eligible`] decides whether a request should ever become
//!   a browser launch. A challenged stylesheet is not a page a browser can
//!   usefully be pointed at.
//! - [`HandoffPolicy::budget`] over [`HandoffPolicy::window`] bounds how many
//!   browsers one *origin* is worth. This is the loop guard: an origin that
//!   challenges whatever you do gets a fixed number of attempts and then its
//!   challenge response is returned to the caller.
//! - Single flight collapses concurrent solves for one *target and identity*, so
//!   ten tasks racing at one challenged URL launch one browser. The shape is
//!   `chromulate-dns`'s, which collapses concurrent lookups for one host and
//!   proves it with a counting resolver; the failure it prevents is the same one.
//! - [`HandoffPolicy::concurrency`] bounds browsers alive at once across
//!   everything. Nothing else does: single flight collapses one target, the
//!   budget bounds one origin, and a crawl over a thousand origins passes both
//!   while starting a thousand browsers.
//! - [`ChallengeHandoff::with_solve_budget`] bounds how long one solve may take,
//!   and is the only bound the layer applies to code it does not own. The others
//!   decide whether to call a fallback; this one decides how long to wait for it.
//!
//! # What this cannot do on its own
//!
//! A `Middleware` is *owned* by the engine that runs it, so it cannot hold the
//! engine back without a reference cycle, and the only doors to the route a
//! response taught are [`Engine::with_session`] and [`Engine::seed_session`]. The
//! layer therefore takes a [`SessionAccess`] the caller wires after the engine
//! exists — see [`ChallengeHandoff::attach_sessions`], which documents the
//! two-line wiring and why a strong handle there would leak the engine. Without
//! it the layer still detects, still hands off, and still returns a page the
//! browser fetched; what it cannot do is *keep* what the browser earned.
//!
//! There are two doors and the layer uses both, which is a distinction rather
//! than a redundancy: [`Engine::with_session`] reads and never mints, so a lookup
//! for an exit that holds nothing changes nothing; [`Engine::seed_session`] mints,
//! and minting runs the `max_routes` eviction. Reading through the minting one
//! would let a stale label discard a live exit's cookies, and writing through the
//! reading one would silently drop a clearance whenever the route had been
//! evicted since the challenge. [`SessionAccess`]'s two methods say which each
//! uses and why.
//!
//! The second thing it cannot do is make the retry leave through the exit the
//! clearance was earned on, which matters to anyone running a rotating proxy
//! pool and is written out in full on
//! [`ChallengeHandoff`](ChallengeHandoff#known-limitation-the-retry-is-not-pinned-to-the-exit-that-earned-the-clearance).
//!
//! [`Observation`]: crate::challenge::Observation
//! [`ResponseInfo::hops`]: crate::ResponseInfo::hops

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use chromulate_core::{
    Body, BoxFuture, CookieContext, Middleware, Next, Origin, Request, Response, Result,
};
use chromulate_profile::Profile;
use futures_util::future::{Shared, WeakShared};
use futures_util::{FutureExt as _, StreamExt as _};
use http::header::{CONTENT_LENGTH, USER_AGENT};
use http::{HeaderValue, Uri};
use http_body_util::BodyExt as _;
use tokio::sync::Semaphore;
use url::Url;

use crate::challenge::{
    BrowserFallback, ChallengeDetector, Content, DeclineReason, Detection, Handback, Handoff,
    HandoffPolicy, Hop, Observation, ProxyExit,
};
use crate::middleware::middleware_error;
use crate::{Engine, ResponseInfo};

/// The name this middleware reports, in logs and in [`Error::Middleware`].
const NAME: &str = "challenge";

/// Called with the URL of an origin that was challenging and has stopped.
///
/// # This is required wiring, not a hook
///
/// A Cloudflare managed challenge answers `403`.
/// `AdaptiveConcurrency` reads a `403` as `Signal::Refused`, sets a sticky
/// `refused` flag, and its condition 7 then blocks every future ramp for that
/// origin — permanently, and including after the challenge has been cleared
/// (`chromulate-concurrency/src/adaptive.rs:330, 808-809, 887-888`). Throughput
/// against a site you have just gained access to quietly never recovers, and
/// nothing in a log says why.
///
/// Teaching the controller "that `403` was a challenge" is not the fix: it would
/// put one law's reading into [`Outcome`](crate::concurrency::Outcome), which
/// carries observations and never verdicts. The fix is that the caller holds both
/// objects — the controller goes in through `ClientBuilder::concurrency`, this
/// layer through `ClientBuilder::middleware` — and can join them with a closure.
/// `AdaptiveConcurrency::forget` is the documented escape hatch and the `403`
/// freeze is deliberately not configurable (`adaptive.rs:71-74`).
///
/// So, with both installed, wire this:
///
/// ```text
/// use std::sync::Arc;
/// use chromulate_concurrency::AdaptiveConcurrency;
/// use chromulate_http::authority_of;
/// use chromulate_http::middleware::{ChallengeHandoff, Cleared};
///
/// let controller = Arc::new(AdaptiveConcurrency::new());
/// let cleared: Cleared = {
///     let controller = Arc::clone(&controller);
///     Arc::new(move |url: &url::Url| {
///         // `forget` takes the same authority key the controller was taught by.
///         controller.forget(authority_of(url));
///     })
/// };
/// let layer = ChallengeHandoff::new(profile, detector)
///     .with_fallback(browser)
///     .on_cleared(cleared);
/// ```
///
/// The block above is `text` rather than a doctest because `chromulate-http` does
/// not depend on `chromulate-concurrency` — the seam lives here and the laws live
/// there, which is the whole point of the split. [`authority_of`] is in this
/// crate, so the key is not something a caller has to reconstruct.
///
/// # When it fires
///
/// Only after a handoff produced session state, that state was applied, and the
/// re-run came back with the detector no longer calling it a challenge. Not on a
/// [`Handback::Content`]: there the browser fetched a page and Chromulate learned
/// nothing, so the origin is still refusing *this* client and un-freezing it would
/// ramp against a wall.
///
/// [`authority_of`]: crate::authority_of
pub type Cleared = Arc<dyn Fn(&Url) + Send + Sync>;

/// Reaches the server-taught state of one route, on the middleware's behalf.
///
/// # Why this exists rather than the layer just calling the engine
///
/// The state a handback belongs in is one route's [`RouteSession`], reached
/// through [`Engine::with_session`] and [`Engine::seed_session`] — and a
/// `Middleware` cannot reach the engine that owns it. `EngineInner` holds
/// `Vec<Arc<dyn Middleware>>`, so a layer holding an [`Engine`] closes a cycle
/// through the engine's own middleware list and neither is ever dropped. The
/// construction order forbids it too: the builder wants the middleware before the
/// engine exists.
///
/// So the layer takes this, and the shipped implementation is on
/// [`Weak<Engine>`] — the one handle that reaches the engine without keeping it
/// alive. There is deliberately **no** implementation for `Engine` itself: it
/// would compile, work in a test, and leak in production.
///
/// # Two methods, two engine doors, and the reason they are not the same door
///
/// [`SessionAccess::cookie_header`] reads and goes through
/// [`Engine::with_session`], which never mints: an exit that holds nothing has
/// nothing to hand a browser, and creating a session to discover that would run
/// the `max_routes` eviction and could discard a live exit's cookies to answer a
/// question. [`SessionAccess::store_cookies`] writes and goes through
/// [`Engine::seed_session`], which does mint: a response came back through this
/// exit, so dropping the clearance because the route was evicted in between would
/// waste a browser run for nothing the retry will not pay for anyway.
///
/// The distinction is load-bearing rather than stylistic. `store_cookies` is a
/// bare statement, so routing it through the reading door would have compiled
/// unchanged and silently stopped working on exactly the evicted-route case —
/// the closure simply never runs. `Engine::with_session`'s `#[must_use]` is what
/// turns that into a build break instead of a behaviour change.
///
/// # Why cookie-shaped
///
/// Because [`RouteSession`] has one accessor today. When it grows a second — a
/// client-hint grant, a validator — this trait grows a method beside these two
/// rather than a second import path being invented next to the first.
///
/// [`RouteSession`]: crate::RouteSession
pub trait SessionAccess: Send + Sync + 'static {
    /// The `Cookie` header the route keyed by `exit` would send for `url`.
    ///
    /// Travels outbound in [`Handoff::cookies`] so the browser starts where
    /// Chromulate stopped. `None` is a valid answer and means "start from
    /// nothing".
    fn cookie_header(&self, exit: Option<&Arc<str>>, url: &Url) -> Option<HeaderValue>;

    /// Records `Set-Cookie` lines against the route keyed by `exit`.
    ///
    /// `exit` is [`ResponseInfo::exit`], handed back unchanged. That is what makes
    /// `CLAUDE.md`'s rule — *server-taught state is keyed by the proxy exit it was
    /// taught through* — hold by construction: a clearance cookie is
    /// server-taught state of exactly that kind, and putting it in another
    /// route's jar tells the origin that two exits are one client.
    fn store_cookies(&self, exit: Option<&Arc<str>>, url: &Url, set_cookie: &[HeaderValue]);
}

impl fmt::Debug for dyn SessionAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionAccess")
    }
}

impl SessionAccess for Weak<Engine> {
    /// Reads, and therefore uses [`Engine::with_session`], which never mints.
    ///
    /// An exit with no session filed under it has nothing to hand a browser, and
    /// creating one to discover that would run the `max_routes` eviction and
    /// could discard another exit's cookies to answer a question. `None` here and
    /// `None` there both mean "start from nothing", so the two flatten together
    /// without a branch.
    fn cookie_header(&self, exit: Option<&Arc<str>>, url: &Url) -> Option<HeaderValue> {
        let engine = self.upgrade()?;
        engine
            .with_session(exit, |session| {
                // `conservative_default` is the context a browser typing this URL
                // into an address bar produces for everything except
                // `SameSite=Strict`, which it withholds. Withholding is the right
                // way to be wrong here: a cookie the browser does not receive
                // costs a login, and one it receives and should not have is state
                // handed to a process this crate does not control.
                session.cookies().and_then(|cookies| {
                    cookies.cookies_for(url, &CookieContext::conservative_default())
                })
            })
            .flatten()
    }

    /// Writes, and therefore uses [`Engine::seed_session`], which mints.
    ///
    /// The opposite call from the read above, and deliberately. A response came
    /// back through this exit, so the route existed a moment ago; if it has been
    /// evicted since, the retry about to go out through it will mint it again
    /// anyway, and dropping the clearance on the floor would mean the browser ran
    /// for nothing. Minting can evict another exit's session — that is the
    /// documented cost of a bounded store, and it is a cost the retry was going
    /// to pay regardless.
    fn store_cookies(&self, exit: Option<&Arc<str>>, url: &Url, set_cookie: &[HeaderValue]) {
        let Some(engine) = self.upgrade() else {
            return;
        };
        engine.seed_session(exit, |session| {
            if let Some(cookies) = session.cookies() {
                cookies.store(url, &mut set_cookie.iter());
            }
        });
    }
}

/// Marks a response that a fallback fetched, rather than this engine.
///
/// Present on exactly the responses built from [`Handback::Content`]. Those carry
/// **no** [`ResponseInfo`], and the absence is deliberate: `ResponseInfo` reports
/// what the engine observed while producing a response, and the engine produced
/// none of this one. Synthesising timings for an exchange that happened in another
/// process would be a number invented to fill a field, which is the one thing a
/// fidelity-shaped project must not do. The final URL the browser reached is here
/// instead.
#[derive(Debug, Clone)]
pub struct FetchedByFallback {
    fallback: &'static str,
    final_url: Url,
}

impl FetchedByFallback {
    /// The [`BrowserFallback::name`] of the fallback that fetched it.
    #[must_use]
    pub fn fallback(&self) -> &'static str {
        self.fallback
    }

    /// Where the fallback ended up, after whatever redirects it followed.
    #[must_use]
    pub fn final_url(&self) -> &Url {
        &self.final_url
    }
}

/// Detects challenges, and hands the ones it can to a browser the caller
/// installed.
///
/// Installed like any other middleware. With no fallback it is a diagnostic: a
/// challenged response comes back untouched with a
/// [`Challenge`](crate::challenge::Challenge) in its
/// extensions, which is enough to log it, alert on it, or route the origin to a
/// different worker. With a fallback it becomes the loop the vendor documents —
/// detect, clear, retry.
///
/// ```
/// use std::sync::Arc;
///
/// use chromulate_core::Origin;
/// use chromulate_http::challenge::{
///     Challenge, ChallengeDetector, ChallengeKind, Detection, Evidence, Observation,
/// };
/// use chromulate_http::middleware::ChallengeHandoff;
/// use chromulate_profile::Profile;
/// use http::HeaderValue;
///
/// /// Reads the one header Cloudflare publishes for the purpose.
/// #[derive(Debug)]
/// struct Mitigated;
///
/// impl ChallengeDetector for Mitigated {
///     fn inspect(&self, observation: &Observation<'_>) -> Detection {
///         if observation.headers().get("cf-mitigated").map(HeaderValue::as_bytes)
///             != Some(b"challenge".as_slice())
///         {
///             return Detection::Clear;
///         }
///         Detection::Challenged(Challenge::new(
///             ChallengeKind::Unknown,
///             // The layer derived this once and handed it over, so no detector
///             // has to write an error branch it can never take.
///             observation.origin().clone(),
///             Evidence::from_signal("cf-mitigated: challenge"),
///         ))
///     }
/// }
///
/// // Detection only: nothing to install, no browser anywhere.
/// let layer = ChallengeHandoff::new(
///     Arc::new(Profile::chrome_stable()),
///     Arc::new(Mitigated),
/// );
/// assert_eq!(layer.policy().budget(), 2);
/// ```
///
/// # Known limitation: the retry is not pinned to the exit that earned the clearance
///
/// **Read this before installing the layer on a client with a rotating proxy
/// pool.** A clearance is bound to the address that earned it. This layer hands
/// the fallback the right exit and files what it earns in that exit's session —
/// and then has no way to make the retry go out through it.
///
/// `Connector::route()` takes an origin and nothing else, and calls
/// [`ProxyProvider::next`](chromulate_proxy::ProxyProvider::next) once per hop.
/// No request extension overrides that. So with
/// [`RoundRobin`](chromulate_proxy::RoundRobin) — the rotating provider this
/// workspace ships — one challenged request goes:
///
/// 1. out through exit A, and is challenged;
/// 2. into a browser that correctly browses as exit A and earns a clearance for
///    A's address;
/// 3. into exit A's jar, correctly;
/// 4. **out through exit B**, which holds no clearance and is a different address
///    to the origin. Challenged again.
///
/// The browser ran, the clearance is real, and it is spent for nothing. Repeat
/// until [`HandoffPolicy::budget`] is exhausted and the caller receives the
/// challenge response having paid for a browser per attempt. The layer logs a
/// `warn` naming both exits when it sees this happen, which is the whole of what
/// it can do about it from here — and that log line is itself untested, for a
/// reason recorded at the call site.
///
/// **Where it does not bite:** any provider that hands out the same exit for
/// consecutive selections. [`Single`](chromulate_proxy::Single) — one proxy, so
/// there is nothing to rotate to — and any sticky or per-origin provider a caller
/// supplies. An unproxied client is also unaffected: there is no exit, so there
/// is nothing to change.
///
/// **Where it bites hardest:** a rotating pool under
/// [`ProxyIsolation::PerProxy`](crate::ProxyIsolation::PerProxy), which is the
/// configuration the per-exit session split exists for in the first place.
///
/// `tests/challenge_layer.rs` reproduces it against the shipped `RoundRobin` and
/// asserts the wasted work, so the limitation is a failing property held by CI
/// rather than a paragraph. The exit-isolation test in the same file has to use a
/// `PinnedExits` provider of its own to observe what the layer *does* get right —
/// and needing to replace a shipped component to see a property hold is the
/// clearest statement of the gap there is.
///
/// Closing it needs a request-pinned exit the connector honours, or a sticky
/// provider in `chromulate-proxy`. Both reach past this layer and neither is
/// decided here.
///
/// # The cost of installing one
///
/// A response passing through pays one [`Url`] clone and one detector call. A
/// request that is *eligible* for a handoff additionally pays one
/// `http::request::Parts` clone, because the replay has to be built before the
/// original is consumed by the chain — the same trade [`Retry`](super::Retry)
/// makes, for the same reason. Neither is on the engine's own path, so the
/// published allocations-per-request figure is unaffected; both are paid by the
/// caller who installed this. UNMEASURED: the allocation harness installs no
/// middleware, so there is no number here, only the count of what the code does.
pub struct ChallengeHandoff {
    profile: Arc<Profile>,
    detector: Arc<dyn ChallengeDetector>,
    fallback: Option<Arc<dyn BrowserFallback>>,
    sessions: OnceLock<Arc<dyn SessionAccess>>,
    cleared: Option<Cleared>,
    policy: HandoffPolicy,
    solve_budget: Duration,
    sniff_limit: usize,
    permits: Arc<Semaphore>,
    state: Mutex<State>,
}

/// Hand-written rather than derived, because [`Cleared`] is a boxed closure and
/// a closure has no `Debug`. Dropping the derive is not the alternative — the
/// workspace lints `missing_debug_implementations` and CI escalates it — and the
/// precedent here is `Next`'s (`chromulate-core/src/traits.rs:114-120`): print a
/// summary of what is held rather than the thing itself, and close with
/// `finish_non_exhaustive`.
///
/// The two booleans are the fields worth having. Both name wiring whose absence
/// is otherwise silent: a layer with no session access cannot keep a clearance,
/// and one with no `Cleared` callback leaves an adaptive controller frozen on the
/// challenge's `403`. An operator reading a `Debug` dump can see both without
/// reading the construction site.
impl fmt::Debug for ChallengeHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeHandoff")
            .field("detector", &self.detector)
            .field("fallback", &self.fallback)
            .field("policy", &self.policy)
            .field("solve_budget", &self.solve_budget)
            .field("sessions_attached", &self.sessions.get().is_some())
            .field("cleared_callback", &self.cleared.is_some())
            .finish_non_exhaustive()
    }
}

impl ChallengeHandoff {
    /// How long one solve may take before the fallback is expected to give up.
    ///
    /// A minute. A browser that has not cleared an interstitial in a minute is
    /// not about to, and the request behind it is being held open the whole time.
    pub const DEFAULT_SOLVE_BUDGET: Duration = Duration::from_secs(60);

    /// The most body bytes a [`Detection::Suspect`] may buy.
    ///
    /// A challenge interstitial is kilobytes. This is two orders of magnitude
    /// above that, which is enough slack for one that grows and still small
    /// enough that buffering it is not a memory event.
    pub const DEFAULT_SNIFF_LIMIT: usize = 128 * 1024;

    /// A layer that detects and does nothing else.
    ///
    /// `profile` is the one the engine was built with; its User-Agent is what a
    /// [`Handoff`] carries, and a request that sets its own `user-agent` header
    /// overrides it. Handing over a different profile than the engine runs is a
    /// wiring mistake this constructor cannot catch — see this module's note on
    /// what a `Middleware` cannot reach.
    #[must_use]
    pub fn new(profile: Arc<Profile>, detector: Arc<dyn ChallengeDetector>) -> Self {
        let policy = HandoffPolicy::default();
        Self {
            permits: Arc::new(Semaphore::new(policy.concurrency())),
            profile,
            detector,
            fallback: None,
            sessions: OnceLock::new(),
            cleared: None,
            policy,
            solve_budget: Self::DEFAULT_SOLVE_BUDGET,
            sniff_limit: Self::DEFAULT_SNIFF_LIMIT,
            state: Mutex::new(State::default()),
        }
    }

    /// Installs the browser that challenges are handed to.
    ///
    /// Without one the layer never launches anything and never replays anything.
    #[must_use]
    pub fn with_fallback(mut self, fallback: Arc<dyn BrowserFallback>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Replaces the eligibility rule and the three bounds.
    #[must_use]
    pub fn with_policy(mut self, policy: HandoffPolicy) -> Self {
        self.permits = Arc::new(Semaphore::new(policy.concurrency()));
        self.policy = policy;
        self
    }

    /// Sets how long one solve may take.
    ///
    /// Both stated and enforced. It travels in the [`Handoff`], where
    /// [`Handoff::remaining`] is the fallback's own view of it, *and* it bounds
    /// the layer's wait — because a seam can only ask, and a third-party
    /// implementation that ignores the ask would otherwise hold the caller's
    /// request open behind a browser that is not coming back. An overrun reads as
    /// [`DeclineReason::BudgetExhausted`]: the attempt happened and produced
    /// nothing.
    ///
    /// Clamped to at least a second, because a budget of zero is a handoff that
    /// expired before the fallback was called — a disabled feature wearing the
    /// costume of a configured one.
    #[must_use]
    pub fn with_solve_budget(mut self, budget: Duration) -> Self {
        self.solve_budget = budget.max(Duration::from_secs(1));
        self
    }

    /// Sets the cap on a [`Detection::Suspect`] body read. Zero is raised to one.
    #[must_use]
    pub fn with_sniff_limit(mut self, limit: usize) -> Self {
        self.sniff_limit = limit.max(1);
        self
    }

    /// Installs the callback fired when a challenged origin starts answering.
    ///
    /// Read [`Cleared`] before deciding you do not need this. With an adaptive
    /// concurrency controller installed, omitting it means throughput against a
    /// cleared origin never recovers, and the failure is silent.
    #[must_use]
    pub fn on_cleared(mut self, cleared: Cleared) -> Self {
        self.cleared = Some(cleared);
        self
    }

    /// Wires the layer to the engine's per-route session state.
    ///
    /// Takes `&self` and is called *after* the engine is built, because the
    /// engine needs the middleware before it exists and the middleware needs the
    /// engine after it does. Returns whether this call was the one that set it;
    /// a second call changes nothing and answers `false`.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use chromulate_core::{CookieStore, Middleware};
    /// # use chromulate_http::challenge::ChallengeDetector;
    /// # use chromulate_http::middleware::ChallengeHandoff;
    /// # use chromulate_http::{Engine, EngineConfig};
    /// # use chromulate_profile::Profile;
    /// # fn wire(detector: Arc<dyn ChallengeDetector>) -> Result<(), chromulate_core::Error> {
    /// let profile = Arc::new(Profile::chrome_stable());
    /// let layer = Arc::new(ChallengeHandoff::new(Arc::clone(&profile), detector));
    ///
    /// let engine = Arc::new(
    ///     Engine::builder(EngineConfig::new(profile))
    ///         .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
    ///         .build()?,
    /// );
    ///
    /// // `Arc::downgrade`, never `Arc::clone`: the engine holds the layer, so a
    /// // strong handle here is a cycle and neither is ever dropped.
    /// layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn attach_sessions(&self, access: Arc<dyn SessionAccess>) -> bool {
        self.sessions.set(access).is_ok()
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &HandoffPolicy {
        &self.policy
    }

    /// How many handoffs one origin has left in the current window.
    ///
    /// For a test or a diagnostic; the layer consults its own counter rather than
    /// this.
    #[must_use]
    pub fn remaining_budget(&self, origin: &Origin) -> u32 {
        let state = self.lock();
        state.remaining(
            origin,
            self.policy.budget(),
            self.policy.window(),
            Instant::now(),
        )
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What the response says about itself, flattened out of the extensions.
    ///
    /// `None` when there is no [`ResponseInfo`] and the request's own URI will not
    /// parse, which is the one case detection has to skip: an [`Observation`] is
    /// built around a URL and there is nothing honest to put there.
    ///
    /// [`Observation`]: crate::challenge::Observation
    fn reported(response: &Response, uri: &Uri) -> Option<Reported> {
        let (url, hops, exit) = match response.extensions().get::<ResponseInfo>() {
            Some(info) => (info.url.clone(), info.hops.clone(), info.exit.clone()),
            // No engine below this middleware — a mock terminal, or a chain a
            // caller assembled themselves. The requested URI is then the only
            // URL there is, and it is the right one: nothing redirected.
            None => (Url::parse(&uri.to_string()).ok()?, None, None),
        };
        // A URL with no origin — no host, or a scheme with no default port — is
        // not one a challenge can be handed off for, so nothing is observed and
        // no detector is consulted. This is the one place that failure has a
        // sensible answer, which is why the seam takes the origin ready-made.
        let origin = Origin::of(&url).ok()?;
        Some(Reported {
            url,
            origin,
            hops,
            exit,
        })
    }

    /// Asks the detector, reading a bounded body prefix if it asks for one.
    ///
    /// The response comes back whole either way. A prefix read rebuilds the body
    /// from what it read, so a caller who wanted that page still gets all of it —
    /// `early-stop`'s `Prefix` discards the tail, which is correct for a page you
    /// are about to throw away and wrong for a false positive.
    async fn detect(&self, response: Response, at: &Reported) -> Result<(Detection, Response)> {
        let hops = at.hops.as_deref().unwrap_or(&[]);
        let first = self.inspect(&response, at, hops, None);
        if first != Detection::Suspect {
            return Ok((first, response));
        }
        if !self.worth_sniffing(&response) {
            tracing::trace!(url = %at.url, "suspect, but the body is too large to be a challenge page");
            return Ok((Detection::Clear, response));
        }

        let (parts, body) = response.into_parts();
        let (prefix, body) = peek(body, self.sniff_limit).await?;
        let response = Response::from_parts(parts, body);

        let second = self.inspect(&response, at, hops, Some(&prefix));
        // A `Suspect` from an observation that already carries a prefix has
        // nothing left to buy — there is no second body to read — so it reads as
        // `Clear` rather than as a reason to loop. `Detection`'s own docs state
        // this rule; enforcing it is this layer's job.
        let second = if second == Detection::Suspect {
            Detection::Clear
        } else {
            second
        };
        Ok((second, response))
    }

    fn inspect(
        &self,
        response: &Response,
        at: &Reported,
        hops: &[Hop],
        prefix: Option<&[u8]>,
    ) -> Detection {
        let observation =
            Observation::new(response.status(), response.headers(), &at.url, &at.origin)
                .with_hops(hops);
        let observation = match prefix {
            Some(prefix) => observation.with_body_prefix(prefix),
            None => observation,
        };
        self.detector.inspect(&observation)
    }

    /// Whether a body is small enough to be worth buffering for a second look.
    ///
    /// A declared length over the cap settles it: a challenge interstitial is
    /// kilobytes, and anything larger is a page the caller asked for. An
    /// *undeclared* length is allowed through, because a chunked interstitial is
    /// a real thing — [`peek`] is what makes that safe, by rebuilding an oversized
    /// body as a stream instead of dropping it.
    fn worth_sniffing(&self, response: &Response) -> bool {
        match response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(declared) => declared <= self.sniff_limit as u64,
            None => true,
        }
    }

    /// The identity the browser must present, which is the profile's unless this
    /// request overrode it.
    ///
    /// `None` for a profile whose User-Agent is not a legal header value. That is
    /// a broken profile rather than a reason to invent one: a handoff carrying a
    /// User-Agent Chromulate could not have sent would earn a clearance bound to
    /// an identity this engine cannot replay.
    fn user_agent(&self, parts: &http::request::Parts) -> Option<HeaderValue> {
        parts
            .headers
            .get(USER_AGENT)
            .cloned()
            .or_else(|| HeaderValue::from_str(&self.profile.user_agent).ok())
    }
}

/// What a finished response reported about itself.
struct Reported {
    url: Url,
    /// Derived once, here, because [`Origin::of`] is fallible and a detector
    /// cannot do anything sensible with the failure — see [`Observation`]'s
    /// documentation on why the origin is carried rather than derived.
    origin: Origin,
    hops: Option<Arc<[Hop]>>,
    exit: Option<Arc<str>>,
}

impl Middleware for ChallengeHandoff {
    fn name(&self) -> &'static str {
        NAME
    }

    fn handle<'a>(&'a self, request: Request, next: Next<'a>) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move {
            let uri = request.uri().clone();

            // Detection only. Nothing is cloned for a replay that cannot happen,
            // so a layer installed without a fallback costs one detector call.
            let Some(fallback) = self.fallback.as_ref() else {
                return self.observe(next.run(request).await?, &uri).await;
            };

            if !self.policy.is_eligible(&request) {
                tracing::trace!(%uri, "not eligible for handoff; detecting only");
                return self.observe(next.run(request).await?, &uri).await;
            }

            let (parts, body) = request.into_parts();

            // The replay guard, and the only place it is *decided*. A body that
            // cannot be produced a second time cannot be handed off, because
            // re-sending with an empty one would quietly send a different
            // request — `Retry` asks the same question at
            // `middleware/retry.rs:157`. The `try_clone` at the foot of the loop
            // is the supply of the next attempt's body rather than a second
            // check; it cannot decide differently from this one.
            //
            // An earlier version really did ask twice — here, and again at the
            // *top* of the loop — and mutating either away left the suite green
            // because each made the other unreachable. That is the shape
            // `CLAUDE.md`'s third testing rule describes, and the second copy was
            // worse than redundant: its fallback branch re-sent with
            // `Body::empty()`, which is the exact bug the guard exists to stop.
            let Some(first) = body.try_clone() else {
                tracing::trace!(%uri, "a streaming body cannot be replayed; detecting only");
                return self
                    .observe(next.run(Request::from_parts(parts, body)).await?, &uri)
                    .await;
            };

            let mut sending = first;
            let mut attempts = 0u32;
            // The exit a session was last applied to, once one has been. The
            // outer `Option` is "has anything been applied"; the inner one is
            // "was there an exit", which is `None` for a direct request.
            let mut applied: Option<Option<Arc<str>>> = None;

            loop {
                let response = next
                    .run(Request::from_parts(parts.clone(), sending))
                    .await?;

                let Some(at) = Self::reported(&response, &uri) else {
                    return Ok(response);
                };
                let (detection, mut response) = self.detect(response, &at).await?;

                // The clearance is bound to the address that earned it, and
                // nothing in this crate can pin the next hop to that address —
                // see this type's documentation. What the layer *can* do is
                // notice, so the budget evaporating against a rotating pool has
                // a log line naming the cause instead of being a mystery.
                //
                // NOTE: no test asserts this line, and saying so is the point.
                // `chromulate-http` has no `tracing-subscriber` dependency, so
                // the `capture_logs`/`callsite_guard` pattern `CLAUDE.md` points
                // at is not available to any test in this crate, and adding the
                // dependency was not this change's to make. What *is* tested is
                // the behaviour underneath —
                // `a_rotating_pool_spends_a_browser_per_exit_because_the_retry_is_not_pinned`
                // reproduces the condition against the shipped `RoundRobin` and
                // asserts the wasted browser runs, with a pinned control proving
                // the rotation is the cause. So the mismatch is guarded; only
                // its rendering is not.
                if let Some(applied_to) = &applied
                    && *applied_to != at.exit
                {
                    tracing::warn!(
                        url = %at.url,
                        earned_on = applied_to.as_deref().unwrap_or("<direct>"),
                        retried_through = at.exit.as_deref().unwrap_or("<direct>"),
                        "the retry left through a different exit than the clearance was \
                         earned on, so the clearance does not apply; pin the exit or use a \
                         sticky ProxyProvider"
                    );
                }

                let Detection::Challenged(challenge) = detection else {
                    if applied.is_some() {
                        self.announce_cleared(&at.url);
                    }
                    return Ok(response);
                };

                // Phase A's whole product: the conclusion travels with the
                // response whether or not anything is done about it.
                response.extensions_mut().insert(challenge.clone());

                if attempts >= self.policy.budget() {
                    tracing::debug!(
                        url = %at.url,
                        attempts,
                        "the handoff budget for this request is spent; returning the challenge"
                    );
                    return Ok(response);
                }
                attempts += 1;

                if !fallback.handles().contains(challenge.kind()) {
                    tracing::debug!(
                        url = %at.url,
                        kind = %challenge.kind(),
                        fallback = fallback.name(),
                        "the installed fallback does not claim this kind; returning the challenge"
                    );
                    return Ok(response);
                }

                let Some(user_agent) = self.user_agent(&parts) else {
                    tracing::warn!(
                        profile = %self.profile.name,
                        "the profile's user agent is not a legal header value, so nothing can be handed off"
                    );
                    return Ok(response);
                };

                let handoff = Handoff::new(
                    at.url.clone(),
                    challenge.kind(),
                    user_agent,
                    self.solve_budget,
                )
                .with_exit(at.exit.as_deref().map(ProxyExit::new))
                .with_cookies(
                    self.sessions
                        .get()
                        .and_then(|access| access.cookie_header(at.exit.as_ref(), &at.url)),
                );

                let Some(outcome) = self.solve(fallback, &at.origin, handoff).await else {
                    tracing::debug!(
                        origin = %at.url,
                        budget = self.policy.budget(),
                        "this origin's handoff budget for the window is spent"
                    );
                    return Ok(response);
                };

                match outcome? {
                    Handback::Session {
                        set_cookie,
                        content,
                        produced_by,
                    } => {
                        let Some(access) = self.sessions.get() else {
                            tracing::warn!(
                                fallback = fallback.name(),
                                "a fallback earned session state and nothing is wired to keep it \
                                 — call `ChallengeHandoff::attach_sessions`"
                            );
                            return match content {
                                Some(content) => Ok(as_response(content, fallback.name())?),
                                None => Ok(response),
                            };
                        };
                        if !handoff_honoured(&produced_by, &parts, &self.profile) {
                            tracing::warn!(
                                fallback = fallback.name(),
                                "the fallback browsed as itself rather than as the handed \
                                 identity; the clearance it earned is bound to a User-Agent this \
                                 engine will not send"
                            );
                        }
                        access.store_cookies(at.exit.as_ref(), &at.url, &set_cookie);
                        applied = Some(at.exit.clone());
                        tracing::debug!(
                            url = %at.url,
                            cookies = set_cookie.len(),
                            "session state applied; re-running the request"
                        );
                    }
                    Handback::Content(content) => {
                        // Nothing is learned here on purpose: no cookie is
                        // replayed, no session resumed, no identity mixed. The
                        // page came from the fallback and is returned as the
                        // fallback's.
                        return as_response(content, fallback.name());
                    }
                    Handback::Declined { reason } => {
                        tracing::debug!(url = %at.url, %reason, "the fallback declined");
                        return Ok(response);
                    }
                }

                // A body that has stopped cloning cannot be sent again, and the
                // response in hand is the honest answer. Nothing is invented and
                // nothing is re-sent.
                let Some(again) = body.try_clone() else {
                    return Ok(response);
                };
                sending = again;
            }
        })
    }
}

impl ChallengeHandoff {
    /// The no-handoff path: detect, attach the conclusion, return.
    async fn observe(&self, response: Response, uri: &Uri) -> Result<Response> {
        let Some(at) = Self::reported(&response, uri) else {
            return Ok(response);
        };
        let (detection, mut response) = self.detect(response, &at).await?;
        if let Detection::Challenged(challenge) = detection {
            tracing::debug!(url = %at.url, kind = %challenge.kind(), "challenge detected");
            response.extensions_mut().insert(challenge);
        }
        Ok(response)
    }

    fn announce_cleared(&self, url: &Url) {
        if let Some(cleared) = &self.cleared {
            tracing::debug!(%url, "origin cleared");
            cleared(url);
        }
    }

    /// Runs one solve, collapsing it into any solve already running for the same
    /// target and identity.
    ///
    /// `None` means the origin's budget for the window is spent. `Some(Err(..))`
    /// means the fallback itself failed, which is the one thing here that becomes
    /// an [`Error`] — a challenge that could not be cleared is a
    /// [`Handback::Declined`] and returns the challenge response, because HTTP
    /// status codes are not errors in this workspace.
    async fn solve(
        &self,
        fallback: &Arc<dyn BrowserFallback>,
        origin: &Origin,
        handoff: Handoff,
    ) -> Option<Result<Handback>> {
        let key = SolveKey {
            url: handoff.url().clone(),
            exit: handoff.exit().map(|exit| Arc::clone(exit.label())),
        };

        let shared = {
            let mut state = self.lock();
            match state.joinable(&key) {
                Some(shared) => {
                    tracing::debug!(url = %key.url, "joining a solve already in flight");
                    shared
                }
                None => {
                    if !state.spend(
                        origin,
                        self.policy.budget(),
                        self.policy.window(),
                        self.policy.tracked_origins(),
                        Instant::now(),
                    ) {
                        return None;
                    }
                    let shared = self.start(fallback, handoff).shared();
                    state.register(&key, &shared, self.policy.tracked_origins());
                    shared
                }
            }
        };

        // The budget is enforced here as well as stated in the `Handoff`, because
        // the seam can only *ask* a fallback to answer within it. `remaining` is
        // a contract a third-party implementation may honour, ignore, or hang
        // through, and the failure mode of ignoring it is the caller's request
        // held open forever behind a browser that is not coming back. Timing out
        // reads as a decline, which is what it is: the attempt happened and
        // produced nothing.
        //
        // The wait for a global permit counts against it deliberately. A solve
        // queued behind `HandoffPolicy::concurrency` is time the caller is
        // spending whether or not a browser has started yet.
        let outcome = match tokio::time::timeout(self.solve_budget, shared).await {
            Ok(outcome) => outcome,
            Err(_) => {
                self.lock().settle(&key);
                tracing::warn!(
                    url = %key.url,
                    budget_ms = u64::try_from(self.solve_budget.as_millis()).unwrap_or(u64::MAX),
                    fallback = fallback.name(),
                    "the fallback overran its budget; treating it as a decline"
                );
                return Some(Ok(Handback::Declined {
                    reason: DeclineReason::BudgetExhausted,
                }));
            }
        };
        self.lock().settle(&key);
        Some(match &*outcome {
            SolveOutcome::Done(handback) => Ok((**handback).clone()),
            SolveOutcome::Failed(message) => {
                Err(middleware_error(NAME, SolveFailed(message.clone())))
            }
        })
    }

    /// Builds the `'static` future a solve is shared through.
    ///
    /// The global permit is taken *inside* it, so joiners do not each hold one
    /// and the bound counts browsers rather than interested callers.
    fn start(&self, fallback: &Arc<dyn BrowserFallback>, handoff: Handoff) -> SolveFuture {
        let fallback = Arc::clone(fallback);
        let permits = Arc::clone(&self.permits);
        Box::pin(async move {
            let _permit = permits.acquire_owned().await.ok();
            Arc::new(match fallback.solve(handoff).await {
                Ok(handback) => SolveOutcome::Done(Box::new(handback)),
                // `Error` is not `Clone` and one solve's failure may be handed to
                // every caller that collapsed into it, so the message is what
                // travels — the same trade `chromulate-dns` makes for a cached
                // resolution failure, and for the same reason.
                Err(error) => SolveOutcome::Failed(flatten(&error)),
            })
        })
    }
}

/// Whether the fallback browsed as the identity it was handed.
fn handoff_honoured(
    produced_by: &crate::challenge::FallbackIdentity,
    parts: &http::request::Parts,
    profile: &Profile,
) -> bool {
    let expected = parts
        .headers
        .get(USER_AGENT)
        .cloned()
        .or_else(|| HeaderValue::from_str(&profile.user_agent).ok());
    expected.is_some_and(|expected| *produced_by.user_agent() == expected)
}

/// Turns a page the fallback fetched into a response, marked as its own.
fn as_response(content: Content, fallback: &'static str) -> Result<Response> {
    let (status, headers, body, final_url) = content.into_parts();
    let mut response = http::Response::builder()
        .status(status)
        .body(Body::fixed(body))
        .map_err(|error| middleware_error(NAME, SolveFailed(error.to_string())))?;
    *response.headers_mut() = headers;
    // Deliberately no `ResponseInfo`; see `FetchedByFallback`.
    response.extensions_mut().insert(FetchedByFallback {
        fallback,
        final_url,
    });
    Ok(response)
}

/// Reads up to `cap` bytes off the front of a body, and returns a body that
/// still yields everything the original would have.
///
/// The whole point is that nothing is lost. [`Body::collect`] would be shorter
/// and would destroy an oversized response — it returns
/// [`Error::BodyTooLarge`](chromulate_core::Error::BodyTooLarge) with the bytes
/// already consumed, and turning a caller's large page into an error because a
/// detector was curious is not a trade this layer gets to make. A body that fits
/// comes back as [`Body::fixed`]; one that does not comes back as the prefix
/// chained to the untouched remainder, with the declared length preserved.
async fn peek(body: Body, cap: usize) -> Result<(Bytes, Body)> {
    let declared = body.content_length();
    let mut chunks = body.into_data_stream();
    let mut buffered = BytesMut::new();

    while buffered.len() < cap {
        match chunks.next().await {
            None => {
                let whole = buffered.freeze();
                return Ok((whole.clone(), Body::fixed(whole)));
            }
            Some(chunk) => buffered.extend_from_slice(&chunk?),
        }
    }

    let prefix = buffered.freeze();
    let head = prefix.clone();
    let rebuilt = Body::stream(
        futures_util::stream::once(async move { Ok(head) }).chain(chunks),
        declared,
    );
    Ok((prefix, rebuilt))
}

/// Renders an error and everything under it as one line.
///
/// `Display` on an [`Error`](chromulate_core::Error) prints only the top frame —
/// `Error::Middleware` renders as ``middleware `x` failed`` and says nothing
/// about why. Since only a string can cross a shared solve, keeping just that
/// line would turn "no browser is installed" into "middleware failed" for every
/// caller who joined, which is the failure being reported disappearing on the way
/// to the person who has to act on it.
fn flatten(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut cause = error.source();
    while let Some(current) = cause {
        rendered.push_str(": ");
        rendered.push_str(&current.to_string());
        cause = current.source();
    }
    rendered
}

/// The source of the [`Error::Middleware`] a failed solve produces.
#[derive(Debug)]
struct SolveFailed(String);

impl fmt::Display for SolveFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SolveFailed {}

/// What one solve produced, cheap to hand to every caller that joined it.
enum SolveOutcome {
    /// Boxed because a `Handback::Session` carrying a page is by far the largest
    /// thing here and the other arm is a string. One allocation per solve, on a
    /// path that has just started a browser.
    Done(Box<Handback>),
    Failed(String),
}

type SolveFuture = BoxFuture<'static, Arc<SolveOutcome>>;
type SharedSolve = Shared<SolveFuture>;
type WeakSolve = WeakShared<SolveFuture>;

/// What a solve is collapsed by.
///
/// The target *and* the exit, not the origin. Collapsing by origin would hand one
/// URL's page to a request for a different one, and — under
/// [`ProxyIsolation::PerProxy`](crate::ProxyIsolation::PerProxy) — hand exit A a
/// clearance minted through exit B, which is the linkage `CLAUDE.md`'s
/// server-taught-state rule exists to prevent. Bounding the *number* of solves per
/// origin is the budget's job, and it is a different job.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SolveKey {
    url: Url,
    exit: Option<Arc<str>>,
}

/// One origin's handoff count for the current window.
struct Counter {
    spent: u32,
    window_started: Instant,
    last_used: u64,
}

/// The maps this layer keys by input the servers it visits choose.
#[derive(Default)]
struct State {
    counters: HashMap<Origin, Counter>,
    inflight: HashMap<SolveKey, WeakSolve>,
    tick: u64,
}

/// The size the in-flight map is swept at.
///
/// Small, because entries here are browser-shaped rather than request-shaped: a
/// deployment with more than this many solves genuinely in flight has a different
/// problem. The same opportunistic-sweep shape as `chromulate-dns`'s cache.
const SWEEP_AT: usize = 32;

impl State {
    /// A solve already running for this exact target and identity.
    ///
    /// An in-flight marker that no longer upgrades belonged to a solve every
    /// caller abandoned, so it decides nothing — the same call `chromulate-dns`
    /// makes about a lookup nobody is waiting for.
    fn joinable(&mut self, key: &SolveKey) -> Option<SharedSolve> {
        self.inflight.get(key)?.upgrade()
    }

    fn register(&mut self, key: &SolveKey, shared: &SharedSolve, capacity: usize) {
        if self.inflight.len() >= SWEEP_AT {
            self.inflight.retain(|_, weak| weak.upgrade().is_some());
        }
        // Past the cap the solve still runs; it is simply not registered, so a
        // later caller starts its own instead of joining. Losing collapsing is
        // the right way to lose: the alternative is a map keyed by URLs the
        // servers choose, growing without a bound.
        if self.inflight.len() >= capacity {
            return;
        }
        // `downgrade` refuses only for a `Shared` already polled to completion,
        // which one built here cannot have been.
        if let Some(weak) = shared.downgrade() {
            self.inflight.insert(key.clone(), weak);
        }
    }

    fn settle(&mut self, key: &SolveKey) {
        self.inflight.remove(key);
    }

    /// Spends one of this origin's handoffs, or refuses.
    ///
    /// `budget` is at least one — [`HandoffPolicy::with_budget`] clamps it and the
    /// field is not otherwise reachable — so a first handoff against a new origin
    /// is always allowed and there is no zero case to guard here.
    fn spend(
        &mut self,
        origin: &Origin,
        budget: u32,
        window: Duration,
        capacity: usize,
        now: Instant,
    ) -> bool {
        self.tick += 1;
        let tick = self.tick;

        if let Some(counter) = self.counters.get_mut(origin) {
            counter.last_used = tick;
            if now.saturating_duration_since(counter.window_started) >= window {
                counter.window_started = now;
                counter.spent = 0;
            }
            if counter.spent >= budget {
                return false;
            }
            counter.spent += 1;
            return true;
        }

        if self.counters.len() >= capacity {
            self.evict_least_recently_used();
        }
        self.counters.insert(
            origin.clone(),
            Counter {
                spent: 1,
                window_started: now,
                last_used: tick,
            },
        );
        true
    }

    fn remaining(&self, origin: &Origin, budget: u32, window: Duration, now: Instant) -> u32 {
        match self.counters.get(origin) {
            None => budget,
            Some(counter) if now.saturating_duration_since(counter.window_started) >= window => {
                budget
            }
            Some(counter) => budget.saturating_sub(counter.spent),
        }
    }

    /// Drops one origin's counter so a new one can be tracked.
    ///
    /// Losing a counter loses a loop guard for that origin until it challenges
    /// again, which is the least bad of the three options: a cap with no eviction
    /// is a stall, and eviction with no cap is decoration.
    fn evict_least_recently_used(&mut self) {
        let victim = self
            .counters
            .iter()
            .min_by_key(|(_, counter)| counter.last_used)
            .map(|(origin, _)| origin.clone());
        if let Some(victim) = victim {
            self.counters.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures_util::stream;

    fn origin(text: &str) -> Origin {
        Origin::of(&Url::parse(text).expect("test url should parse"))
            .expect("test url should have an origin")
    }

    // ------------------------------------------------------------ peek

    #[tokio::test]
    async fn a_body_that_fits_is_read_whole_and_handed_back_whole() {
        let (prefix, body) = peek(Body::fixed("<title>Just a moment"), 1024)
            .await
            .expect("a fixed body cannot fail to read");

        assert_eq!(prefix.as_ref(), b"<title>Just a moment");
        assert_eq!(
            body.collect(1024)
                .await
                .expect("the rebuilt body must still read")
                .as_ref(),
            b"<title>Just a moment",
            "the caller's page must survive a detector looking at it"
        );
    }

    /// The reason this function exists rather than a `Body::collect` call.
    /// `collect` would return `BodyTooLarge` here with the bytes already gone,
    /// turning a caller's large page into an error because a detector was
    /// curious. Mutating `peek` to call `collect` turns this red.
    #[tokio::test]
    async fn a_body_larger_than_the_cap_is_still_delivered_in_full() {
        let chunks = stream::iter(
            (0..4).map(|_| Ok(Bytes::from_static(&[b'x'; 16]))), // 64 bytes, undeclared
        );
        let (prefix, body) = peek(Body::stream(chunks, None), 20)
            .await
            .expect("an oversized body is not an error");

        assert_eq!(
            prefix.len(),
            32,
            "reading stops at the first chunk past the cap"
        );
        let whole = body
            .collect(1024)
            .await
            .expect("the remainder must still be readable");
        assert_eq!(whole.len(), 64, "every byte the origin sent must survive");
        assert!(whole.iter().all(|byte| *byte == b'x'));
    }

    #[tokio::test]
    async fn an_empty_body_reads_as_a_prefix_that_rules_content_rules_out() {
        let (prefix, _) = peek(Body::empty(), 64)
            .await
            .expect("empty is not an error");
        // `Some(&[])` and `None` are different facts to a detector: this one says
        // the body was read and there was nothing in it.
        assert!(prefix.is_empty());
    }

    // ------------------------------------------------------------ the budget

    #[test]
    fn an_origin_gets_its_budget_and_then_stops_getting_it() {
        let mut state = State::default();
        let shop = origin("https://shop.test/");
        let now = Instant::now();
        let window = Duration::from_secs(300);

        assert!(state.spend(&shop, 2, window, 8, now));
        assert!(state.spend(&shop, 2, window, 8, now));
        assert!(
            !state.spend(&shop, 2, window, 8, now),
            "a third handoff inside the window is a loop, not a retry"
        );
        assert_eq!(state.remaining(&shop, 2, window, now), 0);
    }

    #[test]
    fn the_window_is_what_makes_the_budget_come_back() {
        let mut state = State::default();
        let shop = origin("https://shop.test/");
        let start = Instant::now();
        let window = Duration::from_secs(300);

        assert!(state.spend(&shop, 1, window, 8, start));
        assert!(!state.spend(&shop, 1, window, 8, start));

        // Everything above also holds for a `spend` that never resets the
        // window. Only a later clock separates them.
        let later = start + window + Duration::from_secs(1);
        assert!(
            state.spend(&shop, 1, window, 8, later),
            "past the window the count starts again"
        );
        assert_eq!(state.remaining(&shop, 1, window, later), 0);
    }

    #[test]
    fn one_origins_budget_is_not_another_origins() {
        let mut state = State::default();
        let now = Instant::now();
        let window = Duration::from_secs(300);

        assert!(state.spend(&origin("https://a.test/"), 1, window, 8, now));
        assert!(
            state.spend(&origin("https://b.test/"), 1, window, 8, now),
            "a spent budget must belong to the origin that spent it"
        );
        assert!(!state.spend(&origin("https://a.test/"), 1, window, 8, now));
    }

    #[test]
    fn the_counter_map_evicts_the_least_recently_used_rather_than_growing() {
        let mut state = State::default();
        let now = Instant::now();
        let window = Duration::from_secs(300);

        for index in 0..4 {
            let target = format!("https://host{index}.test/");
            assert!(state.spend(&origin(&target), 4, window, 2, now));
        }

        assert_eq!(
            state.counters.len(),
            2,
            "a map keyed by origins the servers choose carries a capacity"
        );
        // The two most recent survive; the two oldest were evicted.
        assert!(state.counters.contains_key(&origin("https://host3.test/")));
        assert!(state.counters.contains_key(&origin("https://host2.test/")));
        assert!(!state.counters.contains_key(&origin("https://host0.test/")));
    }

    /// The hostnames are chosen so that recency and alphabetical order disagree,
    /// and they have to be: with `old.test` and `filler.test` the two policies
    /// pick the same victim, and mutating `min_by_key` from `last_used` to the
    /// host name left this test green. It proved eviction happens and nothing
    /// about what it evicts.
    #[test]
    fn touching_an_origin_keeps_it_from_being_the_one_evicted() {
        let mut state = State::default();
        let now = Instant::now();
        let window = Duration::from_secs(300);
        let kept = origin("https://a-kept.test/");
        let stale = origin("https://z-stale.test/");

        assert!(state.spend(&kept, 8, window, 2, now));
        assert!(state.spend(&stale, 8, window, 2, now));
        // `kept` is used again, so `stale` becomes the least recently used —
        // while staying the *last* alphabetically and the *second* inserted.
        assert!(state.spend(&kept, 8, window, 2, now));
        assert!(state.spend(&origin("https://m-new.test/"), 8, window, 2, now));

        assert!(
            state.counters.contains_key(&kept),
            "eviction must be by recency, not by insertion order or by key"
        );
        assert!(!state.counters.contains_key(&stale));
    }
}
