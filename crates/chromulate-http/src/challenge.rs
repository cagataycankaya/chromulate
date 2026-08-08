//! Noticing that a response is a bot challenge, and handing the page to a
//! browser the caller installed.
//!
//! Chromulate cannot execute JavaScript and will not pretend otherwise. When an
//! origin answers with a challenge, the honest thing a networking library can do
//! is say so precisely, hand the work to something that *can* run a browser, and
//! take back whatever that browser earned. This module is the whole of that
//! seam: an observation vocabulary, two traits, and the policy type that bounds
//! how often either one runs.
//!
//! It ships **no detector and no fallback**. A detector for one vendor's
//! documented signals lives in `chromulate-challenge`; an adapter for a
//! particular browser lives further out still, and may live outside this
//! repository entirely. The split is the same one [`crate::concurrency`] makes
//! and for the same reason: a trait that ships in the same module as its only
//! implementation is a trait whose users cannot tell which parts are the
//! boundary.
//!
//! # What this is not
//!
//! Not a solver. Nothing here mints a token, reimplements a challenge platform's
//! script, or tunes itself against a classifier. The only conclusion this crate
//! draws is "a challenge is present", which is a question a local test can
//! answer — and, for the case this was designed against, one the vendor
//! documents a response header for. Everything past that point is the caller's
//! browser doing what the caller told it to do.
//!
//! # The shape of one round
//!
//! 1. A response comes back. The layer builds an [`Observation`] — status,
//!    headers, URL, redirect hops, and nothing concluded from them.
//! 2. The installed [`ChallengeDetector`] returns a [`Detection`]. Three arms,
//!    not two: [`Detection::Suspect`] is what buys a bounded body read, so the
//!    default path never pays for one.
//! 3. On [`Detection::Challenged`], the layer builds a [`Handoff`] — the target,
//!    the profile's User-Agent, the proxy exit, the cookies the route already
//!    holds — and gives it to the installed [`BrowserFallback`].
//! 4. The fallback answers with a [`Handback`]: session state to apply and
//!    replay, a page it fetched itself, or a decline.
//!
//! # Writing the two halves
//!
//! ```
//! use chromulate_core::{BoxFuture, Origin, Result};
//! use chromulate_http::challenge::{
//!     BrowserFallback, Challenge, ChallengeDetector, ChallengeKind, ChallengeKinds,
//!     DeclineReason, Detection, Evidence, Handback, Handoff, Observation,
//! };
//! use http::{HeaderMap, HeaderValue, StatusCode};
//! use url::Url;
//!
//! /// Reads one header the vendor publishes for the purpose, and concludes
//! /// nothing that header did not say.
//! #[derive(Debug)]
//! struct Mitigated;
//!
//! impl ChallengeDetector for Mitigated {
//!     fn inspect(&self, observation: &Observation<'_>) -> Detection {
//!         if observation.headers().get("cf-mitigated").map(HeaderValue::as_bytes)
//!             != Some(b"challenge".as_slice())
//!         {
//!             return Detection::Clear;
//!         }
//!         Detection::Challenged(Challenge::new(
//!             ChallengeKind::JsRequired,
//!             observation.origin().clone(),
//!             Evidence::from_signal("cf-mitigated: challenge"),
//!         ))
//!     }
//! }
//!
//! /// A fallback with no browser behind it. Declining is a valid answer, and
//! /// saying so through [`Handback::Declined`] is how a fallback stays honest.
//! #[derive(Debug)]
//! struct NoBrowser;
//!
//! impl BrowserFallback for NoBrowser {
//!     fn name(&self) -> &'static str {
//!         "no-browser"
//!     }
//!
//!     fn handles(&self) -> ChallengeKinds {
//!         ChallengeKinds::none()
//!     }
//!
//!     fn solve<'a>(&'a self, handoff: Handoff) -> BoxFuture<'a, Result<Handback>> {
//!         Box::pin(async move {
//!             Ok(Handback::Declined {
//!                 reason: DeclineReason::UnsupportedKind(handoff.kind()),
//!             })
//!         })
//!     }
//! }
//!
//! let url = Url::parse("https://example.com/").unwrap();
//! let origin = Origin::of(&url).unwrap();
//! let mut headers = HeaderMap::new();
//! headers.insert("cf-mitigated", HeaderValue::from_static("challenge"));
//!
//! let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &url, &origin);
//! let Detection::Challenged(challenge) = Mitigated.inspect(&observation) else {
//!     panic!("the documented header should settle this without a body read");
//! };
//! assert_eq!(challenge.kind(), ChallengeKind::JsRequired);
//! assert!(!NoBrowser.handles().contains(challenge.kind()));
//! ```

use std::borrow::Cow;
use std::fmt;
use std::ops::BitOr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chromulate_core::{BoxFuture, FetchDest, Origin, Request, RequestOptions, Result};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use url::Url;

/// One response in a redirect chain.
///
/// The chain is a detection signal — a `302` into a challenge path and back out
/// again looks nothing like a direct `403` — but its sharper use is the loop
/// guard. A clearance the origin refuses bounces the retry straight back to the
/// challenge, and a layer that only sees the terminal `200` on a challenge page
/// hands off forever.
///
/// Read through accessors rather than as public fields, because a `ResponseInfo`
/// that gained two literal-constructible fields would be a source break for
/// anyone building one, and because that is what every other observation type in
/// this crate does — see [`Outcome`](crate::concurrency::Outcome).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    url: Url,
    status: StatusCode,
}

impl Hop {
    /// Records one hop.
    ///
    /// ```
    /// use chromulate_http::challenge::Hop;
    /// use http::StatusCode;
    /// use url::Url;
    ///
    /// let hop = Hop::new(
    ///     Url::parse("https://example.com/").unwrap(),
    ///     StatusCode::FOUND,
    /// );
    /// assert_eq!(hop.status(), StatusCode::FOUND);
    /// assert_eq!(hop.url().path(), "/");
    /// ```
    #[must_use]
    pub fn new(url: Url, status: StatusCode) -> Self {
        Self { url, status }
    }

    /// The URL that was requested at this hop.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The status that URL answered with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

/// What one completed request is known to have produced, for a detector to read.
///
/// Deliberately not a verdict, on exactly the rule
/// [`Outcome`](crate::concurrency::Outcome) states for the concurrency seam: a
/// pre-classified input is one detector's reading of a response, and putting a
/// reading into the type every implementation speaks shapes the seam around the
/// implementation that happened to come first. A `403` is a challenge to one
/// detector and an expired token to another; `<title>Just a moment…` is decisive
/// to one and a coincidence to another. Neither reading belongs here.
///
/// So this carries what was observed — the status, the headers, the final URL,
/// the redirect hops, and the body prefix *if one was read* — and nothing that
/// was concluded. [`ChallengeKind`] is a conclusion, and it is correct that it
/// exists, because concluding is the detector's entire job: it appears on the
/// **output** side, in [`Challenge`].
///
/// # Why the body prefix is an `Option` rather than a slice
///
/// `None` and `Some(&[])` are different facts. `None` is "nobody has read this
/// body", which is the state on the first pass over every response; `Some(&[])`
/// is "the body was read and it was empty", which rules a content-shaped rule
/// out rather than leaving it unanswered. A detector that returns
/// [`Detection::Suspect`] on `None` and `Clear` on `Some(&[])` is behaving
/// correctly and cannot be written against a bare slice.
///
/// # Why the hops are a slice rather than an `Option`
///
/// The opposite call, for the opposite reason. `ResponseInfo::hops` is an
/// `Option<Arc<[Hop]>>` and is `None` — never `Some([])` — when no redirect
/// happened, because there the distinction pays for itself: it is what keeps the
/// no-redirect path at zero extra allocations. A detector cannot use the
/// distinction. "No redirect happened" and "the chain was empty" are one fact
/// about the response, and offering two spellings of it would only invite a rule
/// that fires on one and not the other. Flatten with
/// `info.hops.as_deref().unwrap_or(&[])` on the way in, and never read an empty
/// slice here as "not populated yet".
///
/// # Why the origin is carried rather than derived
///
/// [`Origin::of`] is fallible — a URL with no host, or a scheme with no default
/// port, has no origin. That failure cannot happen to a response, because a
/// response was received, so the URL had a host. Deriving the origin inside each
/// detector therefore made every detector write an error branch that could not be
/// taken, and both of the first two written did: one with a `let … else`, one
/// with a nine-line comment explaining why its `Err` arm returned
/// [`Detection::Clear`].
///
/// So the fallible step happens once, at the layer boundary, where the failure
/// has a sensible answer — a URL with no origin is not one a challenge can be
/// handed off for, so no observation is built and no detector is consulted.
/// Every detector downstream gets an origin that exists.
#[derive(Debug, Clone, Copy)]
pub struct Observation<'a> {
    status: StatusCode,
    headers: &'a HeaderMap,
    url: &'a Url,
    origin: &'a Origin,
    hops: &'a [Hop],
    body_prefix: Option<&'a [u8]>,
}

impl<'a> Observation<'a> {
    /// A response with no redirect chain and no body read, which is the shape
    /// every first pass has.
    ///
    /// The `origin` is the caller's to produce, and producing it is where a URL
    /// that has none gets refused — see the type documentation.
    ///
    /// ```
    /// use chromulate_core::Origin;
    /// use chromulate_http::challenge::Observation;
    /// use http::{HeaderMap, StatusCode};
    /// use url::Url;
    ///
    /// let headers = HeaderMap::new();
    /// let url = Url::parse("https://example.com/").unwrap();
    /// let origin = Origin::of(&url).unwrap();
    ///
    /// let observation = Observation::new(StatusCode::OK, &headers, &url, &origin);
    /// assert_eq!(observation.origin().host(), "example.com");
    /// assert!(observation.hops().is_empty());
    /// assert!(observation.body_prefix().is_none());
    /// ```
    #[must_use]
    pub fn new(
        status: StatusCode,
        headers: &'a HeaderMap,
        url: &'a Url,
        origin: &'a Origin,
    ) -> Self {
        Self {
            status,
            headers,
            url,
            origin,
            hops: &[],
            body_prefix: None,
        }
    }

    /// Attaches the redirect chain, oldest first.
    #[must_use]
    pub fn with_hops(mut self, hops: &'a [Hop]) -> Self {
        self.hops = hops;
        self
    }

    /// Attaches the bytes read after a [`Detection::Suspect`].
    #[must_use]
    pub fn with_body_prefix(mut self, prefix: &'a [u8]) -> Self {
        self.body_prefix = Some(prefix);
        self
    }

    /// What the origin answered with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &'a HeaderMap {
        self.headers
    }

    /// The URL that produced this response, after any redirects were followed.
    #[must_use]
    pub fn url(&self) -> &'a Url {
        self.url
    }

    /// The origin that answered, ready to hand to [`Challenge::new`].
    #[must_use]
    pub fn origin(&self) -> &'a Origin {
        self.origin
    }

    /// The redirect chain, oldest first, empty when the request was answered
    /// directly.
    #[must_use]
    pub fn hops(&self) -> &'a [Hop] {
        self.hops
    }

    /// The bytes read from the front of the body, or `None` when none were.
    #[must_use]
    pub fn body_prefix(&self) -> Option<&'a [u8]> {
        self.body_prefix
    }
}

/// What a detector made of one [`Observation`].
///
/// Three arms rather than two, and the third is the point: it is what keeps a
/// body read off the default path. Header-only detection settles the documented
/// cases at zero body bytes, and [`Detection::Suspect`] is the detector saying
/// the headers are ambiguous and a bounded prefix is worth paying for.
///
/// The layer re-inspects with the prefix attached. A `Suspect` returned from an
/// observation that **already** carries a prefix has nothing left to buy — there
/// is no second body to read — so the layer treats it as [`Detection::Clear`]
/// rather than reading more or looping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detection {
    /// Nothing here looks like a challenge. The response is passed through
    /// untouched.
    Clear,
    /// The headers are ambiguous. Read a bounded prefix of the body and ask
    /// again.
    Suspect,
    /// A challenge, and what is known about it.
    Challenged(Challenge),
}

/// A challenge a detector concluded was present, and the signals it concluded
/// from.
///
/// The evidence travels with the conclusion so that a [`BrowserFallback`] can
/// disagree. A fallback that knows the origin better than the detector does —
/// because it has a real browser to look with — should be able to see *why* it
/// was called rather than only *that* it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    kind: ChallengeKind,
    origin: Origin,
    evidence: Evidence,
}

impl Challenge {
    /// Records a challenge, its kind, and the signals that fired.
    #[must_use]
    pub fn new(kind: ChallengeKind, origin: Origin, evidence: Evidence) -> Self {
        Self {
            kind,
            origin,
            evidence,
        }
    }

    /// What kind of challenge this is.
    #[must_use]
    pub fn kind(&self) -> ChallengeKind {
        self.kind
    }

    /// The origin that issued it.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The signals the detector fired on.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

/// What kind of work clearing a challenge would take.
///
/// This is a conclusion, and unlike [`Observation`] it is allowed to be one:
/// concluding is the detector's job, and this is on the output side of it. It
/// describes the *work*, not the vendor — a fallback should be able to answer
/// "can I carry this?" without a table of challenge products.
///
/// # What this deliberately cannot say
///
/// There is no variant meaning "nothing can carry this". A detector reads one
/// response; it does not know which fallback is installed, what that fallback
/// claims in [`BrowserFallback::handles`], or whether the caller installed one
/// at all. "Unsupported" is a conclusion about the *fallback*, and it already
/// exists in the one place that can reach it — [`DeclineReason::UnsupportedKind`],
/// which the fallback itself returns.
///
/// An earlier version of this enum had an `Unsupported` variant, and it was a
/// quiet instance of the mistake this whole module is built to avoid: putting
/// one participant's verdict into the type every participant speaks. It also
/// made the shipped configuration incoherent. The first detector written against
/// it could only ever return `Unsupported`, because `cf-mitigated: challenge`
/// says a challenge happened and nothing about which kind — so a layer that
/// honoured "never hand off an `Unsupported`" would detect and then always stop.
/// [`ChallengeKind::Unknown`] is what that detector actually meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChallengeKind {
    /// A page that clears itself once script runs. Nothing is asked of a human.
    JsRequired,
    /// A token the client must present on the next request, obtainable without
    /// interaction.
    CookieRequired,
    /// A human, or a service acting for one, must do something.
    Interactive,
    /// A challenge, kind not determined.
    ///
    /// The honest answer from a detector whose evidence proves a challenge
    /// happened without saying what it asks for — which is every header-only
    /// rule, because the headers that announce a challenge do not describe it.
    ///
    /// This is handed off like any other kind, and a browser fallback should
    /// claim it: pointing a browser at a page does not require knowing the
    /// taxonomy first, it navigates and finds out. A fallback that needs to know
    /// in advance declines with [`DeclineReason::UnsupportedKind`], which is the
    /// answer moving to where the knowledge is.
    Unknown,
}

impl ChallengeKind {
    /// Every kind this build knows about.
    ///
    /// NOTE: a new variant belongs here as well as in the enum. The compiler
    /// will make you update `ChallengeKinds::bit`'s match, which is where you
    /// will be standing when you read this; it cannot make you update an array.
    pub const EVERY: [Self; 4] = [
        Self::JsRequired,
        Self::CookieRequired,
        Self::Interactive,
        Self::Unknown,
    ];
}

impl fmt::Display for ChallengeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::JsRequired => "js-required",
            Self::CookieRequired => "cookie-required",
            Self::Interactive => "interactive",
            Self::Unknown => "unknown",
        })
    }
}

/// The set of [`ChallengeKind`]s a [`BrowserFallback`] claims it can carry.
///
/// A set rather than a list because the layer asks one question of it —
/// "does this contain the kind I have?" — on a path where a browser is about to
/// be launched, and because a fallback claiming the same kind twice should not
/// be expressible.
///
/// Every variant is claimable, [`ChallengeKind::Unknown`] included, and
/// [`ChallengeKinds::all`] therefore means all of them with no footnote. A set
/// type that quietly excluded one member would be a policy hidden in a container,
/// and the policy would then live in two places — here and in the layer that
/// decides what to hand off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChallengeKinds(u8);

impl ChallengeKinds {
    /// The bit one kind occupies.
    ///
    /// Exhaustive on purpose: adding a variant to [`ChallengeKind`] must not
    /// silently produce a kind with no bit, which would make `contains` answer
    /// `false` for a fallback that had claimed it.
    const fn bit(kind: ChallengeKind) -> u8 {
        match kind {
            ChallengeKind::JsRequired => 1 << 0,
            ChallengeKind::CookieRequired => 1 << 1,
            ChallengeKind::Interactive => 1 << 2,
            ChallengeKind::Unknown => 1 << 3,
        }
    }

    /// Claims nothing. A fallback that returns this is never asked to solve
    /// anything, which is a valid — and honest — configuration.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Claims every kind this build knows about.
    ///
    /// Useful for a mock in a test. A real fallback that returns this is
    /// promising something about kinds it has not seen, which is a promise it
    /// keeps by returning [`Handback::Declined`] rather than by crashing.
    #[must_use]
    pub fn all() -> Self {
        ChallengeKind::EVERY.into_iter().collect()
    }

    /// Adds one kind to the claim.
    ///
    /// ```
    /// use chromulate_http::challenge::{ChallengeKind, ChallengeKinds};
    ///
    /// let claim = ChallengeKinds::none()
    ///     .with(ChallengeKind::JsRequired)
    ///     .with(ChallengeKind::CookieRequired);
    ///
    /// assert!(claim.contains(ChallengeKind::JsRequired));
    /// assert!(!claim.contains(ChallengeKind::Interactive));
    /// ```
    #[must_use]
    pub const fn with(self, kind: ChallengeKind) -> Self {
        Self(self.0 | Self::bit(kind))
    }

    /// Whether this claim covers `kind`.
    #[must_use]
    pub const fn contains(self, kind: ChallengeKind) -> bool {
        self.0 & Self::bit(kind) != 0
    }

    /// Whether nothing at all is claimed.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr<ChallengeKind> for ChallengeKinds {
    type Output = Self;

    fn bitor(self, kind: ChallengeKind) -> Self {
        self.with(kind)
    }
}

impl BitOr for ChallengeKinds {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl FromIterator<ChallengeKind> for ChallengeKinds {
    fn from_iter<I: IntoIterator<Item = ChallengeKind>>(kinds: I) -> Self {
        kinds.into_iter().fold(Self::none(), Self::with)
    }
}

/// The signals a detector fired on, so that whoever acts on the conclusion can
/// see what it rested on.
///
/// A signal is a short, human-readable label — `"cf-mitigated: challenge"`,
/// `"title: just a moment"` — written by the detector for a log line and for a
/// fallback deciding whether to trust the call. It is deliberately not a
/// structured enum: the set of things a detector might notice is open, and an
/// enum here would either be a list of one vendor's product names or a list of
/// everything anyone might ever add.
///
/// A detector must keep labels short and must not paste response bytes into one.
/// That is documented rather than enforced, because truncating a caller's own
/// label silently is a worse failure than a long log line — but it is the reason
/// nothing here grows with the size of a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    signals: Vec<Cow<'static, str>>,
}

impl Evidence {
    /// No signals. A detector returning [`Detection::Challenged`] with this is
    /// saying "I am sure and I will not say why", which is allowed and is worth
    /// noticing in a review.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The one signal that fired.
    #[must_use]
    pub fn from_signal(signal: impl Into<Cow<'static, str>>) -> Self {
        Self {
            signals: vec![signal.into()],
        }
    }

    /// Adds another signal.
    ///
    /// ```
    /// use chromulate_http::challenge::Evidence;
    ///
    /// let evidence = Evidence::from_signal("status: 403").with("body: challenge-platform");
    /// assert_eq!(evidence.signals().count(), 2);
    /// ```
    #[must_use]
    pub fn with(mut self, signal: impl Into<Cow<'static, str>>) -> Self {
        self.signals.push(signal.into());
        self
    }

    /// The signals, in the order the detector recorded them.
    pub fn signals(&self) -> impl Iterator<Item = &str> {
        self.signals.iter().map(Cow::as_ref)
    }

    /// Whether the detector recorded nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }
}

/// Decides whether a response is a challenge.
///
/// Implementations are consulted once per terminal response, on the response
/// path of a middleware, and must be cheap: the common case is a page that is
/// not a challenge, and that case must cost a few header lookups and no
/// allocation.
///
/// # What a detector may be written against
///
/// A rule must cite a documented signal or a captured response, on the same
/// standard `CLAUDE.md` sets for a fingerprint constant. A rule tuned by trial
/// against a live classifier is out of scope for this repository — not because
/// it would not work, but because nothing here could test whether it still did.
pub trait ChallengeDetector: Send + Sync + 'static {
    /// Reads the observation and says what it saw.
    ///
    /// Called with `body_prefix` absent first. Returning [`Detection::Suspect`]
    /// is what buys a bounded read and a second call with the prefix attached.
    fn inspect(&self, observation: &Observation<'_>) -> Detection;
}

impl fmt::Debug for dyn ChallengeDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeDetector")
    }
}

/// The proxy exit a challenged request went out through.
///
/// Opaque, and the opacity is the feature: this is the same label the engine
/// keys its per-route session state by, so it round-trips out to a fallback and
/// back in with nothing to reconstruct. `CLAUDE.md`'s rule — *server-taught state
/// is keyed by the proxy exit it was taught through* — then holds by
/// construction rather than by anyone remembering it. A clearance cookie is
/// server-taught state of exactly that kind, and a fallback that browses through
/// a different exit earns a cookie bound to the wrong address.
///
/// # Credentials
///
/// The engine's label is [`ProxyUrl`]'s redacted `Display`, so it never held a
/// password to begin with. [`ProxyExit::new`] redacts anyway, at construction
/// rather than in `Debug`, because a redaction that lives only in a formatting
/// impl is one edit away from being lost and this value ends up in logs, in
/// `Debug` dumps of a whole middleware, and in a third party's crash report.
///
/// ```
/// use chromulate_http::challenge::ProxyExit;
///
/// let exit = ProxyExit::new("http://alice:hunter2@127.0.0.1:8080");
/// assert_eq!(exit.as_str(), "http://***@127.0.0.1:8080");
/// assert!(!format!("{exit:?}").contains("hunter2"));
/// ```
///
/// [`ProxyUrl`]: https://docs.rs/chromulate-proxy
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProxyExit {
    label: Arc<str>,
}

impl ProxyExit {
    /// Records an exit, redacting any userinfo the label carried.
    ///
    /// Redaction is idempotent, so passing a label the engine already produced
    /// returns it unchanged.
    #[must_use]
    pub fn new(label: impl AsRef<str>) -> Self {
        Self {
            label: Arc::from(redact_userinfo(label.as_ref()).as_ref()),
        }
    }

    /// The label, for keying the state that belongs to this exit.
    #[must_use]
    pub fn label(&self) -> &Arc<str> {
        &self.label
    }

    /// The label as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for ProxyExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

impl fmt::Debug for ProxyExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProxyExit").field(&&*self.label).finish()
    }
}

/// Replaces the userinfo of a proxy label with `***`.
///
/// Mirrors `chromulate_proxy::ProxyUrl`'s `Display`, which is where the engine's
/// own labels come from, so a label that has been through that already comes
/// back unchanged.
fn redact_userinfo(raw: &str) -> Cow<'_, str> {
    let (prefix, rest) = match raw.find("://") {
        Some(at) => raw.split_at(at + 3),
        None => ("", raw),
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let Some(at) = rest[..authority_end].rfind('@') else {
        return Cow::Borrowed(raw);
    };
    Cow::Owned(format!("{prefix}***@{}", &rest[at + 1..]))
}

/// Everything a fallback needs to attempt one challenge, and nothing it does
/// not.
///
/// # The User-Agent is mandatory, not advisory
///
/// A clearance cookie is understood to be bound to the address *and* the user
/// agent that earned it. A fallback that browses as itself and hands back a
/// cookie Chromulate then replays under a different User-Agent has produced
/// something that either does not work or is a stronger signal to the origin
/// than not rotating at all. So the field is a [`HeaderValue`] and not an
/// `Option<HeaderValue>`, and a fallback that ignores it is a broken
/// implementation. [`Handoff::honoured_by`] is how a test says so.
///
/// # Why a budget rather than a deadline
///
/// The first shape of this type carried `deadline: Instant`. `Instant + Duration`
/// panics on overflow, and `Duration::MAX` is one public call away from any
/// caller-supplied timeout — the same hazard this crate's private `Deadline` already had to
/// answer, and it answered it by making the deadline optional. An optional
/// deadline is the wrong answer *here*, because "no bound" on a handoff means a
/// browser process with no bound. Storing the start and the budget instead makes
/// [`Handoff::remaining`] total, unpanicking, and testable without a clock.
#[derive(Debug, Clone)]
pub struct Handoff {
    url: Url,
    kind: ChallengeKind,
    user_agent: HeaderValue,
    exit: Option<ProxyExit>,
    cookies: Option<HeaderValue>,
    started: Instant,
    budget: Duration,
}

impl Handoff {
    /// The work, the identity to do it under, and how long it may take.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use chromulate_http::challenge::{ChallengeKind, Handoff};
    /// use http::HeaderValue;
    /// use url::Url;
    ///
    /// let handoff = Handoff::new(
    ///     Url::parse("https://example.com/").unwrap(),
    ///     ChallengeKind::JsRequired,
    ///     HeaderValue::from_static("Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36"),
    ///     Duration::from_secs(30),
    /// );
    ///
    /// assert_eq!(handoff.kind(), ChallengeKind::JsRequired);
    /// assert!(!handoff.is_expired());
    /// ```
    #[must_use]
    pub fn new(url: Url, kind: ChallengeKind, user_agent: HeaderValue, budget: Duration) -> Self {
        Self {
            url,
            kind,
            user_agent,
            exit: None,
            cookies: None,
            started: Instant::now(),
            budget,
        }
    }

    /// Names the exit the challenged request went out through.
    ///
    /// Takes an `Option` because the caller has one: a direct request has no
    /// exit, and making that the absence of a builder call rather than a value
    /// invites a branch at every call site.
    #[must_use]
    pub fn with_exit(mut self, exit: Option<ProxyExit>) -> Self {
        self.exit = exit;
        self
    }

    /// Attaches the `Cookie` header the engine would have sent for this URL, so
    /// the browser starts where Chromulate stopped rather than from nothing.
    ///
    /// A `Cookie` header value — `a=1; b=2` — rather than a jar export, because
    /// `chromulate-http` speaks [`CookieStore`](chromulate_core::CookieStore) and
    /// not any particular cookie implementation, and that trait produces exactly
    /// this. Note the asymmetry with [`Handback::Session`], which travels the
    /// other way as `Set-Cookie` lines: outbound has no attributes to carry and
    /// inbound cannot do without them.
    #[must_use]
    pub fn with_cookies(mut self, cookies: Option<HeaderValue>) -> Self {
        self.cookies = cookies;
        self
    }

    /// The page to point a browser at.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// What kind of challenge the detector concluded was there.
    #[must_use]
    pub fn kind(&self) -> ChallengeKind {
        self.kind
    }

    /// The User-Agent the browser must present. Mandatory; see the type docs.
    #[must_use]
    pub fn user_agent(&self) -> &HeaderValue {
        &self.user_agent
    }

    /// The exit to browse through, or `None` for a direct request.
    #[must_use]
    pub fn exit(&self) -> Option<&ProxyExit> {
        self.exit.as_ref()
    }

    /// The `Cookie` header the route already holds for this URL, if any.
    #[must_use]
    pub fn cookies(&self) -> Option<&HeaderValue> {
        self.cookies.as_ref()
    }

    /// The whole budget this handoff was given.
    #[must_use]
    pub fn budget(&self) -> Duration {
        self.budget
    }

    /// How much of the budget is left. Saturates at zero rather than wrapping.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.budget.saturating_sub(self.started.elapsed())
    }

    /// Whether the budget is spent.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Whether a fallback browsed under the identity it was handed.
    ///
    /// The User-Agent half of the identity, which is the half that can be
    /// checked from here. The TLS and JavaScript identity a fallback presents is
    /// its own and is not this crate's to verify — that gap is real, is
    /// permanent, and is recorded in [`FallbackIdentity`] so it travels with the
    /// cookies rather than only with a document.
    #[must_use]
    pub fn honoured_by(&self, identity: &FallbackIdentity) -> bool {
        *identity.user_agent() == self.user_agent
    }
}

/// A page a fallback fetched itself.
///
/// Enough to build a response that is honest about where it came from. The layer
/// marks it so, because telling a caller that a browser-fetched page was fetched
/// by Chromulate would misreport the one thing this whole module exists to be
/// straight about.
#[derive(Debug, Clone)]
pub struct Content {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    final_url: Url,
}

impl Content {
    /// Records a page the fallback retrieved.
    #[must_use]
    pub fn new(status: StatusCode, headers: HeaderMap, body: Bytes, final_url: Url) -> Self {
        Self {
            status,
            headers,
            body,
            final_url,
        }
    }

    /// The status the fallback saw.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers the fallback saw.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The page body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Where the fallback ended up, after whatever redirects it followed.
    #[must_use]
    pub fn final_url(&self) -> &Url {
        &self.final_url
    }

    /// Takes the parts apart to build a response from them.
    #[must_use]
    pub fn into_parts(self) -> (StatusCode, HeaderMap, Bytes, Url) {
        (self.status, self.headers, self.body, self.final_url)
    }
}

/// Who minted the session state a fallback is handing back.
///
/// This type exists because of a discontinuity that cannot be engineered away:
/// a clearance is earned under the fallback's TLS fingerprint, HTTP/2 settings
/// and script environment, and replayed under Chromulate's. Nothing in this
/// repository can make those the same. What it can do is record the identity at
/// the point where the mismatch is created, so that a caller debugging a
/// clearance that stopped working finds the answer next to the cookies rather
/// than in a design document.
///
/// Only the User-Agent is captured, because it is the only part a fallback can
/// state and this crate can check — [`Handoff::honoured_by`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackIdentity {
    fallback: Cow<'static, str>,
    user_agent: HeaderValue,
}

impl FallbackIdentity {
    /// Names the fallback and the User-Agent it actually browsed as.
    ///
    /// The name should carry a version where the fallback has one: "which
    /// browser build minted this" is the first question asked of a clearance
    /// that used to work.
    #[must_use]
    pub fn new(fallback: impl Into<Cow<'static, str>>, user_agent: HeaderValue) -> Self {
        Self {
            fallback: fallback.into(),
            user_agent,
        }
    }

    /// The fallback that produced the state.
    #[must_use]
    pub fn fallback(&self) -> &str {
        &self.fallback
    }

    /// The User-Agent it browsed as.
    #[must_use]
    pub fn user_agent(&self) -> &HeaderValue {
        &self.user_agent
    }
}

/// Why a fallback did not carry a challenge it was handed.
///
/// A decline is an answer, not a failure: the fallback ran and reported what
/// happened. A fallback that could not run at all — no browser installed, a
/// launch that failed, a crash — returns `Err` from
/// [`BrowserFallback::solve`] instead. The split matters because the two lead
/// somewhere different: a decline returns the challenge response to the caller,
/// which is the honest outcome, and an error is a middleware failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclineReason {
    /// The kind was not one this fallback claimed in
    /// [`BrowserFallback::handles`].
    UnsupportedKind(ChallengeKind),
    /// A human, or a service acting for one, must act, and this fallback does
    /// not ask people to do things.
    NeedsHuman,
    /// The budget in the [`Handoff`] ran out before the page cleared.
    BudgetExhausted,
    /// The fallback reached the page, did what it does, and the challenge was
    /// still there.
    NotCleared,
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKind(kind) => write!(f, "unsupported challenge kind: {kind}"),
            Self::NeedsHuman => f.write_str("challenge needs a human"),
            Self::BudgetExhausted => f.write_str("handoff budget exhausted"),
            Self::NotCleared => f.write_str("challenge was still present after the attempt"),
        }
    }
}

/// What the fallback achieved.
///
/// An enum rather than a struct of options, because the arms have different
/// contracts and a caller must not be able to mistake one for the other. The
/// first draft of this design put the page beside the cookies as an
/// `Option<Bytes>`, which ranked them exactly the wrong way round: the session
/// path is the speculative one and the content path is the one that cannot fail.
/// Splitting them buys three things.
///
/// 1. **The layer is useful either way.** If a clearance turns out to be bound to
///    the TLS identity that earned it, [`Handback::Session`] is dead and
///    [`Handback::Content`] is not.
/// 2. **The identity discontinuity is scoped.** Nothing minted by one browser is
///    presented by another on the `Content` path; the page came from the
///    fallback and is returned as the fallback's. The gap
///    [`FallbackIdentity`] exists to record belongs to `Session` alone.
/// 3. **The question is answered by the type.** "Did my session resume?" is a
///    `match`, not an inspection of which field happened to be populated.
#[derive(Debug, Clone)]
pub enum Handback {
    /// Session state was acquired. The layer applies it to the route the
    /// challenged request used and re-runs that request through the normal
    /// engine.
    Session {
        /// `Set-Cookie`-shaped lines, one per cookie, applied through
        /// [`CookieStore::store`](chromulate_core::CookieStore::store).
        ///
        /// `Set-Cookie` rather than a jar export for two reasons. The seam is in
        /// `chromulate-http`, which speaks the `CookieStore` trait and depends
        /// on no cookie implementation, so a jar type here would force every
        /// third-party fallback to link one. And going in through `store` means
        /// an imported cookie passes the same validation an origin's own
        /// `Set-Cookie` passes — the public suffix check, the prefix rules, the
        /// `Secure` overwrite rule — instead of the reduced set an import path
        /// applies.
        set_cookie: Vec<HeaderValue>,
        /// The page, if the browser happened to have it. Free when it does.
        content: Option<Content>,
        /// What identity minted these cookies.
        produced_by: FallbackIdentity,
    },
    /// The browser fetched the page. The layer returns it and learns nothing: no
    /// cookie is replayed, no session is resumed, no identity is mixed. This
    /// outcome always works, and it is the floor the feature stands on.
    Content(Content),
    /// Detected and not carried.
    Declined {
        /// Why.
        reason: DeclineReason,
    },
}

/// Solves a challenge in something that can run a browser.
///
/// The implementation is the caller's: a headless Chrome they drive, a
/// commercial service, a queue a human works through. This crate bundles none of
/// them and depends on none of them.
///
/// # The contract
///
/// - **Browse as the handed identity.** [`Handoff::user_agent`] is not advisory;
///   see the [`Handoff`] docs for why replaying a cookie under a different one is
///   worse than not clearing it at all.
/// - **Go out through the handed exit.** [`Handoff::exit`] names the address the
///   clearance must be bound to. Browsing through a different one earns a cookie
///   for the wrong client.
/// - **Answer within the budget.** [`Handoff::remaining`] is the caller's
///   patience; a fallback that overruns it is holding a request open.
/// - **Decline rather than guess.** A kind outside [`BrowserFallback::handles`]
///   should come back as [`Handback::Declined`], not as an empty
///   [`Handback::Session`].
/// - **Reserve `Err` for your own failure.** A challenge that could not be
///   cleared is a [`Handback`]; a browser that would not start is an `Err`.
pub trait BrowserFallback: Send + Sync + 'static {
    /// What to call this fallback in a log line.
    fn name(&self) -> &'static str;

    /// What this implementation claims it can carry.
    ///
    /// A fallback asked for a kind it did not claim is a caller error, and the
    /// layer will not ask.
    fn handles(&self) -> ChallengeKinds;

    /// Attempts the challenge.
    ///
    /// Takes the [`Handoff`] by value: it is built for this one attempt, it
    /// carries the cookies of one route, and reusing one across attempts would
    /// replay a stale `Cookie` header under a spent budget.
    fn solve<'a>(&'a self, handoff: Handoff) -> BoxFuture<'a, Result<Handback>>;
}

impl fmt::Debug for dyn BrowserFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BrowserFallback")
            .field(&self.name())
            .finish()
    }
}

/// When a handoff is allowed to happen at all, and how many may be in flight.
///
/// A loop guard stops a *repeat*; this decides whether the first one should have
/// happened. They are different questions, and the second one needs an answer
/// because a handoff launches a browser — the most expensive thing this library
/// can be made to do, by three orders of magnitude.
///
/// # Every bound here is a capacity, deliberately
///
/// `CLAUDE.md`: *a map keyed by server-controlled input carries a capacity*, and
/// a capacity of zero is raised to one because a store that cannot hold the entry
/// it was just handed is a silently disabled feature rather than a small one. The
/// set of origins a crawl challenges is chosen by the servers it visits, so:
///
/// - [`HandoffPolicy::budget`] and [`HandoffPolicy::window`] bound handoffs per
///   origin, and [`HandoffPolicy::tracked_origins`] is the capacity of the map
///   that counts them. Past it the least recently used origin's counter is
///   evicted, which loses a loop guard rather than growing without bound.
/// - [`HandoffPolicy::concurrency`] bounds browser processes globally. Single
///   flight collapses concurrent solves for *one* origin; across many origins and
///   several exits nothing collapses, and each solve is a browser. A global
///   semaphore is a few lines and its absence is a fork bomb with a browser in
///   it.
/// - A zero window is clamped to [`HandoffPolicy::MIN_WINDOW`] for the same
///   reason a zero capacity is raised to one: a window of no duration makes the
///   budget unenforceable, which is a disabled loop guard wearing the costume of
///   a configured one.
///
/// ```
/// use std::time::Duration;
///
/// use chromulate_http::challenge::HandoffPolicy;
///
/// // Nothing here can be configured into doing nothing.
/// let policy = HandoffPolicy::default()
///     .with_budget(0, Duration::ZERO)
///     .with_tracked_origins(0)
///     .with_concurrency(0);
///
/// assert_eq!(policy.budget(), 1);
/// assert_eq!(policy.window(), HandoffPolicy::MIN_WINDOW);
/// assert_eq!(policy.tracked_origins(), 1);
/// assert_eq!(policy.concurrency(), 1);
/// ```
#[derive(Clone)]
pub struct HandoffPolicy {
    eligible: Arc<dyn Fn(&Request) -> bool + Send + Sync>,
    budget: u32,
    window: Duration,
    tracked_origins: usize,
    concurrency: usize,
}

impl HandoffPolicy {
    /// Handoffs allowed per origin per [`HandoffPolicy::window`] by default.
    ///
    /// Two rather than one: the second is the retry that a clearance the origin
    /// refused makes necessary. A third inside the same window is a loop, and
    /// the honest response to a loop is to return the challenge.
    pub const DEFAULT_BUDGET: u32 = 2;

    /// The default window the budget is counted over.
    pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

    /// The shortest window the budget can be counted over.
    ///
    /// A zero-length window means every handoff starts a fresh count, which is
    /// the budget switched off by arithmetic rather than by a caller saying so.
    pub const MIN_WINDOW: Duration = Duration::from_secs(1);

    /// How many origins may hold a handoff counter at once, by default.
    pub const DEFAULT_TRACKED_ORIGINS: usize = 256;

    /// Browser processes alive at once, across every origin and every exit, by
    /// default.
    ///
    /// One. A caller who wants a second browser running has to say so, because
    /// the cost of being wrong here is measured in gigabytes and the cost of
    /// being conservative is measured in seconds.
    pub const DEFAULT_CONCURRENCY: usize = 1;

    /// Replaces the eligibility predicate.
    ///
    /// The default is described on [`HandoffPolicy::default`]; read it before
    /// replacing it, because the obvious replacement is narrower than it looks.
    #[must_use]
    pub fn with_eligible(
        mut self,
        eligible: impl Fn(&Request) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.eligible = Arc::new(eligible);
        self
    }

    /// Sets how many handoffs one origin gets per window.
    ///
    /// A budget of zero is raised to one and a window shorter than
    /// [`HandoffPolicy::MIN_WINDOW`] is raised to it. A caller who wants no
    /// handoffs at all installs no fallback.
    #[must_use]
    pub fn with_budget(mut self, budget: u32, window: Duration) -> Self {
        self.budget = budget.max(1);
        self.window = window.max(Self::MIN_WINDOW);
        self
    }

    /// Sets how many origins may hold a counter before the least recently used
    /// one is evicted. Zero is raised to one.
    #[must_use]
    pub fn with_tracked_origins(mut self, tracked_origins: usize) -> Self {
        self.tracked_origins = tracked_origins.max(1);
        self
    }

    /// Sets how many browsers may be solving at once, across everything. Zero is
    /// raised to one.
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Whether this request may be handed to a browser at all.
    #[must_use]
    pub fn is_eligible(&self, request: &Request) -> bool {
        (self.eligible)(request)
    }

    /// Handoffs allowed per origin per [`HandoffPolicy::window`].
    #[must_use]
    pub fn budget(&self) -> u32 {
        self.budget
    }

    /// The window the budget is counted over.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// How many origins may hold a handoff counter at once.
    #[must_use]
    pub fn tracked_origins(&self) -> usize {
        self.tracked_origins
    }

    /// How many browsers may be solving at once.
    #[must_use]
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }
}

impl Default for HandoffPolicy {
    /// The default eligibility is **`GET`, and not a subresource**.
    ///
    /// The design this implements said "GET, and a navigation
    /// (`Sec-Fetch-Mode: navigate`)". Written that way it is a feature that never
    /// fires. Every request built through the facade's `RequestBuilder` carries
    /// `RequestOptions::api()` — `crates/chromulate/src/request.rs:69`, inserted
    /// unconditionally at `:329` — whose mode is `FetchMode::Cors`. So a
    /// navigate-only default would refuse `client.get(url).send()`, which is what
    /// almost every caller writes, and the layer would sit installed and silent.
    ///
    /// That is the shape of this project's sharpest bug to date: a fix whose own
    /// tests all set a field, leaving the far more common absent-field path
    /// untested and broken (`CLAUDE.md`, "Test the default path"). So the default
    /// tests the *destination* instead, which is what the design's reasoning was
    /// actually about — "a challenged subresource is not a page a browser can
    /// usefully be pointed at". A document or an unspecified destination is a
    /// page; a script, an image, a stylesheet, a font or an iframe is not.
    ///
    /// `FetchDest` is `#[non_exhaustive]`, and the wildcard arm here refuses. A
    /// destination this build has never heard of does not get a browser launched
    /// at it.
    fn default() -> Self {
        Self {
            eligible: Arc::new(is_a_page_request),
            budget: Self::DEFAULT_BUDGET,
            window: Self::DEFAULT_WINDOW,
            tracked_origins: Self::DEFAULT_TRACKED_ORIGINS,
            concurrency: Self::DEFAULT_CONCURRENCY,
        }
    }
}

impl fmt::Debug for HandoffPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffPolicy")
            .field("budget", &self.budget)
            .field("window", &self.window)
            .field("tracked_origins", &self.tracked_origins)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

/// The default eligibility rule. See [`HandoffPolicy::default`].
fn is_a_page_request(request: &Request) -> bool {
    if request.method() != Method::GET {
        return false;
    }
    match request.extensions().get::<RequestOptions>() {
        // No fetch context at all: a bare `GET`, which is the address-bar-shaped
        // request as far as anything here can tell.
        None => true,
        Some(options) => matches!(options.dest, FetchDest::Document | FetchDest::Empty),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chromulate_core::Body;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("test url should parse")
    }

    fn origin(text: &str) -> Origin {
        Origin::of(&url(text)).expect("test url should have an origin")
    }

    fn agent() -> HeaderValue {
        HeaderValue::from_static("Mozilla/5.0 Chrome/151.0.0.0")
    }

    fn get(target: &str) -> Request {
        http::Request::builder()
            .method(Method::GET)
            .uri(target)
            .body(Body::empty())
            .expect("test request should build")
    }

    /// A detector that needs the body: `Suspect` until it has one.
    #[derive(Debug)]
    struct NeedsTheBody;

    impl ChallengeDetector for NeedsTheBody {
        fn inspect(&self, observation: &Observation<'_>) -> Detection {
            match observation.body_prefix() {
                None => Detection::Suspect,
                Some(prefix) if prefix.starts_with(b"<title>Just a moment") => {
                    // No `Origin::of` and no unreachable `Err` arm: the origin
                    // arrives with the observation.
                    Detection::Challenged(Challenge::new(
                        ChallengeKind::JsRequired,
                        observation.origin().clone(),
                        Evidence::from_signal("title: just a moment"),
                    ))
                }
                Some(_) => Detection::Clear,
            }
        }
    }

    #[test]
    fn an_observation_reports_what_was_seen_and_nothing_else() {
        let target = url("https://example.com/final");
        let mut headers = HeaderMap::new();
        headers.insert("cf-mitigated", HeaderValue::from_static("challenge"));
        let hops = [Hop::new(url("https://example.com/"), StatusCode::FOUND)];
        let source = origin("https://example.com/final");

        let observation = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &source)
            .with_hops(&hops)
            .with_body_prefix(b"<html>");

        assert_eq!(observation.status(), StatusCode::FORBIDDEN);
        assert_eq!(observation.url(), &target);
        assert_eq!(observation.origin(), &source);
        assert_eq!(observation.headers().len(), 1);
        assert_eq!(observation.hops(), hops.as_slice());
        assert_eq!(observation.body_prefix(), Some(b"<html>".as_slice()));
    }

    #[test]
    fn a_body_read_costs_nothing_until_a_detector_asks_for_one() {
        let target = url("https://example.com/");
        let headers = HeaderMap::new();
        let source = origin("https://example.com/");

        // First pass: no body has been read, and the three-arm `Detection` is
        // what lets the detector ask for one rather than the layer paying for
        // one on every response.
        let first = Observation::new(StatusCode::FORBIDDEN, &headers, &target, &source);
        assert_eq!(NeedsTheBody.inspect(&first), Detection::Suspect);

        let second = first.with_body_prefix(b"<title>Just a moment...</title>");
        let Detection::Challenged(challenge) = NeedsTheBody.inspect(&second) else {
            panic!("the prefix should have settled it");
        };
        assert_eq!(challenge.kind(), ChallengeKind::JsRequired);
        assert_eq!(challenge.origin(), &origin("https://example.com/"));
        assert_eq!(
            challenge.evidence().signals().collect::<Vec<_>>(),
            ["title: just a moment"]
        );

        // The third arm, on a body that turned out to be an ordinary page.
        let innocent = first.with_body_prefix(b"<html><body>hello");
        assert_eq!(NeedsTheBody.inspect(&innocent), Detection::Clear);
    }

    #[test]
    fn evidence_starts_empty_and_records_in_order() {
        assert!(Evidence::none().is_empty());

        let evidence = Evidence::from_signal("status: 403").with("body: challenge-platform");
        assert!(!evidence.is_empty());
        assert_eq!(
            evidence.signals().collect::<Vec<_>>(),
            ["status: 403", "body: challenge-platform"]
        );
    }

    #[test]
    fn a_claim_covers_what_was_claimed_and_no_more() {
        let claim = ChallengeKinds::none()
            .with(ChallengeKind::JsRequired)
            .with(ChallengeKind::JsRequired)
            | ChallengeKind::CookieRequired;

        assert!(claim.contains(ChallengeKind::JsRequired));
        assert!(claim.contains(ChallengeKind::CookieRequired));
        assert!(!claim.contains(ChallengeKind::Interactive));
        assert!(!claim.contains(ChallengeKind::Unknown));
        assert!(!claim.is_empty());
        assert!(ChallengeKinds::none().is_empty());
    }

    #[test]
    fn an_undetermined_kind_is_handed_off_rather_than_swallowed() {
        // The shipped shape: a header-only detector proves a challenge happened
        // and cannot say which kind, because the headers that announce one do
        // not describe it. That must reach a fallback.
        //
        // This is the case an earlier `ChallengeKind::Unsupported` variant got
        // wrong. Its documented contract was "a fallback is never handed one of
        // these", and it was the only kind the first real detector could
        // produce — so the shipped configuration detected every challenge and
        // handed off none of them.
        let undetermined = Challenge::new(
            ChallengeKind::Unknown,
            origin("https://example.com/"),
            Evidence::from_signal("cf-mitigated: challenge"),
        );

        // A browser fallback claims everything, and "everything" has no
        // footnote: pointing a browser at a page does not require knowing the
        // taxonomy first.
        assert!(ChallengeKinds::all().contains(undetermined.kind()));

        // A fallback that does need to know in advance says so itself, through
        // the one type that can carry that verdict — which is the fallback's,
        // not the detector's.
        let picky = ChallengeKinds::none().with(ChallengeKind::CookieRequired);
        assert!(!picky.contains(undetermined.kind()));
        assert_eq!(
            DeclineReason::UnsupportedKind(undetermined.kind()).to_string(),
            "unsupported challenge kind: unknown"
        );
    }

    #[test]
    fn each_kind_renders_as_its_own_name() {
        let rendered: Vec<String> = ChallengeKind::EVERY
            .into_iter()
            .map(|kind| kind.to_string())
            .collect();

        assert_eq!(
            rendered,
            ["js-required", "cookie-required", "interactive", "unknown"]
        );
        // A copy-pasted arm in `Display` renders two kinds the same, which is
        // invisible in a log line and exactly the sort of thing nobody reads.
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "two kinds render alike");
    }

    #[test]
    fn every_kind_has_its_own_bit_and_all_covers_them() {
        let all = ChallengeKinds::all();
        for kind in ChallengeKind::EVERY {
            assert!(all.contains(kind), "`all` should cover {kind}");
            // One bit each: a kind must not be covered by claiming a different
            // one, which is what a copy-pasted shift would produce.
            let only = ChallengeKinds::none().with(kind);
            for other in ChallengeKind::EVERY {
                assert_eq!(
                    only.contains(other),
                    other == kind,
                    "claiming {kind} should not imply {other}"
                );
            }
        }
    }

    #[test]
    fn a_proxy_exit_never_shows_a_password() {
        let exit = ProxyExit::new("http://alice:hunter2@127.0.0.1:8080");

        let debug = format!("{exit:?}");
        let display = format!("{exit}");
        for rendering in [&debug, &display, &exit.as_str().to_owned()] {
            assert!(!rendering.contains("alice"), "leaked the user: {rendering}");
            assert!(
                !rendering.contains("hunter2"),
                "leaked the password: {rendering}"
            );
        }
        assert_eq!(exit.as_str(), "http://***@127.0.0.1:8080");
        assert!(debug.contains("127.0.0.1:8080"), "{debug}");
    }

    #[test]
    fn redacting_a_label_the_engine_already_redacted_changes_nothing() {
        // `chromulate_proxy::ProxyUrl`'s `Display` is where the engine's session
        // key comes from, and this is its output. The exit must round-trip
        // through here unchanged, or a handback lands in a jar keyed by a label
        // nothing else uses.
        let label = "socks5://***@[::1]:1080";
        assert_eq!(ProxyExit::new(label).as_str(), label);

        let plain = "http://127.0.0.1:8080";
        assert_eq!(ProxyExit::new(plain).as_str(), plain);
        assert_eq!(ProxyExit::new(plain).label().as_ref(), plain);
    }

    #[test]
    fn a_handoff_carries_the_route_it_was_challenged_on() {
        let handoff = Handoff::new(
            url("https://example.com/page"),
            ChallengeKind::CookieRequired,
            agent(),
            Duration::from_secs(30),
        )
        .with_exit(Some(ProxyExit::new("http://bob:pw@10.0.0.1:3128")))
        .with_cookies(Some(HeaderValue::from_static("a=1; b=2")));

        assert_eq!(handoff.url(), &url("https://example.com/page"));
        assert_eq!(handoff.kind(), ChallengeKind::CookieRequired);
        assert_eq!(handoff.user_agent(), &agent());
        assert_eq!(
            handoff.exit().map(ProxyExit::as_str),
            Some("http://***@10.0.0.1:3128")
        );
        assert_eq!(
            handoff.cookies(),
            Some(&HeaderValue::from_static("a=1; b=2"))
        );

        // A direct request has no exit, and saying so must be possible without a
        // branch at the call site.
        let direct = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::JsRequired,
            agent(),
            Duration::from_secs(30),
        )
        .with_exit(None)
        .with_cookies(None);
        assert!(direct.exit().is_none());
        assert!(direct.cookies().is_none());
    }

    #[test]
    fn a_spent_budget_is_expired_and_a_fresh_one_is_not() {
        let spent = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::JsRequired,
            agent(),
            Duration::ZERO,
        );
        assert!(spent.is_expired());
        assert_eq!(spent.remaining(), Duration::ZERO);

        let fresh = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::JsRequired,
            agent(),
            Duration::from_secs(3600),
        );
        assert!(!fresh.is_expired());
        assert!(fresh.remaining() <= fresh.budget());
        assert!(fresh.remaining() > Duration::from_secs(3599));

        // Everything above is also true of a `remaining()` that ignores the
        // clock and hands back the budget it was given. Mutating it to do
        // exactly that left this test green, so the two cases above prove the
        // saturation and prove nothing about the subtraction. Only elapsed time
        // separates them, and the only way to have some elapse is to wait — five
        // milliseconds, against a budget three orders of magnitude larger, so
        // the assertion is about the clock moving rather than about how fast.
        let ticking = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::JsRequired,
            agent(),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(5));
        let left = ticking.remaining();
        assert!(
            left < Duration::from_secs(60),
            "the clock did not move: {left:?}"
        );
        assert!(
            left > Duration::from_secs(59),
            "far too much moved: {left:?}"
        );
    }

    #[test]
    fn a_fallback_that_browsed_as_itself_did_not_honour_the_handoff() {
        let handoff = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::JsRequired,
            agent(),
            Duration::from_secs(30),
        );

        let obedient = FallbackIdentity::new("mock 1.0", agent());
        assert!(handoff.honoured_by(&obedient));
        assert_eq!(obedient.fallback(), "mock 1.0");

        let wilful = FallbackIdentity::new(
            "mock 1.0",
            HeaderValue::from_static("Mozilla/5.0 Firefox/143.0"),
        );
        assert!(!handoff.honoured_by(&wilful));
    }

    #[test]
    fn a_session_handback_records_who_minted_it() {
        let handback = Handback::Session {
            set_cookie: vec![HeaderValue::from_static(
                "cf_clearance=abc; Path=/; Secure; HttpOnly",
            )],
            content: None,
            produced_by: FallbackIdentity::new("mock 1.0", agent()),
        };

        let Handback::Session {
            set_cookie,
            content,
            produced_by,
        } = handback
        else {
            panic!("built a session handback");
        };
        assert_eq!(set_cookie.len(), 1);
        // `Set-Cookie` shaped, not `Cookie` shaped: the attributes are the point,
        // and they are what `CookieStore::store` needs to scope the cookie.
        assert!(
            set_cookie[0]
                .to_str()
                .expect("test header is ascii")
                .contains("Path=/")
        );
        assert!(content.is_none());
        assert_eq!(produced_by.user_agent(), &agent());
    }

    #[test]
    fn a_content_handback_carries_a_whole_page() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        let content = Content::new(
            StatusCode::OK,
            headers,
            Bytes::from_static(b"<html>ok</html>"),
            url("https://example.com/after-redirect"),
        );

        assert_eq!(content.status(), StatusCode::OK);
        assert_eq!(content.headers().len(), 1);
        assert_eq!(content.body().as_ref(), b"<html>ok</html>");
        assert_eq!(
            content.final_url(),
            &url("https://example.com/after-redirect")
        );

        let Handback::Content(returned) = Handback::Content(content) else {
            panic!("built a content handback");
        };
        let (status, headers, body, final_url) = returned.into_parts();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.len(), 1);
        assert_eq!(body.len(), 15);
        assert_eq!(final_url.path(), "/after-redirect");
    }

    #[test]
    fn a_decline_says_which_kind_of_no_it_is() {
        let reasons = [
            (
                DeclineReason::UnsupportedKind(ChallengeKind::Interactive),
                "unsupported challenge kind: interactive",
            ),
            (DeclineReason::NeedsHuman, "challenge needs a human"),
            (DeclineReason::BudgetExhausted, "handoff budget exhausted"),
            (
                DeclineReason::NotCleared,
                "challenge was still present after the attempt",
            ),
        ];

        for (reason, rendered) in reasons {
            assert_eq!(reason.to_string(), rendered);
            let Handback::Declined { reason: carried } = (Handback::Declined {
                reason: reason.clone(),
            }) else {
                panic!("built a declined handback");
            };
            assert_eq!(carried, reason);
        }
    }

    #[test]
    fn no_bound_in_the_policy_can_be_configured_down_to_nothing() {
        let policy = HandoffPolicy::default()
            .with_budget(0, Duration::ZERO)
            .with_tracked_origins(0)
            .with_concurrency(0);

        assert_eq!(policy.budget(), 1);
        assert_eq!(policy.window(), HandoffPolicy::MIN_WINDOW);
        assert_eq!(policy.tracked_origins(), 1);
        assert_eq!(policy.concurrency(), 1);
    }

    #[test]
    fn the_policy_keeps_the_bounds_a_caller_did_choose() {
        let policy = HandoffPolicy::default()
            .with_budget(5, Duration::from_secs(60))
            .with_tracked_origins(8)
            .with_concurrency(3);

        assert_eq!(policy.budget(), 5);
        assert_eq!(policy.window(), Duration::from_secs(60));
        assert_eq!(policy.tracked_origins(), 8);
        assert_eq!(policy.concurrency(), 3);
        assert_eq!(
            HandoffPolicy::default().budget(),
            HandoffPolicy::DEFAULT_BUDGET
        );
        assert_eq!(
            HandoffPolicy::default().window(),
            HandoffPolicy::DEFAULT_WINDOW
        );
    }

    #[test]
    fn the_default_policy_accepts_the_request_the_facade_actually_builds() {
        let policy = HandoffPolicy::default();

        // The path almost every caller takes: `client.get(url).send()`. The
        // facade attaches `RequestOptions::api()` unconditionally
        // (`crates/chromulate/src/request.rs:69`, inserted at `:329`), so its
        // mode is `Cors` and its destination is `Empty`. A default that asked
        // for `Sec-Fetch-Mode: navigate` would refuse this, and the layer would
        // never fire for anyone.
        let mut facade = get("https://example.com/");
        facade.extensions_mut().insert(RequestOptions::api());
        assert!(policy.is_eligible(&facade));

        // And the same request with no fetch context at all.
        assert!(policy.is_eligible(&get("https://example.com/")));

        // And an explicit navigation.
        let mut navigation = get("https://example.com/");
        navigation
            .extensions_mut()
            .insert(RequestOptions::navigation());
        assert!(policy.is_eligible(&navigation));
    }

    #[test]
    fn the_default_policy_refuses_what_a_browser_cannot_be_pointed_at() {
        let policy = HandoffPolicy::default();

        for dest in [
            FetchDest::Script,
            FetchDest::Style,
            FetchDest::Image,
            FetchDest::Font,
            FetchDest::Iframe,
        ] {
            let mut subresource = get("https://example.com/asset");
            let mut options = RequestOptions::api();
            options.dest = dest;
            subresource.extensions_mut().insert(options);
            assert!(
                !policy.is_eligible(&subresource),
                "{dest:?} is not a page a browser can be handed"
            );
        }

        let post = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/login")
            .body(Body::empty())
            .expect("test request should build");
        assert!(!policy.is_eligible(&post));
    }

    #[test]
    fn a_caller_can_replace_the_eligibility_rule_entirely() {
        let policy = HandoffPolicy::default()
            .with_eligible(|request: &Request| request.uri().path().starts_with("/product/"));

        assert!(policy.is_eligible(&get("https://example.com/product/1")));
        assert!(!policy.is_eligible(&get("https://example.com/")));

        // Replacing eligibility must not disturb the bounds.
        assert_eq!(policy.budget(), HandoffPolicy::DEFAULT_BUDGET);
        assert_eq!(policy.concurrency(), HandoffPolicy::DEFAULT_CONCURRENCY);
    }

    #[test]
    fn a_hop_records_the_url_that_was_asked_and_the_answer() {
        let hop = Hop::new(url("https://example.com/a"), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(hop.url().path(), "/a");
        assert_eq!(hop.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            hop,
            Hop::new(url("https://example.com/a"), StatusCode::MOVED_PERMANENTLY)
        );
    }

    #[test]
    fn the_trait_objects_are_debuggable_without_naming_their_implementations() {
        #[derive(Debug)]
        struct Mock;

        impl BrowserFallback for Mock {
            fn name(&self) -> &'static str {
                "mock"
            }

            fn handles(&self) -> ChallengeKinds {
                ChallengeKinds::all()
            }

            fn solve<'a>(&'a self, _handoff: Handoff) -> BoxFuture<'a, Result<Handback>> {
                Box::pin(async move {
                    Ok(Handback::Declined {
                        reason: DeclineReason::NotCleared,
                    })
                })
            }
        }

        let fallback: Arc<dyn BrowserFallback> = Arc::new(Mock);
        assert_eq!(format!("{:?}", &*fallback), r#"BrowserFallback("mock")"#);

        let detector: Arc<dyn ChallengeDetector> = Arc::new(NeedsTheBody);
        assert_eq!(format!("{:?}", &*detector), "ChallengeDetector");
    }

    #[tokio::test]
    async fn a_fallback_is_driven_through_a_boxed_future() {
        #[derive(Debug)]
        struct OnlyCookies;

        impl BrowserFallback for OnlyCookies {
            fn name(&self) -> &'static str {
                "only-cookies"
            }

            fn handles(&self) -> ChallengeKinds {
                ChallengeKinds::none().with(ChallengeKind::CookieRequired)
            }

            fn solve<'a>(&'a self, handoff: Handoff) -> BoxFuture<'a, Result<Handback>> {
                Box::pin(async move {
                    if !self.handles().contains(handoff.kind()) {
                        return Ok(Handback::Declined {
                            reason: DeclineReason::UnsupportedKind(handoff.kind()),
                        });
                    }
                    Ok(Handback::Session {
                        set_cookie: vec![HeaderValue::from_static("cf_clearance=abc; Path=/")],
                        content: None,
                        // Honouring the handed identity is the contract, and
                        // this is what honouring it looks like.
                        produced_by: FallbackIdentity::new(
                            "only-cookies 1.0",
                            handoff.user_agent().clone(),
                        ),
                    })
                })
            }
        }

        let fallback: Arc<dyn BrowserFallback> = Arc::new(OnlyCookies);
        let handoff = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::CookieRequired,
            agent(),
            Duration::from_secs(30),
        );

        let handback = fallback
            .solve(handoff.clone())
            .await
            .expect("the mock cannot fail");
        let Handback::Session { produced_by, .. } = handback else {
            panic!("a claimed kind should not be declined");
        };
        assert!(handoff.honoured_by(&produced_by));

        let unclaimed = Handoff::new(
            url("https://example.com/"),
            ChallengeKind::Interactive,
            agent(),
            Duration::from_secs(30),
        );
        let handback = fallback
            .solve(unclaimed)
            .await
            .expect("the mock cannot fail");
        assert!(matches!(
            handback,
            Handback::Declined {
                reason: DeclineReason::UnsupportedKind(ChallengeKind::Interactive)
            }
        ));
    }
}
