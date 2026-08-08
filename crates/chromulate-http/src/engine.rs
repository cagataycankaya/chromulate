//! The engine: one logical request in, one response out, however many
//! connections and hops that took.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use chromulate_compression::ExpansionGuard;
use chromulate_core::{
    Body, BoxFuture, CookieStore, Error, Exchange, Middleware, Next, Origin, Phase, RedirectPolicy,
    Request, RequestOptions, Resolve, Response, Result, Timings,
};
use chromulate_dns::{CachingResolver, SystemResolver};
use chromulate_header::{AcceptChStore, HeaderEngine};
use chromulate_profile::Profile;
use chromulate_proxy::ProxyProvider;
use chromulate_tls::{ActiveBackend, TlsBackendConfig};
use http::header::SET_COOKIE;
use http::{HeaderName, HeaderValue};
use tracing::Instrument as _;
use url::Url;

use crate::body::{bounded_by, from_incoming, returning_to_pool};
use crate::challenge::Hop;
use crate::connect::{Connector, Route};
use crate::deadline::Deadline;
use crate::http2::Http2Fidelity;
use crate::middleware::Retry;
use crate::pool::{Connection, ConnectionIdentity, Pool, PoolConfig, PoolKey, Protocol};
use crate::redirect::{self, Decision};
use crate::session::{ProxyIsolation, RouteSession, Session, SessionFactory, Sessions};

/// How much of a redirect response body is read before its connection is
/// reused.
///
/// A redirect body is discarded, but an HTTP/1.1 connection cannot be reused
/// until the body has been read off the socket. Draining an unbounded body to
/// save one handshake is a bad trade, so a large redirect body costs the
/// connection instead.
const REDIRECT_DRAIN_LIMIT: u64 = 64 * 1024;

/// What the cache asked to have carried from before a hop to after it.
///
/// A type alias with two definitions, so the two calls in the redirect loop are
/// written once. With the `cache` feature off it is `()`, both calls are
/// `#[inline]` identity functions, and nothing of `chromulate-cache` is linked.
#[cfg(feature = "cache")]
type CachePending = chromulate_cache::Pending;
#[cfg(not(feature = "cache"))]
type CachePending = ();

/// A response the cache could serve without an exchange.
///
/// `Option<Infallible>` rather than `Option<Response>` when the feature is off,
/// and the difference is not cosmetic: this value is the scrutinee of a `match`
/// whose other arm awaits the network, and a `match` keeps its scrutinee alive
/// across that await. Typed as `Option<Response>` it put a whole response head
/// into every request's future — 152 bytes on the measured build, for a
/// variant that cannot exist. Typing the impossible case as impossible is what
/// keeps the allocation harness's byte figure where it was.
#[cfg(feature = "cache")]
type CacheHit = Option<Response>;
#[cfg(not(feature = "cache"))]
type CacheHit = Option<std::convert::Infallible>;

/// Unwraps a cache hit into the response to return.
///
/// With the feature off the argument is uninhabited, so the arm that calls this
/// is unreachable and the compiler knows it.
#[cfg(feature = "cache")]
#[inline]
fn cache_hit(response: Response) -> Response {
    response
}

#[cfg(not(feature = "cache"))]
#[inline]
fn cache_hit(never: std::convert::Infallible) -> Response {
    match never {}
}

/// What the engine learned while producing a response, placed in the
/// response's extensions.
///
/// One extension carrying four facts rather than four extensions carrying one
/// each: [`http::Extensions`] boxes every value it stores, so a second insert
/// is a second heap allocation on a path whose per-request allocation count is
/// a published figure.
///
/// `#[non_exhaustive]`, so the next fact the engine learns to report is not a
/// source break for everyone. It became so late: `hops` and `exit` were added
/// after release, and a caller who had written a struct literal would have had
/// to edit it. Read the fields; do not construct one.
///
/// # What `hops` and `exit` cost, measured
///
/// `cargo run --release -p chromulate-bench --bin allocs`, steady state, a
/// request that does not redirect, three runs of each variant and every run
/// byte-identical:
///
/// | variant | allocations | bytes |
/// | --- | --- | --- |
/// | before the two fields existed | 48 | 20,807 |
/// | the two fields, never populated | 48 | 20,839 |
/// | as shipped | 48 | 20,895 |
/// | as shipped, with the chain boxed | 48 | 20,879 |
///
/// **The allocation count does not move.** Forty-eight is the figure `README.md`,
/// `docs/performance.md` and the design document all publish, and it is what
/// [`ResponseInfo::hops`] being an `Option` rather than a `Vec` buys: the
/// no-redirect path builds no collection, so there is no new allocation to
/// count.
///
/// The eighty-eight bytes are the price, and they split in two:
///
/// - **thirty-two** are this struct. [`http::Extensions`] boxes every value it
///   stores, so the one box grew by two `Option<Arc<…>>` at sixteen bytes each.
///   That is the row above with the fields present and never filled, and it is
///   structural — any public two-field shape pays it.
/// - **fifty-six** are the request's future. [`Engine::exchange`] does
///   `Box::pin(self.run(request))`, so `run()`'s frame is itself a per-request
///   heap allocation, and the chain and the exit have to live in it across the
///   network await.
///
/// **A rejected alternative, recorded with its number rather than omitted:**
/// holding the chain as `Option<Box<Vec<Hop>>>` shrinks the future and returns
/// sixteen of those fifty-six bytes — the last row above. It was not taken. It
/// buys them with an extra allocation every time a redirect *is* followed,
/// which spends the metric this project publishes to save one it does not, and
/// it makes the accumulation read worse at the one place it happens.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResponseInfo {
    /// The URL that produced the response.
    ///
    /// After a redirect chain this is not the URL the caller asked for, and a
    /// caller resolving relative links out of the body needs the one that
    /// actually answered.
    pub url: Url,
    /// Where the request spent its time.
    pub timings: Timings,
    /// The redirects that led here, oldest first, or `None` when the request
    /// was answered without one.
    ///
    /// `Option<Arc<[Hop]>>` rather than `Vec<Hop>`, and the difference is the
    /// whole reason this field could be added at all. `None` is not an empty
    /// `Vec`: the no-redirect path — the common one — never constructs a
    /// collection, so it pays no allocation for a chain it does not have, and a
    /// `Vec<Hop>` here would have charged every request for the minority that
    /// redirect. The measurement is in this struct's own documentation, above.
    ///
    /// The URL that finally answered is [`ResponseInfo::url`] and is not
    /// repeated here, so the whole journey is `hops` followed by `url`.
    pub hops: Option<Arc<[Hop]>>,
    /// The proxy exit the answering request went out through, or `None` for a
    /// direct request.
    ///
    /// This is the *same* `Arc<str>` the engine keys per-route state by, not a
    /// label rebuilt to look like it, so handing it back to
    /// [`Engine::with_session`] reaches exactly the session that learned what
    /// this response taught. Nothing has to be reconstructed and nothing can be
    /// reconstructed wrongly — which matters because cookies, client-hint
    /// grants and validators belong to the exit they were taught through, and
    /// putting them somewhere else is silent when it goes wrong. Credentials
    /// are already redacted: this is the label [`crate::pool::PoolKey`] carries.
    ///
    /// It reports the last hop's route, not the first. A redirect chain may
    /// change exits, and the exit that answered is the one whose session the
    /// response taught.
    pub exit: Option<Arc<str>>,
}

/// The request's already-parsed URL, placed in the request's extensions by a
/// caller that has one, so [`Engine`] does not re-parse the `Uri` it was built
/// from.
///
/// Optional: a request without this extension works identically, at the cost
/// of one URL parse. The engine takes it out at the start of the run — after
/// a redirect it would describe the wrong hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUrl(pub Url);

/// The engine's own settings, separate from anything one request carries.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The identity every connection is opened with.
    pub profile: Arc<Profile>,
    /// Deadline for a whole request, redirects included.
    ///
    /// `None` by default, and deliberately: a large download, a streamed
    /// response and an SSE stream all run for as long as they run, and no
    /// default could tell one of those from a hang.
    pub timeout: Option<Duration>,
    /// Deadline for producing a response head on one hop.
    ///
    /// `Some(30s)` by default. A response head has a natural bound whatever the
    /// body ends up costing, so this is what stops a server that accepts a
    /// connection and then says nothing, without putting a ceiling on a
    /// download.
    ///
    /// Set it to `None` for long polling, or for anything else that withholds
    /// the head until an event fires. There the silence is the protocol, and a
    /// deadline on it is a bug.
    pub head_timeout: Option<Duration>,
    /// Deadline for establishing a connection.
    ///
    /// `Some(30s)` by default.
    pub connect_timeout: Option<Duration>,
    /// What to do with 3xx responses.
    pub redirect: RedirectPolicy,
    /// Connection pool limits.
    pub pool: PoolConfig,
}

impl EngineConfig {
    /// Defaults for a profile.
    ///
    /// Two of the three timeouts are on, both at thirty seconds:
    /// [`connect_timeout`] and [`head_timeout`]. Between them a server can no
    /// longer hold a request open by accepting a connection and then going
    /// quiet. [`timeout`], the bound on a whole request, stays off; see its own
    /// documentation for why, and [`head_timeout`]'s for the one protocol that
    /// wants the head wait switched off too.
    ///
    /// [`connect_timeout`]: EngineConfig::connect_timeout
    /// [`head_timeout`]: EngineConfig::head_timeout
    /// [`timeout`]: EngineConfig::timeout
    #[must_use]
    pub fn new(profile: Arc<Profile>) -> Self {
        Self {
            profile,
            timeout: None,
            // Thirty to match `connect_timeout` below: two bounds a caller has
            // to reason about together are easier to hold as one number.
            head_timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(30)),
            redirect: RedirectPolicy::default(),
            pool: PoolConfig::default(),
        }
    }
}

/// Assembles an [`Engine`].
pub struct EngineBuilder {
    config: EngineConfig,
    tls: Option<ActiveBackend>,
    resolver: Option<Arc<dyn Resolve>>,
    proxies: Option<Arc<dyn ProxyProvider>>,
    cookies: Option<Arc<dyn CookieStore>>,
    middleware: Vec<Arc<dyn Middleware>>,
    decompression: Option<ExpansionGuard>,
    pool: Option<Pool>,
    retry: Option<Retry>,
    isolation: Option<(usize, Arc<dyn SessionFactory>)>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<chromulate_cache::HttpCache>>,
    #[cfg(feature = "validator-store")]
    validators: Option<Arc<crate::validators::ValidatorStore>>,
    concurrency: Option<Arc<dyn crate::concurrency::ConcurrencyController>>,
}

impl fmt::Debug for EngineBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("config", &self.config)
            .field("middleware", &self.middleware.len())
            .finish_non_exhaustive()
    }
}

impl EngineBuilder {
    /// Starts from a configuration.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            tls: None,
            resolver: None,
            proxies: None,
            cookies: None,
            middleware: Vec::new(),
            decompression: None,
            pool: None,
            retry: None,
            isolation: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "validator-store")]
            validators: None,
            concurrency: None,
        }
    }

    /// Uses a TLS engine other than the one the profile would build.
    #[must_use]
    pub fn tls(mut self, tls: ActiveBackend) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Uses a specific resolver.
    #[must_use]
    pub fn resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Routes requests through a proxy provider.
    #[must_use]
    pub fn proxies(mut self, proxies: Arc<dyn ProxyProvider>) -> Self {
        self.proxies = Some(proxies);
        self
    }

    /// Stores and replays cookies.
    #[must_use]
    pub fn cookies(mut self, cookies: Arc<dyn CookieStore>) -> Self {
        self.cookies = Some(cookies);
        self
    }

    /// Adds a middleware to the end of the chain.
    #[must_use]
    pub fn middleware(mut self, middleware: Arc<dyn Middleware>) -> Self {
        self.middleware.push(middleware);
        self
    }

    /// Sets the decompression limits.
    #[must_use]
    pub fn decompression(mut self, guard: ExpansionGuard) -> Self {
        self.decompression = Some(guard);
        self
    }

    /// Shares an existing connection pool.
    ///
    /// Only share a pool between engines whose TLS configuration matches:
    /// [`PoolKey`] covers the profile identity, which is what a server
    /// observes, not the trust store, which it does not.
    #[must_use]
    pub fn pool(mut self, pool: Pool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Retries failed requests.
    ///
    /// Installed beneath the middleware chain rather than in it, because
    /// [`chromulate_core::Next`] is consumed by `run` and cannot be taken
    /// twice — see [`crate::middleware::retry`]. One retry therefore re-runs a
    /// whole logical request including its redirect chain, and every attempt is
    /// visible to the middleware above it.
    #[must_use]
    pub fn retry(mut self, retry: Retry) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Gives every proxy its own cookies, client-hint grants and — with the
    /// `validator-store` feature — its own validators, up to `max_routes` exits
    /// at a time.
    ///
    /// **An engine that never calls this shares one session across every
    /// route**, which is what it did before this existed and what a caller
    /// rotating exits purely to spread load on one logged-in site wants. What
    /// isolation buys is the other case: a caller who configured several exits
    /// to spread traffic across several addresses, and whose one session
    /// otherwise couples those addresses together for the origin.
    ///
    /// The base session — whatever [`EngineBuilder::cookies`] and
    /// [`EngineBuilder::validators`] were handed — keeps serving requests that
    /// go through no proxy at all. Every proxy gets state minted by `sessions`;
    /// see [`SessionFactory`] for why this crate cannot mint a cookie store
    /// itself.
    ///
    /// Read [`ProxyIsolation`]'s documentation for what isolation does *not*
    /// cover: TLS session tickets are not split per route.
    ///
    /// # Bound
    ///
    /// `max_routes` is what stops one bounded store becoming an unbounded
    /// family of them. Past it the least recently used exit's state is dropped
    /// and its next request starts a fresh session — loud and recoverable,
    /// rather than silently borrowing another exit's. A `max_routes` of zero is
    /// raised to one.
    #[must_use]
    pub fn isolate_by_proxy(
        mut self,
        max_routes: usize,
        sessions: Arc<dyn SessionFactory>,
    ) -> Self {
        self.isolation = Some((max_routes, sessions));
        self
    }

    /// Serves and stores responses through an RFC 9111 cache.
    ///
    /// Requires the off-by-default `cache` feature, and a direct dependency on
    /// `chromulate-cache` to name the type.
    ///
    /// The cache is consulted **per hop**, not per logical request, because a
    /// cache key is one target URI: a `301` and the resource it points at are
    /// two entries, and a cached redirect is followed exactly as a fresh one
    /// would be. A hop served from store contacts no origin, so it records no
    /// cookies, no HSTS policy, and no connection timings — there was no
    /// exchange to record.
    ///
    /// Read [`chromulate_cache`]'s list of what the cache deliberately does not
    /// implement before turning this on.
    #[cfg(feature = "cache")]
    #[must_use]
    pub fn cache(mut self, cache: Arc<chromulate_cache::HttpCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Remembers response validators and replays them as conditional requests.
    ///
    /// This is deliberately not browser behaviour: a browser does not revalidate
    /// a response it was told not to store. Read
    /// [`ValidatorStore`](crate::validators::ValidatorStore)'s documentation,
    /// which states the divergence and its measured reach, before turning it on.
    #[cfg(feature = "validator-store")]
    #[must_use]
    pub fn validators(mut self, validators: Arc<crate::validators::ValidatorStore>) -> Self {
        self.validators = Some(validators);
        self
    }

    /// Decides how many requests to one origin may be in flight at once.
    ///
    /// The engine asks this for permission before each hop and reports the
    /// outcome against it afterwards; it holds no opinion of its own about what
    /// a limit should be, and this crate ships no control law to hold one with.
    /// Anything implementing
    /// [`ConcurrencyController`](crate::concurrency::ConcurrencyController) goes
    /// here; the `chromulate-concurrency` crate publishes two —
    /// `AdaptiveConcurrency`, which learns a limit per origin from latency and
    /// treats a `429` as a one-way ratchet, and `FixedConcurrency`, which bounds
    /// in-flight requests per origin at a number and never moves it. Both take a
    /// ceiling that cannot be defaulted away, so a caller's rate limit reaches
    /// them by construction.
    ///
    /// Leaving this unset is not the same as installing
    /// [`Unlimited`](crate::concurrency::Unlimited): both send everything
    /// immediately, but an installed controller pays the seam's erasure — one
    /// boxed future and one boxed lease — on every hop.
    ///
    /// A controller runs *below* the middleware chain, so a
    /// [`RateLimiter`](crate::middleware::RateLimiter) the caller installed has
    /// already been paid before one is consulted, and no controller can send a
    /// request the limiter has not released.
    #[must_use]
    pub fn concurrency(
        mut self,
        concurrency: Arc<dyn crate::concurrency::ConcurrencyController>,
    ) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Builds the engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile cannot produce a TLS
    /// configuration, or when [`EngineBuilder::isolate_by_proxy`] is combined
    /// with a response cache — see the message for why one cache cannot serve
    /// isolated routes.
    pub fn build(self) -> Result<Engine> {
        #[cfg(feature = "cache")]
        if self.isolation.is_some() && self.cache.is_some() {
            // Not a limitation of the wiring: one cache genuinely cannot serve
            // isolated routes. A stale entry revalidates with the validator the
            // origin issued to whichever exit stored it, which is the same
            // linking signal `ValidatorStore` is split to remove, and a private
            // cache stores authenticated responses, so an exit would be served
            // a body fetched with another exit's session. Refusing is louder
            // than sharing one silently, which is the failure this whole change
            // is about.
            return Err(Error::config(
                "a response cache cannot be shared between isolated proxy routes: a stale entry \
                 would revalidate with a validator the origin issued to another exit, and a \
                 stored private response would be served to an exit that never fetched it. Build \
                 one engine per proxy, or drop `isolate_by_proxy`.",
            ));
        }

        let profile = Arc::clone(&self.config.profile);
        let tls = match self.tls {
            Some(tls) => tls,
            None => ActiveBackend::from_profile(&profile)?,
        };
        let resolver = self.resolver.unwrap_or_else(|| {
            Arc::new(CachingResolver::with_default_ttls(SystemResolver::new())) as Arc<dyn Resolve>
        });
        let pool = self.pool.unwrap_or_else(|| Pool::new(self.config.pool));

        let connector = Connector::new(
            Arc::clone(&profile),
            tls,
            resolver,
            self.proxies,
            self.config.connect_timeout,
            self.config.pool.http1_max_buf_size,
        );

        let sessions = match self.isolation {
            Some((max_routes, factory)) => Sessions::per_proxy(
                self.cookies,
                #[cfg(feature = "validator-store")]
                self.validators,
                max_routes,
                factory,
            ),
            None => Sessions::shared(
                self.cookies,
                #[cfg(feature = "validator-store")]
                self.validators,
            ),
        };

        Ok(Engine {
            inner: Arc::new(EngineInner {
                headers: HeaderEngine::new(Arc::clone(&profile)),
                hsts: RwLock::new(crate::hsts::HstsStore::new()),
                accept_ch_used: std::sync::atomic::AtomicBool::new(false),
                decompression: self.decompression.unwrap_or_default(),
                sessions,
                middleware: self.middleware,
                retry: self.retry,
                #[cfg(feature = "cache")]
                cache: self.cache,
                concurrency: self.concurrency,
                config: self.config,
                connector,
                pool,
                profile,
            }),
        })
    }
}

/// The HTTP engine.
///
/// Cheap to clone; clones share the connection pool, the cookie store, and the
/// TLS session cache.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    config: EngineConfig,
    profile: Arc<Profile>,
    connector: Connector,
    pool: Pool,
    headers: HeaderEngine,
    /// Origins that have demanded HTTPS; see [`crate::hsts`].
    ///
    /// Deliberately **not** per route. It is a policy about an origin rather
    /// than about this client, and it is consulted before a route exists at
    /// all: the upgrade rewrites the scheme, which changes the port, which
    /// changes the origin the proxy is chosen for. Splitting it would also send
    /// the first request through each new exit in plaintext, which is a
    /// downgrade rather than an isolation win. See [`crate::session`].
    hsts: RwLock<crate::hsts::HstsStore>,
    /// Whether any response, on any route, has ever recorded an `Accept-CH`
    /// grant.
    ///
    /// Most deployments never see one, and `RwLock::read` is still an atomic
    /// read-modify-write on a shared cache line — coherence traffic on every
    /// request that scales with worker count. This flag is a plain read; the
    /// lock is only touched once a grant exists. It never goes back to false:
    /// a revoked grant leaves an empty store behind the lock, which reads
    /// correctly, just no longer lock-free.
    ///
    /// It stays engine-wide while the stores it gates are per route, because it
    /// is only a hint about whether looking is worth it. A route that has been
    /// granted nothing takes its own empty lock and finds nothing, which costs
    /// a little and cannot answer wrongly.
    accept_ch_used: std::sync::atomic::AtomicBool,
    /// The cookies, client-hint grants and validators of every route this
    /// engine serves; see [`crate::session`].
    sessions: Sessions,
    decompression: ExpansionGuard,
    middleware: Vec<Arc<dyn Middleware>>,
    retry: Option<Retry>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<chromulate_cache::HttpCache>>,
    concurrency: Option<Arc<dyn crate::concurrency::ConcurrencyController>>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("profile", &self.inner.profile.name)
            .field("identity", self.inner.connector.identity())
            .field("pool", &self.inner.pool)
            .field("sessions", &self.inner.sessions)
            .field("middleware", &self.inner.middleware.len())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Starts a builder.
    #[must_use]
    pub fn builder(config: EngineConfig) -> EngineBuilder {
        EngineBuilder::new(config)
    }

    /// The profile every connection is opened with.
    #[must_use]
    pub fn profile(&self) -> &Arc<Profile> {
        &self.inner.profile
    }

    /// The connection pool.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.inner.pool
    }

    /// The response cache, when one was installed.
    ///
    /// The way to reach [`chromulate_cache::HttpCache::invalidate`] for a
    /// caller that knows a target has changed by some route this engine did
    /// not see.
    #[cfg(feature = "cache")]
    #[must_use]
    pub fn cache(&self) -> Option<&Arc<chromulate_cache::HttpCache>> {
        self.inner.cache.as_ref()
    }

    /// What separates this engine's connections from another engine's.
    #[must_use]
    pub fn identity(&self) -> &ConnectionIdentity {
        self.inner.connector.identity()
    }

    /// Whether each proxy keeps its own cookies, client-hint grants and
    /// validators, or whether every route shares one session.
    #[must_use]
    pub fn proxy_isolation(&self) -> ProxyIsolation {
        self.inner.sessions.isolation()
    }

    /// How many proxies currently hold state of their own.
    ///
    /// Always zero under [`ProxyIsolation::Shared`], and never more than the
    /// `max_routes` this engine was built with.
    #[must_use]
    pub fn isolated_routes(&self) -> usize {
        self.inner.sessions.isolated_routes()
    }

    /// The TLS engine, whose `fidelity()` reports the handshake gap.
    #[must_use]
    pub fn tls(&self) -> &ActiveBackend {
        self.inner.connector.tls()
    }

    /// What the profile's HTTP/2 preface asks for that hyper cannot send.
    #[must_use]
    pub fn http2_fidelity(&self) -> &Http2Fidelity {
        self.inner.connector.http2_fidelity()
    }

    /// Sends a request through the middleware chain and then the network.
    ///
    /// # Errors
    ///
    /// Returns whatever the chain or the transport produced.
    pub async fn send(&self, request: Request) -> Result<Response> {
        let terminal: &dyn Exchange = self;
        match &self.inner.retry {
            Some(retry) => {
                let retrying = retry.wrap(terminal);
                Next::new(&self.inner.middleware, &retrying)
                    .run(request)
                    .await
            }
            None => {
                Next::new(&self.inner.middleware, terminal)
                    .run(request)
                    .await
            }
        }
    }

    /// Follows the redirect chain for one logical request.
    async fn run(&self, mut request: Request) -> Result<Response> {
        let mut timings = Timings::starting_now();
        let options = request
            .extensions()
            .get::<RequestOptions>()
            .cloned()
            .unwrap_or_default();

        let mut url = match request.extensions_mut().remove::<RequestUrl>() {
            Some(RequestUrl(parsed)) => parsed,
            None => url_of(request.uri())?,
        };
        // Before anything is sent. A browser that has seen HSTS from an origin
        // never speaks plaintext to it, and the whole point is that the
        // plaintext request is not made — a redirect would already be too late.
        self.apply_hsts(&mut url);
        let deadline = Deadline::starting_now(options.timeout.or(self.inner.config.timeout));
        let limit = match effective_policy(&options, self.inner.config.redirect) {
            RedirectPolicy::Follow { limit } => Some(limit),
            // `RedirectPolicy` is non-exhaustive; anything this build does not
            // know how to follow is treated as "do not follow", which returns
            // the 3xx to the caller rather than guessing at a new variant.
            _ => None,
        };

        // `None` rather than an empty `Vec`, and the count derived from it
        // rather than tracked beside it. The first costs the no-redirect path
        // nothing — no collection is built for a chain that never happens. The
        // second removes a counter that could disagree with the chain it is
        // supposed to describe: `chain.len()` *is* how many redirects have been
        // followed, so the redirect limit and the span's hop number cannot
        // drift from what `ResponseInfo::hops` reports.
        let mut chain: Option<Vec<Hop>> = None;
        // The exit the most recent hop went out through. Overwritten per hop
        // because a redirect chain may change route, and it is the exit that
        // *answered* whose session the response taught.
        let mut exit: Option<Arc<str>> = None;
        loop {
            let hops = chain.as_ref().map_or(0, Vec::len);
            // The body is taken out for this hop, and a replayable copy kept
            // back in case a redirect needs to send it again. `try_clone`
            // returns `None` for a streaming body, which is what makes the
            // "cannot replay" error below possible to raise honestly.
            let body = std::mem::replace(request.body_mut(), Body::empty());
            let spare = body.try_clone();

            // The path never enters a span: a query string routinely carries
            // tokens, and these spans are emitted at debug level.
            let span = tracing::debug_span!(
                "exchange",
                method = %request.method(),
                host = url.host_str().unwrap_or_default(),
                hop = hops,
            );

            // The cache sits around one hop, not around the whole logical
            // request: a cache key is a single target URI, so a redirect and
            // what it points at are separate entries and a cached `301` is
            // followed by the loop below exactly as a fresh one would be.
            let (pending, cached) = self.cache_before(&mut request, &url);
            let response = match cached {
                Some(hit) => cache_hit(hit),
                None => {
                    // Per hop rather than per logical request, so a redirect
                    // that crosses origins is charged to the origin it actually
                    // reaches. A cache hit takes no permit at all, which is
                    // correct: nothing was asked of the origin.
                    let permit =
                        crate::concurrency::acquire_from(self.inner.concurrency.as_deref(), &url)
                            .await;
                    let response = self
                        .hop(
                            &mut request,
                            body,
                            &url,
                            &options,
                            &deadline,
                            &mut timings,
                            &mut exit,
                        )
                        .instrument(span)
                        .await?;
                    // On a transport error the `?` above drops the lease, which
                    // returns the slot and teaches nothing — a failure to connect
                    // may be this host's network rather than the origin's load.
                    crate::concurrency::complete_from(permit, &response);
                    self.cache_after(pending, &url, response)
                }
            };

            let decision = redirect::decide(
                response.status(),
                response.headers(),
                &url,
                request.method(),
                limit,
                hops,
            )?;

            let Decision::Follow(hop) = decision else {
                return self.finish(response, &deadline, url, timings, chain, exit);
            };

            // Read before the response is consumed below, so the chain records
            // what each hop actually answered rather than what a 3xx usually
            // answers.
            let status = response.status();

            tracing::debug!(
                status = response.status().as_u16(),
                cross_origin = hop.cross_origin,
                "following a redirect"
            );

            // The socket has to be clean before its connection is reused, and
            // this body is about to be thrown away.
            //
            // `REDIRECT_DRAIN_LIMIT` bounds how much is read, which is not the
            // same as bounding how long it takes: a server that sends a
            // `Content-Length` and then stops writing satisfies the byte limit
            // forever. The deadline is what makes the drain give up, and it is
            // safe to abandon here because a body that fails takes its
            // connection with it rather than returning a half-read socket to
            // the pool — so the cost of giving up is one connection, not a
            // corrupted one.
            let _ = bounded_by(response.into_body(), deadline)
                .collect(REDIRECT_DRAIN_LIMIT)
                .await;

            let next_body = if hop.drop_body {
                Body::empty()
            } else {
                spare.ok_or_else(|| streaming_redirect_error(&hop))?
            };

            request = rebuild(request, &hop, next_body)?;
            // A swap rather than a clone: the URL this hop was made against is
            // exactly what the record needs, and it is about to be replaced
            // anyway, so the chain is built without copying a single `Url`.
            let answered = std::mem::replace(&mut url, hop.url);
            chain
                .get_or_insert_with(Vec::new)
                .push(Hop::new(answered, status));
        }
    }

    /// Performs one hop and returns the response with its body still streaming.
    ///
    /// `exit` is an out-parameter rather than part of the return value because
    /// it must be reported even when this hop fails: the caller's `?` discards
    /// a `Result`'s payload, and which exit a failed hop went out through is
    /// exactly what a caller diagnosing one proxy wants.
    #[allow(clippy::too_many_arguments)]
    async fn hop(
        &self,
        request: &mut Request,
        body: Body,
        url: &Url,
        options: &RequestOptions,
        deadline: &Deadline,
        timings: &mut Timings,
        exit: &mut Option<Arc<str>>,
    ) -> Result<Response> {
        // Every hop, not just the ones a redirect produced: the first hop is
        // what sets the boundary the others are measured against.
        timings.record_hop_start();
        deadline.check(Phase::Connect)?;

        let head_timeout = options.head_timeout.or(self.inner.config.head_timeout);
        let origin = Origin::of(url)?;
        let route = self.inner.connector.route(origin).await;
        // Once per hop, keyed by the same redacted proxy label the pool key
        // carries, and resolved to an owned handle here rather than re-read at
        // each use: everything below awaits the network, and a lock guard held
        // across an `.await` is what `Engine::with_hsts` was reshaped to make
        // unwritable.
        let session = self.inner.sessions.for_route(route.proxy_label());
        // The same `Arc` the session map is keyed by, cloned rather than
        // rebuilt: one atomic increment, no allocation, and `None` — so not
        // even that — for a direct request. Reporting a label built from the
        // proxy URL instead would be a string that merely looks like the key,
        // and `Engine::with_session` would then be reachable with a value that
        // misses.
        *exit = route.proxy_label().cloned();

        let (key, connection) = self.acquire(&route, deadline, timings).await?;
        let protocol = connection.protocol();

        // The header engine emits `Host` only for HTTP/1.1, so the version has
        // to be settled before headers are built. That is why the connection is
        // acquired first even though nothing has been sent yet.
        *request.version_mut() = protocol.version();
        // Before `apply_headers`, so a replayed validator travels the same path a
        // caller's own header would, rather than being appended afterwards by a
        // different route.
        #[cfg(feature = "validator-store")]
        if let Some(validators) = session.validators() {
            validators.condition(url, request);
        }

        let ordered = self.apply_headers(request, url, options, &session)?;

        let outgoing = outgoing_request(request, url, protocol, body, ordered)?;

        let response = deadline
            .run(
                Phase::AwaitResponse,
                head_timeout,
                send_on(connection, key, self.inner.pool.clone(), outgoing),
            )
            .await?;
        // Stamped before the response is inspected, so what the client learns
        // from the headers is not billed as time the origin took.
        timings.record_head();

        self.record_response(url, &response, &session);

        #[cfg(feature = "validator-store")]
        if let Some(validators) = session.validators() {
            validators.observe(url, request.method(), &response);
        }
        Ok(response)
    }

    /// Asks the cache what to do with this hop, before anything is sent.
    ///
    /// Returns what [`Engine::cache_after`] will need, and the stored response
    /// when one may be served without an exchange.
    #[cfg(feature = "cache")]
    fn cache_before(&self, request: &mut Request, url: &Url) -> (CachePending, CacheHit) {
        match &self.inner.cache {
            Some(cache) => cache.before(request, url),
            None => (CachePending::default(), None),
        }
    }

    #[cfg(not(feature = "cache"))]
    #[inline]
    fn cache_before(&self, _request: &mut Request, _url: &Url) -> (CachePending, CacheHit) {
        ((), None)
    }

    /// Hands the cache what the origin answered, and takes back the response
    /// the caller should see — the stored one after a `304`, otherwise the
    /// origin's own with its body wrapped so that reading it also stores it.
    #[cfg(feature = "cache")]
    fn cache_after(&self, pending: CachePending, url: &Url, response: Response) -> Response {
        match &self.inner.cache {
            Some(cache) => cache.after(pending, url, response),
            None => response,
        }
    }

    #[cfg(not(feature = "cache"))]
    #[inline]
    fn cache_after(&self, _pending: CachePending, _url: &Url, response: Response) -> Response {
        response
    }

    /// Takes a pooled connection, or opens one.
    ///
    /// `timings` is only handed to the connector, so a hop served from the pool
    /// leaves the connection phases unrecorded rather than recording zeroes.
    async fn acquire(
        &self,
        route: &Route,
        deadline: &Deadline,
        timings: &mut Timings,
    ) -> Result<(PoolKey, Connection)> {
        for key in self.inner.connector.candidate_keys(route) {
            if let Some(connection) = self.inner.pool.checkout(&key) {
                tracing::trace!(key = %key, "reusing a pooled connection");
                return Ok((key, connection));
            }
        }

        let (key, connection) = self
            .inner
            .connector
            .connect(route, deadline, timings)
            .await?;

        // A multiplexed connection belongs to the pool from the moment it is
        // opened, not when a response body ends. An HTTP/1.1 connection is
        // exclusive for one exchange and comes back through the body
        // (`body::returning_to_pool`); HTTP/2 serves this request and every
        // later one at the same time, so nothing would ever hand it over —
        // which left every HTTP/2 request opening a fresh TCP connection and
        // repeating the TLS handshake.
        if let Connection::Http2(sender) = &connection {
            self.inner
                .pool
                .release(&key, Connection::Http2(sender.clone()));
            tracing::trace!(key = %key, "pooled a new multiplexed connection");
        }

        Ok((key, connection))
    }

    /// Writes the profile's headers onto the request, in the profile's order,
    /// and returns the authoritative wire order.
    ///
    /// `HeaderEngine::apply` returns that order as a list, because a
    /// `HeaderMap` cannot express "this name comes before that one" on its
    /// own. It also rebuilds the request's own map from scratch in the same
    /// pass — insertion order, which is what the next hop's caller-override
    /// semantics and any inspection of the request read — so nothing has to
    /// be rebuilt here. The returned list is what goes on the wire; see
    /// [`outgoing_request`].
    fn apply_headers(
        &self,
        request: &mut Request,
        url: &Url,
        options: &RequestOptions,
        session: &Session,
    ) -> Result<Vec<(HeaderName, HeaderValue)>> {
        // A `Cookie` header already on the request is the caller's own, and
        // theirs wins: the jar is not consulted and the header is left where it
        // is, so it survives into the next hop the way any other header the
        // caller set does.
        let mut from_jar = false;
        if let Some(cookies) = session.cookies()
            && !request.headers().contains_key(http::header::COOKIE)
            && let Some(value) = cookies.cookies_for(url, &options.cookie_context())
        {
            request.headers_mut().insert(http::header::COOKIE, value);
            from_jar = true;
        }

        let ordered = if self
            .inner
            .accept_ch_used
            .load(std::sync::atomic::Ordering::Acquire)
        {
            session.with_accept_ch(|store| self.inner.headers.apply(request, url, options, store))
        } else {
            // No grant was ever recorded, so an empty store answers every
            // origin identically to the locked one — without the lock.
            self.inner
                .headers
                .apply(request, url, options, &AcceptChStore::new())
        };

        // The engine's own answer is taken straight back off, which is what
        // distinguishes it from the caller's. `ordered` already carries its own
        // copy and is what goes on the wire, so this hop is unaffected; what it
        // changes is the next one.
        //
        // Leaving it on the request made a same-origin redirect send the jar's
        // answer from *before* the redirect, because `rebuild` keeps credential
        // headers on a same-origin hop and the check above then found one and
        // skipped the jar. A `Set-Cookie` on the redirect itself was therefore
        // never sent — a login that redirects after authenticating lost its
        // session cookie — and a cookie the redirect deleted was replayed.
        // Neither is visible from an empty jar, which is what every redirect
        // test started from.
        if from_jar {
            request.headers_mut().remove(http::header::COOKIE);
        }
        ordered
    }

    /// Runs `edit` against the HSTS store, with exclusive access, and returns
    /// what it returned.
    ///
    /// Policies are normally learned from responses, but a caller may want to
    /// seed one — a private origin that is HTTPS-only but has never been
    /// visited in this process gets no protection from a store that is still
    /// empty, and the first request is the one that would go out in plaintext.
    /// It is also how a test establishes a policy without a TLS origin.
    ///
    /// ```no_run
    /// # use std::time::SystemTime;
    /// # use std::sync::Arc;
    /// # use chromulate_http::{Engine, EngineConfig};
    /// # use chromulate_profile::Profile;
    /// let engine = Engine::builder(EngineConfig::new(Arc::new(Profile::chrome_stable())))
    ///     .build()?;
    /// engine.with_hsts(|store| {
    ///     store.record(
    ///         "internal.example",
    ///         "max-age=31536000; includeSubDomains",
    ///         true,
    ///         SystemTime::now(),
    ///     );
    /// });
    /// # Ok::<(), chromulate_core::Error>(())
    /// ```
    ///
    /// This took the shape of a closure rather than a `hsts()` returning the
    /// guard, which is what it used to be. The lock is one the request path
    /// takes on every request, and a returned guard is a lock a caller can hold
    /// across an `.await` — at which point the worker stops answering so
    /// completely that a `tokio::time::timeout` around the request never fires,
    /// because the future it wraps is never polled again. A documented "drop it
    /// before issuing requests" is not a fix for that: it is reachable from
    /// safe code by writing the obvious thing. `edit` is synchronous and the
    /// borrow does not escape it, so no `.await` can appear between taking the
    /// lock and releasing it.
    pub fn with_hsts<R>(&self, edit: impl FnOnce(&mut crate::hsts::HstsStore) -> R) -> R {
        let mut store = self
            .inner
            .hsts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        edit(&mut store)
    }

    /// Runs `edit` against one route's server-taught state, and returns what it
    /// returned.
    ///
    /// `exit` is the label from [`ResponseInfo::exit`] — the same `Arc<str>`,
    /// handed straight back. That is the point of the signature: cookies,
    /// client-hint grants and validators belong to the exit they were taught
    /// through, and a caller who has to *describe* the exit rather than repeat
    /// it can describe it wrongly. Taking `Option<&Arc<str>>` means the value
    /// that comes out of a response is the value that goes back in, with no
    /// string built in between and no allocation. `None` reaches the session an
    /// unproxied request uses, which under
    /// [`ProxyIsolation::PerProxy`](crate::ProxyIsolation::PerProxy) is not any
    /// proxy's.
    ///
    /// # `None` means there is no such route, and nothing was created
    ///
    /// This reads; it never mints. `edit` is not called at all when there is no
    /// session filed under `exit`:
    ///
    /// - `exit` is `None` — always `Some`. The unproxied session is not filed
    ///   under a label and always exists.
    /// - a label under [`ProxyIsolation::Shared`](crate::ProxyIsolation::Shared)
    ///   — always `None`. Nothing is filed under a label there, and answering
    ///   with the shared session would tell a caller that the exit they named
    ///   holds state of its own.
    /// - a label under
    ///   [`PerProxy`](crate::ProxyIsolation::PerProxy) — `Some` only if that
    ///   exit has been served or seeded and has not been evicted since.
    ///
    /// Use [`Engine::seed_session`] to create one. The split exists because
    /// minting runs the `max_routes` eviction, so a method that reads like an
    /// accessor could silently discard another exit's cookies when handed a
    /// label with a typo in it. Now a mistyped label finds nothing and changes
    /// nothing.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use chromulate_http::{Engine, EngineConfig};
    /// # use chromulate_profile::Profile;
    /// let engine = Engine::builder(EngineConfig::new(Arc::new(Profile::chrome_stable())))
    ///     .build()?;
    /// # let response: chromulate_core::Response = unimplemented!();
    /// // The exit that answered is the exit whose jar the answer belongs in.
    /// let info = response.extensions().get::<chromulate_http::ResponseInfo>();
    /// let exit = info.and_then(|info| info.exit.as_ref());
    /// match engine.with_session(exit, |session| session.cookies().is_some()) {
    ///     Some(has_jar) => println!("that exit has state; jar: {has_jar}"),
    ///     None => println!("nothing is filed under that exit"),
    /// }
    /// # Ok::<(), chromulate_core::Error>(())
    /// ```
    ///
    /// A closure rather than a returned handle, for the reason
    /// [`Engine::with_hsts`] is one: nothing that borrows engine-internal state
    /// escapes, so no future change to how that state is locked can be turned
    /// into a deadlock by a caller holding it across an `.await`. See
    /// [`RouteSession`] for what the borrow does and does not promise.
    #[must_use = "the `None` says the route does not exist; discarding it turns a \
                  lookup that found nothing into one that looks like it worked"]
    pub fn with_session<R>(
        &self,
        exit: Option<&Arc<str>>,
        edit: impl FnOnce(RouteSession<'_>) -> R,
    ) -> Option<R> {
        let session = self.inner.sessions.existing_route(exit)?;
        Some(edit(RouteSession::new(&session)))
    }

    /// Runs `edit` against one route's state, creating that state if this
    /// engine has not served the route yet.
    ///
    /// The minting counterpart to [`Engine::with_session`], and the split is
    /// deliberate. Seeding a route before its first request is a real use —
    /// the same one [`Engine::with_hsts`] exists for — but creating a session
    /// is not what a caller *reading* one asked for, and under
    /// [`ProxyIsolation::PerProxy`] creating one is not free:
    ///
    /// **This can evict another exit's session.** Minting inserts into the
    /// per-route map, and inserting runs the `max_routes` eviction, which drops
    /// the least recently used route. On an engine at its ceiling, seeding a
    /// route discards the cookies of whichever exit has gone longest unused.
    /// That is the documented cost of a bounded store rather than a defect, and
    /// it is why the read path no longer pays it: a mistyped label handed to
    /// [`Engine::with_session`] now finds nothing and changes nothing, where
    /// once it silently cost a live session.
    ///
    /// `exit` is `None` for the session unproxied requests use, which always
    /// exists and is therefore never minted.
    pub fn seed_session<R>(
        &self,
        exit: Option<&Arc<str>>,
        edit: impl FnOnce(RouteSession<'_>) -> R,
    ) -> R {
        let session = self.inner.sessions.for_route(exit);
        edit(RouteSession::new(&session))
    }

    /// Rewrites `url` to HTTPS when a recorded HSTS policy demands it.
    fn apply_hsts(&self, url: &mut Url) {
        if url.scheme() != "http" {
            return;
        }
        let store = self
            .inner
            .hsts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if store.upgrade(url, SystemTime::now()) {
            tracing::debug!(%url, "upgraded to https by a stored HSTS policy");
        }
    }

    /// Records everything a response teaches the client about the origin.
    ///
    /// What the *origin* taught goes to `session`, so it is remembered against
    /// the exit it arrived through. What is true of the origin whatever route
    /// reached it — its HSTS policy — goes to the engine.
    fn record_response(&self, url: &Url, response: &Response, session: &Session) {
        if let Some(cookies) = session.cookies() {
            let mut set_cookie = response.headers().get_all(SET_COOKIE).iter();
            cookies.store(url, &mut set_cookie);
        }

        // RFC 6797 §8.1: only a response that arrived over TLS may set a
        // policy, so the scheme of the URL that produced it is the gate.
        if let Some(policy) = response.headers().get("strict-transport-security")
            && let Ok(value) = policy.to_str()
            && let Some(host) = url.host_str()
        {
            self.inner
                .hsts
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .record(host, value, url.scheme() == "https", SystemTime::now());
        }

        if let Some(accept_ch) = response.headers().get("accept-ch")
            && let Ok(value) = accept_ch.to_str()
            && let Ok(origin) = Origin::of(url)
        {
            session.record_accept_ch(origin, value);
            // After the write, so a reader that sees the flag finds the grant.
            self.inner
                .accept_ch_used
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Decodes the body, attaches the request deadline to it, and records what
    /// the response cost and which URL produced it.
    fn finish(
        &self,
        response: Response,
        deadline: &Deadline,
        url: Url,
        timings: Timings,
        hops: Option<Vec<Hop>>,
        exit: Option<Arc<str>>,
    ) -> Result<Response> {
        let response = self.inner.decompression.decode_response(response)?;
        let (mut parts, body) = response.into_parts();
        // After a redirect chain the caller's URL is not the one that answered,
        // and nothing else in the response says which one did.
        //
        // `map` rather than `unwrap_or_default().into()`: a request that never
        // redirected must reach `Arc::from` not at all, because an empty
        // `Arc<[Hop]>` is still an allocation and this runs on every request.
        parts.extensions.insert(ResponseInfo {
            url,
            timings,
            hops: hops.map(Arc::from),
            exit,
        });
        Ok(Response::from_parts(parts, bounded_by(body, *deadline)))
    }
}

impl Exchange for Engine {
    fn exchange(&self, request: Request) -> BoxFuture<'_, Result<Response>> {
        Box::pin(self.run(request))
    }
}

/// Sends one request and wires the connection's lifetime to the response body.
async fn send_on(
    connection: Connection,
    key: PoolKey,
    pool: Pool,
    request: Request,
) -> Result<Response> {
    let (result, returning) = match connection {
        // HTTP/2 multiplexes, so the connection never left the pool and there
        // is nothing to give back.
        Connection::Http2(mut sender) => (sender.send_request(request).await, None),
        Connection::Http1(mut sender) => {
            let result = sender.send_request(request).await;
            (result, Some(Connection::Http1(sender)))
        }
    };

    let response = result.map_err(|error| {
        if error.is_timeout() {
            Error::Timeout(Phase::AwaitResponse)
        } else {
            Error::Body {
                phase: Phase::AwaitResponse,
                source: Some(Box::new(error)),
            }
        }
    })?;

    let (parts, incoming) = response.into_parts();
    let body = from_incoming(incoming);
    let body = match returning {
        Some(connection) => returning_to_pool(body, pool, key, connection),
        None => body,
    };
    Ok(Response::from_parts(parts, body))
}

/// Builds the request that actually goes on the wire.
///
/// The caller's request is left intact so the redirect loop can still read its
/// method and headers after the hop; `ordered` — the header engine's
/// authoritative wire order, whose entries the engine already wrote onto the
/// caller's request too — is **moved** onto the outgoing request rather than
/// the map being cloned, because hyper writes headers in map insertion order
/// and every entry is a reference-counted handle that a move keeps free.
fn outgoing_request(
    request: &Request,
    url: &Url,
    protocol: Protocol,
    body: Body,
    ordered: Vec<(HeaderName, HeaderValue)>,
) -> Result<Request> {
    // HTTP/1.1 puts the path on the request line and the authority in `Host`;
    // HTTP/2 needs the whole URL so hyper can derive `:scheme` and
    // `:authority`. hyper writes a `Uri`'s `Display` form verbatim onto an h1
    // request line, so an absolute URI there would produce the absolute form,
    // which is reserved for requests addressed to a proxy. Both shapes are
    // carved out of the request's own `Uri` — every component is a
    // reference-counted handle, so neither arm re-serialises or re-parses the
    // URL.
    let uri = match protocol {
        Protocol::Http11 => {
            let path_and_query = request
                .uri()
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
            let mut parts = http::uri::Parts::default();
            parts.path_and_query = Some(path_and_query);
            http::Uri::from_parts(parts).map_err(|error| {
                Error::url(format!("{url} is not a usable request target: {error}"))
            })?
        }
        Protocol::Http2 => request.uri().clone(),
    };

    let mut builder = http::Request::builder()
        .method(request.method().clone())
        .version(protocol.version())
        .uri(uri);

    if let Some(headers) = builder.headers_mut() {
        headers.reserve(ordered.len());
        for (name, value) in ordered {
            headers.append(name, value);
        }
    }

    builder
        .body(body)
        .map_err(|error| Error::builder(error.to_string()))
}

/// Builds the next request in a redirect chain.
fn rebuild(previous: Request, hop: &redirect::Hop, body: Body) -> Result<Request> {
    let (mut parts, _) = previous.into_parts();

    parts.method = hop.method.clone();
    parts.uri =
        hop.url.as_str().parse().map_err(|error| {
            Error::Redirect(format!("redirect target is not a valid URI: {error}"))
        })?;

    if hop.cross_origin {
        redirect::strip_credentials(&mut parts.headers);
    }
    if hop.drop_body {
        parts.headers.remove(http::header::CONTENT_LENGTH);
        parts.headers.remove(http::header::CONTENT_TYPE);
        parts.headers.remove(http::header::TRANSFER_ENCODING);
    }
    // Recomputed for the new hop by the header engine.
    parts.headers.remove(http::header::HOST);

    Ok(Request::from_parts(parts, body))
}

fn streaming_redirect_error(hop: &redirect::Hop) -> Error {
    Error::Redirect(format!(
        "cannot follow a redirect that re-sends the body as {}: the body is a stream, it has \
         already been sent once, and replaying it is not possible. Buffer the body, or set \
         `RedirectPolicy::None` and follow the hop yourself.",
        hop.method
    ))
}

/// A caller who never touched the per-request policy must not override the
/// engine's configuration, and `RequestOptions::default()` carries the default
/// policy rather than an absence.
fn effective_policy(options: &RequestOptions, fallback: RedirectPolicy) -> RedirectPolicy {
    if options.redirect == RedirectPolicy::default() {
        fallback
    } else {
        options.redirect
    }
}

fn url_of(uri: &http::Uri) -> Result<Url> {
    if uri.scheme().is_none() {
        return Err(Error::url(format!(
            "`{uri}` is not absolute; a request needs a scheme and a host"
        )));
    }
    Url::parse(&uri.to_string())
        .map_err(|error| Error::url(format!("`{uri}` is not a URL: {error}")))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use chromulate_cookie::Jar;
    use chromulate_core::CookieContext;
    use chromulate_dns::StaticResolver;
    use chromulate_proxy::{Proxy, ProxyUrl, Single};
    use http::{HeaderValue, Method, StatusCode};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    fn engine() -> Engine {
        Engine::builder(EngineConfig::new(Arc::new(Profile::chrome_stable())))
            .build()
            .expect("the Chrome profile must build an engine")
    }

    #[test]
    fn an_engine_reports_the_identity_its_connections_carry() {
        let engine = engine();
        assert_eq!(
            engine.identity(),
            &ConnectionIdentity::of(&Profile::chrome_stable())
        );
    }

    #[test]
    fn a_relative_request_uri_is_rejected_with_a_message_that_says_why() {
        let error = url_of(&"/just/a/path".parse().expect("a valid uri"))
            .expect_err("a relative URI cannot be sent");
        assert!(matches!(error, Error::Url(_)), "{error:?}");
        assert!(error.to_string().contains("absolute"), "{error}");
    }

    #[test]
    fn an_http1_request_line_carries_the_path_while_http2_carries_the_whole_url() {
        let url = Url::parse("https://example.com/search?q=rust").expect("a valid url");
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .body(Body::empty())
            .expect("a valid request");

        let h1 = outgoing_request(&request, &url, Protocol::Http11, Body::empty(), Vec::new())
            .expect("an h1 request must build");
        assert_eq!(h1.uri().to_string(), "/search?q=rust");

        let h2 = outgoing_request(&request, &url, Protocol::Http2, Body::empty(), Vec::new())
            .expect("an h2 request must build");
        assert_eq!(h2.uri().to_string(), "https://example.com/search?q=rust");
    }

    #[test]
    fn a_cross_origin_hop_drops_credentials_while_a_same_origin_hop_keeps_them() {
        let build = || {
            let mut request = http::Request::builder()
                .method(Method::GET)
                .uri("https://a.test/one")
                .body(Body::empty())
                .expect("a valid request");
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer token"),
            );
            request
                .headers_mut()
                .insert(http::header::COOKIE, HeaderValue::from_static("s=1"));
            request
        };

        let same = rebuild(
            build(),
            &redirect::Hop {
                url: Url::parse("https://a.test/two").expect("a valid url"),
                method: Method::GET,
                drop_body: false,
                cross_origin: false,
            },
            Body::empty(),
        )
        .expect("a same-origin hop must build");
        assert!(same.headers().contains_key(http::header::AUTHORIZATION));
        assert!(same.headers().contains_key(http::header::COOKIE));

        let cross = rebuild(
            build(),
            &redirect::Hop {
                url: Url::parse("https://b.test/two").expect("a valid url"),
                method: Method::GET,
                drop_body: false,
                cross_origin: true,
            },
            Body::empty(),
        )
        .expect("a cross-origin hop must build");
        assert!(!cross.headers().contains_key(http::header::AUTHORIZATION));
        assert!(!cross.headers().contains_key(http::header::COOKIE));
    }

    #[test]
    fn dropping_a_body_also_drops_the_headers_that_described_it() {
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("https://a.test/one")
            .body(Body::fixed("payload"))
            .expect("a valid request");
        request
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("7"));
        request.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );

        let next = rebuild(
            request,
            &redirect::Hop {
                url: Url::parse("https://a.test/two").expect("a valid url"),
                method: Method::GET,
                drop_body: true,
                cross_origin: false,
            },
            Body::empty(),
        )
        .expect("the hop must build");

        assert_eq!(next.method(), Method::GET);
        assert!(!next.headers().contains_key(http::header::CONTENT_LENGTH));
        assert!(!next.headers().contains_key(http::header::CONTENT_TYPE));
    }

    #[test]
    fn a_request_that_states_no_policy_inherits_the_engines() {
        let options = RequestOptions::default();
        assert_eq!(
            effective_policy(&options, RedirectPolicy::None),
            RedirectPolicy::None
        );
    }

    #[test]
    fn a_request_that_states_a_policy_overrides_the_engines() {
        let mut options = RequestOptions::default();
        options.redirect = RedirectPolicy::Follow { limit: 2 };
        assert_eq!(
            effective_policy(&options, RedirectPolicy::None),
            RedirectPolicy::Follow { limit: 2 }
        );
    }

    /// The whole header-ordering feature rests on `HeaderMap` iterating in the
    /// order names were appended. That is not something the `http` crate
    /// documents as a guarantee, so it is checked here rather than assumed: if
    /// a future version changes it, this fails loudly instead of silently
    /// scrambling every request's fingerprint.
    #[test]
    fn a_rebuilt_header_map_iterates_in_the_order_it_was_appended() {
        let order = [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
            "cookie",
        ];

        let mut headers = http::HeaderMap::new();
        // A header set before the rebuild must not keep its old position.
        headers.insert(http::header::COOKIE, HeaderValue::from_static("s=1"));
        headers.clear();

        for name in order {
            headers.append(
                http::HeaderName::from_static(name),
                HeaderValue::from_static("v"),
            );
        }

        let observed: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(observed, order);
    }

    // ------------------------------------- what a response reports about how
    // ------------------------------------- it was obtained

    // These four properties are about a whole request rather than a function,
    // so they need a real socket. The harness in `tests/common` is richer than
    // what is below but an integration test cannot be reached from here, so a
    // minimal origin and a minimal `CONNECT` proxy live in this module.

    /// A canned 200 with no body, so a connection stays clean enough to pool.
    const OK: &str = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

    /// Reads one HTTP head off `socket`, or `None` at EOF.
    async fn read_head(socket: &mut TcpStream) -> Option<()> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match socket.read(&mut byte).await {
                Ok(0) | Err(_) => return None,
                Ok(_) => head.push(byte[0]),
            }
            if head.ends_with(b"\r\n\r\n") {
                return Some(());
            }
            if head.len() > 16 * 1024 {
                return None;
            }
        }
    }

    /// An origin that answers `replies` in order, one per request, however many
    /// connections the client spreads them over.
    ///
    /// Ordered rather than routed by path on purpose: a chain that arrived in
    /// the wrong order would still be answered by a path-routed origin, and
    /// these tests are about order.
    async fn origin(replies: &[&'static str]) -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback origin must bind");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");
        let queue = Arc::new(Mutex::new(replies.iter().copied().collect::<VecDeque<_>>()));

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let queue = Arc::clone(&queue);
                tokio::spawn(async move {
                    while read_head(&mut socket).await.is_some() {
                        let next = queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .pop_front();
                        let Some(reply) = next else { return };
                        if socket.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A `CONNECT` tunnel to `origin` — the shape this crate opens even for a
    /// plaintext target, so a test that wants a non-`None` exit needs one.
    async fn connect_proxy(origin: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback proxy must bind");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");

        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if read_head(&mut client).await.is_none() {
                        return;
                    }
                    if client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(mut upstream) = TcpStream::connect(origin).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        addr
    }

    /// Mints a jar per exit, which an isolated engine must be handed because
    /// this crate holds cookies behind [`CookieStore`] and cannot make one.
    struct Jars;

    impl SessionFactory for Jars {
        fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
            Some(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
        }
    }

    /// The URL to ask for, with the listener's port in it.
    ///
    /// [`StaticResolver`] pins the address a host resolves to; the *port* still
    /// comes from the URL. Omitting it sends the request to whatever is
    /// listening on port 80 of the loopback interface, which on a developer
    /// machine is often something — these tests were briefly green against a
    /// local Caddy, which redirects nothing and so satisfied every assertion
    /// about an absent redirect chain.
    fn url_for(addr: SocketAddr, path: &str) -> String {
        format!("http://a.test:{}{path}", addr.port())
    }

    fn engine_against(addr: SocketAddr, host: &str) -> EngineBuilder {
        let resolver = StaticResolver::empty().with_host(host.to_owned(), vec![addr]);
        let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
        config.connect_timeout = Some(Duration::from_secs(5));
        Engine::builder(config).resolver(Arc::new(resolver))
    }

    /// Drives one request and returns what the engine reported about it.
    async fn info_for(engine: &Engine, url: &str) -> ResponseInfo {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Body::empty())
            .expect("a valid request");
        let response = engine
            .send(request)
            .await
            .expect("the loopback origin must answer");
        response
            .extensions()
            .get::<ResponseInfo>()
            .cloned()
            .expect("the engine attaches a ResponseInfo to every response")
    }

    #[tokio::test]
    async fn a_redirect_chain_is_reported_oldest_first_with_the_status_each_hop_answered() {
        let addr = origin(&[
            "HTTP/1.1 301 Moved Permanently\r\nlocation: /two\r\ncontent-length: 0\r\n\r\n",
            "HTTP/1.1 302 Found\r\nlocation: /three\r\ncontent-length: 0\r\n\r\n",
            OK,
        ])
        .await;
        let engine = engine_against(addr, "a.test")
            .build()
            .expect("the engine must build");

        let info = info_for(&engine, &url_for(addr, "/one")).await;
        let hops = info
            .hops
            .expect("two redirects were followed, so there is a chain to report");

        assert_eq!(hops.len(), 2, "two redirects, two records");
        // Two *different* statuses, so a chain assembled in the wrong order
        // fails here instead of passing on a coincidence.
        assert_eq!(hops[0].status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(hops[0].url().path(), "/one");
        assert_eq!(hops[1].status(), StatusCode::FOUND);
        assert_eq!(hops[1].url().path(), "/two");
        // The URL that finally answered is not repeated in the chain.
        assert_eq!(info.url.path(), "/three");
    }

    /// The allocation property, asserted as behaviour: `None`, not an empty
    /// slice. An empty `Arc<[Hop]>` would satisfy "no redirects happened" and
    /// would also be a heap allocation on every request that does not redirect,
    /// which is most of them.
    #[tokio::test]
    async fn a_request_answered_without_a_redirect_reports_no_chain_at_all() {
        let addr = origin(&[OK]).await;
        let engine = engine_against(addr, "a.test")
            .build()
            .expect("the engine must build");

        let info = info_for(&engine, &url_for(addr, "/one")).await;
        assert!(
            info.hops.is_none(),
            "no redirect was followed, so there must be no chain object at all: {:?}",
            info.hops
        );
    }

    #[tokio::test]
    async fn a_request_that_went_through_no_proxy_reports_no_exit() {
        let addr = origin(&[OK]).await;
        let engine = engine_against(addr, "a.test")
            .build()
            .expect("the engine must build");

        let info = info_for(&engine, &url_for(addr, "/one")).await;
        assert!(
            info.exit.is_none(),
            "a direct request has no exit to report: {:?}",
            info.exit
        );
    }

    /// The one structural claim the redirect-chain work rests on: the label a
    /// response reports is the very key its route's state is filed under, so a
    /// caller can hand it straight back and reach the session that learned what
    /// the response taught.
    ///
    /// Asserted three ways, because "equal" is the easy half. The cookie proves
    /// `with_session` reached the jar the origin actually taught; the route
    /// count proves it *found* that route rather than minting a second one
    /// under a key that merely looks similar; and the last stanza proves the
    /// route count is sensitive enough for the second claim to mean anything.
    #[tokio::test]
    async fn the_exit_a_response_reports_is_the_key_its_session_is_filed_under() {
        let addr =
            origin(&["HTTP/1.1 200 OK\r\nset-cookie: seen=1; Path=/\r\ncontent-length: 0\r\n\r\n"])
                .await;
        let proxy = connect_proxy(addr).await;
        let proxies = Arc::new(Single::new(Proxy::new(
            ProxyUrl::parse(&format!("http://{proxy}")).expect("a loopback proxy URL must parse"),
        )));

        let engine = engine_against(addr, "a.test")
            .proxies(proxies)
            .cookies(Arc::new(Jar::new()))
            .isolate_by_proxy(4, Arc::new(Jars))
            .build()
            .expect("the engine must build");

        let info = info_for(&engine, &url_for(addr, "/one")).await;
        assert!(
            info.exit.is_some(),
            "a proxied request went out through an exit and must say so"
        );
        assert_eq!(engine.isolated_routes(), 1, "one exit was used");

        let url = Url::parse(&url_for(addr, "/one")).expect("a valid url");
        let context = CookieContext::conservative_default();

        let through_exit = engine
            .with_session(info.exit.as_ref(), |session| {
                session
                    .cookies()
                    .expect("an isolated route is minted with a jar")
                    .cookies_for(&url, &context)
            })
            .expect("the reported label names a route that exists");
        assert_eq!(
            through_exit.as_ref().and_then(|value| value.to_str().ok()),
            Some("seen=1"),
            "the reported label reached the jar the origin taught"
        );
        assert_eq!(
            engine.isolated_routes(),
            1,
            "with_session found the existing route; it did not mint a second one"
        );

        // The exit's cookie must not be visible to an unproxied request, which
        // is the isolation rule this label exists to keep honest.
        let direct = engine
            .with_session(None, |session| {
                session
                    .cookies()
                    .and_then(|jar| jar.cookies_for(&url, &context))
            })
            .expect("the unproxied session always exists");
        assert!(
            direct.is_none(),
            "the base session was never taught this cookie: {direct:?}"
        );

        // A label that is not the one reported names no route at all, and —
        // the property the split exists for — looking does not create one.
        let other: Arc<str> = Arc::from("http://127.0.0.1:9");
        assert!(
            engine.with_session(Some(&other), |_| ()).is_none(),
            "an unserved label finds nothing"
        );
        assert_eq!(
            engine.isolated_routes(),
            1,
            "and reading it created nothing: the real exit's route is untouched"
        );

        // Seeding is what creates one, and it says so in its name.
        engine.seed_session(Some(&other), |_| ());
        assert_eq!(
            engine.isolated_routes(),
            2,
            "a different label is a different route"
        );
    }
}
