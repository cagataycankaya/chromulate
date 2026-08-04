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
use chromulate_tls::TlsEngine;
use http::header::SET_COOKIE;
use http::{HeaderName, HeaderValue};
use tracing::Instrument as _;
use url::Url;

use crate::body::{bounded_by, from_incoming, returning_to_pool};
use crate::connect::{Connector, Route};
use crate::deadline::Deadline;
use crate::http2::Http2Fidelity;
use crate::middleware::Retry;
use crate::pool::{Connection, ConnectionIdentity, Pool, PoolConfig, PoolKey, Protocol};
use crate::redirect::{self, Decision, Hop};

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
/// One extension carrying two facts rather than two extensions carrying one
/// each: [`http::Extensions`] boxes every value it stores, so a second insert
/// is a second heap allocation on a path whose per-request allocation count is
/// a published figure.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// The URL that produced the response.
    ///
    /// After a redirect chain this is not the URL the caller asked for, and a
    /// caller resolving relative links out of the body needs the one that
    /// actually answered.
    pub url: Url,
    /// Where the request spent its time.
    pub timings: Timings,
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
    tls: Option<TlsEngine>,
    resolver: Option<Arc<dyn Resolve>>,
    proxies: Option<Arc<dyn ProxyProvider>>,
    cookies: Option<Arc<dyn CookieStore>>,
    middleware: Vec<Arc<dyn Middleware>>,
    decompression: Option<ExpansionGuard>,
    pool: Option<Pool>,
    retry: Option<Retry>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<chromulate_cache::HttpCache>>,
    #[cfg(feature = "validator-store")]
    validators: Option<Arc<crate::validators::ValidatorStore>>,
    #[cfg(feature = "adaptive-concurrency")]
    concurrency: Option<Arc<crate::adaptive::AdaptiveConcurrency>>,
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
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "validator-store")]
            validators: None,
            #[cfg(feature = "adaptive-concurrency")]
            concurrency: None,
        }
    }

    /// Uses a TLS engine other than the one the profile would build.
    #[must_use]
    pub fn tls(mut self, tls: TlsEngine) -> Self {
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

    /// Learns how many concurrent requests each origin serves comfortably.
    ///
    /// The controller can only ever stay at or under the ceiling it was built
    /// with; it has no way to discover that it could go faster than a caller
    /// allowed. Read
    /// [`AdaptiveConcurrency`](crate::adaptive::AdaptiveConcurrency)'s
    /// documentation for what it does with a `429` and why that differs from a
    /// `403`.
    #[cfg(feature = "adaptive-concurrency")]
    #[must_use]
    pub fn concurrency(mut self, concurrency: Arc<crate::adaptive::AdaptiveConcurrency>) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Builds the engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile cannot produce a TLS
    /// configuration.
    pub fn build(self) -> Result<Engine> {
        let profile = Arc::clone(&self.config.profile);
        let tls = match self.tls {
            Some(tls) => tls,
            None => TlsEngine::new(&profile)?,
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

        Ok(Engine {
            inner: Arc::new(EngineInner {
                headers: HeaderEngine::new(Arc::clone(&profile)),
                accept_ch: RwLock::new(AcceptChStore::new()),
                hsts: RwLock::new(crate::hsts::HstsStore::new()),
                accept_ch_used: std::sync::atomic::AtomicBool::new(false),
                decompression: self.decompression.unwrap_or_default(),
                cookies: self.cookies,
                middleware: self.middleware,
                retry: self.retry,
                #[cfg(feature = "cache")]
                cache: self.cache,
                #[cfg(feature = "validator-store")]
                validators: self.validators,
                #[cfg(feature = "adaptive-concurrency")]
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
    accept_ch: RwLock<AcceptChStore>,
    /// Origins that have demanded HTTPS; see [`crate::hsts`].
    hsts: RwLock<crate::hsts::HstsStore>,
    /// Whether any response has ever recorded an `Accept-CH` grant.
    ///
    /// Most deployments never see one, and `RwLock::read` is still an atomic
    /// read-modify-write on a shared cache line — coherence traffic on every
    /// request that scales with worker count. This flag is a plain read; the
    /// lock is only touched once a grant exists. It never goes back to false:
    /// a revoked grant leaves an empty store behind the lock, which reads
    /// correctly, just no longer lock-free.
    accept_ch_used: std::sync::atomic::AtomicBool,
    cookies: Option<Arc<dyn CookieStore>>,
    decompression: ExpansionGuard,
    middleware: Vec<Arc<dyn Middleware>>,
    retry: Option<Retry>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<chromulate_cache::HttpCache>>,
    #[cfg(feature = "validator-store")]
    validators: Option<Arc<crate::validators::ValidatorStore>>,
    #[cfg(feature = "adaptive-concurrency")]
    concurrency: Option<Arc<crate::adaptive::AdaptiveConcurrency>>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("profile", &self.inner.profile.name)
            .field("identity", self.inner.connector.identity())
            .field("pool", &self.inner.pool)
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

    /// The TLS engine, whose `fidelity()` reports the handshake gap.
    #[must_use]
    pub fn tls(&self) -> &TlsEngine {
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

        let mut hops = 0usize;
        loop {
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
                    #[cfg(feature = "adaptive-concurrency")]
                    let permit =
                        crate::adaptive::acquire_from(self.inner.concurrency.as_deref(), &url)
                            .await;
                    let response = self
                        .hop(&mut request, body, &url, &options, &deadline, &mut timings)
                        .instrument(span)
                        .await?;
                    // On a transport error the `?` above drops the permit, which
                    // returns the slot and teaches nothing — a failure to connect
                    // may be this host's network rather than the origin's load.
                    #[cfg(feature = "adaptive-concurrency")]
                    crate::adaptive::complete_from(permit, &response);
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
                return self.finish(response, &deadline, url, timings);
            };

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
            url = hop.url;
            hops += 1;
        }
    }

    /// Performs one hop and returns the response with its body still streaming.
    async fn hop(
        &self,
        request: &mut Request,
        body: Body,
        url: &Url,
        options: &RequestOptions,
        deadline: &Deadline,
        timings: &mut Timings,
    ) -> Result<Response> {
        // Every hop, not just the ones a redirect produced: the first hop is
        // what sets the boundary the others are measured against.
        timings.record_hop_start();
        deadline.check(Phase::Connect)?;

        let head_timeout = options.head_timeout.or(self.inner.config.head_timeout);
        let origin = Origin::of(url)?;
        let route = self.inner.connector.route(origin).await;

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
        if let Some(validators) = &self.inner.validators {
            validators.condition(url, request);
        }

        let ordered = self.apply_headers(request, url, options)?;

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

        self.record_response(url, &response);

        #[cfg(feature = "validator-store")]
        if let Some(validators) = &self.inner.validators {
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
    ) -> Result<Vec<(HeaderName, HeaderValue)>> {
        // A `Cookie` header already on the request is the caller's own, and
        // theirs wins: the jar is not consulted and the header is left where it
        // is, so it survives into the next hop the way any other header the
        // caller set does.
        let mut from_jar = false;
        if let Some(cookies) = &self.inner.cookies
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
            let store = self
                .inner
                .accept_ch
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.inner.headers.apply(request, url, options, &store)
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
    fn record_response(&self, url: &Url, response: &Response) {
        if let Some(cookies) = &self.inner.cookies {
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
            self.inner
                .accept_ch
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .record(origin, value);
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
    ) -> Result<Response> {
        let response = self.inner.decompression.decode_response(response)?;
        let (mut parts, body) = response.into_parts();
        // After a redirect chain the caller's URL is not the one that answered,
        // and nothing else in the response says which one did.
        parts.extensions.insert(ResponseInfo { url, timings });
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
fn rebuild(previous: Request, hop: &Hop, body: Body) -> Result<Request> {
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

fn streaming_redirect_error(hop: &Hop) -> Error {
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
    use http::{HeaderValue, Method};

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
            &Hop {
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
            &Hop {
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
            &Hop {
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
}
