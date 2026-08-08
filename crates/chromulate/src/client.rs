//! The client and its builder.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chromulate_compression::ExpansionGuard;
use chromulate_cookie::Jar;
use chromulate_core::{
    CookieStore, Error, Middleware, RedirectPolicy, Resolve, Result, reexport::HeaderValue,
};
use chromulate_http::{
    Engine, EngineConfig, PoolConfig, ProxyIsolation, Retry, RetryPolicy, RouteSession,
    SessionFactory,
};
use chromulate_profile::Profile;
use chromulate_proxy::{Proxy, ProxyProvider, ProxyUrl, RoundRobin, Single};
use chromulate_tls::ActiveBackend;
#[cfg(doc)]
use chromulate_tls::TlsEngine;
use http::Method;
use http::header::{HeaderMap, HeaderName, USER_AGENT};

use crate::request::RequestBuilder;

/// The most of a response body [`crate::Response::bytes`] and
/// [`crate::Response::text`] will hold in memory.
///
/// These are convenience methods, and a convenience method that a hostile
/// server can use to exhaust the client's memory is not a convenience. A caller
/// who genuinely wants an unbounded read streams the body instead.
pub const DEFAULT_MAX_RESPONSE_SIZE: u64 = 64 * 1024 * 1024;

/// A browser-identity HTTP client.
///
/// Cheap to clone; clones share the connection pool, the cookie jar, and the
/// TLS session cache, so cloning a client is how you share one identity across
/// tasks.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

pub(crate) struct ClientInner {
    pub(crate) engine: Engine,
    pub(crate) profile: Arc<Profile>,
    pub(crate) default_headers: HeaderMap,
    pub(crate) max_response_size: u64,
    pub(crate) cookies: Option<Arc<Jar>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("profile", &self.inner.profile.name)
            .field("engine", &self.inner.engine)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with the shipped Chrome identity and browser defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the platform's trust store cannot be
    /// read, or when the profile and the linked TLS provider have nothing in
    /// common.
    pub fn chrome() -> Result<Self> {
        Self::builder().build()
    }

    /// Starts a builder.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// The identity this client presents.
    #[must_use]
    pub fn profile(&self) -> &Arc<Profile> {
        &self.inner.profile
    }

    /// The engine underneath, whose `tls()` and `http2_fidelity()` report how
    /// far the wire form is from the profile's target.
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }

    /// The cookie jar, when this client keeps one.
    ///
    /// Under [`ProxyIsolation::Shared`] — which is what a client with no proxy,
    /// one proxy, or a one-member pool gets — this is the jar every request
    /// uses. Under [`ProxyIsolation::PerProxy`] each exit keeps its own jar and
    /// this is the one used for requests that go through no proxy at all, which
    /// on a fully proxied client is none of them. Ask
    /// [`Client::proxy_isolation`] which of the two you have.
    #[must_use]
    pub fn cookies(&self) -> Option<&Arc<Jar>> {
        self.inner.cookies.as_ref()
    }

    /// Whether each proxy keeps its own session, or whether every route shares
    /// one.
    ///
    /// See [`ClientBuilder::proxy_isolation`] for how this is chosen when
    /// nothing states it.
    #[must_use]
    pub fn proxy_isolation(&self) -> ProxyIsolation {
        self.inner.engine.proxy_isolation()
    }

    /// Runs `edit` against the HSTS store this client consults before every
    /// request, with exclusive access, and returns what it returned.
    ///
    /// Policies are learned from `Strict-Transport-Security` responses, so a
    /// freshly built client knows nothing and its *first* request to an
    /// HTTPS-only origin is the one that would go out in plaintext. Seeding the
    /// store closes that window:
    ///
    /// ```no_run
    /// # use std::time::SystemTime;
    /// let client = chromulate::Client::chrome()?;
    /// client.with_hsts(|store| {
    ///     store.record(
    ///         "internal.example",
    ///         "max-age=31536000; includeSubDomains",
    ///         true,
    ///         SystemTime::now(),
    ///     );
    /// });
    /// # Ok::<(), chromulate::Error>(())
    /// ```
    ///
    /// The lock is released before this returns. See
    /// [`Engine::with_hsts`](chromulate_http::Engine::with_hsts) for why the
    /// store is reached through a closure rather than by handing out its guard.
    pub fn with_hsts<R>(&self, edit: impl FnOnce(&mut chromulate_http::HstsStore) -> R) -> R {
        self.inner.engine.with_hsts(edit)
    }

    /// Runs `edit` against one route's server-taught state — its cookies today
    /// — and returns what it returned, or `None` when there is no such route.
    ///
    /// [`Client::cookies`] reaches the jar an *unproxied* request uses, which
    /// under [`ProxyIsolation::PerProxy`] is none of the ones a fully proxied
    /// client actually sends. This is how the others are reached.
    ///
    /// # `None` means there is no such route, and nothing was created
    ///
    /// This reads; it never creates. `edit` is not called at all when nothing
    /// is filed under `exit`:
    ///
    /// | `exit` | isolation | result |
    /// | --- | --- | --- |
    /// | `None` | either | always `Some` — the session an unproxied request uses, the same jar [`Client::cookies`] returns |
    /// | `Some(label)` | [`PerProxy`](ProxyIsolation::PerProxy) | `Some` if that exit has been used or seeded and not evicted since; otherwise `None` |
    /// | `Some(label)` | [`Shared`](ProxyIsolation::Shared) | always `None` — nothing is filed under a label there |
    ///
    /// The last row used to hand back the one shared session and ignore the
    /// label, which was the sharpest way this API could mislead: name exit B,
    /// receive a session exit A also used, and be told nothing. `None` says it
    /// instead of a paragraph asking you to check
    /// [`Client::proxy_isolation`] first — a paragraph only protects the
    /// readers who read it.
    ///
    /// Use [`Client::seed_session`] to create a route rather than read one.
    ///
    /// # Naming an exit
    ///
    /// The label is the exit's redacted URL, and the engine files a route's
    /// state under the identical `Arc<str>` it puts on
    /// [`Response::exit`](crate::Response::exit). Handing that value straight
    /// back reaches a route that cannot be the wrong one; this is what the
    /// signature is shaped for. Deriving it instead is possible —
    /// `Arc::from(proxy.url().to_string())`, since [`ProxyUrl`]'s `Display` is
    /// what the engine uses and it redacts credentials — but it is a formula,
    /// and a formula can be applied wrongly. A wrong label now returns `None`
    /// rather than costing anything.
    ///
    /// [`ProxyUrl`]: crate::proxy::ProxyUrl
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use chromulate::proxy::ProxyUrl;
    /// use chromulate::{Client, ProxyIsolation};
    ///
    /// let client = Client::builder()
    ///     .proxy_pool(["http://a.example:8080", "http://b.example:8080"])?
    ///     .build()?;
    /// assert_eq!(client.proxy_isolation(), ProxyIsolation::per_proxy());
    ///
    /// let label: Arc<str> = Arc::from(
    ///     ProxyUrl::parse("http://a.example:8080")
    ///         .expect("a valid proxy URL")
    ///         .to_string(),
    /// );
    /// // Nothing has used this exit yet, so there is nothing filed under it.
    /// assert!(
    ///     client
    ///         .with_session(Some(&label), |session| session.cookies().is_some())
    ///         .is_none()
    /// );
    ///
    /// // Seeding creates it, and then the read finds it.
    /// let has_jar = client.seed_session(Some(&label), |session| session.cookies().is_some());
    /// assert!(has_jar, "a seeded route is minted with a jar of its own");
    /// assert_eq!(
    ///     client.with_session(Some(&label), |session| session.cookies().is_some()),
    ///     Some(true),
    /// );
    /// # Ok::<(), chromulate::Error>(())
    /// ```
    ///
    /// A closure rather than a returned handle, for the reason
    /// [`Client::with_hsts`] is one: nothing borrowing engine-owned state
    /// escapes, so it cannot be held across an `.await`. See
    /// [`Engine::with_session`](chromulate_http::Engine::with_session).
    #[must_use = "the `None` says the route does not exist; discarding it turns a \
                  lookup that found nothing into one that looks like it worked"]
    pub fn with_session<R>(
        &self,
        exit: Option<&Arc<str>>,
        edit: impl FnOnce(RouteSession<'_>) -> R,
    ) -> Option<R> {
        self.inner.engine.with_session(exit, edit)
    }

    /// Runs `edit` against one route's server-taught state, creating that state
    /// if this client has not used the route yet.
    ///
    /// The counterpart to [`Client::with_session`], for the case where creating
    /// a session is the point: seeding an exit's jar before its first request,
    /// or installing session state a browser earned on this client's behalf.
    /// That is the same use [`Client::with_hsts`] exists for.
    ///
    /// **This can evict another exit's session.** Creating a route inserts into
    /// the per-route map, and inserting runs the
    /// [`max_routes`](ProxyIsolation::PerProxy) eviction, which drops the least
    /// recently used route. On a client at its ceiling, seeding one exit
    /// discards the cookies of whichever exit has gone longest unused. That is
    /// the cost of a bounded store, and it is why reading is a separate method
    /// that cannot pay it.
    ///
    /// `exit` is `None` for the session unproxied requests use, which always
    /// exists and so is never created here.
    pub fn seed_session<R>(
        &self,
        exit: Option<&Arc<str>>,
        edit: impl FnOnce(RouteSession<'_>) -> R,
    ) -> R {
        self.inner.engine.seed_session(exit, edit)
    }

    /// Starts a request with an explicit method.
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder::new(Arc::clone(&self.inner), method, url.as_ref())
    }

    /// Starts a `GET`.
    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Starts a `POST`.
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Starts a `PUT`.
    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Starts a `PATCH`.
    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Starts a `DELETE`.
    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Starts a `HEAD`.
    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }
}

/// How many exit addresses a builder's proxy configuration can produce.
///
/// This is what decides the isolation default, and it is a property of the call
/// site rather than of anything observed at run time: [`ClientBuilder::proxy`]
/// names one exit, [`ClientBuilder::proxy_pool`] names as many as its list has,
/// and [`ClientBuilder::proxy_provider`] names a trait object that could return
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyRoutes {
    /// No proxy: one route, and it is the direct one.
    Direct,
    /// Exactly one exit, so isolating it from itself changes nothing.
    One,
    /// Several exits named up front.
    Several,
    /// A caller's own provider. Assumed to rotate, because a provider that does
    /// not is `Single` and would have been reached through `proxy`.
    Unknown,
}

impl ProxyRoutes {
    /// Whether this configuration can put requests on more than one exit.
    const fn may_rotate(self) -> bool {
        matches!(self, Self::Several | Self::Unknown)
    }
}

/// Mints one jar per exit for an isolated client.
///
/// A struct rather than a closure so the `cookie_store(false)` case is carried
/// explicitly: an engine that keeps no cookies still isolates client-hint
/// grants, and a factory that quietly handed it a jar anyway would turn the
/// switch off.
struct JarPerRoute {
    enabled: bool,
}

impl SessionFactory for JarPerRoute {
    fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
        self.enabled
            .then(|| Arc::new(Jar::new()) as Arc<dyn CookieStore>)
    }
}

/// Assembles a [`Client`].
pub struct ClientBuilder {
    profile: Arc<Profile>,
    cookie_store: bool,
    timeout: Option<Duration>,
    head_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    redirect: RedirectPolicy,
    resolver: Option<Arc<dyn Resolve>>,
    proxies: Option<Arc<dyn ProxyProvider>>,
    routes: ProxyRoutes,
    isolation: Option<ProxyIsolation>,
    concurrency: Option<Arc<dyn chromulate_http::concurrency::ConcurrencyController>>,
    middleware: Vec<Arc<dyn Middleware>>,
    retry: Option<Retry>,
    default_headers: HeaderMap,
    max_response_size: u64,
    pool: PoolConfig,
    decompression: ExpansionGuard,
    tls: Option<ActiveBackend>,
    shared_jar: Option<Arc<Jar>>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("profile", &self.profile.name)
            .field("cookie_store", &self.cookie_store)
            .field("timeout", &self.timeout)
            .field("redirect", &self.redirect)
            .field("routes", &self.routes)
            .field("isolation", &self.isolation)
            .field("middleware", &self.middleware.len())
            .finish_non_exhaustive()
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// A builder with browser defaults.
    ///
    /// Two of the three timeouts are on, both at thirty seconds:
    /// [`connect_timeout`] and [`head_timeout`]. The bound on a whole request,
    /// [`timeout`], is off, because a large download, a streamed response and
    /// an SSE stream all legitimately run long and no default could tell one of
    /// those from a hang. See [`no_head_timeout`] for the protocol that wants
    /// the head wait switched off as well.
    ///
    /// [`connect_timeout`]: ClientBuilder::connect_timeout
    /// [`head_timeout`]: ClientBuilder::head_timeout
    /// [`no_head_timeout`]: ClientBuilder::no_head_timeout
    /// [`timeout`]: ClientBuilder::timeout
    #[must_use]
    pub fn new() -> Self {
        Self {
            profile: Arc::new(Profile::chrome_stable()),
            cookie_store: true,
            timeout: None,
            // Thirty to match `connect_timeout` below, and the same value
            // `EngineConfig::new` uses: this builder overwrites the engine's
            // defaults wholesale, so a difference here would be invisible and
            // would win.
            head_timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(30)),
            redirect: RedirectPolicy::default(),
            resolver: None,
            proxies: None,
            routes: ProxyRoutes::Direct,
            isolation: None,
            concurrency: None,
            middleware: Vec::new(),
            retry: None,
            default_headers: HeaderMap::new(),
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            pool: PoolConfig::default(),
            decompression: ExpansionGuard::default(),
            tls: None,
            shared_jar: None,
        }
    }

    /// Sets the browser identity.
    #[must_use]
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = Arc::new(profile);
        self
    }

    /// Uses an already shared profile.
    #[must_use]
    pub fn shared_profile(mut self, profile: Arc<Profile>) -> Self {
        self.profile = profile;
        self
    }

    /// Turns the cookie jar on or off. On by default, as in a browser.
    #[must_use]
    pub fn cookie_store(mut self, enabled: bool) -> Self {
        self.cookie_store = enabled;
        self
    }

    /// Uses a specific cookie jar, so several clients can share a session.
    ///
    /// Naming one jar is also how a caller says "one session" when several
    /// proxies are configured: unless [`proxy_isolation`] states otherwise, a
    /// builder handed a jar keeps that jar for every exit rather than giving
    /// each its own. Saying both — this and
    /// [`ProxyIsolation::PerProxy`] — is a contradiction and [`build`] refuses
    /// it, because the jar could then only serve unproxied requests and
    /// ignoring it silently is the failure mode isolation exists to remove.
    ///
    /// [`build`]: ClientBuilder::build
    /// [`proxy_isolation`]: ClientBuilder::proxy_isolation
    #[must_use]
    pub fn cookie_jar(mut self, jar: Arc<Jar>) -> Self {
        self.cookie_store = true;
        self.shared_jar = Some(jar);
        self
    }

    /// Bounds a whole request, redirects included.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bounds the wait for one response head, replacing the thirty-second
    /// default.
    ///
    /// This is a per-hop bound, so a redirect chain gets it once per hop rather
    /// than once in total. Use [`timeout`](ClientBuilder::timeout) for a bound
    /// on the whole request.
    #[must_use]
    pub fn head_timeout(mut self, timeout: Duration) -> Self {
        self.head_timeout = Some(timeout);
        self
    }

    /// Waits for a response head for as long as the server takes.
    ///
    /// Long polling is the case this exists for: a server that deliberately
    /// withholds the head until an event fires is not stalled, and the
    /// thirty-second default would cut it off. Anything else that treats
    /// silence as part of the protocol wants this too.
    ///
    /// Nothing else is loosened — [`connect_timeout`] still bounds getting to
    /// the server, and a [`timeout`] still bounds the whole request if one is
    /// set.
    ///
    /// [`connect_timeout`]: ClientBuilder::connect_timeout
    /// [`timeout`]: ClientBuilder::timeout
    #[must_use]
    pub fn no_head_timeout(mut self) -> Self {
        self.head_timeout = None;
        self
    }

    /// Bounds establishing a connection.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Routes every request through a proxy.
    ///
    /// Accepts `http`, `https`, `socks5` and `socks5h` URLs. Prefer `socks5h`
    /// over `socks5`: `socks5` resolves the target hostname locally and so
    /// leaks it to the local resolver, while `socks5h` hands the name to the
    /// proxy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the URL is not a usable proxy URL.
    pub fn proxy(mut self, proxy: impl AsRef<str>) -> Result<Self> {
        let url = ProxyUrl::parse(proxy.as_ref())?;
        self.proxies = Some(Arc::new(Single::new(Proxy::new(url))));
        self.routes = ProxyRoutes::One;
        Ok(self)
    }

    /// Rotates over a pool of proxies.
    ///
    /// **Each proxy gets its own cookies** — see
    /// [`proxy_isolation`](ClientBuilder::proxy_isolation), which is where that
    /// is decided and how it is turned off. A pool of one is one exit and so is
    /// left sharing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when any URL is not a usable proxy URL, or
    /// when the list is empty.
    pub fn proxy_pool<I, S>(mut self, proxies: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let parsed = proxies
            .into_iter()
            .map(|raw| ProxyUrl::parse(raw.as_ref()).map(Proxy::new))
            .collect::<Result<Vec<_>>>()?;
        if parsed.is_empty() {
            return Err(Error::config("a proxy pool needs at least one proxy"));
        }
        self.routes = if parsed.len() == 1 {
            ProxyRoutes::One
        } else {
            ProxyRoutes::Several
        };
        self.proxies = Some(Arc::new(RoundRobin::new(parsed)));
        Ok(self)
    }

    /// Uses a proxy provider directly, for a rotation policy this crate does
    /// not ship.
    ///
    /// A provider is assumed to rotate, so each exit it returns gets its own
    /// session. State [`ProxyIsolation::Shared`] through
    /// [`proxy_isolation`](ClientBuilder::proxy_isolation) for a provider that
    /// always answers with the same proxy.
    #[must_use]
    pub fn proxy_provider(mut self, provider: Arc<dyn ProxyProvider>) -> Self {
        self.proxies = Some(provider);
        self.routes = ProxyRoutes::Unknown;
        self
    }

    /// Chooses whether each proxy keeps its own session, or whether every exit
    /// shares one.
    ///
    /// # What is chosen when nothing says
    ///
    /// - No proxy, one proxy, or a pool of one — [`ProxyIsolation::Shared`].
    ///   There is one exit, so there is nothing to isolate it from, and this is
    ///   byte for byte what the client did before isolation existed.
    /// - A jar named through [`cookie_jar`](ClientBuilder::cookie_jar) —
    ///   [`ProxyIsolation::Shared`]. Handing the builder one jar is a caller
    ///   saying "one session", at the call site, which is the shape this API
    ///   would rather have than a doc comment.
    /// - A pool of two or more, or a [`proxy_provider`] —
    ///   [`ProxyIsolation::per_proxy`].
    ///
    /// # Why per-proxy is the default for a pool
    ///
    /// The two mistakes are not symmetric. Sharing a session the caller wanted
    /// split is **silent**: nothing fails, and the origin quietly learns that
    /// three exit addresses are one client — which is a stronger signal than
    /// using one address would have been. Splitting a session the caller wanted
    /// shared is **loud**: they are logged out, on the first run, and the fix is
    /// one line. Between a silent wrong answer and a loud one, the default
    /// belongs on the loud one.
    ///
    /// The opposite case is real and is why this switch exists: a caller
    /// rotating exits purely to spread load on a site they are logged in to
    /// wants one session, and says so.
    ///
    /// ```
    /// use chromulate::{Client, ProxyIsolation};
    ///
    /// // Three exits, three sessions — the default.
    /// let spread = Client::builder()
    ///     .proxy_pool(["http://a.proxy:8080", "http://b.proxy:8080"])?
    ///     .build()?;
    /// assert_eq!(spread.proxy_isolation(), ProxyIsolation::per_proxy());
    ///
    /// // Two exits, one logged-in session.
    /// let logged_in = Client::builder()
    ///     .proxy_pool(["http://a.proxy:8080", "http://b.proxy:8080"])?
    ///     .proxy_isolation(ProxyIsolation::Shared)
    ///     .build()?;
    /// assert_eq!(logged_in.proxy_isolation(), ProxyIsolation::Shared);
    /// # Ok::<(), chromulate::Error>(())
    /// ```
    ///
    /// # What isolation does not cover
    ///
    /// TLS session tickets are not split per exit; read
    /// [`ProxyIsolation`]'s documentation before treating isolated routes as
    /// unlinkable.
    ///
    /// [`proxy_provider`]: ClientBuilder::proxy_provider
    #[must_use]
    pub fn proxy_isolation(mut self, isolation: ProxyIsolation) -> Self {
        self.isolation = Some(isolation);
        self
    }

    /// Installs a per-origin concurrency controller.
    ///
    /// Nothing paces itself without one. [`ConcurrencyController`] is a trait
    /// and this crate ships no law behind it, so a caller whose system has
    /// limits it already knows can write their own rather than tune someone
    /// else's — and needs no feature switched on to do it.
    ///
    /// Two laws are published under the `adaptive-concurrency` feature, in the
    /// [`concurrency`](crate::concurrency) module: `AdaptiveConcurrency`, which
    /// learns what an origin tolerates, and `FixedConcurrency`, which holds a
    /// number you chose.
    ///
    /// A controller can only ever make a request wait. It runs below the
    /// middleware chain, so a [`RateLimiter`](chromulate_http::RateLimiter) has
    /// already spent its token before a controller is asked, and there is no way
    /// through this seam to send a request the caller's own limit has not
    /// released.
    ///
    /// [`ConcurrencyController`]: chromulate_http::concurrency::ConcurrencyController
    #[must_use]
    pub fn concurrency(
        mut self,
        controller: Arc<dyn chromulate_http::concurrency::ConcurrencyController>,
    ) -> Self {
        self.concurrency = Some(controller);
        self
    }

    /// Replaces the DNS resolver.
    #[must_use]
    pub fn resolver(mut self, resolver: impl Resolve) -> Self {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    /// Appends a middleware to the chain.
    ///
    /// Middleware wraps a whole logical request, so a chain sees one request
    /// even when the engine follows several redirect hops to satisfy it.
    #[must_use]
    pub fn middleware(mut self, middleware: impl Middleware) -> Self {
        self.middleware.push(Arc::new(middleware));
        self
    }

    /// Retries failed requests.
    ///
    /// Off by default: retrying is a policy decision with a cost, and a client
    /// that silently sends a request twice is surprising.
    #[must_use]
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = Some(Retry::with_policy(policy));
        self
    }

    /// Sets what to do with 3xx responses.
    #[must_use]
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.redirect = policy;
        self
    }

    /// Overrides the profile's `User-Agent`.
    ///
    /// **This makes the client's identity incoherent.** The profile's user
    /// agent is one part of a whole that also includes the TLS handshake, the
    /// HTTP/2 preface, and the client hint brands, all captured together from
    /// one browser build. Changing only this string produces a client claiming
    /// to be something its handshake contradicts, which is more distinctive
    /// than either the original profile or an honest non-browser client. Change
    /// the profile instead unless a specific server requires a specific string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Builder`] when the value is not a valid header value.
    pub fn user_agent(self, value: impl AsRef<str>) -> Result<Self> {
        self.default_header(USER_AGENT, value)
    }

    /// Adds a header sent with every request.
    ///
    /// A default header overrides what the profile would have produced for the
    /// same name, and keeps the profile's position for it in the header order.
    /// A name the profile does not know is appended after the profile's
    /// headers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Builder`] when the name or value is not valid.
    pub fn default_header<N>(mut self, name: N, value: impl AsRef<str>) -> Result<Self>
    where
        N: TryInto<HeaderName>,
        N::Error: fmt::Display,
    {
        let name = name
            .try_into()
            .map_err(|error| Error::builder(format!("invalid header name: {error}")))?;
        let value = HeaderValue::from_str(value.as_ref())
            .map_err(|error| Error::builder(format!("invalid header value: {error}")))?;
        self.default_headers.insert(name, value);
        Ok(self)
    }

    /// Caps what [`crate::Response::bytes`] and [`crate::Response::text`] will
    /// buffer.
    #[must_use]
    pub fn max_response_size(mut self, limit: u64) -> Self {
        self.max_response_size = limit;
        self
    }

    /// Sets the connection pool limits.
    #[must_use]
    pub fn pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool;
        self
    }

    /// Sets the decompression limits.
    #[must_use]
    pub fn decompression(mut self, guard: ExpansionGuard) -> Self {
        self.decompression = guard;
        self
    }

    /// Uses a TLS backend other than the one the profile would build, for a
    /// custom trust store or a shared session cache.
    ///
    /// The parameter is [`chromulate_tls::ActiveBackend`], the alias for
    /// whichever backend this build links, rather than the concrete
    /// [`TlsEngine`]. In the default build the two are the same type, so this
    /// signature is unchanged for every caller; naming the concrete type here
    /// is what stopped this crate compiling at all when the alias pointed
    /// somewhere else.
    #[must_use]
    pub fn tls(mut self, tls: ActiveBackend) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the profile cannot produce a TLS
    /// configuration, which usually means the platform trust store could not be
    /// read, or when [`cookie_jar`](ClientBuilder::cookie_jar) and
    /// [`ProxyIsolation::PerProxy`] are asked for together.
    pub fn build(self) -> Result<Client> {
        let isolation = match self.isolation {
            Some(isolation) => isolation,
            // A caller who named one jar named one session; a caller with one
            // exit has nothing to isolate it from. Everything else is a
            // rotation, and a rotation defaults to a session per exit.
            None if self.shared_jar.is_some() || !self.routes.may_rotate() => {
                ProxyIsolation::Shared
            }
            None => ProxyIsolation::per_proxy(),
        };

        if isolation.is_per_proxy() && self.shared_jar.is_some() {
            return Err(Error::config(
                "`cookie_jar` and `proxy_isolation(ProxyIsolation::PerProxy { .. })` contradict \
                 each other: the named jar would serve only requests that go through no proxy, \
                 and every exit would get one of its own. Drop one of the two.",
            ));
        }

        let mut config = EngineConfig::new(Arc::clone(&self.profile));
        config.timeout = self.timeout;
        config.head_timeout = self.head_timeout;
        config.connect_timeout = self.connect_timeout;
        config.redirect = self.redirect;
        config.pool = self.pool;

        let jar = if self.cookie_store {
            Some(self.shared_jar.unwrap_or_else(|| Arc::new(Jar::new())))
        } else {
            None
        };

        let mut builder = Engine::builder(config).decompression(self.decompression);
        if let Some(resolver) = self.resolver {
            builder = builder.resolver(resolver);
        }
        if let Some(proxies) = self.proxies {
            builder = builder.proxies(proxies);
        }
        if let Some(tls) = self.tls {
            builder = builder.tls(tls);
        }
        if let Some(retry) = self.retry {
            builder = builder.retry(retry);
        }
        if let Some(jar) = &jar {
            builder = builder.cookies(Arc::clone(jar) as Arc<dyn CookieStore>);
        }
        if let ProxyIsolation::PerProxy { max_routes } = isolation {
            builder = builder.isolate_by_proxy(
                max_routes,
                Arc::new(JarPerRoute {
                    enabled: self.cookie_store,
                }),
            );
        }
        if let Some(controller) = self.concurrency {
            builder = builder.concurrency(controller);
        }
        for middleware in self.middleware {
            builder = builder.middleware(middleware);
        }

        Ok(Client {
            inner: Arc::new(ClientInner {
                engine: builder.build()?,
                profile: self.profile,
                default_headers: self.default_headers,
                max_response_size: self.max_response_size,
                cookies: jar,
            }),
        })
    }
}
