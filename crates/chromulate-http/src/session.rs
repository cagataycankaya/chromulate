//! What a client keeps per exit address, and what it keeps once.
//!
//! [`crate::pool::PoolKey`] already refuses to serve a request routed through
//! one proxy over a connection opened through another. That is the transport
//! layer getting it right. This module is the same rule one layer up: the state
//! an origin can *observe* — the cookies it set, the validators it issued, the
//! client-hint grant it made — belongs to the exit it was learned through, not
//! to the process.
//!
//! # Why sharing it is a defect rather than a trade
//!
//! Measured against three ISP proxies with distinct, stable exit IPs: one
//! `Client` per proxy showed a cookie on one exit and nothing on the other two;
//! one `Client` with a `proxy_pool` of all three showed the same cookie on all
//! three. A caller who configures three exits has asked to spread traffic over
//! three addresses, and answering from one session through all three does not
//! merely waste that — it **couples** the three addresses for the origin, which
//! is a stronger signal than using one address would have been. And it happened
//! silently, which is what makes it a defect.
//!
//! # What is *not* here, and why
//!
//! - **HSTS.** A policy about an origin, not about a client. It is also applied
//!   before a route exists — the upgrade changes the scheme, and therefore the
//!   port, and therefore the origin the proxy is chosen for — so there is no
//!   route to key it by at the moment it is consulted. Splitting it would send
//!   the first request through each new exit in plaintext, which is a downgrade
//!   bought with an isolation win nobody asked for. See [`crate::hsts`].
//! - **The connection pool.** Already keyed by proxy; see [`crate::pool`].
//! - **The DNS cache.** A proxied route never resolves locally at all — the
//!   proxy resolves the target name inside the tunnel — so there is nothing per
//!   route to keep.
//! - **The response cache.** Isolating it needs a second store per route, and
//!   this crate is handed a built [`chromulate_cache::HttpCache`] rather than
//!   the means to make another. [`crate::EngineBuilder::build`] therefore
//!   refuses the combination rather than sharing one silently.
//! - **TLS session tickets.** A resumed handshake presenting a ticket the origin
//!   issued to another exit links the two below HTTP, and the store lives in
//!   `chromulate-tls` behind a `rustls::ClientConfig` that cannot be re-pointed
//!   without rebuilding it. It is a real remaining leak, stated in
//!   [`ProxyIsolation`]'s documentation rather than left to be discovered.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use chromulate_core::CookieStore;
use chromulate_header::AcceptChStore;

/// How much of the state an origin can observe is shared between the proxies a
/// client rotates over.
///
/// ```
/// use chromulate_http::ProxyIsolation;
///
/// // The default an engine falls back to when nothing asks for isolation.
/// assert_eq!(ProxyIsolation::Shared, ProxyIsolation::Shared);
///
/// // A cap on the number of routes that may hold their own state, so
/// // splitting one bounded store cannot produce an unbounded family of them.
/// assert_eq!(
///     ProxyIsolation::per_proxy(),
///     ProxyIsolation::PerProxy { max_routes: ProxyIsolation::DEFAULT_MAX_ROUTES },
/// );
/// ```
///
/// # What isolation does not cover
///
/// A TLS 1.3 session ticket is issued by the origin and presented on the next
/// handshake to it. The resumption store lives in `chromulate-tls`, bound into
/// one `rustls::ClientConfig`, and is **not** split per route — so a resumed
/// handshake through one exit can carry a ticket the origin issued to another.
/// That links the two exits below HTTP, before a cookie is sent. Building one
/// client per proxy, each with its own TLS engine, is the only thing that
/// closes it today.
///
/// # What it costs on the request path
///
/// One lookup per hop, keyed by the proxy label, and `CLAUDE.md` is right to
/// ask for the number before anyone puts a lock in front of every request.
/// Measured on an Apple M1 Pro on 2026-08-05, best of seven passes over a
/// million calls, three runs, against a control loop that only indexes the
/// label array (0.96 / 0.93 / 0.95 ns) so the loop's own cost is visible rather
/// than folded in:
///
/// | case | ns per lookup | over the control |
/// | --- | --- | --- |
/// | [`Shared`](ProxyIsolation::Shared) — one `Option` branch, no lock | 3.48 / 3.50 / 3.41 | ~2.5 ns |
/// | [`PerProxy`](ProxyIsolation::PerProxy), unproxied request | same branch, same arm | ~2.5 ns |
/// | [`PerProxy`](ProxyIsolation::PerProxy), 8 live exits | 23.45 / 23.38 / 23.47 | ~22.5 ns |
///
/// The shared row is the one that matters, because it is what every client with
/// no proxy and every client with one proxy gets: there is no map to consult,
/// so no lock is taken and no label is hashed. The isolated row is about 20 ns
/// more than that — an `RwLock::read`, a hash of a short string, one relaxed
/// store to record the use, and an `Arc` clone — which beside a millisecond of
/// network is five parts in a million.
///
/// The `Arc` clone is not avoidable and is deliberate: the map's read guard
/// must be released before the request awaits, because a lock held across an
/// `.await` is what `Engine::with_hsts` was reshaped to make unwritable. It
/// allocates nothing, and neither does the lookup — `HashMap<Arc<str>, _>`
/// hashes a borrowed `&str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyIsolation {
    /// One session for every route: a cookie set through one exit is presented
    /// through all of them.
    ///
    /// This is what an engine does when nothing installs a session factory, and
    /// it is what a caller rotating exits purely to spread load on a site they
    /// are logged in to wants.
    Shared,
    /// Each proxy keeps its own cookies, client-hint grants and — with the
    /// `validator-store` feature — its own validators.
    ///
    /// `max_routes` bounds how many exits may hold state at once. Past it the
    /// least recently used route's state is dropped, so the next request
    /// through that exit starts a fresh session rather than borrowing another
    /// exit's: losing a session is loud and recoverable, sharing one silently
    /// is the defect this exists to prevent.
    PerProxy {
        /// The most exits that may hold their own state at one time.
        max_routes: usize,
    },
}

impl ProxyIsolation {
    /// How many exits hold their own state before the least recently used one
    /// is dropped.
    ///
    /// Thirty-two rather than a rounder number because of what isolation is
    /// *for*: a session per exit only means anything when an exit is used
    /// repeatedly, which describes a small, stable set — the three ISP proxies
    /// this was measured against, a datacentre pool, a handful of regions. A
    /// caller rotating over hundreds of residential exits is not building a
    /// session per exit, and the cap turns that into "no session survives",
    /// which is the honest outcome rather than a surprising memory bill.
    pub const DEFAULT_MAX_ROUTES: usize = 32;

    /// Per-proxy isolation with [`ProxyIsolation::DEFAULT_MAX_ROUTES`].
    #[must_use]
    pub const fn per_proxy() -> Self {
        Self::PerProxy {
            max_routes: Self::DEFAULT_MAX_ROUTES,
        }
    }

    /// Whether each proxy keeps its own state.
    #[must_use]
    pub const fn is_per_proxy(&self) -> bool {
        matches!(self, Self::PerProxy { .. })
    }
}

/// Builds the state an isolated engine gives a route it has not served before.
///
/// This crate holds cookies behind [`CookieStore`] on purpose — a caller may
/// supply their own — so it cannot mint one itself, and an engine that isolates
/// routes has to be told how. Everything else in a route's state is built from
/// what the engine already has: a validator store copies the installed store's
/// capacity, and a client-hint store copies its limits.
///
/// ```
/// use std::sync::Arc;
///
/// use chromulate_core::{CookieStore, CookieContext};
/// use chromulate_http::SessionFactory;
///
/// /// A factory for an engine that keeps no cookies at all, so every route
/// /// still gets its own client-hint grant but none of them store anything.
/// struct NoCookies;
///
/// impl SessionFactory for NoCookies {
///     fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
///         None
///     }
/// }
///
/// let factory: Arc<dyn SessionFactory> = Arc::new(NoCookies);
/// assert!(factory.cookies().is_none());
/// ```
pub trait SessionFactory: Send + Sync + 'static {
    /// A fresh, empty cookie store for a route this engine has not served
    /// before, or `None` for an engine that keeps no cookies.
    fn cookies(&self) -> Option<Arc<dyn CookieStore>>;
}

impl fmt::Debug for dyn SessionFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionFactory")
    }
}

/// Everything one route remembers about the origins it has spoken to.
pub(crate) struct Session {
    cookies: Option<Arc<dyn CookieStore>>,
    accept_ch: RwLock<AcceptChStore>,
    #[cfg(feature = "validator-store")]
    validators: Option<Arc<crate::validators::ValidatorStore>>,
}

impl Session {
    pub(crate) fn cookies(&self) -> Option<&Arc<dyn CookieStore>> {
        self.cookies.as_ref()
    }

    #[cfg(feature = "validator-store")]
    pub(crate) fn validators(&self) -> Option<&Arc<crate::validators::ValidatorStore>> {
        self.validators.as_ref()
    }

    /// Runs `read` against this route's client-hint grants.
    pub(crate) fn with_accept_ch<R>(&self, read: impl FnOnce(&AcceptChStore) -> R) -> R {
        let store = self
            .accept_ch
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&store)
    }

    /// Records a grant this route was given.
    pub(crate) fn record_accept_ch(&self, origin: chromulate_core::Origin, value: &str) {
        self.accept_ch
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(origin, value);
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("cookies", &self.cookies.is_some())
            .finish_non_exhaustive()
    }
}

/// A session borrowed from the engine, or one taken out of the per-route map.
///
/// The borrowed arm is the common case by a wide margin — every request of an
/// engine with no proxy, and every request of an engine that shares one session
/// — and it is a borrow rather than an [`Arc`] clone so that path adds no
/// atomic traffic at all. The owned arm exists because the map's read guard
/// must be released before the request awaits the network: a lock held across
/// an `.await` is the shape `Engine::with_hsts` was reshaped to make
/// unwritable.
///
/// Two pointers of the same type cannot share a niche, so this is sixteen bytes
/// and it lives in the hop's future across the network await. That is visible in
/// the allocation harness: `cargo run --release -p chromulate-bench --bin
/// allocs` measured **48 allocations and 20,751 bytes** per steady-state request
/// on 2026-08-05, against 20,735 before, byte-identical across three runs each.
/// The allocation count — the published figure — does not move; the sixteen
/// bytes are the price of taking the lock once per hop rather than three times,
/// and collapsing this to a plain `Arc<Session>` would save them by charging
/// two atomics to every unproxied request instead.
pub(crate) enum SessionRef<'a> {
    Base(&'a Session),
    Route(Arc<Session>),
}

impl std::ops::Deref for SessionRef<'_> {
    type Target = Session;

    fn deref(&self) -> &Session {
        match self {
            Self::Base(session) => session,
            Self::Route(session) => session,
        }
    }
}

/// One route's state, plus the bookkeeping eviction ranks on.
struct Entry {
    session: Arc<Session>,
    /// Ticks once per use, so eviction can pick the least recently used route
    /// without a clock.
    ///
    /// An [`AtomicU64`] rather than a plain field so a hit records its use
    /// under a read lock, exactly as `ValidatorStore` and the cookie jar do,
    /// and a counter rather than an `Instant` because `Instant + Duration`
    /// panics on overflow while `fetch_add` wraps. At a billion uses a second a
    /// wrap is five centuries away, and the only consequence then is one poor
    /// eviction choice.
    last_use_seq: AtomicU64,
}

struct Isolated {
    routes: RwLock<HashMap<Arc<str>, Entry>>,
    seq: AtomicU64,
    max_routes: usize,
    factory: Arc<dyn SessionFactory>,
    /// Copied from the base session's store so a minted one is bounded the same
    /// way, rather than by a number invented here.
    accept_ch_limits: chromulate_header::AcceptChLimits,
    #[cfg(feature = "validator-store")]
    validator_capacity: Option<usize>,
}

impl Isolated {
    fn session_for(&self, proxy: &Arc<str>) -> Arc<Session> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        {
            let routes = self.read();
            if let Some(entry) = routes.get(proxy.as_ref()) {
                entry.last_use_seq.store(seq, Ordering::Relaxed);
                return Arc::clone(&entry.session);
            }
        }

        // A route this engine has not served before. Rare by construction —
        // once per distinct exit — so the write lock and the eviction scan are
        // not on the path a request normally takes.
        let mut routes = self.write();
        // Another task may have minted it while no lock was held.
        if let Some(entry) = routes.get(proxy.as_ref()) {
            entry.last_use_seq.store(seq, Ordering::Relaxed);
            return Arc::clone(&entry.session);
        }

        let session = Arc::new(self.mint());
        routes.insert(
            Arc::clone(proxy),
            Entry {
                session: Arc::clone(&session),
                last_use_seq: AtomicU64::new(seq),
            },
        );
        self.evict(&mut routes);
        session
    }

    fn mint(&self) -> Session {
        Session {
            cookies: self.factory.cookies(),
            accept_ch: RwLock::new(AcceptChStore::with_limits(self.accept_ch_limits)),
            #[cfg(feature = "validator-store")]
            validators: self.validator_capacity.map(|capacity| {
                Arc::new(crate::validators::ValidatorStore::with_capacity(capacity))
            }),
        }
    }

    /// Drops the least recently used routes until the map is back inside its
    /// cap.
    ///
    /// One at a time rather than in a batch, because the map is small — the cap
    /// is what makes it small — and this runs only when a *new* route appears,
    /// not on every request. There is no purge batch to amortise a scan over.
    ///
    /// A dropped route's next request starts a fresh session. That is the loud
    /// failure and it is the one to choose: the alternative, handing the route
    /// some other exit's state, is the coupling this module exists to prevent.
    fn evict(&self, routes: &mut HashMap<Arc<str>, Entry>) {
        while routes.len() > self.max_routes {
            let Some(victim) = routes
                .iter()
                .min_by_key(|(_, entry)| entry.last_use_seq.load(Ordering::Relaxed))
                .map(|(key, _)| Arc::clone(key))
            else {
                return;
            };
            // `debug` rather than `warn`: a provider rotating over hundreds of
            // exits evicts on most requests, and a warning per request is a log
            // flood rather than a signal. The cap is documented on
            // `ProxyIsolation::PerProxy` instead, which is where a caller can
            // act on it.
            tracing::debug!(
                proxy = %victim,
                max_routes = self.max_routes,
                "dropping the least recently used route's session state"
            );
            routes.remove(&victim);
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Arc<str>, Entry>> {
        self.routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Arc<str>, Entry>> {
        self.routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The engine's sessions: one shared, or one per route.
pub(crate) struct Sessions {
    base: Arc<Session>,
    /// `None` when routes share one session, and that is what keeps the default
    /// path free: no lock is taken and no label is hashed, because there is no
    /// map to consult.
    isolated: Option<Isolated>,
}

impl Sessions {
    /// One session for every route.
    pub(crate) fn shared(
        cookies: Option<Arc<dyn CookieStore>>,
        #[cfg(feature = "validator-store")] validators: Option<
            Arc<crate::validators::ValidatorStore>,
        >,
    ) -> Self {
        Self {
            base: Arc::new(Session {
                cookies,
                accept_ch: RwLock::new(AcceptChStore::new()),
                #[cfg(feature = "validator-store")]
                validators,
            }),
            isolated: None,
        }
    }

    /// Gives `factory`-minted state to every route but the direct one.
    ///
    /// The base session keeps what the builder was handed and serves requests
    /// that go through no proxy at all; every proxy gets its own.
    pub(crate) fn per_proxy(
        cookies: Option<Arc<dyn CookieStore>>,
        #[cfg(feature = "validator-store")] validators: Option<
            Arc<crate::validators::ValidatorStore>,
        >,
        max_routes: usize,
        factory: Arc<dyn SessionFactory>,
    ) -> Self {
        let accept_ch = AcceptChStore::new();
        let accept_ch_limits = accept_ch.limits();
        #[cfg(feature = "validator-store")]
        let validator_capacity = validators.as_ref().map(|store| store.capacity());

        Self {
            base: Arc::new(Session {
                cookies,
                accept_ch: RwLock::new(accept_ch),
                #[cfg(feature = "validator-store")]
                validators,
            }),
            isolated: Some(Isolated {
                routes: RwLock::new(HashMap::new()),
                seq: AtomicU64::new(0),
                // Zero is raised to one, as every capacity in this workspace is:
                // a registry that cannot hold the route it was just asked for
                // would mint a session per request and drop it again, which is
                // a silently disabled feature rather than a small one.
                max_routes: max_routes.max(1),
                factory,
                accept_ch_limits,
                #[cfg(feature = "validator-store")]
                validator_capacity,
            }),
        }
    }

    /// The session a request routed through `proxy` speaks with.
    ///
    /// `proxy` is the redacted label [`crate::pool::PoolKey`] carries, so a
    /// route's state is keyed by exactly what its connections are keyed by.
    pub(crate) fn for_route(&self, proxy: Option<&Arc<str>>) -> SessionRef<'_> {
        let (Some(isolated), Some(proxy)) = (&self.isolated, proxy) else {
            return SessionRef::Base(&self.base);
        };
        SessionRef::Route(isolated.session_for(proxy))
    }

    pub(crate) fn isolation(&self) -> ProxyIsolation {
        match &self.isolated {
            Some(isolated) => ProxyIsolation::PerProxy {
                max_routes: isolated.max_routes,
            },
            None => ProxyIsolation::Shared,
        }
    }

    /// How many proxies currently hold state of their own.
    pub(crate) fn isolated_routes(&self) -> usize {
        self.isolated
            .as_ref()
            .map_or(0, |isolated| isolated.read().len())
    }
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("isolation", &self.isolation())
            .field("routes", &self.isolated_routes())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Counts how many stores it has been asked for, so a test can tell a
    /// cached route from a freshly minted one.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl SessionFactory for Counting {
        fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    fn label(text: &str) -> Arc<str> {
        Arc::from(text)
    }

    fn per_proxy(max_routes: usize, factory: Arc<Counting>) -> Sessions {
        Sessions::per_proxy(
            None,
            #[cfg(feature = "validator-store")]
            None,
            max_routes,
            factory,
        )
    }

    fn shared() -> Sessions {
        Sessions::shared(
            None,
            #[cfg(feature = "validator-store")]
            None,
        )
    }

    #[test]
    fn a_shared_registry_answers_every_route_with_the_same_session() {
        let sessions = shared();
        let direct = sessions.for_route(None);
        let one = sessions.for_route(Some(&label("http://a:8080")));
        let two = sessions.for_route(Some(&label("http://b:8080")));

        assert!(std::ptr::eq(&*direct, &*one));
        assert!(std::ptr::eq(&*one, &*two));
        assert_eq!(sessions.isolation(), ProxyIsolation::Shared);
    }

    #[test]
    fn an_isolated_registry_gives_each_proxy_its_own_session_and_reuses_it() {
        let factory = Arc::new(Counting::default());
        let sessions = per_proxy(4, Arc::clone(&factory));

        let one = sessions.for_route(Some(&label("http://a:8080")));
        let two = sessions.for_route(Some(&label("http://b:8080")));
        assert!(!std::ptr::eq(&*one, &*two));
        assert_eq!(factory.0.load(Ordering::Relaxed), 2);

        // The second visit is the same session, not a third mint.
        let again = sessions.for_route(Some(&label("http://a:8080")));
        assert!(std::ptr::eq(&*one, &*again));
        assert_eq!(factory.0.load(Ordering::Relaxed), 2);
        assert_eq!(sessions.isolated_routes(), 2);
    }

    #[test]
    fn an_unproxied_request_keeps_the_base_session_even_when_routes_are_isolated() {
        let factory = Arc::new(Counting::default());
        let sessions = per_proxy(4, Arc::clone(&factory));

        let direct = sessions.for_route(None);
        let proxied = sessions.for_route(Some(&label("http://a:8080")));
        assert!(!std::ptr::eq(&*direct, &*proxied));
        // The direct route costs no mint: it is the session the builder built.
        assert_eq!(factory.0.load(Ordering::Relaxed), 1);
        assert_eq!(sessions.isolated_routes(), 1);
    }

    #[test]
    fn the_cap_is_a_ceiling_and_the_least_recently_used_route_is_the_one_dropped() {
        let factory = Arc::new(Counting::default());
        let sessions = per_proxy(2, Arc::clone(&factory));

        let _ = sessions.for_route(Some(&label("http://a:8080")));
        let _ = sessions.for_route(Some(&label("http://b:8080")));
        // Touch `a` so `b` is the least recently used.
        let a = sessions.for_route(Some(&label("http://a:8080")));
        let _ = sessions.for_route(Some(&label("http://c:8080")));

        assert_eq!(sessions.isolated_routes(), 2, "the cap is never exceeded");
        assert!(
            std::ptr::eq(&*a, &*sessions.for_route(Some(&label("http://a:8080")))),
            "the recently used route survived"
        );
        // `b` was dropped, so asking for it again mints: four mints for three
        // distinct labels.
        let _ = sessions.for_route(Some(&label("http://b:8080")));
        assert_eq!(factory.0.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn a_cap_of_zero_is_raised_to_one_rather_than_holding_nothing() {
        let factory = Arc::new(Counting::default());
        let sessions = per_proxy(0, factory);
        let _ = sessions.for_route(Some(&label("http://a:8080")));
        assert_eq!(sessions.isolated_routes(), 1);
        assert_eq!(
            sessions.isolation(),
            ProxyIsolation::PerProxy { max_routes: 1 }
        );
    }

    /// A client-hint grant is server-taught state that changes what later
    /// requests send, which puts it in the same class as a cookie: an origin
    /// that granted hints to one exit and then sees another exit send them
    /// unprompted has linked the two.
    ///
    /// This is proved here rather than on the wire, and deliberately so: the
    /// shipped Chrome profile carries **no** high-entropy hint values — see
    /// `chromulate_header::client_hints`, where `HighEntropyHints` is empty
    /// until someone captures real ones — so a granted hint currently emits no
    /// header at all and an integration test could not tell the two behaviours
    /// apart. Reverting the split turns this test red, which is the property
    /// being claimed; the day the values are captured, the leak would otherwise
    /// have arrived silently.
    #[test]
    fn a_grant_recorded_on_one_route_is_not_visible_on_another() {
        let sessions = per_proxy(4, Arc::new(Counting::default()));
        let origin = chromulate_core::Origin::of(
            &url::Url::parse("https://example.com/").expect("a valid url"),
        )
        .expect("a valid origin");

        sessions
            .for_route(Some(&label("http://a:8080")))
            .record_accept_ch(origin.clone(), "sec-ch-ua-platform-version");

        assert!(
            !sessions
                .for_route(Some(&label("http://a:8080")))
                .with_accept_ch(|store| store.granted_for(&origin).is_empty()),
            "the exit that was granted the hints keeps them"
        );
        assert!(
            sessions
                .for_route(Some(&label("http://b:8080")))
                .with_accept_ch(|store| store.granted_for(&origin).is_empty()),
            "an exit the origin never granted anything must send nothing extra"
        );
        assert!(
            sessions
                .for_route(None)
                .with_accept_ch(|store| store.granted_for(&origin).is_empty()),
            "and neither must a direct request"
        );
    }

    #[test]
    fn per_proxy_is_the_named_default_cap() {
        assert_eq!(
            ProxyIsolation::per_proxy(),
            ProxyIsolation::PerProxy {
                max_routes: ProxyIsolation::DEFAULT_MAX_ROUTES
            }
        );
        assert!(ProxyIsolation::per_proxy().is_per_proxy());
        assert!(!ProxyIsolation::Shared.is_per_proxy());
    }
}
