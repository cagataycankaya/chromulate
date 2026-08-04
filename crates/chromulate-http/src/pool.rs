//! The connection pool, and the key that decides what may be reused.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chromulate_core::Body;
use chromulate_profile::Profile;
use hyper::client::conn::{http1, http2};

/// The application protocol a connection speaks.
///
/// Part of the pool key: an h2 connection and an h1 connection to the same
/// origin are different connections and one cannot serve the other's requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
}

impl Protocol {
    /// The ALPN identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http11 => "http/1.1",
            Self::Http2 => "h2",
        }
    }

    /// The `http` crate's version constant.
    #[must_use]
    pub const fn version(self) -> http::Version {
        match self {
            Self::Http11 => http::Version::HTTP_11,
            Self::Http2 => http::Version::HTTP_2,
        }
    }
}

/// The observable network identity a connection was opened with.
///
/// Derived from the profile's content rather than from the address of the
/// `Profile` value, so two engines built from equal profiles agree, and two
/// engines built from different profiles disagree, however they were
/// constructed.
///
/// The three components are the three things a server can tell apart: the
/// handshake (JA4), the HTTP/2 preface (the Akamai fingerprint), and the
/// `User-Agent`. A profile that differs in any of them is a different client on
/// the wire and must not be served from another profile's connection.
#[derive(Clone)]
pub struct ConnectionIdentity {
    text: Arc<str>,
    /// The content's hash, computed once at construction. A pool probe hashes
    /// the key two to three times per request, and the identity string —
    /// dominated by the user agent — is around 200 bytes; writing a cached
    /// word instead keeps that off the request path.
    content_hash: u64,
}

impl ConnectionIdentity {
    /// Computes the identity of a profile.
    ///
    /// Call this once when an engine is built, not per request: it hashes the
    /// whole ClientHello specification by way of the JA4 computation.
    #[must_use]
    pub fn of(profile: &Profile) -> Self {
        let text: Arc<str> = format!(
            "{}|{}|{}",
            profile.ja4(),
            profile.akamai_http2(),
            profile.user_agent
        )
        .into();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut hasher);
        Self {
            content_hash: hasher.finish(),
            text,
        }
    }

    /// The identity as a string, for logs and tests.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl PartialEq for ConnectionIdentity {
    fn eq(&self, other: &Self) -> bool {
        // The hash first: two different identities almost always part ways on
        // one word instead of a 200-byte string compare.
        self.content_hash == other.content_hash && self.text == other.text
    }
}

impl Eq for ConnectionIdentity {}

impl Hash for ConnectionIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.content_hash);
    }
}

impl fmt::Debug for ConnectionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionIdentity({})", self.text)
    }
}

/// What makes two requests eligible to share one connection.
///
/// **Do not narrow this to the origin.** It is the obvious simplification and
/// it silently destroys the property the whole project exists to provide.
/// A pooled connection carries a TLS handshake and an HTTP/2 SETTINGS preface
/// that were sent once, when it was opened. Serving a second request over it
/// means that request is observed with the *first* request's fingerprint. Two
/// clients configured with different profiles would then be distinguishable
/// from each other only by whichever of them opened the connection — which is
/// both wrong and worse than not emulating at all, because the resulting
/// identity is a blend that no real browser produces.
///
/// The proxy is in the key for the same reason at the IP layer: a request
/// routed through a rotating proxy pool must not be served over a connection
/// established through a different exit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    /// `http` or `https`.
    pub scheme: Arc<str>,
    /// The lowercased host.
    pub host: Arc<str>,
    /// The port, with the scheme default filled in.
    pub port: u16,
    /// The proxy the connection is routed through, credentials redacted.
    pub proxy: Option<Arc<str>>,
    /// The profile the connection was opened with.
    pub identity: ConnectionIdentity,
    /// The protocol negotiated over the connection.
    pub protocol: Protocol,
}

impl fmt::Display for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)?;
        if let Some(proxy) = &self.proxy {
            write!(f, " via {proxy}")?;
        }
        write!(
            f,
            " [{} {}]",
            self.protocol.as_str(),
            self.identity.as_str()
        )
    }
}

/// A live connection, in whichever of the two shapes it has.
pub(crate) enum Connection {
    /// Exclusive for the duration of one request.
    Http1(http1::SendRequest<Body>),
    /// Multiplexed, so one connection serves concurrent requests.
    Http2(http2::SendRequest<Body>),
}

impl Connection {
    fn is_usable(&self) -> bool {
        match self {
            Self::Http1(sender) => !sender.is_closed(),
            Self::Http2(sender) => !sender.is_closed(),
        }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        match self {
            Self::Http1(_) => Protocol::Http11,
            Self::Http2(_) => Protocol::Http2,
        }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Connection")
            .field(&self.protocol().as_str())
            .finish()
    }
}

/// Limits on how many connections are kept and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// How long an idle HTTP/1.1 connection is kept before it is dropped.
    pub idle_timeout: Duration,
    /// The most connections kept for one pool key.
    pub max_per_host: usize,
    /// The most connections kept in each of the pool's two populations: idle
    /// HTTP/1.1 sockets, and registered HTTP/2 connections.
    ///
    /// Each population separately, not their sum, so a pool can hold up to
    /// `2 * max_total` entries — `100` by default means at most 100 idle
    /// HTTP/1.1 sockets *and* at most 100 multiplexed connections. In practice
    /// the second number is bounded far below that by the number of distinct
    /// HTTP/2 origins in flight, since a key holds one multiplexed connection
    /// however many requests ride it.
    ///
    /// They are counted apart because one number for both was a defect rather
    /// than a simplification. The only entry this cap can free is an idle
    /// HTTP/1.1 socket: at its cap the multiplexed population declines to pool
    /// a new origin rather than evicting one, since deregistering a live
    /// multiplexed connection would make the next request open a second
    /// connection to an origin that already has one — a shape no browser
    /// produces. So every HTTP/2 entry counted here raised the number that
    /// HTTP/1.1 eviction reacted to while contributing nothing it could
    /// reclaim. Against `max_total = 10`, twenty HTTP/2 origins left one
    /// survivor out of five subsequent HTTP/1.1 releases: each release found
    /// the pool over cap and threw away the one before it.
    pub max_total: usize,
    /// Ceiling for hyper's per-connection HTTP/1.1 read and write buffers, in
    /// bytes. `None` keeps hyper's default of 408 KiB.
    ///
    /// The read buffer grows adaptively and never shrinks while a connection
    /// idles in the pool, so a wide pool that once saw fast large responses
    /// can hold hundreds of kilobytes per connection. Lowering this bounds
    /// that — but the same ceiling is the largest response **header block**
    /// hyper will accept before failing the request, so it is a behavioural
    /// limit, not a free optimisation. Values below hyper's 8 KiB minimum
    /// are raised to it rather than passed through, because hyper treats a
    /// smaller value as a caller bug and panics.
    pub http1_max_buf_size: Option<usize>,
}

impl Default for PoolConfig {
    /// Six per host matches the limit browsers apply to HTTP/1.1 origins, which
    /// is the case this cap exists for; HTTP/2 keeps one connection per key
    /// regardless.
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(90),
            max_per_host: 6,
            max_total: 100,
            http1_max_buf_size: None,
        }
    }
}

struct Idle {
    connection: Connection,
    since: Instant,
}

/// A shared pool of established connections.
///
/// Cloning is cheap and clones share one pool. Two engines may share a pool
/// only when their TLS configuration matches: [`PoolKey`] covers the profile
/// identity, which is what a server observes, not the trust store, which it
/// does not.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Mutex<PoolState>>,
    config: PoolConfig,
}

struct PoolState {
    /// HTTP/1.1 connections waiting to be checked out. A key maps to several
    /// because a browser opens several per origin.
    idle: HashMap<PoolKey, Vec<Idle>>,
    /// HTTP/2 connections, which stay in the map while in use because they are
    /// multiplexed.
    multiplexed: HashMap<PoolKey, Connection>,
    /// Entries in `idle`, kept in step by every insert and remove, so asking
    /// whether the idle pool is full does not walk it.
    ///
    /// HTTP/1.1 only. The multiplexed population is not counted here and does
    /// not need a counter of its own: `multiplexed` holds one connection per
    /// key, so `HashMap::len` already is that count, in O(1) and with no way
    /// to drift from the map it describes. The one counter this replaced
    /// tracked both maps by hand and drifted in exactly that way — the HTTP/2
    /// release path incremented it and then returned above the cap check, so
    /// it grew without bound while HTTP/1.1 releases paid for the growth.
    idle_held: usize,
    /// When the last full expiry sweep ran; see [`Pool::sweep_if_due`].
    last_sweep: Instant,
}

impl PoolState {
    /// Connections held across both populations.
    fn held(&self) -> usize {
        self.idle_held + self.multiplexed.len()
    }
}

impl Pool {
    /// Builds a pool with the given limits.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolState {
                idle: HashMap::new(),
                multiplexed: HashMap::new(),
                idle_held: 0,
                last_sweep: Instant::now(),
            })),
            config,
        }
    }

    /// The limits this pool enforces.
    #[must_use]
    pub fn config(&self) -> PoolConfig {
        self.config
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        // A panic while holding this lock leaves the maps structurally intact —
        // every operation on them is a single insert or remove — so recovering
        // is better than poisoning every later request.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes a connection for `key`, if a usable one is pooled.
    ///
    /// An HTTP/2 connection is cloned and left in the pool, because it
    /// multiplexes. An HTTP/1.1 connection is removed and must be returned with
    /// [`Pool::release`] once the response body is finished with.
    pub(crate) fn checkout(&self, key: &PoolKey) -> Option<Connection> {
        let mut guard = self.lock();
        let state = &mut *guard;

        if let Some(shared) = state.multiplexed.get(key) {
            if shared.is_usable() {
                if let Connection::Http2(sender) = shared {
                    return Some(Connection::Http2(sender.clone()));
                }
            } else {
                state.multiplexed.remove(key);
            }
        }

        let now = Instant::now();
        let idle_timeout = self.config.idle_timeout;
        let entries = state.idle.get_mut(key)?;
        while let Some(entry) = entries.pop() {
            state.idle_held -= 1;
            if now.duration_since(entry.since) < idle_timeout && entry.connection.is_usable() {
                return Some(entry.connection);
            }
        }
        state.idle.remove(key);
        None
    }

    /// Puts a connection into the pool.
    ///
    /// HTTP/2 connections are stored once and shared; a second one for the same
    /// key replaces a dead entry and is otherwise dropped, since duplicating a
    /// multiplexed connection wastes a handshake and doubles the SETTINGS
    /// preface a server sees from one client. They are capped separately from
    /// idle HTTP/1.1 sockets and by a different rule — see
    /// [`Pool::release_multiplexed`] and [`PoolConfig::max_total`].
    pub(crate) fn release(&self, key: &PoolKey, connection: Connection) {
        if !connection.is_usable() {
            return;
        }
        let mut guard = self.lock();
        let state = &mut *guard;

        // Runs on both paths. It used to run only here, below the HTTP/2
        // branch's early return, which left nothing in the pool ever walking
        // the multiplexed map: a closed multiplexed connection was reclaimed
        // only if someone checked its own key out again.
        self.sweep_if_due(state);

        if matches!(connection, Connection::Http2(_)) {
            self.release_multiplexed(state, key, connection);
            return;
        }

        // Against `idle_held`, not the total. An HTTP/2 entry cannot be freed
        // by `evict_oldest`, so counting one here would spend an HTTP/1.1
        // connection on a slot that was never going to come back.
        if state.idle_held >= self.config.max_total {
            // The oldest idle entry is also the first to expire, so the at-cap
            // path does not need a separate expiry sweep.
            Self::evict_oldest(state);
        }

        let entries = state.idle.entry(key.clone()).or_default();
        if entries.len() >= self.config.max_per_host {
            // Bounded by `max_per_host`, so this stays O(one bucket) rather
            // than O(pool).
            entries.remove(0);
            state.idle_held -= 1;
        }
        entries.push(Idle {
            connection,
            since: Instant::now(),
        });
        state.idle_held += 1;
    }

    /// Registers a multiplexed connection, unless the pool already holds
    /// `max_total` of them.
    ///
    /// **At the cap this declines to pool; it never evicts.** That is a
    /// deliberate answer to a question several answers would fit, so here is
    /// the reasoning.
    ///
    /// Dropping the pool's handle would not close the connection. An in-flight
    /// request holds its own clone of the `SendRequest` and hyper's driver runs
    /// until the last clone is gone, so eviction is not the socket-freeing act
    /// it is for an idle HTTP/1.1 entry. What it *would* do is deregister a
    /// live connection, so the next request to that origin opens a second one
    /// alongside it: two concurrent HTTP/2 connections from one client to one
    /// origin, and a second SETTINGS preface for the server to read. A browser
    /// coalesces to one connection per origin and never produces that shape,
    /// which makes eviction a fingerprint regression rather than a capacity
    /// trade. Declining costs a crawler a handshake per request to origins it
    /// could not fit, and costs nothing a server can see.
    ///
    /// "Evict the multiplexed connection with no active streams" would be the
    /// better rule if it could be written. It cannot: hyper 1.11's
    /// `http2::SendRequest` exposes `is_ready` and `is_closed` and no stream
    /// count, so this pool cannot tell a connection carrying forty streams
    /// from one carrying none.
    ///
    /// The split also matches where a browser draws the line. Chrome's global
    /// socket ceiling governs its socket pools; HTTP/2 sessions live in a
    /// separate per-key session pool that socket pressure does not evict.
    ///
    /// Two consequences worth stating plainly. A dead entry is replaced even at
    /// the cap, because replacing does not grow the population — otherwise a
    /// full map of corpses would refuse the origins that own them. And age
    /// never expires a multiplexed entry: `idle_timeout` measures a socket with
    /// nothing on it, which a multiplexed connection is not, so a slot frees
    /// when the server closes the connection and the sweep notices, not on a
    /// clock of ours.
    fn release_multiplexed(&self, state: &mut PoolState, key: &PoolKey, connection: Connection) {
        match state.multiplexed.get(key) {
            // This origin already has its one connection and it is alive.
            Some(existing) if existing.is_usable() => return,
            // Replacing a dead entry leaves the population the same size, so
            // the cap has no opinion about it.
            Some(_) => {}
            None => {
                if state.multiplexed.len() >= self.config.max_total {
                    tracing::debug!(
                        key = %key,
                        max_total = self.config.max_total,
                        "the multiplexed pool is full; this origin will not be pooled"
                    );
                    return;
                }
            }
        }
        state.multiplexed.insert(key.clone(), connection);
    }

    /// The number of connections currently held.
    ///
    /// Counts what the maps hold, which between sweeps can include entries
    /// that have already outlived the idle timeout; they are discarded the
    /// next time their key is checked out or a sweep runs.
    ///
    /// Both populations together, so this can reach `2 * max_total`; see
    /// [`PoolConfig::max_total`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().held()
    }

    /// Whether the pool holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every pooled connection.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.idle.clear();
        state.multiplexed.clear();
        state.idle_held = 0;
    }

    /// Runs a full expiry sweep at most once per quarter of the idle timeout.
    ///
    /// The sweep walks every entry in the pool, and doing that on every
    /// release put the whole pool behind one O(pool) scan per request. Expiry
    /// does not need that freshness: an expired entry is already rejected at
    /// checkout, and the at-cap path evicts oldest-first, so the sweep's only
    /// job is to stop long-idle keys nobody checks out from holding sockets —
    /// a quarter of the timeout bounds that overstay.
    fn sweep_if_due(&self, state: &mut PoolState) {
        let now = Instant::now();
        if now.duration_since(state.last_sweep) < self.config.idle_timeout / 4 {
            return;
        }
        state.last_sweep = now;
        Self::evict_expired(state, self.config.idle_timeout);
    }

    fn evict_expired(state: &mut PoolState, idle_timeout: Duration) {
        let now = Instant::now();
        let mut kept = 0;
        state.idle.retain(|_, entries| {
            entries.retain(|entry| {
                now.duration_since(entry.since) < idle_timeout && entry.connection.is_usable()
            });
            kept += entries.len();
            !entries.is_empty()
        });
        state
            .multiplexed
            .retain(|_, connection| connection.is_usable());
        state.idle_held = kept;
    }

    /// Drops the HTTP/1.1 connection that has been idle longest, so that
    /// reaching the cap costs the least useful entry rather than refusing to
    /// pool.
    ///
    /// It walks `idle` and only `idle`, which is the whole reason the cap it
    /// serves counts `idle` and only `idle`.
    fn evict_oldest(state: &mut PoolState) {
        let oldest = state
            .idle
            .iter()
            .filter_map(|(key, entries)| {
                entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.since)
                    .map(|(index, entry)| (key.clone(), index, entry.since))
            })
            .min_by_key(|(_, _, since)| *since);

        if let Some((key, index, _)) = oldest
            && let Some(entries) = state.idle.get_mut(&key)
        {
            entries.remove(index);
            state.idle_held -= 1;
            if entries.is_empty() {
                state.idle.remove(&key);
            }
        }
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("Pool")
            .field("config", &self.config)
            .field("idle_keys", &state.idle.len())
            .field("multiplexed_keys", &state.multiplexed.len())
            .field("connections", &state.held())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use chromulate_fingerprint::{Setting, SettingId};

    use super::*;

    fn key_for(profile: &Profile, host: &str, protocol: Protocol) -> PoolKey {
        PoolKey {
            scheme: "https".into(),
            host: host.into(),
            port: 443,
            proxy: None,
            identity: ConnectionIdentity::of(profile),
            protocol,
        }
    }

    /// A second profile that differs from Chrome only in its HTTP/2 SETTINGS,
    /// which is enough to make it a different client to a server.
    fn altered_profile() -> Profile {
        let mut profile = Profile::chrome_stable();
        profile.name = "altered".to_owned();
        profile.http2.settings = vec![Setting::new(SettingId::INITIAL_WINDOW_SIZE, 65_535)];
        profile
    }

    #[test]
    fn two_profiles_that_look_different_on_the_wire_get_different_identities() {
        let chrome = ConnectionIdentity::of(&Profile::chrome_stable());
        let altered = ConnectionIdentity::of(&altered_profile());
        assert_ne!(chrome, altered);
    }

    #[test]
    fn an_identity_is_derived_from_content_not_from_the_profile_value() {
        assert_eq!(
            ConnectionIdentity::of(&Profile::chrome_stable()),
            ConnectionIdentity::of(&Profile::chrome_stable()),
            "two separately built copies of one profile must pool together"
        );
    }

    #[test]
    fn keys_differ_when_only_the_profile_differs() {
        let chrome = key_for(&Profile::chrome_stable(), "example.com", Protocol::Http2);
        let altered = key_for(&altered_profile(), "example.com", Protocol::Http2);
        assert_ne!(
            chrome, altered,
            "the same origin under two identities is two pool entries"
        );
    }

    #[test]
    fn keys_differ_when_only_the_protocol_differs() {
        let profile = Profile::chrome_stable();
        assert_ne!(
            key_for(&profile, "example.com", Protocol::Http11),
            key_for(&profile, "example.com", Protocol::Http2)
        );
    }

    #[test]
    fn keys_differ_when_only_the_proxy_differs() {
        let profile = Profile::chrome_stable();
        let direct = key_for(&profile, "example.com", Protocol::Http2);
        let proxied = PoolKey {
            proxy: Some("socks5h://proxy.test:1080".into()),
            ..direct.clone()
        };
        assert_ne!(direct, proxied);
    }

    #[test]
    fn an_empty_pool_hands_back_nothing() {
        let pool = Pool::new(PoolConfig::default());
        let key = key_for(&Profile::chrome_stable(), "example.com", Protocol::Http11);
        assert!(pool.checkout(&key).is_none());
        assert!(pool.is_empty());
    }

    /// A live HTTP/1.1 connection over an in-memory duplex pipe. The server
    /// half is returned so the test controls when the connection dies: hyper
    /// reports a sender closed once its peer is gone.
    async fn h1_connection() -> (Connection, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(1024);
        let (sender, driver) = http1::Builder::new()
            .handshake::<_, Body>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("an in-memory handshake succeeds");
        tokio::spawn(driver);
        (Connection::Http1(sender), server)
    }

    /// A live HTTP/2 connection over an in-memory duplex pipe. As with
    /// [`h1_connection`] the server half is returned so the test controls when
    /// the connection dies. The client half of an HTTP/2 handshake completes
    /// once its preface is written, so nothing has to answer on the other end.
    async fn h2_connection() -> (Connection, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(4096);
        let (sender, driver) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake::<_, Body>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("an in-memory handshake succeeds");
        tokio::spawn(driver);
        (Connection::Http2(sender), server)
    }

    fn small_pool(max_per_host: usize, max_total: usize, idle_timeout: Duration) -> Pool {
        Pool::new(PoolConfig {
            idle_timeout,
            max_per_host,
            max_total,
            ..PoolConfig::default()
        })
    }

    #[tokio::test]
    async fn len_tracks_releases_and_checkouts() {
        let pool = small_pool(6, 100, Duration::from_secs(90));
        let profile = Profile::chrome_stable();
        let key_a = key_for(&profile, "a.example", Protocol::Http11);
        let key_b = key_for(&profile, "b.example", Protocol::Http11);

        let (first, _first_io) = h1_connection().await;
        let (second, _second_io) = h1_connection().await;
        let (third, _third_io) = h1_connection().await;
        pool.release(&key_a, first);
        pool.release(&key_a, second);
        pool.release(&key_b, third);
        assert_eq!(pool.len(), 3);

        let taken = pool
            .checkout(&key_a)
            .expect("a pooled connection comes back");
        assert_eq!(pool.len(), 2);

        pool.release(&key_a, taken);
        assert_eq!(pool.len(), 3);

        pool.clear();
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn the_total_cap_is_enforced_on_every_release() {
        let pool = small_pool(10, 2, Duration::from_secs(90));
        let profile = Profile::chrome_stable();

        let mut io_keepalive = Vec::new();
        for host in ["a.example", "b.example", "c.example", "d.example"] {
            let (connection, io) = h1_connection().await;
            io_keepalive.push(io);
            pool.release(&key_for(&profile, host, Protocol::Http11), connection);
            assert!(
                pool.len() <= 2,
                "after releasing for {host} the pool holds {}",
                pool.len()
            );
        }
    }

    /// The first of the two probes from the 2026-08-04 review: the total cap
    /// has to mean something for multiplexed connections too. Before the fix
    /// the HTTP/2 arm of `release` returned above the cap check, so fifty
    /// origins produced fifty entries in a pool told to hold ten.
    #[tokio::test]
    async fn multiplexed_connections_are_bounded_by_the_total_cap() {
        let pool = small_pool(6, 10, Duration::from_secs(90));
        let profile = Profile::chrome_stable();

        let mut io_keepalive = Vec::new();
        for index in 0..50 {
            let (connection, io) = h2_connection().await;
            io_keepalive.push(io);
            let host = format!("h{index}.example");
            pool.release(&key_for(&profile, &host, Protocol::Http2), connection);
        }

        assert!(
            pool.len() <= 10,
            "fifty HTTP/2 origins against max_total = 10 left {} pooled",
            pool.len()
        );
    }

    /// The second probe, and the one that says why the counters have to be
    /// separate. HTTP/2 entries used to inflate the count that HTTP/1.1
    /// eviction reacts to, while `evict_oldest` can only ever free an HTTP/1.1
    /// entry — so every HTTP/1.1 release past the cap threw away the previous
    /// HTTP/1.1 release and one survivor was left out of five.
    #[tokio::test]
    async fn http2_pressure_does_not_destroy_http1_pooling() {
        let pool = small_pool(6, 10, Duration::from_secs(90));
        let profile = Profile::chrome_stable();

        let mut io_keepalive = Vec::new();
        for index in 0..20 {
            let (connection, io) = h2_connection().await;
            io_keepalive.push(io);
            let host = format!("h2-{index}.example");
            pool.release(&key_for(&profile, &host, Protocol::Http2), connection);
        }

        let mut h1_keys = Vec::new();
        for index in 0..5 {
            let (connection, io) = h1_connection().await;
            io_keepalive.push(io);
            let key = key_for(&profile, &format!("h1-{index}.example"), Protocol::Http11);
            pool.release(&key, connection);
            h1_keys.push(key);
        }

        let recovered = h1_keys
            .iter()
            .filter(|key| pool.checkout(key).is_some())
            .count();
        assert_eq!(
            recovered, 5,
            "HTTP/2 traffic must not evict HTTP/1.1 connections: {recovered} of 5 came back"
        );
    }

    /// The path every ordinary HTTP/2 request takes, which none of the cap
    /// tests above can reach: they all fill a deliberately tiny pool, so the
    /// below-cap behaviour is untested by construction in each of them.
    #[tokio::test]
    async fn a_multiplexed_connection_is_pooled_and_reused_below_the_cap() {
        let pool = Pool::new(PoolConfig::default());
        let profile = Profile::chrome_stable();
        let key = key_for(&profile, "a.example", Protocol::Http2);

        let (connection, _io) = h2_connection().await;
        pool.release(&key, connection);
        assert_eq!(pool.len(), 1, "an HTTP/2 connection must be pooled");

        // Checking one out clones it and leaves it pooled, because it
        // multiplexes.
        assert!(pool.checkout(&key).is_some(), "it must be reusable");
        assert_eq!(pool.len(), 1, "and checking it out must not remove it");

        // A second connection for a key that already has a live one is
        // dropped: one connection per origin is what a browser shows a server.
        let (second, _second_io) = h2_connection().await;
        pool.release(&key, second);
        assert_eq!(pool.len(), 1, "an origin keeps one multiplexed connection");
    }

    /// A closed multiplexed entry is replaced by a live one for the same key
    /// even when the pool is at its cap, because replacing does not grow the
    /// population. Without that, an origin whose connection died would be
    /// locked out of the pool by its own corpse.
    ///
    /// The idle timeout is the default ninety seconds so the expiry sweep —
    /// which runs at most once per quarter of it — cannot fire during the
    /// test and clear the entry instead. Only the replacement makes this pass.
    #[tokio::test]
    async fn a_dead_multiplexed_entry_is_replaced_at_the_cap() {
        let pool = small_pool(6, 1, Duration::from_secs(90));
        let profile = Profile::chrome_stable();
        let key = key_for(&profile, "a.example", Protocol::Http2);

        let (first, first_io) = h2_connection().await;
        pool.release(&key, first);
        assert_eq!(pool.len(), 1);

        drop(first_io);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (second, _second_io) = h2_connection().await;
        pool.release(&key, second);
        assert_eq!(pool.len(), 1, "the pool must not grow past its cap");
        assert!(
            pool.checkout(&key).is_some(),
            "the live connection must have replaced the dead one"
        );
    }

    /// The expiry sweep has to run on the HTTP/2 release path too. It used to
    /// sit below that path's early return, so nothing in the pool ever walked
    /// the multiplexed map: a pool whose multiplexed entries had all closed
    /// stayed full of them and refused every new origin.
    ///
    /// The idle timeout is short so the sweep's once-per-quarter-timeout gate
    /// opens during the test. Without the sweep the third release finds two
    /// corpses filling a cap of two and is declined.
    #[tokio::test]
    async fn the_sweep_reclaims_closed_multiplexed_entries() {
        let pool = small_pool(6, 2, Duration::from_millis(200));
        let profile = Profile::chrome_stable();

        let mut dead_io = Vec::new();
        for host in ["a.example", "b.example"] {
            let (connection, io) = h2_connection().await;
            dead_io.push(io);
            pool.release(&key_for(&profile, host, Protocol::Http2), connection);
        }
        assert_eq!(pool.len(), 2, "the multiplexed pool starts full");

        drop(dead_io);
        tokio::task::yield_now().await;
        // Past a quarter of the idle timeout, so the next release sweeps.
        tokio::time::sleep(Duration::from_millis(120)).await;

        let fresh = key_for(&profile, "c.example", Protocol::Http2);
        let (connection, _io) = h2_connection().await;
        pool.release(&fresh, connection);

        assert_eq!(
            pool.len(),
            1,
            "the two closed entries must be gone, leaving only the new one"
        );
        assert!(
            pool.checkout(&fresh).is_some(),
            "a new origin must be poolable once dead entries are reclaimed"
        );
    }

    #[tokio::test]
    async fn the_per_host_cap_keeps_the_newest_connection() {
        let pool = small_pool(1, 100, Duration::from_secs(90));
        let profile = Profile::chrome_stable();
        let key = key_for(&profile, "a.example", Protocol::Http11);

        let (first, _first_io) = h1_connection().await;
        let (second, _second_io) = h1_connection().await;
        pool.release(&key, first);
        pool.release(&key, second);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn a_dead_connection_is_not_pooled() {
        let pool = small_pool(6, 100, Duration::from_secs(90));
        let profile = Profile::chrome_stable();
        let key = key_for(&profile, "a.example", Protocol::Http11);

        let (connection, server_io) = h1_connection().await;
        drop(server_io);
        // The driver needs a poll to observe the closed pipe.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        pool.release(&key, connection);
        assert!(pool.is_empty(), "a closed connection must not be pooled");
    }

    #[tokio::test]
    async fn an_expired_entry_is_not_handed_back() {
        let pool = small_pool(6, 100, Duration::from_millis(10));
        let profile = Profile::chrome_stable();
        let key = key_for(&profile, "a.example", Protocol::Http11);

        let (connection, _io) = h1_connection().await;
        pool.release(&key, connection);
        tokio::time::sleep(Duration::from_millis(25)).await;

        assert!(
            pool.checkout(&key).is_none(),
            "an entry older than the idle timeout must not be reused"
        );
    }

    #[test]
    fn the_key_renders_the_origin_the_protocol_and_the_identity() {
        let rendered =
            key_for(&Profile::chrome_stable(), "example.com", Protocol::Http2).to_string();
        assert!(
            rendered.starts_with("https://example.com:443 ["),
            "{rendered}"
        );
        assert!(rendered.contains("h2"), "{rendered}");
        assert!(
            rendered.contains(&Profile::chrome_stable().ja4()),
            "the identity must be visible in a log line: {rendered}"
        );
    }
}
