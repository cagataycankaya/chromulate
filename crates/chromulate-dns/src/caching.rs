//! A TTL cache with single-flight lookup collapsing, wrapping any [`Resolve`].

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chromulate_core::{BoxFuture, Error, HostPort, Resolve, Result};
use futures_util::FutureExt as _;
use futures_util::future::{Shared, WeakShared};

/// A source of the current instant.
///
/// [`CachingResolver`] takes its notion of "now" through this trait instead of
/// calling [`Instant::now`] directly, so cache expiry can be tested deterministically
/// with a fake clock that is advanced explicitly, rather than by sleeping in tests and
/// hoping the scheduler cooperates.
pub trait Clock: Send + Sync + 'static {
    /// The current instant, as this clock sees it.
    fn now(&self) -> Instant;
}

#[derive(Debug, Default)]
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The positive TTL [`CachingResolver::with_default_ttls`] uses.
///
/// `lookup_host` does not expose the TTL a DNS server actually returned, so this
/// crate cannot honor it and instead applies a fixed duration. 60 seconds keeps a
/// long-running crawler from re-resolving a host on every request while still
/// noticing a change in well under the multi-minute TTLs long-lived records
/// typically carry.
pub const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(60);

/// The negative TTL [`CachingResolver::with_default_ttls`] uses.
///
/// Short on purpose: a failed lookup is cached just long enough to collapse a burst
/// of concurrent callers into one failure, without letting a transient resolver
/// hiccup make a host look down for as long as a successful lookup would be cached.
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// The result of a completed resolution, cheap to share across every caller that was
/// waiting on it.
///
/// The failure case stores a message rather than the original [`Error`], because
/// [`Error`] is not [`Clone`] and a single resolution's outcome may need to be handed
/// out to hundreds of callers that collapsed into it. Each caller reconstructs a
/// fresh [`Error::Resolve`] from the message, so the error class is preserved even
/// though the exact source error's type is not.
#[derive(Clone)]
enum CacheOutcome {
    Ok(Vec<SocketAddr>),
    Err(String),
}

/// The source attached to an [`Error::Resolve`] rebuilt from a cached failure.
#[derive(Debug)]
struct CachedResolveFailure(String);

impl fmt::Display for CachedResolveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CachedResolveFailure {}

type SharedOutcome = Shared<BoxFuture<'static, Arc<CacheOutcome>>>;
type WeakOutcome = WeakShared<BoxFuture<'static, Arc<CacheOutcome>>>;

enum Slot {
    /// A resolution is in progress; join it instead of starting another.
    ///
    /// The handle is deliberately weak. If the map held a strong one, it would
    /// be the map keeping an abandoned resolution alive: every caller waiting
    /// on the lookup could go away and the entry would still hand that
    /// half-finished lookup's outcome to everyone who came later. Weak means a
    /// lookup nobody is waiting for is simply gone, and the next caller starts
    /// a fresh one.
    InFlight(WeakOutcome),
    /// A completed resolution, valid until `expires_at`.
    Cached {
        outcome: Arc<CacheOutcome>,
        expires_at: Instant,
    },
}

/// The smallest map size an opportunistic sweep runs at.
const MIN_SWEEP_SIZE: usize = 64;

/// The cache a resolver shares with the lookups it has started.
///
/// A lookup owns a handle to this, so it settles its own slot when it finishes
/// no matter which caller ends up driving it to completion. Nothing here
/// depends on the caller that happened to start a lookup still being around.
struct Cache {
    slots: Mutex<Slots>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    clock: Arc<dyn Clock>,
}

struct Slots {
    entries: HashMap<HostPort, Slot>,
    /// The size at which the next opportunistic sweep runs. Doubling it after
    /// each sweep keeps the sweep cost amortised constant per lookup, rather
    /// than paying an O(n) walk on every one.
    sweep_at: usize,
}

impl Cache {
    /// Locks the cache map, recovering the data even if a prior panic poisoned
    /// the lock.
    ///
    /// A cache is not worth losing over an unrelated panic elsewhere while the
    /// lock happened to be held: the map itself is never left in a logically
    /// inconsistent state mid-mutation (every block that mutates it does so
    /// without any `.await` in between), so recovering the poisoned guard is
    /// safe.
    fn lock(&self) -> MutexGuard<'_, Slots> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records a finished resolution, replacing its in-flight marker.
    ///
    /// This runs inside the lookup future itself, so the entry is settled by
    /// whoever finishes the lookup rather than by whoever started it.
    fn settle(&self, target: HostPort, outcome: &Arc<CacheOutcome>) {
        let ttl = match &**outcome {
            CacheOutcome::Ok(_) => self.positive_ttl,
            CacheOutcome::Err(_) => self.negative_ttl,
        };
        let now = self.clock.now();
        let mut slots = self.lock();
        slots.entries.insert(
            target,
            Slot::Cached {
                outcome: Arc::clone(outcome),
                expires_at: now + ttl,
            },
        );
        sweep(&mut slots, now);
    }
}

/// Drops expired entries, and in-flight markers whose lookup has gone away.
fn sweep(slots: &mut Slots, now: Instant) {
    slots.entries.retain(|_, slot| match slot {
        Slot::Cached { expires_at, .. } => *expires_at > now,
        Slot::InFlight(weak) => weak.upgrade().is_some(),
    });
    slots.sweep_at = slots.entries.len().saturating_mul(2).max(MIN_SWEEP_SIZE);
}

/// Wraps a [`Resolve`] with a TTL cache and single-flight lookup collapsing.
///
/// Concurrent lookups for the same host share one in-flight resolution: a crawler
/// starting many tasks against a single host issues exactly one DNS query, not one
/// per task. Successful and failed lookups are cached separately, since a failure
/// should not be trusted for nearly as long as a success (see
/// [`DEFAULT_NEGATIVE_TTL`]). Expired entries are swept opportunistically whenever a
/// resolution completes and whenever the map grows past its last swept size, so the
/// cache does not grow without bound over a long-running process.
///
/// A caller that gives up on a lookup — a connect timeout, an aborted task, a client
/// shutdown — never leaves the cache holding that lookup's outcome. Either another
/// caller was waiting on it, in which case it completes and is cached with the normal
/// TTL, or nobody was, in which case it is dropped and the next caller starts again.
pub struct CachingResolver<R> {
    inner: Arc<R>,
    cache: Arc<Cache>,
}

impl<R> fmt::Debug for CachingResolver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachingResolver")
            .field("positive_ttl", &self.cache.positive_ttl)
            .field("negative_ttl", &self.cache.negative_ttl)
            .finish_non_exhaustive()
    }
}

impl<R: Resolve> CachingResolver<R> {
    /// Wraps `inner` with [`DEFAULT_POSITIVE_TTL`] and [`DEFAULT_NEGATIVE_TTL`].
    pub fn with_default_ttls(inner: R) -> Self {
        Self::new(inner, DEFAULT_POSITIVE_TTL, DEFAULT_NEGATIVE_TTL)
    }

    /// Wraps `inner` with the given positive and negative TTLs.
    pub fn new(inner: R, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self::with_clock(inner, positive_ttl, negative_ttl, Arc::new(SystemClock))
    }

    /// Same as [`Self::new`], but with an injected [`Clock`] for deterministic tests.
    pub fn with_clock(
        inner: R,
        positive_ttl: Duration,
        negative_ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            cache: Arc::new(Cache {
                slots: Mutex::new(Slots {
                    entries: HashMap::new(),
                    sweep_at: MIN_SWEEP_SIZE,
                }),
                positive_ttl,
                negative_ttl,
                clock,
            }),
        }
    }

    /// Finds or starts the shared resolution for `target`, joining an in-flight
    /// lookup or a fresh cache entry when one already covers it.
    ///
    /// The entire "check cache, check in-flight, or register a new in-flight slot"
    /// decision happens while holding the lock, so two concurrent callers for the
    /// same host can never both decide to start a fresh resolution: whichever
    /// acquires the lock second always observes the first one's freshly inserted
    /// [`Slot::InFlight`].
    ///
    /// Settling the finished slot is the lookup's own job rather than the starting
    /// caller's, so a caller that walks away mid-resolution changes nothing about
    /// what the cache ends up holding.
    async fn shared_outcome(&self, target: HostPort) -> Arc<CacheOutcome> {
        enum Action {
            UseCached(Arc<CacheOutcome>),
            Await(SharedOutcome),
        }

        let now = self.cache.clock.now();
        let action = {
            let mut slots = self.cache.lock();
            let existing = match slots.entries.get(&target) {
                Some(Slot::Cached {
                    outcome,
                    expires_at,
                }) if *expires_at > now => Some(Action::UseCached(Arc::clone(outcome))),
                // An in-flight marker that no longer upgrades belonged to a
                // lookup every caller abandoned, so it decides nothing here.
                Some(Slot::InFlight(weak)) => weak.upgrade().map(Action::Await),
                _ => None,
            };

            match existing {
                Some(action) => action,
                None => {
                    if slots.entries.len() >= slots.sweep_at {
                        sweep(&mut slots, now);
                    }

                    let cache = Arc::clone(&self.cache);
                    let inner = Arc::clone(&self.inner);
                    let lookup_target = target.clone();
                    let fut: BoxFuture<'static, Arc<CacheOutcome>> = Box::pin(async move {
                        let outcome = match inner.resolve(lookup_target.clone()).await {
                            Ok(addrs) => Arc::new(CacheOutcome::Ok(addrs)),
                            Err(err) => Arc::new(CacheOutcome::Err(err.to_string())),
                        };
                        cache.settle(lookup_target, &outcome);
                        outcome
                    });
                    let shared = fut.shared();
                    match shared.downgrade() {
                        Some(weak) => {
                            slots.entries.insert(target, Slot::InFlight(weak));
                        }
                        // `downgrade` only refuses for a `Shared` already polled
                        // to completion, which one built here cannot have been.
                        // Leave no marker rather than one nobody could join.
                        None => {
                            slots.entries.remove(&target);
                        }
                    }
                    Action::Await(shared)
                }
            }
        };

        match action {
            Action::UseCached(outcome) => outcome,
            Action::Await(shared) => shared.await,
        }
    }
}

impl<R: Resolve> Resolve for CachingResolver<R> {
    fn resolve(&self, target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            let host = target.host().to_string();
            let outcome = self.shared_outcome(target).await;
            match &*outcome {
                CacheOutcome::Ok(addrs) => Ok(addrs.clone()),
                CacheOutcome::Err(message) => Err(Error::Resolve {
                    host,
                    source: Some(Box::new(CachedResolveFailure(message.clone()))),
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use tokio::sync::Semaphore;

    use super::*;

    struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            let mut instant = self.0.lock().expect("fake clock mutex was poisoned");
            *instant += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("fake clock mutex was poisoned")
        }
    }

    /// A resolver that counts calls and blocks on a semaphore before returning, so
    /// tests can control exactly when a resolution is allowed to complete.
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        result: std::result::Result<Vec<SocketAddr>, String>,
    }

    impl Resolve for CountingResolver {
        fn resolve(&self, _target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = Arc::clone(&self.gate);
            let result = self.result.clone();
            Box::pin(async move {
                let _permit = gate
                    .acquire()
                    .await
                    .expect("semaphore should not be closed");
                result.map_err(|message| Error::Resolve {
                    host: "counted".to_string(),
                    source: Some(message.into()),
                })
            })
        }
    }

    /// A resolver that hands out a scripted result per call, blocking on a gate
    /// first so a test controls exactly when each resolution completes.
    struct ScriptedResolver {
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        results: Vec<std::result::Result<Vec<SocketAddr>, String>>,
    }

    impl Resolve for ScriptedResolver {
        fn resolve(&self, _target: HostPort) -> BoxFuture<'_, Result<Vec<SocketAddr>>> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = Arc::clone(&self.gate);
            let result = self
                .results
                .get(index)
                .cloned()
                .unwrap_or_else(|| Err(format!("the script has no result for call {index}")));
            Box::pin(async move {
                let _permit = gate
                    .acquire()
                    .await
                    .expect("semaphore should not be closed");
                result.map_err(|message| Error::Resolve {
                    host: "scripted".to_string(),
                    source: Some(message.into()),
                })
            })
        }
    }

    fn addr() -> SocketAddr {
        SocketAddr::from(([93, 184, 216, 34], 443))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn many_concurrent_lookups_for_one_host_issue_a_single_resolution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let inner = CountingResolver {
            calls: Arc::clone(&calls),
            gate: Arc::clone(&gate),
            result: Ok(vec![addr()]),
        };
        let resolver = Arc::new(CachingResolver::with_default_ttls(inner));
        let target = HostPort::new("example.com", 443);

        let handles: Vec<_> = (0..500)
            .map(|_| {
                let resolver = Arc::clone(&resolver);
                let target = target.clone();
                tokio::spawn(async move { resolver.resolve(target).await })
            })
            .collect();

        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        for _ in 0..1000 {
            tokio::task::yield_now().await;
        }
        gate.add_permits(1);

        for handle in handles {
            let addrs = handle
                .await
                .expect("resolver task should not panic")
                .expect("resolution should succeed");
            assert_eq!(addrs, vec![addr()]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_cached_entry_is_reused_until_its_ttl_expires() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(1_000));
        let inner = CountingResolver {
            calls: Arc::clone(&calls),
            gate,
            result: Ok(vec![addr()]),
        };
        let clock = FakeClock::new();
        let resolver = CachingResolver::with_clock(
            inner,
            Duration::from_secs(10),
            Duration::from_secs(2),
            clock.clone(),
        );
        let target = HostPort::new("example.com", 443);

        resolver
            .resolve(target.clone())
            .await
            .expect("first lookup should succeed");
        resolver
            .resolve(target.clone())
            .await
            .expect("second lookup should hit the cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(11));
        resolver
            .resolve(target.clone())
            .await
            .expect("lookup after expiry should succeed");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_negative_cache_entry_expires_sooner_than_a_positive_one() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(1_000));
        let inner = CountingResolver {
            calls: Arc::clone(&calls),
            gate,
            result: Err("no such host".to_string()),
        };
        let clock = FakeClock::new();
        let resolver = CachingResolver::with_clock(
            inner,
            Duration::from_secs(60),
            Duration::from_secs(2),
            clock.clone(),
        );
        let target = HostPort::new("missing.example", 443);

        resolver
            .resolve(target.clone())
            .await
            .expect_err("lookup should fail");
        resolver
            .resolve(target.clone())
            .await
            .expect_err("second lookup should hit the negative cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(3));
        resolver
            .resolve(target.clone())
            .await
            .expect_err("lookup after the negative TTL should try again");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_cached_failure_is_reported_as_a_resolve_error_for_the_original_host() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(1_000));
        let inner = CountingResolver {
            calls,
            gate,
            result: Err("no such host".to_string()),
        };
        let resolver = CachingResolver::with_default_ttls(inner);

        let err = resolver
            .resolve(HostPort::new("missing.example", 443))
            .await
            .expect_err("lookup should fail");
        assert!(matches!(err, Error::Resolve { host, .. } if host == "missing.example"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancelled_starter_does_not_pin_its_outcome_on_later_callers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let inner = ScriptedResolver {
            calls: Arc::clone(&calls),
            gate: Arc::clone(&gate),
            results: vec![Err("SERVFAIL".to_string()), Ok(vec![addr()])],
        };
        let clock = FakeClock::new();
        let resolver = Arc::new(CachingResolver::with_clock(
            inner,
            Duration::from_secs(60),
            Duration::from_secs(5),
            clock.clone(),
        ));
        let target = HostPort::new("example.com", 443);

        // The task spawned first is provably the starter: nothing else is
        // asking for this host until the inner resolver reports being entered.
        let starter = tokio::spawn({
            let resolver = Arc::clone(&resolver);
            let target = target.clone();
            async move { resolver.resolve(target).await }
        });
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        // Eight more callers collapse into that one resolution. Each reports
        // itself joined only after its first poll, which is where the join
        // happens, so the cancellation below cannot race ahead of them.
        let joined = Arc::new(AtomicUsize::new(0));
        let joiners: Vec<_> = (0..8)
            .map(|_| {
                let resolver = Arc::clone(&resolver);
                let target = target.clone();
                let joined = Arc::clone(&joined);
                tokio::spawn(async move {
                    let mut lookup = resolver.resolve(target);
                    let first =
                        std::future::poll_fn(|cx| Poll::Ready(lookup.as_mut().poll(cx))).await;
                    joined.fetch_add(1, Ordering::SeqCst);
                    match first {
                        Poll::Ready(outcome) => outcome,
                        Poll::Pending => lookup.await,
                    }
                })
            })
            .collect();
        while joined.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }

        starter.abort();
        assert!(
            starter
                .await
                .expect_err("the starter was aborted")
                .is_cancelled()
        );

        gate.add_permits(64);
        for joiner in joiners {
            joiner
                .await
                .expect("a joining task must not panic")
                .expect_err("the scripted first lookup fails");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the joiners must share the starter's single lookup"
        );

        clock.advance(Duration::from_secs(6));
        let addrs = resolver.resolve(target).await.expect(
            "the negative entry must expire on its TTL rather than be pinned by the cancellation",
        );
        assert_eq!(addrs, vec![addr()]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_lookup_abandoned_before_anyone_joins_is_retried_by_the_next_caller() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let inner = ScriptedResolver {
            calls: Arc::clone(&calls),
            gate: Arc::clone(&gate),
            results: vec![Err("SERVFAIL".to_string()), Ok(vec![addr()])],
        };
        let resolver = CachingResolver::with_clock(
            inner,
            Duration::from_secs(60),
            Duration::from_secs(5),
            FakeClock::new(),
        );
        let target = HostPort::new("example.com", 443);

        // Poll once and drop, which is what a per-request connect timeout does.
        assert!(
            resolver.resolve(target.clone()).now_or_never().is_none(),
            "the gate holds the first resolution open"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        gate.add_permits(64);
        tokio::task::yield_now().await;

        let addrs = resolver
            .resolve(target)
            .await
            .expect("an abandoned lookup must not decide the next caller's answer");
        assert_eq!(addrs, vec![addr()]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn abandoned_lookups_do_not_accumulate_in_the_cache_map() {
        let gate = Arc::new(Semaphore::new(0));
        let inner = ScriptedResolver {
            calls: Arc::new(AtomicUsize::new(0)),
            gate,
            results: Vec::new(),
        };
        let resolver = CachingResolver::with_default_ttls(inner);

        for n in 0..10_000u32 {
            assert!(
                resolver
                    .resolve(HostPort::new(format!("h{n}.example"), 443))
                    .now_or_never()
                    .is_none(),
                "the gate holds every resolution open"
            );
        }

        let retained = resolver.cache.lock().entries.len();
        assert!(
            retained <= MIN_SWEEP_SIZE,
            "10000 abandoned lookups left {retained} entries behind"
        );
    }
}
