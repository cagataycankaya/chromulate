//! A fixed number of requests in flight per origin, and nothing else.

use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use chromulate_core::BoxFuture;
use chromulate_http::concurrency::{ConcurrencyController, Lease, Outcome, authority_of};
use chromulate_http::time::TimeSource;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::Ceiling;

/// How many origins a [`FixedConcurrency`] remembers before evicting.
///
/// The key is an authority chosen by the servers a crawl visits rather than by
/// the caller, so this pairs a capacity with an eviction policy exactly as the
/// other per-origin stores in this workspace do. Twice
/// [`crate::adaptive::DEFAULT_ORIGIN_CAPACITY`], because an entry here is one
/// semaphore and one counter while an adaptive origin also carries its latency
/// state.
pub const DEFAULT_FIXED_CAPACITY: usize = 8_192;

/// A fixed number of requests in flight per origin, and nothing else.
///
/// No latency baseline, no probes, no ratchet, no cooldown: a `429` and a `200`
/// are the same event to this controller, which returns the slot and moves on.
/// [`crate::adaptive::AdaptiveConcurrency`] configured with `min == max`
/// produces the same in-flight bound, but reaching it means configuring a
/// learning controller into submission and carrying its per-origin latency state
/// for a number that will never move.
///
/// It exists as much to keep the seam honest as to be used: a trait with one
/// implementation is a trait shaped like that implementation, and this one
/// ignores [`Outcome`] entirely.
///
/// # Example
///
/// ```
/// use chromulate_concurrency::{Ceiling, FixedConcurrency};
/// use url::Url;
///
/// # async fn run() {
/// let controller = FixedConcurrency::new(4, Ceiling::Unlimited);
/// let url = Url::parse("https://example.com/a").unwrap();
///
/// let lease = controller.acquire(&url).await;
/// assert_eq!(controller.in_flight("example.com"), Some(1));
/// drop(lease);
/// assert_eq!(controller.in_flight("example.com"), Some(0));
/// # }
/// ```
pub struct FixedConcurrency {
    limit: usize,
    capacity: usize,
    ceiling: Ceiling,
    time: TimeSource,
    store: RwLock<HashMap<Box<str>, Gate>>,
    seq: AtomicU64,
}

/// One origin's slots, and enough to rank it for eviction.
#[derive(Debug)]
struct Gate {
    slots: Arc<Semaphore>,
    /// Ticks on use, so eviction can rank by recency without a clock.
    ///
    /// A counter rather than an `Instant` for the reason the other stores in
    /// this workspace give: `Instant + Duration` panics on overflow and this
    /// module is keyed by server-controlled input, while `fetch_add` wraps.
    last_use_seq: AtomicU64,
}

impl fmt::Debug for FixedConcurrency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedConcurrency")
            .field("limit", &self.limit)
            .field("capacity", &self.capacity)
            .field("ceiling", &self.ceiling)
            .field("origins", &self.len())
            .finish_non_exhaustive()
    }
}

impl FixedConcurrency {
    /// At most `limit` requests in flight per origin, under `ceiling`.
    ///
    /// A limit of zero is raised to one, for the reason every capacity in this
    /// workspace is: a controller that can grant no permits at all is a hung
    /// client rather than a careful one. The upper clamp is tokio's own
    /// semaphore maximum, which no caller reaches by intent.
    #[must_use]
    pub fn new(limit: usize, ceiling: Ceiling) -> Self {
        Self {
            limit: limit.clamp(1, Semaphore::MAX_PERMITS),
            capacity: DEFAULT_FIXED_CAPACITY,
            ceiling,
            time: TimeSource::system(),
            store: RwLock::new(HashMap::new()),
            seq: AtomicU64::new(0),
        }
    }

    /// Remembers at most `capacity` origins, evicting the least recently used.
    ///
    /// Zero becomes one: a store that cannot hold the entry it was just handed
    /// is a disabled feature rather than a small one.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Replaces the clock and timer, so a test can drive the ceiling without
    /// waiting for it.
    #[must_use]
    pub fn with_time_source(mut self, time: TimeSource) -> Self {
        self.time = time;
        self
    }

    /// The number of requests this controller allows in flight per origin.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// How many origins are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether nothing is remembered yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slots taken and not yet returned for one authority.
    #[must_use]
    pub fn in_flight(&self, authority: &str) -> Option<usize> {
        let store = self.read();
        let gate = store.get(authority)?;
        Some(self.limit.saturating_sub(gate.slots.available_permits()))
    }

    /// Forgets an authority.
    ///
    /// Leases already outstanding keep working: a permit holds its own handle to
    /// the semaphore it came from, so returning it cannot be lost by a store
    /// that has moved on.
    pub fn forget(&self, authority: &str) -> bool {
        self.write().remove(authority).is_some()
    }

    /// Waits for permission to send one request to `url`.
    ///
    /// In order: the caller's [`Ceiling`], then a slot. The ceiling comes first
    /// on purpose — a permit that has not paid the caller's rate must not exist,
    /// and holding a slot while waiting to pay would block an origin on a wait
    /// that had nothing to do with it. The origin's entry is not even created
    /// until the token is spent, so a request queued behind a rate limit costs
    /// nothing in the store.
    pub async fn acquire(&self, url: &Url) -> FixedLease {
        self.acquire_authority(authority_of(url)).await
    }

    /// [`FixedConcurrency::acquire`], for a caller that already has the
    /// authority.
    pub async fn acquire_authority(&self, authority: &str) -> FixedLease {
        self.ceiling.pay(&self.time).await;
        let slots = self.gate_for(authority);
        // `ok()` rather than a panic or an error: `acquire_owned` fails only on
        // a closed semaphore, nothing in this type ever closes one, and there is
        // no constructor that hands one out. The arm is unreachable, no test
        // reaches it, and mutating it turns nothing red — it is written this way
        // because the alternatives in a library are a panic or a hang.
        FixedLease {
            permit: slots.acquire_owned().await.ok(),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Box<str>, Gate>> {
        self.store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Box<str>, Gate>> {
        self.store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn gate_for(&self, authority: &str) -> Arc<Semaphore> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let Some(gate) = self.read().get(authority) {
            gate.last_use_seq.store(seq, Ordering::Relaxed);
            return Arc::clone(&gate.slots);
        }

        let mut store = self.write();
        // Another writer may have inserted while no lock was held.
        if let Some(gate) = store.get(authority) {
            gate.last_use_seq.store(seq, Ordering::Relaxed);
            return Arc::clone(&gate.slots);
        }
        let slots = Arc::new(Semaphore::new(self.limit));
        store.insert(
            authority.into(),
            Gate {
                slots: Arc::clone(&slots),
                last_use_seq: AtomicU64::new(seq),
            },
        );
        self.evict(&mut store, authority);
        slots
    }

    /// How far a purge drops the store below the capacity.
    ///
    /// A batch rather than one entry, so a store under sustained pressure pays
    /// the eviction scan once per batch instead of once per insert.
    fn purge_target(&self) -> usize {
        let batch = (self.capacity / 16).max(1);
        self.capacity.saturating_sub(batch).max(1)
    }

    /// Evicts the least recently used entries, never touching `protect` or one
    /// with a request in flight.
    ///
    /// One pass holding no more than the `doomed` worst candidates, so the store
    /// is never flattened into a temporary its own size. An entry with a slot
    /// outstanding is skipped, because a fresh gate would grant the origin a
    /// full set of slots on top of the ones already out; the store can therefore
    /// exceed its capacity by the number of origins with a request in flight — a
    /// number set by the caller's own concurrency, not by the servers.
    fn evict(&self, store: &mut HashMap<Box<str>, Gate>, protect: &str) {
        if store.len() <= self.capacity {
            return;
        }
        let doomed = store.len() - self.purge_target();

        let mut worst: BinaryHeap<(u64, &str)> = BinaryHeap::with_capacity(doomed + 1);
        for (key, gate) in store.iter() {
            // `protect` cannot bind today and no test reaches it: the entry that
            // triggered this purge carries the highest sequence number in the
            // store, and this pass evicts the lowest. It stays because the
            // sequence wraps — `fetch_add` is chosen over an `Instant` precisely
            // so that it does rather than panicking — and on the wrap the
            // newcomer is the entry with the *lowest* number, which is the one
            // moment forgetting a gate would let an origin hold two sets of
            // slots at once.
            if &**key == protect || gate.slots.available_permits() < self.limit {
                continue;
            }
            let candidate = (gate.last_use_seq.load(Ordering::Relaxed), &**key);
            if worst.len() < doomed {
                worst.push(candidate);
            } else if worst.peek().is_some_and(|held| *held > candidate) {
                worst.pop();
                worst.push(candidate);
            }
        }
        let victims: Vec<Box<str>> = worst.into_iter().map(|(_, key)| key.into()).collect();
        for key in victims {
            store.remove(&key);
        }
    }
}

/// One slot on one origin, held by a [`FixedConcurrency`].
///
/// Dropping it returns the slot; so does [`Lease::complete`], which has nothing
/// else to do because this controller learns nothing.
#[derive(Debug)]
pub struct FixedLease {
    permit: Option<OwnedSemaphorePermit>,
}

impl FixedLease {
    /// Whether this lease is holding one of its origin's slots.
    ///
    /// Always true for a lease this crate issued. It is false only for the
    /// unreachable case in [`FixedConcurrency::acquire_authority`] — a semaphore
    /// closed by nothing that exists — and it is exposed so that "unreachable"
    /// is something a caller can check rather than something a comment claims.
    #[must_use]
    pub fn holds_a_slot(&self) -> bool {
        self.permit.is_some()
    }
}

impl Lease for FixedLease {
    fn complete(self: Box<Self>, _outcome: &Outcome<'_>) {
        // Nothing is learned from an outcome here, and the slot comes back when
        // the permit inside this drops. A fixed limit is fixed.
    }
}

impl ConcurrencyController for FixedConcurrency {
    fn acquire<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>> {
        Box::pin(
            async move { Box::new(FixedConcurrency::acquire(self, url).await) as Box<dyn Lease> },
        )
    }
}
