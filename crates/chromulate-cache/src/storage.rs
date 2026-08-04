//! Where stored responses live: the backend trait, and the in-memory one.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher as _, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::entry::{CacheEntry, CacheKey};

/// The variants stored under one key, newest last.
///
/// An `Arc` rather than a `Vec`, so a lookup hands out a reference count
/// instead of copying: the overwhelmingly common case is one variant, and a
/// hit should not allocate to report it.
pub type Variants = Arc<[Arc<CacheEntry>]>;

/// What a cache backend can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// The backend could not be reached or is not usable right now.
    #[error("the cache backend is unavailable: {message}")]
    Unavailable {
        /// What went wrong.
        message: String,
    },
    /// The backend failed while reading or writing an entry.
    #[error("the cache backend failed: {message}")]
    Backend {
        /// What went wrong.
        message: String,
        /// The underlying failure, when the backend has one to give.
        #[source]
        source: Option<chromulate_core::BoxError>,
    },
}

/// Somewhere to keep stored responses.
///
/// The in-memory [`MemoryStore`] is what ships; implement this to put the cache
/// on disk, in Redis, or anywhere else.
///
/// # What an implementation owes its caller
///
/// - [`put`](CacheStorage::put) must **replace** any stored variant whose
///   [`Selector`](crate::Selector) equals the incoming one, and keep the rest.
///   Appending instead grows an unbounded list of variants that can never be
///   reached, because lookup takes the first match.
/// - [`get`](CacheStorage::get) may return variants in any order; the cache
///   selects among them itself.
/// - Every method may fail. A failure is logged and treated as a miss: a cache
///   that cannot be read must never be a request that cannot be made.
///
/// [`merge_variants`] implements the replacement rule, so a backend only has to
/// store what it is handed.
pub trait CacheStorage: Send + Sync + fmt::Debug + 'static {
    /// The variants stored under `key`, or an empty slice.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot be read.
    fn get(&self, key: &CacheKey) -> Result<Variants, CacheError>;

    /// Stores `entry`, replacing the variant it supersedes.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot be written.
    fn put(&self, key: &CacheKey, entry: Arc<CacheEntry>) -> Result<(), CacheError>;

    /// Drops everything stored under `key`.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot be written.
    fn remove(&self, key: &CacheKey) -> Result<(), CacheError>;
}

/// Applies the replacement rule a backend's `put` owes its caller.
///
/// The incoming entry supersedes any stored variant selected by the same
/// header values, and is appended otherwise.
#[must_use]
pub fn merge_variants(
    existing: &[Arc<CacheEntry>],
    entry: Arc<CacheEntry>,
) -> Vec<Arc<CacheEntry>> {
    let mut merged: Vec<Arc<CacheEntry>> = existing
        .iter()
        .filter(|stored| stored.selector() != entry.selector())
        .cloned()
        .collect();
    merged.push(entry);
    merged
}

/// How large an in-memory cache is allowed to get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimits {
    /// The byte budget across the whole store.
    ///
    /// Counted as the estimate in [`CacheEntry::size`] plus the key, not as
    /// resident set size.
    pub max_bytes: usize,
    /// How many independently locked shards the store is split into.
    ///
    /// One lock in front of every request is the shape this project already
    /// pays for in the connection pool and does not want a second copy of.
    /// Sixteen shards mean sixteen uncontended locks in the common case, and
    /// the byte budget is divided evenly among them.
    pub shards: usize,
}

impl Default for MemoryLimits {
    /// Thirty-two megabytes across sixteen shards.
    ///
    /// Ordinary configuration rather than a captured constant: it is big enough
    /// that a crawl of one site keeps its static assets, and small enough that
    /// a forgotten cache is not a leak.
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            shards: 16,
        }
    }
}

impl MemoryLimits {
    fn per_shard(&self) -> usize {
        (self.max_bytes / self.shards.max(1)).max(1)
    }

    /// How far below its cap an overflowing shard is purged in one pass.
    ///
    /// One eighth, so a store under sustained pressure oscillates between
    /// seven eighths and full and pays for one purge every eighth of a
    /// capacity stored, rather than a full scan on every single store. The
    /// cookie jar batches for the same reason and with the same shape.
    fn purge_target(&self) -> usize {
        let cap = self.per_shard();
        cap.saturating_sub(cap / 8)
    }
}

/// What an in-memory store is currently holding, and what it has cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryStats {
    /// How many keys are stored.
    pub keys: usize,
    /// The store's own estimate of the bytes it holds.
    pub bytes: usize,
    /// How many keys have been evicted to stay inside the budget.
    pub evictions: u64,
    /// How many records purges have examined, in total.
    ///
    /// Divided by the number of stores, this is the amortised cost of
    /// eviction. It exists so that "eviction is batched" is a measurement
    /// rather than a claim.
    pub purge_scans: u64,
}

/// A bounded, sharded, least-recently-used cache in process memory.
///
/// # Eviction
///
/// Least-recently-used, batched. A store that pushes a shard past its share of
/// the budget purges that shard down to seven eighths of it in one pass,
/// dropping whole keys — every variant of a key goes together — in ascending
/// order of last use.
///
/// Staleness is deliberately **not** part of the ranking. The store has no
/// clock, and a stale entry is not worthless: it still carries the `ETag` that
/// turns the next request into a conditional one and the next response into a
/// `304`. Ranking it below a fresh entry would throw away the cheapest hit the
/// cache has.
///
/// # Locking, and what measuring it settled
///
/// One `Mutex` per shard, taken for reads as well as writes, because a lookup
/// updates the recency stamp and a stamp nobody updates is not an LRU.
///
/// The obvious refinement — an `RwLock` per shard with the stamp as an
/// `AtomicU64` inside the record, so a lookup takes a shared lock — was written
/// and measured, and it was **slower**: 118 ns per uncontended lookup against
/// this design's 70, and 177 ns against 174 with eight threads over sixteen
/// shards (medians of three runs each, macOS/arm64). A read does not get
/// cheaper by becoming shared when it still writes a stamp into a shared cache
/// line, and `std`'s `RwLock` costs more to acquire than its `Mutex` there.
/// `tests/lock_cost.rs` is the harness; re-run it before assuming the
/// refinement is an improvement.
///
/// What the same harness says about sharding is the number that mattered: eight
/// threads over sixteen shards reach 174 ns per lookup against 247 ns over one
/// shard, and one uncontended lookup costs 70 ns. The sharding earns its
/// complexity; a single global lock in front of every request would not have.
pub struct MemoryStore {
    shards: Box<[Mutex<Shard>]>,
    limits: MemoryLimits,
    hasher: RandomState,
    /// A strictly increasing stamp handed out on every access, so no two
    /// records share a last-use value and the purge cutoff below is exact.
    tick: AtomicU64,
    evictions: AtomicU64,
    purge_scans: AtomicU64,
}

#[derive(Debug, Default)]
struct Shard {
    records: HashMap<CacheKey, Record>,
    bytes: usize,
}

#[derive(Debug)]
struct Record {
    variants: Variants,
    bytes: usize,
    last_used: u64,
}

impl MemoryStore {
    /// A store with the default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(MemoryLimits::default())
    }

    /// A store with custom limits.
    #[must_use]
    pub fn with_limits(limits: MemoryLimits) -> Self {
        let shards = limits.shards.max(1);
        Self {
            shards: (0..shards).map(|_| Mutex::new(Shard::default())).collect(),
            limits: MemoryLimits { shards, ..limits },
            hasher: RandomState::new(),
            tick: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            purge_scans: AtomicU64::new(0),
        }
    }

    /// What the store is holding and what eviction has cost.
    #[must_use]
    pub fn stats(&self) -> MemoryStats {
        let mut keys = 0;
        let mut bytes = 0;
        for shard in &self.shards {
            let shard = lock(shard);
            keys += shard.records.len();
            bytes += shard.bytes;
        }
        MemoryStats {
            keys,
            bytes,
            evictions: self.evictions.load(Ordering::Relaxed),
            purge_scans: self.purge_scans.load(Ordering::Relaxed),
        }
    }

    fn shard_of(&self, key: &CacheKey) -> &Mutex<Shard> {
        let index = (self.hasher.hash_one(key) % self.shards.len() as u64) as usize;
        &self.shards[index]
    }

    /// The next recency stamp. Saturating, so a process that somehow performs
    /// `u64::MAX` lookups stops ordering rather than wrapping to zero and
    /// evicting everything it just touched.
    fn next_tick(&self) -> u64 {
        self.tick
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |tick| {
                Some(tick.saturating_add(1))
            })
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }

    /// Purges `shard` down to the target when it has outgrown its cap.
    ///
    /// Two passes and no key clones: one to collect `(last_used, bytes)` pairs,
    /// which finds the exact stamp below which everything must go, and one
    /// `retain` to drop them. `last_used` is unique within a shard, so the
    /// cutoff is not ambiguous.
    fn purge(&self, shard: &mut Shard) {
        let cap = self.limits.per_shard();
        if shard.bytes <= cap {
            return;
        }
        let target = self.limits.purge_target();

        let mut ages: Vec<(u64, usize)> = shard
            .records
            .values()
            .map(|record| (record.last_used, record.bytes))
            .collect();
        self.purge_scans
            .fetch_add(ages.len() as u64, Ordering::Relaxed);
        ages.sort_unstable_by_key(|(last_used, _)| *last_used);

        let mut remaining = shard.bytes;
        let mut cutoff = 0;
        for (last_used, bytes) in ages {
            if remaining <= target {
                break;
            }
            remaining -= bytes.min(remaining);
            cutoff = last_used;
        }

        let before = shard.records.len();
        shard.records.retain(|_, record| record.last_used > cutoff);
        shard.bytes = shard.records.values().map(|record| record.bytes).sum();
        self.evictions
            .fetch_add((before - shard.records.len()) as u64, Ordering::Relaxed);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stats = self.stats();
        f.debug_struct("MemoryStore")
            .field("keys", &stats.keys)
            .field("bytes", &stats.bytes)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl CacheStorage for MemoryStore {
    fn get(&self, key: &CacheKey) -> Result<Variants, CacheError> {
        let tick = self.next_tick();
        let mut shard = lock(self.shard_of(key));
        match shard.records.get_mut(key) {
            Some(record) => {
                record.last_used = tick;
                Ok(Arc::clone(&record.variants))
            }
            None => Ok(Variants::from([])),
        }
    }

    fn put(&self, key: &CacheKey, entry: Arc<CacheEntry>) -> Result<(), CacheError> {
        let tick = self.next_tick();
        let mut shard = lock(self.shard_of(key));

        let existing = shard.records.get(key);
        let previous = existing.map_or(0, |record| record.bytes);
        let merged = merge_variants(existing.map_or(&[][..], |record| &record.variants), entry);
        let bytes = key.size() + merged.iter().map(|entry| entry.size()).sum::<usize>();

        // A record larger than its shard's whole share of the budget can never
        // be held: the purge below would drop it again on the way out, and
        // would take every other key in the shard with it — a cache flush an
        // origin can trigger with one large response. Refusing it here costs
        // the one entry that does not fit and nothing else.
        //
        // What is still dropped is the copy this entry supersedes: the origin
        // has answered with something newer, so the older body is no longer
        // true, and being unable to store the replacement does not make it so.
        if bytes > self.limits.per_shard() {
            if shard.records.remove(key).is_some() {
                shard.bytes -= previous.min(shard.bytes);
            }
            return Ok(());
        }

        shard.bytes = shard.bytes + bytes - previous.min(shard.bytes);
        shard.records.insert(
            key.clone(),
            Record {
                variants: Variants::from(merged),
                bytes,
                last_used: tick,
            },
        );

        self.purge(&mut shard);
        Ok(())
    }

    fn remove(&self, key: &CacheKey) -> Result<(), CacheError> {
        let mut shard = lock(self.shard_of(key));
        if let Some(record) = shard.records.remove(key) {
            shard.bytes -= record.bytes.min(shard.bytes);
        }
        Ok(())
    }
}

/// A poisoned cache lock is recovered rather than propagated: a panic somewhere
/// else must not turn every later request into a failure.
fn lock(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, StatusCode, Version};
    use url::Url;

    use super::*;
    use crate::entry::Selector;

    fn entry(size: usize) -> Arc<CacheEntry> {
        Arc::new(CacheEntry::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from(vec![b'x'; size]),
            Selector::any(),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
        ))
    }

    fn key(path: &str) -> CacheKey {
        CacheKey::new(
            &http::Method::GET,
            &Url::parse(&format!("https://a.test/{path}")).expect("a valid url"),
        )
    }

    #[test]
    fn a_stored_entry_comes_back() {
        let store = MemoryStore::new();
        store.put(&key("one"), entry(16)).expect("put succeeds");
        let variants = store.get(&key("one")).expect("get succeeds");
        assert_eq!(variants.len(), 1);
        assert_eq!(store.get(&key("two")).expect("get succeeds").len(), 0);
    }

    #[test]
    fn a_second_entry_with_the_same_selector_replaces_the_first() {
        let store = MemoryStore::new();
        store.put(&key("one"), entry(16)).expect("put succeeds");
        store.put(&key("one"), entry(32)).expect("put succeeds");
        let variants = store.get(&key("one")).expect("get succeeds");
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].body().len(), 32);
    }

    #[test]
    fn entries_with_different_selectors_are_kept_side_by_side() {
        let store = MemoryStore::new();
        let names = [HeaderName::from_static("accept-language")];

        for language in ["tr", "en"] {
            let mut request = HeaderMap::new();
            request.insert("accept-language", language.parse().expect("a valid value"));
            store
                .put(
                    &key("one"),
                    Arc::new(CacheEntry::new(
                        StatusCode::OK,
                        Version::HTTP_11,
                        HeaderMap::new(),
                        Bytes::from_static(b"body"),
                        Selector::of(&names, &request),
                        SystemTime::UNIX_EPOCH,
                        SystemTime::UNIX_EPOCH,
                    )),
                )
                .expect("put succeeds");
        }

        assert_eq!(store.get(&key("one")).expect("get succeeds").len(), 2);
    }

    #[test]
    fn removing_a_key_frees_its_bytes() {
        let store = MemoryStore::new();
        store.put(&key("one"), entry(1024)).expect("put succeeds");
        assert!(store.stats().bytes > 1024);
        store.remove(&key("one")).expect("remove succeeds");
        assert_eq!(store.stats().bytes, 0);
        assert_eq!(store.stats().keys, 0);
    }

    #[test]
    fn the_store_stays_inside_its_byte_budget() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 64 * 1024,
            shards: 1,
        });
        for index in 0..200 {
            store
                .put(&key(&index.to_string()), entry(1024))
                .expect("put succeeds");
        }
        assert!(
            store.stats().bytes <= 64 * 1024,
            "the store held {} bytes against a 65536 byte budget",
            store.stats().bytes
        );
        assert!(store.stats().evictions > 0);
    }

    #[test]
    fn a_purge_drops_the_least_recently_used_key_and_keeps_the_newcomer() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 8 * 1024,
            shards: 1,
        });
        for index in 0..8 {
            store
                .put(&key(&index.to_string()), entry(512))
                .expect("put succeeds");
        }
        // Touch the oldest key so it is no longer the least recently used.
        let _ = store.get(&key("0")).expect("get succeeds");
        for index in 8..16 {
            store
                .put(&key(&index.to_string()), entry(512))
                .expect("put succeeds");
        }

        assert_eq!(
            store.get(&key("15")).expect("get succeeds").len(),
            1,
            "the entry that caused the purge must survive it"
        );
        assert_eq!(
            store.get(&key("1")).expect("get succeeds").len(),
            0,
            "an untouched early key must be among the evicted"
        );
    }

    /// A purge that scanned the whole shard on every store would make eviction
    /// quadratic in the number of stores, which is the bug the cookie jar's
    /// batching exists to avoid. This pins the amortisation as a number rather
    /// than as an intention.
    #[test]
    fn eviction_cost_amortises_across_stores_once_the_store_is_full() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 64 * 1024,
            shards: 1,
        });
        for index in 0..200 {
            store
                .put(&key(&index.to_string()), entry(512))
                .expect("put succeeds");
        }
        let filled = store.stats().purge_scans;

        for index in 200..300 {
            store
                .put(&key(&index.to_string()), entry(512))
                .expect("put succeeds");
        }
        let scans = store.stats().purge_scans - filled;

        // A full shard holds roughly 100 records. Purging on every store would
        // be ~100 * 100 = 10_000 scans; batching one eighth of the budget makes
        // it a purge every ~12 stores.
        assert!(
            scans < 100 * 30,
            "100 stores into a full cache examined {scans} records — eviction is not batched"
        );
    }

    /// A record too large for its shard cannot be kept whatever happens: the
    /// purge that follows its own store evicts it again. What must not happen
    /// is that it takes the rest of the shard with it on the way out, which is
    /// a whole-cache flush an origin can trigger with one large response.
    #[test]
    fn an_entry_too_large_for_its_shard_is_refused_rather_than_flushing_it() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 8 * 1024,
            shards: 1,
        });
        for index in 0..4 {
            store
                .put(&key(&index.to_string()), entry(512))
                .expect("put succeeds");
        }
        assert_eq!(store.stats().keys, 4);

        store
            .put(&key("huge"), entry(16 * 1024))
            .expect("put succeeds");

        assert_eq!(
            store.get(&key("huge")).expect("get succeeds").len(),
            0,
            "an entry larger than the whole shard cannot be stored"
        );
        assert_eq!(
            store.stats().keys,
            4,
            "and refusing it must not evict the four keys that do fit"
        );
        assert_eq!(store.stats().evictions, 0);
        assert!(store.stats().bytes <= 8 * 1024);
    }

    /// The oversized entry supersedes what was stored under its own key, and
    /// the fact that it cannot be kept does not make the copy it replaced true
    /// again.
    #[test]
    fn a_refused_oversized_entry_still_drops_the_copy_it_supersedes() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 8 * 1024,
            shards: 1,
        });
        store.put(&key("one"), entry(512)).expect("put succeeds");
        store
            .put(&key("one"), entry(16 * 1024))
            .expect("put succeeds");

        assert_eq!(store.get(&key("one")).expect("get succeeds").len(), 0);
        assert_eq!(store.stats().bytes, 0);
    }

    #[test]
    fn sharding_keeps_keys_apart_without_losing_them() {
        let store = MemoryStore::with_limits(MemoryLimits {
            max_bytes: 8 * 1024 * 1024,
            shards: 16,
        });
        for index in 0..256 {
            store
                .put(&key(&index.to_string()), entry(64))
                .expect("put succeeds");
        }
        assert_eq!(store.stats().keys, 256);
        for index in 0..256 {
            assert_eq!(
                store
                    .get(&key(&index.to_string()))
                    .expect("get succeeds")
                    .len(),
                1
            );
        }
    }
}
