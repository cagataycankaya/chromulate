//! What the in-memory store's locking costs, measured rather than asserted.
//!
//! `MemoryStore` puts a `Mutex` in front of every lookup, which is the shape
//! this workspace already pays for once in the connection pool and does not
//! want a second copy of. Sharding is the answer, and "sharding helps" is a
//! claim, so this measures it.
//!
//! Both tests are `#[ignore]`d: they are a harness, not an assertion. A timing
//! threshold in CI is a flaky test on a loaded runner. Run them by hand:
//!
//! ```text
//! cargo test -p chromulate-cache --release --test lock_cost -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use chromulate_cache::{CacheKey, CacheStorage, MemoryLimits, MemoryStore, Selector};
use http::{HeaderMap, Method, StatusCode, Version};
use url::Url;

const KEYS: usize = 1_000;
const RUNS: usize = 3;

fn filled(shards: usize) -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::with_limits(MemoryLimits {
        max_bytes: 256 * 1024 * 1024,
        shards,
    }));
    for index in 0..KEYS {
        store
            .put(
                &key(index),
                Arc::new(chromulate_cache::CacheEntry::new(
                    StatusCode::OK,
                    Version::HTTP_11,
                    HeaderMap::new(),
                    Bytes::from_static(b"body"),
                    Selector::any(),
                    SystemTime::UNIX_EPOCH,
                    SystemTime::UNIX_EPOCH,
                )),
            )
            .expect("put succeeds");
    }
    store
}

fn key(index: usize) -> CacheKey {
    CacheKey::new(
        &Method::GET,
        &Url::parse(&format!("https://origin.test/asset/{index}")).expect("a valid url"),
    )
}

/// Nanoseconds per lookup, over `RUNS` runs, reported as the median.
fn median_ns(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[test]
#[ignore = "a measurement harness, not an assertion"]
fn one_thread_lookup_cost() {
    let store = filled(16);
    let keys: Vec<CacheKey> = (0..KEYS).map(key).collect();
    let iterations = 200_000;

    let mut samples = Vec::new();
    for _ in 0..RUNS {
        let started = Instant::now();
        for index in 0..iterations {
            let found = store.get(&keys[index % KEYS]).expect("get succeeds");
            std::hint::black_box(found.len());
        }
        samples.push(started.elapsed().as_nanos() as f64 / iterations as f64);
    }

    println!(
        "uncontended lookup: {:.1} ns/op (median of {RUNS} runs, {iterations} lookups each)",
        median_ns(samples)
    );
}

#[test]
#[ignore = "a measurement harness, not an assertion"]
fn contended_lookup_cost_by_shard_count() {
    let threads = 8;
    let iterations = 100_000;

    for shards in [1, 16] {
        let store = filled(shards);
        let keys: Arc<Vec<CacheKey>> = Arc::new((0..KEYS).map(key).collect());

        let mut samples = Vec::new();
        for _ in 0..RUNS {
            let done = Arc::new(AtomicU64::new(0));
            let started = Instant::now();
            std::thread::scope(|scope| {
                for thread in 0..threads {
                    let store = Arc::clone(&store);
                    let keys = Arc::clone(&keys);
                    let done = Arc::clone(&done);
                    scope.spawn(move || {
                        for index in 0..iterations {
                            let found = store
                                .get(&keys[(index * 31 + thread) % KEYS])
                                .expect("get succeeds");
                            std::hint::black_box(found.len());
                        }
                        done.fetch_add(iterations as u64, Ordering::Relaxed);
                    });
                }
            });
            let total = done.load(Ordering::Relaxed) as f64;
            samples.push(started.elapsed().as_nanos() as f64 / total);
        }

        println!(
            "{threads} threads, {shards:>2} shard(s): {:.1} ns/op (median of {RUNS} runs)",
            median_ns(samples)
        );
    }
}
