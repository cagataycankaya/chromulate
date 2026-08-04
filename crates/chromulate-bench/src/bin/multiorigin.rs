//! Throughput as the number of distinct origins grows.
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin multiorigin
//! ```
//!
//! Every other end-to-end measurement in this crate uses one origin, which is
//! the shape that hides anything costing *per pool key* rather than per
//! request. A crawler is the opposite shape: it holds idle connections to many
//! hosts at once, and work that walks the pool on every request then scales
//! with how many hosts the crawl has touched, not with how much it is asking
//! for.
//!
//! The harness sweeps the origin count with everything else fixed. A client
//! whose per-request cost is independent of pool size holds a flat line; one
//! that walks the pool bends downwards. `BENCH_ORIGINS` sets the sweep
//! (default `1,10,50,100`).
//!
//! `reqwest` runs the same sweep, as a control: a bend that appears in both is
//! the machine or the loopback stack rather than either client.

#![forbid(unsafe_code)]

use std::env;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chromulate_bench::server;
use chromulate_bench::stats::Summary;
use chromulate_http::PoolConfig;

/// Requests in flight, held constant across the sweep so the only thing
/// changing is how many origins those requests are spread over.
const CONCURRENCY: usize = 32;

/// Idle connections the pool may hold in total.
///
/// High enough that a hundred origins can all keep a connection: the point of
/// the sweep is a *full* pool of many keys, which is what a long crawl reaches
/// and what makes any per-request walk over it expensive.
const MAX_TOTAL: usize = 4096;

/// Idle connections per origin.
///
/// Set to the concurrency level rather than a browser-like six, because a
/// smaller number turns the one-origin row into a connection-churn benchmark:
/// 32 requests in flight through 6 idle slots reopen sockets continuously,
/// which on a loopback sweep exhausts ephemeral ports and drowns the thing
/// being measured in connect errors.
const MAX_PER_HOST: usize = CONCURRENCY;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let measure = Duration::from_secs(env_u64("BENCH_SECS", 2));
    let warmup = Duration::from_millis(env_u64("BENCH_WARMUP_MS", 500));
    let repeats = env_u64("BENCH_REPEATS", 3) as usize;
    let counts: Vec<usize> = env::var("BENCH_ORIGINS")
        .unwrap_or_else(|_| "1,10,50,100".to_owned())
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect();

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env_u64("BENCH_CLIENT_THREADS", 4) as usize)
        .thread_name("bench-client")
        .enable_all()
        .build()?;

    println!("# throughput against N distinct origins, requests/second");
    println!(
        "# concurrency {CONCURRENCY}, max_total {MAX_TOTAL}, {repeats} interleaved repeats of \
         {measure:?} after {warmup:?}"
    );
    println!("# a client whose per-request cost does not depend on pool size holds a flat line.");
    println!();

    let mut chromulate: Vec<Vec<f64>> = vec![Vec::new(); counts.len()];
    let mut baseline: Vec<Vec<f64>> = vec![Vec::new(); counts.len()];

    // One set of origins per count, held for the whole sweep. Restarting them
    // per round would burn a fresh listening port every time and, on a loopback
    // sweep of a hundred origins, run the machine out of ephemeral ports before
    // the measurement finished. Each measurement builds a *fresh client*, which
    // is what actually matters: the pool belongs to the client, so a new client
    // starts with an empty one regardless of how old the origins are.
    //
    // The origin runtime gets its own workers scaled to the largest set: a
    // hundred accept loops sharing four threads starves the accept path under
    // load, and a client that cannot connect measures nothing.
    let origin_threads = env_u64("BENCH_SERVER_THREADS", 8) as usize;
    let mut origin_sets = Vec::with_capacity(counts.len());
    for count in counts.iter().copied() {
        origin_sets.push(server::start_many(count, origin_threads)?);
    }

    for round in 1..=repeats {
        for (slot, count) in counts.iter().copied().enumerate() {
            let origins = &origin_sets[slot];
            let urls: Arc<Vec<String>> = Arc::new(origins.urls("/"));

            let mine = client_rt.block_on(run_chromulate(
                Arc::clone(&urls),
                warmup,
                measure,
                origins.accept_counter(),
            ))?;
            let theirs = client_rt.block_on(run_reqwest(
                Arc::clone(&urls),
                warmup,
                measure,
                origins.accept_counter(),
            ))?;

            println!(
                "round {round}  origins={count:<4} chromulate {:>8.0} rps (errors {}, conns {})  \
                 reqwest {:>8.0} rps (errors {}, conns {})",
                mine.rps(),
                mine.errors,
                mine.connections,
                theirs.rps(),
                theirs.errors,
                theirs.connections
            );
            chromulate[slot].push(mine.rps());
            baseline[slot].push(theirs.rps());
        }
        println!();
    }

    println!("# summary");
    let report = |label: &str, samples: &[Vec<f64>]| {
        let first = Summary::of(&samples[0]).median;
        for (slot, count) in counts.iter().copied().enumerate() {
            let summary = Summary::of(&samples[slot]);
            println!(
                "{label:<11} origins={count:<4} median {:>8.0} rps  \
                 (min {:>8.0}, max {:>8.0}, n={})  {:.3}x of the 1-origin figure",
                summary.median,
                summary.min,
                summary.max,
                summary.runs,
                summary.median / first
            );
        }
        println!();
    };
    report("chromulate", &chromulate);
    report("reqwest", &baseline);

    println!("# paired ratio against reqwest, within each round");
    for (slot, count) in counts.iter().copied().enumerate() {
        let ratios: Vec<f64> = chromulate[slot]
            .iter()
            .zip(&baseline[slot])
            .map(|(mine, theirs)| mine / theirs)
            .collect();
        let summary = Summary::of(&ratios);
        println!(
            "origins={count:<4} median {:.3}x  (min {:.3}, max {:.3}, n={})",
            summary.median, summary.min, summary.max, summary.runs
        );
    }

    Ok(())
}

struct Outcome {
    ok: u64,
    errors: u64,
    elapsed: Duration,
    connections: u64,
}

impl Outcome {
    fn rps(&self) -> f64 {
        self.ok as f64 / self.elapsed.as_secs_f64()
    }
}

async fn run_chromulate(
    urls: Arc<Vec<String>>,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let client = chromulate::Client::builder()
        .pool(PoolConfig {
            max_per_host: MAX_PER_HOST,
            max_total: MAX_TOTAL,
            ..PoolConfig::default()
        })
        .build()?;
    let fetch = move |url: String| {
        let client = client.clone();
        async move {
            let response = client.get(&url).send().await.map_err(err)?;
            response.bytes().await.map_err(err).map(|body| body.len())
        }
    };
    drive(urls, warmup, measure, accepted, fetch).await
}

async fn run_reqwest(
    urls: Arc<Vec<String>>,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(MAX_PER_HOST)
        .tcp_nodelay(true)
        .build()?;
    let fetch = move |url: String| {
        let client = client.clone();
        async move {
            let response = client.get(&url).send().await.map_err(err)?;
            response.bytes().await.map_err(err).map(|body| body.len())
        }
    };
    drive(urls, warmup, measure, accepted, fetch).await
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn drive<F, Fut>(
    urls: Arc<Vec<String>>,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
    fetch: F,
) -> Result<Outcome, Box<dyn std::error::Error>>
where
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<usize, String>> + Send,
{
    if !warmup.is_zero() {
        // The warmup is what fills the pool: after it, every origin has an idle
        // connection waiting, which is the state the measurement is about.
        load(Arc::clone(&urls), warmup, fetch.clone()).await?;
    }
    let before = accepted.load(Ordering::Relaxed);
    let mut outcome = load(urls, measure, fetch).await?;
    outcome.connections = accepted.load(Ordering::Relaxed) - before;
    Ok(outcome)
}

async fn load<F, Fut>(
    urls: Arc<Vec<String>>,
    duration: Duration,
    fetch: F,
) -> Result<Outcome, Box<dyn std::error::Error>>
where
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<usize, String>> + Send,
{
    let started = Instant::now();
    let deadline = started + duration;

    let mut workers = Vec::with_capacity(CONCURRENCY);
    for worker in 0..CONCURRENCY {
        let fetch = fetch.clone();
        let urls = Arc::clone(&urls);
        workers.push(tokio::spawn(async move {
            let mut ok = 0u64;
            let mut errors = 0u64;
            let mut first_error: Option<String> = None;
            // Each worker starts at a different origin and walks the list, so
            // the load is spread rather than piled onto whichever origin the
            // first worker picked.
            let mut next = worker;
            while Instant::now() < deadline {
                let url = urls[next % urls.len()].clone();
                next += 1;
                match fetch(url).await {
                    Ok(_) => ok += 1,
                    Err(message) => {
                        errors += 1;
                        if first_error.is_none() {
                            first_error = Some(message);
                        }
                    }
                }
            }
            (ok, errors, first_error)
        }));
    }

    let mut outcome = Outcome {
        ok: 0,
        errors: 0,
        elapsed: Duration::ZERO,
        connections: 0,
    };
    let mut first_error = None;
    for worker in workers {
        let (ok, errors, error) = worker.await?;
        outcome.ok += ok;
        outcome.errors += errors;
        if first_error.is_none() {
            first_error = error;
        }
    }
    outcome.elapsed = started.elapsed();

    if let Some(message) = first_error {
        eprintln!(
            "  note: {} request(s) failed, first: {message}",
            outcome.errors
        );
    }
    Ok(outcome)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
