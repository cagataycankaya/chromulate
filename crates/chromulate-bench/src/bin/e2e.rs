//! End-to-end throughput: `chromulate::Client` against `reqwest::Client`.
//!
//! A throughput number on its own says nothing — it is a property of the
//! machine as much as of the client. So the harness runs the identical workload
//! through reqwest, which is what a user would otherwise reach for, and reports
//! the ratio.
//!
//! Both clients talk to the same loopback hyper server over plaintext HTTP/1.1
//! with connection reuse on. Plaintext is deliberate: with TLS in the path and
//! connections reused, the handshake amortises to nothing and all the
//! measurement would gain is noise from two different TLS stacks. What is being
//! measured here is per-request client overhead.
//!
//! Run with:
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin e2e
//! ```
//!
//! Environment overrides: `BENCH_SECS` (measurement window, default 2),
//! `BENCH_WARMUP_MS` (default 500), `BENCH_REPEATS` (default 3),
//! `BENCH_SERVER_THREADS` (default 4), `BENCH_CLIENT_THREADS` (default 4).

#![forbid(unsafe_code)]

use std::env;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chromulate_bench::server;
use chromulate_bench::stats::Summary;
use chromulate_http::PoolConfig;

/// Concurrency levels the harness sweeps.
const CONCURRENCY: [usize; 4] = [1, 8, 64, 256];

/// Pool size used by the "tuned" configurations, chosen so that the highest
/// concurrency level never has to open a connection mid-run.
const WIDE_POOL: usize = 512;

#[derive(Debug, Clone, Copy)]
struct Outcome {
    ok: u64,
    errors: u64,
    bytes: u64,
    elapsed: Duration,
    /// TCP connections the server accepted during the measured window only.
    connections: u64,
}

impl Outcome {
    fn rps(self) -> f64 {
        self.ok as f64 / self.elapsed.as_secs_f64()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let measure = Duration::from_secs(env_u64("BENCH_SECS", 2));
    let warmup = Duration::from_millis(env_u64("BENCH_WARMUP_MS", 500));
    let repeats = env_u64("BENCH_REPEATS", 3) as usize;
    let server_threads = env_u64("BENCH_SERVER_THREADS", 4) as usize;
    let client_threads = env_u64("BENCH_CLIENT_THREADS", 4) as usize;

    let origin = server::start(server_threads)?;
    let url = Arc::new(origin.url("/"));

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(client_threads)
        .thread_name("bench-client")
        .enable_all()
        .build()?;

    println!("# end-to-end throughput, requests/second");
    println!(
        "# server {} on {} worker threads, client on {} worker threads",
        origin.addr(),
        server_threads,
        client_threads
    );
    println!(
        "# body {} bytes, HTTP/1.1 plaintext, keep-alive, {} repeats of {:?} after {:?} warmup",
        server::SMALL_BODY_LEN,
        repeats,
        measure,
        warmup
    );
    println!("# rounds are interleaved: every client is measured once per round, so a");
    println!("# busy patch on the machine lands on all of them rather than on one.");
    println!();

    // [configuration][concurrency] -> one rps sample per round.
    let mut samples: Vec<Vec<Vec<f64>>> =
        vec![vec![Vec::with_capacity(repeats); CONCURRENCY.len()]; configurations().len()];
    let mut errors = vec![vec![0u64; CONCURRENCY.len()]; configurations().len()];
    let mut requests = vec![vec![0u64; CONCURRENCY.len()]; configurations().len()];
    let mut opened = vec![vec![0u64; CONCURRENCY.len()]; configurations().len()];

    for round in 0..repeats {
        for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
            for (index, (label, kind)) in configurations().into_iter().enumerate() {
                let outcome = client_rt.block_on(run(
                    kind,
                    Arc::clone(&url),
                    concurrency,
                    warmup,
                    measure,
                    origin.accept_counter(),
                ))?;
                errors[index][slot] += outcome.errors;
                requests[index][slot] += outcome.ok;
                opened[index][slot] += outcome.connections;
                samples[index][slot].push(outcome.rps());
                println!(
                    "round {} c={concurrency:<4} {label:<34} {:.0} rps  \
                     errors={} conns={}",
                    round + 1,
                    outcome.rps(),
                    outcome.errors,
                    outcome.connections
                );
            }
        }
        println!();
    }

    println!();
    println!("# summary, requests/second");
    for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
        for (index, (label, _)) in configurations().into_iter().enumerate() {
            let summary = Summary::of(&samples[index][slot]);
            let churn = if opened[index][slot] == 0 {
                "no connections opened after warmup".to_owned()
            } else {
                format!(
                    "{} conns opened, {:.0} req/conn",
                    opened[index][slot],
                    requests[index][slot] as f64 / opened[index][slot] as f64
                )
            };
            println!(
                "c={concurrency:<4} {label:<34} {summary}  errors={}  [{churn}]",
                errors[index][slot]
            );
        }
        println!();
    }

    let baseline_index = configurations()
        .iter()
        .position(|(label, _)| *label == REQWEST)
        .ok_or("the reqwest baseline must be one of the configurations")?;

    println!();
    println!("# ratio against reqwest, paired within each round (>1 means Chromulate is faster)");
    println!("# pairing matters: it compares runs that saw the same machine, not two means");
    println!("# taken minutes apart.");
    for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
        for (index, (label, _)) in configurations().into_iter().enumerate() {
            if index == baseline_index {
                continue;
            }
            let ratios: Vec<f64> = samples[index][slot]
                .iter()
                .zip(&samples[baseline_index][slot])
                .map(|(mine, theirs)| mine / theirs)
                .collect();
            let summary = Summary::of(&ratios);
            println!(
                "c={concurrency:<4} {label:<34} median {:.3}x  \
                 (mean {:.3}, min {:.3}, max {:.3}, n={})",
                summary.median, summary.mean, summary.min, summary.max, summary.runs
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `Client::chrome()` exactly as shipped: 6 idle connections per host,
    /// cookie jar on. This is what a user gets without tuning.
    ChromulateDefault,
    /// The same client with the idle pool widened past the concurrency level,
    /// which separates per-request cost from connection churn.
    ChromulateWidePool,
    /// Wide pool and no cookie jar, which is the configuration closest to what
    /// reqwest does by default.
    ChromulateWidePoolNoCookies,
    Reqwest,
}

const REQWEST: &str = "reqwest";

fn configurations() -> [(&'static str, Kind); 4] {
    [
        ("chromulate (default pool 6)", Kind::ChromulateDefault),
        ("chromulate (pool 512)", Kind::ChromulateWidePool),
        (
            "chromulate (pool 512, no cookies)",
            Kind::ChromulateWidePoolNoCookies,
        ),
        (REQWEST, Kind::Reqwest),
    ]
}

async fn run(
    kind: Kind,
    url: Arc<String>,
    concurrency: usize,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    match kind {
        Kind::Reqwest => {
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(WIDE_POOL)
                .tcp_nodelay(true)
                .build()?;
            let fetch = move |url: Arc<String>| {
                let client = client.clone();
                async move {
                    let response = client.get(url.as_str()).send().await.map_err(err)?;
                    let body = response.bytes().await.map_err(err)?;
                    Ok(body.len())
                }
            };
            drive(url, concurrency, warmup, measure, accepted, fetch).await
        }
        _ => {
            let mut builder = chromulate::Client::builder();
            if kind != Kind::ChromulateDefault {
                builder = builder.pool(PoolConfig {
                    max_per_host: WIDE_POOL,
                    max_total: WIDE_POOL * 4,
                    ..PoolConfig::default()
                });
            }
            if kind == Kind::ChromulateWidePoolNoCookies {
                builder = builder.cookie_store(false);
            }
            let client = builder.build()?;
            let fetch = move |url: Arc<String>| {
                let client = client.clone();
                async move {
                    let response = client.get(url.as_str()).send().await.map_err(err)?;
                    let body = response.bytes().await.map_err(err)?;
                    Ok(body.len())
                }
            };
            drive(url, concurrency, warmup, measure, accepted, fetch).await
        }
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn drive<F, Fut>(
    url: Arc<String>,
    concurrency: usize,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
    fetch: F,
) -> Result<Outcome, Box<dyn std::error::Error>>
where
    F: Fn(Arc<String>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<usize, String>> + Send,
{
    if !warmup.is_zero() {
        load(Arc::clone(&url), concurrency, warmup, fetch.clone()).await?;
    }
    let before = accepted.load(Ordering::Relaxed);
    let mut outcome = load(url, concurrency, measure, fetch).await?;
    outcome.connections = accepted.load(Ordering::Relaxed) - before;
    Ok(outcome)
}

async fn load<F, Fut>(
    url: Arc<String>,
    concurrency: usize,
    duration: Duration,
    fetch: F,
) -> Result<Outcome, Box<dyn std::error::Error>>
where
    F: Fn(Arc<String>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<usize, String>> + Send,
{
    let started = Instant::now();
    let deadline = started + duration;

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let fetch = fetch.clone();
        let url = Arc::clone(&url);
        workers.push(tokio::spawn(async move {
            let mut ok = 0u64;
            let mut errors = 0u64;
            let mut bytes = 0u64;
            let mut first_error: Option<String> = None;
            while Instant::now() < deadline {
                match fetch(Arc::clone(&url)).await {
                    Ok(read) => {
                        ok += 1;
                        bytes += read as u64;
                    }
                    Err(message) => {
                        errors += 1;
                        if first_error.is_none() {
                            first_error = Some(message);
                        }
                    }
                }
            }
            (ok, errors, bytes, first_error)
        }));
    }

    let mut outcome = Outcome {
        ok: 0,
        errors: 0,
        bytes: 0,
        elapsed: Duration::ZERO,
        connections: 0,
    };
    let mut first_error = None;
    for worker in workers {
        let (ok, errors, bytes, error) = worker.await?;
        outcome.ok += ok;
        outcome.errors += errors;
        outcome.bytes += bytes;
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
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}
