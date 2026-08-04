//! Concurrent throughput over the real protocol stack: TLS, ALPN, HTTP/2.
//!
//! ```text
//! cargo run --release -p chromulate-bench --features live --bin tlsbench
//! ```
//!
//! The plaintext harness measures per-request overhead with the handshake
//! excluded, and the live harness measures a real origin one request at a time.
//! Neither answers "how many concurrent HTTPS requests per second", which is
//! the number a crawler actually plans against — and the HTTP/2 path in
//! particular went unexercised by any offline benchmark here for long enough to
//! hide a defect that cost a full handshake per request.
//!
//! The origin is local (see [`chromulate_bench::tls_server`]) and presents a
//! certificate generated in-process. Both clients are given that certificate as
//! an extra trust root and verify it normally: nothing here disables
//! certificate checking, because a handshake that skips verification is not the
//! handshake being measured.
//!
//! `BENCH_H1` forces HTTP/1.1 over the same TLS origin, which separates "what
//! TLS costs" from "what HTTP/2 costs".

#![forbid(unsafe_code)]

use std::env;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chromulate_bench::stats::Summary;
use chromulate_bench::tls_server;
use chromulate_http::PoolConfig;

const CONCURRENCY: [usize; 4] = [1, 8, 64, 256];

/// Idle connections per host for the tuned configurations.
const WIDE_POOL: usize = 512;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let measure = Duration::from_secs(env_u64("BENCH_SECS", 2));
    let warmup = Duration::from_millis(env_u64("BENCH_WARMUP_MS", 500));
    let repeats = env_u64("BENCH_REPEATS", 3) as usize;

    let origin = tls_server::start(env_u64("BENCH_SERVER_THREADS", 4) as usize)?;
    let url = Arc::new(origin.url("/"));
    let certificate = origin.certificate_der().to_vec();

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env_u64("BENCH_CLIENT_THREADS", 4) as usize)
        .thread_name("bench-client")
        .enable_all()
        .build()?;

    println!("# concurrent throughput over TLS, requests/second");
    println!("# origin {} serving {}", origin.addr(), url);
    println!(
        "# {repeats} interleaved repeats of {measure:?} after {warmup:?}, \
         certificate verified against the origin's own root"
    );
    println!();

    let configurations: [(&str, Kind); 3] = [
        ("chromulate (default pool 6)", Kind::ChromulateDefault),
        ("chromulate (pool 512)", Kind::ChromulateWidePool),
        ("reqwest", Kind::Reqwest),
    ];

    let mut samples: Vec<Vec<Vec<f64>>> =
        vec![vec![Vec::with_capacity(repeats); CONCURRENCY.len()]; configurations.len()];
    let mut protocols = vec!["?"; configurations.len()];

    for round in 1..=repeats {
        for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
            for (index, (label, kind)) in configurations.into_iter().enumerate() {
                let outcome = client_rt.block_on(run(
                    kind,
                    Arc::clone(&url),
                    certificate.clone(),
                    concurrency,
                    warmup,
                    measure,
                    origin.accept_counter(),
                ))?;
                protocols[index] = outcome.protocol;
                samples[index][slot].push(outcome.rps());
                println!(
                    "round {round} c={concurrency:<4} {label:<28} {:>8.0} rps  \
                     errors={} conns={} proto={}",
                    outcome.rps(),
                    outcome.errors,
                    outcome.connections,
                    outcome.protocol
                );
            }
        }
        println!();
    }

    println!("# summary");
    for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
        for (index, (label, _)) in configurations.into_iter().enumerate() {
            println!(
                "c={concurrency:<4} {label:<28} {}  proto={}",
                Summary::of(&samples[index][slot]),
                protocols[index]
            );
        }
        println!();
    }

    let baseline = configurations.len() - 1;
    println!("# ratio against reqwest, paired within each round (>1 means Chromulate is faster)");
    for (slot, concurrency) in CONCURRENCY.iter().copied().enumerate() {
        for (index, (label, _)) in configurations.into_iter().enumerate() {
            if index == baseline {
                continue;
            }
            let ratios: Vec<f64> = samples[index][slot]
                .iter()
                .zip(&samples[baseline][slot])
                .map(|(mine, theirs)| mine / theirs)
                .collect();
            let summary = Summary::of(&ratios);
            println!(
                "c={concurrency:<4} {label:<28} median {:.3}x  (min {:.3}, max {:.3}, n={})",
                summary.median, summary.min, summary.max, summary.runs
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ChromulateDefault,
    ChromulateWidePool,
    Reqwest,
}

struct Outcome {
    ok: u64,
    errors: u64,
    elapsed: Duration,
    connections: u64,
    /// The HTTP version actually negotiated, so a run cannot silently fall back
    /// to HTTP/1.1 and be read as an HTTP/2 figure.
    protocol: &'static str,
}

impl Outcome {
    fn rps(&self) -> f64 {
        self.ok as f64 / self.elapsed.as_secs_f64()
    }
}

async fn run(
    kind: Kind,
    url: Arc<String>,
    certificate: Vec<u8>,
    concurrency: usize,
    warmup: Duration,
    measure: Duration,
    accepted: Arc<AtomicU64>,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let force_h1 = env::var("BENCH_H1").is_ok();

    match kind {
        Kind::Reqwest => {
            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                .add_root_certificate(reqwest::Certificate::from_der(&certificate)?)
                .pool_max_idle_per_host(WIDE_POOL)
                .tcp_nodelay(true);
            if force_h1 {
                builder = builder.http1_only();
            }
            let client = builder.build()?;
            let probe = client.get(url.as_str()).send().await?;
            let protocol = version_name(probe.version() == reqwest::Version::HTTP_2);
            drop(probe);

            let fetch = move |url: Arc<String>| {
                let client = client.clone();
                async move {
                    let response = client.get(url.as_str()).send().await.map_err(err)?;
                    response.bytes().await.map_err(err).map(|body| body.len())
                }
            };
            drive(url, concurrency, warmup, measure, accepted, protocol, fetch).await
        }
        _ => {
            // The facade has no trust-root setter of its own, so the engine is
            // built here and handed over whole.
            let profile = chromulate::Profile::chrome_stable();
            let tls = chromulate::tls::TlsEngine::builder(&profile)
                .add_root_certificate(rustls_pki_types::CertificateDer::from(certificate))
                .build()?;
            let mut builder = chromulate::Client::builder().tls(tls);
            if kind == Kind::ChromulateWidePool {
                builder = builder.pool(PoolConfig {
                    max_per_host: WIDE_POOL,
                    max_total: WIDE_POOL * 4,
                    ..PoolConfig::default()
                });
            }
            let client = builder.build()?;
            let probe = client.get(url.as_str()).send().await?;
            let protocol = version_name(probe.version() == chromulate::Version::HTTP_2);
            drop(probe);

            let fetch = move |url: Arc<String>| {
                let client = client.clone();
                async move {
                    let response = client.get(url.as_str()).send().await.map_err(err)?;
                    response.bytes().await.map_err(err).map(|body| body.len())
                }
            };
            drive(url, concurrency, warmup, measure, accepted, protocol, fetch).await
        }
    }
}

fn version_name(is_h2: bool) -> &'static str {
    if is_h2 { "h2" } else { "http/1.1" }
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
    protocol: &'static str,
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
    outcome.protocol = protocol;
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
            let mut first_error: Option<String> = None;
            while Instant::now() < deadline {
                match fetch(Arc::clone(&url)).await {
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
        protocol: "?",
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
