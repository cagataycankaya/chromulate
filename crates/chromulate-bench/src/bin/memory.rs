//! Resident memory: an idle client, a client holding pooled connections, and
//! the peak while a large response streams through.
//!
//! The README claims streaming is constant-memory. That is a correctness claim,
//! not a performance one, so it gets a measurement with a **control**: the same
//! 256 MB body is also read with `Response::bytes`, which is supposed to buffer.
//! If the streaming peak is flat but the buffering peak is flat too, the
//! measurement is blind and neither number means anything.
//!
//! The origin server runs in a **child process**. In one process, 512 pooled
//! client connections would be measured together with the 512 server-side
//! connections holding them open, and the resulting number would belong to
//! neither side.
//!
//! Run one phase at a time, because resident memory never comes back down
//! cleanly within a process:
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin memory -- idle
//! cargo run --release -p chromulate-bench --bin memory -- pool 64
//! cargo run --release -p chromulate-bench --bin memory -- stream
//! cargo run --release -p chromulate-bench --bin memory -- buffer
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use chromulate_bench::{resident_kib, server};
use chromulate_http::PoolConfig;
use futures_util::StreamExt as _;

/// Body size for the streaming and buffering phases.
const BIG_BODY: u64 = 256 * 1024 * 1024;

/// How often the streaming phase samples resident memory, in bytes consumed.
const SAMPLE_EVERY: u64 = 8 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("serve-many") => {
            let count: usize = args.get(1).map_or(Ok(1), |raw| raw.parse())?;
            serve_many(count)
        }
        Some("idle") => idle(),
        Some("pool") => {
            let connections: usize = args.get(1).map_or(Ok(1), |raw| raw.parse())?;
            pool(connections)
        }
        Some("stream") => big_body(false),
        Some("buffer") => big_body(true),
        Some("soak") => {
            let seconds: u64 = args.get(1).map_or(Ok(120), |raw| raw.parse())?;
            soak(seconds)
        }
        other => {
            eprintln!(
                "unknown phase {other:?}; expected idle | pool N | stream | buffer | soak [seconds]"
            );
            std::process::exit(2);
        }
    }
}

fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let origin = server::start(4)?;
    println!("PORT {}", origin.addr().port());
    // The parent kills this process when it is done with it.
    loop {
        std::thread::park();
    }
}

fn serve_many(count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let origins = server::start_many(count, 4)?;
    let ports: Vec<String> = origins
        .urls("/")
        .iter()
        .filter_map(|url| {
            url.rsplit(':')
                .next()
                .map(|tail| tail.trim_end_matches('/').to_owned())
        })
        .collect();
    println!("PORTS {}", ports.join(","));
    loop {
        std::thread::park();
    }
}

/// Several origins in a child process, killed on drop.
///
/// The soak phase needs this for the same reason the pooled phase does: the
/// growth it looks for is a few megabytes per minute, and a server sharing the
/// process would contribute its own connection buffers to exactly the number
/// under examination. Measuring both together and calling the total a client
/// leak is the mistake this exists to prevent — and it was made once, which is
/// why this comment is here.
#[derive(Debug)]
struct Origins {
    child: Child,
    ports: Vec<u16>,
}

impl Origins {
    fn spawn(count: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(env::current_exe()?)
            .arg("serve-many")
            .arg(count.to_string())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("child produced no stdout")?;
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line)?;
        let ports = line
            .trim()
            .strip_prefix("PORTS ")
            .ok_or("child did not announce its ports")?
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<u16>, _>>()?;
        Ok(Self { child, ports })
    }

    fn urls(&self) -> Vec<String> {
        self.ports
            .iter()
            .map(|port| format!("http://127.0.0.1:{port}/"))
            .collect()
    }
}

impl Drop for Origins {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A child process running the origin server, killed on drop.
#[derive(Debug)]
struct Origin {
    child: Child,
    port: u16,
}

impl Origin {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(env::current_exe()?)
            .arg("serve")
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("child produced no stdout")?;
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line)?;
        let port = line
            .trim()
            .strip_prefix("PORT ")
            .ok_or("child did not announce a port")?
            .parse()?;
        Ok(Self { child, port })
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn rss() -> u64 {
    resident_kib().unwrap_or(0)
}

fn mib(kib: u64) -> f64 {
    kib as f64 / 1024.0
}

fn idle() -> Result<(), Box<dyn std::error::Error>> {
    let floor = rss();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let with_runtime = rss();

    let client = chromulate::Client::chrome()?;
    let with_client = rss();

    let reqwest_client = reqwest::Client::builder().build()?;
    let with_reqwest = rss();

    println!("phase=idle");
    println!("process_floor_mib={:.2}", mib(floor));
    println!(
        "tokio_runtime_mib={:.2} (delta {:.2})",
        mib(with_runtime),
        mib(with_runtime.saturating_sub(floor))
    );
    println!(
        "chromulate_client_mib={:.2} (delta {:.2})",
        mib(with_client),
        mib(with_client.saturating_sub(with_runtime))
    );
    println!(
        "reqwest_client_mib={:.2} (delta {:.2})",
        mib(with_reqwest),
        mib(with_reqwest.saturating_sub(with_client))
    );

    drop(client);
    drop(reqwest_client);
    drop(runtime);
    Ok(())
}

fn pool(connections: usize) -> Result<(), Box<dyn std::error::Error>> {
    let origin = Origin::spawn()?;
    // `BENCH_POOL_BODY` sets how many bytes each connection downloads before
    // idling in the pool. The default 1 KiB body never grows hyper's adaptive
    // read buffer, so the retained-buffer cost this phase exists to expose
    // stays invisible; a multi-megabyte body grows every connection's buffer
    // to its ceiling first, which is the state a crawler's pool is really in.
    let path = std::env::var("BENCH_POOL_BODY")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or_else(|| "/".to_owned(), |bytes| format!("/big/{bytes}"));
    let url = Arc::new(origin.url(&path));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    // `BENCH_H1_MAX_BUF` bounds hyper's per-connection h1 buffers, so the
    // pooled phase can measure what `PoolConfig::http1_max_buf_size` is worth;
    // unset means hyper's default, which is what the baseline recorded.
    let http1_max_buf_size = std::env::var("BENCH_H1_MAX_BUF")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());

    let baseline = rss();
    let client = chromulate::Client::builder()
        .pool(PoolConfig {
            max_per_host: connections.max(1),
            max_total: connections.max(1) * 2,
            http1_max_buf_size,
            ..PoolConfig::default()
        })
        .build()?;
    let built = rss();

    // `connections` requests in flight at once force that many sockets open;
    // when they finish the pool retains them, because `max_per_host` was set to
    // exactly that number.
    runtime
        .block_on(async {
            let mut tasks = Vec::with_capacity(connections);
            for _ in 0..connections {
                let client = client.clone();
                let url = Arc::clone(&url);
                tasks.push(tokio::spawn(async move {
                    client
                        .get(url.as_str())
                        .send()
                        .await
                        .map_err(|error| error.to_string())?
                        .bytes()
                        .await
                        .map_err(|error| error.to_string())
                }));
            }
            for task in tasks {
                task.await.map_err(|error| error.to_string())??;
            }
            Ok::<_, String>(())
        })
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    let pooled = rss();

    println!("phase=pool connections={connections}");
    println!("baseline_mib={:.2}", mib(baseline));
    println!(
        "client_built_mib={:.2} (delta {:.2})",
        mib(built),
        mib(built.saturating_sub(baseline))
    );
    println!(
        "pooled_mib={:.2} (delta {:.2})",
        mib(pooled),
        mib(pooled.saturating_sub(built))
    );
    println!(
        "kib_per_connection={:.1}",
        pooled.saturating_sub(built) as f64 / connections.max(1) as f64
    );

    drop(client);
    drop(runtime);
    Ok(())
}

fn big_body(buffer: bool) -> Result<(), Box<dyn std::error::Error>> {
    let origin = Origin::spawn()?;
    let url = origin.url(&format!("/big/{BIG_BODY}"));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    let client = chromulate::Client::builder()
        .max_response_size(BIG_BODY * 2)
        .build()?;

    let baseline = rss();
    let (read, peak) = runtime.block_on(async {
        let response = client.get(&url).send().await?;
        if buffer {
            let bytes = response.bytes().await?;
            Ok::<_, Box<dyn std::error::Error>>((bytes.len() as u64, rss()))
        } else {
            let mut stream = response.bytes_stream();
            let mut read = 0u64;
            let mut next_sample = SAMPLE_EVERY;
            let mut peak = rss();
            while let Some(chunk) = stream.next().await {
                read += chunk?.len() as u64;
                if read >= next_sample {
                    peak = peak.max(rss());
                    next_sample += SAMPLE_EVERY;
                }
            }
            Ok((read, peak.max(rss())))
        }
    })?;

    println!(
        "phase={}",
        if buffer { "buffer (control)" } else { "stream" }
    );
    println!("body_mib={:.2}", mib(read / 1024));
    println!("baseline_mib={:.2}", mib(baseline));
    println!(
        "peak_mib={:.2} (delta {:.2})",
        mib(peak),
        mib(peak.saturating_sub(baseline))
    );

    drop(client);
    drop(runtime);
    Ok(())
}

/// Sustained load with resident memory sampled over time.
///
/// Every other phase here is a point measurement: build a client, do a fixed
/// amount of work, read RSS once. None of them would notice a leak, because a
/// leak is a *slope*, and a single point has none. This runs a steady request
/// loop for `seconds` and prints RSS each interval, so the shape can be read
/// rather than inferred.
///
/// Three things are deliberately exercised at once, because they are the state
/// a long-running crawler accumulates and each is a plausible leak site: pooled
/// connections across many origins, a cookie jar taking `Set-Cookie` on every
/// response, and the `Accept-CH` store. The origins are separate so pool and
/// jar keys grow rather than being overwritten.
fn soak(seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    const ORIGINS: usize = 24;
    const CONCURRENCY: usize = 16;

    let origins = Origins::spawn(ORIGINS)?;
    let urls: Vec<String> = origins.urls();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    let client = chromulate::Client::builder().build()?;
    let baseline = rss();

    println!("phase=soak seconds={seconds} origins={ORIGINS} concurrency={CONCURRENCY}");
    println!("baseline_mib={:.2}", mib(baseline));
    println!("# elapsed_s  rss_mib  delta_mib  requests");

    let completed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let urls = std::sync::Arc::new(urls);

    runtime.block_on(async {
        let mut workers = Vec::with_capacity(CONCURRENCY);
        for worker in 0..CONCURRENCY {
            let client = client.clone();
            let urls = std::sync::Arc::clone(&urls);
            let completed = std::sync::Arc::clone(&completed);
            workers.push(tokio::spawn(async move {
                let mut next = worker;
                while std::time::Instant::now() < deadline {
                    let url = &urls[next % urls.len()];
                    next += 1;
                    if let Ok(response) = client.get(url).send().await
                        && response.bytes().await.is_ok()
                    {
                        completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }

        let started = std::time::Instant::now();
        let mut samples: Vec<(u64, u64)> = Vec::new();
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let elapsed = started.elapsed().as_secs();
            let current = rss();
            samples.push((elapsed, current));
            println!(
                "{elapsed:>10}  {:>7.2}  {:>9.2}  {}",
                mib(current),
                mib(current.saturating_sub(baseline)),
                completed.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        for worker in workers {
            let _ = worker.await;
        }

        // The verdict is the slope over the second half: startup allocates
        // pools and buffers that never come back, and counting that as a leak
        // would make every run look like one.
        if samples.len() >= 4 {
            let half = samples.len() / 2;
            let (first_t, first_rss) = samples[half];
            let (last_t, last_rss) = samples[samples.len() - 1];
            let minutes = (last_t.saturating_sub(first_t)) as f64 / 60.0;
            let growth = mib(last_rss.saturating_sub(first_rss));
            println!();
            println!(
                "second-half growth: {growth:.2} MiB over {minutes:.1} min \
                 ({:.2} MiB/min)",
                if minutes > 0.0 { growth / minutes } else { 0.0 }
            );
            println!(
                "requests completed: {}",
                completed.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
    });

    drop(client);
    drop(runtime);
    Ok(())
}
