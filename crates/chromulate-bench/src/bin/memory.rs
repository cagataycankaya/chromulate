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
        Some("idle") => idle(),
        Some("pool") => {
            let connections: usize = args.get(1).map_or(Ok(1), |raw| raw.parse())?;
            pool(connections)
        }
        Some("stream") => big_body(false),
        Some("buffer") => big_body(true),
        other => {
            eprintln!("unknown phase {other:?}; expected idle | pool N | stream | buffer");
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
