//! A steady load of Chromulate requests, for a sampling profiler to attach to.
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin profile -- [seconds] [concurrency]
//! ```
//!
//! The other harnesses interleave several clients in one process, which is what
//! makes their *ratios* trustworthy and their *profiles* useless: a sample taken
//! during an `e2e` run attributes time to whichever client happened to be
//! running. This one drives Chromulate and nothing else, against the same
//! loopback origin, so a profiler's call tree describes this crate.
//!
//! It prints its own pid and then runs until the deadline, so the sampler can be
//! pointed at it:
//!
//! ```text
//! ./target/release/profile 20 &
//! sample $! 10 -file /tmp/chromulate.sample
//! ```
//!
//! Plaintext HTTP/1.1 on purpose. A profile taken over TLS is dominated by the
//! handshake and the record layer, which are `rustls`'s code rather than this
//! crate's, and the question this exists to answer — where does Chromulate's own
//! per-request CPU go — is exactly the one that would drown in it.

#![forbid(unsafe_code)]

use std::env;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromulate_bench::server;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let seconds = args
        .first()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20u64);
    let concurrency = args
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(64usize);

    let origin = server::start(4)?;
    let url = Arc::new(origin.url("/"));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("profile-client")
        .enable_all()
        .build()?;

    println!("pid {}", process::id());
    println!("driving {concurrency} concurrent requests at {url} for {seconds}s");

    let completed = runtime.block_on(async move {
        // `PROFILE_NO_COOKIES` turns the jar off, which is how the cookie
        // jar's share of lock contention is attributed by experiment rather
        // than by reading a call graph and guessing.
        let mut builder = chromulate::Client::builder();
        if env::var("PROFILE_NO_COOKIES").is_ok() {
            builder = builder.cookie_store(false);
        }
        let client = builder.build()?;
        let deadline = Instant::now() + Duration::from_secs(seconds);

        let mut workers = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let client = client.clone();
            let url = Arc::clone(&url);
            workers.push(tokio::spawn(async move {
                let mut done = 0u64;
                while Instant::now() < deadline {
                    if let Ok(response) = client.get(url.as_str()).send().await
                        && response.bytes().await.is_ok()
                    {
                        done += 1;
                    }
                }
                done
            }));
        }

        let mut total = 0u64;
        for worker in workers {
            total += worker.await?;
        }
        Ok::<u64, Box<dyn std::error::Error>>(total)
    })?;

    println!("completed {completed} requests");
    Ok(())
}
