//! Allocations on the request path, counted rather than claimed.
//!
//! The design documents describe Chromulate as a low-allocation client. A
//! counting global allocator is the only thing that can substantiate or refute
//! that, so this binary installs one and brackets a single request with it.
//!
//! The counters are **thread-local**. The client runs on a current-thread tokio
//! runtime pinned to the main thread, and the loopback server runs on its own
//! runtime with its own threads, so the server's allocations are not counted.
//! A process-wide counter would have folded the two together and reported a
//! number that belongs to neither.
//!
//! Three regimes are reported, because they answer different questions:
//!
//! - the **first** request, which pays for DNS, the TCP connect and the HTTP/1.1
//!   handshake;
//! - the **second** request, the first to run against a pooled connection;
//! - the **steady state**, averaged over a hundred pooled requests.
//!
//! `reqwest` is measured the same way in the same process, because "N
//! allocations per request" only means something next to what the alternative
//! costs.
//!
//! Run with:
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin allocs
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use chromulate_bench::server;
use chromulate_bench::stats::Summary;
use chromulate_http::PoolConfig;

#[global_allocator]
static COUNTER: Counting = Counting;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<u64> = const { Cell::new(0) };
    static REALLOCS: Cell<u64> = const { Cell::new(0) };
    static DEALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// A pass-through allocator that tallies calls on the calling thread.
///
/// `try_with` rather than `with`: a thread-local may be accessed while it is
/// being destroyed during thread teardown, and a panic inside the global
/// allocator aborts the process.
struct Counting;

// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract, and the counters touch no allocator
// state. The thread-locals are const-initialised, so reading them cannot
// allocate and cannot re-enter this allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        let _ = ALLOC_BYTES.try_with(|c| c.set(c.get() + layout.size() as u64));
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        let _ = ALLOC_BYTES.try_with(|c| c.set(c.get() + layout.size() as u64));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = DEALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = REALLOCS.try_with(|c| c.set(c.get() + 1));
        if new_size > layout.size() {
            let grew = (new_size - layout.size()) as u64;
            let _ = ALLOC_BYTES.try_with(|c| c.set(c.get() + grew));
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    allocs: u64,
    reallocs: u64,
    deallocs: u64,
    bytes: u64,
}

impl Counts {
    fn read() -> Self {
        Self {
            allocs: ALLOCS.with(Cell::get),
            reallocs: REALLOCS.with(Cell::get),
            deallocs: DEALLOCS.with(Cell::get),
            bytes: ALLOC_BYTES.with(Cell::get),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            allocs: self.allocs - before.allocs,
            reallocs: self.reallocs - before.reallocs,
            deallocs: self.deallocs - before.deallocs,
            bytes: self.bytes - before.bytes,
        }
    }

    fn per(self, requests: u64) -> (f64, f64, f64, f64) {
        let n = requests as f64;
        (
            self.allocs as f64 / n,
            self.reallocs as f64 / n,
            self.deallocs as f64 / n,
            self.bytes as f64 / n,
        )
    }
}

/// Requests averaged for the steady-state figure.
const STEADY: u64 = 100;

/// Repeats of the whole measurement.
const REPEATS: usize = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = server::start(2)?;
    let url = Arc::new(origin.url("/"));

    println!("# allocations on the request path");
    println!(
        "# counters are thread-local; the loopback server runs on its own threads and is excluded"
    );
    println!(
        "# body {} bytes, HTTP/1.1 plaintext",
        server::SMALL_BODY_LEN
    );
    println!();

    let mut chromulate_first = Vec::new();
    let mut chromulate_second = Vec::new();
    let mut chromulate_steady = Vec::new();
    let mut chromulate_bytes = Vec::new();
    let mut reqwest_first = Vec::new();
    let mut reqwest_second = Vec::new();
    let mut reqwest_steady = Vec::new();
    let mut reqwest_bytes = Vec::new();

    for _ in 0..REPEATS {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let (first, second, steady) = runtime.block_on(measure_chromulate(Arc::clone(&url)))?;
        chromulate_first.push(first.allocs as f64);
        chromulate_second.push(second.allocs as f64);
        chromulate_steady.push(steady.per(STEADY).0);
        chromulate_bytes.push(steady.per(STEADY).3);

        let (first, second, steady) = runtime.block_on(measure_reqwest(Arc::clone(&url)))?;
        reqwest_first.push(first.allocs as f64);
        reqwest_second.push(second.allocs as f64);
        reqwest_steady.push(steady.per(STEADY).0);
        reqwest_bytes.push(steady.per(STEADY).3);
    }

    report(
        "chromulate",
        "first request (connect + handshake)",
        &chromulate_first,
    );
    report("chromulate", "second request (pooled)", &chromulate_second);
    report(
        "chromulate",
        "steady state, per request",
        &chromulate_steady,
    );
    report(
        "chromulate",
        "steady state, bytes per request",
        &chromulate_bytes,
    );
    println!();
    report(
        "reqwest",
        "first request (connect + handshake)",
        &reqwest_first,
    );
    report("reqwest", "second request (pooled)", &reqwest_second);
    report("reqwest", "steady state, per request", &reqwest_steady);
    report("reqwest", "steady state, bytes per request", &reqwest_bytes);

    println!();
    let ratio = Summary::of(&chromulate_steady).mean / Summary::of(&reqwest_steady).mean;
    println!("steady-state allocation ratio, chromulate / reqwest: {ratio:.2}x");

    println!();
    println!("# where they go: pieces of the request path measured on their own");
    components(&url)?;

    Ok(())
}

/// Attributes part of the per-request total to individual steps.
///
/// These do not sum to the total — the engine, hyper and the response path are
/// not broken out — but they are enough to say whether the request-assembly
/// side is a rounding error or a real share of the cost.
fn components(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use chromulate_core::{CookieContext, CookieStore};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _guard = runtime.enter();

    let client = chromulate::Client::chrome()?;
    let parsed = url::Url::parse(url)?;
    let context = CookieContext::conservative_default();

    // Warm anything lazily initialised so the first call is not the one
    // measured.
    let _ = client.get(url).build()?;
    let _ = client
        .cookies()
        .map(|jar| jar.cookies_for(&parsed, &context));

    let measure = |what: &str, mut body: Box<dyn FnMut()>| {
        const ROUNDS: u64 = 1000;
        let before = Counts::read();
        for _ in 0..ROUNDS {
            body();
        }
        let delta = Counts::read().since(before);
        let (allocs, _, _, bytes) = delta.per(ROUNDS);
        println!("  {what:<44} {allocs:>6.1} allocs  {bytes:>8.0} bytes");
    };

    measure(
        "url::Url::parse(url)",
        Box::new(|| {
            let _ = std::hint::black_box(url::Url::parse(url));
        }),
    );

    {
        let client = client.clone();
        measure(
            "RequestBuilder::build (assembly, no send)",
            Box::new(move || {
                let _ = std::hint::black_box(client.get(url).build());
            }),
        );
    }

    {
        let request = client.get(url).build()?;
        measure(
            "send()'s Url::parse(uri.to_string()) round-trip",
            Box::new(move || {
                let _ = std::hint::black_box(url::Url::parse(&request.uri().to_string()));
            }),
        );
    }

    {
        use chromulate_core::{Body, RequestOptions};
        use chromulate_header::{AcceptChStore, HeaderEngine};

        let engine = HeaderEngine::new(std::sync::Arc::new(
            chromulate_profile::Profile::chrome_stable(),
        ));
        let store = AcceptChStore::new();
        let options = RequestOptions::navigation();
        let target = parsed.clone();
        measure(
            "HeaderEngine::apply (navigation)",
            Box::new(move || {
                let mut request = chromulate_core::Request::new(Body::empty());
                let _ = std::hint::black_box(engine.apply(&mut request, &target, &options, &store));
            }),
        );
    }

    if let Some(jar) = client.cookies().cloned() {
        let parsed = parsed.clone();
        measure(
            "Jar::cookies_for (empty jar)",
            Box::new(move || {
                let _ = std::hint::black_box(jar.cookies_for(&parsed, &context));
            }),
        );
    }

    Ok(())
}

fn report(client: &str, what: &str, samples: &[f64]) {
    println!("{client:<11} {what:<38} {}", Summary::of(samples));
}

async fn measure_chromulate(
    url: Arc<String>,
) -> Result<(Counts, Counts, Counts), Box<dyn std::error::Error>> {
    let client = chromulate::Client::builder()
        .pool(PoolConfig {
            max_per_host: 8,
            ..PoolConfig::default()
        })
        .build()?;

    let before = Counts::read();
    let _ = client.get(url.as_str()).send().await?.bytes().await?;
    let after_first = Counts::read();

    let _ = client.get(url.as_str()).send().await?.bytes().await?;
    let after_second = Counts::read();

    for _ in 0..STEADY {
        let _ = client.get(url.as_str()).send().await?.bytes().await?;
    }
    let after_steady = Counts::read();

    Ok((
        after_first.since(before),
        after_second.since(after_first),
        after_steady.since(after_second),
    ))
}

async fn measure_reqwest(
    url: Arc<String>,
) -> Result<(Counts, Counts, Counts), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(8)
        .tcp_nodelay(true)
        .build()?;

    let before = Counts::read();
    let _ = client.get(url.as_str()).send().await?.bytes().await?;
    let after_first = Counts::read();

    let _ = client.get(url.as_str()).send().await?.bytes().await?;
    let after_second = Counts::read();

    for _ in 0..STEADY {
        let _ = client.get(url.as_str()).send().await?.bytes().await?;
    }
    let after_steady = Counts::read();

    Ok((
        after_first.since(before),
        after_second.since(after_first),
        after_steady.since(after_second),
    ))
}
