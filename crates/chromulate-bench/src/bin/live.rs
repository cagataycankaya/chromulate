//! Latency against a real HTTPS origin, Chromulate versus `reqwest`.
//!
//! Every other harness in this crate measures plaintext loopback, which is
//! deliberate — it isolates per-request client overhead — but it means the work
//! that distinguishes Chromulate never runs: no TLS handshake, no ALPN, no
//! HTTP/2. This one measures a real origin over the public internet, so the
//! handshake and the h2 path are included and the numbers describe what a
//! caller actually experiences.
//!
//! ```text
//! cargo run --release -p chromulate-bench --features live --bin live -- single <url>...
//! cargo run --release -p chromulate-bench --features live --bin live -- crawl <file>
//! cargo run --release -p chromulate-bench --features live --bin live -- links <url>
//! ```
//!
//! Two costs are reported separately because they answer different questions:
//!
//! - **cold** — a brand-new client per request: DNS, TCP, the TLS handshake, and
//!   one request. This is what a fresh process, or a crawler that opens a new
//!   connection per site, pays. Chromulate's ClientHello is larger than a plain
//!   client's, so if the browser identity costs anything on the wire it shows
//!   up here.
//! - **warm** — one client, repeated requests over its pooled connection. This
//!   is the per-request overhead the loopback harness measures, now with TLS
//!   records and HPACK in the picture.
//!
//! Rounds are interleaved and ratios are paired, for the reason given in
//! `benches/README.md`: on a network whose latency drifts minute to minute, a
//! ratio between two runs that saw the same conditions is worth far more than a
//! ratio between two means taken minutes apart.
//!
//! **This talks to somebody else's server.** Requests are paced (`LIVE_PACE_MS`,
//! default 500 ms) and the counts are small on purpose. Raise them and you are
//! load-testing a stranger's origin, which is neither polite nor a measurement
//! of your client.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use chromulate_bench::stats::Summary;

/// One measured request.
#[derive(Debug, Clone)]
struct Sample {
    /// Milliseconds until the response head was available.
    ttfb_ms: f64,
    /// Milliseconds until the body was fully read.
    total_ms: f64,
    /// Decoded body length.
    bytes: usize,
    /// HTTP status.
    status: u16,
    /// Whether the exchange ran over HTTP/2.
    http2: bool,
    /// What the origin said it encoded the body with, before the client
    /// decoded it. Two clients that negotiate different codings are not doing
    /// the same work, and the body sizes will not compare either.
    encoding: String,
}

/// What a client is called in the output.
const CHROMULATE: &str = "chromulate";
const CHROMULATE_NO_COOKIES: &str = "chromulate-nc";
const REQWEST: &str = "reqwest";

/// The clients under comparison.
///
/// The no-cookie Chromulate variant is here because it is the only way to tell
/// a slow client from an origin that answers a cookied request differently: the
/// two look identical in a latency number and have nothing in common as causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Chromulate,
    ChromulateNoCookies,
    Reqwest,
}

impl Kind {
    const ALL: [Self; 3] = [Self::Chromulate, Self::ChromulateNoCookies, Self::Reqwest];

    fn label(self) -> &'static str {
        match self {
            Self::Chromulate => CHROMULATE,
            Self::ChromulateNoCookies => CHROMULATE_NO_COOKIES,
            Self::Reqwest => REQWEST,
        }
    }
}

/// A built client of one kind, kept alive so its pool is reused.
enum AnyClient {
    Chromulate(chromulate::Client),
    Reqwest(reqwest::Client),
}

impl AnyClient {
    fn build(kind: Kind) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(match kind {
            Kind::Chromulate => Self::Chromulate(chromulate::Client::builder().build()?),
            Kind::ChromulateNoCookies => {
                Self::Chromulate(chromulate::Client::builder().cookie_store(false).build()?)
            }
            Kind::Reqwest => Self::Reqwest(reqwest_client()?),
        })
    }

    async fn fetch(&self, url: &str) -> Result<Sample, Box<dyn std::error::Error>> {
        match self {
            Self::Chromulate(client) => fetch_chromulate(client, url).await,
            Self::Reqwest(client) => fetch_reqwest(client, url).await,
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pace = Duration::from_millis(env_or("LIVE_PACE_MS", 500));
    let rounds = env_or("LIVE_ROUNDS", 5) as usize;
    let warm_requests = env_or("LIVE_WARM_REQUESTS", 3) as usize;

    match args.first().map(String::as_str) {
        Some("single") if args.len() > 1 => {
            for url in &args[1..] {
                single(url, rounds, warm_requests, pace).await?;
            }
            Ok(())
        }
        Some("crawl") if args.len() > 1 => {
            let listing = std::fs::read_to_string(&args[1])?;
            let urls: Vec<String> = listing
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("http"))
                .map(ToOwned::to_owned)
                .collect();
            let limit = args
                .get(2)
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(urls.len());
            crawl(&urls[..limit.min(urls.len())], pace).await
        }
        Some("links") if args.len() > 1 => links(&args[1]).await,
        Some("dump") if args.len() > 2 => dump(&args[1], &args[2]).await,
        Some("pool") if args.len() > 1 => pool_probe(&args[1], pace).await,
        _ => {
            eprintln!(
                "usage:\n  live single <url>...\n  live crawl <file-of-urls> [limit]\n  live links <category-url>\n\n\
                 environment: LIVE_PACE_MS (500), LIVE_ROUNDS (5), LIVE_WARM_REQUESTS (3)"
            );
            Err("no command".into())
        }
    }
}

fn env_or(name: &str, fallback: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

/// Builds a Chromulate client presenting the default Chrome profile.
fn chromulate_client() -> Result<chromulate::Client, Box<dyn std::error::Error>> {
    Ok(chromulate::Client::builder().build()?)
}

/// Builds the `reqwest` baseline.
///
/// Configured to do the same work Chromulate does: rustls against the platform
/// trust store, HTTP/2 available through ALPN, and the same four content
/// codings advertised and decoded. A baseline that skipped those would be
/// measuring less work, not a faster client.
fn reqwest_client() -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::builder().use_rustls_tls().build()?)
}

async fn fetch_chromulate(
    client: &chromulate::Client,
    url: &str,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let response = client.get(url).send().await?;
    let ttfb = started.elapsed();
    let status = response.status().as_u16();
    let http2 = response.version() == chromulate::Version::HTTP_2;
    let encoding = header_of(response.headers(), "content-encoding");
    let body = response.bytes().await?;
    Ok(Sample {
        ttfb_ms: ttfb.as_secs_f64() * 1000.0,
        total_ms: started.elapsed().as_secs_f64() * 1000.0,
        bytes: body.len(),
        status,
        http2,
        encoding,
    })
}

async fn fetch_reqwest(
    client: &reqwest::Client,
    url: &str,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let response = client.get(url).send().await?;
    let ttfb = started.elapsed();
    let status = response.status().as_u16();
    let http2 = response.version() == reqwest::Version::HTTP_2;
    let encoding = header_of(response.headers(), "content-encoding");
    let body = response.bytes().await?;
    Ok(Sample {
        ttfb_ms: ttfb.as_secs_f64() * 1000.0,
        total_ms: started.elapsed().as_secs_f64() * 1000.0,
        bytes: body.len(),
        status,
        http2,
        encoding,
    })
}

/// One header as a string, or `none` when the response did not carry it.
///
/// Both clients strip `Content-Encoding` once they have decoded the body, so an
/// empty answer here means the body arrived uncompressed rather than that the
/// client failed to report it.
fn header_of(headers: &chromulate::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("none")
        .to_owned()
}

/// Cold and warm latency for one URL.
async fn single(
    url: &str,
    rounds: usize,
    warm_requests: usize,
    pace: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n# {url}");
    println!(
        "# {rounds} interleaved rounds, {warm_requests} warm requests per round, \
         {} ms between requests",
        pace.as_millis()
    );

    let mut cold: Vec<Vec<Sample>> = vec![Vec::new(); Kind::ALL.len()];
    let mut warm: Vec<Vec<Sample>> = vec![Vec::new(); Kind::ALL.len()];

    for round in 1..=rounds {
        let mut cold_line = Vec::new();
        let mut warm_line = Vec::new();

        // One kind at a time, but all kinds inside one round: a slow patch on
        // the network or the origin then lands on every client rather than on
        // whichever happened to be running.
        for (slot, kind) in Kind::ALL.into_iter().enumerate() {
            // Cold: a fresh client, so DNS, TCP and the TLS handshake are all
            // inside the measurement.
            let client = AnyClient::build(kind)?;
            let sample = client.fetch(url).await?;
            tokio::time::sleep(pace).await;
            cold_line.push(format!("{} {:.0} ms", kind.label(), sample.total_ms));
            cold[slot].push(sample);
            drop(client);

            // Warm: one client, first request discarded as the warmup that
            // fills the pool.
            let client = AnyClient::build(kind)?;
            let _ = client.fetch(url).await?;
            tokio::time::sleep(pace).await;
            let mut samples = Vec::new();
            for _ in 0..warm_requests {
                samples.push(client.fetch(url).await?);
                tokio::time::sleep(pace).await;
            }
            let median =
                Summary::of(&samples.iter().map(|s| s.total_ms).collect::<Vec<_>>()).median;
            warm_line.push(format!("{} {median:.0} ms", kind.label()));
            warm[slot].extend(samples);
        }

        println!(
            "round {round}  cold: {}   warm median: {}",
            cold_line.join(" / "),
            warm_line.join(" / ")
        );
    }

    // What came back has to match, or the timings compare two different things.
    println!("\nfirst cold response per client:");
    for (slot, kind) in Kind::ALL.into_iter().enumerate() {
        let fact = &cold[slot][0];
        println!(
            "  {:<14} status={} http2={} encoding={:<5} bytes={}",
            kind.label(),
            fact.status,
            fact.http2,
            fact.encoding,
            fact.bytes
        );
    }
    let sizes: Vec<usize> = cold.iter().map(|samples| samples[0].bytes).collect();
    let smallest = sizes.iter().copied().min().unwrap_or(0);
    let largest = sizes.iter().copied().max().unwrap_or(0);
    if smallest > 0 && (largest - smallest) * 20 > largest {
        println!(
            "!! body sizes differ by more than 5% ({smallest}..{largest} bytes): the origin is \
             answering these clients differently, so the latencies below are not measuring the \
             same download"
        );
    }

    report_all("cold (DNS + TCP + TLS + one request)", &cold);
    report_all("warm (pooled connection)", &warm);
    Ok(())
}

/// Prints one section: per-client medians, then paired ratios against
/// `reqwest`, which is the baseline every ratio in this project is quoted
/// against.
fn report_all(label: &str, per_kind: &[Vec<Sample>]) {
    if per_kind.iter().any(Vec::is_empty) {
        return;
    }
    println!("\n## {label}");
    for (slot, kind) in Kind::ALL.into_iter().enumerate() {
        let samples = &per_kind[slot];
        let ttfb = Summary::of(&samples.iter().map(|s| s.ttfb_ms).collect::<Vec<_>>());
        let total = Summary::of(&samples.iter().map(|s| s.total_ms).collect::<Vec<_>>());
        let bytes = Summary::of(&samples.iter().map(|s| s.bytes as f64).collect::<Vec<_>>());
        // Body-size normalised, because an origin that serves two clients
        // different pages makes the raw total a comparison of two downloads.
        // `ttfb` is size-independent already; this is its counterpart for the
        // part of the time that is the body.
        let per_100k = Summary::of(
            &samples
                .iter()
                .map(|s| (s.total_ms - s.ttfb_ms) / (s.bytes.max(1) as f64 / 100_000.0))
                .collect::<Vec<_>>(),
        );
        println!(
            "{:<14} ttfb median {:>7.0} ms   total median {:>7.0} ms (min {:>6.0}, max {:>6.0})   \
             body {:>6.0} ms/100KB   median bytes {:>8.0}   n={}",
            kind.label(),
            ttfb.median,
            total.median,
            total.min,
            total.max,
            per_100k.median,
            bytes.median,
            total.runs
        );
    }

    let baseline = &per_kind[Kind::ALL
        .iter()
        .position(|k| *k == Kind::Reqwest)
        .unwrap_or(0)];
    for (slot, kind) in Kind::ALL.into_iter().enumerate() {
        if kind == Kind::Reqwest {
            continue;
        }
        let ratios: Vec<f64> = per_kind[slot]
            .iter()
            .zip(baseline.iter())
            .map(|(mine, theirs)| theirs.total_ms / mine.total_ms)
            .collect();
        if ratios.is_empty() {
            continue;
        }
        println!(
            "paired ratio {} vs {REQWEST} (>1 means {} is faster): median {:.3}x, n={}",
            kind.label(),
            kind.label(),
            Summary::of(&ratios).median,
            ratios.len()
        );
    }
}

/// Sequential crawl of many URLs through one warm client per side.
async fn crawl(urls: &[String], pace: Duration) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n# crawl of {} urls, {} ms between requests",
        urls.len(),
        pace.as_millis()
    );

    let chromulate = chromulate_client()?;
    let reqwest = reqwest_client()?;

    let mut paired = Paired::default();
    let mut chromulate_wall = Duration::ZERO;
    let mut reqwest_wall = Duration::ZERO;
    let mut failures = Vec::new();

    for (index, url) in urls.iter().enumerate() {
        // Interleaved per URL, so a slow patch on the network or the origin
        // lands on both clients rather than on whichever went first — and the
        // order alternates, because going second to the same URL can be the
        // easier job (a warmed cache, a primed origin) and a fixed order would
        // hand that advantage to the same client every time.
        let (a, b);
        if index % 2 == 0 {
            let started = Instant::now();
            a = fetch_chromulate(&chromulate, url).await;
            chromulate_wall += started.elapsed();
            tokio::time::sleep(pace).await;

            let started = Instant::now();
            b = fetch_reqwest(&reqwest, url).await;
            reqwest_wall += started.elapsed();
            tokio::time::sleep(pace).await;
        } else {
            let started = Instant::now();
            b = fetch_reqwest(&reqwest, url).await;
            reqwest_wall += started.elapsed();
            tokio::time::sleep(pace).await;

            let started = Instant::now();
            a = fetch_chromulate(&chromulate, url).await;
            chromulate_wall += started.elapsed();
            tokio::time::sleep(pace).await;
        }

        match (a, b) {
            (Ok(a), Ok(b)) => {
                if a.status != b.status {
                    failures.push(format!(
                        "{url}: {CHROMULATE} {} vs {REQWEST} {}",
                        a.status, b.status
                    ));
                }
                println!(
                    "{:>3}. {CHROMULATE} {:>6.0} ms {:>3} {:>7} B   {REQWEST} {:>6.0} ms {:>3} {:>7} B   {}",
                    index + 1,
                    a.total_ms,
                    a.status,
                    a.bytes,
                    b.total_ms,
                    b.status,
                    b.bytes,
                    short(url),
                );
                paired.push(a, b);
            }
            (a, b) => {
                let describe = |result: &Result<Sample, Box<dyn std::error::Error>>| match result {
                    Ok(sample) => format!("{}", sample.status),
                    Err(error) => format!("ERROR {error}"),
                };
                failures.push(format!(
                    "{url}: {CHROMULATE} {} vs {REQWEST} {}",
                    describe(&a),
                    describe(&b)
                ));
                println!("{:>3}. FAILED {}", index + 1, short(url));
            }
        }
    }

    println!(
        "\nwall clock excluding pacing: {CHROMULATE} {:.1} s   {REQWEST} {:.1} s",
        chromulate_wall.as_secs_f64(),
        reqwest_wall.as_secs_f64()
    );
    paired.report("per url");

    if failures.is_empty() {
        println!("\nno disagreements: both clients got the same status for every url");
    } else {
        println!("\ndisagreements ({}):", failures.len());
        for failure in &failures {
            println!("  {failure}");
        }
    }
    Ok(())
}

/// Reports what the connection pool holds after each of several requests.
///
/// A latency number cannot tell "the client is slow" from "the client is
/// opening a fresh connection every time"; the pool's own count can. Against an
/// HTTPS origin that negotiates HTTP/2 this is the direct observation of
/// whether the connection is being reused at all.
async fn pool_probe(url: &str, pace: Duration) -> Result<(), Box<dyn std::error::Error>> {
    use chromulate::engine::{Engine, EngineConfig, Pool, PoolConfig};

    let profile = std::sync::Arc::new(chromulate::Profile::chrome_stable());
    let pool = Pool::new(PoolConfig::default());
    let engine = Engine::builder(EngineConfig::new(profile))
        .pool(pool.clone())
        .build()?;

    println!("# {url}");
    println!(
        "# pool holds {} connections before the first request",
        pool.len()
    );
    for attempt in 1..=4 {
        let started = Instant::now();
        let response = engine
            .send(
                http::Request::builder()
                    .uri(url)
                    .body(chromulate::Body::empty())?,
            )
            .await?;
        let version = response.version();
        let status = response.status();
        let body = response.into_body().collect(64 * 1024 * 1024).await?;
        println!(
            "request {attempt}: {status} {version:?} {:>7} bytes in {:>6.0} ms -> pool holds {}",
            body.len(),
            started.elapsed().as_secs_f64() * 1000.0,
            pool.len()
        );
        tokio::time::sleep(pace).await;
    }
    println!(
        "\nA pool that holds 0 after a request means the connection was not kept: every request \
         pays a fresh TCP connection and TLS handshake."
    );
    Ok(())
}

/// Writes each client's body for one URL to `<prefix>-<client>.html`.
///
/// When two clients report different body sizes for the same URL, the timings
/// are comparing two different downloads, and no amount of re-running fixes
/// that. This is how to find out what actually differs.
async fn dump(url: &str, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    for kind in Kind::ALL {
        let client = AnyClient::build(kind)?;
        let body = match &client {
            AnyClient::Chromulate(client) => client.get(url).send().await?.text().await?,
            AnyClient::Reqwest(client) => client.get(url).send().await?.text().await?,
        };
        let path = format!("{prefix}-{}.html", kind.label());
        std::fs::write(&path, &body)?;
        println!("{:<14} {:>8} bytes -> {path}", kind.label(), body.len());
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

/// Prints the product links a category page carries.
///
/// A category listing is the natural source of a bulk URL set, and pulling it
/// through Chromulate itself is also a test: a page that comes back empty, or
/// carries no links, is a finding about the client rather than an inconvenience.
async fn links(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = chromulate_client()?;
    let response = client.get(url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    eprintln!("# {url} -> {status}, {} bytes", body.len());

    // Product URLs on this listing look like `/brand/slug-p-123456`. Matching on
    // the `-p-<digits>` suffix rather than on any markup keeps this independent
    // of how the page is rendered.
    let mut seen = Vec::new();
    let mut rest = body.as_str();
    while let Some(start) = rest.find("\"/") {
        let after = &rest[start + 1..];
        let end = after.find(['"', '\\']).unwrap_or(after.len().min(300));
        let candidate = &after[..end];
        rest = &after[end.max(1)..];

        if !is_product_path(candidate) {
            continue;
        }
        let absolute = format!("https://www.trendyol.com{candidate}");
        if !seen.contains(&absolute) {
            seen.push(absolute);
        }
    }

    for link in &seen {
        println!("{link}");
    }
    eprintln!("# {} distinct product links", seen.len());
    Ok(())
}

/// Whether a path looks like a product page: `…-p-<digits>`, optionally with a
/// query string.
fn is_product_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let Some((prefix, tail)) = path.rsplit_once("-p-") else {
        return false;
    };
    !prefix.is_empty()
        && !tail.is_empty()
        && tail.chars().all(|character| character.is_ascii_digit())
}

fn short(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

/// Paired samples from the two clients, kept so ratios compare runs that saw
/// the same network rather than two means taken minutes apart.
#[derive(Default)]
struct Paired {
    chromulate: Vec<Sample>,
    reqwest: Vec<Sample>,
    /// One reqwest-over-chromulate ratio per pair. Above 1 means Chromulate was
    /// faster on that pair.
    ratios: Vec<f64>,
    ttfb_ratios: Vec<f64>,
}

impl Paired {
    fn push(&mut self, chromulate: Sample, reqwest: Sample) {
        self.ratios.push(reqwest.total_ms / chromulate.total_ms);
        self.ttfb_ratios.push(reqwest.ttfb_ms / chromulate.ttfb_ms);
        self.chromulate.push(chromulate);
        self.reqwest.push(reqwest);
    }

    fn report(&self, label: &str) {
        if self.chromulate.is_empty() {
            return;
        }
        let field = |samples: &[Sample], pick: fn(&Sample) -> f64| {
            Summary::of(&samples.iter().map(pick).collect::<Vec<_>>())
        };

        println!("\n## {label}");
        for (name, samples) in [(CHROMULATE, &self.chromulate), (REQWEST, &self.reqwest)] {
            let ttfb = field(samples, |sample| sample.ttfb_ms);
            let total = field(samples, |sample| sample.total_ms);
            println!(
                "{name:<11} ttfb median {:>7.0} ms (min {:>6.0}, max {:>6.0})   \
                 total median {:>7.0} ms (min {:>6.0}, max {:>6.0})   n={}",
                ttfb.median, ttfb.min, ttfb.max, total.median, total.min, total.max, total.runs
            );
        }
        let total = Summary::of(&self.ratios);
        let ttfb = Summary::of(&self.ttfb_ratios);
        println!(
            "paired ratio (>1 means chromulate is faster): total median {:.3}x, ttfb median {:.3}x, n={}",
            total.median, ttfb.median, total.runs
        );
    }
}
