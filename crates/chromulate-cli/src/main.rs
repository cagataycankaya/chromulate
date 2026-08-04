//! `chromulate` — a command-line client for inspecting what Chromulate puts on
//! the wire.
//!
//! The `fingerprint` subcommand is the reason this binary exists: it prints the
//! identity a profile targets *and* the parts of that identity this build
//! cannot actually send, so the project's central claim is checkable from a
//! shell rather than only from a test.

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromulate::engine::UnsupportedSetting;
use chromulate::header::{HeaderName, HeaderValue};
use chromulate::{Client, Method, Profile, ProfileRegistry, RedirectPolicy, RequestOptions};
use clap::{Args, Parser, Subcommand};

/// Success.
const EXIT_OK: u8 = 0;
/// The request itself failed.
const EXIT_REQUEST_FAILED: u8 = 1;
/// The command line was wrong, or named something that does not exist.
const EXIT_USAGE: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "chromulate",
    version,
    about = "A browser-grade HTTP client and fingerprint inspector"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Perform a request.
    Get(GetArgs),
    /// Print the JA3, JA4 and Akamai HTTP/2 fingerprints a profile targets.
    Fingerprint(FingerprintArgs),
    /// List the profiles this build ships.
    Profiles,
}

#[derive(Debug, Args)]
struct GetArgs {
    /// The URL to request.
    url: String,

    /// Add a request header, as `Name: value`. May be repeated.
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,

    /// Send a request body. Implies `POST` unless `--method` says otherwise.
    #[arg(short = 'd', long = "data", value_name = "BODY")]
    data: Option<String>,

    /// The HTTP method.
    #[arg(short = 'X', long = "method", value_name = "METHOD")]
    method: Option<String>,

    /// The browser profile to present.
    #[arg(long, default_value = "chrome", value_name = "NAME")]
    profile: String,

    /// Route through a proxy, for example `socks5h://127.0.0.1:1080`.
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Write the body to a file instead of standard output.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: Option<String>,

    /// Print the request and response headers, and the identity report.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Print one JSON object instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Give up after this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,

    /// Return the 3xx instead of following it.
    #[arg(long)]
    no_redirect: bool,

    /// Send as a programmatic `fetch()` rather than as a navigation.
    ///
    /// Fetching a URL from a shell is a top-level navigation — the same thing a
    /// browser does for a typed address — so that is the default. It decides
    /// `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, the `Accept` value, and whether
    /// `Upgrade-Insecure-Requests` is sent, all of which a server can see.
    #[arg(long)]
    fetch: bool,
}

#[derive(Debug, Args)]
struct FingerprintArgs {
    /// The profile to report on.
    #[arg(long, default_value = "chrome", value_name = "NAME")]
    profile: String,

    /// Print one JSON object instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let code = match cli.command {
        Command::Get(args) => run_get(args).await,
        Command::Fingerprint(args) => run_fingerprint(&args),
        Command::Profiles => run_profiles(),
    };

    ExitCode::from(code)
}

/// Looks a profile up, reporting what is available when it is not found.
fn load_profile(name: &str) -> Result<Arc<Profile>, String> {
    ProfileRegistry::with_builtin()
        .require(name)
        .map_err(|error| error.to_string())
}

fn run_profiles() -> u8 {
    let registry = ProfileRegistry::with_builtin();
    let mut names: Vec<&str> = registry.names().collect();
    names.sort_unstable();

    for name in names {
        match registry.get(name) {
            Some(profile) => println!(
                "{name:<10} {} {} on {}",
                profile.name,
                profile.version,
                profile.platform.client_hint()
            ),
            None => println!("{name}"),
        }
    }
    EXIT_OK
}

fn run_fingerprint(args: &FingerprintArgs) -> u8 {
    let profile = match load_profile(&args.profile) {
        Ok(profile) => profile,
        Err(message) => {
            eprintln!("error: {message}");
            return EXIT_USAGE;
        }
    };

    // Building a client is what reveals the gap: the target comes from the
    // profile, but what is reproducible depends on the TLS provider and the
    // hyper build this binary actually links.
    let client = match Client::builder()
        .shared_profile(Arc::clone(&profile))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "error: could not build a client for `{}`: {error}",
                args.profile
            );
            return EXIT_USAGE;
        }
    };
    let engine = client.engine();
    let tls = engine.tls();
    let http2 = engine.http2_fidelity();

    if args.json {
        let report = serde_json::json!({
            "profile": profile.name,
            "version": profile.version,
            "platform": profile.platform.client_hint(),
            "user_agent": profile.user_agent,
            "target": {
                "ja3": profile.ja3(),
                "ja3_hash": profile.ja3_hash(),
                "ja4": profile.ja4(),
                "ja4_r": profile.ja4_raw(),
                "akamai_http2": profile.akamai_http2(),
                "akamai_http2_hash":
                    chromulate::fingerprint::akamai_http2_hash(&profile.akamai_http2()),
            },
            "emitted": {
                "tls_provider": tls.fidelity().provider,
                "cipher_coverage": tls.fidelity().cipher_coverage(),
                "group_coverage": tls.fidelity().group_coverage(),
                "alpn": tls.fidelity().alpn,
                "all_primitives_available": tls.fidelity().all_primitives_available(),
                "tls_structural_limits": chromulate::tls::STRUCTURAL_LIMITS,
                "http2_settings_applied": http2
                    .applied
                    .iter()
                    .map(|(id, value)| format!("{}:{value}", id.get()))
                    .collect::<Vec<_>>(),
                "http2_unsupported": http2
                    .unsupported
                    .iter()
                    .map(UnsupportedSetting::to_string)
                    .collect::<Vec<_>>(),
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
        );
        return EXIT_OK;
    }

    println!("profile      {} {}", profile.name, profile.version);
    println!("platform     {}", profile.platform.client_hint());
    println!("user agent   {}", profile.user_agent);
    println!();
    println!("Target identity — what the captured browser sends");
    println!("  JA4        {}", profile.ja4());
    println!("  JA4_r      {}", profile.ja4_raw());
    println!("  Akamai H2  {}", profile.akamai_http2());
    println!(
        "  Akamai MD5 {}",
        chromulate::fingerprint::akamai_http2_hash(&profile.akamai_http2())
    );
    println!();
    // JA3 does not sort before hashing, so a profile that permutes its
    // extensions has no single JA3 — the capture recorded two different hashes
    // for two connections from the same browser. Printing one as "the" JA3
    // would be presenting an artefact of one sample as an identity.
    println!("  This profile permutes its extension order every connection, so it has no");
    println!("  stable JA3. The string below is one deterministic permutation, shown for");
    println!("  comparison only; JA4 sorts before hashing and is the stable identifier.");
    println!("    JA3 (reference order) {}", profile.ja3_hash());
    println!("    JA3 text              {}", profile.ja3());
    println!();
    println!("What this build actually emits");
    println!("  TLS provider     {}", tls.fidelity().provider);

    let (suites, suites_total) = tls.fidelity().cipher_coverage();
    let (groups, groups_total) = tls.fidelity().group_coverage();
    println!("  cipher suites    {suites} of {suites_total} offered");
    println!("  named groups     {groups} of {groups_total} offered");
    println!("  ALPN             {}", tls.fidelity().alpn.join(", "));
    println!();
    println!("  The ClientHello above is a target, not a measurement. rustls builds its");
    println!("  own ClientHello and takes no instruction on its shape:");
    for limit in chromulate::tls::STRUCTURAL_LIMITS {
        println!("    - {limit}");
    }
    println!();
    println!("  HTTP/2 settings applied to hyper:");
    for (id, value) in &http2.applied {
        println!("    - {}:{value}", id.get());
    }
    println!("  HTTP/2 shape hyper will not reproduce:");
    for gap in &http2.unsupported {
        println!("    - {gap}");
    }

    EXIT_OK
}

async fn run_get(args: GetArgs) -> u8 {
    if args.verbose {
        init_tracing();
    }

    let profile = match load_profile(&args.profile) {
        Ok(profile) => profile,
        Err(message) => {
            eprintln!("error: {message}");
            return EXIT_USAGE;
        }
    };

    let method = match args.method.as_deref() {
        Some(raw) => match Method::from_bytes(raw.to_ascii_uppercase().as_bytes()) {
            Ok(method) => method,
            Err(_) => {
                eprintln!("error: `{raw}` is not a valid HTTP method");
                return EXIT_USAGE;
            }
        },
        // A body with no stated method means a POST, which is what every other
        // command-line HTTP client does.
        None if args.data.is_some() => Method::POST,
        None => Method::GET,
    };

    let mut headers = Vec::new();
    for raw in &args.headers {
        match parse_header(raw) {
            Ok(pair) => headers.push(pair),
            Err(message) => {
                eprintln!("error: {message}");
                return EXIT_USAGE;
            }
        }
    }

    let mut builder = Client::builder()
        .shared_profile(Arc::clone(&profile))
        .timeout(Duration::from_secs(args.timeout));
    if args.no_redirect {
        builder = builder.redirect(RedirectPolicy::None);
    }
    if let Some(proxy) = &args.proxy {
        builder = match builder.proxy(proxy) {
            Ok(builder) => builder,
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_USAGE;
            }
        };
    }

    let client = match builder.build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("error: could not build a client: {error}");
            return EXIT_USAGE;
        }
    };

    let mut request = client.request(method.clone(), &args.url);
    if !args.fetch {
        request = request.fetch_context(RequestOptions::navigation());
    }
    for (name, value) in headers {
        request = request.header(name, value.to_str().unwrap_or_default());
    }
    if let Some(data) = args.data.clone() {
        request = request.body(data);
    }

    if args.verbose && !args.json {
        eprintln!("> {method} {}", args.url);
        eprintln!("> identity {}", client.engine().tls().target_identity());
    }

    let started = Instant::now();
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("error: {error}");
            return EXIT_REQUEST_FAILED;
        }
    };
    let elapsed = started.elapsed();

    let status = response.status();
    let version = format!("{:?}", response.version());
    let final_url = response.url().to_string();
    let response_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("<binary>").to_owned(),
            )
        })
        .collect();

    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            eprintln!("error: reading the body failed: {error}");
            return EXIT_REQUEST_FAILED;
        }
    };

    if args.json {
        let headers_object: serde_json::Map<String, serde_json::Value> = response_headers
            .iter()
            .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
            .collect();

        let report = serde_json::json!({
            "url": final_url,
            "status": status.as_u16(),
            "version": version,
            "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "headers": headers_object,
            "body_bytes": body.len(),
            "body": String::from_utf8_lossy(&body),
            "identity": {
                "target_ja4": profile.ja4(),
                "target_akamai_http2": profile.akamai_http2(),
                "http2_unsupported": client
                    .engine()
                    .http2_fidelity()
                    .unsupported
                    .iter()
                    .map(UnsupportedSetting::to_string)
                    .collect::<Vec<_>>(),
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
        );
    } else {
        if args.verbose {
            eprintln!("< {version} {status}");
            for (name, value) in &response_headers {
                eprintln!("< {name}: {value}");
            }
            eprintln!("< {} bytes in {elapsed:?}", body.len());
            eprintln!();
        }

        match &args.output {
            Some(path) => {
                if let Err(error) = tokio::fs::write(path, &body).await {
                    eprintln!("error: writing `{path}` failed: {error}");
                    return EXIT_REQUEST_FAILED;
                }
                eprintln!("wrote {} bytes to {path}", body.len());
            }
            None => {
                let mut out = std::io::stdout().lock();
                if out.write_all(&body).is_err() || out.flush().is_err() {
                    return EXIT_REQUEST_FAILED;
                }
            }
        }
    }

    if status.is_success() {
        EXIT_OK
    } else {
        EXIT_REQUEST_FAILED
    }
}

/// Splits a `Name: value` argument.
fn parse_header(raw: &str) -> Result<(HeaderName, HeaderValue), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("`{raw}` is not a header; expected `Name: value`"))?;

    let name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|error| format!("`{name}` is not a valid header name: {error}"))?;
    let value = HeaderValue::from_str(value.trim())
        .map_err(|error| format!("`{value}` is not a valid header value: {error}"))?;
    Ok((name, value))
}

/// Sends engine logs to stderr, so a body piped from stdout stays clean.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("CHROMULATE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("chromulate=debug,chromulate_http=debug"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_argument_splits_on_the_first_colon() {
        let (name, value) = parse_header("X-Trace: id:with:colons").expect("a valid header");
        assert_eq!(name.as_str(), "x-trace");
        assert_eq!(value.to_str().expect("ascii"), "id:with:colons");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_from_both_halves() {
        let (name, value) = parse_header("  Accept :  text/plain  ").expect("a valid header");
        assert_eq!(name.as_str(), "accept");
        assert_eq!(value.to_str().expect("ascii"), "text/plain");
    }

    #[test]
    fn an_argument_without_a_colon_is_rejected_with_the_expected_shape() {
        let error = parse_header("NotAHeader").expect_err("no colon, no header");
        assert!(error.contains("Name: value"), "{error}");
    }

    #[test]
    fn an_invalid_header_name_is_rejected() {
        assert!(parse_header("bad name: value").is_err());
    }

    #[test]
    fn the_builtin_registry_knows_chrome_and_reports_what_it_has_otherwise() {
        assert!(load_profile("chrome").is_ok());
        let error = load_profile("netscape").expect_err("no such profile");
        assert!(
            error.contains("chrome"),
            "an unknown profile must list what is available: {error}"
        );
    }

    #[test]
    fn the_command_line_parses_the_documented_shapes() {
        let cli = Cli::try_parse_from([
            "chromulate",
            "get",
            "https://example.com",
            "-H",
            "Accept: */*",
            "-X",
            "POST",
            "-d",
            "body",
            "--profile",
            "chrome",
            "-v",
        ])
        .expect("the documented flags must parse");

        match cli.command {
            Command::Get(args) => {
                assert_eq!(args.url, "https://example.com");
                assert_eq!(args.headers, ["Accept: */*"]);
                assert_eq!(args.method.as_deref(), Some("POST"));
                assert_eq!(args.data.as_deref(), Some("body"));
                assert!(args.verbose);
            }
            other => panic!("expected a get command, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_takes_an_optional_profile() {
        let cli = Cli::try_parse_from(["chromulate", "fingerprint"]).expect("no arguments needed");
        match cli.command {
            Command::Fingerprint(args) => assert_eq!(args.profile, "chrome"),
            other => panic!("expected a fingerprint command, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_subcommand_is_a_usage_error() {
        let error = Cli::try_parse_from(["chromulate", "teleport"]).expect_err("no such command");
        assert_eq!(
            error.exit_code(),
            i32::from(EXIT_USAGE),
            "clap must exit 2 on a usage error, matching this binary's contract"
        );
    }
}
