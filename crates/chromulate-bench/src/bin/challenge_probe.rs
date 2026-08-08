//! Measurement probe for the challenge-handoff design, `design-plan.md` §7.
//!
//! Three questions gate the architecture
//! (`.superpowers/preflight/design-plan.md`, §7, "The probe — Phase B, and the
//! thing to do first"):
//!
//! - **Q1.** Does `obscura fetch <url> --stealth --dump cookies` come back with
//!   a clearance cookie, and in what fraction of attempts (n ≥ 10)?
//! - **Q2 — the one that decides the architecture.** Replayed through
//!   `chromulate`'s own rustls identity, on the same exit and the same
//!   User-Agent, does the earned cookie still work?
//! - **Q3.** Wall clock and peak RSS per solve, n ≥ 3.
//!
//! # What is, and is not, measured by this binary
//!
//! **Obscura is not installed on this machine** (`which obscura` found nothing,
//! checked 2026-08-08). This binary is the harness the design plan asked for —
//! "a throwaway binary that prints what it observed, in the shape the
//! BoringSSL probe took" — not a measurement. Run without `--dry-run` and with
//! no `obscura` binary reachable, it prints `UNMEASURED` for Q1/Q2/Q3 and exits
//! cleanly; it does not invent numbers.
//!
//! What *can* be checked without Obscura, and is checked by this file's own
//! tests plus `--dry-run`, is that the harness's JSON → [`CookieRecord`]
//! mapping is correct against what Obscura actually emits. That shape was not
//! guessed from the docs: `obscura fetch --dump cookies` runs `dump_cookies()`
//! in `crates/obscura-cli/src/main.rs`, which serializes
//! `CookieJar::get_all_cookies() -> Vec<CookieInfo>`
//! (`crates/obscura-net/src/cookies.rs`), and `CookieInfo` is
//!
//! ```text
//! pub struct CookieInfo {
//!     pub name: String,
//!     pub value: String,
//!     pub domain: String,
//!     pub path: String,
//!     pub secure: bool,
//!     #[serde(rename = "httpOnly")]
//!     pub http_only: bool,
//!     #[serde(default, rename = "sameSite")]
//!     pub same_site: String,
//!     #[serde(default)]
//!     pub expires: Option<i64>,
//! }
//! ```
//!
//! read from `h4ckf0r0day/obscura` commit
//! `97124edeb2ea610615e78f43e097454e3b221f6b` (`main`, pushed 2026-08-08). This
//! corrects the handoff brief's assumed shape (`same_site`/`http_only`
//! snake_case, plus `host_only` and `partitioned` fields): the wire format is
//! `sameSite`/`httpOnly` camelCase, and `--dump cookies` carries neither
//! `host_only` nor `partitioned` — `CookieInfo` has no such fields anywhere in
//! the crate. Both gaps are real information loss on the way into a
//! [`CookieRecord`], not oversights in this file; see
//! [`cookie_record_from_json`]'s doc comment for what that costs Q2.
//!
//! # Credentials never reach argv
//!
//! A proxy URL can carry `user:pass@host` credentials
//! (`docs/Configure-stealth-and-proxies.md` shows exactly that form), and
//! anything on a command line is visible to every other process on the box
//! through `ps` — including *this* process's own argv, not only the child's.
//! An earlier version of this probe took `--proxy` as a flag, which protected
//! `obscura`'s argv while leaking the same credential onto its own. `ps` does
//! not care which process it is reading, so there is no such thing as a
//! partially-safe proxy flag here: `--proxy` is refused outright
//! ([`refuse_proxy_on_argv`]), and the only way in is [`PROBE_PROXY_ENV`] in
//! the environment. `chromulate-proxy` redacts credentials from `Debug` and
//! from every error message for the identical reason (`ProxyUrl`'s `Debug`
//! impl, `crates/chromulate-proxy/src/url.rs`).
//!
//! The child gets the same treatment: `OBSCURA_PROXY` is set in `obscura`'s
//! environment, never passed as `.arg(...)`. Obscura's own docs name that
//! variable: `docs/Environment-variables.md`, "HTTP proxy environment",
//! closes with "Use `--proxy` or `OBSCURA_PROXY`." The per-flag section above
//! it scopes `OBSCURA_PROXY` to `obscura-worker`'s use in `scrape`, not
//! explicitly to `fetch` — so whether `obscura fetch` honours it at all is an
//! open question no amount of reading settles. [`preflight_proxy_honored`]
//! answers it empirically before a single sample is trusted through a proxy:
//! it stands up a local, credential-free `TcpListener`, points `OBSCURA_PROXY`
//! at it, runs one `obscura fetch`, and aborts the whole run rather than
//! measuring unproxied if no connection arrives. Same technique
//! `chromulate-proxy`'s own tests use against a local `TcpListener` playing
//! the proxy role (`crates/chromulate-proxy/src/http_connect.rs`).
//!
//! # Usage
//!
//! Works today, no Obscura required — proves the harness against a fixture:
//!
//! ```text
//! cargo run --release -p chromulate-bench --bin challenge_probe -- --dry-run
//! ```
//!
//! Once Obscura is installed (see the report for the install command). A
//! proxy, if any, is named by [`PROBE_PROXY_ENV`] — never `--proxy`, which
//! this binary refuses on sight:
//!
//! ```text
//! CHALLENGE_PROBE_PROXY=http://user:pass@host:port \
//! cargo run --release -p chromulate-bench --bin challenge_probe -- \
//!     --url https://example.com [--runs 10] [--clearance-cookie cf_clearance] \
//!     [--obscura-bin /path/to/obscura] [--storage-dir /path/to/dir]
//! ```

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, fs, process};

use chromulate::cookie::{CookieRecord, Jar, JarSnapshot, SameSite};
use chromulate_bench::stats::Summary;

/// Cookie name Cloudflare documents for a cleared managed/JS challenge.
const CLEARANCE_COOKIE: &str = "cf_clearance";

/// Environment variable Obscura reads for a proxy URL when `--proxy` is not
/// passed on argv (`docs/Environment-variables.md`, "HTTP proxy environment").
const OBSCURA_PROXY_ENV: &str = "OBSCURA_PROXY";

/// Environment variable *this probe* reads its own proxy URL from. Never a
/// `--proxy` flag — see the module doc's "Credentials never reach argv"
/// section and [`refuse_proxy_on_argv`].
const PROBE_PROXY_ENV: &str = "CHALLENGE_PROBE_PROXY";

/// Q1's minimum sample size, `design-plan.md` §7. Also used as the default
/// `--runs`; Q3's own minimum (n ≥ 3) is satisfied for free since the same
/// invocations feed both questions.
const MIN_RUNS: usize = 10;

/// How often the RSS sampler polls the child while it runs.
const RSS_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How long [`preflight_proxy_honored`] waits for `obscura` to attempt a
/// connection through `OBSCURA_PROXY` before concluding it does not honour
/// it. Generous on purpose: this runs once per invocation, not once per
/// sample, so there is no throughput cost to affording it a slow first
/// connection attempt.
const PROXY_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(15);

/// Synthetic `obscura fetch --dump cookies` output, shaped exactly like
/// `CookieInfo`'s JSON (see the module doc for where that shape was read).
/// Not a capture — there is no Obscura install on this machine to capture one
/// from — so this exercises the parsing and mapping code below, not a
/// fingerprint claim; `CLAUDE.md`'s "captured, never invented" rule governs
/// browser fingerprint constants, which this is not.
const FIXTURE: &str = include_str!("../../tests/fixtures/obscura_cookies.json");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    // Checked before anything else, dry-run included: a `--proxy` credential
    // on this process's own argv is exactly as `ps`-visible as one on
    // obscura's, and there is no mode where accepting it is safe. See the
    // module doc's "Credentials never reach argv" section.
    refuse_proxy_on_argv(&args)?;

    if args.iter().any(|a| a == "--dry-run") {
        let fixture_path = flag_value(&args, "--fixture");
        return dry_run(fixture_path.as_deref());
    }

    if let Some(url) = flag_value(&args, "--url") {
        let runs: usize = flag_value(&args, "--runs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(MIN_RUNS)
            .max(1);
        let real_args = RealArgs {
            url,
            runs,
            proxy: env::var(PROBE_PROXY_ENV).ok(),
            obscura_bin: flag_value(&args, "--obscura-bin").unwrap_or_else(|| "obscura".to_owned()),
            clearance_cookie: flag_value(&args, "--clearance-cookie")
                .unwrap_or_else(|| CLEARANCE_COOKIE.to_owned()),
            storage_dir: flag_value(&args, "--storage-dir").map(PathBuf::from),
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("challenge-probe")
            .build()?;
        return runtime.block_on(real_run(real_args));
    }

    eprintln!("usage:");
    eprintln!("  challenge_probe --dry-run [--fixture PATH]");
    eprintln!("  challenge_probe --url URL [--runs N] [--clearance-cookie NAME] \\");
    eprintln!("                  [--obscura-bin PATH] [--storage-dir DIR]");
    eprintln!(
        "  (a proxy, if any, is named by the {PROBE_PROXY_ENV} environment variable — never a flag)"
    );
    process::exit(2);
}

/// Reads `--name value` out of a manually parsed argument list. No `clap`:
/// `chromulate-bench`'s `Cargo.toml` gains no new dependency for this probe
/// (the handoff brief's scope boundary), and every other binary in this crate
/// already parses its own arguments by hand (see `profile.rs`, `memory.rs`).
fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Refuses to run if `--proxy` appears anywhere on argv, rather than quietly
/// accepting it: a proxy URL can carry `user:pass@host` credentials, and this
/// process's own command line is exactly as `ps`-visible to every other user
/// on the box as any child's. See the module doc's "Credentials never reach
/// argv" section — the gap this closes is that an earlier version of this
/// probe protected `obscura`'s argv while leaking the same value onto its
/// own.
fn refuse_proxy_on_argv(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--proxy") {
        return Err(format!(
            "--proxy is not accepted here: a proxy URL can carry credentials, and this \
             process's own argv is `ps`-visible to every other user on the box — the same \
             reason obscura never gets one on its argv either. Set {PROBE_PROXY_ENV} in the \
             environment instead."
        ));
    }
    Ok(())
}

/// Parses `text` as an `obscura fetch --dump cookies` JSON array into a
/// [`JarSnapshot`]. A record that fails to map is skipped rather than failing
/// the whole batch — one malformed cookie should not hide the clearance
/// cookie sitting next to it — and the skip count is returned so a caller can
/// still notice.
fn parse_obscura_cookies(text: &str) -> Result<(JarSnapshot, usize), String> {
    let root = json::parse(text).map_err(|e| e.to_string())?;
    let items = root.as_array().ok_or("expected a top-level JSON array")?;

    let mut cookies = Vec::with_capacity(items.len());
    let mut skipped = 0usize;
    for item in items {
        match item.as_object() {
            Some(fields) => match cookie_record_from_json(fields) {
                Ok(record) => cookies.push(record),
                Err(_message) => skipped += 1,
            },
            None => skipped += 1,
        }
    }
    Ok((JarSnapshot { cookies }, skipped))
}

/// Maps one `CookieInfo`-shaped JSON object (see the module doc) to a
/// [`CookieRecord`].
///
/// Two fields are filled with a default because Obscura's `--dump cookies`
/// output has nothing to fill them from — verified by reading
/// `crates/obscura-net/src/cookies.rs`'s `CookieInfo`, which has neither
/// field:
///
/// - `host_only: false`. Obscura does not report whether a cookie was set
///   with a `Domain` attribute (domain-scoped) or without one (host-only).
///   Treating every imported cookie as domain-scoped is the wider of the two
///   readings — it applies the cookie to the recorded `domain` and every
///   subdomain of it — which is a real approximation with a real failure
///   mode: if Obscura's cookie was actually host-only, this can hand it to a
///   sibling subdomain the origin never authorised. It is also the reading
///   that keeps a clearance cookie issued to a bare domain reachable from
///   `www.` and other subdomains, which is the shape a Cloudflare
///   `cf_clearance` cookie needs to be useful (`design-plan.md` §2.1, Gap C).
///   Neither direction is verified against a real capture; flagged here
///   rather than decided silently.
/// - `partitioned: false`. Obscura has no CHIPS/partitioned-cookie concept
///   anywhere in the crate (a code search for `partitioned` across
///   `h4ckf0r0day/obscura` at the commit cited in the module doc has no
///   hits), so there is nothing to read here even in principle.
fn cookie_record_from_json(fields: &[(String, json::Value)]) -> Result<CookieRecord, String> {
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, value)| value)
    };

    let name = get("name")
        .and_then(json::Value::as_str)
        .ok_or("missing or non-string \"name\"")?
        .to_owned();
    let value = get("value")
        .and_then(json::Value::as_str)
        .ok_or("missing or non-string \"value\"")?
        .to_owned();
    let domain = get("domain")
        .and_then(json::Value::as_str)
        .ok_or("missing or non-string \"domain\"")?
        .to_owned();
    let path = get("path")
        .and_then(json::Value::as_str)
        .ok_or("missing or non-string \"path\"")?
        .to_owned();
    let secure = get("secure")
        .and_then(json::Value::as_bool)
        .ok_or("missing or non-bool \"secure\"")?;
    let http_only = get("httpOnly")
        .and_then(json::Value::as_bool)
        .ok_or("missing or non-bool \"httpOnly\"")?;
    let same_site = get("sameSite")
        .and_then(json::Value::as_str)
        .map(same_site_from_str)
        // Obscura's own default when nothing set the attribute
        // (`DEFAULT_SAME_SITE` in `obscura-net/src/cookies.rs`).
        .unwrap_or(SameSite::Lax);
    let expires = match get("expires") {
        None | Some(json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .ok_or("\"expires\" is neither an integer nor null")?,
        ),
    };

    Ok(CookieRecord {
        name,
        value,
        domain,
        host_only: false,
        path,
        secure,
        http_only,
        same_site,
        partitioned: false,
        expires,
        creation_seq: 0,
        last_access_seq: 0,
    })
}

/// `Strict` / `Lax` / `None`, matching the exact strings Obscura normalizes to
/// (`normalize_same_site` in `obscura-net/src/cookies.rs`). Case-insensitive
/// and defaults to `Lax` for anything else, mirroring that function's own
/// fallback rather than trusting it: this reads Obscura's *output*, and
/// nothing here depends on a future Obscura version keeping the same casing.
fn same_site_from_str(raw: &str) -> SameSite {
    match raw.to_ascii_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "none" => SameSite::None,
        _ => SameSite::Lax,
    }
}

/// Reads a fixture (the embedded [`FIXTURE`], or `--fixture PATH`), maps it
/// to a [`JarSnapshot`], imports it into a fresh [`Jar`], and prints what
/// landed. Proves the JSON → `CookieRecord` → `Jar` path without needing
/// Obscura installed, per the brief's §7 verification method.
fn dry_run(fixture_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let (source, text) = match fixture_path {
        Some(path) => (path.to_owned(), fs::read_to_string(path)?),
        None => (
            "<embedded: tests/fixtures/obscura_cookies.json>".to_owned(),
            FIXTURE.to_owned(),
        ),
    };

    println!("# --dry-run: parsing {source} as Obscura `--dump cookies` output");
    println!("# (no obscura process runs; this exercises the JSON -> CookieRecord path only)");
    println!("# Q1/Q2/Q3 are not answered by this mode; see `--url` once obscura is installed.");
    println!();

    let (snapshot, skipped) = parse_obscura_cookies(&text)?;
    println!(
        "parsed {} cookie record(s), {skipped} unparseable",
        snapshot.cookies.len()
    );
    for record in &snapshot.cookies {
        println!(
            "  {:<16} domain={:<14} path={:<6} secure={:<5} http_only={:<5} same_site={:?} expires={:?}",
            record.name,
            record.domain,
            record.path,
            record.secure,
            record.http_only,
            record.same_site,
            record.expires
        );
    }
    println!();
    println!(
        "note: host_only and partitioned are always false above — Obscura's `--dump cookies`\n\
         carries neither field; see cookie_record_from_json's doc comment for what that costs."
    );

    let jar = Jar::new();
    jar.import(&snapshot);
    let landed = jar.export().cookies.len();
    println!();
    println!(
        "Jar::import: {landed} of {} parsed record(s) are in a fresh jar (any remainder was \
         dropped by Jar::import's own validation — expired, or unrepresentable in a Cookie \
         header; see chromulate-cookie/src/jar.rs's `import` doc comment)",
        snapshot.cookies.len()
    );

    let has_clearance = jar
        .export()
        .cookies
        .iter()
        .any(|c| c.name == CLEARANCE_COOKIE);
    println!("a `{CLEARANCE_COOKIE}` cookie is present after import: {has_clearance}");

    Ok(())
}

/// Arguments for the real (non-dry-run) path.
struct RealArgs {
    url: String,
    runs: usize,
    proxy: Option<String>,
    obscura_bin: String,
    clearance_cookie: String,
    storage_dir: Option<PathBuf>,
}

/// One `obscura fetch` invocation's outcome.
struct FetchSample {
    elapsed: Duration,
    peak_rss_kib: Option<u64>,
    cookies: Result<(JarSnapshot, usize), String>,
}

async fn real_run(args: RealArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("# challenge_probe — design-plan.md §7, Q1/Q2/Q3");
    println!("# target: {}", args.url);
    println!("# runs:   {}", args.runs);
    if args.runs < MIN_RUNS {
        eprintln!(
            "warning: --runs {} is below design-plan.md §7's n >= {MIN_RUNS} for Q1; the \
             fraction below is not a reliable answer at this sample size",
            args.runs
        );
    }
    println!();

    let Some(version) = probe_obscura_binary(&args.obscura_bin).await else {
        println!(
            "obscura binary `{}` did not run (not on PATH, or `--version` failed).",
            args.obscura_bin
        );
        println!();
        print_unmeasured();
        return Ok(());
    };
    println!("using `{}`: {version}", args.obscura_bin);
    println!();

    if args.proxy.is_some() {
        println!(
            "preflight: confirming `{}` opens a connection through {OBSCURA_PROXY_ENV} before \
             trusting any sample through it (Q2 is the question this probe exists to answer, \
             and it is meaningless if the traffic never left this machine's own address)...",
            args.obscura_bin
        );
        if let Err(message) = preflight_proxy_honored(&args.obscura_bin, &args.url).await {
            println!("{message}");
            println!();
            println!("Q1 (clearance rate):        UNMEASURED — proxy preflight failed, see above");
            println!("Q2 (replay under rustls):   UNMEASURED — proxy preflight failed, see above");
            println!("Q3 (wall clock / peak RSS): UNMEASURED — proxy preflight failed, see above");
            return Ok(());
        }
        println!(
            "preflight: confirmed — `{}` opened a connection through {OBSCURA_PROXY_ENV}",
            args.obscura_bin
        );
        println!();
    }

    let profile = chromulate::Profile::chrome_stable();
    let mut clearance_hits = 0usize;
    let mut failures = 0usize;
    let mut elapsed_secs = Vec::with_capacity(args.runs);
    let mut rss_kib = Vec::with_capacity(args.runs);
    let mut last_clearance: Option<JarSnapshot> = None;

    for run in 1..=args.runs {
        let (storage_dir, owned) = match &args.storage_dir {
            Some(dir) => (dir.clone(), false),
            // A fresh directory per run, deliberately: a shared `--storage-dir`
            // would let run 2 inherit run 1's clearance cookie, and "did
            // Obscura solve it" would silently turn into "did Obscura solve it
            // once, ever". Pass `--storage-dir` explicitly to measure the
            // cached-clearance case instead — that is a different question.
            None => (
                env::temp_dir().join(format!(
                    "chromulate-challenge-probe-{}-{run}",
                    process::id()
                )),
                true,
            ),
        };

        let sample = run_obscura_fetch(
            &args.obscura_bin,
            &args.url,
            &profile.user_agent,
            args.proxy.as_deref(),
            &storage_dir,
        )
        .await;

        if owned {
            let _ = fs::remove_dir_all(&storage_dir);
        }

        match sample {
            Ok(sample) => {
                elapsed_secs.push(sample.elapsed.as_secs_f64());
                if let Some(kib) = sample.peak_rss_kib {
                    rss_kib.push(kib as f64);
                }
                match sample.cookies {
                    Ok((snapshot, skipped)) => {
                        let has_clearance = snapshot
                            .cookies
                            .iter()
                            .any(|c| c.name == args.clearance_cookie);
                        if has_clearance {
                            clearance_hits += 1;
                            last_clearance = Some(snapshot.clone());
                        }
                        println!(
                            "run {run:>3}/{}: {} cookie(s) ({skipped} unparseable), \
                             clearance={has_clearance}, {:.2}s, rss={}",
                            args.runs,
                            snapshot.cookies.len(),
                            sample.elapsed.as_secs_f64(),
                            sample.peak_rss_kib.map_or_else(
                                || "n/a".to_owned(),
                                |k| format!("{:.1} MiB", k as f64 / 1024.0)
                            )
                        );
                    }
                    Err(message) => {
                        failures += 1;
                        println!(
                            "run {run:>3}/{}: obscura exited but its output did not parse: {message}",
                            args.runs
                        );
                    }
                }
            }
            Err(message) => {
                failures += 1;
                println!(
                    "run {run:>3}/{}: obscura invocation failed: {message}",
                    args.runs
                );
            }
        }
    }

    println!();
    println!("# Q1 — clearance cookie obtained (design-plan.md §7 Q1)");
    println!(
        "{clearance_hits}/{} runs returned a `{}` cookie ({:.1}%); {failures} run(s) failed outright",
        args.runs,
        args.clearance_cookie,
        100.0 * clearance_hits as f64 / args.runs as f64
    );

    println!();
    println!(
        "# Q3 — wall clock and peak RSS per solve (n={})",
        elapsed_secs.len()
    );
    if elapsed_secs.is_empty() {
        println!("no successful invocation to measure");
    } else {
        println!("wall clock, seconds: {}", Summary::of(&elapsed_secs));
    }
    if rss_kib.is_empty() {
        println!("peak RSS: no sample (`ps` did not report one on this platform)");
    } else {
        let rss_mib: Vec<f64> = rss_kib.iter().map(|kib| kib / 1024.0).collect();
        println!("peak RSS, MiB: {}", Summary::of(&rss_mib));
    }

    println!();
    println!(
        "# Q2 — the architecture question: does chromulate's rustls identity replay the clearance?"
    );
    match last_clearance {
        None => println!(
            "no run produced a `{}` cookie; nothing to replay",
            args.clearance_cookie
        ),
        Some(snapshot) => {
            let jar = Arc::new(Jar::new());
            jar.import(&snapshot);
            let mut builder = chromulate::Client::builder().cookie_jar(jar);
            if let Some(proxy) = &args.proxy {
                builder = builder.proxy(proxy)?;
            }
            let client = builder.build()?;
            let response = client.get(&args.url).send().await?;
            println!(
                "replayed the original request through the profile's identity (same UA, same \
                 exit) with the earned cookie imported: status {}",
                response.status()
            );
            println!(
                "this is an observation, not a verdict: a non-2xx here is consistent with the \
                 clearance being bound to Obscura's TLS/JS identity (Gap C, design-plan.md \
                 §2.1), but is also consistent with an unrelated fresh challenge on this \
                 attempt. Only a run repeated against a target the maintainer controls, \
                 comparing this status against a same-identity Obscura replay, actually \
                 distinguishes the two."
            );
        }
    }

    Ok(())
}

fn print_unmeasured() {
    println!("Q1 (clearance rate):        UNMEASURED — obscura not installed on this machine");
    println!("Q2 (replay under rustls):   UNMEASURED — obscura not installed on this machine");
    println!("Q3 (wall clock / peak RSS): UNMEASURED — obscura not installed on this machine");
    println!();
    println!("install (macOS Apple Silicon — this machine, `uname -sm` = \"Darwin arm64\"):");
    println!(
        "  curl -LO https://github.com/h4ckf0r0day/obscura/releases/latest/download/obscura-aarch64-macos-stealth.tar.gz"
    );
    println!("  tar xzf obscura-aarch64-macos-stealth.tar.gz");
    println!("  ./obscura --version");
    println!(
        "(other platforms: docs/Installation.md in h4ckf0r0day/obscura; pick the `-stealth` \
         archive — `--stealth` is what Q1/Q2 need.)"
    );
}

/// Runs `obscura --version` and reports what came back, or `None` when the
/// binary could not be run at all (not found, not executable). Distinct from
/// a run that starts and fails, so the top-level message can say which one
/// happened.
async fn probe_obscura_binary(bin: &str) -> Option<String> {
    let output = tokio::process::Command::new(bin)
        .arg("--version")
        .stdin(process::Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if version.is_empty() {
        version = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    }
    Some(version)
}

/// Proves `obscura fetch` actually attempts a connection through whatever
/// `OBSCURA_PROXY` names, before a single sample is trusted through it.
///
/// Obscura's own docs scope `OBSCURA_PROXY` to `obscura-worker`'s use in
/// `scrape` (see the module doc); whether `fetch` honours it at all is a
/// question reading cannot answer. Q2 is the question this whole probe
/// exists to answer — does a clearance minted at one exit still work when
/// replayed from that exit — and running it from the wrong address does not
/// produce a wrong number, it produces a number that looks right and is not.
/// So this preflight is mandatory whenever a proxy was requested, and its
/// failure aborts the run: there is no unproxied fallback to measure with,
/// because an unproxied measurement is not an answer to Q1/Q2/Q3, it is an
/// answer to a different, unstated question.
///
/// Uses a local, credential-free listener rather than the real proxy —
/// `.env(OBSCURA_PROXY_ENV, ...)` here, never `.arg(...)`, for the same
/// reason as everywhere else in this file — because this only needs to
/// observe that `obscura` *attempted* a connection somewhere `OBSCURA_PROXY`
/// pointed it. Same technique `chromulate-proxy`'s own tests use against a
/// local `TcpListener` playing the proxy role
/// (`crates/chromulate-proxy/src/http_connect.rs`); see the module doc.
async fn preflight_proxy_honored(obscura_bin: &str, probe_url: &str) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("preflight: could not bind a local listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("preflight: could not read the local listener's address: {e}"))?;

    let mut command = tokio::process::Command::new(obscura_bin);
    command
        .arg("fetch")
        .arg(probe_url)
        .arg("--stealth")
        .arg("--dump")
        .arg("cookies")
        .arg("--timeout")
        .arg("5")
        .env(OBSCURA_PROXY_ENV, format!("http://{addr}"))
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null());

    let mut child = command
        .spawn()
        .map_err(|e| format!("preflight: could not spawn `{obscura_bin}`: {e}"))?;

    let connected = wait_for_connection(&listener, PROXY_PREFLIGHT_TIMEOUT).await;
    let _ = child.kill().await;
    let _ = child.wait().await;

    if connected {
        Ok(())
    } else {
        Err(format!(
            "preflight FAILED: `{obscura_bin} fetch` did not open a connection through \
             {OBSCURA_PROXY_ENV} within {PROXY_PREFLIGHT_TIMEOUT:?}. Obscura's own docs scope \
             that variable to `obscura-worker`/`scrape` and say nothing about `fetch` either \
             way — this is the case that leaves open. Refusing to measure through an exit this \
             probe cannot prove was used; see the module doc's \"Credentials never reach argv\" \
             section."
        ))
    }
}

/// Waits up to `timeout` for one inbound connection on `listener`, returning
/// whether one arrived. Split out from [`preflight_proxy_honored`] so the
/// accept/timeout race — the part with a timing window to get wrong — is
/// testable without spawning `obscura`, or anything else, at all.
async fn wait_for_connection(listener: &tokio::net::TcpListener, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, listener.accept()).await,
        Ok(Ok(_))
    )
}

/// Runs `obscura fetch <url> --stealth --dump cookies`, timing it and
/// sampling the child's RSS while it runs.
async fn run_obscura_fetch(
    obscura_bin: &str,
    url: &str,
    user_agent: &str,
    proxy: Option<&str>,
    storage_dir: &Path,
) -> Result<FetchSample, String> {
    fs::create_dir_all(storage_dir).map_err(|e| format!("could not create storage dir: {e}"))?;

    let mut command = tokio::process::Command::new(obscura_bin);
    command
        .arg("fetch")
        .arg(url)
        .arg("--stealth")
        .arg("--dump")
        .arg("cookies")
        .arg("--user-agent")
        .arg(user_agent)
        .arg("--storage-dir")
        .arg(storage_dir)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped());

    // SECURITY: the proxy URL can carry `user:pass@host` credentials. Never
    // `.arg(proxy)` here — see the module doc's "Credentials never reach
    // argv" section.
    if let Some(proxy) = proxy {
        command.env(OBSCURA_PROXY_ENV, proxy);
    }

    let started = Instant::now();
    let child = command.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let pid = child.id();

    let mut peak_rss_kib: Option<u64> = None;
    let output_fut = child.wait_with_output();
    tokio::pin!(output_fut);
    let output = loop {
        tokio::select! {
            result = &mut output_fut => break result.map_err(|e| format!("wait failed: {e}"))?,
            () = tokio::time::sleep(RSS_POLL_INTERVAL) => {
                if let Some(pid) = pid
                    && let Some(kib) = child_rss_kib(pid).await
                {
                    peak_rss_kib = Some(peak_rss_kib.map_or(kib, |p: u64| p.max(kib)));
                }
            }
        }
    };
    let elapsed = started.elapsed();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(FetchSample {
            elapsed,
            peak_rss_kib,
            cookies: Err(format!("exit status {}: {}", output.status, stderr.trim())),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let cookies = parse_obscura_cookies(&stdout);

    Ok(FetchSample {
        elapsed,
        peak_rss_kib,
        cookies,
    })
}

/// Peak RSS is approximated by polling; see [`RSS_POLL_INTERVAL`]. Mirrors
/// `chromulate_bench::resident_kib`'s `ps -o rss= -p <pid>` idiom
/// (`crates/chromulate-bench/src/lib.rs`), generalised to an arbitrary pid:
/// that helper only ever reports the *current* process's RSS, and what this
/// probe needs is the child's.
async fn child_rss_kib(pid: u32) -> Option<u64> {
    let output = tokio::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(pid.to_string())
        .output()
        .await
        .ok()?;
    parse_rss_output(&String::from_utf8(output.stdout).ok()?)
}

fn parse_rss_output(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// A JSON reader scoped to exactly what `obscura fetch --dump cookies` can
/// produce: an array of flat objects whose values are strings, numbers,
/// booleans, or null (see the module doc for where that shape was verified).
/// Not a general-purpose parser, and deliberately not one:
/// `chromulate-bench`'s `Cargo.toml` gains no dependency for this probe, so
/// there is no `serde_json` here to reach for, and the alternative — the
/// scoped, tested reader below — is smaller than the dependency it replaces.
mod json {
    use std::fmt;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub fn as_object(&self) -> Option<&[(String, Value)]> {
            match self {
                Value::Object(fields) => Some(fields),
                _ => None,
            }
        }

        pub fn as_array(&self) -> Option<&[Value]> {
            match self {
                Value::Array(items) => Some(items),
                _ => None,
            }
        }

        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::String(s) => Some(s),
                _ => None,
            }
        }

        pub fn as_bool(&self) -> Option<bool> {
            match self {
                Value::Bool(b) => Some(*b),
                _ => None,
            }
        }

        pub fn as_i64(&self) -> Option<i64> {
            match self {
                Value::Number(n) if n.fract() == 0.0 => Some(*n as i64),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ParseError(String);

    impl fmt::Display for ParseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for ParseError {}

    pub fn parse(input: &str) -> Result<Value, ParseError> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(parser.err("trailing data after the JSON value"));
        }
        Ok(value)
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl Parser<'_> {
        fn err(&self, message: &str) -> ParseError {
            ParseError(format!("{message} at byte {}", self.pos))
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn bump(&mut self) -> Option<u8> {
            let byte = self.peek()?;
            self.pos += 1;
            Some(byte)
        }

        fn skip_ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.pos += 1;
            }
        }

        fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
            if self.bump() == Some(byte) {
                Ok(())
            } else {
                Err(self.err(&format!("expected '{}'", byte as char)))
            }
        }

        fn expect_literal(&mut self, literal: &str) -> Result<(), ParseError> {
            for expected in literal.bytes() {
                if self.bump() != Some(expected) {
                    return Err(self.err(&format!("expected literal {literal:?}")));
                }
            }
            Ok(())
        }

        fn parse_value(&mut self) -> Result<Value, ParseError> {
            self.skip_ws();
            match self.peek() {
                Some(b'{') => self.parse_object(),
                Some(b'[') => self.parse_array(),
                Some(b'"') => self.parse_string().map(Value::String),
                Some(b't') => {
                    self.expect_literal("true")?;
                    Ok(Value::Bool(true))
                }
                Some(b'f') => {
                    self.expect_literal("false")?;
                    Ok(Value::Bool(false))
                }
                Some(b'n') => {
                    self.expect_literal("null")?;
                    Ok(Value::Null)
                }
                Some(b'-' | b'0'..=b'9') => self.parse_number(),
                _ => Err(self.err("expected a JSON value")),
            }
        }

        fn parse_object(&mut self) -> Result<Value, ParseError> {
            self.expect(b'{')?;
            let mut fields = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Value::Object(fields));
            }
            loop {
                self.skip_ws();
                let key = self.parse_string()?;
                self.skip_ws();
                self.expect(b':')?;
                let value = self.parse_value()?;
                fields.push((key, value));
                self.skip_ws();
                match self.bump() {
                    Some(b',') => continue,
                    Some(b'}') => break,
                    _ => return Err(self.err("expected ',' or '}' in object")),
                }
            }
            Ok(Value::Object(fields))
        }

        fn parse_array(&mut self) -> Result<Value, ParseError> {
            self.expect(b'[')?;
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            loop {
                let value = self.parse_value()?;
                items.push(value);
                self.skip_ws();
                match self.bump() {
                    Some(b',') => continue,
                    Some(b']') => break,
                    _ => return Err(self.err("expected ',' or ']' in array")),
                }
            }
            Ok(Value::Array(items))
        }

        fn parse_string(&mut self) -> Result<String, ParseError> {
            self.expect(b'"')?;
            let mut out = String::new();
            loop {
                match self.bump() {
                    None => return Err(self.err("unterminated string")),
                    Some(b'"') => break,
                    Some(b'\\') => match self.bump() {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{8}'),
                        Some(b'f') => out.push('\u{c}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => out.push(self.parse_unicode_escape()?),
                        _ => return Err(self.err("invalid escape sequence")),
                    },
                    Some(byte) if byte < 0x80 => out.push(byte as char),
                    Some(_) => {
                        // Multi-byte UTF-8: the source text is valid UTF-8
                        // (`&str` guarantees it), so re-decode the whole rest
                        // of this character from its start byte rather than
                        // reassembling it one byte at a time.
                        let start = self.pos - 1;
                        let rest = std::str::from_utf8(&self.bytes[start..])
                            .map_err(|_| self.err("invalid UTF-8 in string"))?;
                        let ch = rest
                            .chars()
                            .next()
                            .ok_or_else(|| self.err("invalid UTF-8 in string"))?;
                        self.pos = start + ch.len_utf8();
                        out.push(ch);
                    }
                }
            }
            Ok(out)
        }

        fn parse_unicode_escape(&mut self) -> Result<char, ParseError> {
            let unit = self.parse_hex4()?;
            if (0xD800..=0xDBFF).contains(&unit) {
                // High surrogate: a low surrogate must follow immediately.
                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                    return Err(self.err("expected a low surrogate after a high surrogate"));
                }
                let low = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.err("invalid low surrogate"));
                }
                let combined =
                    0x10000 + (u32::from(unit) - 0xD800) * 0x400 + (u32::from(low) - 0xDC00);
                char::from_u32(combined).ok_or_else(|| self.err("invalid surrogate pair"))
            } else {
                char::from_u32(u32::from(unit)).ok_or_else(|| self.err("invalid \\u escape"))
            }
        }

        fn parse_hex4(&mut self) -> Result<u16, ParseError> {
            let mut value: u16 = 0;
            for _ in 0..4 {
                let digit = self.bump().and_then(|b| (b as char).to_digit(16));
                match digit {
                    Some(d) => value = value * 16 + u16::try_from(d).unwrap_or(0),
                    None => return Err(self.err("invalid \\u escape")),
                }
            }
            Ok(value)
        }

        fn parse_number(&mut self) -> Result<Value, ParseError> {
            let start = self.pos;
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.peek() == Some(b'.') {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.pos += 1;
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.pos += 1;
                }
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            let text = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| self.err("invalid number"))?;
            text.parse::<f64>()
                .map(Value::Number)
                .map_err(|_| self.err("invalid number"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_scalars() {
            assert_eq!(parse("null").unwrap(), Value::Null);
            assert_eq!(parse("true").unwrap(), Value::Bool(true));
            assert_eq!(parse("false").unwrap(), Value::Bool(false));
            assert_eq!(parse("42").unwrap(), Value::Number(42.0));
            assert_eq!(parse("-3.5e1").unwrap(), Value::Number(-35.0));
            assert_eq!(parse("\"hi\"").unwrap(), Value::String("hi".to_owned()));
        }

        #[test]
        fn parses_string_escapes_including_a_surrogate_pair() {
            // U+1F600 GRINNING FACE, encoded as a UTF-16 surrogate pair.
            let parsed = parse(r#""line1\nline2\t\"quoted\"😀""#).unwrap();
            assert_eq!(
                parsed,
                Value::String("line1\nline2\t\"quoted\"\u{1F600}".to_owned())
            );
        }

        #[test]
        fn parses_nested_array_of_objects() {
            let parsed = parse(r#"[{"a": 1, "b": [true, null]}, {}]"#).unwrap();
            let Value::Array(items) = parsed else {
                panic!("expected an array")
            };
            assert_eq!(items.len(), 2);
            let first = items[0].as_object().unwrap();
            assert_eq!(first[0], ("a".to_owned(), Value::Number(1.0)));
            assert_eq!(
                first[1].1,
                Value::Array(vec![Value::Bool(true), Value::Null])
            );
        }

        #[test]
        fn rejects_trailing_garbage() {
            assert!(parse("null null").is_err());
        }

        #[test]
        fn rejects_an_object_missing_a_comma() {
            assert!(parse(r#"{"a": 1 "b": 2}"#).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_obscura_dump_cookies_json_to_cookie_records() {
        let (snapshot, skipped) = parse_obscura_cookies(FIXTURE).expect("fixture should parse");
        assert_eq!(skipped, 0, "the fixture has no malformed records");
        assert_eq!(snapshot.cookies.len(), 3);

        let clearance = snapshot
            .cookies
            .iter()
            .find(|c| c.name == "cf_clearance")
            .expect("fixture should carry a cf_clearance cookie");
        assert_eq!(clearance.value, "Xk9F3jz7q2VvY8pR-example-not-a-real-token");
        assert_eq!(clearance.domain, "example.com");
        assert_eq!(clearance.path, "/");
        assert!(clearance.secure);
        assert!(clearance.http_only);
        assert_eq!(clearance.same_site, SameSite::None);
        assert_eq!(clearance.expires, Some(4_070_908_800));
        assert!(
            !clearance.host_only,
            "not reported by Obscura; see cookie_record_from_json's doc comment"
        );
        assert!(!clearance.partitioned, "Obscura has no CHIPS concept");
        assert_eq!(clearance.creation_seq, 0);
        assert_eq!(clearance.last_access_seq, 0);

        let session_only = snapshot
            .cookies
            .iter()
            .find(|c| c.name == "_cfuvid")
            .expect("fixture should carry _cfuvid");
        assert_eq!(
            session_only.expires, None,
            "a null `expires` in Obscura's output is a session cookie"
        );
        assert_eq!(session_only.same_site, SameSite::Lax);

        let strict = snapshot
            .cookies
            .iter()
            .find(|c| c.name == "session_pref")
            .expect("fixture should carry session_pref");
        assert_eq!(strict.same_site, SameSite::Strict);
        assert_eq!(strict.expires, Some(4_083_955_200));
        assert!(!strict.secure);
        assert!(!strict.http_only);
    }

    #[test]
    fn same_site_falls_back_to_lax_for_an_unrecognized_value() {
        assert_eq!(same_site_from_str("Bogus"), SameSite::Lax);
        assert_eq!(same_site_from_str("strict"), SameSite::Strict);
        assert_eq!(same_site_from_str("NONE"), SameSite::None);
    }

    #[test]
    fn a_record_missing_a_required_field_is_skipped_not_fatal() {
        let text = r#"[
            {"name": "cf_clearance", "value": "v", "domain": "example.com", "path": "/",
             "secure": true, "httpOnly": true, "sameSite": "None", "expires": 4070908800},
            {"name": "broken"}
        ]"#;
        let (snapshot, skipped) = parse_obscura_cookies(text).expect("should parse the array");
        assert_eq!(snapshot.cookies.len(), 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn fixture_cookies_survive_a_real_jar_import() {
        let (snapshot, _) = parse_obscura_cookies(FIXTURE).expect("fixture should parse");
        let jar = Jar::new();
        jar.import(&snapshot);
        let exported = jar.export();
        assert_eq!(exported.cookies.len(), snapshot.cookies.len());
        assert!(exported.cookies.iter().any(|c| c.name == "cf_clearance"));
    }

    #[test]
    fn refuses_a_proxy_url_anywhere_on_argv() {
        let args = vec!["--url".to_owned(), "https://example.com".to_owned()];
        assert!(
            refuse_proxy_on_argv(&args).is_ok(),
            "no --proxy at all is fine"
        );

        let args = vec![
            "--proxy".to_owned(),
            "http://user:pass@proxy.example.com:8080".to_owned(),
            "--url".to_owned(),
            "https://example.com".to_owned(),
        ];
        let err = refuse_proxy_on_argv(&args).expect_err("--proxy on argv must be refused");
        assert!(
            err.contains(PROBE_PROXY_ENV),
            "the refusal should name the environment variable to use instead, got: {err}"
        );
        assert!(
            !err.contains("user:pass"),
            "the refusal message must not echo the credential back: {err}"
        );
    }

    #[tokio::test]
    async fn wait_for_connection_sees_a_connection_before_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = tokio::net::TcpStream::connect(addr).await;
        });

        assert!(wait_for_connection(&listener, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn wait_for_connection_times_out_when_nothing_connects() {
        // Nothing connects to this listener; the future being tested is the
        // one that has to notice that and give up rather than hang, which is
        // exactly the failure mode `preflight_proxy_honored` depends on this
        // not having.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local listener");

        assert!(!wait_for_connection(&listener, Duration::from_millis(200)).await);
    }
}
