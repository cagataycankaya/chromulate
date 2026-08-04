//! Cookie jar work on the request and response paths.
//!
//! Both directions run on every request that has a jar attached, so both are
//! hot. The question each group answers:
//!
//! - `cookies_for/single_domain` — how lookup scales when the cookies really do
//!   all belong to the domain being asked about. Some growth here is
//!   unavoidable: RFC 6265 §5.4 requires the `Cookie` header be sorted, so the
//!   matching set has to be walked and ordered.
//! - `cookies_for/spread` — the same *total* cookie count spread over many
//!   domains, always asking about a domain holding ten. If these rows grow with
//!   the total, lookup is linear in the whole jar rather than in the bucket,
//!   which is the failure mode worth knowing about: a long-running crawl
//!   accumulates cookies for thousands of sites and pays for all of them on
//!   every request to any one of them.
//! - `store/replace_in_jar_of` — writing a `Set-Cookie` that replaces an
//!   existing entry, in jars of increasing size. Jar size is constant across
//!   iterations by construction, so growth across rows is growth in the cost of
//!   the write path itself.
//! - `store/at_default_cap/*` — the same write path with `JarLimits::default()`
//!   and the jar pinned at its 3,000-cookie ceiling. This is the state a
//!   long-running crawler lives in permanently, and it is the only one where
//!   eviction runs. The `insert` and `replace` rows differ only in whether the
//!   incoming cookie is new, so the gap between them is the eviction cost.
//!
//! ## The fixtures verify themselves
//!
//! There are two ways to silently measure the wrong thing here, and both are
//! guarded by assertions rather than by care:
//!
//! 1. **The jar evicts rather than refusing.** Asking it to hold 10,000 cookies
//!    under `JarLimits::default()` yields a jar of 3,000 — or of 180, for a
//!    single domain — and a benchmark row labelled with a number the jar never
//!    held. `fill` asserts the jar holds what the row claims.
//! 2. **A wrong `CookieContext` turns the benchmark into an early return.** With
//!    `is_top_level_navigation: false` and no initiator, ordinary `Lax` cookies
//!    are ineligible, so `cookies_for` returns `None` almost immediately: a
//!    fast, flat, meaningless number. `check_lookup` asserts that a header with
//!    the expected number of cookies comes back before any timing is trusted.
//!
//! Run with `cargo bench -p chromulate-cookie`.

use std::hint::black_box;

use chromulate_cookie::{CookieContext, CookieStore, Jar, JarLimits};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use http::HeaderValue;
use url::Url;

const TOTALS: [usize; 3] = [10, 1_000, 10_000];

/// Cookies per domain in the `spread` case, so that the bucket the benchmark
/// asks about stays the same size as the total grows.
const SPREAD_BUCKET: usize = 10;

/// Limits high enough that none of the sized fixtures evict. `fill` asserts
/// that rather than assuming it.
fn roomy_limits() -> JarLimits {
    JarLimits {
        per_domain: 50_000,
        total: 500_000,
    }
}

fn site(index: usize) -> Url {
    Url::parse(&format!("https://site{index}.com/path/page"))
        .expect("a generated site URL must parse")
}

fn set_cookie(index: usize) -> HeaderValue {
    HeaderValue::from_str(&format!("name{index}=value{index}; Path=/; SameSite=Lax"))
        .expect("a generated Set-Cookie must be a valid header value")
}

/// Fills `jar`, and asserts it actually holds what was put into it.
///
/// Returns the held count, so a caller measuring a deliberately capped jar can
/// report the real number rather than the requested one.
fn fill(jar: &Jar, domains: usize, per_domain: usize, expect_held: Option<usize>) -> usize {
    for domain in 0..domains {
        let url = site(domain);
        for cookie in 0..per_domain {
            jar.store(&url, &mut std::iter::once(&set_cookie(cookie)));
        }
    }
    let held = jar.export().cookies.len();
    if let Some(expected) = expect_held {
        assert_eq!(
            held, expected,
            "fixture holds {held} cookies but the row claims {expected}; the jar \
             evicted rather than refusing, so JarLimits needs raising"
        );
    }
    held
}

/// Asserts a lookup really returns cookies before its timing is trusted.
fn check_lookup(jar: &Jar, url: &Url, context: &CookieContext, expect_cookies: usize) {
    let value = jar.cookies_for(url, context).unwrap_or_else(|| {
        panic!(
            "cookies_for returned None for {url}; this benchmark would be timing an \
             early return rather than a lookup"
        )
    });
    let text = value.to_str().expect("a Cookie header must be ASCII");
    let count = text
        .split(';')
        .filter(|part| !part.trim().is_empty())
        .count();
    assert_eq!(
        count, expect_cookies,
        "cookies_for returned {count} cookies, expected {expect_cookies}"
    );
}

fn benches(c: &mut Criterion) {
    let context = CookieContext::conservative_default();
    let target = site(0);

    let mut lookup = c.benchmark_group("cookies_for");

    for total in TOTALS {
        let jar = Jar::with_limits(roomy_limits());
        fill(&jar, 1, total, Some(total));
        check_lookup(&jar, &target, &context, total);
        lookup.bench_with_input(BenchmarkId::new("single_domain", total), &total, |b, _| {
            b.iter(|| black_box(jar.cookies_for(black_box(&target), &context)));
        });
    }

    for total in TOTALS {
        let domains = total.div_ceil(SPREAD_BUCKET);
        let jar = Jar::with_limits(roomy_limits());
        fill(&jar, domains, SPREAD_BUCKET, Some(total));
        check_lookup(&jar, &target, &context, SPREAD_BUCKET.min(total));
        lookup.bench_with_input(BenchmarkId::new("spread", total), &total, |b, _| {
            b.iter(|| black_box(jar.cookies_for(black_box(&target), &context)));
        });
    }

    lookup.finish();

    let mut write = c.benchmark_group("store");

    let plain = HeaderValue::from_static("sid=abc123; Path=/");
    let attributed = HeaderValue::from_static(
        "sid=abc123; Path=/; Domain=site0.com; Max-Age=3600; \
         Expires=Wed, 09 Jun 2027 10:18:14 GMT; Secure; HttpOnly; SameSite=Lax",
    );

    {
        let jar = Jar::with_limits(roomy_limits());
        write.bench_function("into_empty_jar", |b| {
            b.iter(|| jar.store(black_box(&target), &mut std::iter::once(&plain)));
        });
    }
    {
        let jar = Jar::with_limits(roomy_limits());
        write.bench_function("into_empty_jar_all_attributes", |b| {
            b.iter(|| jar.store(black_box(&target), &mut std::iter::once(&attributed)));
        });
    }

    for total in TOTALS {
        let domains = total.div_ceil(SPREAD_BUCKET);
        let jar = Jar::with_limits(roomy_limits());
        fill(&jar, domains, SPREAD_BUCKET, Some(total));
        write.bench_with_input(
            BenchmarkId::new("replace_in_jar_of", total),
            &total,
            |b, _| {
                b.iter(|| jar.store(black_box(&target), &mut std::iter::once(&plain)));
            },
        );
    }

    // The state a long-running crawler is permanently in: default limits, jar
    // full. `replace` never evicts; `insert` evicts on nearly every call, since
    // the cycled names far outnumber what one domain is allowed to hold.
    let default_cap = JarLimits::default().total;
    let fresh: Vec<HeaderValue> = (0..4096).map(set_cookie).collect();

    {
        let jar = Jar::with_limits(JarLimits::default());
        let held = fill(&jar, default_cap / SPREAD_BUCKET, SPREAD_BUCKET, None);
        assert_eq!(
            held, default_cap,
            "the default-cap fixture must sit exactly at the cap"
        );
        write.bench_function("at_default_cap/replace", |b| {
            b.iter(|| jar.store(black_box(&target), &mut std::iter::once(&plain)));
        });
    }
    {
        let jar = Jar::with_limits(JarLimits::default());
        let held = fill(&jar, default_cap / SPREAD_BUCKET, SPREAD_BUCKET, None);
        assert_eq!(held, default_cap);
        let mut next = 0usize;
        write.bench_function("at_default_cap/insert", |b| {
            b.iter(|| {
                let header = &fresh[next % fresh.len()];
                next += 1;
                jar.store(black_box(&target), &mut std::iter::once(header));
            });
        });
        assert_eq!(
            jar.export().cookies.len(),
            default_cap,
            "the jar must still sit at its cap after the insert benchmark"
        );
    }

    write.finish();
}

criterion_group! {
    name = cookie;
    config = Criterion::default().sample_size(100);
    targets = benches
}
criterion_main!(cookie);
