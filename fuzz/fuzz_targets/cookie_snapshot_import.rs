//! `Jar::import`, the path that rebuilds a jar from bytes that have been outside
//! the process.
//!
//! Every other way into the jar goes through `Cookie::parse`, which only ever sees
//! a `Set-Cookie` header value and therefore inherits that grammar's constraints
//! for free. A snapshot inherits nothing: `CookieRecord` is a public `Deserialize`
//! type whose fields a caller fills in directly, from a file they stored wherever
//! they liked. The hand-written defences that fact forced — the name-prefix
//! re-check, the representability check, the saturating sequence counters — are
//! what this target aims at, so the input is JSON: arbitrary bytes are parsed into
//! a `JarSnapshot` and only a document that deserialises reaches `import`.
//!
//! Deliberately not covered: the `Set-Cookie` grammar (`cookie_set_cookie`), the
//! date grammar (`cookie_expires_date`), and serde's JSON parser, which is not
//! this project's code and is fuzzed by its own project. The per-domain half of
//! `JarLimits` is not asserted either, because grouping records into buckets needs
//! the crate-private registrable-domain function; the total cap below is the half
//! a caller can check from outside.

#![no_main]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chromulate_cookie::{Clock, CookieRecord, Jar, JarLimits, JarSnapshot};
use chromulate_core::{CookieContext, CookieStore};
use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use url::Url;

/// Far below the shipped defaults of 180 and 3000, for the reason
/// `compression_decode` arms its expansion guard low: no fuzzer reaches a
/// 3000-cookie snapshot inside a CI time budget, so a cap that size is a branch
/// the corpus can never take.
const LIMITS: JarLimits = JarLimits {
    per_domain: 4,
    total: 8,
};

/// The jar the canary check below uses, where eviction must *not* bind.
const ROOMY_LIMITS: JarLimits = JarLimits {
    per_domain: 180,
    total: 3000,
};

/// How many records the canary check tolerates before it stops trusting that
/// nothing was evicted. One under a quarter of `ROOMY_LIMITS.per_domain`, so even
/// a snapshot that lands every record in one bucket stays well clear of the cap.
const CANARY_HEADROOM: usize = 40;

/// The site the canary is stored on. A record naming it could replace the canary
/// outright — `import` documents that it does — so such a snapshot skips the check
/// rather than reporting the replacement as a suppression.
const CANARY_SITE: &str = "canary.example";

/// A clock frozen at 2026-08-04, so whether a record has expired depends on the
/// input and nothing else.
///
/// `Jar::new` reads the wall clock, which would make the same bytes import
/// differently either side of an `expires` value and leave a crash that only
/// reproduces during the minute it was found.
#[derive(Debug)]
struct FrozenClock;

impl Clock for FrozenClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_785_801_600)
    }
}

/// `chromulate_cookie`'s `keeps_name_prefix_promise`, restated because it is
/// crate-private.
///
/// A second copy on purpose, not a workaround for the visibility: an oracle that
/// calls the function under test agrees with it by construction, including on the
/// day both are wrong together. This one is written from RFC 6265bis §4.1.3 — a
/// `__Host-` cookie is `Secure`, host-only and scoped to `/`; a `__Secure-` cookie
/// is `Secure` — and matched case-insensitively, which is how a browser matches a
/// prefix.
fn keeps_name_prefix_promise(record: &CookieRecord) -> bool {
    fn has_prefix(name: &str, prefix: &str) -> bool {
        name.as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    }

    if has_prefix(&record.name, "__Host-") {
        return record.secure && record.host_only && record.path == "/";
    }
    if has_prefix(&record.name, "__Secure-") {
        return record.secure;
    }
    true
}

/// `chromulate_cookie`'s `is_representable`, restated for the same reason: a name
/// and value that can go into a `Cookie` request header without corrupting it.
fn is_representable(record: &CookieRecord) -> bool {
    fn header_safe(text: &str) -> bool {
        text.bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    }

    !record.name.is_empty()
        && header_safe(&record.name)
        && header_safe(&record.value)
        && !record.name.contains([';', '='])
        && !record.value.contains(';')
}

/// What must be true of everything the jar is holding, whatever it was handed.
fn jar_holds_only_valid_cookies(snapshot: &JarSnapshot, stage: &str) {
    assert!(
        snapshot.cookies.len() <= LIMITS.total,
        "{stage}: the jar holds {} cookies against a total cap of {}",
        snapshot.cookies.len(),
        LIMITS.total
    );

    for record in &snapshot.cookies {
        assert!(
            keeps_name_prefix_promise(record),
            "{stage}: {:?} is in the jar with secure={}, host_only={}, path={:?}, \
             which is not what its own name prefix promises",
            record.name,
            record.secure,
            record.host_only,
            record.path
        );
        assert!(
            is_representable(record),
            "{stage}: {:?}={:?} is in the jar but cannot go in a Cookie header",
            record.name,
            record.value
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(snapshot) = serde_json::from_slice::<JarSnapshot>(data) else {
        return;
    };

    let jar = Jar::with_clock_and_limits(Arc::new(FrozenClock), LIMITS);
    jar.import(&snapshot);
    let imported = jar.export();
    jar_holds_only_valid_cookies(&imported, "after import");

    // The read path as well as the write one: a record that should not have been
    // accepted does its damage here, where the `Cookie` header is built, rather
    // than at the moment it was stored. Both schemes, because `Secure` decides
    // which cookies a plaintext request may see.
    for target in ["https://example.com/", "http://example.com/nested/path"] {
        let target = Url::parse(target).expect("a literal URL parses");
        let _ = jar.cookies_for(&target, &CookieContext::conservative_default());
    }

    // A snapshot the jar produced must import back into an empty jar unchanged.
    // `export` omits expired cookies and `import` drops them, and both apply the
    // prefix and representability rules, so a record lost on the way back is the
    // two halves disagreeing about the same record.
    let restored = Jar::with_clock_and_limits(Arc::new(FrozenClock), LIMITS);
    restored.import(&imported);
    let round_tripped = restored.export();
    jar_holds_only_valid_cookies(&round_tripped, "after round trip");
    assert_eq!(
        round_tripped.cookies.len(),
        imported.cookies.len(),
        "a snapshot the jar produced lost records when imported back into an empty jar"
    );

    // One unusable record must cost that record and nothing else. The bug this
    // guards took every cookie for a site down with it, which no count can see:
    // the cookies are still in the jar, it is the header built from them that
    // fails. Skipped when the snapshot could legitimately evict or replace the
    // canary, so that documented behaviour is not reported as suppression.
    if snapshot.cookies.len() <= CANARY_HEADROOM
        && !snapshot
            .cookies
            .iter()
            .any(|record| record.domain.contains(CANARY_SITE))
    {
        let jar = Jar::with_clock_and_limits(Arc::new(FrozenClock), ROOMY_LIMITS);
        jar.import(&snapshot);

        let target = Url::parse("https://canary.example/").expect("a literal URL parses");
        let canary = HeaderValue::from_static("canary=1; Path=/");
        jar.store(&target, &mut std::iter::once(&canary));

        assert!(
            jar.cookies_for(&target, &CookieContext::conservative_default())
                .is_some(),
            "an imported record suppressed a cookie stored afterwards on a site it does not name"
        );
    }
});
