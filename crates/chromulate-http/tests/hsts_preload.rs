//! The preload list as a caller sees it: through `HstsStore`.
//!
//! The engine asks one question before every request — `HstsStore::upgrade` —
//! and never learns where the answer came from. These tests hold that seam: they
//! only ever touch the public store API, so they would still pass if the preload
//! table were replaced wholesale, and they fail if the store stops consulting it.
//!
//! The whole file compiles away without the feature, which is the point of the
//! feature: the default build has no preload list and no test claiming it has one.
#![cfg(feature = "hsts-preload")]

use std::time::{Duration, SystemTime};

use chromulate_http::HstsStore;
use chromulate_http::hsts::preload;
use url::Url;

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

fn url(text: &str) -> Url {
    Url::parse(text).expect("test url should parse")
}

/// Every host these tests name, and what the committed blob says about it.
///
/// The fixtures below are meaningless unless the list still holds what they
/// assume, and a regenerated list can move any of it. Asserting the assumption
/// here turns "the list changed" into one clear failure instead of a scatter of
/// confusing ones, and keeps the fixture choice honest: the names are read out of
/// the data, never asserted into it.
#[test]
fn the_fixtures_these_tests_rely_on_are_what_the_committed_list_says() {
    assert_eq!(
        preload::lookup("gmail.com"),
        Some(false),
        "the includeSubDomains-absent fixture"
    );
    assert_eq!(
        preload::lookup("app"),
        Some(true),
        "the public-suffix fixture, preloaded as a whole TLD"
    );
    assert_eq!(preload::lookup("mail.gmail.com"), None);
    assert_eq!(preload::lookup("notgmail.com"), None);
    assert_eq!(
        preload::lookup("example.com"),
        None,
        "the dynamic-store tests next door use example.com and must stay unaffected"
    );
    assert_eq!(preload::lookup("evil.example"), None);
}

#[test]
fn a_preloaded_host_is_upgraded_before_any_response_has_been_seen() {
    // The case a store learned from responses structurally cannot cover: the
    // first request to an origin this process has never visited.
    let store = HstsStore::new();
    let mut target = url("http://gmail.com/mail");
    assert!(store.upgrade(&mut target, now()));
    assert_eq!(target.as_str(), "https://gmail.com/mail");
}

#[test]
fn an_ordinary_host_that_is_not_preloaded_is_left_alone() {
    // The default path. Almost every host a caller reaches is not on the list,
    // and a lookup that answered "yes" broadly would be invisible in tests that
    // only ever ask about preloaded names.
    let store = HstsStore::new();
    let mut target = url("http://example.com/page");
    assert!(!store.upgrade(&mut target, now()));
    assert_eq!(target.as_str(), "http://example.com/page");
}

#[test]
fn an_entry_without_include_subdomains_does_not_reach_a_subdomain() {
    let store = HstsStore::new();
    let mut target = url("http://mail.gmail.com/");
    assert!(
        !store.upgrade(&mut target, now()),
        "gmail.com is preloaded without includeSubDomains, so mail.gmail.com is not covered"
    );
}

#[test]
fn a_preloaded_public_suffix_covers_the_hosts_under_it() {
    // `app` is preloaded as a whole TLD with includeSubDomains. Clamping the
    // ancestor walk at the registrable domain — which is what `psl` would give —
    // makes this false and quietly drops the protection for every `.app` host.
    let store = HstsStore::new();
    for host in ["example.app", "deep.nested.example.app"] {
        let mut target = url(&format!("http://{host}/"));
        assert!(
            store.upgrade(&mut target, now()),
            "{host} should be upgraded"
        );
        assert_eq!(target.as_str(), format!("https://{host}/"));
    }
}

#[test]
fn a_sibling_that_merely_shares_a_string_suffix_is_not_upgraded() {
    let store = HstsStore::new();
    for host in ["notgmail.com", "evilapp", "xgmail.com"] {
        let mut target = url(&format!("http://{host}/"));
        assert!(
            !store.upgrade(&mut target, now()),
            "{host} shares a suffix with an entry but no label boundary"
        );
    }
}

#[test]
fn an_ip_literal_is_not_upgraded_by_the_preload_list() {
    // RFC 6797 §8.1.1 keeps IP literals out of the dynamic store; the preload
    // path sits behind the same guard rather than beside it.
    let store = HstsStore::new();
    let mut target = url("http://127.0.0.1:8080/");
    assert!(!store.upgrade(&mut target, now()));
}

#[test]
fn max_age_zero_cannot_take_a_host_off_the_preload_list() {
    // Precedence. Chromium resolves this as
    // `GetDynamicSTSState(host, result) || GetStaticSTSState(host, result)`
    // (net/http/transport_security_state.cc, revision
    // 7be0edc636b0e7b0143e2700ecf5c8af750d09ec), and `max-age=0` erases the
    // dynamic entry rather than storing a negative one — `AddHSTSInternal` calls
    // `enabled_sts_hosts_.erase` when the mode is not force-https. So the static
    // entry is what remains and the host stays upgraded. RFC 6797 §8.1 agrees on
    // the wording: max-age=0 means the UA "MUST remove its *cached* HSTS Policy
    // information", and a pre-loaded list (§12.3) is configured rather than
    // cached.
    let mut store = HstsStore::new();
    store.record("gmail.com", "max-age=31536000", true, now());
    store.record("gmail.com", "max-age=0", true, now());

    let mut target = url("http://gmail.com/");
    assert!(
        store.upgrade(&mut target, now()),
        "an origin cannot unpreload itself with a response header"
    );
}

#[test]
fn max_age_zero_still_removes_a_dynamic_policy_for_a_host_that_is_not_preloaded() {
    // The other half of the precedence claim, and the one that keeps the test
    // above from passing for the wrong reason. If `max-age=0` had simply stopped
    // removing anything, the test above would still be green; this one would not.
    let mut store = HstsStore::new();
    store.record("example.com", "max-age=31536000", true, now());
    store.record("example.com", "max-age=0", true, now());

    let mut target = url("http://example.com/");
    assert!(!store.upgrade(&mut target, now()));
}

#[test]
fn a_dynamic_policy_still_works_for_a_host_the_list_has_never_heard_of() {
    // Wiring the preload list in must not cost the dynamic store anything.
    let mut store = HstsStore::new();
    store.record("example.com", "max-age=100; includeSubDomains", true, now());

    let mut target = url("http://api.example.com/");
    assert!(store.upgrade(&mut target, now()));

    let mut expired = url("http://api.example.com/");
    assert!(!store.upgrade(&mut expired, now() + Duration::from_secs(101)));
}

#[test]
fn a_preloaded_host_stays_upgraded_after_its_dynamic_policy_expires() {
    // The dynamic answer is consulted first and is allowed to expire; the
    // preload answer behind it does not.
    let mut store = HstsStore::new();
    store.record("gmail.com", "max-age=100", true, now());

    let mut target = url("http://gmail.com/");
    assert!(store.upgrade(&mut target, now() + Duration::from_secs(1_000)));
}

/// What a preload lookup costs, measured rather than asserted.
///
/// Ignored because it is a measurement and not a guard: a timing threshold on a
/// shared CI runner fails for reasons that have nothing to do with this code.
/// Run it with
///
/// ```text
/// cargo test -p chromulate-http --features hsts-preload --release \
///     --test hsts_preload -- --ignored --nocapture
/// ```
#[test]
#[ignore = "a measurement, not a guard; run it deliberately"]
fn measure_the_cost_of_a_lookup() {
    // A mix of what a caller actually asks: a miss with no dots to walk, a miss
    // that walks two ancestors, a hit on the host itself, a hit through a TLD
    // entry, and a deep name that walks four levels before it hits.
    let hosts = [
        "localhost",
        "example.com",
        "static.assets.example.org",
        "gmail.com",
        "deep.nested.example.app",
        "notgmail.com",
    ];

    let rounds = 5;
    let per_round = 200_000;
    let mut nanos_per_lookup = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let started = std::time::Instant::now();
        let mut sink = 0u64;
        for index in 0..per_round {
            let host = hosts[index % hosts.len()];
            sink += u64::from(preload::covers(host));
        }
        let elapsed = started.elapsed();
        // Keep the loop from being optimised away without pulling a benchmark
        // harness in: the sum is a real dependency of the printed line.
        assert!(sink > 0, "round {round} answered no for every host");
        let per = elapsed.as_secs_f64() * 1e9 / per_round as f64;
        nanos_per_lookup.push(per);
        println!("round {round}: {per:.1} ns/lookup ({sink} hits of {per_round})");
    }

    let best = nanos_per_lookup
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    let worst = nanos_per_lookup.iter().copied().fold(0.0, f64::max);
    println!(
        "{rounds} rounds of {per_round} lookups over {} entries: {best:.1}-{worst:.1} ns/lookup",
        preload::ENTRY_COUNT
    );
}
