//! Golden tests tying the shipped Chrome profile to the capture it came from.
//!
//! The single most important assertion in this crate is
//! `the_chrome_profile_reproduces_the_captured_ja4`: if it fails, the profile
//! describes a browser that does not exist.

use chromulate_profile::{CHROME_STABLE_CAPTURE, Platform, Profile, ProfileRegistry};

/// The copy the fingerprint crate's own golden tests run against.
const FINGERPRINT_CRATE_CAPTURE: &str =
    include_str!("../../chromulate-fingerprint/tests/data/chrome-151-macos.json");

#[test]
fn the_chrome_profile_reproduces_the_captured_ja4() {
    let chrome = Profile::chrome_stable();

    assert_eq!(chrome.ja4(), "t13d1516h2_8daaf6152771_806a8c22fdea");
    assert_eq!(
        chrome.ja4_raw(),
        "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9\
         _0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01\
         _0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
    );
}

#[test]
fn the_chrome_profile_reproduces_the_captured_ja4_on_a_resumed_connection() {
    let resumed = Profile::chrome_stable().with_session_resumption();

    assert_eq!(resumed.ja4(), "t13d1517h2_8daaf6152771_a87ad97598a9");
}

#[test]
fn the_chrome_profile_reproduces_the_captured_akamai_fingerprint() {
    let chrome = Profile::chrome_stable();

    assert_eq!(
        chrome.akamai_http2(),
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
}

#[test]
fn the_profile_offers_the_captured_ciphers_in_the_captured_order() {
    // JA4 sorts the cipher list before hashing, so it cannot see a transposed
    // pair. JA3 does not sort, which makes its cipher field the check that
    // catches an ordering mistake in the transcribed constants.
    let chrome = Profile::chrome_stable();
    let cipher_field = |fingerprint: &str| {
        fingerprint
            .split(',')
            .nth(1)
            .expect("a JA3 string has five comma separated fields")
            .to_owned()
    };

    assert_eq!(
        cipher_field(&chrome.ja3()),
        "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53"
    );
}

#[test]
fn the_hand_written_profile_equals_the_one_loaded_from_the_capture() {
    let transcribed = Profile::chrome_stable();
    let loaded = Profile::from_capture(CHROME_STABLE_CAPTURE)
        .expect("the shipped capture must load into a profile");

    assert_eq!(transcribed, loaded);
}

#[test]
fn the_shipped_capture_is_the_same_file_the_fingerprint_crate_tests_against() {
    assert_eq!(
        CHROME_STABLE_CAPTURE, FINGERPRINT_CRATE_CAPTURE,
        "the two copies of the capture have drifted apart"
    );
}

#[test]
fn the_profile_identity_fields_come_out_of_the_captured_user_agent() {
    let chrome = Profile::chrome_stable();

    assert_eq!(chrome.name, "chrome");
    assert_eq!(chrome.version, "151.0.0.0");
    assert_eq!(chrome.platform, Platform::MacOs);
    assert_eq!(
        chrome.user_agent,
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/151.0.0.0 Safari/537.36"
    );
}

#[test]
fn the_rendered_client_hints_match_the_headers_that_were_observed() {
    let chrome = Profile::chrome_stable();

    assert_eq!(chrome.sec_ch_ua(), chrome.observed_headers["sec-ch-ua"]);
    assert_eq!(
        chrome.sec_ch_ua_platform(),
        chrome.observed_headers["sec-ch-ua-platform"]
    );
    assert_eq!(
        chrome.sec_ch_ua(),
        "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\""
    );
}

#[test]
fn the_accept_headers_match_the_ones_that_were_observed() {
    let chrome = Profile::chrome_stable();

    assert_eq!(chrome.accept, chrome.observed_headers["accept"]);
    assert_eq!(
        chrome.accept_language,
        chrome.observed_headers["accept-language"]
    );
    assert_eq!(
        chrome.accept_encoding,
        chrome.observed_headers["accept-encoding"]
    );
    assert_eq!(chrome.accept_encoding, "gzip, deflate, br, zstd");
}

#[test]
fn the_navigation_header_order_is_the_captured_one() {
    let chrome = Profile::chrome_stable();

    assert_eq!(
        chrome.header_order.navigate,
        vec![
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
}

#[test]
fn no_subresource_order_is_claimed_because_none_was_captured() {
    let chrome = Profile::chrome_stable();

    assert!(
        chrome.header_order.subresource.is_none(),
        "the capture recorded only a navigation, so no subresource order may be claimed"
    );
    assert_eq!(
        chrome.header_order.subresource_or_navigate(),
        chrome.header_order.navigate.as_slice(),
        "callers fall back to the navigation order rather than to an invented one"
    );
}

#[test]
fn the_profile_ja3_changes_between_connections_while_ja4_does_not() {
    let chrome = Profile::chrome_stable();
    let spec = &chrome.client_hello;

    let first = chromulate_fingerprint::ja3_with_extension_order(
        spec,
        &spec.wire_extension_order_seeded(1),
    );
    let second = chromulate_fingerprint::ja3_with_extension_order(
        spec,
        &spec.wire_extension_order_seeded(2),
    );

    assert_ne!(
        first, second,
        "Chrome permutes its extensions, so JA3 must not be stable"
    );
    assert_eq!(chrome.ja4(), "t13d1516h2_8daaf6152771_806a8c22fdea");
}

#[test]
fn a_profile_loaded_from_a_user_supplied_capture_keeps_its_provenance() {
    let loaded = Profile::from_capture(CHROME_STABLE_CAPTURE).expect("the capture must load");
    let provenance = loaded
        .provenance
        .expect("a profile built from a capture records where it came from");

    assert_eq!(provenance.browser, "Google Chrome 151.0.0.0");
    assert_eq!(provenance.captured_at, "2026-08-04");
    assert_eq!(
        provenance.capture_method,
        "browser automation, two separate TLS connections"
    );
}

#[test]
fn a_capture_whose_extension_set_contradicts_its_recorded_handshake_is_rejected() {
    // A browser that does not permute — the population `from_capture` exists to
    // serve — records one authoritative order, so a set wider than that order
    // describes two different handshakes. Loading it used to succeed and leave
    // `ja3()` and `ja4()` reporting different extension counts for the one
    // connection, with nothing to notice it.
    let mut document: serde_json::Value =
        serde_json::from_str(CHROME_STABLE_CAPTURE).expect("the shipped capture is JSON");
    document["_finding_extension_order_is_randomised"]["verified"] = serde_json::json!(false);
    document["client_hello"]["extension_set_sorted"]
        .as_array_mut()
        .expect("the capture lists its extension set")
        .push(serde_json::json!(0x0015));

    let error = Profile::from_capture(&document.to_string())
        .expect_err("an internally inconsistent capture must not load");

    assert!(error.is_user_error(), "{error}");
    assert!(
        error.to_string().contains("0x0015"),
        "the error must name the extension the two sides disagree on: {error}"
    );
}

#[test]
fn a_capture_that_is_not_a_capture_is_rejected_with_a_readable_error() {
    let error = Profile::from_capture("{\"nope\": true}")
        .expect_err("an unrelated JSON document is not a capture");

    assert!(error.is_user_error(), "{error}");
    assert!(error.to_string().contains("capture"), "{error}");
}

#[test]
fn the_registry_hands_back_a_profile_that_still_matches_the_capture() {
    let registry = ProfileRegistry::with_builtin();
    let chrome = registry
        .require("chrome")
        .expect("chrome is a builtin profile");

    assert_eq!(chrome.ja4(), "t13d1516h2_8daaf6152771_806a8c22fdea");
}
