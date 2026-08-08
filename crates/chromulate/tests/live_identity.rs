//! What a real server sees, measured against what the profile targets.
//!
//! These tests reach the public internet, so they are behind the
//! `network-tests` feature *and* `#[ignore]`: `cargo test --workspace` stays
//! hermetic, and CI runs them in a separate job.
//!
//! ```text
//! cargo test -p chromulate --features network-tests -- --ignored --nocapture
//! ```
//!
//! They assert the gap rather than the absence of one. A test that demanded a
//! match would fail on every run and teach nothing; these pin down which parts
//! of the identity this stack does reproduce, so that a regression in those is
//! caught and the parts it cannot reproduce stay documented rather than
//! quietly drifting.

#![cfg(feature = "network-tests")]

use chromulate::tls::TlsBackendConfig;
use chromulate::{Client, Profile, RequestOptions};
use serde_json::Value;

/// An echo endpoint that reports the TLS and HTTP/2 fingerprints it observed.
const ECHO: &str = "https://tls.peet.ws/api/all";

async fn observed() -> Value {
    let client = Client::chrome().expect("the client must build");
    client
        .get(ECHO)
        .fetch_context(RequestOptions::navigation())
        .send()
        .await
        .expect("the echo endpoint must answer")
        .json()
        .await
        .expect("the echo endpoint returns JSON")
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn the_http2_settings_and_window_update_reach_the_wire_exactly_as_captured() {
    let report = observed().await;
    let akamai = report["http2"]["akamai_fingerprint"]
        .as_str()
        .expect("the endpoint reports an Akamai fingerprint");

    let target = Profile::chrome_stable().akamai_http2();
    let (target_settings, target_rest) = target.split_once('|').expect("four fields");
    let (settings, rest) = akamai.split_once('|').expect("four fields");

    assert_eq!(
        settings, target_settings,
        "the SETTINGS frame is fully reproducible and must match the capture"
    );

    let (target_window, target_tail) = target_rest.split_once('|').expect("four fields");
    let (window, tail) = rest.split_once('|').expect("four fields");
    assert_eq!(
        window, target_window,
        "the connection WINDOW_UPDATE increment must match the capture"
    );

    let (target_priority, target_pseudo) = target_tail.split_once('|').expect("four fields");
    let (priority, pseudo) = tail.split_once('|').expect("four fields");
    assert_eq!(
        priority, target_priority,
        "neither client sends PRIORITY frames"
    );

    // The one field h2 hard-codes. Asserted as a known difference so that a
    // future h2 that made it configurable turns this test red and prompts the
    // gap to be closed, rather than leaving a stale caveat in the docs.
    assert_eq!(target_pseudo, "m,a,s,p");
    assert_eq!(
        pseudo, "m,s,a,p",
        "h2 emits its pseudo-headers from a fixed struct order"
    );
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn the_request_headers_arrive_in_the_captured_browser_order() {
    let report = observed().await;
    let sent = report["http2"]["sent_frames"]
        .as_array()
        .expect("the endpoint reports the frames it received");

    let headers = sent
        .iter()
        .find(|frame| frame["frame_type"] == "HEADERS")
        .and_then(|frame| frame["headers"].as_array())
        .expect("a HEADERS frame must have been sent");

    let observed_order: Vec<String> = headers
        .iter()
        .filter_map(|entry| entry.as_str())
        .filter(|entry| !entry.starts_with(':'))
        .filter_map(|entry| entry.split(':').next())
        .map(str::to_owned)
        .collect();

    assert_eq!(
        observed_order,
        Profile::chrome_stable().header_order.navigate,
        "header order is fully reproducible, so it must match the capture exactly"
    );
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn the_handshake_does_not_reach_the_profiles_ja4_and_the_client_says_so() {
    let report = observed().await;
    let ja4 = report["tls"]["ja4"]
        .as_str()
        .expect("the endpoint reports JA4");

    let client = Client::chrome().expect("the client must build");
    let target = &TlsBackendConfig::target_identity(client.engine().tls()).ja4;

    assert_ne!(
        ja4, target,
        "rustls cannot emit the profile's ClientHello; a match here would mean the \
         measurement is wrong, not that the gap closed"
    );

    // The ALPN component is the part rustls does reproduce, and it sits in the
    // middle of the JA4 string as `h2`.
    assert!(ja4.starts_with("t13d"), "TLS 1.3 over TCP with SNI: {ja4}");
    assert!(ja4.contains("h2_"), "the negotiated ALPN must be h2: {ja4}");
    assert!(
        target.starts_with("t13d") && target.contains("h2_"),
        "the target agrees on those components: {target}"
    );

    // The gap is reported rather than discovered: the crate already knows.
    assert!(
        !TlsBackendConfig::fidelity(client.engine().tls()).all_primitives_available(),
        "the ring provider drops some of the profile's primitives, and says so"
    );
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn a_plain_request_to_a_real_site_succeeds_over_http2() {
    let client = Client::chrome().expect("the client must build");
    let response = client
        .get("https://example.com")
        .send()
        .await
        .expect("example.com must answer");

    assert!(response.status().is_success());
    assert_eq!(response.version(), chromulate::Version::HTTP_2);
    assert!(
        response
            .text()
            .await
            .expect("the body must decode")
            .contains("Example Domain")
    );
}
