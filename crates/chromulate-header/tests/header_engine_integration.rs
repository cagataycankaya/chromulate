//! Integration tests exercising `HeaderEngine::apply` end to end: caller
//! overrides, transport-dependent `Host`, referrer policy, and high-entropy
//! client hint escalation.

use std::sync::Arc;

use chromulate_core::{Body, Origin, Request, RequestOptions};
use chromulate_header::{AcceptChStore, HeaderEngine, HighEntropyHints};
use chromulate_profile::Profile;
use http::header::USER_AGENT;
use http::{HeaderValue, Method, Version};
use url::Url;

fn engine() -> HeaderEngine {
    HeaderEngine::new(Arc::new(Profile::chrome_stable()))
}

fn navigation_to(url: &str, version: Version) -> (Request, Url, RequestOptions) {
    let target = Url::parse(url).expect("test url should parse");
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(target.as_str())
        .version(version)
        .body(Body::empty())
        .expect("request should build");
    (request, target, RequestOptions::navigation())
}

#[test]
fn a_caller_set_user_agent_survives_and_keeps_its_profile_position() {
    let engine = engine();
    let (mut request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
    request
        .headers_mut()
        .insert(USER_AGENT, HeaderValue::from_static("curl/8.0"));

    let emitted = engine
        .apply(&mut request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");

    let position = emitted
        .iter()
        .position(|(name, _)| name.as_str() == "user-agent")
        .expect("user-agent should still be emitted");
    let expected_position = Profile::chrome_stable()
        .header_order
        .navigate
        .iter()
        .position(|name| name == "user-agent")
        .expect("the profile order includes user-agent");

    assert_eq!(position, expected_position);
    assert_eq!(emitted[position].1, HeaderValue::from_static("curl/8.0"));
}

#[test]
fn host_is_absent_over_http2_and_present_over_http1() {
    let engine = engine();

    let (mut h2_request, url, options) = navigation_to("https://example.com/", Version::HTTP_2);
    let h2_emitted = engine
        .apply(&mut h2_request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");
    assert!(
        h2_emitted.iter().all(|(name, _)| name.as_str() != "host"),
        "HTTP/2 must never carry a Host header"
    );

    let (mut h1_request, url, options) = navigation_to("https://example.com/", Version::HTTP_11);
    let h1_emitted = engine
        .apply(&mut h1_request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");
    let host_value = h1_emitted
        .iter()
        .find(|(name, _)| name.as_str() == "host")
        .map(|(_, value)| value.to_str().expect("host is ascii"));
    assert_eq!(host_value, Some("example.com"));
}

#[test]
fn referer_is_suppressed_on_a_secure_to_insecure_downgrade() {
    let engine = engine();
    let (mut request, url, mut options) =
        navigation_to("http://insecure.example/", Version::HTTP_2);
    options.referrer =
        Some(Url::parse("https://example.com/page").expect("referrer url should parse"));

    let emitted = engine
        .apply(&mut request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");

    assert!(
        emitted.iter().all(|(name, _)| name.as_str() != "referer"),
        "a secure-to-insecure downgrade must never leak a Referer"
    );
}

#[test]
fn referer_is_present_and_computed_by_the_engine_when_the_referrer_policy_allows_it() {
    let engine = engine();
    let (mut request, url, mut options) = navigation_to("https://example.com/", Version::HTTP_2);
    options.referrer =
        Some(Url::parse("https://example.com/start").expect("referrer url should parse"));

    let emitted = engine
        .apply(&mut request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");

    let referer = emitted
        .iter()
        .find(|(name, _)| name.as_str() == "referer")
        .map(|(_, value)| value.to_str().expect("referer is ascii"));
    assert_eq!(referer, Some("https://example.com/start"));
}

#[test]
fn a_high_entropy_hint_is_sent_only_after_accept_ch_grants_it_and_only_to_that_origin() {
    let hints = HighEntropyHints {
        arch: Some("arm".to_owned()),
        ..HighEntropyHints::default()
    };
    let engine =
        HeaderEngine::new(Arc::new(Profile::chrome_stable())).with_high_entropy_hints(hints);

    let (mut first_request, url, options) =
        navigation_to("https://granted.example/", Version::HTTP_2);
    let first = engine
        .apply(&mut first_request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");
    assert!(
        first
            .iter()
            .all(|(name, _)| name.as_str() != "sec-ch-ua-arch"),
        "a high-entropy hint must not be sent before a server asks for it"
    );

    let mut store = AcceptChStore::new();
    let granted_origin = Origin::of(&url).expect("target should have an origin");
    store.record(granted_origin, "Sec-CH-UA-Arch");

    let (mut second_request, _, _) = navigation_to("https://granted.example/", Version::HTTP_2);
    let second = engine
        .apply(&mut second_request, &url, &options, &store)
        .expect("header planning should succeed");
    let arch = second
        .iter()
        .find(|(name, _)| name.as_str() == "sec-ch-ua-arch")
        .map(|(_, value)| value.to_str().expect("arch is ascii"));
    assert_eq!(arch, Some("arm"));

    let (mut other_request, other_url, other_options) =
        navigation_to("https://not-granted.example/", Version::HTTP_2);
    let other = engine
        .apply(&mut other_request, &other_url, &other_options, &store)
        .expect("header planning should succeed");
    assert!(
        other
            .iter()
            .all(|(name, _)| name.as_str() != "sec-ch-ua-arch"),
        "a grant to one origin must not leak to another"
    );
}
