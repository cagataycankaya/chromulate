//! The single most important test in this crate: a cross-site navigation
//! built with the shipped Chrome profile must emit headers in exactly the
//! order Chrome 151 was observed sending them in, with exactly the values
//! it was observed sending.

use std::sync::Arc;

use chromulate_core::{Body, Origin, Request, RequestOptions};
use chromulate_header::{AcceptChStore, HeaderEngine};
use chromulate_profile::Profile;
use http::{Method, Version};
use url::Url;

/// A navigation to `https://example.com/`, initiated by a different site,
/// over HTTP/2 — the same shape the Chrome 151 capture recorded.
fn cross_site_navigation_request() -> (Request, Url, RequestOptions) {
    let target = Url::parse("https://example.com/").expect("target url should parse");
    let initiator_url = Url::parse("https://other-site.test/").expect("initiator url should parse");
    let initiator = Origin::of(&initiator_url).expect("initiator should have an origin");

    let mut options = RequestOptions::navigation();
    options.initiator = Some(initiator);

    let request = http::Request::builder()
        .method(Method::GET)
        .uri(target.as_str())
        .version(Version::HTTP_2)
        .body(Body::empty())
        .expect("request should build");

    (request, target, options)
}

#[test]
fn a_cross_site_navigation_emits_headers_in_exactly_chromes_captured_order() {
    let profile = Arc::new(Profile::chrome_stable());
    let engine = HeaderEngine::new(profile.clone());
    let (mut request, url, options) = cross_site_navigation_request();

    let emitted = engine
        .apply(&mut request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");

    let emitted_names: Vec<String> = emitted
        .iter()
        .map(|(name, _)| name.as_str().to_owned())
        .collect();

    assert_eq!(
        emitted_names, profile.header_order.navigate,
        "emitted header order must equal Chrome's captured navigation order exactly"
    );
}

#[test]
fn a_cross_site_navigation_emits_chromes_captured_header_values() {
    let profile = Arc::new(Profile::chrome_stable());
    let engine = HeaderEngine::new(profile.clone());
    let (mut request, url, options) = cross_site_navigation_request();

    let emitted = engine
        .apply(&mut request, &url, &options, &AcceptChStore::new())
        .expect("header planning should succeed");

    for (name, value) in &emitted {
        let value = value.to_str().expect("captured header values are ascii");
        if name.as_str() == "user-agent" {
            assert_eq!(
                value, profile.user_agent,
                "user-agent must match the capture"
            );
            continue;
        }
        let expected = profile
            .observed_headers
            .get(name.as_str())
            .unwrap_or_else(|| panic!("{name} has no observed value to compare against"));
        assert_eq!(value, expected, "value for {name} must match the capture");
    }
}
