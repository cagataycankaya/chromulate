//! Whether a connection to a real origin is actually reused.
//!
//! These tests reach the public internet, so they are behind the
//! `network-tests` feature *and* `#[ignore]`: `cargo test --workspace` stays
//! hermetic, and CI runs them in a separate job.
//!
//! ```text
//! cargo test -p chromulate-http --features network-tests -- --ignored --nocapture
//! ```
//!
//! They exist because the hermetic harness structurally cannot answer this
//! question. The loopback benchmark server is plaintext, ALPN never runs, and
//! `chromulate_http::connect` therefore only ever produces HTTP/1.1 there — so
//! no offline test in this repository exercises the HTTP/2 connection at all.
//! An HTTP/2 connection that is never pooled costs a TCP round trip and a full
//! TLS handshake on **every** request against every modern origin, and nothing
//! offline would notice.

#![cfg(feature = "network-tests")]

use std::sync::Arc;

use chromulate_core::Body;
use chromulate_http::{Engine, EngineConfig, Pool, PoolConfig};
use chromulate_profile::Profile;

/// An origin that negotiates HTTP/2 over ALPN and answers a small GET.
///
/// The `www` host is deliberate: the apex redirects to it, and a redirect would
/// leave two origins in the pool and turn a count of one into a count of two
/// for a reason that has nothing to do with what these tests are checking.
const HTTP2_ORIGIN: &str = "https://www.cloudflare.com/robots.txt";

fn engine_with(pool: Pool) -> Engine {
    Engine::builder(EngineConfig::new(Arc::new(Profile::chrome_stable())))
        .pool(pool)
        .build()
        .expect("the engine must build")
}

async fn fetch(engine: &Engine, url: &str) -> http::Version {
    let request = http::Request::builder()
        .uri(url)
        .body(Body::empty())
        .expect("the request must build");
    let response = engine.send(request).await.expect("the origin must answer");
    let version = response.version();
    // The body has to be drained: an HTTP/1.1 connection is only returned to
    // the pool once its response body ends, so a test that dropped the body
    // would be measuring an abandoned connection rather than a kept one.
    response
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the body must arrive");
    version
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn an_http2_connection_is_pooled_after_the_first_request() {
    let pool = Pool::new(PoolConfig::default());
    let engine = engine_with(pool.clone());

    assert_eq!(pool.len(), 0, "a fresh pool holds nothing");

    let version = fetch(&engine, HTTP2_ORIGIN).await;
    assert_eq!(
        version,
        http::Version::HTTP_2,
        "this test is about the HTTP/2 path; the origin negotiated {version:?} instead"
    );

    assert_eq!(
        pool.len(),
        1,
        "after one HTTP/2 request the connection must be in the pool. A pool holding nothing \
         means every later request re-opens a TCP connection and repeats the TLS handshake, \
         which is invisible to every offline benchmark in this repository because the loopback \
         origin is plaintext and never negotiates HTTP/2."
    );
}

#[tokio::test]
#[ignore = "reaches the public internet"]
async fn repeated_http2_requests_share_one_connection() {
    let pool = Pool::new(PoolConfig::default());
    let engine = engine_with(pool.clone());

    for attempt in 1..=3 {
        fetch(&engine, HTTP2_ORIGIN).await;
        assert_eq!(
            pool.len(),
            1,
            "after request {attempt} the pool must still hold exactly one multiplexed \
             connection, not zero (nothing kept) and not several (a new one per request)"
        );
    }
}
