//! The adaptive law, reached the way a caller reaches it: through the seam, from
//! inside a real engine.
//!
//! `adaptive_concurrency.rs` drives the law by hand against an injected clock,
//! which is where its rules are checked. This file checks the wiring instead —
//! that an `AdaptiveConcurrency` installed on an `EngineBuilder` is consulted per
//! hop, and that the status and headers the origin actually sent survive the
//! trip across `Outcome` and are read as this law reads them.
//!
//! These two tests used to live in `chromulate-http`'s `concurrency_seam.rs`.
//! They moved with the law: that crate holds the trait and must not depend on
//! this one, dev-dependencies included, or the seam and its implementation
//! become a cycle.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chromulate_concurrency::adaptive::{AdaptiveConcurrency, Ceiling, authority_of};
use chromulate_core::{Body, Request, Response};
use chromulate_dns::StaticResolver;
use chromulate_http::concurrency::ConcurrencyController;
use chromulate_http::{Engine, EngineConfig};
use chromulate_profile::Profile;
use common::{Reply, TestServer};
use url::Url;

const HOST: &str = "origin.test";

fn engine_for(server: &TestServer, controller: Arc<dyn ConcurrencyController>) -> Engine {
    let resolver = StaticResolver::empty().with_host(HOST.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .resolver(Arc::new(resolver))
        .concurrency(controller)
        .build()
        .expect("the engine must build")
}

fn get(url: &str) -> Request {
    http::Request::builder()
        .uri(url)
        .body(Body::empty())
        .expect("a valid request")
}

fn authority(url: &str) -> String {
    authority_of(&Url::parse(url).expect("a valid url")).to_owned()
}

async fn drain(response: Response) {
    let _ = response
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the body must be readable");
}

#[tokio::test]
async fn the_adaptive_law_starts_a_new_origin_at_one_slot_through_the_engine() {
    let server = TestServer::always(Reply::text("body")).await;
    let controller = Arc::new(AdaptiveConcurrency::new(Ceiling::Unlimited));
    let engine = engine_for(
        &server,
        Arc::clone(&controller) as Arc<dyn ConcurrencyController>,
    );
    let url = server.url_for(HOST, "/default");

    for _ in 0..3 {
        let response = engine.send(get(&url)).await.expect("the request must send");
        drain(response).await;
    }

    let seen = controller
        .snapshot(&authority(&url))
        .expect("the origin was visited");
    assert_eq!(
        seen.limit, 1,
        "a new origin still starts at one and still needs the whole run of clean \
         probes to move"
    );
    assert_eq!(seen.in_flight, 0, "every lease came back");
    assert_eq!(
        seen.ceiling, 6,
        "and the ceiling is still the default maximum"
    );
}

#[tokio::test]
async fn the_adaptive_law_still_ratchets_and_pauses_on_a_429_through_the_seam() {
    let server = TestServer::always(Reply::new(429).with_header("retry-after", "60")).await;
    let controller = Arc::new(AdaptiveConcurrency::new(Ceiling::Unlimited));
    let engine = engine_for(
        &server,
        Arc::clone(&controller) as Arc<dyn ConcurrencyController>,
    );
    let url = server.url_for(HOST, "/refused");

    let response = engine.send(get(&url)).await.expect("the request must send");
    drain(response).await;

    let seen = controller
        .snapshot(&authority(&url))
        .expect("the origin was visited");
    assert_eq!(seen.ceiling, 1, "the ratchet still falls");
    assert_eq!(
        seen.retry_after_requested,
        Some(Duration::from_secs(60)),
        "and the header is still read on the way through the seam"
    );
    // The real clock is running here, so the pause left is a shade under the
    // minute that was asked for rather than exactly it.
    let left = seen.paused_for.expect("the origin is paused");
    assert!(
        left > Duration::from_secs(59) && left <= Duration::from_secs(60),
        "the pause the header asked for is what is being waited: {left:?}"
    );
    assert_eq!(seen.refusals, 1);
}
