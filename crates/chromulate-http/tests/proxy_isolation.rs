//! What the engine keeps per exit address, driven over real sockets.
//!
//! The cookie half of this property is proved at the facade, where the default
//! lives (`chromulate/tests/proxy_isolation.rs`). What is here is the part the
//! facade cannot reach: validators, which have no `ClientBuilder` method, and
//! the response cache, which an isolated engine refuses to share.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chromulate_cookie::Jar;
use chromulate_core::{Body, CookieStore, Request};
use chromulate_http::{Engine, EngineConfig, ProxyIsolation, SessionFactory};
use chromulate_profile::Profile;
use chromulate_proxy::{Proxy, ProxyProvider, ProxyUrl, RoundRobin};
use common::{Recorded, Reply, TestProxy, TestServer};
use http::Method;

/// Mints a fresh jar for every exit, which is what an isolated engine has to be
/// handed because this crate holds cookies behind `CookieStore` and cannot make
/// one itself.
struct Jars;

impl SessionFactory for Jars {
    fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
        Some(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
    }
}

fn rotating(proxies: &[&TestProxy]) -> Arc<dyn ProxyProvider> {
    let pool = proxies
        .iter()
        .map(|proxy| {
            Proxy::new(ProxyUrl::parse(&proxy.url()).expect("a loopback proxy URL must parse"))
        })
        .collect();
    Arc::new(RoundRobin::new(pool))
}

fn config() -> EngineConfig {
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    config
}

fn get(url: &str) -> Request {
    http::Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Body::empty())
        .expect("a valid request")
}

async fn send(engine: &Engine, path: &str) {
    let response = engine
        .send(get(&format!("http://shop.test{path}")))
        .await
        .expect("the request must reach the origin");
    let _ = response
        .into_body()
        .collect(64 * 1024)
        .await
        .expect("the body must arrive");
}

// ---------------------------------------------------------------- validators

/// An `If-None-Match` for a URL only one exit has ever fetched tells the origin
/// that the two exits are one client. It is the same linking signal a cookie
/// is, arriving in a different header.
#[cfg(feature = "validator-store")]
#[tokio::test]
async fn a_validator_learned_through_one_exit_is_not_replayed_through_another() {
    let server = TestServer::start(|_: &Recorded| Reply::ok().with_header("etag", "\"v1\"")).await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let engine = Engine::builder(config())
        .proxies(rotating(&[&first, &second]))
        .validators(Arc::new(chromulate_http::ValidatorStore::new()))
        .isolate_by_proxy(8, Arc::new(Jars))
        .build()
        .expect("the engine must build");

    send(&engine, "/product").await; // first exit, learns the ETag
    send(&engine, "/product").await; // second exit, has never seen it
    send(&engine, "/product").await; // first exit again

    let received = server.received();
    assert_eq!(
        received[1].header("if-none-match"),
        None,
        "the second exit must not replay a validator the origin issued to the first"
    );
    assert_eq!(
        received[2].header("if-none-match"),
        Some("\"v1\""),
        "the exit that was issued the validator must still replay it"
    );
}

/// The control: with one session the very same run replays the validator
/// through the other exit, which is what makes the assertion above a property
/// of isolation rather than of the test setup.
#[cfg(feature = "validator-store")]
#[tokio::test]
async fn a_shared_engine_replays_a_validator_through_every_exit() {
    let server = TestServer::start(|_: &Recorded| Reply::ok().with_header("etag", "\"v1\"")).await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let engine = Engine::builder(config())
        .proxies(rotating(&[&first, &second]))
        .validators(Arc::new(chromulate_http::ValidatorStore::new()))
        .build()
        .expect("the engine must build");

    assert_eq!(engine.proxy_isolation(), ProxyIsolation::Shared);

    send(&engine, "/product").await;
    send(&engine, "/product").await;

    assert_eq!(
        server.received()[1].header("if-none-match"),
        Some("\"v1\""),
        "one session means one validator memory, which is the behaviour being opted out of"
    );
}

// -------------------------------------------------------------------- cookies

/// The engine's own half of the facade's reproduction, so the mechanism is
/// covered where it lives and not only where it is configured.
#[tokio::test]
async fn each_exit_gets_a_jar_of_its_own_from_the_factory() {
    let server = TestServer::start(|request: &Recorded| {
        if request.target == "/set" {
            Reply::ok().with_header("set-cookie", "tenant=one; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let engine = Engine::builder(config())
        .proxies(rotating(&[&first, &second]))
        .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
        .isolate_by_proxy(8, Arc::new(Jars))
        .build()
        .expect("the engine must build");

    assert_eq!(
        engine.isolated_routes(),
        0,
        "nothing is minted until it is used"
    );

    send(&engine, "/set").await;
    send(&engine, "/read").await;
    send(&engine, "/read").await;

    assert_eq!(
        engine.isolated_routes(),
        2,
        "one route per exit, and no more"
    );
    let received = server.received();
    assert_eq!(received[1].header("cookie"), None);
    assert_eq!(received[2].header("cookie"), Some("tenant=one"));
}

/// The cap is a ceiling on the whole family of stores, not a suggestion, and it
/// is what keeps per-exit splitting from turning one bounded map into an
/// unbounded number of them.
#[tokio::test]
async fn the_cap_bounds_how_many_exits_hold_state_at_once() {
    let server = TestServer::always(Reply::ok()).await;
    let exits: Vec<TestProxy> = {
        let mut exits = Vec::new();
        for _ in 0..3 {
            exits.push(TestProxy::start(server.addr()).await);
        }
        exits
    };

    let engine = Engine::builder(config())
        .proxies(rotating(&exits.iter().collect::<Vec<_>>()))
        .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
        .isolate_by_proxy(2, Arc::new(Jars))
        .build()
        .expect("the engine must build");

    assert_eq!(
        engine.proxy_isolation(),
        ProxyIsolation::PerProxy { max_routes: 2 }
    );

    for _ in 0..6 {
        send(&engine, "/").await;
    }

    assert_eq!(
        engine.isolated_routes(),
        2,
        "three exits through a cap of two must never hold three sessions"
    );
}

// ---------------------------------------------------------------- the cache

/// One cache cannot serve isolated routes, and the engine says so at build time
/// rather than sharing one and hoping.
#[cfg(feature = "cache")]
#[test]
fn a_response_cache_cannot_be_shared_between_isolated_routes() {
    let error = Engine::builder(config())
        .cache(Arc::new(chromulate_http::HttpCache::new()))
        .isolate_by_proxy(8, Arc::new(Jars))
        .build()
        .expect_err("one cache across isolated exits is a contradiction");
    let message = error.to_string();
    assert!(message.contains("cache"), "{message}");
    assert!(message.contains("isolate_by_proxy"), "{message}");
}

/// And an engine that shares its routes still takes a cache, because there the
/// combination means what it says.
#[cfg(feature = "cache")]
#[test]
fn a_shared_engine_still_takes_a_response_cache() {
    let engine = Engine::builder(config())
        .cache(Arc::new(chromulate_http::HttpCache::new()))
        .build()
        .expect("a shared engine and a cache are not in conflict");
    assert_eq!(engine.proxy_isolation(), ProxyIsolation::Shared);
}
