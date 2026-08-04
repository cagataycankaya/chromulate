//! The cache, wired into the engine, driven against a real socket.
//!
//! The claim these tests exist to check is the one the unit tests structurally
//! cannot: that a hit means *no request reached the origin*. Counting what the
//! server received is the only way to see that, so every assertion below is on
//! the server's own record rather than on the response.
//!
//! The whole file compiles to nothing without the `cache` feature, which is
//! also the point: with the feature off the engine has no cache to wire.

#![cfg(feature = "cache")]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chromulate_cache::{CacheStatus, HttpCache, ManualClock};
use chromulate_core::{Body, Request, Response};
use chromulate_dns::StaticResolver;
use chromulate_http::{Engine, EngineConfig};
use chromulate_profile::Profile;
use common::{Reply, TestServer};

const HOST: &str = "cached.test";

fn engine_for(server: &TestServer, cache: Option<Arc<HttpCache>>) -> Engine {
    let resolver = StaticResolver::empty().with_host(HOST.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));

    let mut builder = Engine::builder(config).resolver(Arc::new(resolver));
    if let Some(cache) = cache {
        builder = builder.cache(cache);
    }
    builder.build().expect("the engine must build")
}

fn get(url: &str) -> Request {
    http::Request::builder()
        .uri(url)
        .body(Body::empty())
        .expect("a valid request")
}

async fn text(response: Response) -> String {
    let body = response
        .into_body()
        .collect(64 * 1024)
        .await
        .expect("the body must arrive");
    String::from_utf8_lossy(&body).into_owned()
}

fn cache_at(now: SystemTime) -> (Arc<HttpCache>, Arc<ManualClock>) {
    let clock = ManualClock::at(now);
    let cache = Arc::new(HttpCache::builder().clock(Arc::clone(&clock) as _).build());
    (cache, clock)
}

#[tokio::test]
async fn an_engine_without_a_cache_reaches_the_origin_every_time() {
    let server =
        TestServer::always(Reply::text("payload").with_header("cache-control", "max-age=600"))
            .await;
    let engine = engine_for(&server, None);
    let url = server.url_for(HOST, "/asset");

    for _ in 0..2 {
        let response = engine
            .send(get(&url))
            .await
            .expect("the request must succeed");
        assert_eq!(text(response).await, "payload");
    }

    assert_eq!(
        server.request_count(),
        2,
        "no cache was installed, so nothing may be short-circuited"
    );
}

#[tokio::test]
async fn a_fresh_entry_means_the_second_request_never_leaves_the_process() {
    let server =
        TestServer::always(Reply::text("payload").with_header("cache-control", "max-age=600"))
            .await;
    let (cache, clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let first = engine.send(get(&url)).await.expect("the first request");
    assert!(first.extensions().get::<CacheStatus>().is_none());
    assert_eq!(text(first).await, "payload");

    clock.advance(Duration::from_secs(30));
    let second = engine.send(get(&url)).await.expect("the second request");
    assert_eq!(
        second.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Hit)
    );
    assert_eq!(second.headers()["age"], "30");
    assert_eq!(text(second).await, "payload");

    assert_eq!(
        server.request_count(),
        1,
        "the second request was answered from store and must not have been sent"
    );
}

#[tokio::test]
async fn a_stale_entry_revalidates_and_a_304_returns_the_stored_body() {
    let server = TestServer::start(|request| {
        if request.header("if-none-match") == Some("\"v1\"") {
            Reply::new(304).with_header("cache-control", "max-age=60")
        } else {
            Reply::text("payload")
                .with_header("cache-control", "max-age=60")
                .with_header("etag", "\"v1\"")
        }
    })
    .await;
    let (cache, clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let first = engine.send(get(&url)).await.expect("the first request");
    assert_eq!(text(first).await, "payload");

    clock.advance(Duration::from_secs(120));
    let second = engine.send(get(&url)).await.expect("the revalidation");
    assert_eq!(
        second.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Revalidated)
    );
    assert_eq!(second.status(), 200, "the caller gets the stored status");
    assert_eq!(
        text(second).await,
        "payload",
        "a 304 carries no body, so the stored one is what the caller reads"
    );

    let received = server.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].header("if-none-match"), Some("\"v1\""));

    // The 304 restarted the entry's clock, so the third request is a hit.
    let third = engine.send(get(&url)).await.expect("the third request");
    assert_eq!(
        third.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Hit)
    );
    assert_eq!(server.request_count(), 2);

    // A `304` has no body, but its body still has to be *polled* to the end:
    // the engine returns an HTTP/1.1 connection to the pool when its response
    // body ends, and one dropped instead takes the connection with it. Only a
    // later request that actually reaches the origin can see the difference,
    // so the accept count is checked here rather than above.
    clock.advance(Duration::from_secs(120));
    let fourth = engine.send(get(&url)).await.expect("a second revalidation");
    assert_eq!(
        fourth.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Revalidated)
    );
    assert_eq!(text(fourth).await, "payload");
    assert_eq!(server.request_count(), 3);
    assert_eq!(
        server.accepts(),
        1,
        "every hop reused one connection, so the 304's body was drained rather than dropped"
    );
}

// --- responses that must never come back from store -----------------------
//
// Each of these has a unit test asserting that the store stayed empty. That
// proves the flag, not the property: an entry can be absent from `stats()` and
// still be served, and a hit can be reported without the store having anything
// to do with it. The only evidence that nothing was served is that the origin
// was asked again, so every assertion below is on the server's own count.

/// Drives two identical `GET`s through an engine with a cache and returns how
/// many requests the origin saw. Two means nothing was served from store.
async fn requests_reaching_the_origin(server: &TestServer, headers: &[(&str, &str)]) -> usize {
    let (cache, _clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    for _ in 0..2 {
        let mut builder = http::Request::builder().uri(&url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(Body::empty()).expect("a valid request");
        let response = engine
            .send(request)
            .await
            .expect("the request must succeed");
        let _ = text(response).await;
    }
    server.request_count()
}

#[tokio::test]
async fn a_private_response_is_fetched_again_rather_than_served_from_store() {
    let server = TestServer::always(
        Reply::text("mine").with_header("cache-control", "private, max-age=600"),
    )
    .await;
    assert_eq!(
        requests_reaching_the_origin(&server, &[]).await,
        2,
        "`private` is off by default because this engine may be more than one identity"
    );
}

#[tokio::test]
async fn a_response_to_an_authorized_request_is_fetched_again() {
    let server =
        TestServer::always(Reply::text("mine").with_header("cache-control", "max-age=600")).await;
    assert_eq!(
        requests_reaching_the_origin(&server, &[("authorization", "Bearer token")]).await,
        2,
        "RFC 9111 §3.5: without an explicit allowance this response is not shareable"
    );
}

#[tokio::test]
async fn a_set_cookie_response_is_fetched_again() {
    let server = TestServer::always(
        Reply::text("welcome")
            .with_header("cache-control", "max-age=600")
            .with_header("set-cookie", "session=abc"),
    )
    .await;
    assert_eq!(
        requests_reaching_the_origin(&server, &[]).await,
        2,
        "replaying a stored Set-Cookie re-applies one identity's state to another request"
    );
}

#[tokio::test]
async fn a_vary_star_response_is_fetched_again() {
    let server = TestServer::always(
        Reply::text("payload")
            .with_header("cache-control", "max-age=600")
            .with_header("vary", "*"),
    )
    .await;
    assert_eq!(
        requests_reaching_the_origin(&server, &[]).await,
        2,
        "`Vary: *` says no future request can be proved equivalent to this one"
    );
}

#[tokio::test]
async fn a_response_varying_on_a_header_the_cache_cannot_see_is_fetched_again() {
    for unselectable in ["cookie", "accept", "referer", "sec-fetch-dest"] {
        let server = TestServer::always(
            Reply::text("per-user")
                .with_header("cache-control", "max-age=600")
                .with_header("vary", unselectable),
        )
        .await;
        assert_eq!(
            requests_reaching_the_origin(&server, &[]).await,
            2,
            "a response selecting on `{unselectable}` must not be served to a second request"
        );
    }
}

/// The `Vary` case the cache *can* see. The first request declares a selecting
/// value, the second declares another, and the second must reach the origin.
#[tokio::test]
async fn a_vary_mismatch_on_a_visible_header_reaches_the_origin() {
    let server = TestServer::start(|request| {
        let language = request.header("accept-language").unwrap_or("none");
        Reply::text(language)
            .with_header("cache-control", "max-age=600")
            .with_header("vary", "accept-language")
    })
    .await;
    let (cache, _clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let send = async |language: &str| {
        let request = http::Request::builder()
            .uri(&url)
            .header("accept-language", language)
            .body(Body::empty())
            .expect("a valid request");
        text(engine.send(request).await.expect("the request")).await
    };

    assert_eq!(send("tr").await, "tr");
    assert_eq!(
        send("tr").await,
        "tr",
        "the same selecting value is the same variant"
    );
    assert_eq!(server.request_count(), 1, "the second request was a hit");

    assert_eq!(
        send("en").await,
        "en",
        "a different selecting value must not be answered with the stored variant"
    );
    assert_eq!(server.request_count(), 2);
}

/// A `304` is the one path that writes an entry without the response ever
/// being put to the storability rules. An origin that refreshes a session on
/// its `304` would, if that merge were unconditional, leave one identity's
/// `Set-Cookie` in the store to be handed to every later request for the same
/// URL. The count on the server is what shows it is not.
#[tokio::test]
async fn a_304_that_carries_set_cookie_is_not_left_in_the_store() {
    let server = TestServer::start(|request| {
        if request.header("if-none-match") == Some("\"v1\"") {
            Reply::new(304)
                .with_header("cache-control", "max-age=600")
                .with_header("set-cookie", "session=leaked")
        } else {
            Reply::text("payload")
                .with_header("cache-control", "max-age=60")
                .with_header("etag", "\"v1\"")
        }
    })
    .await;
    let (cache, clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let _ = text(engine.send(get(&url)).await.expect("the first request")).await;

    clock.advance(Duration::from_secs(120));
    let revalidated = engine.send(get(&url)).await.expect("the revalidation");
    assert_eq!(
        revalidated.headers()["set-cookie"],
        "session=leaked",
        "the caller is still handed the state the origin sent"
    );
    assert_eq!(text(revalidated).await, "payload");

    let third = engine.send(get(&url)).await.expect("the third request");
    assert!(
        third.extensions().get::<CacheStatus>().is_none(),
        "the entry the 304 would have refreshed carried a Set-Cookie, so it was not kept"
    );
    assert!(!third.headers().contains_key("set-cookie"));
    let _ = text(third).await;

    assert_eq!(
        server.request_count(),
        3,
        "the third request must reach the origin rather than replay a stored cookie"
    );
}

/// RFC 9111 §4.3.4: a `304` naming a validator this cache does not hold updates
/// nothing here. The stored body must not come back wearing the new tag.
#[tokio::test]
async fn a_304_naming_a_different_entity_tag_leaves_nothing_stored() {
    let server = TestServer::start(|request| {
        if request.header("if-none-match").is_some() {
            Reply::new(304)
                .with_header("cache-control", "max-age=600")
                .with_header("etag", "\"v2\"")
        } else {
            Reply::text("payload")
                .with_header("cache-control", "max-age=60")
                .with_header("etag", "\"v1\"")
        }
    })
    .await;
    let (cache, clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let _ = text(engine.send(get(&url)).await.expect("the first request")).await;

    clock.advance(Duration::from_secs(120));
    let second = engine.send(get(&url)).await.expect("the revalidation");
    assert_ne!(
        second.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Revalidated),
        "nothing here was revalidated: the origin confirmed a representation this cache does not \
         hold"
    );
    let _ = text(second).await;

    let third = engine.send(get(&url)).await.expect("the third request");
    assert!(third.extensions().get::<CacheStatus>().is_none());
    let _ = text(third).await;
    assert_eq!(server.request_count(), 3);
}

#[tokio::test]
async fn a_no_store_response_is_fetched_again_every_time() {
    let server = TestServer::always(
        Reply::text("secret").with_header("cache-control", "max-age=600, no-store"),
    )
    .await;
    let (cache, _clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/private");

    for _ in 0..2 {
        let response = engine
            .send(get(&url))
            .await
            .expect("the request must succeed");
        assert_eq!(text(response).await, "secret");
    }

    assert_eq!(
        server.request_count(),
        2,
        "a no-store response must never be served from store"
    );
}

/// The cache is consulted per hop, so the `301` and its target are separate
/// entries and a stored redirect is followed exactly as a fresh one is.
#[tokio::test]
async fn a_cached_redirect_is_followed_without_re_fetching_either_hop() {
    let server = TestServer::start(|request| {
        if request.target == "/from" {
            Reply::redirect(301, "/to").with_header("cache-control", "max-age=600")
        } else {
            Reply::text("arrived").with_header("cache-control", "max-age=600")
        }
    })
    .await;
    let (cache, _clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/from");

    for _ in 0..2 {
        let response = engine
            .send(get(&url))
            .await
            .expect("the request must succeed");
        assert_eq!(text(response).await, "arrived");
    }

    assert_eq!(
        server.request_count(),
        2,
        "two hops on the first request, and neither of them again on the second"
    );
}

#[tokio::test]
async fn a_successful_post_invalidates_the_target_it_wrote_to() {
    let server = TestServer::start(|request| {
        if request.method == "POST" {
            Reply::text("written")
        } else {
            Reply::text("payload").with_header("cache-control", "max-age=600")
        }
    })
    .await;
    let (cache, _clock) = cache_at(SystemTime::UNIX_EPOCH);
    let engine = engine_for(&server, Some(cache));
    let url = server.url_for(HOST, "/asset");

    let _ = text(engine.send(get(&url)).await.expect("the first GET")).await;
    let _ = text(engine.send(get(&url)).await.expect("the cached GET")).await;
    assert_eq!(server.request_count(), 1, "the second GET was a hit");

    let post = http::Request::builder()
        .method("POST")
        .uri(&url)
        .body(Body::fixed("update"))
        .expect("a valid request");
    let _ = text(engine.send(post).await.expect("the POST")).await;

    let after = engine
        .send(get(&url))
        .await
        .expect("the GET after the POST");
    assert!(
        after.extensions().get::<CacheStatus>().is_none(),
        "the POST changed the target, so the stored copy is no longer true"
    );
    let _ = text(after).await;
    assert_eq!(server.request_count(), 3);
}
