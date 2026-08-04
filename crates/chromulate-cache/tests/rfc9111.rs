//! The cache's behaviour, driven the way the engine drives it.
//!
//! Each test plays a whole exchange: `before`, then a response the origin might
//! have sent, then `after`, then the body read to its end — because the entry
//! is committed by the caller reading the body, not by `after` returning.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use chromulate_cache::{
    CacheConfig, CacheStatus, HttpCache, ManualClock, MemoryLimits, MemoryStore,
};
use chromulate_core::{Body, Request, Response};
use url::Url;

const URL: &str = "https://origin.test/resource";

fn url() -> Url {
    Url::parse(URL).expect("a valid url")
}

fn request(headers: &[(&str, &str)]) -> Request {
    let mut builder = http::Request::builder().uri(URL);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).expect("a valid request")
}

fn response(status: u16, headers: &[(&str, &str)], body: &'static str) -> Response {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::fixed(body)).expect("a valid response")
}

/// A cache with a clock a test can move, and the store it wrote into.
fn cache_at(now: SystemTime) -> (HttpCache, Arc<ManualClock>, Arc<MemoryStore>) {
    cache_with(now, CacheConfig::default())
}

fn cache_with(
    now: SystemTime,
    config: CacheConfig,
) -> (HttpCache, Arc<ManualClock>, Arc<MemoryStore>) {
    let clock = ManualClock::at(now);
    let store = Arc::new(MemoryStore::with_limits(MemoryLimits {
        max_bytes: 1024 * 1024,
        shards: 4,
    }));
    let cache = HttpCache::builder()
        .clock(Arc::clone(&clock) as _)
        .storage(Arc::clone(&store) as _)
        .config(config)
        .build();
    (cache, clock, store)
}

fn epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

/// Runs one exchange: sends `request`, has the origin answer `from_origin`,
/// and reads the returned body to the end. Returns the request as it went out
/// and the bytes the caller saw.
async fn exchange(
    cache: &HttpCache,
    mut request: Request,
    from_origin: Response,
) -> (Request, Bytes) {
    let (pending, hit) = cache.before(&mut request, &url());
    assert!(
        hit.is_none(),
        "this exchange was expected to reach the origin"
    );
    let served = cache.after(pending, &url(), from_origin);
    let body = served
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the body must arrive");
    (request, body)
}

/// Looks the request up without sending anything.
fn lookup(cache: &HttpCache, mut request: Request) -> (Request, Option<Response>) {
    let (_pending, hit) = cache.before(&mut request, &url());
    (request, hit)
}

#[tokio::test]
async fn a_fresh_stored_response_is_served_without_asking_the_origin() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=60")], "payload"),
    )
    .await;

    clock.advance(Duration::from_secs(30));
    let (_, hit) = lookup(&cache, request(&[]));
    let hit = hit.expect("a 30 second old entry with a 60 second lifetime is fresh");

    assert_eq!(
        hit.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Hit)
    );
    assert_eq!(
        hit.headers()["age"],
        "30",
        "RFC 9111 §5.1 requires a cache to state the age it is serving"
    );
    let body = hit
        .into_body()
        .collect(1024)
        .await
        .expect("the stored body is already in memory");
    assert_eq!(body, Bytes::from_static(b"payload"));
}

#[tokio::test]
async fn an_entry_past_its_lifetime_is_not_served() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=60")], "payload"),
    )
    .await;

    clock.advance(Duration::from_secs(60));
    let (_, hit) = lookup(&cache, request(&[]));
    assert!(hit.is_none(), "an age equal to the lifetime is stale");
}

// --- no-store -------------------------------------------------------------

/// One of the three tests that guard against handing out data the origin said
/// nobody may keep.
#[tokio::test]
async fn a_no_store_response_is_never_served_back() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600, no-store")], "secret"),
    )
    .await;

    assert_eq!(store.stats().keys, 0, "nothing may be stored at all");
    let (_, hit) = lookup(&cache, request(&[]));
    assert!(
        hit.is_none(),
        "a no-store response must never be served back"
    );
}

#[tokio::test]
async fn a_no_store_response_also_drops_what_was_already_stored() {
    let (cache, clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "old"),
    )
    .await;
    assert_eq!(store.stats().keys, 1);

    // Past its lifetime, so the next request reaches the origin — which now
    // says nobody may keep a copy of this target at all.
    clock.advance(Duration::from_secs(601));
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "no-store")], "new"),
    )
    .await;

    assert_eq!(store.stats().keys, 0);
    assert!(lookup(&cache, request(&[])).1.is_none());
}

#[tokio::test]
async fn a_request_carrying_no_store_neither_reads_nor_writes_the_cache() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "payload"),
    )
    .await;

    let (_, hit) = lookup(&cache, request(&[("cache-control", "no-store")]));
    assert!(hit.is_none(), "the request refused a stored response");

    exchange(
        &cache,
        request(&[("cache-control", "no-store")]),
        response(200, &[("cache-control", "max-age=600")], "fresh"),
    )
    .await;
    assert_eq!(
        store.stats().keys,
        1,
        "the pre-existing entry survives, and the no-store exchange added nothing"
    );
}

// --- no-cache, which is a different thing entirely ------------------------

#[tokio::test]
async fn a_no_cache_response_is_stored_and_revalidated_rather_than_discarded() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("cache-control", "no-cache, max-age=600"),
                ("etag", "\"v1\""),
            ],
            "payload",
        ),
    )
    .await;

    assert_eq!(
        store.stats().keys,
        1,
        "`no-cache` asks for revalidation, so the entry has to exist to revalidate"
    );

    let (sent, hit) = lookup(&cache, request(&[]));
    assert!(
        hit.is_none(),
        "`no-cache` is never fresh, whatever max-age says"
    );
    assert_eq!(
        sent.headers()["if-none-match"],
        "\"v1\"",
        "the point of storing it is the conditional request"
    );
}

#[tokio::test]
async fn a_request_carrying_no_cache_forces_revalidation_of_a_fresh_entry() {
    let (cache, _clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=600"), ("etag", "\"v1\"")],
            "payload",
        ),
    )
    .await;

    for forcing in ["no-cache", "max-age=0"] {
        let (sent, hit) = lookup(&cache, request(&[("cache-control", forcing)]));
        assert!(hit.is_none(), "`{forcing}` must not be served from store");
        assert_eq!(sent.headers()["if-none-match"], "\"v1\"");
    }
}

// --- revalidation ---------------------------------------------------------

#[tokio::test]
async fn a_stale_entry_sends_both_validators_and_a_304_restores_its_freshness() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("cache-control", "max-age=60"),
                ("etag", "\"v1\""),
                ("last-modified", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("content-type", "text/plain"),
            ],
            "payload",
        ),
    )
    .await;

    clock.advance(Duration::from_secs(120));
    let mut stale = request(&[]);
    let (pending, hit) = cache.before(&mut stale, &url());
    assert!(hit.is_none());
    assert_eq!(stale.headers()["if-none-match"], "\"v1\"");
    assert_eq!(
        stale.headers()["if-modified-since"],
        "Thu, 01 Jan 1970 00:00:00 GMT"
    );

    let served = cache.after(
        pending,
        &url(),
        response(
            304,
            &[("cache-control", "max-age=600"), ("x-added", "yes")],
            "",
        ),
    );

    assert_eq!(
        served.extensions().get::<CacheStatus>(),
        Some(&CacheStatus::Revalidated)
    );
    assert_eq!(served.status(), 200, "the caller gets the stored status");
    assert_eq!(served.headers()["content-type"], "text/plain");
    assert_eq!(served.headers()["x-added"], "yes");
    assert_eq!(served.headers()["cache-control"], "max-age=600");
    let body = served
        .into_body()
        .collect(1024)
        .await
        .expect("the stored body must be served");
    assert_eq!(body, Bytes::from_static(b"payload"));

    // The refreshed entry starts its age again: this is the half of §4.3.4
    // that is invisible until every request revalidates forever.
    let (_, hit) = lookup(&cache, request(&[]));
    let hit = hit.expect("a revalidated entry is fresh again");
    assert_eq!(hit.headers()["age"], "0");
}

#[tokio::test]
async fn a_revalidation_answered_with_a_new_body_replaces_the_entry() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=60"), ("etag", "\"v1\"")],
            "old",
        ),
    )
    .await;

    clock.advance(Duration::from_secs(120));
    let (_, body) = exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=60"), ("etag", "\"v2\"")],
            "new",
        ),
    )
    .await;
    assert_eq!(body, Bytes::from_static(b"new"));

    let (_, hit) = lookup(&cache, request(&[]));
    let hit = hit.expect("the replacement is fresh");
    assert_eq!(hit.headers()["etag"], "\"v2\"");
}

// --- Vary -----------------------------------------------------------------

/// The second of the three security-relevant tests. A stored variant that
/// matched on one selecting value must not be handed to a request presenting
/// another.
#[tokio::test]
async fn a_vary_mismatch_is_not_served() {
    let (cache, _clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[("accept-language", "tr")]),
        response(
            200,
            &[
                ("cache-control", "max-age=600"),
                ("vary", "accept-language"),
            ],
            "merhaba",
        ),
    )
    .await;

    let (_, matching) = lookup(&cache, request(&[("accept-language", "tr")]));
    assert!(matching.is_some(), "the same selecting value is a hit");

    let (_, mismatched) = lookup(&cache, request(&[("accept-language", "en")]));
    assert!(
        mismatched.is_none(),
        "a different accept-language selects a different variant, which does not exist"
    );

    let (_, absent) = lookup(&cache, request(&[]));
    assert!(
        absent.is_none(),
        "an absent selecting header is a value of its own, not a wildcard"
    );
}

#[tokio::test]
async fn two_variants_of_one_url_are_stored_side_by_side() {
    let (cache, _clock, store) = cache_at(epoch());
    for (language, body) in [("tr", "merhaba"), ("en", "hello")] {
        exchange(
            &cache,
            request(&[("accept-language", language)]),
            response(
                200,
                &[
                    ("cache-control", "max-age=600"),
                    ("vary", "accept-language"),
                ],
                body,
            ),
        )
        .await;
    }
    assert_eq!(store.stats().keys, 1, "one key, two variants under it");

    for (language, expected) in [("tr", "merhaba"), ("en", "hello")] {
        let (_, hit) = lookup(&cache, request(&[("accept-language", language)]));
        let body = hit
            .expect("both variants are stored")
            .into_body()
            .collect(1024)
            .await
            .expect("the stored body");
        assert_eq!(body, Bytes::from(expected));
    }
}

#[tokio::test]
async fn vary_star_is_never_stored() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=600"), ("vary", "*")],
            "payload",
        ),
    )
    .await;
    assert_eq!(store.stats().keys, 0);
    assert!(lookup(&cache, request(&[])).1.is_none());
}

/// The cache is consulted before the profile's header engine and the cookie jar
/// have written the request, so a response selecting on `Cookie` cannot be
/// matched safely — and matching it wrongly is how one user's page reaches
/// another.
#[tokio::test]
async fn a_response_that_varies_on_a_header_the_cache_cannot_see_is_not_stored() {
    let (cache, _clock, store) = cache_at(epoch());
    for unselectable in ["cookie", "sec-fetch-dest", "accept", "referer"] {
        exchange(
            &cache,
            request(&[]),
            response(
                200,
                &[("cache-control", "max-age=600"), ("vary", unselectable)],
                "per-user",
            ),
        )
        .await;
        assert_eq!(
            store.stats().keys,
            0,
            "a response selecting on `{unselectable}` must not be stored"
        );
    }

    // The profile writes this one identically on every request, so two
    // snapshots that both lack it describe two requests that both carried the
    // same value.
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("cache-control", "max-age=600"),
                ("vary", "accept-encoding"),
            ],
            "shared",
        ),
    )
    .await;
    assert_eq!(store.stats().keys, 1);
}

// --- private and Authorization -------------------------------------------

/// The third security-relevant test. A `private` response and a response to an
/// authorized request are both storable only when the caller has said this
/// engine belongs to one identity.
#[tokio::test]
async fn private_and_authorized_responses_are_refused_by_default() {
    let (cache, _clock, store) = cache_at(epoch());

    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "private, max-age=600")], "mine"),
    )
    .await;
    assert_eq!(store.stats().keys, 0, "`private` is not stored by default");
    assert!(lookup(&cache, request(&[])).1.is_none());

    exchange(
        &cache,
        request(&[("authorization", "Bearer token")]),
        response(200, &[("cache-control", "max-age=600")], "mine"),
    )
    .await;
    assert_eq!(
        store.stats().keys,
        0,
        "RFC 9111 §3.5: a response to an authorized request needs an explicit allowance"
    );
    assert!(lookup(&cache, request(&[])).1.is_none());
}

#[tokio::test]
async fn private_is_stored_when_the_engine_is_declared_to_be_one_identity() {
    let (cache, _clock, store) = cache_with(
        epoch(),
        CacheConfig {
            store_private: true,
            ..CacheConfig::default()
        },
    );
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "private, max-age=600")], "mine"),
    )
    .await;
    assert_eq!(store.stats().keys, 1);
    assert!(lookup(&cache, request(&[])).1.is_some());
}

#[tokio::test]
async fn an_authorized_request_is_stored_when_the_response_says_it_may_be() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[("authorization", "Bearer token")]),
        response(200, &[("cache-control", "public, max-age=600")], "shared"),
    )
    .await;
    assert_eq!(store.stats().keys, 1);
}

#[tokio::test]
async fn a_set_cookie_response_is_never_stored() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=600"), ("set-cookie", "s=abc")],
            "welcome",
        ),
    )
    .await;
    assert_eq!(store.stats().keys, 0);
}

// --- invalidation ---------------------------------------------------------

#[tokio::test]
async fn a_successful_unsafe_method_invalidates_the_target() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "before"),
    )
    .await;
    assert_eq!(store.stats().keys, 1);

    let mut post = http::Request::builder()
        .method("POST")
        .uri(URL)
        .body(Body::fixed("update"))
        .expect("a valid request");
    let (pending, hit) = cache.before(&mut post, &url());
    assert!(hit.is_none(), "a POST is never served from cache");
    let _ = cache.after(pending, &url(), response(200, &[], "done"));

    assert_eq!(store.stats().keys, 0);
    assert!(lookup(&cache, request(&[])).1.is_none());
}

#[tokio::test]
async fn a_failed_unsafe_method_leaves_the_stored_response_alone() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "before"),
    )
    .await;

    let mut post = http::Request::builder()
        .method("POST")
        .uri(URL)
        .body(Body::fixed("update"))
        .expect("a valid request");
    let (pending, _) = cache.before(&mut post, &url());
    let _ = cache.after(pending, &url(), response(500, &[], "no"));

    assert_eq!(
        store.stats().keys,
        1,
        "a request that failed changed nothing, so the stored copy is still true"
    );
}

#[tokio::test]
async fn an_unsafe_method_invalidates_the_same_origin_location_it_names() {
    let (cache, _clock, store) = cache_at(epoch());
    let created = Url::parse("https://origin.test/created").expect("a valid url");

    let mut seed = http::Request::builder()
        .uri(created.as_str())
        .body(Body::empty())
        .expect("a valid request");
    let (pending, _) = cache.before(&mut seed, &created);
    let stored = cache.after(
        pending,
        &created,
        response(200, &[("cache-control", "max-age=600")], "resource"),
    );
    let _ = stored.into_body().collect(1024).await.expect("the body");
    assert_eq!(store.stats().keys, 1);

    let mut post = http::Request::builder()
        .method("POST")
        .uri(URL)
        .body(Body::empty())
        .expect("a valid request");
    let (pending, _) = cache.before(&mut post, &url());
    let _ = cache.after(
        pending,
        &url(),
        response(201, &[("location", "/created")], "made"),
    );

    assert_eq!(store.stats().keys, 0);
}

#[tokio::test]
async fn a_cross_origin_location_is_not_invalidated() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "resource"),
    )
    .await;

    let elsewhere = Url::parse("https://attacker.test/post").expect("a valid url");
    let mut post = http::Request::builder()
        .method("POST")
        .uri(elsewhere.as_str())
        .body(Body::empty())
        .expect("a valid request");
    let (pending, _) = cache.before(&mut post, &elsewhere);
    let _ = cache.after(
        pending,
        &elsewhere,
        response(200, &[("location", "https://origin.test/resource")], "ok"),
    );

    assert_eq!(
        store.stats().keys,
        1,
        "one origin must not be able to evict another's entries by naming them"
    );
}

// --- bodies ---------------------------------------------------------------

#[tokio::test]
async fn a_body_over_the_budget_is_streamed_but_not_stored() {
    let (cache, _clock, store) = cache_with(
        epoch(),
        CacheConfig {
            max_body_bytes: 4,
            ..CacheConfig::default()
        },
    );
    let (_, body) = exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "far too long"),
    )
    .await;

    assert_eq!(
        body,
        Bytes::from_static(b"far too long"),
        "the caller still receives every byte"
    );
    assert_eq!(store.stats().keys, 0);
}

/// The declared-length check in `after` cannot see this one: the body arrives
/// as a stream with no length at all, so the budget has to be enforced while
/// the bytes go past. This is the test that distinguishes the two layers.
#[tokio::test]
async fn a_streamed_body_of_undeclared_length_is_cut_off_at_the_budget() {
    let (cache, _clock, store) = cache_with(
        epoch(),
        CacheConfig {
            max_body_bytes: 8,
            ..CacheConfig::default()
        },
    );

    let chunks = futures_util::stream::iter(vec![
        Ok(Bytes::from_static(b"chunk-one")),
        Ok(Bytes::from_static(b"chunk-two")),
    ]);
    let streamed = http::Response::builder()
        .status(200)
        .header("cache-control", "max-age=600")
        .body(Body::stream(chunks, None))
        .expect("a valid response");
    assert_eq!(
        streamed.body().content_length(),
        None,
        "the declared-length check must have nothing to work with"
    );

    let mut request = request(&[]);
    let (pending, _) = cache.before(&mut request, &url());
    let served = cache.after(pending, &url(), streamed);
    let body = served
        .into_body()
        .collect(1024)
        .await
        .expect("the caller still receives every byte");

    assert_eq!(body, Bytes::from_static(b"chunk-onechunk-two"));
    assert_eq!(store.stats().keys, 0);
}

#[tokio::test]
async fn a_body_the_caller_abandons_halfway_is_not_stored() {
    let (cache, _clock, store) = cache_at(epoch());
    let mut request = request(&[]);
    let (pending, _) = cache.before(&mut request, &url());
    let served = cache.after(
        pending,
        &url(),
        response(200, &[("cache-control", "max-age=600")], "payload"),
    );

    // Dropped without being read: half a response is not a response.
    drop(served);
    assert_eq!(store.stats().keys, 0);
}

#[tokio::test]
async fn hop_by_hop_fields_do_not_survive_into_the_store() {
    let (cache, _clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("cache-control", "max-age=600"),
                ("connection", "keep-alive"),
                ("keep-alive", "timeout=5"),
                ("content-type", "text/plain"),
            ],
            "payload",
        ),
    )
    .await;

    let hit = lookup(&cache, request(&[])).1.expect("a fresh entry");
    assert!(!hit.headers().contains_key("connection"));
    assert!(!hit.headers().contains_key("keep-alive"));
    assert_eq!(hit.headers()["content-type"], "text/plain");
}

#[tokio::test]
async fn a_caller_running_its_own_conditional_request_is_left_alone() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=600"), ("etag", "\"v1\"")],
            "payload",
        ),
    )
    .await;

    let (sent, hit) = lookup(&cache, request(&[("if-none-match", "\"mine\"")]));
    assert!(hit.is_none(), "the caller owns this exchange");
    assert_eq!(
        sent.headers()["if-none-match"],
        "\"mine\"",
        "the cache must not overwrite the caller's own validator"
    );
    assert_eq!(store.stats().keys, 1);
}

#[tokio::test]
async fn a_range_request_bypasses_the_cache_entirely() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(200, &[("cache-control", "max-age=600")], "payload"),
    )
    .await;

    let (_, hit) = lookup(&cache, request(&[("range", "bytes=0-3")]));
    assert!(
        hit.is_none(),
        "this cache does not do ranges, so it does not answer them"
    );
    assert_eq!(store.stats().keys, 1);
}

// --- freshness sources ----------------------------------------------------

#[tokio::test]
async fn an_expires_header_alone_establishes_freshness() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("expires", "Thu, 01 Jan 1970 00:10:00 GMT"),
            ],
            "payload",
        ),
    )
    .await;

    clock.advance(Duration::from_secs(599));
    assert!(lookup(&cache, request(&[])).1.is_some());
    clock.advance(Duration::from_secs(1));
    assert!(lookup(&cache, request(&[])).1.is_none());
}

/// The distinction this test exists for is between an `Expires` that is
/// *invalid* and one that is *absent*, which is only visible when a heuristic
/// is available to fall through to. The response below carries a
/// `Last-Modified` eleven days before its `Date`, so a cache that read the
/// invalid `Expires` as an absent one would guess a lifetime of a day and serve
/// this for a day.
#[tokio::test]
async fn the_expires_zero_sentinel_is_a_time_in_the_past_not_an_absent_field() {
    let (cache, _clock, store) = cache_at(epoch() + Duration::from_secs(1_000_000));
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("date", "Mon, 12 Jan 1970 13:46:40 GMT"),
                ("last-modified", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("expires", "0"),
            ],
            "payload",
        ),
    )
    .await;

    assert_eq!(
        store.stats().keys,
        1,
        "it is stored, it is simply never fresh"
    );
    assert!(
        lookup(&cache, request(&[])).1.is_none(),
        "RFC 9111 §5.3: an invalid Expires is a time in the past, and a time in the past is not \
         an invitation to guess"
    );
}

#[tokio::test]
async fn the_last_modified_heuristic_gives_a_tenth_of_the_documents_age() {
    let (cache, clock, _) = cache_at(epoch() + Duration::from_secs(1_000));
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[
                ("date", "Thu, 01 Jan 1970 00:16:40 GMT"),
                ("last-modified", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
            "payload",
        ),
    )
    .await;

    clock.advance(Duration::from_secs(99));
    assert!(
        lookup(&cache, request(&[])).1.is_some(),
        "a tenth of 1000 seconds is 100, so 99 seconds old is fresh"
    );
    clock.advance(Duration::from_secs(1));
    assert!(lookup(&cache, request(&[])).1.is_none());
}

/// The `Age` a proxy stated is not the whole age, and reading it as though it
/// were is the classic arithmetic bug.
#[tokio::test]
async fn an_age_header_from_an_intermediary_shortens_the_stored_lifetime() {
    let (cache, clock, _) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(
            200,
            &[("cache-control", "max-age=100"), ("age", "90")],
            "payload",
        ),
    )
    .await;

    clock.advance(Duration::from_secs(9));
    let hit = lookup(&cache, request(&[]))
        .1
        .expect("90 + 9 is still under 100");
    assert_eq!(hit.headers()["age"], "99");

    clock.advance(Duration::from_secs(1));
    assert!(
        lookup(&cache, request(&[])).1.is_none(),
        "the entry expires ten seconds after it was stored, not a hundred"
    );
}

#[tokio::test]
async fn a_response_with_no_lifetime_and_no_validator_is_not_stored_at_all() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(&cache, request(&[]), response(200, &[], "payload")).await;
    assert_eq!(store.stats().keys, 0);
}

#[tokio::test]
async fn an_uncacheable_status_is_not_stored() {
    let (cache, _clock, store) = cache_at(epoch());
    exchange(
        &cache,
        request(&[]),
        response(201, &[("cache-control", "max-age=600")], "created"),
    )
    .await;
    assert_eq!(store.stats().keys, 0);
}
