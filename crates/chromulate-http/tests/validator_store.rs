//! The validator store against a real socket.
//!
//! Every test here drives the real `Engine` over a real TCP connection to a
//! local server and asserts on what that server received.
//!
//! Most of them call `condition` and `observe` from the test, which is what the
//! engine's own two lines do — see `visit` below. The ones named for the engine
//! wiring instead hand the store to `EngineBuilder::validators` and let the
//! engine make both calls itself, because the engine makes them *per hop* with
//! the hop's own URL, and a redirect is where that stops being the same thing.
//!
//! Nothing below reaches the network: the resolver only knows the host each
//! test pins to the loopback listener.

#![cfg(feature = "validator-store")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use chromulate_core::{Body, Request, Response};
use chromulate_dns::StaticResolver;
use chromulate_http::{Engine, EngineConfig, ValidatorStore, Validators};
use chromulate_profile::Profile;
use common::{Recorded, Reply, TestServer};
use http::{HeaderValue, Method, StatusCode};
use url::Url;

/// A real body, so a `304` costing nothing is visible against something.
const FULL_BODY_LEN: usize = 64 * 1024;

/// The `Last-Modified` mediamarkt actually sent on 2026-08-04, kept verbatim so
/// the round trip is exercised with a value a real origin produced rather than
/// one shaped to suit a parser this store deliberately does not have.
const OBSERVED_LAST_MODIFIED: &str = "Tue, 04 Aug 2026 16:32:20 GMT";

fn engine_for(server: &TestServer, host: &str) -> Engine {
    let resolver = StaticResolver::empty().with_host(host.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .resolver(Arc::new(resolver))
        .build()
        .expect("the engine must build")
}

fn get(url: &Url) -> Request {
    http::Request::builder()
        .uri(url.as_str())
        .body(Body::empty())
        .expect("the test request must build")
}

/// One request through the engine with the store consulted on both sides,
/// exactly as the two-line engine wiring would, reporting the status and how
/// many body bytes came back.
async fn visit(engine: &Engine, store: &ValidatorStore, url: &Url) -> (StatusCode, usize) {
    let mut request = get(url);
    // Wiring line one, before the header engine runs.
    store.condition(url, &mut request);
    let method = request.method().clone();

    let response = engine
        .send(request)
        .await
        .expect("the request must complete");
    // Wiring line two, once the head has arrived.
    store.observe(url, &method, &response);

    let status = response.status();
    (status, body_len(response).await)
}

async fn body_len(response: Response) -> usize {
    response
        .into_body()
        .collect(8 * 1024 * 1024)
        .await
        .expect("the body must be readable")
        .len()
}

/// A server that answers `304` when a conditional header arrives and a full
/// body when one does not — the behaviour mediamarkt was measured doing.
fn conditional_origin(recorded: &Recorded) -> Reply {
    let conditional = recorded.header("if-none-match").is_some()
        || recorded.header("if-modified-since").is_some();
    if conditional {
        Reply::new(304)
    } else {
        Reply::ok()
            .with_header("last-modified", OBSERVED_LAST_MODIFIED)
            .with_header(
                "cache-control",
                "public, max-age=120, stale-while-revalidate=600",
            )
            .with_body(vec![b'x'; FULL_BODY_LEN])
    }
}

/// An engine that makes the two calls itself, per hop, as it does in `hop`.
fn engine_with_store(server: &TestServer, host: &str, store: &Arc<ValidatorStore>) -> Engine {
    let resolver = StaticResolver::empty().with_host(host.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .resolver(Arc::new(resolver))
        .validators(Arc::clone(store))
        .build()
        .expect("the engine must build")
}

/// The silent-corruption case, through the engine's own wiring.
///
/// A redirect means one logical request touches two URLs with two different
/// representations. A validator learned from the second, remembered against the
/// first, would let the origin answer `304` for a representation the caller
/// never saw — and the caller would skip parsing a page it does not have.
#[tokio::test]
async fn a_validator_learned_across_a_redirect_belongs_to_the_url_that_answered() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.target == "/old" {
            return Reply::redirect(302, "/new");
        }
        if recorded.header("if-none-match").is_some() {
            Reply::new(304)
        } else {
            Reply::ok()
                .with_header("etag", "\"the-new-representation\"")
                .with_body(vec![b'x'; FULL_BODY_LEN])
        }
    })
    .await;
    let store = Arc::new(ValidatorStore::new());
    let engine = engine_with_store(&server, "hop.test", &store);
    let old = Url::parse(&server.url_for("hop.test", "/old")).expect("url");
    let new = Url::parse(&server.url_for("hop.test", "/new")).expect("url");

    engine
        .send(get(&old))
        .await
        .expect("the request must complete");

    assert!(
        store.get(&old).is_none(),
        "a 302 describes no representation, so the URL that redirected must \
         remember nothing"
    );
    assert_eq!(
        store.get(&new).and_then(|stored| stored.etag),
        Some(HeaderValue::from_static("\"the-new-representation\"")),
        "the validator belongs to the URL that answered"
    );

    engine
        .send(get(&old))
        .await
        .expect("the second request must complete");

    let received = server.received();
    assert_eq!(received.len(), 4, "two hops, twice");
    assert!(
        received[2].header("if-none-match").is_none(),
        "the second visit's first hop is /old, which has no representation of \
         its own to be conditional about"
    );
    assert_eq!(
        received[3].header("if-none-match"),
        Some("\"the-new-representation\""),
        "and the hop that does have one sends it"
    );
}

/// The store is keyed by URL, and a query is part of a URL. Two products that
/// differ only in a query parameter are two representations.
#[tokio::test]
async fn a_validator_is_never_replayed_on_a_url_that_differs_by_query_or_path() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.header("if-none-match").is_some() {
            Reply::new(304)
        } else {
            Reply::ok()
                .with_header("etag", "\"one\"")
                .with_body(vec![b'x'; 32])
        }
    })
    .await;
    let store = Arc::new(ValidatorStore::new());
    let engine = engine_with_store(&server, "query.test", &store);

    let first = Url::parse(&server.url_for("query.test", "/p?id=1")).expect("url");
    engine
        .send(get(&first))
        .await
        .expect("the request must complete");

    for other in ["/p?id=2", "/p", "/p?id=1&x=2", "/q?id=1"] {
        let target = Url::parse(&server.url_for("query.test", other)).expect("url");
        engine
            .send(get(&target))
            .await
            .expect("the request must complete");
        let received = server.received();
        let last = received.last().expect("a request was recorded");
        assert_eq!(last.target, other);
        assert!(
            last.header("if-none-match").is_none(),
            "{other} is a different resource from /p?id=1 and must not carry \
             its validator"
        );
    }

    // The fragment is the exception, because it is never sent: the origin is
    // asked the same question and must get the same conditional header.
    let fragment = Url::parse(&server.url_for("query.test", "/p?id=1#section")).expect("url");
    engine
        .send(get(&fragment))
        .await
        .expect("the request must complete");
    let received = server.received();
    assert_eq!(
        received
            .last()
            .expect("a request was recorded")
            .header("if-none-match"),
        Some("\"one\""),
        "a fragment cannot distinguish two requests, so it must not split the entry"
    );
}

/// `HEAD` and `GET` share an entry, which RFC 9110 §9.3.2 licenses: a `HEAD`
/// response's fields are the ones the equivalent `GET` would have sent.
///
/// The consequence is worth stating rather than discovering: a caller that only
/// ever sent `HEAD` and then sends a `GET` can be answered `304`, having never
/// held the body. That is visible — the status is `304`, not a `200` with an
/// empty body — but it is not nothing, and a caller that treats `304` as
/// "unchanged since I parsed it" has not parsed it.
#[tokio::test]
async fn a_validator_learned_from_a_head_is_replayed_on_a_later_get() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.header("if-none-match").is_some() {
            Reply::new(304)
        } else {
            Reply::ok()
                .with_header("etag", "\"same-representation\"")
                .with_body(vec![b'x'; FULL_BODY_LEN])
        }
    })
    .await;
    let store = Arc::new(ValidatorStore::new());
    let engine = engine_with_store(&server, "head.test", &store);
    let url = Url::parse(&server.url_for("head.test", "/p")).expect("url");

    let head = http::Request::builder()
        .method(Method::HEAD)
        .uri(url.as_str())
        .body(Body::empty())
        .expect("the test request must build");
    engine.send(head).await.expect("the HEAD must complete");

    let response = engine.send(get(&url)).await.expect("the GET must complete");

    assert_eq!(
        server.received()[1].header("if-none-match"),
        Some("\"same-representation\""),
        "RFC 9110 9.3.2: a HEAD's fields describe the representation a GET \
         would have returned"
    );
    assert_eq!(
        response.status(),
        StatusCode::NOT_MODIFIED,
        "so the GET is answered 304 — with no body the caller ever had"
    );
}

#[tokio::test]
async fn a_second_visit_replays_last_modified_and_the_origin_answers_304_with_no_body() {
    let server = TestServer::start(conditional_origin).await;
    let engine = engine_for(&server, "shop.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("shop.test", "/product/1")).expect("url");

    let (status, length) = visit(&engine, &store, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(length, FULL_BODY_LEN);

    let (status, length) = visit(&engine, &store, &url).await;
    assert_eq!(
        status,
        StatusCode::NOT_MODIFIED,
        "the stored validator must turn the second visit into a revalidation"
    );
    assert_eq!(
        length, 0,
        "a 304 with no body is the whole saving; a body here means nothing was saved"
    );

    let received = server.received();
    assert_eq!(received.len(), 2);
    assert!(
        received[0].header("if-modified-since").is_none(),
        "the first visit has nothing to revalidate against"
    );
    assert_eq!(
        received[1].header("if-modified-since"),
        Some(OBSERVED_LAST_MODIFIED),
        "the origin's own Last-Modified must come back verbatim"
    );
}

#[tokio::test]
async fn a_stored_etag_is_replayed_as_if_none_match() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.header("if-none-match").is_some() {
            Reply::new(304)
        } else {
            Reply::ok()
                .with_header("etag", "\"v1-abc\"")
                .with_body(vec![b'x'; FULL_BODY_LEN])
        }
    })
    .await;
    let engine = engine_for(&server, "etag.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("etag.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    let (status, _) = visit(&engine, &store, &url).await;

    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(
        server.received()[1].header("if-none-match"),
        Some("\"v1-abc\"")
    );
}

#[tokio::test]
async fn a_200_carrying_no_validator_clears_the_one_that_was_stored() {
    let server = TestServer::always(Reply::ok().with_body(b"plain".to_vec())).await;
    let engine = engine_for(&server, "drop.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("drop.test", "/p")).expect("url");

    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"stale\"")),
            last_modified: None,
        },
    );
    visit(&engine, &store, &url).await;

    assert_eq!(
        server.received()[0].header("if-none-match"),
        Some("\"stale\""),
        "the seeded validator must have gone out before it was cleared"
    );
    assert!(
        store.get(&url).is_none(),
        "a 200 with no validator means the caller now holds a representation \
         that has none, so the old one must go"
    );
}

#[tokio::test]
async fn a_200_carrying_a_new_validator_replaces_the_stored_one() {
    let server = TestServer::always(Reply::ok().with_header("etag", "\"fresh\"")).await;
    let engine = engine_for(&server, "replace.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("replace.test", "/p")).expect("url");

    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"stale\"")),
            last_modified: Some(HeaderValue::from_static(OBSERVED_LAST_MODIFIED)),
        },
    );
    visit(&engine, &store, &url).await;

    assert_eq!(
        store.get(&url),
        Some(Validators {
            etag: Some(HeaderValue::from_static("\"fresh\"")),
            last_modified: None,
        }),
        "a 200 replaces the stored validators wholesale; the old Last-Modified \
         belongs to a representation the caller no longer holds"
    );
}

#[tokio::test]
async fn a_response_that_varies_is_never_stored() {
    let server = TestServer::always(
        Reply::ok()
            .with_header("last-modified", OBSERVED_LAST_MODIFIED)
            .with_header("vary", "Accept-Encoding"),
    )
    .await;
    let engine = engine_for(&server, "vary.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("vary.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    assert!(
        store.is_empty(),
        "the store is keyed by URL alone and cannot evaluate a secondary cache \
         key, so a varying representation must not be remembered"
    );

    visit(&engine, &store, &url).await;
    assert!(
        server.received()[1].header("if-modified-since").is_none(),
        "nothing was stored, so nothing may be replayed"
    );
}

#[tokio::test]
async fn a_vary_on_a_later_response_evicts_what_an_earlier_one_stored() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.header("if-none-match").is_some() {
            Reply::ok()
                .with_header("etag", "\"v2\"")
                .with_header("vary", "Cookie")
        } else {
            Reply::ok().with_header("etag", "\"v1\"")
        }
    })
    .await;
    let engine = engine_for(&server, "latevary.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("latevary.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    assert!(store.get(&url).is_some());

    visit(&engine, &store, &url).await;
    assert!(
        store.get(&url).is_none(),
        "an origin that starts varying makes the validator we hold unsafe, so \
         it must be dropped rather than left to be replayed"
    );
}

#[tokio::test]
async fn a_post_is_never_conditioned_and_never_stored() {
    let server = TestServer::always(Reply::ok().with_header("etag", "\"from-post\"")).await;
    let engine = engine_for(&server, "post.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("post.test", "/submit")).expect("url");

    // Seed a validator so the request path has something it could wrongly send.
    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"seeded\"")),
            last_modified: None,
        },
    );

    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri(url.as_str())
        .body(Body::fixed(&b"a=1"[..]))
        .expect("request");
    store.condition(&url, &mut request);
    let response = engine
        .send(request)
        .await
        .expect("the request must complete");
    store.observe(&url, &Method::POST, &response);

    assert!(
        server.received()[0].header("if-none-match").is_none(),
        "a conditional POST asks the origin about a representation the POST is \
         not retrieving"
    );
    assert_eq!(
        store.get(&url).and_then(|stored| stored.etag),
        Some(HeaderValue::from_static("\"seeded\"")),
        "a POST response must not overwrite what a GET learned"
    );
}

#[tokio::test]
async fn a_caller_that_set_its_own_conditional_header_keeps_it() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, "own.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("own.test", "/p")).expect("url");

    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"ours\"")),
            last_modified: None,
        },
    );

    let mut request = get(&url);
    request.headers_mut().insert(
        http::header::IF_NONE_MATCH,
        HeaderValue::from_static("\"theirs\""),
    );
    store.condition(&url, &mut request);
    engine
        .send(request)
        .await
        .expect("the request must complete");

    assert_eq!(
        server.received()[0].header("if-none-match"),
        Some("\"theirs\""),
        "the caller asked the origin its own question and must get its own answer"
    );
}

#[tokio::test]
async fn an_absurd_last_modified_survives_a_full_round_trip_without_panicking() {
    // Every one of these is server-controlled text a date parser would have to
    // cope with. This store has no date parser, and this test is what shows
    // adding one is not required for the round trip to work.
    let absurd = [
        "Thu, 99 Xxx 999999999999999999999 25:99:99 GMT",
        "-9223372036854775808",
        "0",
        "Tue, 04 Aug 292277026596 16:32:20 GMT",
        "not a date at all",
    ];

    for value in absurd {
        let echoed = value.to_owned();
        let server = TestServer::start(move |recorded: &Recorded| {
            if recorded.header("if-modified-since").is_some() {
                Reply::new(304)
            } else {
                Reply::ok().with_header("last-modified", &echoed)
            }
        })
        .await;
        let engine = engine_for(&server, "absurd.test");
        let store = ValidatorStore::new();
        let url = Url::parse(&server.url_for("absurd.test", "/p")).expect("url");

        visit(&engine, &store, &url).await;
        let (status, _) = visit(&engine, &store, &url).await;

        assert_eq!(status, StatusCode::NOT_MODIFIED, "value: {value}");
        assert_eq!(
            server.received()[1].header("if-modified-since"),
            Some(value),
            "the stored value must go back exactly as it arrived: {value}"
        );
    }
}

#[tokio::test]
async fn an_empty_validator_is_not_stored_and_nothing_is_replayed() {
    let server = TestServer::always(
        Reply::ok()
            .with_header("last-modified", "")
            .with_header("etag", ""),
    )
    .await;
    let engine = engine_for(&server, "empty.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("empty.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    assert!(
        store.is_empty(),
        "an empty field value is no validator at all, and replaying it would \
         put a header on every later request that can never produce a 304"
    );

    visit(&engine, &store, &url).await;
    assert!(server.received()[1].header("if-modified-since").is_none());
    assert!(server.received()[1].header("if-none-match").is_none());
}

#[tokio::test]
async fn a_304_that_carries_a_new_validator_replaces_the_stored_one() {
    // RFC 9110 15.4.5: a 304's header fields update the stored ones.
    let server = TestServer::start(
        |recorded: &Recorded| match recorded.header("if-none-match") {
            None => Reply::ok().with_header("etag", "\"first\""),
            Some(_) => Reply::new(304).with_header("etag", "\"second\""),
        },
    )
    .await;
    let engine = engine_for(&server, "update.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("update.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    visit(&engine, &store, &url).await;
    visit(&engine, &store, &url).await;

    let received = server.received();
    assert_eq!(received[1].header("if-none-match"), Some("\"first\""));
    assert_eq!(
        received[2].header("if-none-match"),
        Some("\"second\""),
        "RFC 9110 15.4.5: a 304's header fields update the stored ones"
    );
}

#[tokio::test]
async fn the_conditional_headers_are_appended_and_leave_the_profile_order_untouched() {
    // Header order is the fingerprint, so what this feature does to it is not a
    // detail. Two facts are asserted, and the second is a known divergence
    // rather than a success:
    //
    //  1. the profile's own headers keep their exact relative order, so turning
    //     the store on does not reshuffle the part that was captured;
    //  2. the conditional headers land at the *end*, after `priority`, because
    //     that is where the header engine puts anything the profile does not
    //     name. No capture of Chrome sending `If-None-Match` was available when
    //     this was written, so this placement is a guess by omission and an
    //     origin comparing header order can see it.
    let with_store = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&with_store, "order.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&with_store.url_for("order.test", "/p")).expect("url");
    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"e\"")),
            last_modified: Some(HeaderValue::from_static(OBSERVED_LAST_MODIFIED)),
        },
    );
    visit(&engine, &store, &url).await;
    let conditioned = with_store.received()[0].header_order.clone();

    let without_store = TestServer::always(Reply::ok()).await;
    let plain_engine = engine_for(&without_store, "order.test");
    let plain_url = Url::parse(&without_store.url_for("order.test", "/p")).expect("url");
    visit(&plain_engine, &ValidatorStore::new(), &plain_url).await;
    let plain = without_store.received()[0].header_order.clone();

    assert_eq!(
        conditioned.len(),
        plain.len() + 2,
        "exactly the two conditional headers are added"
    );
    assert_eq!(
        &conditioned[..plain.len()],
        &plain[..],
        "the profile's captured header order must survive untouched"
    );
    assert_eq!(
        &conditioned[plain.len()..],
        ["if-none-match", "if-modified-since"],
        "appended at the end, which is not a captured browser placement"
    );
}

/// The header-order claim again, through the engine's own call site rather
/// than the test's.
///
/// The engine calls `condition` inside `hop`, before `apply_headers` and after
/// the version is settled, which is a different place from where `visit` calls
/// it. If that placement ever moved, the profile's captured order — which is
/// the fingerprint — would move with it, and no test above would notice.
#[tokio::test]
async fn the_engines_own_wiring_leaves_the_profile_header_order_untouched() {
    let with_store = TestServer::always(Reply::ok()).await;
    let store = Arc::new(ValidatorStore::new());
    let engine = engine_with_store(&with_store, "wired.test", &store);
    let url = Url::parse(&with_store.url_for("wired.test", "/p")).expect("url");
    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"e\"")),
            last_modified: Some(HeaderValue::from_static(OBSERVED_LAST_MODIFIED)),
        },
    );
    engine
        .send(get(&url))
        .await
        .expect("the request must complete");
    let conditioned = with_store.received()[0].header_order.clone();

    // The same engine with no store at all: the feature off.
    let without_store = TestServer::always(Reply::ok()).await;
    let plain_engine = engine_for(&without_store, "wired.test");
    let plain_url = Url::parse(&without_store.url_for("wired.test", "/p")).expect("url");
    plain_engine
        .send(get(&plain_url))
        .await
        .expect("the request must complete");
    let plain = without_store.received()[0].header_order.clone();

    assert_eq!(
        plain.len(),
        12,
        "the profile's captured order is twelve headers: {plain:?}"
    );
    assert_eq!(
        &conditioned[..plain.len()],
        &plain[..],
        "every header the profile names must keep its captured position"
    );
    assert_eq!(
        &conditioned[plain.len()..],
        ["if-none-match", "if-modified-since"],
        "appended at the end, which is a guess by omission rather than a \
         captured browser placement"
    );
}

#[tokio::test]
async fn a_304_that_carries_no_validator_keeps_the_stored_one() {
    let server = TestServer::start(|recorded: &Recorded| {
        if recorded.header("if-none-match").is_some() {
            Reply::new(304)
        } else {
            Reply::ok().with_header("etag", "\"kept\"")
        }
    })
    .await;
    let engine = engine_for(&server, "keep.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("keep.test", "/p")).expect("url");

    visit(&engine, &store, &url).await;
    visit(&engine, &store, &url).await;
    let (status, _) = visit(&engine, &store, &url).await;

    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(
        server.received()[2].header("if-none-match"),
        Some("\"kept\""),
        "a 304 that says nothing new leaves what we hold alone; forgetting it \
         would cost a full body on every third visit"
    );
}

#[tokio::test]
async fn a_404_leaves_the_stored_validator_alone() {
    let server = TestServer::always(Reply::new(404)).await;
    let engine = engine_for(&server, "gone.test");
    let store = ValidatorStore::new();
    let url = Url::parse(&server.url_for("gone.test", "/p")).expect("url");

    store.insert(
        &url,
        Validators {
            etag: Some(HeaderValue::from_static("\"kept\"")),
            last_modified: None,
        },
    );
    visit(&engine, &store, &url).await;

    assert!(
        store.get(&url).is_some(),
        "only 200 and 304 describe a representation; nothing else may rewrite \
         what the caller last saw"
    );
}
