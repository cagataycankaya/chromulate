//! What the engine does against a real socket.
//!
//! Every test here drives the real `Engine` over a real TCP connection to a
//! local server, and asserts on what that server received. Nothing below the
//! engine's own API is mocked, and no test can reach the network: the resolver
//! only knows the hosts each test pins to the loopback listener.

mod common;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use chromulate_cookie::Jar;
use chromulate_core::{
    Body, CookieStore, Error, Origin, Phase, RedirectPolicy, Request, RequestOptions, Response,
};
use chromulate_dns::StaticResolver;
use chromulate_fingerprint::{Setting, SettingId};
use chromulate_http::{Engine, EngineConfig, Pool, PoolConfig};
use chromulate_profile::Profile;
use common::{Recorded, Reply, TestServer};
use http::{HeaderValue, Method, StatusCode};
use url::Url;

fn engine_for(server: &TestServer, hosts: &[&str]) -> Engine {
    engine_with(server, hosts, Profile::chrome_stable(), None, |config| {
        config.connect_timeout = Some(Duration::from_secs(5));
    })
}

fn engine_with(
    server: &TestServer,
    hosts: &[&str],
    profile: Profile,
    pool: Option<Pool>,
    configure: impl FnOnce(&mut EngineConfig),
) -> Engine {
    let mut resolver = StaticResolver::empty();
    for host in hosts {
        resolver = resolver.with_host((*host).to_owned(), vec![server.addr()]);
    }

    let mut config = EngineConfig::new(Arc::new(profile));
    config.connect_timeout = Some(Duration::from_secs(5));
    configure(&mut config);

    let mut builder = Engine::builder(config).resolver(Arc::new(resolver));
    if let Some(pool) = pool {
        builder = builder.pool(pool);
    }
    builder.build().expect("the engine must build")
}

fn tuned(server: &TestServer, hosts: &[&str], configure: impl FnOnce(&mut EngineConfig)) -> Engine {
    engine_with(server, hosts, Profile::chrome_stable(), None, configure)
}

fn get(url: &str) -> Request {
    request(Method::GET, url, Body::empty())
}

fn request(method: Method, url: &str, body: Body) -> Request {
    http::Request::builder()
        .method(method)
        .uri(url)
        .body(body)
        .expect("a valid request")
}

async fn text_of(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the body must be readable");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ----------------------------------------------------------------- HTTP/1.1

#[tokio::test]
async fn a_request_completes_over_http1_and_the_body_comes_back() {
    let server = TestServer::always(Reply::text("hello from the origin")).await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/index.html")))
        .await
        .expect("the request must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_11);
    assert_eq!(text_of(response).await, "hello from the origin");

    let received = server.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].method, "GET");
    assert_eq!(
        received[0].target, "/index.html",
        "an HTTP/1.1 request line carries the path, not the absolute URL"
    );
}

#[tokio::test]
async fn the_request_carries_the_profiles_headers_in_the_profiles_order() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, &["example.test"]);

    let mut options = RequestOptions::navigation();
    options.redirect = RedirectPolicy::None;
    let mut request = get(&server.url_for("example.test", "/"));
    request.extensions_mut().insert(options);

    engine
        .send(request)
        .await
        .expect("the request must succeed");

    let received = server.received();
    let profile = Profile::chrome_stable();

    // `Host` is an HTTP/1.1 addition that the capture — taken over HTTP/2 —
    // never saw, so it is set aside before comparing with the captured order.
    let observed: Vec<&String> = received[0]
        .header_order
        .iter()
        .filter(|name| *name != "host")
        .collect();
    let expected: Vec<&String> = profile.header_order.navigate.iter().collect();

    assert_eq!(
        observed, expected,
        "the order on the wire must be the profile's captured order"
    );
    assert_eq!(
        received[0].header("user-agent"),
        Some(profile.user_agent.as_str())
    );
    assert_eq!(
        received[0].header("accept-language"),
        Some(profile.accept_language.as_str())
    );
}

#[tokio::test]
async fn a_post_body_reaches_the_origin_intact() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, &["example.test"]);

    engine
        .send(request(
            Method::POST,
            &server.url_for("example.test", "/submit"),
            Body::fixed("field=value"),
        ))
        .await
        .expect("the request must succeed");

    let received = server.received();
    assert_eq!(received[0].method, "POST");
    assert_eq!(received[0].body_text(), "field=value");
}

// -------------------------------------------------------------- pool reuse

#[tokio::test]
async fn two_requests_to_one_origin_share_a_single_connection() {
    let server = TestServer::always(Reply::text("body")).await;
    let engine = engine_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/");

    for _ in 0..2 {
        let response = engine
            .send(get(&url))
            .await
            .expect("the request must succeed");
        // The body has to be read before the connection returns to the pool,
        // which is part of what this asserts.
        let _ = text_of(response).await;
    }

    assert_eq!(server.request_count(), 2);
    assert_eq!(
        server.accepts(),
        1,
        "the second request must reuse the first connection"
    );
}

#[tokio::test]
async fn a_connection_the_server_closed_is_replaced_rather_than_reused() {
    let server = TestServer::always(Reply::text("body").closing()).await;
    let engine = engine_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/");

    for _ in 0..2 {
        let response = engine
            .send(get(&url))
            .await
            .expect("the request must succeed");
        let _ = text_of(response).await;
    }

    assert_eq!(server.accepts(), 2);
}

/// The pool-key requirement, tested where it matters: one shared pool, two
/// identities, one origin.
#[tokio::test]
async fn two_profiles_sharing_a_pool_never_share_a_connection() {
    let server = TestServer::always(Reply::text("body")).await;
    let pool = Pool::new(PoolConfig::default());

    // A second identity differing only in its HTTP/2 preface, which is enough
    // to make it a different client to a server.
    let mut altered = Profile::chrome_stable();
    altered.name = "altered".to_owned();
    altered.http2.settings = vec![Setting::new(SettingId::INITIAL_WINDOW_SIZE, 65_535)];

    let first = engine_with(
        &server,
        &["example.test"],
        Profile::chrome_stable(),
        Some(pool.clone()),
        |_| {},
    );
    let second = engine_with(
        &server,
        &["example.test"],
        altered,
        Some(pool.clone()),
        |_| {},
    );

    assert_ne!(
        first.identity(),
        second.identity(),
        "the two engines must not be treated as the same client"
    );

    let url = server.url_for("example.test", "/");
    let _ = text_of(first.send(get(&url)).await.expect("first must succeed")).await;
    let _ = text_of(second.send(get(&url)).await.expect("second must succeed")).await;

    assert_eq!(server.request_count(), 2);
    assert_eq!(
        server.accepts(),
        2,
        "a second identity must open its own connection, or it would be observed with \
         the first identity's TLS and HTTP/2 fingerprint"
    );

    // The same identity twice still reuses, so the isolation above is the key
    // doing its job rather than pooling being broken outright.
    let _ = text_of(first.send(get(&url)).await.expect("third must succeed")).await;
    assert_eq!(server.accepts(), 2);
}

// ---------------------------------------------------------------- redirects

#[tokio::test]
async fn a_post_becomes_a_get_without_a_body_on_301_302_and_303() {
    for status in [301u16, 302, 303] {
        let server = TestServer::start(move |request| {
            if request.target == "/start" {
                Reply::redirect(status, "/landing")
            } else {
                Reply::text("arrived")
            }
        })
        .await;
        let engine = engine_for(&server, &["example.test"]);

        let response = engine
            .send(request(
                Method::POST,
                &server.url_for("example.test", "/start"),
                Body::fixed("payload"),
            ))
            .await
            .unwrap_or_else(|error| panic!("status {status} must be followed: {error}"));

        assert_eq!(text_of(response).await, "arrived");

        let received = server.received();
        assert_eq!(received.len(), 2, "status {status}");
        assert_eq!(received[0].method, "POST", "status {status}");
        assert_eq!(received[1].method, "GET", "status {status}");
        assert!(
            received[1].body.is_empty(),
            "status {status} must drop the body"
        );
        assert_eq!(
            received[1].header("content-length"),
            None,
            "status {status} must drop Content-Length along with the body"
        );
    }
}

#[tokio::test]
async fn a_post_keeps_its_method_and_body_on_307_and_308() {
    for status in [307u16, 308] {
        let server = TestServer::start(move |request| {
            if request.target == "/start" {
                Reply::redirect(status, "/landing")
            } else {
                Reply::text("arrived")
            }
        })
        .await;
        let engine = engine_for(&server, &["example.test"]);

        engine
            .send(request(
                Method::POST,
                &server.url_for("example.test", "/start"),
                Body::fixed("payload"),
            ))
            .await
            .unwrap_or_else(|error| panic!("status {status} must be followed: {error}"));

        let received = server.received();
        assert_eq!(received.len(), 2, "status {status}");
        assert_eq!(received[1].method, "POST", "status {status}");
        assert_eq!(
            received[1].body_text(),
            "payload",
            "status {status} must replay the body"
        );
    }
}

#[tokio::test]
async fn a_relative_location_is_resolved_against_the_url_that_sent_it() {
    let server = TestServer::start(|request| {
        if request.target == "/a/b/c" {
            Reply::redirect(302, "../d")
        } else {
            Reply::text(&request.target)
        }
    })
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/a/b/c")))
        .await
        .expect("the redirect must be followed");

    assert_eq!(text_of(response).await, "/a/d");
}

#[tokio::test]
async fn exceeding_the_redirect_limit_reports_too_many_redirects() {
    let server = TestServer::always(Reply::redirect(302, "/again")).await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.redirect = RedirectPolicy::Follow { limit: 3 };
    });

    let error = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect_err("a redirect loop must terminate");

    assert!(
        matches!(error, Error::TooManyRedirects { limit: 3 }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_redirect_policy_of_none_hands_the_3xx_back_to_the_caller() {
    let server = TestServer::always(Reply::redirect(302, "/elsewhere")).await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.redirect = RedirectPolicy::None;
    });

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("a 3xx is an ordinary response under this policy");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(server.request_count(), 1);
}

// ------------------------------------------------------ credential stripping

/// The required test. Both hostnames point at one listener, so the hop is a
/// real network hop that is nonetheless a different origin.
#[tokio::test]
async fn credentials_are_dropped_on_a_cross_origin_hop_and_kept_on_a_same_origin_one() {
    static CROSS_TARGET: OnceLock<String> = OnceLock::new();

    let server = TestServer::start(|request| match request.target.as_str() {
        "/same-origin" => Reply::redirect(302, "/landing"),
        "/cross-origin" => Reply::redirect(
            302,
            CROSS_TARGET
                .get()
                .expect("the target is set before any request is made"),
        ),
        _ => Reply::text("arrived"),
    })
    .await;

    let port = server.port();
    CROSS_TARGET
        .set(format!("http://second.test:{port}/landing"))
        .expect("the target is set exactly once");

    let engine = engine_for(&server, &["first.test", "second.test"]);

    let with_credentials = |url: &str| {
        let mut request = get(url);
        let headers = request.headers_mut();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer super-secret-token"),
        );
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session=secret-session"),
        );
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            http::HeaderValue::from_static("Basic secret-proxy"),
        );
        request
    };

    // Same origin: everything survives the hop.
    engine
        .send(with_credentials(&format!(
            "http://first.test:{port}/same-origin"
        )))
        .await
        .expect("the same-origin redirect must be followed");

    let same_origin_hop = server
        .received()
        .last()
        .cloned()
        .expect("a second request must have arrived");
    assert_eq!(
        same_origin_hop.header("authorization"),
        Some("Bearer super-secret-token"),
        "a same-origin redirect must keep Authorization"
    );
    assert_eq!(
        same_origin_hop.header("cookie"),
        Some("session=secret-session"),
        "a same-origin redirect must keep Cookie"
    );
    assert_eq!(
        same_origin_hop.header("proxy-authorization"),
        Some("Basic secret-proxy")
    );

    // Cross origin: none of them may follow.
    engine
        .send(with_credentials(&format!(
            "http://first.test:{port}/cross-origin"
        )))
        .await
        .expect("the cross-origin redirect must be followed");

    let cross_origin_hop = server
        .received()
        .last()
        .cloned()
        .expect("a fourth request must have arrived");
    assert_eq!(
        cross_origin_hop.header("host"),
        Some(format!("second.test:{port}").as_str()),
        "the hop must really have gone to the other origin"
    );
    assert_eq!(
        cross_origin_hop.header("authorization"),
        None,
        "Authorization must not cross an origin boundary"
    );
    assert_eq!(
        cross_origin_hop.header("cookie"),
        None,
        "Cookie must not cross an origin boundary"
    );
    assert_eq!(
        cross_origin_hop.header("proxy-authorization"),
        None,
        "Proxy-Authorization must not cross an origin boundary"
    );

    // Belt and braces: the secrets appear nowhere in the second exchange.
    let raw = format!("{:?}", cross_origin_hop.headers);
    assert!(!raw.contains("super-secret-token"), "{raw}");
    assert!(!raw.contains("secret-session"), "{raw}");
}

// ----------------------------------------------------------------- SameSite

/// An engine wired to a jar that already holds one `SameSite=Strict` and one
/// `SameSite=Lax` cookie for `app.test`.
///
/// Both sit at `Path=/` and the strict one is stored first, so RFC 6265 §5.4 ordering
/// puts it first in every `Cookie` header these tests expect.
fn engine_with_same_site_cookies(server: &TestServer, hosts: &[&str]) -> Engine {
    let jar = Arc::new(Jar::new());
    let seed = Url::parse(&server.url_for("app.test", "/")).expect("a valid seed URL");
    for header in [
        "session=strict-value; Path=/; SameSite=Strict",
        "visitor=lax-value; Path=/; SameSite=Lax",
    ] {
        let value = HeaderValue::from_static(header);
        jar.store(&seed, &mut std::iter::once(&value));
    }

    let mut resolver = StaticResolver::empty();
    for host in hosts {
        resolver = resolver.with_host((*host).to_owned(), vec![server.addr()]);
    }

    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    Engine::builder(config)
        .resolver(Arc::new(resolver))
        .cookies(jar as Arc<dyn CookieStore>)
        .build()
        .expect("the engine must build")
}

/// Names the document that is asking for `url`, the way a browser knows it.
fn initiated_by(mut options: RequestOptions, initiator: &str) -> RequestOptions {
    let url = Url::parse(initiator).expect("a valid initiator URL");
    options.initiator = Some(Origin::of(&url).expect("the initiator must have an origin"));
    options
}

fn with_options(mut request: Request, options: RequestOptions) -> Request {
    request.extensions_mut().insert(options);
    request
}

/// The `Cookie` header on the most recent request the server saw.
fn last_cookie(server: &TestServer) -> Option<String> {
    server
        .received()
        .last()
        .expect("the server must have seen a request")
        .header("cookie")
        .map(str::to_owned)
}

#[tokio::test]
async fn a_strict_cookie_is_sent_on_a_same_origin_request() {
    let server = TestServer::always(Reply::ok()).await;
    let port = server.port();
    let engine = engine_with_same_site_cookies(&server, &["app.test"]);

    let request = with_options(
        get(&format!("http://app.test:{port}/api/profile")),
        initiated_by(
            RequestOptions::api(),
            &format!("http://app.test:{port}/dashboard"),
        ),
    );
    engine
        .send(request)
        .await
        .expect("the same-origin request must succeed");

    assert_eq!(
        last_cookie(&server).as_deref(),
        Some("session=strict-value; visitor=lax-value"),
        "a SameSite=Strict cookie belongs on a same-origin request"
    );
}

#[tokio::test]
async fn a_strict_cookie_is_sent_on_a_same_site_top_level_navigation() {
    let server = TestServer::always(Reply::ok()).await;
    let port = server.port();
    let engine = engine_with_same_site_cookies(&server, &["app.test"]);

    // A different subdomain of the same registrable domain: same site, not same origin.
    let request = with_options(
        get(&format!("http://app.test:{port}/account")),
        initiated_by(
            RequestOptions::navigation(),
            &format!("http://www.app.test:{port}/"),
        ),
    );
    engine
        .send(request)
        .await
        .expect("the same-site navigation must succeed");

    assert_eq!(
        last_cookie(&server).as_deref(),
        Some("session=strict-value; visitor=lax-value"),
        "a SameSite=Strict cookie belongs on a same-site top-level navigation"
    );
}

#[tokio::test]
async fn a_strict_cookie_is_withheld_from_a_cross_site_request() {
    let server = TestServer::always(Reply::ok()).await;
    let port = server.port();
    let engine = engine_with_same_site_cookies(&server, &["app.test"]);

    // A cross-site top-level navigation: Lax's carve-out applies, Strict's does not.
    let navigation = with_options(
        get(&format!("http://app.test:{port}/account")),
        initiated_by(
            RequestOptions::navigation(),
            &format!("http://other.test:{port}/"),
        ),
    );
    engine
        .send(navigation)
        .await
        .expect("the cross-site navigation must succeed");

    assert_eq!(
        last_cookie(&server).as_deref(),
        Some("visitor=lax-value"),
        "a cross-site navigation carries Lax but never Strict"
    );

    // A cross-site subresource fetch: neither carve-out applies.
    let fetch = with_options(
        get(&format!("http://app.test:{port}/api/profile")),
        initiated_by(RequestOptions::api(), &format!("http://other.test:{port}/")),
    );
    engine
        .send(fetch)
        .await
        .expect("the cross-site fetch must succeed");

    assert_eq!(
        last_cookie(&server),
        None,
        "a cross-site subresource fetch carries neither Strict nor Lax"
    );
}

#[tokio::test]
async fn an_unattributed_request_still_carries_its_lax_cookie() {
    let server = TestServer::always(Reply::ok()).await;
    let port = server.port();
    let engine = engine_with_same_site_cookies(&server, &["app.test"]);

    // No `RequestOptions` at all, which is what the plain client sends: the engine has
    // no site information to offer, so the conservative fallback decides. This is the
    // end-to-end guard on `RequestOptions::cookie_context`'s no-initiator arm. Deriving
    // `is_top_level_navigation` from the fetch mode alone turns the default `Cors` into
    // "cross-site subresource" and empties this header, which logs out every session on
    // every site the client talks to.
    engine
        .send(get(&format!("http://app.test:{port}/api/profile")))
        .await
        .expect("the unattributed request must succeed");

    assert_eq!(
        last_cookie(&server).as_deref(),
        Some("visitor=lax-value"),
        "an unnamed initiator is not evidence of a cross-site request"
    );
}

// ---------------------------------------------------------- streaming bodies

#[tokio::test]
async fn a_redirect_that_would_replay_a_streaming_body_fails_with_a_clear_error() {
    let server = TestServer::start(|request| {
        if request.target == "/start" {
            // 307 preserves the method and the body, so the body would have to
            // go out a second time.
            Reply::redirect(307, "/landing")
        } else {
            Reply::text("arrived")
        }
    })
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let chunks = futures_util::stream::iter(vec![Ok(bytes::Bytes::from_static(b"streamed"))]);
    let error = engine
        .send(request(
            Method::POST,
            &server.url_for("example.test", "/start"),
            Body::stream(chunks, None),
        ))
        .await
        .expect_err("a streaming body cannot be replayed");

    let message = error.to_string();
    assert!(matches!(error, Error::Redirect(_)), "{error:?}");
    assert!(
        message.contains("replay"),
        "the error must say why, not merely that it failed: {message}"
    );
    assert_eq!(
        server.request_count(),
        1,
        "the second hop must not be sent with a silently emptied body"
    );
}

#[tokio::test]
async fn a_303_after_a_streaming_body_succeeds_because_the_body_is_dropped_anyway() {
    let server = TestServer::start(|request| {
        if request.target == "/start" {
            Reply::redirect(303, "/landing")
        } else {
            Reply::text("arrived")
        }
    })
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let chunks = futures_util::stream::iter(vec![Ok(bytes::Bytes::from_static(b"streamed"))]);
    let response = engine
        .send(request(
            Method::POST,
            &server.url_for("example.test", "/start"),
            Body::stream(chunks, None),
        ))
        .await
        .expect("a 303 drops the body, so there is nothing to replay");

    assert_eq!(text_of(response).await, "arrived");
}

// ----------------------------------------------------------------- timeouts

#[tokio::test]
async fn a_server_that_never_answers_times_out_while_awaiting_the_response() {
    let server = TestServer::always(Reply::ok().delayed(Duration::from_secs(60))).await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.timeout = Some(Duration::from_millis(150));
    });

    let error = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect_err("the deadline must fire");

    assert!(
        matches!(error, Error::Timeout(Phase::AwaitResponse)),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_head_timeout_bounds_one_hop_even_without_a_whole_request_deadline() {
    let server = TestServer::always(Reply::ok().delayed(Duration::from_secs(60))).await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.timeout = None;
        config.head_timeout = Some(Duration::from_millis(150));
    });

    let error = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect_err("the head timeout must fire");

    assert!(
        matches!(error, Error::Timeout(Phase::AwaitResponse)),
        "{error:?}"
    );
}

/// A server that answers `/prompt` at once and never answers anything else.
///
/// The prompt reply is what warms a pooled connection, so the stalling hop that
/// follows it reuses that connection instead of dialling. That matters because
/// these tests pause the clock: a paused clock jumps to the next deadline as
/// soon as the runtime idles, and a dial still in flight when it jumps would
/// expire the connect timeout instead of the one under test.
fn prompt_then_silent(request: &Recorded) -> Reply {
    if request.target == "/prompt" {
        Reply::text("here")
    } else {
        Reply::ok().delayed(Duration::from_secs(3600))
    }
}

#[tokio::test]
async fn a_default_configured_engine_gives_up_when_the_head_never_arrives() {
    let server = TestServer::start(prompt_then_silent).await;
    // `head_timeout` is left exactly as `EngineConfig::new` leaves it, because
    // that default is the entire subject of this test.
    let engine = engine_for(&server, &["example.test"]);

    let warm = engine
        .send(get(&server.url_for("example.test", "/prompt")))
        .await
        .expect("the first request must succeed");
    assert_eq!(text_of(warm).await, "here");

    tokio::time::pause();

    // The outer bound is the difference between a test that reports and a test
    // that hangs: without a default head timeout the send below never returns,
    // and a suite people learn to skip guards nothing.
    let outcome = tokio::time::timeout(
        Duration::from_secs(600),
        engine.send(get(&server.url_for("example.test", "/silent"))),
    )
    .await
    .expect("a default-configured engine must bound the head wait itself, not hang on it");

    let error = outcome.expect_err("the head never arrives, so the request must fail");
    assert!(
        matches!(error, Error::Timeout(Phase::AwaitResponse)),
        "{error:?}"
    );
    assert_eq!(
        server.accepts(),
        1,
        "the stalling hop must have reused the warmed connection rather than dialled again"
    );
}

#[tokio::test]
async fn an_explicit_head_timeout_of_none_still_means_no_bound() {
    let server = TestServer::start(prompt_then_silent).await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.head_timeout = None;
    });

    let warm = engine
        .send(get(&server.url_for("example.test", "/prompt")))
        .await
        .expect("the first request must succeed");
    assert_eq!(text_of(warm).await, "here");

    tokio::time::pause();

    // Long-polling asks for exactly this, so opting out has to keep working:
    // the outer bound is what expires here, not anything the engine imposed.
    let outcome = tokio::time::timeout(
        Duration::from_secs(1800),
        engine.send(get(&server.url_for("example.test", "/silent"))),
    )
    .await;

    assert!(
        outcome.is_err(),
        "an opted-out head wait must outlast half an hour of silence, not end early"
    );
}

#[tokio::test]
async fn a_server_that_stalls_after_the_head_times_out_while_receiving_the_body() {
    let server = TestServer::always(
        Reply::ok()
            .with_header("content-length", "1024")
            .stalling_after_head(),
    )
    .await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.timeout = Some(Duration::from_millis(200));
    });

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the head arrives promptly");

    let error = response
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect_err("the body never arrives, so the deadline must fire");

    assert!(
        matches!(error, Error::Timeout(Phase::ReceiveBody)),
        "a deadline must cover the body, not only the head: {error:?}"
    );
}

#[tokio::test]
async fn the_request_deadline_spans_a_redirect_chain_rather_than_restarting() {
    let server =
        TestServer::start(|_| Reply::redirect(302, "/again").delayed(Duration::from_millis(80)))
            .await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.timeout = Some(Duration::from_millis(250));
        config.redirect = RedirectPolicy::Follow { limit: 50 };
    });

    let started = std::time::Instant::now();
    let error = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect_err("a chain of slow hops must exhaust the budget");

    assert!(error.is_timeout(), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "every hop must draw down one shared budget rather than getting a fresh one: {:?}",
        started.elapsed()
    );
    assert!(
        server.request_count() < 50,
        "the deadline, not the hop limit, must have stopped this"
    );
}

// ------------------------------------------------------------ decompression

#[tokio::test]
async fn a_gzip_response_is_decoded_and_its_encoding_headers_are_cleaned_up() {
    let payload = "compressed payload that the client must decode";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload.as_bytes())
        .expect("writing to an in-memory encoder cannot fail");
    let compressed = encoder.finish().expect("the encoder must finish");

    let server = TestServer::always(
        Reply::ok()
            .with_header("content-encoding", "gzip")
            .with_body(compressed),
    )
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the request must succeed");

    assert!(
        !response
            .headers()
            .contains_key(http::header::CONTENT_ENCODING),
        "a decoded body must not still claim to be encoded"
    );
    assert!(
        !response
            .headers()
            .contains_key(http::header::CONTENT_LENGTH),
        "the encoded length no longer describes the decoded body"
    );
    assert_eq!(text_of(response).await, payload);
}

#[tokio::test]
async fn the_request_advertises_the_profiles_accept_encoding() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, &["example.test"]);

    engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the request must succeed");

    assert_eq!(
        server.received()[0].header("accept-encoding"),
        Some(Profile::chrome_stable().accept_encoding.as_str())
    );
}

// ------------------------------------------------------------------- errors

#[tokio::test]
async fn a_host_that_does_not_resolve_reports_a_resolve_error() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, &["known.test"]);

    let error = engine
        .send(get(&server.url_for("unknown.test", "/")))
        .await
        .expect_err("an unpinned host cannot resolve");

    assert!(
        matches!(&error, Error::Resolve { host, .. } if host == "unknown.test"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_request_without_a_scheme_is_rejected_before_any_connection_is_made() {
    let server = TestServer::always(Reply::ok()).await;
    let engine = engine_for(&server, &["example.test"]);

    let error = engine
        .send(get("/relative/path"))
        .await
        .expect_err("a relative URI cannot be sent");

    assert!(matches!(error, Error::Url(_)), "{error:?}");
    assert_eq!(server.accepts(), 0, "nothing should have been dialled");
}

// -------------------------------------------------------------------- HSTS

/// The engine must not send the plaintext request at all once a policy is
/// known — a redirect would already be too late, because the request went out.
#[tokio::test]
async fn a_recorded_hsts_policy_upgrades_a_later_plaintext_request() {
    let server = TestServer::always(
        Reply::text("body").with_header("strict-transport-security", "max-age=31536000"),
    )
    .await;
    let engine = engine_for(&server, &["example.test"]);

    // The policy can only be recorded from a TLS response, and this harness is
    // plaintext, so the store is reached directly to set up the state under
    // test. What is being tested is what the engine does *with* a policy.
    engine.hsts().record(
        "example.test",
        "max-age=31536000",
        true,
        std::time::SystemTime::now(),
    );

    let url = server.url_for("example.test", "/");
    let error = engine
        .send(get(&url))
        .await
        .expect_err("a plaintext request to a pinned host must not be sent as plaintext");

    // The upgraded request goes to port 443 of a host that only listens on the
    // test port, so it fails to connect — which is the observable proof that
    // the scheme was rewritten before anything was sent.
    assert!(
        server.request_count() == 0,
        "the plaintext request reached the origin despite an HSTS policy: {error}"
    );
}

#[tokio::test]
async fn a_strict_transport_security_header_over_plaintext_is_not_recorded() {
    let server = TestServer::always(
        Reply::text("body").with_header("strict-transport-security", "max-age=31536000"),
    )
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let url = server.url_for("example.test", "/");
    let _ = text_of(engine.send(get(&url)).await.expect("the request succeeds")).await;

    // A second request must still be plaintext: honouring an STS header that
    // arrived over cleartext would let anyone who can inject into it pin the
    // origin, which RFC 6797 section 8.1 forbids.
    let _ = text_of(
        engine
            .send(get(&url))
            .await
            .expect("the second request must also succeed over plaintext"),
    )
    .await;
    assert_eq!(server.request_count(), 2);
}

// ------------------------------------------------------------------ timings

/// The `ResponseInfo` the engine attaches, which is where the timings ride.
fn info_of(response: &Response) -> &chromulate_http::ResponseInfo {
    response
        .extensions()
        .get::<chromulate_http::ResponseInfo>()
        .expect("the engine must attach the response info")
}

#[tokio::test]
async fn a_request_that_opens_a_connection_times_the_phases_it_performed() {
    let server = TestServer::always(Reply::text("body")).await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the request succeeds");
    let timings = info_of(&response).timings;

    assert!(
        timings.resolve().is_some(),
        "a request that had to resolve a name must report how long it took: {timings:?}"
    );
    assert!(
        timings.connect().is_some(),
        "a request that opened a socket must report how long it took: {timings:?}"
    );
    assert!(
        timings.handshake().is_none(),
        "a plaintext origin performs no TLS handshake, so there is nothing to time: {timings:?}"
    );
    assert!(
        timings.head() > Duration::ZERO,
        "the response head cannot have arrived before the request was sent: {timings:?}"
    );
}

#[tokio::test]
async fn a_pooled_request_reports_no_connection_phases_rather_than_zero_ones() {
    let server = TestServer::always(Reply::text("body")).await;
    let engine = engine_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/");

    // The first request opens the connection; the body has to be read before
    // an HTTP/1.1 connection goes back to the pool.
    let _ = text_of(
        engine
            .send(get(&url))
            .await
            .expect("the first request succeeds"),
    )
    .await;

    let response = engine
        .send(get(&url))
        .await
        .expect("the second request succeeds");
    let timings = info_of(&response).timings;

    assert_eq!(
        server.accepts(),
        1,
        "the fixture is only meaningful if the second request reused the connection"
    );
    // `Some(ZERO)` would read as "the handshake was instant". No handshake
    // happened at all, and the difference is the whole point of the `Option`.
    assert_eq!(timings.resolve(), None, "{timings:?}");
    assert_eq!(timings.connect(), None, "{timings:?}");
    assert_eq!(timings.handshake(), None, "{timings:?}");
}

#[tokio::test]
async fn a_slow_origin_shows_up_in_the_time_to_head_and_not_in_the_connect_phases() {
    let server = TestServer::always(Reply::text("body").delayed(Duration::from_millis(200))).await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the request succeeds");
    let timings = info_of(&response).timings;

    assert!(
        timings.head() >= Duration::from_millis(200),
        "an origin that thinks for 200ms must show it in the time to head: {timings:?}"
    );
    assert!(
        timings.connect().expect("the connection was opened") < Duration::from_millis(200),
        "the origin's thinking time must not be attributed to the connect phase: {timings:?}"
    );
}

#[tokio::test]
async fn a_redirect_chain_separates_the_earlier_hops_from_the_final_one() {
    let server = TestServer::start(|request| {
        if request.target == "/start" {
            // Slow enough to be measurable, and on the first hop only, so the
            // delay can only appear as redirect time.
            Reply::redirect(302, "/end").delayed(Duration::from_millis(200))
        } else {
            Reply::text("arrived")
        }
    })
    .await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/start")))
        .await
        .expect("the redirect is followed");
    let timings = info_of(&response).timings;

    assert_eq!(info_of(&response).url.path(), "/end");
    assert!(
        timings.redirect() >= Duration::from_millis(200),
        "the first hop's 200ms belongs to redirect time: {timings:?}"
    );
    assert!(
        timings.head() >= timings.redirect(),
        "every milestone counts from the start of the request: {timings:?}"
    );
    // The second hop reuses the first hop's connection, so the reported phases
    // describe the final hop and not the one that did the connecting.
    assert_eq!(server.accepts(), 1);
    assert_eq!(timings.connect(), None, "{timings:?}");
}

#[tokio::test]
async fn reading_the_body_is_visible_in_elapsed_but_not_in_the_time_to_head() {
    let server = TestServer::always(Reply::text("body")).await;
    let engine = engine_for(&server, &["example.test"]);

    let response = engine
        .send(get(&server.url_for("example.test", "/")))
        .await
        .expect("the request succeeds");
    let timings = info_of(&response).timings;
    let head = timings.head();

    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = text_of(response).await;

    assert_eq!(timings.head(), head, "the head milestone is fixed");
    assert!(
        timings.elapsed() >= head + Duration::from_millis(50),
        "elapsed read after the body is the time to body complete: {timings:?}"
    );
}

/// A redirect body is thrown away, but it is still read off the socket first so
/// the connection can be reused. That read had no deadline on it: a server that
/// sends `302` with a `Content-Length` and then stops writing held the whole
/// request open for as long as it cared to, regardless of what the caller asked
/// for. The outer `timeout` here is the test harness, not the behaviour under
/// test — without the fix it is what ends the test, and its presence is the
/// difference between a red test and one that hangs the suite.
#[tokio::test]
async fn a_stalled_redirect_body_cannot_outlive_the_request_deadline() {
    let server = TestServer::start(|recorded| {
        if recorded.target == "/start" {
            Reply::redirect(302, "/landing")
                .with_header("content-length", "1024")
                .stalling_after_head()
        } else {
            Reply::text("arrived")
        }
    })
    .await;
    let engine = tuned(&server, &["example.test"], |config| {
        config.timeout = Some(Duration::from_millis(200));
    });

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        engine.send(get(&server.url_for("example.test", "/start"))),
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        outcome.is_ok(),
        "the drain ignored the 200ms deadline and was still going after {elapsed:?}"
    );
    assert!(
        outcome.expect("checked above").is_err(),
        "a request that could not finish inside its deadline must report an error"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "the deadline was 200ms but the request took {elapsed:?}"
    );
}
