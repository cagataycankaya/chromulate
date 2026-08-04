//! The public API from the README, exercised against a local server.
//!
//! The README's usage section is a contract. These tests drive the same shapes
//! it shows, so a change that breaks the documented API breaks a test rather
//! than only the documentation.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chromulate::cookie::Jar;
use chromulate::dns::StaticResolver;
use chromulate::{Client, Error, Profile, RedirectPolicy, Stop, StopReason};
use common::{Reply, TestServer};
use futures_util::StreamExt as _;

fn client_for(server: &TestServer, hosts: &[&str]) -> Client {
    build(server, hosts, |builder| builder)
}

fn build(
    server: &TestServer,
    hosts: &[&str],
    configure: impl FnOnce(chromulate::ClientBuilder) -> chromulate::ClientBuilder,
) -> Client {
    let mut resolver = StaticResolver::empty();
    for host in hosts {
        resolver = resolver.with_host((*host).to_owned(), vec![server.addr()]);
    }
    configure(Client::builder().resolver(resolver))
        .build()
        .expect("the client must build")
}

// -------------------------------------------------------------- the basics

#[tokio::test]
async fn a_get_returns_the_status_version_headers_and_body() {
    let server = TestServer::always(
        Reply::text("hello")
            .with_header("content-type", "text/plain")
            .with_header("x-marker", "seen"),
    )
    .await;
    let client = client_for(&server, &["example.test"]);

    let response = client
        .get(server.url_for("example.test", "/page"))
        .send()
        .await
        .expect("the request must succeed");

    assert_eq!(response.status(), chromulate::StatusCode::OK);
    assert_eq!(response.version(), chromulate::Version::HTTP_11);
    assert_eq!(
        response.headers().get("x-marker").map(|v| v.as_bytes()),
        Some(&b"seen"[..])
    );
    assert_eq!(response.url().path(), "/page");
    assert_eq!(
        response.text().await.expect("the body must decode"),
        "hello"
    );
}

#[tokio::test]
async fn every_method_helper_sends_that_method() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/");

    let _ = client.get(&url).send().await.expect("get");
    let _ = client.post(&url).send().await.expect("post");
    let _ = client.put(&url).send().await.expect("put");
    let _ = client.patch(&url).send().await.expect("patch");
    let _ = client.delete(&url).send().await.expect("delete");
    let _ = client.head(&url).send().await.expect("head");

    let methods: Vec<String> = server
        .received()
        .into_iter()
        .map(|request| request.method)
        .collect();
    assert_eq!(methods, ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
}

#[tokio::test]
async fn a_request_carries_headers_and_query_parameters() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    client
        .get(server.url_for("example.test", "/search?existing=kept"))
        .header("x-custom", "value")
        .query([("q", "rust"), ("page", "2")])
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(received.header("x-custom"), Some("value"));
    assert_eq!(
        received.target, "/search?existing=kept&q=rust&page=2",
        "query() must append rather than replace what the URL already carried"
    );
}

#[tokio::test]
async fn a_body_is_sent_as_given() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    client
        .post(server.url_for("example.test", "/"))
        .body("raw bytes")
        .send()
        .await
        .expect("the request must succeed");

    assert_eq!(server.received()[0].body_text(), "raw bytes");
}

// ------------------------------------------------------ stopping early

/// The default path, which no early-stop work may disturb: `bytes()` reads all
/// of it and the connection comes back, exactly as before.
#[tokio::test]
async fn bytes_still_reads_the_whole_body_and_returns_the_connection() {
    let mut page = b"<head>application/ld+json{}".to_vec();
    page.resize(64 * 1024, b'x');

    let server = TestServer::always(Reply::ok().with_body(page.clone())).await;
    let client = client_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/product");

    let body = client
        .get(&url)
        .send()
        .await
        .expect("the request must succeed")
        .bytes()
        .await
        .expect("the body must read");

    assert_eq!(body.len(), page.len());
    assert_eq!(body, page);

    let _ = client
        .get(&url)
        .send()
        .await
        .expect("the second request must succeed")
        .bytes()
        .await
        .expect("the second body must read");
    assert_eq!(
        server.accepts(),
        1,
        "an ordinary whole-body read must still pool its connection"
    );
}

#[tokio::test]
async fn bytes_until_a_marker_reads_the_front_of_the_body_and_says_it_matched() {
    let mut page = b"<head>application/ld+json{\"price\":42}".to_vec();
    page.resize(512 * 1024, b'x');

    let server = TestServer::always(Reply::ok().with_body(page)).await;
    let client = client_for(&server, &["example.test"]);

    let prefix = client
        .get(server.url_for("example.test", "/product"))
        .send()
        .await
        .expect("the request must succeed")
        .bytes_until(Stop::marker("application/ld+json").plus(11))
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::Matched);
    assert!(prefix.matched());
    assert!(!prefix.is_complete());
    assert_eq!(
        prefix.bytes(),
        &b"<head>application/ld+json{\"price\":42"[..]
    );
}

/// The distinction a scraper mis-parses without: this page has no marker, and
/// the answer has to say so rather than hand back a short read.
#[tokio::test]
async fn bytes_until_reports_a_page_that_never_contained_the_marker() {
    let server = TestServer::always(Reply::text("a page with no structured data")).await;
    let client = client_for(&server, &["example.test"]);

    let prefix = client
        .get(server.url_for("example.test", "/product"))
        .send()
        .await
        .expect("the request must succeed")
        .bytes_until(Stop::marker("application/ld+json"))
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.reason(), StopReason::EndOfBody);
    assert!(!prefix.matched());
    assert!(prefix.is_complete());
    assert_eq!(prefix.bytes(), "a page with no structured data");
}

/// The client's ceiling still bounds the read, but a truncating read that
/// failed on truncation would have nothing to report, so it stops instead.
#[tokio::test]
async fn the_clients_maximum_response_size_caps_the_budget_without_failing() {
    let server = TestServer::always(Reply::ok().with_body(vec![b'x'; 64 * 1024])).await;
    let client = build(&server, &["example.test"], |builder| {
        builder.max_response_size(4096)
    });
    let url = server.url_for("example.test", "/product");

    let prefix = client
        .get(&url)
        .send()
        .await
        .expect("the request must succeed")
        .bytes_until(Stop::marker("never-present"))
        .await
        .expect("a budget is an instruction to stop, not a limit to fail on");

    assert_eq!(prefix.bytes().len(), 4096);
    assert_eq!(prefix.reason(), StopReason::Budget);

    // The same client's `bytes()` still fails on the same body, so the ceiling
    // has not been quietly relaxed for everyone.
    let error = client
        .get(&url)
        .send()
        .await
        .expect("the request must succeed")
        .bytes()
        .await
        .expect_err("bytes() still refuses an oversized body");
    assert!(
        matches!(error, Error::BodyTooLarge { limit: 4096 }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_smaller_budget_than_the_clients_ceiling_is_the_one_that_applies() {
    let server = TestServer::always(Reply::ok().with_body(vec![b'x'; 64 * 1024])).await;
    let client = client_for(&server, &["example.test"]);

    let prefix = client
        .get(server.url_for("example.test", "/product"))
        .send()
        .await
        .expect("the request must succeed")
        .bytes_until(Stop::after(100))
        .await
        .expect("the prefix must read");

    assert_eq!(prefix.bytes().len(), 100);
    assert_eq!(prefix.reason(), StopReason::Budget);
}

// ---------------------------------------------------------------- encoding

#[tokio::test]
async fn text_decodes_through_the_charset_the_server_declared() {
    // `grün` in ISO-8859-1: the 0xFC byte is invalid on its own in UTF-8, so a
    // client that ignored the charset would produce a replacement character.
    let server = TestServer::always(
        Reply::ok()
            .with_header("content-type", "text/plain; charset=iso-8859-1")
            .with_body(vec![b'g', b'r', 0xFC, b'n']),
    )
    .await;
    let client = client_for(&server, &["example.test"]);

    let text = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed")
        .text()
        .await
        .expect("the body must decode");

    assert_eq!(text, "grün");
}

#[tokio::test]
async fn a_body_with_no_declared_charset_is_read_as_utf8_without_failing() {
    // A trailing byte that is not valid UTF-8 on its own. Reading must replace
    // it rather than fail: a body is data, and refusing to hand back any of it
    // because one byte is malformed is worse than a replacement character.
    let server = TestServer::always(Reply::ok().with_body(vec![b'o', b'k', 0xFF])).await;
    let client = client_for(&server, &["example.test"]);

    let text = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed")
        .text()
        .await
        .expect("invalid bytes must not fail the read");

    assert!(text.starts_with("ok"), "{text:?}");
    assert!(
        text.contains('\u{FFFD}'),
        "the bad byte is replaced: {text:?}"
    );
}

/// A byte-order mark wins over the declared charset, which is what the WHATWG
/// Encoding Standard requires and is surprising enough to pin down.
#[tokio::test]
async fn a_byte_order_mark_overrides_the_declared_charset() {
    // The UTF-16LE BOM followed by one code unit for `A`.
    let server = TestServer::always(
        Reply::ok()
            .with_header("content-type", "text/plain; charset=iso-8859-1")
            .with_body(vec![0xFF, 0xFE, 0x41, 0x00]),
    )
    .await;
    let client = client_for(&server, &["example.test"]);

    let text = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed")
        .text()
        .await
        .expect("the body must decode");

    assert_eq!(
        text, "A",
        "the BOM says UTF-16LE, so the Latin-1 the header claimed is ignored"
    );
}

// ------------------------------------------------------------------ limits

#[tokio::test]
async fn a_body_over_the_size_limit_is_refused_rather_than_buffered() {
    let server = TestServer::always(Reply::ok().with_body(vec![b'x'; 4096])).await;
    let client = build(&server, &["example.test"], |builder| {
        builder.max_response_size(1024)
    });

    let error = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the head arrives")
        .bytes()
        .await
        .expect_err("a body over the limit must be refused");

    assert!(
        matches!(error, Error::BodyTooLarge { limit: 1024 }),
        "{error:?}"
    );
}

#[tokio::test]
async fn streaming_is_not_bound_by_the_buffering_limit() {
    let server = TestServer::always(Reply::ok().with_body(vec![b'x'; 4096])).await;
    let client = build(&server, &["example.test"], |builder| {
        builder.max_response_size(1024)
    });

    let mut stream = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed")
        .bytes_stream();

    let mut total = 0usize;
    while let Some(chunk) = stream.next().await {
        total += chunk.expect("the stream must not fail").len();
    }

    assert_eq!(
        total, 4096,
        "the limit guards the convenience methods, not the stream"
    );
}

// ----------------------------------------------------------------- cookies

#[tokio::test]
async fn a_cookie_the_server_sets_is_replayed_on_the_next_request() {
    let server = TestServer::start(|request| {
        if request.target == "/login" {
            Reply::ok().with_header("set-cookie", "session=abc123; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await;
    let client = client_for(&server, &["example.test"]);

    let login = client
        .get(server.url_for("example.test", "/login"))
        .send()
        .await
        .expect("login must succeed");
    let _ = login.bytes().await;

    let echoed = client
        .get(server.url_for("example.test", "/whoami"))
        .send()
        .await
        .expect("the second request must succeed")
        .text()
        .await
        .expect("the body must decode");

    assert_eq!(echoed, "session=abc123");
}

#[tokio::test]
async fn turning_the_cookie_store_off_stops_the_replay() {
    let server = TestServer::start(|request| {
        if request.target == "/login" {
            Reply::ok().with_header("set-cookie", "session=abc123; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await;
    let client = build(&server, &["example.test"], |builder| {
        builder.cookie_store(false)
    });

    let _ = client
        .get(server.url_for("example.test", "/login"))
        .send()
        .await
        .expect("login must succeed")
        .bytes()
        .await;

    let echoed = client
        .get(server.url_for("example.test", "/whoami"))
        .send()
        .await
        .expect("the second request must succeed")
        .text()
        .await
        .expect("the body must decode");

    assert_eq!(echoed, "<none>");
    assert!(client.cookies().is_none());
}

#[tokio::test]
async fn two_clients_can_share_one_session_through_a_shared_jar() {
    let server = TestServer::start(|request| {
        if request.target == "/login" {
            Reply::ok().with_header("set-cookie", "session=shared; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await;

    let jar = Arc::new(Jar::new());
    let first = build(&server, &["example.test"], |builder| {
        builder.cookie_jar(Arc::clone(&jar))
    });
    let second = build(&server, &["example.test"], |builder| {
        builder.cookie_jar(Arc::clone(&jar))
    });

    let _ = first
        .get(server.url_for("example.test", "/login"))
        .send()
        .await
        .expect("login must succeed")
        .bytes()
        .await;

    let echoed = second
        .get(server.url_for("example.test", "/whoami"))
        .send()
        .await
        .expect("the second client must succeed")
        .text()
        .await
        .expect("the body must decode");

    assert_eq!(echoed, "session=shared");
    assert_eq!(jar.export().cookies.len(), 1);
}

// --------------------------------------------------------------- redirects

#[tokio::test]
async fn the_response_url_is_the_hop_that_answered_not_the_one_requested() {
    let server = TestServer::start(|request| {
        if request.target == "/start" {
            Reply::redirect(302, "/finish")
        } else {
            Reply::text("arrived")
        }
    })
    .await;
    let client = client_for(&server, &["example.test"]);

    let response = client
        .get(server.url_for("example.test", "/start"))
        .send()
        .await
        .expect("the redirect must be followed");

    assert_eq!(response.url().path(), "/finish");
}

#[tokio::test]
async fn a_per_request_redirect_policy_overrides_the_clients() {
    let server = TestServer::always(Reply::redirect(302, "/elsewhere")).await;
    let client = client_for(&server, &["example.test"]);

    let response = client
        .get(server.url_for("example.test", "/"))
        .redirect(RedirectPolicy::None)
        .send()
        .await
        .expect("the 3xx is an ordinary response under this policy");

    assert_eq!(response.status(), chromulate::StatusCode::FOUND);
}

// ------------------------------------------------------------------ errors

#[tokio::test]
async fn error_for_status_turns_a_404_into_an_error_and_leaves_a_200_alone() {
    let server = TestServer::start(|request| {
        if request.target == "/missing" {
            Reply::new(404)
        } else {
            Reply::ok()
        }
    })
    .await;
    let client = client_for(&server, &["example.test"]);

    let error = client
        .get(server.url_for("example.test", "/missing"))
        .send()
        .await
        .expect("the request itself succeeds")
        .error_for_status()
        .expect_err("a 404 must become an error");
    assert!(error.to_string().contains("404"), "{error}");

    client
        .get(server.url_for("example.test", "/present"))
        .send()
        .await
        .expect("the request must succeed")
        .error_for_status()
        .expect("a 200 must pass through");
}

#[tokio::test]
async fn a_url_that_is_not_a_url_fails_at_send_rather_than_panicking() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    let error = client
        .get("not a url at all")
        .send()
        .await
        .expect_err("a malformed URL must be reported");
    assert!(matches!(error, Error::Url(_)), "{error:?}");
}

#[tokio::test]
async fn a_scheme_the_client_does_not_speak_is_refused_by_name() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    let error = client
        .get("ftp://example.test/file")
        .send()
        .await
        .expect_err("ftp is not an HTTP scheme");
    assert!(
        matches!(&error, Error::UnsupportedScheme(scheme) if scheme == "ftp"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_request_timeout_overrides_the_clients_own() {
    let server = TestServer::always(Reply::ok().delayed(Duration::from_secs(60))).await;
    let client = build(&server, &["example.test"], |builder| {
        builder.timeout(Duration::from_secs(600))
    });

    let error = client
        .get(server.url_for("example.test", "/"))
        .timeout(Duration::from_millis(150))
        .send()
        .await
        .expect_err("the per-request timeout must fire");

    assert!(error.is_timeout(), "{error:?}");
}

/// A server that answers `/prompt` at once and never answers anything else.
///
/// The prompt reply warms a pooled connection so the stalling request that
/// follows reuses it instead of dialling. The tests below pause the clock, and a
/// paused clock jumps to the next deadline as soon as the runtime idles — a dial
/// still in flight when it jumps would expire the connect timeout rather than
/// the one under test.
fn prompt_then_silent(request: &common::Recorded) -> Reply {
    if request.target == "/prompt" {
        Reply::text("here")
    } else {
        Reply::ok().delayed(Duration::from_secs(3600))
    }
}

#[tokio::test]
async fn a_default_built_client_gives_up_when_the_head_never_arrives() {
    let server = TestServer::start(prompt_then_silent).await;
    // Nothing but the resolver is configured: the timeouts are whatever
    // `Client::builder()` hands out, which is what this test is about.
    let client = client_for(&server, &["example.test"]);

    let warm = client
        .get(server.url_for("example.test", "/prompt"))
        .send()
        .await
        .expect("the first request must succeed");
    assert_eq!(warm.text().await.expect("the body must decode"), "here");

    tokio::time::pause();

    // The outer bound is the difference between a test that reports and a test
    // that hangs: with no default head timeout the send below never returns.
    let outcome = tokio::time::timeout(
        Duration::from_secs(600),
        client.get(server.url_for("example.test", "/silent")).send(),
    )
    .await
    .expect("a default-built client must bound the head wait itself, not hang on it");

    let error = outcome.expect_err("the head never arrives, so the request must fail");
    assert!(error.is_timeout(), "{error:?}");
}

#[tokio::test]
async fn a_client_can_opt_out_of_the_default_head_timeout_for_long_polling() {
    let server = TestServer::start(prompt_then_silent).await;
    let client = build(&server, &["example.test"], |builder| {
        builder.no_head_timeout()
    });

    let warm = client
        .get(server.url_for("example.test", "/prompt"))
        .send()
        .await
        .expect("the first request must succeed");
    assert_eq!(warm.text().await.expect("the body must decode"), "here");

    tokio::time::pause();

    let outcome = tokio::time::timeout(
        Duration::from_secs(1800),
        client.get(server.url_for("example.test", "/silent")).send(),
    )
    .await;

    assert!(
        outcome.is_err(),
        "a caller that opted out must wait as long as it likes: half an hour of \
         silence must not end the request"
    );
}

// -------------------------------------------------------- identity plumbing

#[tokio::test]
async fn the_client_exposes_the_identity_it_presents_and_the_gap_to_it() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    assert_eq!(client.profile().name, "chrome");
    assert_eq!(
        client.engine().tls().target_identity().ja4,
        Profile::chrome_stable().ja4()
    );
    assert!(
        !client.engine().http2_fidelity().is_exact(),
        "the HTTP/2 gap must be reported, never reported as absent"
    );
}

#[tokio::test]
async fn a_default_header_overrides_the_profiles_value_for_that_name() {
    let server = TestServer::always(Reply::ok()).await;
    let client = build(&server, &["example.test"], |builder| {
        builder
            .user_agent("custom-agent/1.0")
            .expect("a valid user agent")
    });

    client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(received.header("user-agent"), Some("custom-agent/1.0"));
    assert!(
        received.header_order.contains(&"user-agent".to_owned()),
        "the override must keep the profile's position in the order"
    );
}

#[tokio::test]
async fn a_per_request_header_beats_a_client_default() {
    let server = TestServer::always(Reply::ok()).await;
    let client = build(&server, &["example.test"], |builder| {
        builder
            .default_header("x-source", "client-default")
            .expect("a valid header")
    });

    client
        .get(server.url_for("example.test", "/"))
        .header("x-source", "request-override")
        .send()
        .await
        .expect("the request must succeed");

    assert_eq!(
        server.received()[0].header("x-source"),
        Some("request-override")
    );
}

// -------------------------------------------------------------------- json

#[cfg(feature = "json")]
#[tokio::test]
async fn json_round_trips_through_the_request_and_the_response() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Payload {
        name: String,
        count: u32,
    }

    let server = TestServer::start(|request| {
        // Echo the request body back, so one test covers both directions.
        Reply::ok()
            .with_header("content-type", "application/json")
            .with_body(request.body.clone())
    })
    .await;
    let client = client_for(&server, &["example.test"]);

    let sent = Payload {
        name: "chromulate".to_owned(),
        count: 7,
    };

    let echoed: Payload = client
        .post(server.url_for("example.test", "/"))
        .json(&sent)
        .send()
        .await
        .expect("the request must succeed")
        .json()
        .await
        .expect("the response must parse");

    assert_eq!(echoed, sent);
    assert_eq!(
        server.received()[0].header("content-type"),
        Some("application/json")
    );
}

#[cfg(feature = "json")]
#[tokio::test]
async fn a_body_that_is_not_json_reports_a_decode_error() {
    let server = TestServer::always(Reply::text("this is not json")).await;
    let client = client_for(&server, &["example.test"]);

    let error = client
        .get(server.url_for("example.test", "/"))
        .send()
        .await
        .expect("the request must succeed")
        .json::<serde_json::Value>()
        .await
        .expect_err("the body is not JSON");

    assert!(
        matches!(&error, Error::Decode { encoding, .. } if encoding == "json"),
        "{error:?}"
    );
}

// -------------------------------------------------------------------- form

#[cfg(feature = "form")]
#[tokio::test]
async fn a_form_body_is_url_encoded_with_the_matching_content_type() {
    let server = TestServer::always(Reply::ok()).await;
    let client = client_for(&server, &["example.test"]);

    client
        .post(server.url_for("example.test", "/"))
        .form(&[("name", "chromulate"), ("kind", "http client")])
        .send()
        .await
        .expect("the request must succeed");

    let received = &server.received()[0];
    assert_eq!(
        received.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(received.body_text(), "name=chromulate&kind=http+client");
}

#[test]
fn basic_auth_encodes_the_colon_separated_pair_and_marks_it_sensitive() {
    let client = Client::chrome().expect("the client must build");
    let request = client
        .get("https://example.com/")
        .basic_auth("aladdin", Some("open sesame"))
        .build()
        .expect("the request must build");

    let value = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .expect("the header must be set");
    // RFC 7617's own example, so this checks the encoding rather than
    // re-deriving it with the same code under test.
    assert_eq!(
        value.to_str().expect("ascii"),
        "Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    assert!(
        value.is_sensitive(),
        "a credential must be marked sensitive so Debug does not print it"
    );
}

#[test]
fn basic_auth_without_a_password_still_sends_the_separator() {
    let client = Client::chrome().expect("the client must build");
    let request = client
        .get("https://example.com/")
        .basic_auth("user", None::<&str>)
        .build()
        .expect("the request must build");

    let value = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .expect("the header must be set");
    // "user:" not "user" — they are different credentials on the wire.
    assert_eq!(value.to_str().expect("ascii"), "Basic dXNlcjo=");
}

#[test]
fn bearer_auth_sets_the_scheme_and_marks_it_sensitive() {
    let client = Client::chrome().expect("the client must build");
    let request = client
        .get("https://example.com/")
        .bearer_auth("t0ken")
        .build()
        .expect("the request must build");

    let value = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .expect("the header must be set");
    assert_eq!(value.to_str().expect("ascii"), "Bearer t0ken");
    assert!(value.is_sensitive());
}

#[test]
fn a_credential_is_not_echoed_when_it_cannot_be_encoded() {
    let client = Client::chrome().expect("the client must build");
    let error = client
        .get("https://example.com/")
        .bearer_auth("has\nnewline")
        .build()
        .expect_err("a header value with a newline must be refused");

    let message = error.to_string();
    assert!(
        !message.contains("newline") || !message.contains("has\nnewline"),
        "the error must not quote the credential back: {message}"
    );
}

// ----------------------------------------------------------------- timings

#[tokio::test]
async fn a_response_reports_where_the_request_spent_its_time() {
    let server = TestServer::always(Reply::text("hello").delayed(Duration::from_millis(150))).await;
    let client = client_for(&server, &["example.test"]);

    let response = client
        .get(server.url_for("example.test", "/page"))
        .send()
        .await
        .expect("the request must succeed");

    let timings = response
        .timings()
        .expect("a response the engine produced carries its timings");
    assert!(timings.resolve().is_some(), "{timings:?}");
    assert!(timings.connect().is_some(), "{timings:?}");
    assert!(timings.head() >= Duration::from_millis(150), "{timings:?}");

    // The documented shape: hold the `Copy` timings across the body read and
    // `elapsed` afterwards is the time to body complete.
    let body = response.bytes().await.expect("the body must be readable");
    assert_eq!(&body[..], b"hello");
    assert!(timings.elapsed() >= timings.head(), "{timings:?}");
}

#[tokio::test]
async fn a_pooled_response_reports_no_connection_phases() {
    let server = TestServer::always(Reply::text("hello")).await;
    let client = client_for(&server, &["example.test"]);
    let url = server.url_for("example.test", "/page");

    let _ = client
        .get(&url)
        .send()
        .await
        .expect("the first request must succeed")
        .bytes()
        .await
        .expect("the body must be readable");

    let response = client
        .get(&url)
        .send()
        .await
        .expect("the second request must succeed");
    let timings = response.timings().expect("the timings must be attached");

    assert_eq!(server.accepts(), 1, "the second request must have pooled");
    assert_eq!(timings.connect(), None, "{timings:?}");
    assert_eq!(timings.handshake(), None, "{timings:?}");
}
