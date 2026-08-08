//! What a facade `Response` says about how it was obtained.
//!
//! The engine has recorded the redirect chain and the proxy exit for a while;
//! until this file's companion change, `Response::new` destructured
//! `ResponseInfo` down to the URL and the timings and dropped the rest, so
//! neither was reachable by anyone not holding an `Engine`.
//!
//! The last test here is the one that matters: it closes the loop the whole
//! per-exit design rests on — a response reports the exit it came back
//! through, and that value, handed straight back, reaches the session that
//! learned from it.

mod common;

use chromulate::{Client, ProxyIsolation};
use chromulate_core::CookieContext;
use chromulate_dns::StaticResolver;
use common::{Recorded, Reply, TestProxy, TestServer};
use http::StatusCode;
use url::Url;

/// An origin that redirects twice and then answers, with a different status on
/// each hop so an out-of-order chain cannot pass.
async fn redirecting() -> TestServer {
    TestServer::start(|request: &Recorded| match request.target.as_str() {
        "/one" => Reply::redirect(301, "/two"),
        "/two" => Reply::redirect(302, "/three"),
        _ => Reply::ok(),
    })
    .await
}

/// A client that resolves `shop.test` to the loopback origin.
///
/// Only the unproxied tests need this. A proxied route hands the name to the
/// proxy rather than resolving it, so the last test in this file deliberately
/// has no resolver.
fn pinned(server: &TestServer) -> Client {
    Client::builder()
        .resolver(StaticResolver::empty().with_host("shop.test".to_owned(), vec![server.addr()]))
        .build()
        .expect("the client must build")
}

#[tokio::test]
async fn a_redirect_chain_is_visible_on_the_response_oldest_first() {
    let server = redirecting().await;
    let client = pinned(&server);

    let response = client
        .get(server.url_for("shop.test", "/one"))
        .send()
        .await
        .expect("the origin must answer");

    let hops = response
        .hops()
        .expect("two redirects were followed, so there is a chain");
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[0].status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(hops[0].url().path(), "/one");
    assert_eq!(hops[1].status(), StatusCode::FOUND);
    assert_eq!(hops[1].url().path(), "/two");
    assert_eq!(
        response.url().path(),
        "/three",
        "the URL that answered is not repeated in the chain"
    );
}

/// The allocation property, asserted as behaviour at the facade: `None`, not an
/// empty slice.
#[tokio::test]
async fn a_response_with_no_redirect_reports_no_chain_at_all() {
    let server = TestServer::start(|_: &Recorded| Reply::ok()).await;
    let client = pinned(&server);

    let response = client
        .get(server.url_for("shop.test", "/plain"))
        .send()
        .await
        .expect("the origin must answer");

    assert!(
        response.hops().is_none(),
        "nothing redirected, so there is no chain object: {:?}",
        response.hops()
    );
}

#[tokio::test]
async fn a_direct_response_reports_no_exit() {
    let server = TestServer::start(|_: &Recorded| Reply::ok()).await;
    let client = pinned(&server);

    let response = client
        .get(server.url_for("shop.test", "/plain"))
        .send()
        .await
        .expect("the origin must answer");

    assert!(
        response.exit().is_none(),
        "no proxy was configured: {:?}",
        response.exit()
    );
}

/// The loop the per-exit design rests on, closed entirely through the public
/// facade — no `Engine`, no extension reading.
///
/// Before `Response` kept `ResponseInfo`, this test could not be written: the
/// exit was recorded by the engine and thrown away one layer up, so a caller
/// had no way to name the session their own response had just taught.
#[tokio::test]
async fn the_exit_a_response_reports_reaches_the_session_it_taught() {
    let server = TestServer::start(|request: &Recorded| {
        if request.target == "/set" {
            Reply::ok().with_header("set-cookie", "tenant=one; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await;
    let exit = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy_pool([exit.url()])
        .expect("a loopback proxy URL must parse")
        .proxy_isolation(ProxyIsolation::per_proxy())
        .build()
        .expect("the client must build");

    let response = client
        .get("http://shop.test/set")
        .send()
        .await
        .expect("the request must reach the origin through the proxy");

    let reported = response
        .exit()
        .expect("a proxied request reports the exit it went out through");
    assert!(
        reported.contains(&exit.url()[7..]),
        "the label is the exit's redacted URL: {reported}"
    );
    assert_eq!(client.engine().isolated_routes(), 1);

    let url = Url::parse("http://shop.test/").expect("a valid url");
    let context = CookieContext::conservative_default();

    let through_exit = client
        .with_session(response.exit(), |session| {
            session
                .cookies()
                .expect("an isolated route is minted with a jar")
                .cookies_for(&url, &context)
                .and_then(|value| value.to_str().ok().map(str::to_owned))
        })
        .expect("the reported exit names a route that already exists");
    assert_eq!(
        through_exit.as_deref(),
        Some("tenant=one"),
        "the reported exit reached the jar the origin taught through it"
    );
    assert_eq!(
        client.engine().isolated_routes(),
        1,
        "and it found that route rather than minting a second one"
    );

    // The unproxied session was never taught anything, which is the isolation
    // rule the label exists to keep honest.
    let direct = client
        .with_session(None, |session| {
            session
                .cookies()
                .and_then(|jar| jar.cookies_for(&url, &context))
        })
        .expect("the unproxied session always exists");
    assert!(direct.is_none(), "the direct session learned nothing");
}
