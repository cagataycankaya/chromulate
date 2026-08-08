//! Reaching one route's session from the facade.
//!
//! [`Client::cookies`] returns the jar an *unproxied* request uses, which on a
//! fully proxied client is none of the ones being sent. `Client::with_session`
//! is how the others are reached, and these tests pin the three things a caller
//! can get wrong: which session a label names, what an unknown label does, and
//! whether the label a response reports is the one the session map is keyed by.

mod common;

use std::sync::Arc;

use chromulate::proxy::ProxyUrl;
use chromulate::{Client, ProxyIsolation};
use chromulate_cookie::Jar;
use chromulate_core::{CookieContext, CookieStore};
use chromulate_http::ResponseInfo;
use common::{Recorded, Reply, TestProxy, TestServer};
use http::HeaderValue;
use url::Url;

/// The label the engine files a route under: the exit's redacted URL.
fn label_for(proxy: &TestProxy) -> Arc<str> {
    Arc::from(
        ProxyUrl::parse(&proxy.url())
            .expect("a loopback proxy URL must parse")
            .to_string(),
    )
}

fn url() -> Url {
    Url::parse("http://shop.test/").expect("a valid url")
}

/// Writes a cookie straight into whichever session `exit` names.
fn seed(client: &Client, exit: Option<&Arc<str>>, cookie: &str) {
    let value = HeaderValue::from_str(cookie).expect("a valid header value");
    client.seed_session(exit, |session| {
        session
            .cookies()
            .expect("this client keeps cookies")
            .store(&url(), &mut std::iter::once(&value));
    });
}

/// What whichever session `exit` names would send to the origin.
fn read(client: &Client, exit: Option<&Arc<str>>) -> Option<String> {
    client
        .with_session(exit, |session| {
            session
                .cookies()
                .expect("this client keeps cookies")
                .cookies_for(&url(), &CookieContext::conservative_default())
                .and_then(|value| value.to_str().ok().map(str::to_owned))
        })
        .flatten()
}

/// Under `Shared`, nothing is filed under a label, and `with_session` says so.
///
/// This used to hand back the one shared session and ignore the label, which
/// was the sharpest way this API could mislead: name exit B, receive a session
/// exit A also used, be told nothing. The `None` is the whole point of the
/// test.
#[test]
fn a_shared_client_has_nothing_filed_under_any_label() {
    let client = Client::builder()
        .proxy_isolation(ProxyIsolation::Shared)
        .build()
        .expect("the client must build");
    assert_eq!(client.proxy_isolation(), ProxyIsolation::Shared);

    let label: Arc<str> = Arc::from("http://a.example:8080");
    assert!(
        client
            .with_session(Some(&label), |session| session.cookies().is_some())
            .is_none(),
        "a shared client files no route state, so no label names anything"
    );

    // The one session is reachable, and only without a label.
    seed(&client, None, "who=shared; Path=/");
    assert_eq!(read(&client, None).as_deref(), Some("who=shared"));
    assert_eq!(
        client.engine().isolated_routes(),
        0,
        "and asking about a label created nothing"
    );
}

/// Under `PerProxy` each label is its own session, and `None` is a third one.
#[test]
fn each_label_names_its_own_session_and_none_names_the_unproxied_one() {
    let client = Client::builder()
        .proxy_pool(["http://a.example:8080", "http://b.example:8080"])
        .expect("two proxy URLs must parse")
        .build()
        .expect("the client must build");
    assert_eq!(client.proxy_isolation(), ProxyIsolation::per_proxy());

    let a: Arc<str> = Arc::from("http://a.example:8080");
    let b: Arc<str> = Arc::from("http://b.example:8080");

    seed(&client, Some(&a), "who=a; Path=/");
    seed(&client, Some(&b), "who=b; Path=/");
    seed(&client, None, "who=direct; Path=/");

    assert_eq!(read(&client, Some(&a)).as_deref(), Some("who=a"));
    assert_eq!(read(&client, Some(&b)).as_deref(), Some("who=b"));
    assert_eq!(
        read(&client, None).as_deref(),
        Some("who=direct"),
        "the unproxied session is not either exit's"
    );
    assert_eq!(client.engine().isolated_routes(), 2, "two exits, not three");
}

/// The hazard the split exists to remove, and the one it deliberately keeps.
///
/// Reading an unserved label finds nothing **and creates nothing**, so a typo
/// in a read is inert. Seeding one still mints, and minting still runs the
/// `max_routes` eviction — at the ceiling that discards a live exit's cookies.
/// That cost is the documented price of a bounded store; what changed is that
/// only the method whose name says "create" can pay it.
///
/// Both halves are asserted here, in that order, because the second is what
/// makes the first worth having.
#[test]
fn reading_an_unserved_label_creates_nothing_but_seeding_one_can_evict() {
    let client = Client::builder()
        .proxy_pool(["http://a.example:8080", "http://b.example:8080"])
        .expect("two proxy URLs must parse")
        .proxy_isolation(ProxyIsolation::PerProxy { max_routes: 1 })
        .build()
        .expect("the client must build");

    let real: Arc<str> = Arc::from("http://a.example:8080");
    seed(&client, Some(&real), "session=alive; Path=/");
    assert_eq!(
        read(&client, Some(&real)).as_deref(),
        Some("session=alive"),
        "the exit holds its cookie before anything else is named"
    );
    assert_eq!(client.engine().isolated_routes(), 1);

    // A label nobody has served — a typo, or a stale one from a rotation that
    // has since moved on. Reading it is inert.
    let typo: Arc<str> = Arc::from("http://a.example:8081");
    assert!(
        client
            .with_session(Some(&typo), |session| session.cookies().is_some())
            .is_none(),
        "an unserved label names no session"
    );
    assert_eq!(
        client.engine().isolated_routes(),
        1,
        "and looking for it created nothing, so nothing was evicted to make room"
    );
    assert_eq!(
        read(&client, Some(&real)).as_deref(),
        Some("session=alive"),
        "the real exit still holds its cookie — this is what the split buys"
    );

    // Seeding the same label does mint, and at the ceiling that costs the
    // least recently used route. The name is the warning.
    let seeded = client.seed_session(Some(&typo), |session| {
        session
            .cookies()
            .expect("a minted route gets a jar")
            .cookies_for(&url(), &CookieContext::conservative_default())
    });
    assert!(seeded.is_none(), "a freshly minted route starts empty");
    assert_eq!(
        client.engine().isolated_routes(),
        1,
        "the cap held, which means something was dropped to make room"
    );
    assert_eq!(
        read(&client, Some(&real)),
        None,
        "and what was dropped is the real exit's session, cookie and all"
    );
}

/// The structural claim the whole round-trip rests on: the label a response
/// reports is the key its session is filed under, through a real proxied
/// request over real sockets.
///
/// Read through `client.engine()` rather than the facade's `Response`, because
/// `Response::new` currently drops `ResponseInfo` and keeps only the URL and
/// the timings — see this file's companion report. That is the gap this test
/// documents by having to reach around it.
#[tokio::test]
async fn the_exit_a_response_reports_reaches_the_session_that_learned_from_it() {
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

    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("http://shop.test/set")
        .body(chromulate_core::Body::empty())
        .expect("a valid request");
    let response = client
        .engine()
        .send(request)
        .await
        .expect("the request must reach the origin through the proxy");
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .cloned()
        .expect("the engine attaches a ResponseInfo");

    let reported = info
        .exit
        .clone()
        .expect("a proxied request reports its exit");
    assert_eq!(
        reported,
        label_for(&exit),
        "the reported label is the exit's redacted URL, which is what a caller \
         deriving one would build"
    );
    assert_eq!(client.engine().isolated_routes(), 1);

    // The origin taught this exit a cookie; the reported label must reach it.
    assert_eq!(
        read(&client, info.exit.as_ref()).as_deref(),
        Some("tenant=one"),
        "the label round-trips to the session that learned from the response"
    );
    assert_eq!(
        client.engine().isolated_routes(),
        1,
        "and it found that session rather than minting a second one"
    );

    // The unproxied session was never taught anything, which is the isolation
    // rule this label exists to keep honest.
    //
    // Two `Option`s, and they mean different things: the outer one is "does
    // this route exist" and is `Some` because the unproxied session always
    // does; the inner one is "does it hold a cookie for this URL". Asserting
    // `is_none()` on the outer one would pass for a route that does not exist
    // and fail for an empty jar, which is backwards — hence the `flatten`.
    let existed = client.with_session(None, |session| {
        session
            .cookies()
            .and_then(|jar| jar.cookies_for(&url(), &CookieContext::conservative_default()))
    });
    assert!(existed.is_some(), "the unproxied session always exists");
    assert!(
        existed.flatten().is_none(),
        "and it learned nothing from the proxied response"
    );
}

/// A client built with `cookie_store(false)` has no jar on any route, and
/// `with_session` must say so rather than hand out an empty one.
#[test]
fn a_client_that_keeps_no_cookies_offers_no_jar_on_any_route() {
    let client = Client::builder()
        .cookie_store(false)
        .proxy_pool(["http://a.example:8080", "http://b.example:8080"])
        .expect("two proxy URLs must parse")
        .build()
        .expect("the client must build");

    let label: Arc<str> = Arc::from("http://a.example:8080");
    assert!(
        client.seed_session(Some(&label), |session| session.cookies().is_none()),
        "a seeded route on a cookie-less client still has no jar"
    );
    assert_eq!(
        client.with_session(Some(&label), |session| session.cookies().is_none()),
        Some(true),
        "and reading it back finds the route, still without a jar"
    );
    assert_eq!(
        client.with_session(None, |session| session.cookies().is_none()),
        Some(true),
        "nor does the unproxied session"
    );
}

/// `Jar` is re-exported and usable as the shared store, so the type the facade
/// hands back through `with_session` is the same one `Client::cookies` returns
/// for the unproxied route.
#[test]
fn the_unproxied_session_is_the_jar_client_cookies_returns() {
    let jar = Arc::new(Jar::new());
    let client = Client::builder()
        .cookie_jar(Arc::clone(&jar))
        .build()
        .expect("the client must build");

    seed(&client, None, "who=direct; Path=/");
    assert_eq!(
        jar.cookies_for(&url(), &CookieContext::conservative_default())
            .and_then(|value| value.to_str().ok().map(str::to_owned))
            .as_deref(),
        Some("who=direct"),
        "with_session(None) wrote into the very jar the builder was handed"
    );
}
