//! What a client keeps per exit address, and what it keeps once.
//!
//! The reproduction these tests encode was first measured against three ISP
//! proxies with distinct, stable exit IPs. One `Client` per proxy showed the
//! cookie on one exit and nothing on the other two; one `Client` with a
//! `proxy_pool` of all three showed the same cookie on all three. The second
//! row is the defect: a caller who configures three exits has asked to spread
//! traffic across three addresses, and presenting one session from all three
//! does not waste that so much as **couple** the three addresses together for
//! the origin — a stronger signal than using one address would have been.
//!
//! Nothing here needs anybody's paid proxies. `TestProxy` is a local `CONNECT`
//! tunnel to the loopback origin, and two of them are two exits as far as the
//! client is concerned: different pool keys, different routes, different
//! sessions.

mod common;

use std::sync::Arc;

use chromulate::{Client, ClientBuilder, ProxyIsolation};
use chromulate_cookie::Jar;
use chromulate_dns::StaticResolver;
use common::{Recorded, Reply, TestProxy, TestServer};

/// An origin that hands out one cookie at `/set` and echoes what it is sent
/// everywhere else.
async fn origin() -> TestServer {
    TestServer::start(|request: &Recorded| {
        if request.target == "/set" {
            Reply::ok().with_header("set-cookie", "tenant=one; Path=/")
        } else {
            Reply::text(request.header("cookie").unwrap_or("<none>"))
        }
    })
    .await
}

/// What the origin saw in the `Cookie` header of the `n`th request it received.
fn cookie_on(server: &TestServer, n: usize) -> Option<String> {
    server
        .received()
        .get(n)
        .and_then(|request| request.header("cookie").map(str::to_owned))
}

/// Sends one request through whatever route the client picks next.
///
/// The URL carries no port, and that is safe only because every caller of this
/// is proxied: a proxied route hands the name to the proxy instead of resolving
/// it, and the test proxy tunnels to the origin whatever authority it was given.
/// An unproxied client must use [`direct`] instead — `StaticResolver` takes the
/// port from the URL, so `http://shop.test/` there dials `127.0.0.1:80`, which
/// on a developer's machine is somebody else's web server.
async fn get(client: &Client, path: &str) {
    send(client, format!("http://shop.test{path}")).await;
}

/// Sends one request to a pinned host, port and all.
async fn direct(client: &Client, server: &TestServer, path: &str) {
    send(client, server.url_for("shop.test", path)).await;
}

async fn send(client: &Client, url: String) {
    let _ = client
        .get(url)
        .send()
        .await
        .expect("the request must reach the origin")
        .bytes()
        .await
        .expect("the body must arrive");
}

// ------------------------------------------------------- the reproduction

/// The table's second row, made local and made to fail.
///
/// `RoundRobin` advances once per hop, so three requests visit the first exit,
/// the second exit, and the first exit again. The cookie belongs to the first
/// exit's session and to nothing else.
#[tokio::test]
async fn a_cookie_set_through_one_exit_is_not_presented_through_another() {
    let server = origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy_pool([first.url(), second.url()])
        .expect("two loopback proxy URLs must parse")
        .build()
        .expect("the client must build");

    get(&client, "/set").await;
    get(&client, "/read").await;
    get(&client, "/read").await;

    // One tunnel each, not two and one: the third hop returns to the first exit
    // and reuses the connection `PoolKey` already keeps separate per proxy. The
    // origin's own connection numbering is what says which exit each hop took.
    assert_eq!(first.tunnels(), 1);
    assert_eq!(second.tunnels(), 1);
    let connections: Vec<usize> = server
        .received()
        .iter()
        .map(|request| request.connection)
        .collect();
    assert_eq!(
        connections,
        vec![0, 1, 0],
        "the three hops must have visited the first exit, the second, and the first again"
    );

    assert_eq!(
        cookie_on(&server, 1),
        None,
        "a cookie set through the first exit must not be presented through the second"
    );
    assert_eq!(
        cookie_on(&server, 2).as_deref(),
        Some("tenant=one"),
        "the exit that was given the cookie must still present it"
    );
}

/// The other half of the same property: two exits, and the second one is never
/// told anything the first one learned, however many times it is used.
#[tokio::test]
async fn each_exit_builds_its_own_session_from_nothing() {
    let server = TestServer::start(|request: &Recorded| {
        Reply::ok().with_header(
            "set-cookie",
            match request.target.as_str() {
                "/one" => "exit=one; Path=/",
                _ => "exit=two; Path=/",
            },
        )
    })
    .await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy_pool([first.url(), second.url()])
        .expect("two loopback proxy URLs must parse")
        .build()
        .expect("the client must build");

    get(&client, "/one").await; // first exit, stores exit=one
    get(&client, "/two").await; // second exit, stores exit=two
    get(&client, "/three").await; // first exit again
    get(&client, "/four").await; // second exit again

    assert_eq!(
        cookie_on(&server, 2).as_deref(),
        Some("exit=one"),
        "the first exit must see only what it was told"
    );
    assert_eq!(
        cookie_on(&server, 3).as_deref(),
        Some("exit=two"),
        "the second exit must see only what it was told"
    );
}

// ------------------------------------------- the caller who wants one session

/// A caller rotating exits purely to spread load on a site they are logged in
/// to wants the opposite, and has to be able to say so.
#[tokio::test]
async fn a_caller_can_still_ask_for_one_session_across_every_exit() {
    let server = origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy_pool([first.url(), second.url()])
        .expect("two loopback proxy URLs must parse")
        .proxy_isolation(ProxyIsolation::Shared)
        .build()
        .expect("the client must build");

    get(&client, "/set").await;
    get(&client, "/read").await;

    assert_eq!(
        cookie_on(&server, 1).as_deref(),
        Some("tenant=one"),
        "`ProxyIsolation::Shared` is what the login-spreading caller asks for"
    );
}

/// Handing the builder one jar is the same request said a different way, and it
/// is visible at the call site rather than in a doc comment.
#[tokio::test]
async fn naming_one_jar_gives_every_exit_that_one_jar() {
    let server = origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;

    let jar = Arc::new(Jar::new());
    let client = Client::builder()
        .proxy_pool([first.url(), second.url()])
        .expect("two loopback proxy URLs must parse")
        .cookie_jar(Arc::clone(&jar))
        .build()
        .expect("the client must build");

    assert_eq!(client.proxy_isolation(), ProxyIsolation::Shared);

    get(&client, "/set").await;
    get(&client, "/read").await;

    assert_eq!(
        cookie_on(&server, 1).as_deref(),
        Some("tenant=one"),
        "a caller who named one jar asked for one session"
    );
}

/// Asking for both at once is a contradiction, and it fails at build time
/// rather than by quietly ignoring one of them.
#[test]
fn asking_for_one_jar_and_per_exit_isolation_at_once_is_refused() {
    let error = ClientBuilder::new()
        .cookie_jar(Arc::new(Jar::new()))
        .proxy_isolation(ProxyIsolation::per_proxy())
        .build()
        .expect_err("the two requests contradict each other");
    let message = error.to_string();
    assert!(message.contains("cookie_jar"), "{message}");
    assert!(message.contains("proxy_isolation"), "{message}");
}

// ---------------------------------------------------------- the default path

/// The overwhelmingly common case: no proxy at all. One route, one session,
/// exactly as before this existed.
#[tokio::test]
async fn a_client_with_no_proxy_keeps_one_session() {
    let server = origin().await;
    let client = Client::builder()
        .resolver(StaticResolver::empty().with_host("shop.test".to_owned(), vec![server.addr()]))
        .build()
        .expect("the client must build");

    assert_eq!(
        client.proxy_isolation(),
        ProxyIsolation::Shared,
        "there is one route, so there is nothing to isolate from"
    );

    direct(&client, &server, "/set").await;
    direct(&client, &server, "/read").await;

    assert_eq!(
        cookie_on(&server, 1).as_deref(),
        Some("tenant=one"),
        "an unproxied client must behave exactly as it did before"
    );
}

/// One proxy is one exit, so it is also one session. A caller who configured a
/// single proxy expressed no intent to spread anything.
#[tokio::test]
async fn a_client_with_a_single_proxy_keeps_one_session() {
    let server = origin().await;
    let only = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy(only.url())
        .expect("a loopback proxy URL must parse")
        .build()
        .expect("the client must build");

    assert_eq!(client.proxy_isolation(), ProxyIsolation::Shared);

    get(&client, "/set").await;
    get(&client, "/read").await;

    assert_eq!(
        cookie_on(&server, 1).as_deref(),
        Some("tenant=one"),
        "a single-proxy client must behave exactly as it did before"
    );
    assert_eq!(
        client
            .cookies()
            .map(|jar| jar.export().cookies.len())
            .unwrap_or_default(),
        1,
        "and the jar `cookies()` hands back must be the one actually in use"
    );
}

/// A pool of one is still one exit.
#[tokio::test]
async fn a_pool_with_one_member_keeps_one_session() {
    let server = origin().await;
    let only = TestProxy::start(server.addr()).await;

    let client = Client::builder()
        .proxy_pool([only.url()])
        .expect("a loopback proxy URL must parse")
        .build()
        .expect("the client must build");

    assert_eq!(client.proxy_isolation(), ProxyIsolation::Shared);

    get(&client, "/set").await;
    get(&client, "/read").await;

    assert_eq!(cookie_on(&server, 1).as_deref(), Some("tenant=one"));
}
