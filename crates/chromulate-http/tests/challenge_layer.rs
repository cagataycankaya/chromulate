//! The challenge layer, driven over real sockets against a local origin that
//! behaves the way a challenge wall behaves.
//!
//! Everything here is hermetic. The "browser" is a mock that hands back a
//! clearance without launching anything, which is the point: this file tests the
//! *layer*, and a test whose result depends on a third party's live classifier
//! tests their policy instead.
//!
//! # What these tests are shaped by
//!
//! `CLAUDE.md`'s three testing rules, and in particular the second. Every test
//! that proves the layer *acts* installs a fallback — so the far more common
//! shape, a client carrying this middleware with nothing behind it, would be
//! untested by construction. `mod default_paths` is that half, and it is not
//! optional: the `Lax`-cookie incident in this repository was exactly a fix whose
//! own tests all set a field.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chromulate_cookie::Jar;
use chromulate_core::{
    Body, BoxFuture, CookieContext, CookieStore, Middleware, Origin, Request, Response, Result,
};
use chromulate_dns::StaticResolver;
use chromulate_http::challenge::{
    BrowserFallback, Challenge, ChallengeDetector, ChallengeKind, ChallengeKinds, Content,
    DeclineReason, Detection, Evidence, FallbackIdentity, Handback, Handoff, HandoffPolicy,
    Observation,
};
use chromulate_http::middleware::challenge::{FetchedByFallback, SessionAccess};
use chromulate_http::middleware::{ChallengeHandoff, middleware_error};
use chromulate_http::{Engine, EngineConfig, ProxyIsolation, ResponseInfo, SessionFactory};
use chromulate_profile::Profile;
use chromulate_proxy::{Proxy, ProxyProvider, ProxyUrl, RoundRobin};
use common::{Recorded, Reply, TestProxy, TestServer};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use url::Url;

/// The clearance the local origin insists on, in `Set-Cookie` shape.
const CLEARANCE: &str = "cf_clearance=granted; Path=/; Max-Age=600";

/// What the origin looks for in a `Cookie` header before it serves the page.
const GRANTED: &str = "cf_clearance=granted";

/// What the origin serves once cleared.
const PAGE: &str = "the real page";

// ------------------------------------------------------------------ the origin

/// An origin that answers `403` with Cloudflare's documented challenge header
/// until the request carries a clearance cookie.
///
/// The header is the vendor's own. Cloudflare documents `cf-mitigated:
/// challenge` as the signal a client reads to detect a challenge page, and
/// documents the loop this layer implements: detect it, let a browser clear it,
/// obtain `cf_clearance`, retry the original request.
async fn challenge_origin() -> TestServer {
    TestServer::start(|request: &Recorded| {
        // `/ping` is never challenged, so a test can give an exit a session
        // without giving it a clearance. Without it, "exit A's jar is untouched"
        // would be satisfied by exit A having no jar at all, which is a weaker
        // claim wearing the same assertion.
        if request.target.ends_with("/ping") {
            return Reply::text("pong");
        }
        if request
            .header("cookie")
            .is_some_and(|cookie| cookie.contains(GRANTED))
        {
            Reply::text(PAGE)
        } else {
            challenged()
        }
    })
    .await
}

/// An origin that challenges whatever the client presents.
async fn immovable_origin() -> TestServer {
    TestServer::start(|_: &Recorded| challenged()).await
}

fn challenged() -> Reply {
    Reply::new(403)
        .with_header("cf-mitigated", "challenge")
        .with_body(b"<title>Just a moment...</title>".to_vec())
}

// ---------------------------------------------------------------- the detector

/// Reads the one header the vendor publishes for the purpose. Header-only, so it
/// concludes at zero body bytes.
#[derive(Debug)]
struct Mitigated;

impl ChallengeDetector for Mitigated {
    fn inspect(&self, observation: &Observation<'_>) -> Detection {
        if observation
            .headers()
            .get("cf-mitigated")
            .map(HeaderValue::as_bytes)
            != Some(b"challenge".as_slice())
        {
            return Detection::Clear;
        }
        Detection::Challenged(Challenge::new(
            ChallengeKind::Unknown,
            observation.origin().clone(),
            Evidence::from_signal("cf-mitigated: challenge"),
        ))
    }
}

/// A detector whose headers are never enough: it asks for a body and decides on
/// the title. The only thing here that exercises `Detection::Suspect`.
#[derive(Debug)]
struct NeedsTheBody;

impl ChallengeDetector for NeedsTheBody {
    fn inspect(&self, observation: &Observation<'_>) -> Detection {
        match observation.body_prefix() {
            None => Detection::Suspect,
            Some(prefix) if prefix.starts_with(b"<title>Just a moment") => {
                Detection::Challenged(Challenge::new(
                    ChallengeKind::JsRequired,
                    observation.origin().clone(),
                    Evidence::from_signal("title: just a moment"),
                ))
            }
            Some(_) => Detection::Clear,
        }
    }
}

// ---------------------------------------------------------------- the fallback

/// What the mock browser answers with.
#[derive(Clone)]
enum Answer {
    /// A clearance, applied to the route and replayed.
    Clearance,
    /// A clearance the origin will not accept, so the retry is challenged again.
    /// This is what makes the loop guard observable.
    WorthlessClearance,
    /// A page the browser fetched itself.
    Page(&'static str),
    /// A refusal that is an answer rather than a failure.
    Decline(DeclineReason),
    /// A browser that would not start.
    Broken,
}

/// A browser that is not a browser: it records what it was handed and answers to
/// script.
struct MockBrowser {
    answer: Answer,
    delay: Option<Duration>,
    handles: ChallengeKinds,
    calls: AtomicUsize,
    seen: Mutex<Vec<Handoff>>,
}

impl std::fmt::Debug for MockBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockBrowser")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

impl MockBrowser {
    fn answering(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            delay: None,
            handles: ChallengeKinds::all(),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn clearing() -> Arc<Self> {
        Self::answering(Answer::Clearance)
    }

    fn slow(answer: Answer, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            answer,
            delay: Some(delay),
            handles: ChallengeKinds::all(),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn claiming(kinds: ChallengeKinds) -> Arc<Self> {
        Arc::new(Self {
            answer: Answer::Clearance,
            delay: None,
            handles: kinds,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn handoffs(&self) -> Vec<Handoff> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl BrowserFallback for MockBrowser {
    fn name(&self) -> &'static str {
        "mock-browser"
    }

    fn handles(&self) -> ChallengeKinds {
        self.handles
    }

    fn solve<'a>(&'a self, handoff: Handoff) -> BoxFuture<'a, Result<Handback>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            let user_agent = handoff.user_agent().clone();
            let target = handoff.url().clone();
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(handoff);

            let identity = FallbackIdentity::new("mock-browser 1.0", user_agent);
            Ok(match &self.answer {
                Answer::Clearance => Handback::Session {
                    set_cookie: vec![HeaderValue::from_static(CLEARANCE)],
                    content: None,
                    produced_by: identity,
                },
                Answer::WorthlessClearance => Handback::Session {
                    set_cookie: vec![HeaderValue::from_static("stale=1; Path=/")],
                    content: None,
                    produced_by: identity,
                },
                Answer::Page(body) => Handback::Content(Content::new(
                    StatusCode::OK,
                    {
                        let mut headers = HeaderMap::new();
                        headers.insert("content-type", HeaderValue::from_static("text/html"));
                        headers
                    },
                    bytes::Bytes::from_static(body.as_bytes()),
                    target,
                )),
                Answer::Decline(reason) => Handback::Declined {
                    reason: reason.clone(),
                },
                Answer::Broken => {
                    return Err(middleware_error(
                        "mock-browser",
                        "no browser is installed".to_owned(),
                    ));
                }
            })
        })
    }
}

// ------------------------------------------------------------------ the wiring

/// Mints a fresh jar per exit, which an isolated engine has to be handed.
#[derive(Debug)]
struct Jars;

impl SessionFactory for Jars {
    fn cookies(&self) -> Option<Arc<dyn CookieStore>> {
        Some(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
    }
}

/// A proxy provider the test steers, rather than one that rotates on its own.
///
/// `RoundRobin` advances its cursor on every selection and the engine selects
/// once per hop, so a retry after a handoff would go out through a *different*
/// exit than the one the clearance was minted for. Pinning keeps the exit under
/// test the exit under test — and the fact that it is needed at all is a real
/// limitation of the shipped layer, recorded in B1's report rather than papered
/// over here.
struct PinnedExits {
    pool: Vec<Arc<Proxy>>,
    index: AtomicUsize,
}

impl std::fmt::Debug for PinnedExits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedExits")
            .field("pinned", &self.index.load(Ordering::SeqCst))
            .finish()
    }
}

impl PinnedExits {
    fn over(proxies: &[&TestProxy]) -> Arc<Self> {
        Arc::new(Self {
            pool: proxies
                .iter()
                .map(|proxy| {
                    Arc::new(Proxy::new(
                        ProxyUrl::parse(&proxy.url()).expect("a loopback proxy URL must parse"),
                    ))
                })
                .collect(),
            index: AtomicUsize::new(0),
        })
    }

    fn pin(&self, index: usize) {
        self.index.store(index, Ordering::SeqCst);
    }
}

impl ProxyProvider for PinnedExits {
    fn next(&self) -> BoxFuture<'_, Option<Arc<Proxy>>> {
        let index = self.index.load(Ordering::SeqCst);
        Box::pin(async move { self.pool.get(index).cloned() })
    }

    fn report_failure(&self, _proxy: &Proxy) {}
}

fn config() -> EngineConfig {
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    config
}

fn get(target: &str) -> Request {
    http::Request::builder()
        .method(Method::GET)
        .uri(target)
        .body(Body::empty())
        .expect("a valid request")
}

async fn body_of(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect(256 * 1024)
        .await
        .expect("the body must arrive");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn url(text: &str) -> Url {
    Url::parse(text).expect("a test URL must parse")
}

/// A layer with a detector and a fallback, and nothing else changed.
fn layer_with(
    detector: Arc<dyn ChallengeDetector>,
    browser: &Arc<MockBrowser>,
) -> ChallengeHandoff {
    ChallengeHandoff::new(Arc::new(Profile::chrome_stable()), detector)
        .with_fallback(Arc::clone(browser) as Arc<dyn BrowserFallback>)
}

/// Everything a test needs to drive one layer against one origin, with no proxy.
struct Harness {
    engine: Arc<Engine>,
    layer: Arc<ChallengeHandoff>,
    url: String,
}

impl Harness {
    async fn direct(server: &TestServer, layer: ChallengeHandoff) -> Self {
        let layer = Arc::new(layer);
        let resolver =
            StaticResolver::empty().with_host("shop.test".to_owned(), vec![server.addr()]);
        let engine = Arc::new(
            Engine::builder(config())
                .resolver(Arc::new(resolver))
                .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
                .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
                .build()
                .expect("the engine must build"),
        );
        layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));
        Self {
            url: format!("http://shop.test:{}/product", server.port()),
            engine,
            layer,
        }
    }

    async fn send(&self) -> Result<Response> {
        self.engine.send(get(&self.url)).await
    }

    async fn fetch(&self) -> Response {
        self.send().await.expect("the layer must answer")
    }
}

/// Whether a route's jar holds the clearance.
///
/// `false` for a route that does not exist. Pair it with [`route_exists`] where
/// the distinction matters — an exit with no session at all passes "holds no
/// clearance" trivially, which is not the property being asserted.
fn cleared_at(engine: &Engine, exit: Option<&Arc<str>>, target: &str) -> bool {
    let target = url(target);
    engine
        .with_session(exit, |session| {
            session
                .cookies()
                .and_then(|jar| jar.cookies_for(&target, &CookieContext::conservative_default()))
        })
        .flatten()
        .is_some_and(|header| {
            header
                .to_str()
                .expect("a test cookie header is ascii")
                .contains(GRANTED)
        })
}

/// Whether this engine has a session filed under `exit` at all.
fn route_exists(engine: &Engine, exit: Option<&Arc<str>>) -> bool {
    engine.with_session(exit, |_| ()).is_some()
}

// =============================================================== the whole loop

/// The reproduction this file was written around, and the first thing that ran.
///
/// It was watched to fail against a `ChallengeHandoff` whose `handle` only called
/// `next.run`: `assertion left == right failed: the retry after clearance must
/// reach the page — left: 403, right: 200`.
#[tokio::test]
async fn a_challenged_request_is_cleared_by_the_fallback_and_re_run() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let response = harness.fetch().await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the retry after clearance must reach the page"
    );
    assert_eq!(body_of(response).await, PAGE);
    assert_eq!(browser.calls(), 1, "one challenge, one handoff");
    assert_eq!(
        server.request_count(),
        2,
        "the challenged request and the cleared retry"
    );
    assert!(
        cleared_at(&harness.engine, None, &harness.url),
        "the clearance must be kept, or every later request pays for another browser"
    );
}

/// The `Suspect` arm, which is the only reason `Detection` has three arms rather
/// than two: a detector that needs the body says so, gets a bounded prefix, and
/// is asked again. The page it eventually clears must still arrive whole.
#[tokio::test]
async fn a_detector_that_needs_the_body_gets_a_prefix_and_the_page_still_arrives_whole() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let harness = Harness::direct(&server, layer_with(Arc::new(NeedsTheBody), &browser)).await;

    let response = harness.fetch().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_of(response).await,
        PAGE,
        "a body read for detection must not truncate the body the caller wanted"
    );
    assert_eq!(browser.calls(), 1);
}

/// The identity half of the contract, asserted against the profile rather than
/// against a literal — a User-Agent copied into a test is a constant that stops
/// tracking the profile the moment either moves.
#[tokio::test]
async fn the_handoff_carries_the_profiles_user_agent() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;
    let _ = harness.fetch().await;

    let expected = HeaderValue::from_str(&Profile::chrome_stable().user_agent)
        .expect("the shipped profile's user agent is a legal header value");
    let handoffs = browser.handoffs();
    assert_eq!(handoffs.len(), 1);
    assert_eq!(
        handoffs[0].user_agent(),
        &expected,
        "a clearance minted under a different User-Agent is bound to an identity \
         this engine will not send"
    );
    assert!(
        handoffs[0].honoured_by(&FallbackIdentity::new("mock-browser 1.0", expected)),
        "the seam's own check of the same property"
    );
}

/// A request that set its own `user-agent` overrides the profile, because that is
/// the identity the origin actually saw.
#[tokio::test]
async fn a_request_that_sets_its_own_user_agent_hands_that_one_over() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let mut request = get(&harness.url);
    request.headers_mut().insert(
        "user-agent",
        HeaderValue::from_static("Chromulate/0.3 test"),
    );
    let _ = harness
        .engine
        .send(request)
        .await
        .expect("the layer must answer");

    assert_eq!(
        browser.handoffs()[0].user_agent(),
        &HeaderValue::from_static("Chromulate/0.3 test")
    );
}

// ============================================================ the arms back

/// The `Content` arm: the browser fetched the page, and Chromulate learns nothing
/// from it. The assertion that matters is the negative one.
#[tokio::test]
async fn a_content_handback_is_returned_and_teaches_the_session_nothing() {
    let server = challenge_origin().await;
    let browser = MockBrowser::answering(Answer::Page("<html>fetched by the browser</html>"));
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let response = harness.fetch().await;

    assert_eq!(response.status(), StatusCode::OK);
    let marked = response
        .extensions()
        .get::<FetchedByFallback>()
        .expect("a browser-fetched page must say so");
    assert_eq!(marked.fallback(), "mock-browser");
    assert_eq!(marked.final_url().as_str(), harness.url);
    assert!(
        response.extensions().get::<ResponseInfo>().is_none(),
        "this engine did not produce this response and must not report timings for it"
    );
    assert_eq!(
        body_of(response).await,
        "<html>fetched by the browser</html>"
    );

    assert!(
        !cleared_at(&harness.engine, None, &harness.url),
        "the content path replays no cookie and resumes no session"
    );
    assert_eq!(
        server.request_count(),
        1,
        "the content path does not re-run the request"
    );
}

/// A decline is an answer: the challenge response goes back to the caller with
/// the evidence attached, and nothing becomes an error.
#[tokio::test]
async fn a_decline_returns_the_challenge_response_with_its_evidence() {
    let server = challenge_origin().await;
    let browser = MockBrowser::answering(Answer::Decline(DeclineReason::NeedsHuman));
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let response = harness.fetch().await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .extensions()
        .get::<Challenge>()
        .expect("the conclusion travels with the response");
    assert_eq!(
        challenge.evidence().signals().collect::<Vec<_>>(),
        ["cf-mitigated: challenge"]
    );
    assert_eq!(browser.calls(), 1);
}

/// A kind the fallback did not claim is never handed to it. The layer asks before
/// it launches, so `handles` is a bound rather than documentation.
#[tokio::test]
async fn a_kind_the_fallback_did_not_claim_is_never_handed_to_it() {
    let server = challenge_origin().await;
    // `Mitigated` concludes `Unknown`; this browser claims everything else.
    let browser = MockBrowser::claiming(
        ChallengeKinds::none()
            .with(ChallengeKind::JsRequired)
            .with(ChallengeKind::CookieRequired)
            .with(ChallengeKind::Interactive),
    );
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let response = harness.fetch().await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(browser.calls(), 0);
    assert!(response.extensions().get::<Challenge>().is_some());
}

/// A browser that would not start is the one thing here that becomes an
/// `Error::Middleware`. A challenge that could not be cleared is not: HTTP status
/// codes are not errors in this workspace, and folding the two would make "the
/// origin beat us" and "your Chrome is not installed" the same event.
#[tokio::test]
async fn a_fallback_that_could_not_run_is_a_middleware_error() {
    let server = challenge_origin().await;
    let browser = MockBrowser::answering(Answer::Broken);
    let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

    let error = harness
        .send()
        .await
        .expect_err("a browser that will not start is a failure, not a decline");

    // `Display` prints one frame, so the reason lives under it — and the layer
    // must not have dropped it on the way through the shared solve.
    let mut message = error.to_string();
    let mut cause = std::error::Error::source(&error);
    while let Some(current) = cause {
        message.push_str(&format!(": {current}"));
        cause = current.source();
    }
    assert!(
        message.starts_with("middleware `challenge` failed"),
        "{message}"
    );
    assert!(
        message.contains("no browser is installed"),
        "the reason a browser would not start must survive the trip: {message}"
    );
}

/// Session state with nowhere to keep it. The layer says so loudly rather than
/// applying it somewhere convenient, and returns the challenge unchanged.
#[tokio::test]
async fn session_state_with_no_session_access_wired_is_not_quietly_applied() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let layer = Arc::new(layer_with(Arc::new(Mitigated), &browser));
    let resolver = StaticResolver::empty().with_host("shop.test".to_owned(), vec![server.addr()]);
    let engine = Engine::builder(config())
        .resolver(Arc::new(resolver))
        .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
        .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
        .build()
        .expect("the engine must build");
    // Deliberately no `attach_sessions`.

    let target = format!("http://shop.test:{}/product", server.port());
    let response = engine
        .send(get(&target))
        .await
        .expect("the layer must still answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(browser.calls(), 1, "the handoff still happened");
    assert!(!cleared_at(&engine, None, &target));
}

// ============================================================== the four bounds

/// Ten tasks at one challenged URL launch one browser, not ten.
///
/// The budget is widened for this test on purpose: with the default of two, the
/// origin's own bound would cap the count at two and the assertion would pass
/// against a layer with no single flight at all. The shape is `chromulate-dns`'s,
/// which proves the same property with a counting resolver.
#[tokio::test]
async fn ten_concurrent_requests_at_one_challenged_url_launch_one_browser() {
    let server = challenge_origin().await;
    let browser = MockBrowser::slow(Answer::Clearance, Duration::from_millis(300));
    let layer = layer_with(Arc::new(Mitigated), &browser)
        .with_policy(HandoffPolicy::default().with_budget(20, Duration::from_secs(300)));
    let harness = Arc::new(Harness::direct(&server, layer).await);

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let harness = Arc::clone(&harness);
        tasks.spawn(async move { harness.fetch().await.status() });
    }

    let mut statuses = Vec::new();
    while let Some(finished) = tasks.join_next().await {
        statuses.push(finished.expect("no task may panic"));
    }

    assert_eq!(statuses.len(), 10);
    assert!(
        statuses.iter().all(|status| *status == StatusCode::OK),
        "every joiner gets the clearance the one solve earned: {statuses:?}"
    );
    assert_eq!(
        browser.calls(),
        1,
        "nine tasks joined the flight; ten browsers is the failure this prevents"
    );
}

/// An origin that challenges whatever you present gets a fixed number of attempts
/// and then its challenge response is what the caller receives.
#[tokio::test]
async fn an_origin_that_always_challenges_gets_exactly_the_budget_and_then_stops() {
    let server = immovable_origin().await;
    let browser = MockBrowser::answering(Answer::WorthlessClearance);
    let layer = layer_with(Arc::new(Mitigated), &browser)
        .with_policy(HandoffPolicy::default().with_budget(2, Duration::from_secs(300)));
    let harness = Harness::direct(&server, layer).await;

    let first = harness.fetch().await;
    assert_eq!(first.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        browser.calls(),
        2,
        "a budget of two is two handoffs, and a third inside the window is a loop"
    );

    let origin = Origin::of(&url(&harness.url)).expect("the test URL has an origin");
    assert_eq!(harness.layer.remaining_budget(&origin), 0);

    // A second request inside the same window does not buy a third browser.
    let second = harness.fetch().await;
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        browser.calls(),
        2,
        "the budget is per origin per window, not per request"
    );
}

/// A fallback that never comes back does not hold the caller's request open.
///
/// `Handoff::remaining` is a contract a third-party implementation may honour,
/// ignore, or hang through, and a seam can only ask. The layer enforces it, and
/// an overrun reads as a decline — the attempt happened and produced nothing.
#[tokio::test]
async fn a_fallback_that_overruns_its_budget_is_treated_as_a_decline() {
    let server = challenge_origin().await;
    // Five seconds of "browser", against a one-second budget.
    let browser = MockBrowser::slow(Answer::Clearance, Duration::from_secs(5));
    let layer = layer_with(Arc::new(Mitigated), &browser).with_solve_budget(Duration::from_secs(1));
    let harness = Harness::direct(&server, layer).await;

    let started = std::time::Instant::now();
    let response = harness.fetch().await;
    let waited = started.elapsed();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        waited < Duration::from_secs(4),
        "the request must not wait out a browser that is not coming back: {waited:?}"
    );
    assert_eq!(browser.calls(), 1, "the fallback really was asked");
}

/// A body that cannot be produced a second time cannot be handed off, because
/// re-sending with an empty one would quietly send a different request. The same
/// guard `Retry` applies at `middleware/retry.rs:157`.
///
/// Eligibility is widened here so that the *replay guard* is what refuses rather
/// than the default rule's `GET` test — and the second half proves it, by showing
/// the same method with a replayable body does get handed off.
#[tokio::test]
async fn a_streaming_body_is_never_handed_off_and_a_replayable_one_is() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let layer = layer_with(Arc::new(Mitigated), &browser)
        .with_policy(HandoffPolicy::default().with_eligible(|_: &Request| true));
    let harness = Harness::direct(&server, layer).await;

    let streaming = http::Request::builder()
        .method(Method::POST)
        .uri(&harness.url)
        .body(Body::stream(futures_util::stream::empty(), None))
        .expect("a valid request");
    let response = harness
        .engine
        .send(streaming)
        .await
        .expect("the layer must answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        browser.calls(),
        0,
        "a body the transport consumed cannot be replayed, so there is nothing to hand off"
    );

    let replayable = http::Request::builder()
        .method(Method::POST)
        .uri(&harness.url)
        .body(Body::fixed("{}"))
        .expect("a valid request");
    let response = harness
        .engine
        .send(replayable)
        .await
        .expect("the layer must answer");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        browser.calls(),
        1,
        "the same method with a replayable body is handed off, so the refusal above \
         was the replay guard and not the method"
    );
}

// ==================================================================== the exits

/// The test that protects `CLAUDE.md`'s rule: *server-taught state is keyed by the
/// proxy exit it was taught through.*
///
/// A clearance is server-taught state of exactly that kind. Landing it in another
/// exit's jar tells the origin that two exits are one client — worse than not
/// rotating at all, and silent when it happens.
#[tokio::test]
async fn a_clearance_earned_on_one_exit_lands_in_that_exits_jar_and_no_other() {
    let server = challenge_origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;
    let exits = PinnedExits::over(&[&first, &second]);

    let browser = MockBrowser::clearing();
    let layer = Arc::new(layer_with(Arc::new(Mitigated), &browser));
    let engine = Arc::new(
        Engine::builder(config())
            .proxies(Arc::clone(&exits) as Arc<dyn ProxyProvider>)
            .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
            .isolate_by_proxy(8, Arc::new(Jars))
            .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
            .build()
            .expect("the engine must build"),
    );
    layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));
    assert_eq!(
        engine.proxy_isolation(),
        ProxyIsolation::PerProxy { max_routes: 8 }
    );

    let target = format!("http://shop.test:{}/product", server.port());

    // Exit A goes first, at the one path this origin never challenges. That
    // gives it a real session with a real jar and no clearance in it, so the
    // final assertion is "A has a jar and it is empty of this" rather than the
    // much weaker "A has no jar".
    let ping = format!("http://shop.test:{}/ping", server.port());
    exits.pin(0);
    let through_a = engine
        .send(get(&ping))
        .await
        .expect("the layer must answer");
    let exit_a = through_a
        .extensions()
        .get::<ResponseInfo>()
        .and_then(|info| info.exit.clone())
        .expect("a proxied request went out through an exit and must say so");
    assert_eq!(through_a.status(), StatusCode::OK);
    assert!(
        route_exists(&engine, Some(&exit_a)),
        "exit A must hold a session of its own for the last assertion to mean anything"
    );

    // Exit B takes the challenge and earns the clearance.
    exits.pin(1);
    let through_b = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");
    let exit_b = through_b
        .extensions()
        .get::<ResponseInfo>()
        .and_then(|info| info.exit.clone())
        .expect("a proxied request went out through an exit and must say so");

    assert_ne!(exit_a, exit_b, "the two exits must be two");
    assert_eq!(through_b.status(), StatusCode::OK);
    assert_eq!(body_of(through_b).await, PAGE);

    // 1. The fallback was pointed at the exit the challenge arrived on.
    let handoffs = browser.handoffs();
    assert_eq!(handoffs.len(), 1);
    assert_eq!(
        handoffs[0].exit().map(|exit| exit.as_str()),
        Some(exit_b.as_ref()),
        "a browser going out through a different address earns a clearance for the \
         wrong client"
    );

    // 2. The cookie landed in exit B's jar.
    assert!(cleared_at(&engine, Some(&exit_b), &target));

    // 3. And exit A's is untouched. This is the silent half of the bug.
    assert!(
        route_exists(&engine, Some(&exit_a)),
        "exit A's session must still be there to be untouched"
    );
    assert!(
        !cleared_at(&engine, Some(&exit_a), &target),
        "exit A never earned this clearance and must not present it"
    );
    assert_eq!(
        engine.isolated_routes(),
        2,
        "one session per exit, and the clearance went into exactly one of them"
    );
}

/// **A known limitation, reproduced against the provider this workspace ships.**
///
/// A clearance is bound to the address that earned it, and nothing in
/// `chromulate-http` can pin the next hop to that address: `Connector::route()`
/// takes an origin and calls `ProxyProvider::next()` once per hop, and no request
/// extension overrides it. So under `RoundRobin` the retry leaves through the
/// *next* exit, where the clearance is not, and the browser ran for nothing.
///
/// Three exits and a budget of two make the waste unambiguous: two browser runs,
/// two real clearances filed in two real jars, and a `403` for the caller. With
/// two exits it would accidentally succeed on the third attempt, which is a worse
/// test — it would pass while the bug was present.
///
/// **When this test goes red, the routing fix has landed.** Do not repair the
/// assertions; delete the test, and delete the limitation section on
/// `ChallengeHandoff` that points at it.
#[tokio::test]
async fn a_rotating_pool_spends_a_browser_per_exit_because_the_retry_is_not_pinned() {
    let server = challenge_origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;
    let third = TestProxy::start(server.addr()).await;

    // The shipped rotating provider, deliberately — a test double here would be
    // measuring the double.
    let pool = vec![
        Proxy::new(ProxyUrl::parse(&first.url()).expect("a loopback proxy URL must parse")),
        Proxy::new(ProxyUrl::parse(&second.url()).expect("a loopback proxy URL must parse")),
        Proxy::new(ProxyUrl::parse(&third.url()).expect("a loopback proxy URL must parse")),
    ];

    let browser = MockBrowser::clearing();
    let layer = Arc::new(
        layer_with(Arc::new(Mitigated), &browser)
            .with_policy(HandoffPolicy::default().with_budget(2, Duration::from_secs(300))),
    );
    let engine = Arc::new(
        Engine::builder(config())
            .proxies(Arc::new(RoundRobin::new(pool)) as Arc<dyn ProxyProvider>)
            .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
            .isolate_by_proxy(8, Arc::new(Jars))
            .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
            .build()
            .expect("the engine must build"),
    );
    layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));

    let target = format!("http://shop.test:{}/product", server.port());
    let response = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the clearance never reaches the exit the retry uses, so the caller is still challenged"
    );
    assert_eq!(
        browser.calls(),
        2,
        "one browser per attempt, and the budget is what stops it rather than success"
    );

    // The work was done and thrown away: two exits really do hold a real
    // clearance, and the request that paid for them received none of it.
    let cleared: Vec<bool> = (0..3)
        .map(|index| {
            let label: Arc<str> = Arc::from(
                ProxyUrl::parse(&[&first, &second, &third][index].url())
                    .expect("a loopback proxy URL must parse")
                    .to_string()
                    .as_str(),
            );
            cleared_at(&engine, Some(&label), &target)
        })
        .collect();
    assert_eq!(
        cleared.iter().filter(|held| **held).count(),
        2,
        "two clearances were earned, filed correctly, and never used: {cleared:?}"
    );

    // The control, and the reason the assertions above are about rotation rather
    // than about anything else in the setup. Identical origin, identical exits,
    // identical policy — only the provider changes, and the outcome inverts.
    // Without this, the block above would pass just as happily if the layer had
    // simply stopped working.
    let exits = PinnedExits::over(&[&first, &second, &third]);
    let browser = MockBrowser::clearing();
    let layer = Arc::new(
        layer_with(Arc::new(Mitigated), &browser)
            .with_policy(HandoffPolicy::default().with_budget(2, Duration::from_secs(300))),
    );
    let engine = Arc::new(
        Engine::builder(config())
            .proxies(Arc::clone(&exits) as Arc<dyn ProxyProvider>)
            .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
            .isolate_by_proxy(8, Arc::new(Jars))
            .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
            .build()
            .expect("the engine must build"),
    );
    layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));

    exits.pin(1);
    let pinned = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");

    assert_eq!(
        pinned.status(),
        StatusCode::OK,
        "held to one exit, the very same clearance works first time"
    );
    assert_eq!(
        browser.calls(),
        1,
        "one challenge, one browser — which is what the rotating run above should \
         have cost and did not"
    );
}

/// The same run under `ProxyIsolation::Shared`, which is the other half of the
/// pair. One session, so the clearance is the whole client's and both exits carry
/// it — the behaviour a caller opts *out* of by isolating, and it has to work as
/// well as the isolated one.
#[tokio::test]
async fn a_shared_session_carries_the_clearance_through_every_exit() {
    let server = challenge_origin().await;
    let first = TestProxy::start(server.addr()).await;
    let second = TestProxy::start(server.addr()).await;
    let exits = PinnedExits::over(&[&first, &second]);

    let browser = MockBrowser::clearing();
    let layer = Arc::new(layer_with(Arc::new(Mitigated), &browser));
    let engine = Arc::new(
        Engine::builder(config())
            .proxies(Arc::clone(&exits) as Arc<dyn ProxyProvider>)
            .cookies(Arc::new(Jar::new()) as Arc<dyn CookieStore>)
            .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
            .build()
            .expect("the engine must build"),
    );
    layer.attach_sessions(Arc::new(Arc::downgrade(&engine)));
    assert_eq!(engine.proxy_isolation(), ProxyIsolation::Shared);

    let target = format!("http://shop.test:{}/product", server.port());

    exits.pin(0);
    let cleared = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(browser.calls(), 1);

    // The other exit inherits it, because sharing is what was asked for.
    exits.pin(1);
    let inherited = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");
    assert_eq!(inherited.status(), StatusCode::OK);
    assert_eq!(
        browser.calls(),
        1,
        "a shared session does not pay for a second browser"
    );
    assert_eq!(
        second.tunnels(),
        1,
        "the second request really did change exit"
    );
}

// ================================================================ default paths

/// The half `CLAUDE.md`'s second testing rule exists for.
///
/// Every test above installs a fallback and drives a challenged origin, so the
/// shapes most callers actually have — no fallback at all, an ordinary `403`, no
/// proxy — are untested by construction unless they are tested here.
mod default_paths {
    use super::*;

    /// With no fallback the layer is a diagnostic and nothing else: same status,
    /// same headers, same body, same number of requests.
    #[tokio::test]
    async fn with_no_fallback_installed_the_response_is_returned_unaltered() {
        let server = challenge_origin().await;
        let layer = ChallengeHandoff::new(Arc::new(Profile::chrome_stable()), Arc::new(Mitigated));
        let harness = Harness::direct(&server, layer).await;

        let response = harness.fetch().await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("cf-mitigated"),
            Some(&HeaderValue::from_static("challenge"))
        );
        // The conclusion rides along in the extensions, which is the detection
        // phase's whole product and is not a change to anything on the wire.
        assert!(response.extensions().get::<Challenge>().is_some());
        assert_eq!(
            body_of(response).await,
            "<title>Just a moment...</title>",
            "the challenge page itself must reach a caller who wants to look at it"
        );
        assert_eq!(
            server.request_count(),
            1,
            "with nothing to hand off to, nothing is re-run"
        );
    }

    /// An origin returning `403` for an expired token is the common case.
    /// Launching a browser on every auth failure is not acceptable, and the
    /// detector is what stops it.
    #[tokio::test]
    async fn a_403_that_is_not_a_challenge_is_not_handed_off() {
        let server = TestServer::always(Reply::new(403).with_body(b"expired token".to_vec())).await;
        let browser = MockBrowser::clearing();
        let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

        let response = harness.fetch().await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response.extensions().get::<Challenge>().is_none(),
            "nothing here says challenge, so nothing may conclude one"
        );
        assert_eq!(browser.calls(), 0);
        assert_eq!(server.request_count(), 1);
        assert_eq!(body_of(response).await, "expired token");
    }

    /// An ordinary `200` costs a detector call and nothing else.
    #[tokio::test]
    async fn an_ordinary_response_passes_through_untouched() {
        let server = TestServer::always(Reply::text("hello")).await;
        let browser = MockBrowser::clearing();
        let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

        let response = harness.fetch().await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.extensions().get::<Challenge>().is_none());
        assert!(response.extensions().get::<FetchedByFallback>().is_none());
        assert!(
            response.extensions().get::<ResponseInfo>().is_some(),
            "the engine's own report must survive a middleware that did nothing"
        );
        assert_eq!(body_of(response).await, "hello");
        assert_eq!(browser.calls(), 0);
    }

    /// No proxy configured: `Handoff::exit` is `None` and the per-exit path never
    /// runs. The shape of every unproxied client, which is most of them.
    #[tokio::test]
    async fn an_unproxied_client_hands_off_with_no_exit_at_all() {
        let server = challenge_origin().await;
        let browser = MockBrowser::clearing();
        let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

        let response = harness.fetch().await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            browser.handoffs()[0].exit().is_none(),
            "a direct request has no exit, and inventing one would point a browser at \
             a proxy that is not there"
        );
        assert_eq!(
            harness.engine.isolated_routes(),
            0,
            "an unproxied engine mints no per-exit session"
        );
    }

    /// A subresource is refused by the default eligibility rule, because a browser
    /// cannot usefully be pointed at a stylesheet. Detection still happens: that
    /// is not what eligibility switches off.
    #[tokio::test]
    async fn a_challenged_subresource_is_detected_and_not_handed_off() {
        let server = challenge_origin().await;
        let browser = MockBrowser::clearing();
        let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

        let mut request = get(&harness.url);
        let mut options = chromulate_core::RequestOptions::api();
        options.dest = chromulate_core::FetchDest::Style;
        request.extensions_mut().insert(options);

        let response = harness
            .engine
            .send(request)
            .await
            .expect("the layer must answer");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.extensions().get::<Challenge>().is_some());
        assert_eq!(browser.calls(), 0);
    }

    /// And the request the facade actually builds — `RequestOptions::api()`, which
    /// every `client.get(url).send()` carries — is eligible. A rule written against
    /// `Sec-Fetch-Mode: navigate` would have made the whole layer inert, and this
    /// is the end-to-end half of the unit test that guards it.
    #[tokio::test]
    async fn the_request_the_facade_actually_builds_is_handed_off() {
        let server = challenge_origin().await;
        let browser = MockBrowser::clearing();
        let harness = Harness::direct(&server, layer_with(Arc::new(Mitigated), &browser)).await;

        let mut request = get(&harness.url);
        request
            .extensions_mut()
            .insert(chromulate_core::RequestOptions::api());

        let response = harness
            .engine
            .send(request)
            .await
            .expect("the layer must answer");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(browser.calls(), 1);
    }
}

// ========================================================= the cleared callback

/// The wiring that keeps an adaptive controller from freezing an origin forever
/// after its `403`. It fires on the transition, and only then.
#[tokio::test]
async fn the_cleared_callback_fires_once_the_origin_answers_again() {
    let server = challenge_origin().await;
    let browser = MockBrowser::clearing();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    let layer =
        layer_with(Arc::new(Mitigated), &browser).on_cleared(Arc::new(move |cleared: &Url| {
            recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(cleared.to_string());
        }));
    let harness = Harness::direct(&server, layer).await;

    let response = harness.fetch().await;
    assert_eq!(response.status(), StatusCode::OK);

    let cleared = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        cleared,
        vec![harness.url.clone()],
        "the callback is how `AdaptiveConcurrency::forget` gets called, and a missed \
         call is throughput that never recovers"
    );
}

/// It does not fire when nothing was cleared. A `Content` handback means the
/// browser fetched a page and this client is still refused, so un-freezing the
/// origin would ramp against a wall.
#[tokio::test]
async fn the_cleared_callback_does_not_fire_for_a_page_the_browser_merely_fetched() {
    let server = challenge_origin().await;
    let browser = MockBrowser::answering(Answer::Page("<html>fetched</html>"));
    let fired = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fired);

    let layer = layer_with(Arc::new(Mitigated), &browser).on_cleared(Arc::new(move |_: &Url| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let harness = Harness::direct(&server, layer).await;

    let response = harness.fetch().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "nothing was cleared: the origin is still challenging this client"
    );
}

/// And it does not fire for a response that was never a challenge, which is every
/// ordinary request a crawl makes.
#[tokio::test]
async fn the_cleared_callback_does_not_fire_for_a_request_that_was_never_challenged() {
    let server = TestServer::always(Reply::text("hello")).await;
    let browser = MockBrowser::clearing();
    let fired = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fired);

    let layer = layer_with(Arc::new(Mitigated), &browser).on_cleared(Arc::new(move |_: &Url| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let harness = Harness::direct(&server, layer).await;

    let _ = harness.fetch().await;
    assert_eq!(fired.load(Ordering::SeqCst), 0);
}

/// The `Debug` impl reports the two pieces of wiring whose absence is silent.
///
/// Both failures this layer can suffer without saying anything are configuration
/// rather than code: no session access means a clearance cannot be kept, and no
/// `Cleared` callback means an adaptive controller stays frozen on the
/// challenge's `403`. A `Debug` that shows neither is a `Debug` that answers the
/// wrong question in the log line where someone is asking it.
#[test]
fn the_debug_output_says_which_wiring_is_missing() {
    let browser = MockBrowser::clearing();

    let bare = layer_with(Arc::new(Mitigated), &browser);
    let rendered = format!("{bare:?}");
    assert!(rendered.contains("sessions_attached: false"), "{rendered}");
    assert!(rendered.contains("cleared_callback: false"), "{rendered}");
    assert!(rendered.contains("mock-browser"), "{rendered}");

    let wired = layer_with(Arc::new(Mitigated), &browser).on_cleared(Arc::new(|_: &Url| {}));
    #[derive(Debug)]
    struct Nowhere;
    impl SessionAccess for Nowhere {
        fn cookie_header(&self, _: Option<&Arc<str>>, _: &Url) -> Option<HeaderValue> {
            None
        }
        fn store_cookies(&self, _: Option<&Arc<str>>, _: &Url, _: &[HeaderValue]) {}
    }
    wired.attach_sessions(Arc::new(Nowhere) as Arc<dyn SessionAccess>);

    let rendered = format!("{wired:?}");
    assert!(rendered.contains("sessions_attached: true"), "{rendered}");
    assert!(rendered.contains("cleared_callback: true"), "{rendered}");
}

// ============================================================== the session seam

/// `SessionAccess` is a trait rather than a hard-wired engine call, so a caller
/// who keeps cookies somewhere else can still keep a clearance — and both
/// directions can be observed without an engine in the way.
#[tokio::test]
async fn a_caller_may_supply_their_own_session_access() {
    #[derive(Debug, Default)]
    struct Recorder {
        stored: Mutex<Vec<(Option<String>, String)>>,
    }

    impl SessionAccess for Recorder {
        fn cookie_header(&self, _exit: Option<&Arc<str>>, _url: &Url) -> Option<HeaderValue> {
            Some(HeaderValue::from_static("session=already-here"))
        }

        fn store_cookies(&self, exit: Option<&Arc<str>>, target: &Url, set_cookie: &[HeaderValue]) {
            let lines = set_cookie
                .iter()
                .map(|line| line.to_str().unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
                .join(", ");
            self.stored
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((
                    exit.map(|exit| exit.to_string()),
                    format!("{target} => {lines}"),
                ));
        }
    }

    let server = immovable_origin().await;
    let browser = MockBrowser::clearing();
    let recorder = Arc::new(Recorder::default());
    let layer = Arc::new(
        layer_with(Arc::new(Mitigated), &browser)
            .with_policy(HandoffPolicy::default().with_budget(1, Duration::from_secs(300))),
    );
    layer.attach_sessions(Arc::clone(&recorder) as Arc<dyn SessionAccess>);

    let resolver = StaticResolver::empty().with_host("shop.test".to_owned(), vec![server.addr()]);
    let engine = Engine::builder(config())
        .resolver(Arc::new(resolver))
        .middleware(Arc::clone(&layer) as Arc<dyn Middleware>)
        .build()
        .expect("the engine must build");

    let target = format!("http://shop.test:{}/product", server.port());
    let _ = engine
        .send(get(&target))
        .await
        .expect("the layer must answer");

    let stored = recorder
        .stored
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0, None, "no proxy, so no exit");
    assert!(
        stored[0].1.contains("cf_clearance=granted"),
        "{:?}",
        stored[0]
    );

    // And the outbound direction: what the route already held reached the
    // browser, so it starts where Chromulate stopped rather than from nothing.
    assert_eq!(
        browser.handoffs()[0].cookies(),
        Some(&HeaderValue::from_static("session=already-here"))
    );

    // Wiring it twice is not a way to change it.
    assert!(
        !layer.attach_sessions(Arc::new(Recorder::default()) as Arc<dyn SessionAccess>),
        "a second attach must not silently replace the first"
    );
}
