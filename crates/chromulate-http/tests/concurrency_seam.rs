//! The concurrency seam, driven through the real engine.
//!
//! `chromulate_http::adaptive` is one control law. These tests are about the
//! boundary it sits behind: whether a caller who disagrees with that law can
//! supply their own, whether the engine actually obeys it, and whether anything
//! installed through the seam can get out from under a rate limit the caller
//! configured.
//!
//! The controller below is written here, in a test, outside the crate, using
//! only what the public API offers. That is the point — if it needed anything
//! `pub(crate)` the seam would not be a seam.

#![cfg(feature = "adaptive-concurrency")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chromulate_core::{Body, BoxFuture, Middleware, Request, Response};
use chromulate_dns::StaticResolver;
use chromulate_http::adaptive::{AdaptiveConcurrency, authority_of};
use chromulate_http::concurrency::{Ceiling, ConcurrencyController, Lease, Outcome};
use chromulate_http::{Engine, EngineBuilder, EngineConfig, RateLimit, RateLimiter};
use chromulate_profile::Profile;
use common::{Reply, TestServer};
use tokio::sync::Notify;
use url::Url;

// ---------------------------------------------------------------------------
// A controller written outside the crate, with a law of its own.
// ---------------------------------------------------------------------------

/// What the controller was told about one completed request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Testimony {
    authority: String,
    status: Option<u16>,
    retry_after: Option<String>,
}

#[derive(Debug)]
struct AimdState {
    limit: usize,
    in_flight: usize,
    max_in_flight: usize,
    seen: Vec<Testimony>,
    limits: Vec<usize>,
}

/// The shared half, so a lease can own the controller that issued it.
///
/// Any implementation needs this shape: `acquire` only has `&self`, and the
/// lease it returns outlives that borrow.
#[derive(Debug)]
struct Inner {
    ceiling: usize,
    state: Mutex<AimdState>,
    slot: Notify,
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, AimdState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn try_take(&self) -> bool {
        let mut state = self.lock();
        if state.in_flight < state.limit {
            state.in_flight += 1;
            state.max_in_flight = state.max_in_flight.max(state.in_flight);
            true
        } else {
            false
        }
    }

    async fn take(&self) {
        loop {
            if self.try_take() {
                return;
            }
            let notified = self.slot.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.try_take() {
                return;
            }
            notified.await;
        }
    }

    fn release(&self, authority: String, outcome: &Outcome<'_>) {
        {
            let mut state = self.lock();
            state.in_flight = state.in_flight.saturating_sub(1);
            state.seen.push(Testimony {
                authority,
                status: outcome.status().map(|status| status.as_u16()),
                retry_after: outcome.headers().and_then(|headers| {
                    headers
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned)
                }),
            });
            let moved = match outcome.status().map(|status| status.as_u16()) {
                // Multiplicative decrease, and nothing else: no cooldown, and no
                // ceiling that only ever falls.
                Some(429) => (state.limit / 2).max(1),
                // Additive increase, all the way back to where it started. The
                // built-in law never returns to a level that earned a refusal;
                // this one does, deliberately.
                Some(_) => (state.limit + 1).min(self.ceiling),
                None => state.limit,
            };
            state.limit = moved;
            state.limits.push(moved);
        }
        self.slot.notify_waiters();
    }
}

/// Classic additive-increase/multiplicative-decrease, which is precisely what
/// the built-in law refuses to do.
///
/// A `429` halves the limit and any other answer adds one back, up to the
/// number this controller was built with. Nothing is permanent, nothing pauses,
/// and a `403` means nothing at all. A caller who has been told what their quota
/// is may reasonably want exactly this; before the seam existed they could not
/// have it.
#[derive(Debug, Clone)]
struct Aimd {
    inner: Arc<Inner>,
}

impl Aimd {
    /// A controller that grants nothing until [`Aimd::open`] is called.
    fn closed(ceiling: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                ceiling,
                state: Mutex::new(AimdState {
                    limit: 0,
                    in_flight: 0,
                    max_in_flight: 0,
                    seen: Vec::new(),
                    limits: Vec::new(),
                }),
                slot: Notify::new(),
            }),
        }
    }

    fn open_at(limit: usize, ceiling: usize) -> Self {
        let controller = Self::closed(ceiling);
        controller.open(limit);
        controller
    }

    fn open(&self, limit: usize) {
        self.inner.lock().limit = limit;
        self.inner.slot.notify_waiters();
    }

    fn seen(&self) -> Vec<Testimony> {
        self.inner.lock().seen.clone()
    }

    /// Every value the limit took, in order, so a test can see the dip and the
    /// recovery rather than only where it ended up.
    fn limits(&self) -> Vec<usize> {
        self.inner.lock().limits.clone()
    }

    fn max_in_flight(&self) -> usize {
        self.inner.lock().max_in_flight
    }
}

impl ConcurrencyController for Aimd {
    fn acquire<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Box<dyn Lease>> {
        Box::pin(async move {
            self.inner.take().await;
            Box::new(AimdLease {
                inner: Arc::clone(&self.inner),
                authority: authority_of(url).to_owned(),
            }) as Box<dyn Lease>
        })
    }
}

#[derive(Debug)]
struct AimdLease {
    inner: Arc<Inner>,
    authority: String,
}

impl Lease for AimdLease {
    fn complete(self: Box<Self>, outcome: &Outcome<'_>) {
        self.inner.release(self.authority.clone(), outcome);
    }
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const HOST: &str = "origin.test";

fn engine_for(server: &TestServer, controller: Arc<dyn ConcurrencyController>) -> Engine {
    engine_built(server, |builder| builder.concurrency(controller))
}

fn engine_built(server: &TestServer, wire: impl FnOnce(EngineBuilder) -> EngineBuilder) -> Engine {
    let resolver = StaticResolver::empty().with_host(HOST.to_owned(), vec![server.addr()]);
    let mut config = EngineConfig::new(Arc::new(Profile::chrome_stable()));
    config.connect_timeout = Some(Duration::from_secs(5));
    wire(Engine::builder(config).resolver(Arc::new(resolver)))
        .build()
        .expect("the engine must build")
}

fn get(url: &str) -> Request {
    http::Request::builder()
        .uri(url)
        .body(Body::empty())
        .expect("a valid request")
}

fn authority(url: &str) -> String {
    authority_of(&Url::parse(url).expect("a valid url")).to_owned()
}

async fn drain(response: Response) {
    let _ = response
        .into_body()
        .collect(1024 * 1024)
        .await
        .expect("the body must be readable");
}

// ---------------------------------------------------------------------------
// The engine obeys a controller it did not write.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_engine_sends_nothing_until_a_third_party_controller_grants_a_lease() {
    let server = TestServer::always(Reply::text("body")).await;
    let controller = Aimd::closed(2);
    let engine = engine_for(&server, Arc::new(controller.clone()));
    let url = server.url_for(HOST, "/gated");

    let sending = tokio::spawn(async move {
        let response = engine.send(get(&url)).await.expect("the request must send");
        drain(response).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.request_count(),
        0,
        "the engine sent a request the controller had not granted"
    );

    controller.open(2);
    sending.await.expect("the request task must finish");

    assert_eq!(server.request_count(), 1, "and it sends once permitted");
}

#[tokio::test]
async fn a_third_party_controller_replaces_the_built_in_law_entirely() {
    // The first answer refuses; everything after it is healthy.
    let answered = Arc::new(AtomicUsize::new(0));
    let server = {
        let answered = Arc::clone(&answered);
        TestServer::start(move |_| {
            if answered.fetch_add(1, Ordering::SeqCst) == 0 {
                Reply::new(429).with_header("retry-after", "3600")
            } else {
                Reply::text("body")
            }
        })
        .await
    };

    let controller = Aimd::open_at(2, 2);
    let engine = engine_for(&server, Arc::new(controller.clone()));
    let url = server.url_for(HOST, "/aimd");

    let started = Instant::now();
    for _ in 0..4 {
        let response = engine.send(get(&url)).await.expect("the request must send");
        drain(response).await;
    }
    let elapsed = started.elapsed();

    let seen = controller.seen();
    assert_eq!(seen.len(), 4, "every hop reported an outcome");
    assert_eq!(
        seen[0].status,
        Some(429),
        "the raw status reaches the seam, not a verdict someone else reached"
    );
    assert_eq!(
        seen[0].retry_after.as_deref(),
        Some("3600"),
        "and so do the headers, so a controller can read what it needs itself"
    );
    assert_eq!(seen[0].authority, authority(&url));

    assert_eq!(
        controller.limits(),
        vec![1, 2, 2, 2],
        "halved on the refusal and recovered from it: the built-in law never \
         returns to a level that was refused"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "nothing paused: the built-in law would have held this origin for its \
         five-second cooldown, or for the hour the header asked for ({elapsed:?})"
    );
}

#[tokio::test]
async fn the_engine_holds_requests_back_to_the_limit_a_third_party_controller_sets() {
    let arrivals = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let server = {
        let arrivals = Arc::clone(&arrivals);
        TestServer::start(move |_| {
            arrivals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Instant::now());
            Reply::text("body").delayed(Duration::from_millis(60))
        })
        .await
    };

    // One slot, and no way for it to grow: every increase is clamped to the
    // ceiling this was built with.
    let controller = Aimd::open_at(1, 1);
    let engine = engine_for(&server, Arc::new(controller.clone()));
    let url = server.url_for(HOST, "/serial");

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let engine = engine.clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let response = engine.send(get(&url)).await.expect("the request must send");
            drain(response).await;
        }));
    }
    for task in tasks {
        task.await.expect("every request task must finish");
    }

    assert_eq!(
        controller.max_in_flight(),
        1,
        "the engine took a second lease while one was outstanding"
    );

    let arrivals = arrivals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(arrivals.len(), 3);
    for pair in arrivals.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap >= Duration::from_millis(40),
            "the origin saw two requests overlap, so the engine did not wait for \
             the controller: {gap:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The caller's rate limit is not something the seam can escape.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_permissive_third_party_controller_cannot_outrun_the_callers_rate_limiter() {
    let server = TestServer::always(Reply::text("body")).await;

    // Fifty per second, one token of burst: four of the five requests below
    // must wait twenty milliseconds each.
    let limiter = Arc::new(RateLimiter::new(
        RateLimit::per_second(50.0).with_burst(1.0),
    ));
    // A controller that grants everything, instantly, for ever. It holds no
    // reference to the limiter and the trait offers it no way to obtain one.
    let controller = Aimd::open_at(64, 64);

    let engine = engine_built(&server, |builder| {
        builder
            .middleware(limiter as Arc<dyn Middleware>)
            .concurrency(Arc::new(controller.clone()))
    });
    let url = server.url_for(HOST, "/limited");

    let started = Instant::now();
    for _ in 0..5 {
        let response = engine.send(get(&url)).await.expect("the request must send");
        drain(response).await;
    }
    let elapsed = started.elapsed();

    assert_eq!(server.request_count(), 5);
    assert_eq!(controller.max_in_flight(), 1, "nothing queued on the seam");
    assert!(
        elapsed >= Duration::from_millis(80),
        "five requests at fifty per second cannot take less than eighty \
         milliseconds, whatever the controller says: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// The default path: a caller who names no controller of their own.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_built_in_law_is_what_an_engine_gets_when_it_names_no_other_controller() {
    let server = TestServer::always(Reply::text("body")).await;
    let controller = Arc::new(AdaptiveConcurrency::new(Ceiling::Unlimited));
    let engine = engine_for(
        &server,
        Arc::clone(&controller) as Arc<dyn ConcurrencyController>,
    );
    let url = server.url_for(HOST, "/default");

    for _ in 0..3 {
        let response = engine.send(get(&url)).await.expect("the request must send");
        drain(response).await;
    }

    let seen = controller
        .snapshot(&authority(&url))
        .expect("the origin was visited");
    assert_eq!(
        seen.limit, 1,
        "a new origin still starts at one and still needs the whole run of clean \
         probes to move"
    );
    assert_eq!(seen.in_flight, 0, "every lease came back");
    assert_eq!(
        seen.ceiling, 6,
        "and the ceiling is still the default maximum"
    );
}

#[tokio::test]
async fn the_built_in_law_still_ratchets_and_pauses_on_a_429_through_the_seam() {
    let server = TestServer::always(Reply::new(429).with_header("retry-after", "60")).await;
    let controller = Arc::new(AdaptiveConcurrency::new(Ceiling::Unlimited));
    let engine = engine_for(
        &server,
        Arc::clone(&controller) as Arc<dyn ConcurrencyController>,
    );
    let url = server.url_for(HOST, "/refused");

    let response = engine.send(get(&url)).await.expect("the request must send");
    drain(response).await;

    let seen = controller
        .snapshot(&authority(&url))
        .expect("the origin was visited");
    assert_eq!(seen.ceiling, 1, "the ratchet still falls");
    assert_eq!(
        seen.retry_after_requested,
        Some(Duration::from_secs(60)),
        "and the header is still read on the way through the seam"
    );
    // The real clock is running here, so the pause left is a shade under the
    // minute that was asked for rather than exactly it.
    let left = seen.paused_for.expect("the origin is paused");
    assert!(
        left > Duration::from_secs(59) && left <= Duration::from_secs(60),
        "the pause the header asked for is what is being waited: {left:?}"
    );
    assert_eq!(seen.refusals, 1);
}
