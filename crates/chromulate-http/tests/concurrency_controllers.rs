//! The two controllers this crate ships, driven by hand.
//!
//! Like `adaptive_concurrency.rs`, every test here runs against an injectable
//! clock and a local decision — no socket, no origin, no sleeping. What is new
//! is that there are now two implementations to drive, and the second one exists
//! partly to show that the first did not shape the seam around itself.

#![cfg(feature = "adaptive-concurrency")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chromulate_core::BoxFuture;
use chromulate_http::adaptive::{AdaptiveConcurrency, ConcurrencyConfig, Signal, authority_of};
use chromulate_http::concurrency::{
    Ceiling, ConcurrencyController, FixedConcurrency, FixedLease, Lease, Outcome,
};
use chromulate_http::{Clock, RateLimit, RateLimiter, Sleeper, TimeSource};
use http::{HeaderMap, StatusCode};
use url::Url;

/// Polls a future exactly once. See `adaptive_concurrency.rs` for why this is
/// hand-written rather than taken from `futures-util`.
fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    future.poll(&mut context)
}

// ---------------------------------------------------------------------------
// A clock a test moves by hand.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TestTime {
    state: Mutex<TestState>,
}

#[derive(Debug)]
struct TestState {
    now: Instant,
    slept: Vec<Duration>,
}

impl TestTime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(TestState {
                now: Instant::now(),
                slept: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TestState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn advance(&self, by: Duration) {
        let mut state = self.lock();
        state.now += by;
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.lock().slept.clone()
    }

    fn source(self: &Arc<Self>) -> TimeSource {
        TimeSource::new(Arc::clone(self) as Arc<dyn Clock>, Arc::clone(self) as _)
    }
}

impl Clock for TestTime {
    fn now(&self) -> Instant {
        self.lock().now
    }
}

impl Sleeper for TestTime {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let mut state = self.lock();
        state.slept.push(duration);
        state.now += duration;
        Box::pin(std::future::ready(()))
    }
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const ORIGIN: &str = "https://example.test/product/1";

fn url() -> Url {
    Url::parse(ORIGIN).expect("a valid url")
}

fn authority() -> String {
    authority_of(&url()).to_owned()
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// An outcome carrying a status and no headers worth reading.
fn answered(status: StatusCode) -> (StatusCode, HeaderMap) {
    (status, HeaderMap::new())
}

// ---------------------------------------------------------------------------
// FixedConcurrency: a number the caller chose, and nothing else.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_fixed_controller_bounds_in_flight_requests_per_origin() {
    let controller = FixedConcurrency::new(2, Ceiling::Unlimited);
    let url = url();

    let first = controller.acquire(&url).await;
    let second = controller.acquire(&url).await;
    assert!(first.holds_a_slot() && second.holds_a_slot());
    assert_eq!(controller.in_flight(&authority()), Some(2));

    let mut queued = Box::pin(controller.acquire(&url));
    assert!(
        poll_once(queued.as_mut()).is_pending(),
        "a third request must wait for one of the two slots"
    );

    drop(first);
    let third = queued.await;
    assert_eq!(controller.in_flight(&authority()), Some(2));
    drop((second, third));
    assert_eq!(controller.in_flight(&authority()), Some(0));
}

#[tokio::test]
async fn a_fixed_controller_never_adapts_however_the_origin_answers() {
    let time = TestTime::new();
    let controller = FixedConcurrency::new(3, Ceiling::Unlimited).with_time_source(time.source());
    let url = url();

    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::FORBIDDEN,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::OK,
    ] {
        let lease: Box<dyn Lease> = Box::new(controller.acquire(&url).await);
        let (status, headers) = answered(status);
        let mut headers = headers;
        headers.insert("retry-after", "3600".parse().expect("a valid value"));
        lease.complete(&Outcome::answered(status, &headers));

        assert_eq!(
            controller.limit(),
            3,
            "{status} moved a limit that is not supposed to move"
        );
        assert_eq!(controller.in_flight(&authority()), Some(0));
    }

    // A request that produced nothing at all is not a signal either.
    let lease: Box<dyn Lease> = Box::new(controller.acquire(&url).await);
    lease.complete(&Outcome::failed());
    assert_eq!(controller.limit(), 3);

    assert!(
        time.sleeps().is_empty(),
        "nothing here backs off, so nothing here waits: {:?}",
        time.sleeps()
    );

    // And the three slots are still three slots.
    let held: Vec<FixedLease> = vec![
        controller.acquire(&url).await,
        controller.acquire(&url).await,
        controller.acquire(&url).await,
    ];
    assert_eq!(controller.in_flight(&authority()), Some(3));
    let mut queued = Box::pin(controller.acquire(&url));
    assert!(poll_once(queued.as_mut()).is_pending());
    drop(held);
    let _ = queued.await;
}

#[tokio::test]
async fn a_fixed_controller_counts_each_origin_on_its_own() {
    let controller = FixedConcurrency::new(1, Ceiling::Unlimited);
    let first = Url::parse("https://one.test/a").expect("a valid url");
    let second = Url::parse("https://two.test/a").expect("a valid url");

    let held = controller.acquire(&first).await;
    // A different origin is not queued behind this one.
    let other = controller.acquire(&second).await;

    assert_eq!(controller.in_flight("one.test"), Some(1));
    assert_eq!(controller.in_flight("two.test"), Some(1));
    assert_eq!(controller.len(), 2);
    assert_eq!(controller.in_flight("three.test"), None);

    let mut queued = Box::pin(controller.acquire(&first));
    assert!(
        poll_once(queued.as_mut()).is_pending(),
        "the second request to the *same* origin still waits"
    );
    drop(held);
    let _ = queued.await;
    drop(other);
}

#[tokio::test]
async fn a_fixed_lease_dropped_without_a_report_still_returns_its_slot() {
    let controller = FixedConcurrency::new(1, Ceiling::Unlimited);
    let url = url();

    let lease = controller.acquire(&url).await;
    assert_eq!(controller.in_flight(&authority()), Some(1));
    drop(lease);

    assert_eq!(
        controller.in_flight(&authority()),
        Some(0),
        "a cancelled request must not leak a slot"
    );
    let _ = controller.acquire(&url).await;
}

#[tokio::test]
async fn a_fixed_controller_cannot_outrun_the_callers_rate_limit() {
    let time = TestTime::new();
    let limiter = Arc::new(RateLimiter::with_time_source(
        RateLimit::per_second(4.0).with_burst(1.0),
        time.source(),
    ));
    // Eight slots against four requests a second: the slots are not the binding
    // constraint, and cannot become one.
    let controller =
        FixedConcurrency::new(8, Ceiling::RateLimit(limiter)).with_time_source(time.source());
    let url = url();

    for _ in 0..5 {
        let lease = controller.acquire(&url).await;
        drop(lease);
    }

    assert_eq!(
        time.sleeps(),
        vec![ms(250), ms(250), ms(250), ms(250)],
        "at four per second, four of the five waited a quarter of a second"
    );
}

#[tokio::test]
async fn a_fixed_controller_with_an_unusable_limit_still_grants_permits() {
    let controller = FixedConcurrency::new(0, Ceiling::Unlimited);
    assert_eq!(
        controller.limit(),
        1,
        "a controller that can grant nothing is a hang, not a careful default"
    );

    let lease = controller.acquire(&url()).await;
    assert!(lease.holds_a_slot());
    assert_eq!(controller.in_flight(&authority()), Some(1));
}

#[tokio::test]
async fn the_fixed_controllers_origin_store_stays_inside_its_capacity() {
    let controller = FixedConcurrency::new(2, Ceiling::Unlimited).with_capacity(32);

    for index in 0..1_000u32 {
        let url = Url::parse(&format!("https://host-{index}.test/")).expect("a valid url");
        let lease = controller.acquire(&url).await;
        drop(lease);
        assert!(
            controller.len() <= 32,
            "the store held {} entries against a capacity of 32",
            controller.len()
        );
    }
    assert!(
        controller.len() > 32 - (32 / 16) - 1,
        "and a purge must not empty it: {}",
        controller.len()
    );
    assert!(!controller.is_empty());
}

#[tokio::test]
async fn an_origin_with_a_lease_outstanding_is_not_evicted_from_under_it() {
    let controller = FixedConcurrency::new(2, Ceiling::Unlimited).with_capacity(8);

    let busy = Url::parse("https://busy.test/").expect("a valid url");
    let lease = controller.acquire(&busy).await;

    for index in 0..200u32 {
        let url = Url::parse(&format!("https://noise-{index}.test/")).expect("a valid url");
        drop(controller.acquire(&url).await);
    }

    assert_eq!(
        controller.in_flight("busy.test"),
        Some(1),
        "an origin holding a slot must keep the gate that is counting it"
    );
    drop(lease);
    assert_eq!(controller.in_flight("busy.test"), Some(0));

    // And forgetting is still the caller's lever.
    assert!(controller.forget("busy.test"));
    assert!(!controller.forget("busy.test"));
    assert_eq!(controller.in_flight("busy.test"), None);
}

#[tokio::test]
async fn a_fixed_controller_is_reachable_through_the_seam_it_shares() {
    let controller: Arc<dyn ConcurrencyController> =
        Arc::new(FixedConcurrency::new(1, Ceiling::Unlimited));
    let url = url();

    let lease = controller.acquire(&url).await;
    let mut queued = Box::pin(controller.acquire(&url));
    assert!(
        poll_once(queued.as_mut()).is_pending(),
        "the limit is one, whichever side of the trait object it is asked from"
    );

    let headers = HeaderMap::new();
    lease.complete(&Outcome::answered(StatusCode::OK, &headers));
    let second = queued.await;
    second.complete(&Outcome::failed());
}

#[tokio::test]
async fn reaching_a_controller_through_the_seam_does_not_skip_its_ceiling() {
    let time = TestTime::new();
    let limiter = Arc::new(RateLimiter::with_time_source(
        RateLimit::per_second(2.0).with_burst(1.0),
        time.source(),
    ));
    // Both shipped controllers, both reached only as trait objects, both under
    // the same limiter. There is no method on the trait that could have skipped
    // it, and no constructor that could have left it out.
    let controllers: Vec<Arc<dyn ConcurrencyController>> = vec![
        Arc::new(
            AdaptiveConcurrency::with_config(quick(), Ceiling::RateLimit(Arc::clone(&limiter)))
                .with_time_source(time.source()),
        ),
        Arc::new(
            FixedConcurrency::new(8, Ceiling::RateLimit(Arc::clone(&limiter)))
                .with_time_source(time.source()),
        ),
    ];

    let url = url();
    let headers = HeaderMap::new();
    for controller in &controllers {
        for _ in 0..3 {
            let lease = controller.acquire(&url).await;
            lease.complete(&Outcome::answered(StatusCode::OK, &headers));
        }
    }

    assert_eq!(
        time.sleeps(),
        vec![ms(500); 5],
        "six requests at two per second: the first spends the burst token and \
         every one after it waits half a second, whichever controller asked"
    );
}

// ---------------------------------------------------------------------------
// The one piece of the built-in law that became a caller's choice.
// ---------------------------------------------------------------------------

/// The short-run configuration `adaptive_concurrency.rs` uses, so the numbers
/// below can be written out by hand.
fn quick() -> ConcurrencyConfig {
    ConcurrencyConfig {
        min: 1,
        max: 4,
        probe: 2,
        clean_probes_before_increase: 2,
        degradation: 2.0,
        hold: Duration::from_secs(30),
        cooldown: Duration::from_secs(5),
        max_cooldown: Duration::from_secs(300),
        max_pause: Duration::from_secs(3600),
        capacity: 64,
    }
}

fn recovering(time: &Arc<TestTime>, interval: Duration) -> AdaptiveConcurrency {
    AdaptiveConcurrency::with_config(quick(), Ceiling::Unlimited)
        .with_time_source(time.source())
        .with_ceiling_recovery(interval)
}

fn ceiling_of(controller: &AdaptiveConcurrency) -> usize {
    controller
        .snapshot(&authority())
        .expect("the origin has been seen")
        .ceiling
}

/// `count` healthy responses one at a time, so nothing queues for a slot.
async fn probes(controller: &AdaptiveConcurrency, time: &TestTime, count: usize) {
    let url = url();
    for _ in 0..count {
        let permit = controller.acquire(&url).await;
        time.advance(ms(10));
        permit.complete(Signal::Healthy);
    }
}

async fn refuse(controller: &AdaptiveConcurrency) {
    let permit = controller.acquire(&url()).await;
    permit.complete(Signal::Backpressure { retry_after: None });
}

#[tokio::test]
async fn a_refusal_is_final_unless_the_caller_asked_for_it_not_to_be() {
    assert_eq!(
        AdaptiveConcurrency::new(Ceiling::Unlimited).ceiling_recovery(),
        None,
        "the default must stay what it was: a refused level is never revisited"
    );

    let time = TestTime::new();
    let controller = AdaptiveConcurrency::with_config(quick(), Ceiling::Unlimited)
        .with_time_source(time.source());

    refuse(&controller).await;
    assert_eq!(ceiling_of(&controller), 1);

    // Years of clean probes, and the lesson still stands.
    for _ in 0..20 {
        time.advance(Duration::from_secs(86_400));
        probes(&controller, &time, 2).await;
    }
    assert_eq!(
        ceiling_of(&controller),
        1,
        "without an interval there is no recovery, however long the quiet lasts"
    );
}

#[tokio::test]
async fn an_opted_in_ceiling_recovers_one_slot_per_interval_and_no_faster() {
    let time = TestTime::new();
    let interval = Duration::from_secs(600);
    let controller = recovering(&time, interval);

    refuse(&controller).await;
    assert_eq!(ceiling_of(&controller), 1, "the refusal still ratchets");

    // A baseline, then a clean probe, with no interval elapsed.
    probes(&controller, &time, 4).await;
    assert_eq!(
        ceiling_of(&controller),
        1,
        "recovery is not immediate: the interval has not passed"
    );

    time.advance(interval);
    probes(&controller, &time, 2).await;
    assert_eq!(ceiling_of(&controller), 2, "one interval buys one slot");

    // A second clean probe straight afterwards buys nothing: the interval runs
    // from the last move, not from the last refusal.
    probes(&controller, &time, 2).await;
    assert_eq!(
        ceiling_of(&controller),
        2,
        "one slot per interval, not one per probe after the first interval"
    );

    time.advance(interval);
    probes(&controller, &time, 2).await;
    assert_eq!(ceiling_of(&controller), 3);
}

#[tokio::test]
async fn a_recovering_ceiling_stops_at_the_configured_maximum() {
    let time = TestTime::new();
    let interval = Duration::from_secs(600);
    let controller = recovering(&time, interval);

    refuse(&controller).await;
    for _ in 0..20 {
        time.advance(interval);
        probes(&controller, &time, 2).await;
    }

    assert_eq!(
        ceiling_of(&controller),
        4,
        "a recovered ceiling is still bounded by the configured maximum"
    );
}

#[tokio::test]
async fn a_recovered_ceiling_is_permission_to_try_rather_than_slots_to_spend() {
    let time = TestTime::new();
    let interval = Duration::from_secs(600);
    let controller = recovering(&time, interval);

    refuse(&controller).await;
    for _ in 0..20 {
        time.advance(interval);
        probes(&controller, &time, 2).await;
    }

    let seen = controller
        .snapshot(&authority())
        .expect("the origin has been seen");
    assert_eq!(seen.ceiling, 4);
    assert_eq!(
        seen.limit, 1,
        "the limit still has to earn every slot back through the increase rule, \
         and a caller that never fills its slots earns none"
    );
}

#[tokio::test]
async fn a_second_refusal_ratchets_a_recovering_ceiling_down_again() {
    let time = TestTime::new();
    let interval = Duration::from_secs(600);
    let controller = AdaptiveConcurrency::with_config(
        ConcurrencyConfig { min: 2, ..quick() },
        Ceiling::Unlimited,
    )
    .with_time_source(time.source())
    .with_ceiling_recovery(interval);

    refuse(&controller).await;
    assert_eq!(ceiling_of(&controller), 2, "the floor is the floor");

    for _ in 0..3 {
        time.advance(interval);
        probes(&controller, &time, 2).await;
    }
    assert_eq!(ceiling_of(&controller), 4, "it climbed back");

    time.advance(Duration::from_secs(3600));
    refuse(&controller).await;
    assert_eq!(
        ceiling_of(&controller),
        2,
        "and a fresh refusal is still a fresh lesson"
    );
}

#[tokio::test]
async fn the_two_builders_compose_in_either_order() {
    let time = TestTime::new();
    let interval = Duration::from_secs(42);

    let first = AdaptiveConcurrency::new(Ceiling::Unlimited)
        .with_time_source(time.source())
        .with_ceiling_recovery(interval);
    let second = AdaptiveConcurrency::new(Ceiling::Unlimited)
        .with_ceiling_recovery(interval)
        .with_time_source(time.source());

    assert_eq!(first.ceiling_recovery(), Some(interval));
    assert_eq!(
        second.ceiling_recovery(),
        Some(interval),
        "a clock installed after the interval must not throw the interval away"
    );

    // And both are still running on the test clock rather than the real one: a
    // permit against a paused origin waits exactly the recorded amount.
    for controller in [&first, &second] {
        let permit = controller.acquire(&url()).await;
        permit.complete(Signal::Backpressure {
            retry_after: Some(Duration::from_secs(120)),
        });
    }
    let before = time.sleeps().len();
    let permit = first.acquire(&url()).await;
    assert_eq!(&time.sleeps()[before..], &[Duration::from_secs(120)]);
    drop(permit);
}
