//! The adaptive concurrency controller, driven by hand.
//!
//! Every test here runs against an injectable clock and a local decision — no
//! socket, no origin, no sleeping. A controller that discovered its limits by
//! probing someone's production site is the thing this design exists to avoid,
//! and a test suite that did it would be worse, because it would do it on every
//! CI run.
//!
//! The clock below implements the crate's public [`Clock`] and [`Sleeper`]
//! traits rather than reaching for `crate::time::testing::ManualTime`, which is
//! `pub(crate)`. That it can be written from outside the crate at all is part of
//! what these tests check.

#![cfg(feature = "adaptive-concurrency")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chromulate_core::BoxFuture;
use chromulate_http::adaptive::{
    self, AdaptiveConcurrency, Ceiling, ConcurrencyConfig, OriginSnapshot, Permit, Signal,
    authority_of, retry_after_delay,
};
use chromulate_http::{Clock, RateLimit, RateLimiter, Sleeper, TimeSource};
use http::{HeaderMap, StatusCode};
use url::Url;

/// Polls a future exactly once.
///
/// `futures_util::poll!` would do this, but it lives behind that crate's
/// `async-await` feature and this workspace builds `futures-util` with default
/// features off. A no-op waker is enough here: the futures polled this way are
/// always awaited afterwards, and `tokio::sync::Notify` records the
/// notification on the `Notified` future itself rather than only in the waker,
/// so a wake that lands between the two is still seen.
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
    /// Records the request, moves the clock by exactly that much, and returns
    /// without yielding to a timer.
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

/// A configuration whose runs are short enough to write out by hand.
///
/// `probe: 2` and `clean_probes_before_increase: 2` mean a slot costs six
/// healthy responses rather than the default twenty-five: one probe to learn a
/// baseline and two clean ones after it.
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

fn controller(config: ConcurrencyConfig, time: &Arc<TestTime>) -> AdaptiveConcurrency {
    AdaptiveConcurrency::with_config(config, Ceiling::Unlimited).with_time_source(time.source())
}

fn snapshot(controller: &AdaptiveConcurrency) -> OriginSnapshot {
    controller
        .snapshot(&authority())
        .expect("the origin has been seen")
}

fn limit(controller: &AdaptiveConcurrency) -> usize {
    snapshot(controller).limit
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// Runs `count` healthy responses at `latency`, arranging for one of them to
/// queue for its slot.
///
/// The queue is not decoration: an increase needs evidence that the limit is
/// the binding constraint, and a caller that never fills its slots supplies
/// none. Filling every slot and then starting one more acquire is what a
/// concurrent caller does, expressed so a test can see the exact moment.
async fn healthy(
    controller: &AdaptiveConcurrency,
    time: &TestTime,
    count: usize,
    latency: Duration,
) {
    let url = url();
    let current = controller
        .snapshot(&authority())
        .map_or(1, |seen| seen.limit);
    assert!(
        count > current,
        "a run of {count} cannot fill and queue behind {current} slots"
    );

    let mut held: Vec<Permit> = Vec::with_capacity(current);
    for _ in 0..current {
        held.push(controller.acquire(&url).await);
    }

    let mut queued = Box::pin(controller.acquire(&url));
    assert!(
        poll_once(queued.as_mut()).is_pending(),
        "one more than the limit must queue"
    );

    time.advance(latency);
    for permit in held {
        permit.complete(Signal::Healthy);
    }

    let permit = queued.await;
    assert!(permit.waited_for_a_slot(), "that permit queued");
    time.advance(latency);
    permit.complete(Signal::Healthy);

    for _ in (current + 1)..count {
        let permit = controller.acquire(&url).await;
        time.advance(latency);
        permit.complete(Signal::Healthy);
    }
}

/// Runs `count` responses one at a time, so nothing ever queues.
async fn sequential(
    controller: &AdaptiveConcurrency,
    time: &TestTime,
    count: usize,
    latency: Duration,
    signal: Signal,
) {
    let url = url();
    for _ in 0..count {
        let permit = controller.acquire(&url).await;
        time.advance(latency);
        permit.complete(signal);
    }
}

/// One response carrying `status` and whatever headers it needs.
async fn respond(controller: &AdaptiveConcurrency, status: StatusCode, headers: &[(&str, &str)]) {
    let url = url();
    let permit = controller.acquire(&url).await;
    let mut response = http::Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(*name, *value);
    }
    let response = response.body(()).expect("a valid response");
    permit.complete(Signal::from_response(&response, SystemTime::UNIX_EPOCH));
}

// ---------------------------------------------------------------------------
// A new origin.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_new_origin_starts_at_the_minimum_with_no_baseline() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    let permit = controller.acquire(&url()).await;
    let seen = snapshot(&controller);

    assert_eq!(seen.limit, 1, "an unknown origin starts at the minimum");
    assert_eq!(seen.in_flight, 1);
    assert_eq!(seen.baseline, None, "nothing has been measured yet");
    assert_eq!(seen.ceiling, 4, "the ceiling starts at the configured max");
    permit.complete(Signal::Healthy);
}

#[tokio::test]
async fn the_first_probe_only_establishes_a_baseline_and_cannot_add_a_slot() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    // Exactly one probe: two healthy responses.
    healthy(&controller, &time, 2, ms(10)).await;

    let seen = snapshot(&controller);
    assert_eq!(seen.baseline, Some(ms(10)), "the probe set the baseline");
    assert_eq!(
        seen.limit, 1,
        "there was nothing to compare the first probe against"
    );
    assert_eq!(
        seen.clean_probes, 0,
        "a baseline probe is not a clean probe"
    );
}

// ---------------------------------------------------------------------------
// Increase.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_slot_is_added_only_after_the_full_run_of_clean_probes() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    healthy(&controller, &time, 2, ms(10)).await;
    assert_eq!(limit(&controller), 1, "baseline probe");

    healthy(&controller, &time, 2, ms(10)).await;
    assert_eq!(limit(&controller), 1, "one clean probe is not enough");

    healthy(&controller, &time, 2, ms(10)).await;
    assert_eq!(
        limit(&controller),
        2,
        "two clean probes buy exactly one slot"
    );
    assert_eq!(
        snapshot(&controller).clean_probes,
        0,
        "the run restarts after an increase"
    );
}

#[tokio::test]
async fn a_limit_nobody_queued_behind_is_never_increased() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    // Twenty healthy responses, none of them overlapping: ten probes, all of
    // them clean, and no evidence at all that another slot would be used.
    sequential(&controller, &time, 20, ms(10), Signal::Healthy).await;

    let seen = snapshot(&controller);
    assert_eq!(
        seen.limit, 1,
        "a caller that never fills its slots has not shown the limit binds"
    );
    assert_eq!(seen.baseline, Some(ms(10)), "latency was still measured");
}

#[tokio::test]
async fn the_limit_never_passes_the_configured_maximum() {
    let time = TestTime::new();
    let controller = controller(ConcurrencyConfig { max: 2, ..quick() }, &time);

    for _ in 0..12 {
        healthy(&controller, &time, 6, ms(10)).await;
    }

    assert_eq!(
        limit(&controller),
        2,
        "learning an origin tolerates more is not permission to send more"
    );
}

// ---------------------------------------------------------------------------
// Decrease on latency.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_probe_slower_than_the_baseline_halves_the_limit_at_once() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    // Up to four.
    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(limit(&controller), 4, "the ramp reached the maximum");
    let baseline = snapshot(&controller).baseline.expect("a baseline exists");

    // One probe at more than twice the baseline.
    sequential(&controller, &time, 2, baseline * 3, Signal::Healthy).await;

    let seen = snapshot(&controller);
    assert_eq!(seen.limit, 2, "degradation halves the limit immediately");
    assert_eq!(
        seen.ceiling, 4,
        "latency is transient: it must not lower the ceiling"
    );
}

#[tokio::test]
async fn a_probe_inside_the_band_is_not_a_degradation() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..3 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    let before = limit(&controller);
    assert!(before >= 2, "the ramp moved");

    // Slower, but inside the 2x band.
    sequential(&controller, &time, 2, ms(19), Signal::Healthy).await;

    assert_eq!(
        limit(&controller),
        before,
        "a probe under the degradation ratio is not a signal"
    );
}

#[tokio::test]
async fn a_near_instant_origin_is_not_read_as_degraded_by_noise() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    // Nothing moves the clock, so every response is instantaneous and the
    // baseline is zero. Twice zero is zero, so a ratio on its own would call
    // every later response in the world a degradation.
    for _ in 0..9 {
        healthy(&controller, &time, 6, Duration::ZERO).await;
    }
    assert_eq!(limit(&controller), 4, "an instant origin ramps");
    assert_eq!(snapshot(&controller).baseline, Some(Duration::ZERO));

    // Three milliseconds of movement above a zero baseline is scheduler noise.
    sequential(&controller, &time, 2, ms(3), Signal::Healthy).await;
    assert_eq!(
        limit(&controller),
        4,
        "microsecond noise is not congestion and must not halve anything"
    );

    // Fifty is not noise.
    sequential(&controller, &time, 2, ms(50), Signal::Healthy).await;
    assert_eq!(
        limit(&controller),
        2,
        "a real change above the floor is still a signal"
    );
}

#[tokio::test]
async fn recovery_takes_longer_than_the_decrease_and_waits_out_the_hold() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(limit(&controller), 4);

    // One bad probe undoes three good runs.
    sequential(&controller, &time, 2, ms(60), Signal::Healthy).await;
    assert_eq!(limit(&controller), 2, "one probe, one halving");

    // Clean probes during the hold do not buy the slot back.
    for _ in 0..3 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(
        limit(&controller),
        2,
        "the hold after a decrease outranks the evidence"
    );

    time.advance(Duration::from_secs(31));
    healthy(&controller, &time, 6, ms(10)).await;
    assert_eq!(
        limit(&controller),
        3,
        "and recovery is one slot at a time, not one halving at a time"
    );
}

#[tokio::test]
async fn a_permanently_slower_origin_is_relearned_rather_than_cut_forever() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..6 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    let before = limit(&controller);
    assert!(before >= 3, "the ramp moved: {before}");

    // The origin is simply slower now, and stays there.
    for _ in 0..40 {
        time.advance(Duration::from_secs(31));
        sequential(&controller, &time, 2, ms(25), Signal::Healthy).await;
    }

    let seen = snapshot(&controller);
    assert!(
        seen.baseline.is_some_and(|base| base >= ms(24)),
        "the baseline must drift up to the new normal, not sit at the old one: {:?}",
        seen.baseline
    );
    assert!(
        seen.limit >= 1,
        "a slower origin must not be driven below the floor"
    );
}

// ---------------------------------------------------------------------------
// Refusals: 429 and 503.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_429_lowers_the_origin_ceiling_permanently_rather_than_climbing_back_to_it() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(limit(&controller), 4, "the ramp reached four");

    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;

    let after = snapshot(&controller);
    assert_eq!(after.ceiling, 2, "half the level that earned the refusal");
    assert_eq!(after.limit, 2, "and the limit comes down to it at once");
    assert_eq!(
        after.baseline, None,
        "what was normal at four slots is not the measurement to hold two against"
    );

    // Whatever happens next, four is a level this origin has refused.
    for _ in 0..30 {
        time.advance(Duration::from_secs(60));
        healthy(&controller, &time, 6, ms(10)).await;
        let seen = snapshot(&controller);
        assert!(
            seen.limit <= 2,
            "the controller climbed back to a refused level: {seen:?}"
        );
        assert_eq!(seen.ceiling, 2, "the lesson is permanent");
    }
}

#[tokio::test]
async fn a_503_is_treated_as_the_same_lesson_as_a_429() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(limit(&controller), 4);

    respond(&controller, StatusCode::SERVICE_UNAVAILABLE, &[]).await;

    let seen = snapshot(&controller);
    assert_eq!(
        seen.ceiling, 2,
        "a client cannot tell which of the two an origin says slow down with"
    );
}

#[tokio::test]
async fn a_second_refusal_ratchets_the_ceiling_down_again_and_never_up() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }

    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(snapshot(&controller).ceiling, 2);

    time.advance(Duration::from_secs(600));
    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(snapshot(&controller).ceiling, 1, "it only ever falls");

    time.advance(Duration::from_secs(600));
    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(
        snapshot(&controller).ceiling,
        1,
        "and it stops at the configured floor"
    );
}

// ---------------------------------------------------------------------------
// Retry-After, in both forms, and absurd in each.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_retry_after_in_seconds_is_obeyed_exactly() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[("retry-after", "120")],
    )
    .await;

    let seen = snapshot(&controller);
    assert_eq!(seen.retry_after_requested, Some(Duration::from_secs(120)));
    assert_eq!(seen.paused_for, Some(Duration::from_secs(120)));

    // The next permit waits precisely that long, and no cooldown is invented on
    // top of what the origin asked for.
    let before = time.sleeps().len();
    let permit = controller.acquire(&url()).await;
    assert_eq!(
        &time.sleeps()[before..],
        &[Duration::from_secs(120)],
        "exactly what the origin asked for"
    );
    drop(permit);
}

#[tokio::test]
async fn a_retry_after_as_an_http_date_is_obeyed_exactly() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("retry-after", "Sun, 06 Nov 1994 08:59:37 GMT"),
        ],
    )
    .await;

    let seen = snapshot(&controller);
    assert_eq!(
        seen.retry_after_requested,
        Some(Duration::from_secs(600)),
        "ten minutes, measured entirely in the server's own clock"
    );
    assert_eq!(seen.paused_for, Some(Duration::from_secs(600)));
}

#[tokio::test]
async fn an_absurd_retry_after_in_seconds_is_clamped_rather_than_overflowing() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[("retry-after", "18446744073709551615")],
    )
    .await;

    let seen = snapshot(&controller);
    assert_eq!(
        seen.retry_after_requested,
        Some(Duration::from_secs(u64::MAX)),
        "what was asked for is reported verbatim"
    );
    assert_eq!(
        seen.paused_for,
        Some(Duration::from_secs(3600)),
        "and what is waited for is the configured ceiling"
    );

    let before = time.sleeps().len();
    let permit = controller.acquire(&url()).await;
    assert_eq!(&time.sleeps()[before..], &[Duration::from_secs(3600)]);
    drop(permit);
}

#[tokio::test]
async fn an_absurd_retry_after_date_is_clamped_rather_than_overflowing() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[
            ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ("retry-after", "Fri, 31 Dec 9999 23:59:59 GMT"),
        ],
    )
    .await;

    let seen = snapshot(&controller);
    assert!(
        seen.retry_after_requested
            .is_some_and(|asked| asked > Duration::from_secs(250_000_000_000)),
        "eight thousand years is what was asked for"
    );
    assert_eq!(
        seen.paused_for,
        Some(Duration::from_secs(3600)),
        "and an hour is what is waited"
    );
}

#[tokio::test]
async fn a_retry_after_date_already_in_the_past_pauses_for_nothing() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("retry-after", "Sun, 06 Nov 1994 08:39:37 GMT"),
        ],
    )
    .await;

    let seen = snapshot(&controller);
    assert_eq!(seen.retry_after_requested, Some(Duration::ZERO));
    assert_eq!(seen.paused_for, None, "a past date is not a pause");
    assert_eq!(seen.ceiling, 1, "the lesson still lands");
}

#[tokio::test]
async fn a_refusal_without_a_retry_after_backs_off_multiplicatively() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(
        snapshot(&controller).paused_for,
        Some(Duration::from_secs(5))
    );

    time.advance(Duration::from_secs(5));
    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(
        snapshot(&controller).paused_for,
        Some(Duration::from_secs(10)),
        "the second costs twice the first"
    );

    time.advance(Duration::from_secs(10));
    respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    assert_eq!(
        snapshot(&controller).paused_for,
        Some(Duration::from_secs(20))
    );
}

#[tokio::test]
async fn the_multiplicative_backoff_stops_at_its_ceiling() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(20),
            ..quick()
        },
        &time,
    );

    for _ in 0..40 {
        time.advance(Duration::from_secs(3600));
        respond(&controller, StatusCode::TOO_MANY_REQUESTS, &[]).await;
    }

    assert_eq!(
        snapshot(&controller).paused_for,
        Some(Duration::from_secs(20)),
        "doubling forty times must not run away"
    );
}

#[tokio::test]
async fn retry_after_reads_both_forms_and_neither_of_them_wrongly() {
    let mut headers = HeaderMap::new();
    assert_eq!(retry_after_delay(&headers, SystemTime::UNIX_EPOCH), None);

    headers.insert("retry-after", "30".parse().expect("a valid value"));
    assert_eq!(
        retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(30))
    );

    headers.insert("retry-after", "  30  ".parse().expect("a valid value"));
    assert_eq!(
        retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(30)),
        "surrounding whitespace is not part of the number"
    );

    headers.insert("retry-after", "later".parse().expect("a valid value"));
    assert_eq!(
        retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
        None,
        "a value that is neither form is no instruction, not a zero-length one"
    );

    headers.insert("retry-after", "-5".parse().expect("a valid value"));
    assert_eq!(
        retry_after_delay(&headers, SystemTime::UNIX_EPOCH),
        None,
        "a negative delta is not a delta"
    );

    // The date form against the client's clock, when the response sent no Date.
    let mut headers = HeaderMap::new();
    headers.insert(
        "retry-after",
        "Sun, 06 Nov 1994 08:49:37 GMT"
            .parse()
            .expect("a valid value"),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_177);
    assert_eq!(
        retry_after_delay(&headers, now),
        Some(Duration::from_secs(600))
    );
}

// ---------------------------------------------------------------------------
// Answers that are neither health nor backpressure.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_server_error_is_neither_a_latency_sample_nor_backpressure() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        assert_eq!(
            Signal::from_status(status),
            Signal::Neutral,
            "{status} is an answer, but a fast failure is not a latency worth learning"
        );
    }

    // Establish a baseline of ten milliseconds, then serve a burst of instant
    // 500s. If those counted as healthy samples the baseline would collapse
    // towards zero and every real response afterwards would read as degraded.
    healthy(&controller, &time, 6, ms(10)).await;
    let baseline = snapshot(&controller).baseline;
    assert_eq!(baseline, Some(ms(10)));

    sequential(&controller, &time, 10, Duration::ZERO, Signal::Neutral).await;

    let seen = snapshot(&controller);
    assert_eq!(seen.baseline, baseline, "a 500 must not move the baseline");
    assert_eq!(seen.ceiling, 4, "and it is not backpressure either");
    assert_eq!(seen.paused_for, None);
}

#[tokio::test]
async fn an_answer_that_is_not_evidence_of_health_breaks_the_run() {
    for interruption in [Signal::Neutral, Signal::Failed] {
        let time = TestTime::new();
        let controller = controller(quick(), &time);

        // A baseline, then one clean probe: one more would buy a slot.
        healthy(&controller, &time, 4, ms(10)).await;
        let before = limit(&controller);

        // Two of those in the middle of the run.
        sequential(&controller, &time, 2, ms(10), interruption).await;

        // And the probe that would have completed the run.
        sequential(&controller, &time, 2, ms(10), Signal::Healthy).await;
        assert_eq!(
            limit(&controller),
            before,
            "{interruption:?} in the middle of a run must not leave it intact"
        );
    }
}

// ---------------------------------------------------------------------------
// 403 is not backpressure.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_403_is_not_treated_as_backpressure() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    for _ in 0..9 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(limit(&controller), 4);

    respond(
        &controller,
        StatusCode::FORBIDDEN,
        &[("retry-after", "120")],
    )
    .await;

    let seen = snapshot(&controller);
    assert!(seen.refused, "the refusal is surfaced");
    assert_eq!(
        seen.limit, 4,
        "a refusal is not a rate signal: nothing halves"
    );
    assert_eq!(seen.ceiling, 4, "and nothing ratchets");
    assert_eq!(
        seen.paused_for, None,
        "backing off into a 403 would be tuning around a refusal"
    );
    assert_eq!(
        seen.refusals, 0,
        "a 403 is not counted as one of the rate refusals"
    );

    // And the next request is not delayed, retried, or altered by this module.
    let before = time.sleeps().len();
    let permit = controller.acquire(&url()).await;
    assert_eq!(
        time.sleeps().len(),
        before,
        "nothing waits, because nothing is being tuned around"
    );
    drop(permit);
}

#[tokio::test]
async fn a_403_freezes_the_limit_where_it_stands() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    healthy(&controller, &time, 6, ms(10)).await;
    let frozen = limit(&controller);

    respond(&controller, StatusCode::FORBIDDEN, &[]).await;

    for _ in 0..20 {
        healthy(&controller, &time, 6, ms(10)).await;
    }
    assert_eq!(
        limit(&controller),
        frozen,
        "an origin that refused must not be ramped against"
    );
    assert!(snapshot(&controller).refused);
}

#[tokio::test]
async fn forgetting_an_origin_is_how_a_caller_clears_a_refusal() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);

    respond(&controller, StatusCode::FORBIDDEN, &[]).await;
    assert!(snapshot(&controller).refused);

    assert!(controller.forget(&authority()));
    assert!(!controller.forget(&authority()), "and only once");
    assert!(controller.snapshot(&authority()).is_none());
}

// ---------------------------------------------------------------------------
// The caller's rate limit is a ceiling, not a suggestion.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_callers_rate_limit_is_never_exceeded_however_much_the_controller_learns() {
    let time = TestTime::new();
    let limiter = Arc::new(RateLimiter::with_time_source(
        RateLimit::per_second(10.0).with_burst(1.0),
        time.source(),
    ));
    // Pinned at four slots, which is the most this configuration could ever
    // learn. Whatever the controller had discovered, this is the state it would
    // have discovered it into, and the question is whether four slots let a
    // caller outrun a limit of ten per second. They do not, and cannot: the
    // slot is granted after the token is spent, never instead of it.
    let controller = AdaptiveConcurrency::with_config(
        ConcurrencyConfig {
            min: 4,
            max: 4,
            ..quick()
        },
        Ceiling::RateLimit(Arc::clone(&limiter)),
    )
    .with_time_source(time.source());

    let url = url();
    let mut permits = 0usize;
    for _ in 0..10 {
        // Four in flight at once, which is the whole point of the controller.
        let mut held: Vec<Permit> = Vec::new();
        for _ in 0..4 {
            held.push(controller.acquire(&url).await);
            permits += 1;
        }
        assert_eq!(snapshot(&controller).in_flight, 4, "four really were open");
        for permit in held {
            permit.complete(Signal::Healthy);
        }
    }

    assert_eq!(limit(&controller), 4, "and it stayed at four throughout");

    let sleeps = time.sleeps();
    assert_eq!(
        sleeps.len(),
        permits - 1,
        "every permit but the first had to wait for a token"
    );
    assert!(
        sleeps.iter().all(|wait| *wait == ms(100)),
        "at ten per second each one waits a tenth of a second: {sleeps:?}"
    );
}

#[tokio::test]
async fn a_rate_limited_caller_is_never_shown_the_saturation_an_increase_needs() {
    let time = TestTime::new();
    let limiter = Arc::new(RateLimiter::with_time_source(
        RateLimit::per_second(4.0).with_burst(1.0),
        time.source(),
    ));
    let controller = AdaptiveConcurrency::with_config(quick(), Ceiling::RateLimit(limiter))
        .with_time_source(time.source());

    // A caller issuing one at a time under a rate limit. The limiter is the
    // binding constraint, so nothing ever queues for a *slot*, so the evidence
    // condition five asks for is never produced. The controller has no way to
    // discover it could go faster, because going faster was never its call.
    let url = url();
    for _ in 0..60 {
        let permit = controller.acquire(&url).await;
        assert!(
            !permit.waited_for_a_slot(),
            "the limiter was the constraint, not the limit"
        );
        permit.complete(Signal::Healthy);
    }

    assert_eq!(
        limit(&controller),
        1,
        "the controller must not climb past what the caller's rate allows"
    );
}

#[tokio::test]
async fn a_permit_cannot_be_issued_without_paying_the_ceiling_first() {
    let time = TestTime::new();
    let limiter = Arc::new(RateLimiter::with_time_source(
        RateLimit::per_second(2.0).with_burst(1.0),
        time.source(),
    ));
    let controller = AdaptiveConcurrency::with_config(quick(), Ceiling::RateLimit(limiter))
        .with_time_source(time.source());

    let url = url();
    for _ in 0..5 {
        let permit = controller.acquire(&url).await;
        permit.complete(Signal::Healthy);
    }

    assert_eq!(
        time.sleeps(),
        vec![ms(500), ms(500), ms(500), ms(500)],
        "at two per second, four of the five waited half a second"
    );
}

// ---------------------------------------------------------------------------
// Slots, and what happens to them.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_slot_is_not_granted_while_every_slot_is_busy() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);
    let url = url();

    let held = controller.acquire(&url).await;
    let mut queued = Box::pin(controller.acquire(&url));
    assert!(poll_once(queued.as_mut()).is_pending(), "the limit is one");

    held.complete(Signal::Healthy);
    let second = queued.await;
    assert!(second.waited_for_a_slot());
    assert_eq!(snapshot(&controller).in_flight, 1);
}

#[tokio::test]
async fn the_engine_wiring_is_the_same_two_lines_with_or_without_a_controller() {
    let time = TestTime::new();
    let installed = controller(quick(), &time);
    let url = url();

    // With a controller: a slot is taken and the response is reported.
    let permit = adaptive::acquire_from(Some(&installed), &url).await;
    assert!(permit.is_some());
    assert_eq!(snapshot(&installed).in_flight, 1);

    let response = http::Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("retry-after", "30")
        .body(())
        .expect("a valid response");
    adaptive::complete_from(permit, &response);

    let seen = snapshot(&installed);
    assert_eq!(seen.in_flight, 0);
    assert_eq!(
        seen.retry_after_requested,
        Some(Duration::from_secs(30)),
        "the header is read through the wiring helper too"
    );

    // Without one: the same two lines, and nothing happens.
    let permit = adaptive::acquire_from(None, &url).await;
    assert!(permit.is_none());
    adaptive::complete_from(permit, &response);
}

#[tokio::test]
async fn a_permit_dropped_without_a_report_still_returns_its_slot() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);
    let url = url();

    let permit = controller.acquire(&url).await;
    assert_eq!(snapshot(&controller).in_flight, 1);
    drop(permit);

    let seen = snapshot(&controller);
    assert_eq!(
        seen.in_flight, 0,
        "a cancelled request must not leak a slot"
    );
    assert_eq!(
        seen.baseline, None,
        "and it must not teach a latency nobody observed"
    );

    // The slot really is available again.
    let permit = controller.acquire(&url).await;
    assert!(!permit.waited_for_a_slot());
}

// ---------------------------------------------------------------------------
// Bounded state.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_origin_store_stays_inside_its_capacity() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            capacity: 32,
            ..quick()
        },
        &time,
    );

    for index in 0..1_000u32 {
        let url = Url::parse(&format!("https://host-{index}.test/")).expect("a valid url");
        let permit = controller.acquire(&url).await;
        permit.complete(Signal::Healthy);
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
}

#[tokio::test]
async fn eviction_keeps_what_the_controller_has_learned_a_lesson_from() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            capacity: 16,
            ..quick()
        },
        &time,
    );

    // One origin refuses, and is then never touched again.
    let taught = Url::parse("https://taught.test/").expect("a valid url");
    let permit = controller.acquire(&taught).await;
    permit.complete(Signal::Backpressure { retry_after: None });
    let learned = controller
        .snapshot(authority_of(&taught))
        .expect("the lesson landed");
    assert!(learned.ceiling < 4, "there is a lesson to keep");

    // Churn far past the capacity with origins that teach nothing.
    for index in 0..500u32 {
        let url = Url::parse(&format!("https://noise-{index}.test/")).expect("a valid url");
        let permit = controller.acquire(&url).await;
        permit.complete(Signal::Healthy);
    }

    assert!(controller.len() <= 16);
    assert_eq!(
        controller
            .snapshot(authority_of(&taught))
            .map(|seen| seen.ceiling),
        Some(learned.ceiling),
        "an origin that refused must outlive the ones that did not"
    );
}

#[tokio::test]
async fn a_purge_never_evicts_the_entry_that_triggered_it() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            capacity: 8,
            ..quick()
        },
        &time,
    );

    // Fill the store to capacity with origins that have all refused, so every
    // one of them outranks a newcomer on the "has taught us something" half of
    // the eviction key. A newcomer is then the most evictable entry in the
    // store — including, without the protection, the newcomer that caused the
    // purge, which would be forgotten before its own permit was granted.
    for index in 0..8u32 {
        let url = Url::parse(&format!("https://taught-{index}.test/")).expect("a valid url");
        let permit = controller.acquire(&url).await;
        permit.complete(Signal::Backpressure { retry_after: None });
    }
    assert_eq!(controller.len(), 8, "the store is exactly full");

    let newcomer = Url::parse("https://newcomer.test/").expect("a valid url");
    let permit = controller.acquire(&newcomer).await;

    assert!(
        controller.snapshot(authority_of(&newcomer)).is_some(),
        "the entry a purge was triggered by must survive the purge"
    );
    assert!(controller.len() <= 8);
    permit.complete(Signal::Healthy);
}

#[tokio::test]
async fn an_origin_with_a_request_in_flight_is_not_evicted_from_under_it() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            capacity: 8,
            ..quick()
        },
        &time,
    );

    let busy = Url::parse("https://busy.test/").expect("a valid url");
    let permit = controller.acquire(&busy).await;

    for index in 0..200u32 {
        let url = Url::parse(&format!("https://noise-{index}.test/")).expect("a valid url");
        let held = controller.acquire(&url).await;
        held.complete(Signal::Healthy);
    }

    let seen = controller
        .snapshot(authority_of(&busy))
        .expect("an origin holding a slot is still there");
    assert_eq!(seen.in_flight, 1, "and its count is intact");
    permit.complete(Signal::Healthy);
}

// ---------------------------------------------------------------------------
// Configuration that is not a configuration.
// ---------------------------------------------------------------------------

#[test]
fn a_configuration_that_cannot_be_used_is_clamped_rather_than_panicking() {
    let sane = ConcurrencyConfig {
        min: 0,
        max: 0,
        probe: 0,
        clean_probes_before_increase: 0,
        degradation: f64::NAN,
        capacity: 0,
        ..ConcurrencyConfig::default()
    }
    .sanitised();

    assert_eq!(sane.min, 1, "a floor of zero grants no permits at all");
    assert_eq!(
        sane.max, 1,
        "and a ceiling below the floor is not a ceiling"
    );
    assert_eq!(sane.probe, 1);
    assert_eq!(sane.clean_probes_before_increase, 1);
    assert_eq!(sane.degradation, 2.0);
    assert_eq!(
        sane.capacity, 1,
        "a store that cannot hold what it was handed is a disabled feature"
    );

    for degradation in [f64::INFINITY, f64::NEG_INFINITY, 0.0, -1.0, 1.0] {
        let sane = ConcurrencyConfig {
            degradation,
            ..ConcurrencyConfig::default()
        }
        .sanitised();
        assert!(
            sane.degradation > 1.0,
            "a ratio of {degradation} makes every probe degraded"
        );
    }

    // A pause this process is not willing to wait for is not a pause it may
    // silently drop: `Instant::checked_add` returns `None` past the end of the
    // representable range, and an unclamped `Duration::MAX` would land there.
    assert_eq!(
        ConcurrencyConfig {
            max_pause: Duration::MAX,
            ..ConcurrencyConfig::default()
        }
        .sanitised()
        .max_pause,
        Duration::from_secs(86_400),
    );
}

#[tokio::test]
async fn a_max_pause_that_cannot_be_added_to_an_instant_still_pauses() {
    let time = TestTime::new();
    let controller = controller(
        ConcurrencyConfig {
            max_pause: Duration::MAX,
            ..quick()
        },
        &time,
    );

    respond(
        &controller,
        StatusCode::TOO_MANY_REQUESTS,
        &[("retry-after", "18446744073709551615")],
    )
    .await;

    assert_eq!(
        snapshot(&controller).paused_for,
        Some(Duration::from_secs(86_400)),
        "an unrepresentable pause must become the longest representable one, \
         not none at all"
    );
}

#[tokio::test]
async fn a_degradation_ratio_large_enough_to_overflow_a_duration_does_not_panic() {
    let time = TestTime::new();
    // Finite and greater than one, so it passes every check `sanitised` makes,
    // and large enough that `baseline * ratio` leaves what a `Duration` holds.
    let controller = controller(
        ConcurrencyConfig {
            degradation: 1e308,
            ..quick()
        },
        &time,
    );

    sequential(&controller, &time, 20, ms(10), Signal::Healthy).await;

    let seen = snapshot(&controller);
    assert_eq!(
        seen.limit, 1,
        "a threshold that nothing can exceed means nothing is ever degraded"
    );
    assert!(seen.baseline.is_some());
}

#[tokio::test]
async fn a_latency_no_clock_should_produce_does_not_overflow_the_baseline() {
    let time = TestTime::new();
    let controller = controller(quick(), &time);
    let url = url();

    // A clock that jumped a century between the acquire and the report.
    let permit = controller.acquire(&url).await;
    time.advance(Duration::from_secs(3_155_760_000));
    permit.complete(Signal::Healthy);

    let permit = controller.acquire(&url).await;
    time.advance(Duration::from_secs(3_155_760_000));
    permit.complete(Signal::Healthy);

    let seen = snapshot(&controller);
    assert!(seen.baseline.is_some(), "it recorded something finite");
    assert_eq!(seen.limit, 1);
}

#[test]
fn the_authority_is_the_server_address_and_carries_no_credentials() {
    let plain = Url::parse("https://example.com/a?b=c").expect("a valid url");
    assert_eq!(authority_of(&plain), "example.com");

    let credentialed = Url::parse("https://user:secret@example.com/a").expect("a valid url");
    assert_eq!(
        authority_of(&credentialed),
        "example.com",
        "a password must never reach a map key or a log line"
    );

    let ported = Url::parse("https://example.com:8443/").expect("a valid url");
    assert_eq!(authority_of(&ported), "example.com:8443");

    let default_port = Url::parse("https://example.com:443/").expect("a valid url");
    assert_eq!(
        authority_of(&default_port),
        "example.com",
        "the default port is the same server"
    );

    let http = Url::parse("http://example.com/").expect("a valid url");
    assert_eq!(
        authority_of(&http),
        authority_of(&plain),
        "one machine, one budget, whatever the scheme"
    );
}
