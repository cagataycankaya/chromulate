//! A token-bucket rate limiter.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chromulate_core::{BoxFuture, Error, Middleware, Next, Request, Response, Result};

use crate::time::TimeSource;

/// How fast a bucket refills and how much it may bank.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    /// Requests allowed per second, on average.
    pub per_second: f64,
    /// The most requests that may be spent at once after an idle period.
    ///
    /// A burst of one is a strict metronome. Anything larger lets a client that
    /// has been quiet catch up, which is what makes a limiter usable for a
    /// crawler that alternates between bursts of fetches and long parses.
    pub burst: f64,
}

impl RateLimit {
    /// A limit of `per_second` requests per second, allowing a burst of one
    /// second's worth.
    ///
    /// # Panics
    ///
    /// Panics if `per_second` is not a positive, finite number.
    #[must_use]
    pub fn per_second(per_second: f64) -> Self {
        assert!(
            per_second.is_finite() && per_second > 0.0,
            "a rate limit must be a positive, finite number of requests per second"
        );
        Self {
            per_second,
            burst: per_second.max(1.0),
        }
    }

    /// Sets how much the bucket may bank.
    #[must_use]
    pub fn with_burst(mut self, burst: f64) -> Self {
        self.burst = burst.max(1.0);
        self
    }
}

/// The bucket's state, kept together so one lock covers a whole decision.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Delays requests so they do not exceed a configured rate.
///
/// The bucket is shared by every request through this middleware, so a limit
/// applies to the client as a whole rather than per call site.
pub struct RateLimiter {
    limit: RateLimit,
    bucket: Mutex<Bucket>,
    time: TimeSource,
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limit", &self.limit)
            .field("tokens", &self.tokens())
            .finish_non_exhaustive()
    }
}

/// The longest wait a limiter will report.
///
/// Reached only when a rate is so small that the honest answer overflows a
/// `Duration`. An hour is long enough that a caller notices it is rate limited
/// and short enough that the number stays printable.
const MAX_WAIT: Duration = Duration::from_secs(3600);

/// Replaces a rate that cannot describe a rate.
///
/// Zero, negative, subnormal and non-finite values all arrive through
/// [`RateLimit`]'s public fields. Clamping rather than panicking is the right
/// answer for a client library: a misconfigured limiter that runs slowly is a
/// bug the caller can see and fix, and a panic is one that takes their process
/// with it.
fn sanitise(limit: RateLimit) -> RateLimit {
    /// What a rate that is not a rate becomes: one request per hour.
    ///
    /// Chosen to be comprehensible rather than merely safe. Clamping to
    /// something like `1e-5` is equally panic-free and puts twenty-seven hours
    /// between requests, which reads as a hang; an hour is slow enough that a
    /// caller who wrote `per_second: 0.0` notices immediately, and short enough
    /// that what they see is a rate limit rather than a stall.
    const SLOWEST: f64 = 1.0 / 3600.0;

    RateLimit {
        per_second: if limit.per_second.is_finite() && limit.per_second >= SLOWEST {
            limit.per_second
        } else {
            SLOWEST
        },
        burst: if limit.burst.is_finite() && limit.burst >= 0.0 {
            limit.burst
        } else {
            0.0
        },
    }
}

impl RateLimiter {
    /// A limiter that starts with a full bucket.
    ///
    /// Starting full rather than empty means the first request is not delayed,
    /// which matches what a caller expects from a fresh client.
    #[must_use]
    pub fn new(limit: RateLimit) -> Self {
        Self::with_time_source(limit, TimeSource::system())
    }

    /// A limiter running against a specific clock.
    ///
    /// The limit is sanitised here rather than trusted. [`RateLimit`]'s fields
    /// are public, so `RateLimit { per_second: 0.0, burst: 1.0 }` reaches this
    /// point without ever passing the assertion in [`RateLimit::per_second`] —
    /// and a zero or subnormal rate makes the wait computation in
    /// [`RateLimiter::reserve`] divide by something that is not a rate. This is
    /// the one funnel every limit passes through, which is why the check lives
    /// here and not at each use.
    #[must_use]
    pub fn with_time_source(limit: RateLimit, time: TimeSource) -> Self {
        let now = time.now();
        let limit = sanitise(limit);
        Self {
            bucket: Mutex::new(Bucket {
                tokens: limit.burst,
                last_refill: now,
            }),
            limit,
            time,
        }
    }

    /// The limit in force.
    #[must_use]
    pub fn limit(&self) -> RateLimit {
        self.limit
    }

    /// Tokens currently available, for tests and diagnostics.
    #[must_use]
    pub fn tokens(&self) -> f64 {
        self.lock().tokens
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Bucket> {
        self.bucket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Spends one token, returning how long the caller must wait first.
    ///
    /// The whole decision — refill, check, spend — happens inside one critical
    /// section with no `await` in it, so two concurrent callers can never both
    /// see the same last token.
    #[must_use]
    pub fn reserve(&self) -> Duration {
        let now = self.time.now();
        let mut bucket = self.lock();

        let elapsed = now.saturating_duration_since(bucket.last_refill);
        bucket.tokens =
            (bucket.tokens + elapsed.as_secs_f64() * self.limit.per_second).min(self.limit.burst);
        bucket.last_refill = now;

        // The token is spent whether or not it existed yet. A caller that has
        // to wait has already reserved its place, so a later caller queues
        // behind it instead of overtaking — the debt is what keeps the average
        // rate correct under concurrency.
        bucket.tokens -= 1.0;

        if bucket.tokens >= 0.0 {
            return Duration::ZERO;
        }

        // The total conversion rather than `Duration::from_secs_f64`, which
        // panics on a negative, infinite or out-of-range value.
        //
        // No input reaches it today: `sanitise` keeps the rate finite and at
        // least `1/3600`, and the debt would have to pass -5e15 tokens to
        // overflow a `Duration` at that rate. Mutating this line back does not
        // turn any test red, and the honest reading of that is "unreachable",
        // not "guarded". It stays because the partial function's failure mode
        // is a panic in a library, and because it is the line that stops
        // mattering the moment someone widens `sanitise` — which is precisely
        // when nobody will be looking here.
        let seconds = -bucket.tokens / self.limit.per_second;
        Duration::try_from_secs_f64(seconds).unwrap_or(MAX_WAIT)
    }
}

impl Middleware for RateLimiter {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    fn handle<'a>(&'a self, request: Request, next: Next<'a>) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move {
            let wait = self.reserve();
            if !wait.is_zero() {
                tracing::trace!(
                    wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "rate limited"
                );
                self.time.sleep(wait).await;
            }
            next.run(request).await
        })
    }
}

/// Builds an [`Error::Middleware`] attributed to a named middleware.
///
/// Exposed because a third-party middleware in this chain should report
/// failures the same way the built-in ones do.
#[must_use]
pub fn middleware_error(name: &'static str, source: impl Into<chromulate_core::BoxError>) -> Error {
    Error::Middleware {
        name,
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rates that reach a limiter without passing `RateLimit::per_second`'s
    /// assertion, because the fields are public and a struct literal skips it.
    /// Every one of them used to panic inside `Duration::from_secs_f64` — a
    /// client library taking a caller's process down over its configuration.
    const NOT_A_RATE: [f64; 6] = [
        0.0,
        -1.0,
        1e-300,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];

    #[test]
    fn a_rate_that_cannot_describe_a_rate_does_not_panic() {
        for per_second in NOT_A_RATE {
            let time = ManualTime::new();
            let limiter = raw_limiter(per_second, 1.0, &time);
            // Two reserves: the first spends the burst, the second is the one
            // that has to compute a wait and divide by the rate.
            let _ = limiter.reserve();
            let wait = limiter.reserve();
            assert!(
                wait <= MAX_WAIT,
                "per_second={per_second} produced a wait of {wait:?}"
            );
        }
    }

    /// The guard in `reserve` alone makes the panic go away, so it alone is not
    /// enough: without `sanitise`, a rate of `0.0` survives into the refill on
    /// line one of `reserve` and adds `elapsed * 0.0` tokens forever. The bucket
    /// never recovers, and the limiter reports its ceiling wait until the
    /// process ends. Clamping the rate is what makes the recovery below happen,
    /// which is why this test — not the one above — is the one that holds
    /// `sanitise` in place.
    #[test]
    fn a_clamped_rate_still_refills() {
        for per_second in NOT_A_RATE {
            let time = ManualTime::new();
            let limiter = raw_limiter(per_second, 1.0, &time);
            assert_eq!(limiter.reserve(), Duration::ZERO, "burst token");
            assert!(limiter.reserve() > Duration::ZERO, "burst is spent");

            // Two hours is more than the clamped rate of one per hour needs.
            time.advance(Duration::from_secs(7200));
            assert_eq!(
                limiter.reserve(),
                Duration::ZERO,
                "per_second={per_second} left a limiter that never refills"
            );
        }
    }

    #[test]
    fn a_pathological_burst_does_not_panic() {
        for burst in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let time = ManualTime::new();
            let limiter = raw_limiter(10.0, burst, &time);
            let _ = limiter.reserve();
            let _ = limiter.reserve();
        }
    }

    #[test]
    fn a_sane_rate_is_left_exactly_as_given() {
        // The clamp must not quietly alter a limit a caller meant, or a crawler
        // tuned to a site's published rate would run at a different one.
        let limit = sanitise(RateLimit {
            per_second: 2.5,
            burst: 7.0,
        });
        assert_eq!(limit.per_second, 2.5);
        assert_eq!(limit.burst, 7.0);
    }

    use chromulate_core::{Body, Exchange};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::time::testing::ManualTime;

    /// Builds a limiter from a struct literal, which is how these values
    /// actually arrive: `RateLimit`'s fields are public, so a caller can skip
    /// [`RateLimit::per_second`] and its assertion entirely. The `limiter`
    /// helper below goes through that constructor and so cannot express any of
    /// them — it would panic in the test harness rather than in the code under
    /// test.
    fn raw_limiter(per_second: f64, burst: f64, time: &Arc<ManualTime>) -> RateLimiter {
        RateLimiter::with_time_source(RateLimit { per_second, burst }, time.source())
    }

    fn limiter(per_second: f64, burst: f64, time: &Arc<ManualTime>) -> RateLimiter {
        RateLimiter::with_time_source(
            RateLimit::per_second(per_second).with_burst(burst),
            time.source(),
        )
    }

    #[test]
    fn a_fresh_bucket_lets_the_burst_through_without_waiting() {
        let time = ManualTime::new();
        let limiter = limiter(10.0, 3.0, &time);

        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert_eq!(limiter.reserve(), Duration::ZERO);
    }

    #[test]
    fn the_request_after_the_burst_waits_exactly_one_interval() {
        let time = ManualTime::new();
        let limiter = limiter(10.0, 3.0, &time);

        for _ in 0..3 {
            assert_eq!(limiter.reserve(), Duration::ZERO);
        }
        assert_eq!(
            limiter.reserve(),
            Duration::from_millis(100),
            "at ten per second the fourth request waits a tenth of a second"
        );
    }

    #[test]
    fn queued_requests_wait_progressively_longer_rather_than_all_the_same() {
        let time = ManualTime::new();
        let limiter = limiter(10.0, 1.0, &time);

        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert_eq!(limiter.reserve(), Duration::from_millis(100));
        assert_eq!(limiter.reserve(), Duration::from_millis(200));
        assert_eq!(limiter.reserve(), Duration::from_millis(300));
    }

    #[test]
    fn tokens_come_back_as_time_passes() {
        let time = ManualTime::new();
        let limiter = limiter(10.0, 5.0, &time);

        for _ in 0..5 {
            assert_eq!(limiter.reserve(), Duration::ZERO);
        }
        assert_eq!(limiter.reserve(), Duration::from_millis(100));

        time.advance(Duration::from_secs(1));
        // A second at ten per second earns ten tokens, which the burst caps at
        // five; spending one leaves four.
        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert!(
            (limiter.tokens() - 4.0).abs() < 1e-9,
            "{}",
            limiter.tokens()
        );
    }

    #[test]
    fn a_long_idle_period_refills_no_further_than_the_burst() {
        let time = ManualTime::new();
        let limiter = limiter(10.0, 2.0, &time);

        time.advance(Duration::from_secs(3600));
        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert_eq!(limiter.reserve(), Duration::ZERO);
        assert_eq!(
            limiter.reserve(),
            Duration::from_millis(100),
            "an hour of idling must not bank an hour of requests"
        );
    }

    struct Counter(AtomicUsize);

    impl Exchange for Counter {
        fn exchange(&self, _request: Request) -> BoxFuture<'_, Result<Response>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(http::Response::builder()
                    .status(200)
                    .body(Body::empty())
                    .expect("a valid response"))
            })
        }
    }

    #[tokio::test]
    async fn the_middleware_spends_a_token_per_request_and_still_reaches_the_transport() {
        let time = ManualTime::new();
        let limiter: Arc<dyn Middleware> = Arc::new(limiter(10.0, 2.0, &time));
        let chain = vec![Arc::clone(&limiter)];
        let terminal = Counter(AtomicUsize::new(0));

        for _ in 0..4 {
            let request = http::Request::builder()
                .uri("https://example.test/")
                .body(Body::empty())
                .expect("a valid request");
            Next::new(&chain, &terminal)
                .run(request)
                .await
                .expect("the chain must reach the transport");
        }

        assert_eq!(terminal.0.load(Ordering::SeqCst), 4);
        assert_eq!(
            time.recorded_sleeps(),
            vec![Duration::from_millis(100), Duration::from_millis(100)],
            "the first two requests spend the burst; the next two each wait one interval"
        );
    }

    #[test]
    #[should_panic(expected = "positive, finite")]
    fn a_zero_rate_is_rejected_rather_than_silently_blocking_forever() {
        let _ = RateLimit::per_second(0.0);
    }
}
