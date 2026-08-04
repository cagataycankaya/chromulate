//! A bounded retry policy with exponential backoff.
//!
//! # Why this is not a `Middleware`
//!
//! Retrying means running the same downstream work more than once.
//! [`chromulate_core::Next`] is consumed by `Next::run`, is neither `Clone` nor
//! `Copy`, and exposes no accessor for the slice and terminal it holds, so a
//! `Middleware` receives exactly one chance to continue the chain and cannot
//! take a second. A retry therefore has to sit where it owns the thing it
//! repeats: it decorates an [`Exchange`] instead, and the engine installs it
//! directly beneath the middleware chain.
//!
//! That placement is also the correct one on its own terms. Retry wraps the
//! redirect loop, so one retry re-runs a whole logical request rather than a
//! single hop, and it sits inside the middleware chain, so a rate limiter or a
//! logger above it sees every attempt.

use std::fmt;
use std::time::Duration;

use chromulate_core::{
    Body, BoxFuture, Exchange, Request, Response, Result, reexport::HeaderValue,
};
use http::{Method, StatusCode};
use rand::Rng as _;

use crate::time::TimeSource;

/// The share of a backoff interval that jitter may remove.
///
/// Jitter exists to stop a fleet of clients retrying in lockstep after a shared
/// failure. It is capped well below the factor of two between successive
/// intervals so the schedule stays strictly increasing: a delay lands in
/// `[0.8, 1.0]` of its nominal value, and `0.8 * 2 > 1.0`, so attempt *n+1*
/// always waits longer than attempt *n* however the dice land. A policy that
/// can reorder its own backoff is needlessly hard to read in a log.
const JITTER_FRACTION: f64 = 0.2;

/// Which requests may be sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RetryOn {
    /// Only requests whose method is idempotent.
    ///
    /// The default. A `POST` that timed out may well have been received and
    /// acted on; re-sending it can duplicate an order or a payment, and the
    /// client has no way to tell which happened.
    #[default]
    IdempotentMethods,
    /// Any request, whatever its method.
    ///
    /// Correct only when every endpoint the client talks to is genuinely
    /// idempotent, which is a claim about the server rather than the client.
    AnyMethod,
}

/// How many times, how long between, and on what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts after the first. `2` means up to three requests in total.
    pub max_retries: u32,
    /// The wait before the first retry, doubled for each one after.
    pub base_delay: Duration,
    /// A ceiling on any single wait.
    pub max_delay: Duration,
    /// Which methods may be replayed.
    pub retry_on: RetryOn,
    /// Whether to subtract a random fraction from each wait.
    pub jitter: bool,
    /// Whether a `Retry-After` header may lengthen a wait.
    pub honour_retry_after: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(10),
            retry_on: RetryOn::IdempotentMethods,
            jitter: true,
            honour_retry_after: true,
        }
    }
}

impl RetryPolicy {
    /// The nominal wait before retry number `attempt`, counting from zero.
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

/// A retry policy and the clock it runs against.
#[derive(Clone)]
pub struct Retry {
    policy: RetryPolicy,
    time: TimeSource,
}

impl fmt::Debug for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retry")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Retry {
    /// The default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(RetryPolicy::default())
    }

    /// A specific policy.
    #[must_use]
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self {
            policy,
            time: TimeSource::system(),
        }
    }

    /// Replaces the clock and timer, so a test can assert the schedule without
    /// waiting for it.
    #[must_use]
    pub fn with_time_source(mut self, time: TimeSource) -> Self {
        self.time = time;
        self
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> RetryPolicy {
        self.policy
    }

    /// Wraps an exchange so its failures are retried.
    #[must_use]
    pub fn wrap<'a>(&'a self, inner: &'a dyn Exchange) -> Retrying<'a> {
        Retrying { retry: self, inner }
    }

    fn may_replay(&self, method: &Method, body: &Body) -> bool {
        let method_allows = match self.policy.retry_on {
            RetryOn::AnyMethod => true,
            RetryOn::IdempotentMethods => is_idempotent(method),
        };
        // A streaming body was consumed by the failed attempt and cannot be
        // produced again. Re-sending with an empty body would quietly send a
        // *different* request, which is worse than returning the failure.
        method_allows && body.try_clone().is_some()
    }

    fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let mut delay = self.policy.backoff(attempt);
        if self.policy.jitter {
            let keep = 1.0 - rand::rng().random_range(0.0..JITTER_FRACTION);
            delay = delay.mul_f64(keep);
        }
        match retry_after {
            // A server that states how long to wait knows more than the
            // client's schedule does, but only upwards: honouring a shorter
            // value would let a struggling server be retried faster than the
            // policy allows.
            Some(after) if self.policy.honour_retry_after => {
                delay.max(after).min(self.policy.max_delay)
            }
            _ => delay,
        }
    }
}

impl Default for Retry {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Exchange`] with a retry policy in front of it.
pub struct Retrying<'a> {
    retry: &'a Retry,
    inner: &'a dyn Exchange,
}

impl fmt::Debug for Retrying<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retrying")
            .field("policy", &self.retry.policy)
            .finish_non_exhaustive()
    }
}

impl Exchange for Retrying<'_> {
    fn exchange(&self, request: Request) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            let policy = self.retry.policy;
            if policy.max_retries == 0 || !self.retry.may_replay(request.method(), request.body()) {
                return self.inner.exchange(request).await;
            }

            let (parts, body) = request.into_parts();
            let mut attempt = 0u32;

            loop {
                let Some(replay) = body.try_clone() else {
                    return self.inner.exchange(Request::from_parts(parts, body)).await;
                };
                let outcome = self
                    .inner
                    .exchange(Request::from_parts(parts.clone(), replay))
                    .await;

                let retry_after = match &outcome {
                    Ok(response) if should_retry_status(response.status()) => {
                        parse_retry_after(response.headers().get(http::header::RETRY_AFTER))
                    }
                    Err(error) if error.is_retryable() => None,
                    _ => return outcome,
                };

                if attempt >= policy.max_retries {
                    return outcome;
                }

                let delay = self.retry.delay(attempt, retry_after);
                tracing::debug!(
                    attempt = attempt + 1,
                    max = policy.max_retries,
                    delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "retrying"
                );
                self.retry.time.sleep(delay).await;
                attempt += 1;
            }
        })
    }
}

/// Whether a response status is worth another attempt.
#[must_use]
pub fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Whether replaying a method leaves the server in the same state.
#[must_use]
pub fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

/// Reads the delay-seconds form of `Retry-After`.
///
/// The HTTP-date form is not honoured: acting on it means trusting the server's
/// clock against the client's, and a skewed pair yields either an immediate
/// retry or an absurd wait. A server that wants a particular delay can state it
/// in seconds.
#[must_use]
pub fn parse_retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let seconds: u64 = value?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chromulate_core::Error;

    use super::*;
    use crate::time::testing::ManualTime;

    /// An exchange that plays a scripted sequence of outcomes and counts calls.
    struct Script {
        outcomes: Mutex<Vec<Result<StatusCode>>>,
        calls: AtomicUsize,
    }

    impl Script {
        fn new(outcomes: Vec<Result<StatusCode>>) -> Self {
            Self {
                // Reversed so each call can `pop` from the end in O(1).
                outcomes: Mutex::new(outcomes.into_iter().rev().collect()),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Exchange for Script {
        fn exchange(&self, _request: Request) -> BoxFuture<'_, Result<Response>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let next = self
                    .outcomes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop();
                match next {
                    Some(Ok(status)) => Ok(http::Response::builder()
                        .status(status)
                        .body(Body::empty())
                        .expect("a valid response")),
                    Some(Err(error)) => Err(error),
                    None => panic!("the exchange was called more times than the script allows"),
                }
            })
        }
    }

    fn request() -> Request {
        http::Request::builder()
            .method(Method::GET)
            .uri("https://example.test/")
            .body(Body::fixed("payload"))
            .expect("a valid request")
    }

    fn deterministic(max_retries: u32) -> RetryPolicy {
        RetryPolicy {
            max_retries,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            jitter: false,
            ..RetryPolicy::default()
        }
    }

    #[tokio::test]
    async fn a_request_that_fails_twice_then_succeeds_is_sent_three_times_with_doubling_backoff() {
        let script = Script::new(vec![
            Err(Error::Timeout(chromulate_core::Phase::Connect)),
            Err(Error::Timeout(chromulate_core::Phase::Connect)),
            Ok(StatusCode::OK),
        ]);
        let time = ManualTime::new();
        let retry = Retry::with_policy(deterministic(2)).with_time_source(time.source());

        let response = retry
            .wrap(&script)
            .exchange(request())
            .await
            .expect("the third attempt succeeds");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(script.calls(), 3, "one original attempt plus two retries");
        assert_eq!(
            time.recorded_sleeps(),
            vec![Duration::from_millis(100), Duration::from_millis(200)],
            "the schedule must double between attempts"
        );
    }

    #[tokio::test]
    async fn the_last_failure_is_returned_once_the_attempts_run_out() {
        let script = Script::new(vec![
            Err(Error::Timeout(chromulate_core::Phase::Connect)),
            Err(Error::Timeout(chromulate_core::Phase::Connect)),
        ]);
        let time = ManualTime::new();
        let retry = Retry::with_policy(deterministic(1)).with_time_source(time.source());

        let error = retry
            .wrap(&script)
            .exchange(request())
            .await
            .expect_err("both attempts fail");

        assert!(error.is_timeout(), "{error:?}");
        assert_eq!(script.calls(), 2);
        assert_eq!(time.recorded_sleeps().len(), 1);
    }

    #[tokio::test]
    async fn an_error_that_is_not_retryable_is_returned_after_one_attempt() {
        let script = Script::new(vec![Err(Error::url("not a url"))]);
        let time = ManualTime::new();
        let retry = Retry::with_policy(deterministic(5)).with_time_source(time.source());

        let error = retry
            .wrap(&script)
            .exchange(request())
            .await
            .expect_err("a user error is not retried");

        assert!(error.is_user_error(), "{error:?}");
        assert_eq!(script.calls(), 1);
        assert!(time.recorded_sleeps().is_empty());
    }

    #[tokio::test]
    async fn a_503_is_retried_and_its_retry_after_lengthens_the_wait() {
        struct Unavailable(AtomicUsize);
        impl Exchange for Unavailable {
            fn exchange(&self, _request: Request) -> BoxFuture<'_, Result<Response>> {
                Box::pin(async move {
                    let n = self.0.fetch_add(1, Ordering::SeqCst);
                    let builder = http::Response::builder();
                    Ok(if n == 0 {
                        builder
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .header(http::header::RETRY_AFTER, "5")
                            .body(Body::empty())
                            .expect("a valid response")
                    } else {
                        builder
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .expect("a valid response")
                    })
                })
            }
        }

        let inner = Unavailable(AtomicUsize::new(0));
        let time = ManualTime::new();
        let retry = Retry::with_policy(deterministic(2)).with_time_source(time.source());

        let response = retry
            .wrap(&inner)
            .exchange(request())
            .await
            .expect("the second attempt succeeds");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            time.recorded_sleeps(),
            vec![Duration::from_secs(5)],
            "Retry-After must override the shorter computed backoff"
        );
    }

    #[tokio::test]
    async fn a_post_is_sent_exactly_once_by_default_even_when_it_fails_retryably() {
        let script = Script::new(vec![Err(Error::Timeout(chromulate_core::Phase::Connect))]);
        let time = ManualTime::new();
        let retry = Retry::with_policy(deterministic(3)).with_time_source(time.source());

        let post = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.test/orders")
            .body(Body::fixed("{}"))
            .expect("a valid request");

        let error = retry
            .wrap(&script)
            .exchange(post)
            .await
            .expect_err("the single attempt fails");

        assert!(error.is_timeout());
        assert_eq!(
            script.calls(),
            1,
            "replaying a POST can duplicate a side effect the client cannot see"
        );
    }

    #[tokio::test]
    async fn a_streaming_body_is_sent_once_because_it_cannot_be_replayed() {
        let script = Script::new(vec![Err(Error::Timeout(chromulate_core::Phase::Connect))]);
        let time = ManualTime::new();
        let retry = Retry::with_policy(RetryPolicy {
            retry_on: RetryOn::AnyMethod,
            ..deterministic(3)
        })
        .with_time_source(time.source());

        let streaming = http::Request::builder()
            .method(Method::GET)
            .uri("https://example.test/")
            .body(Body::stream(futures_util::stream::empty(), None))
            .expect("a valid request");

        let error = retry
            .wrap(&script)
            .exchange(streaming)
            .await
            .expect_err("the single attempt fails");

        assert!(error.is_timeout());
        assert_eq!(script.calls(), 1);
    }

    #[test]
    fn backoff_doubles_and_then_stops_at_the_ceiling() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            ..RetryPolicy::default()
        };
        assert_eq!(policy.backoff(0), Duration::from_millis(100));
        assert_eq!(policy.backoff(1), Duration::from_millis(200));
        assert_eq!(policy.backoff(2), Duration::from_millis(400));
        assert_eq!(policy.backoff(3), Duration::from_millis(500));
        assert_eq!(policy.backoff(30), Duration::from_millis(500));
    }

    #[test]
    fn jitter_never_reorders_two_successive_intervals() {
        let retry = Retry::with_policy(RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            jitter: true,
            ..RetryPolicy::default()
        });

        for _ in 0..1_000 {
            let first = retry.delay(0, None);
            let second = retry.delay(1, None);
            assert!(
                second > first,
                "backoff must stay monotonic under jitter: {first:?} then {second:?}"
            );
            assert!(first >= Duration::from_millis(80) && first <= Duration::from_millis(100));
        }
    }

    #[test]
    fn a_retry_after_longer_than_the_backoff_wins_and_a_shorter_one_does_not() {
        let retry = Retry::with_policy(RetryPolicy {
            base_delay: Duration::from_secs(1),
            jitter: false,
            ..RetryPolicy::default()
        });

        assert_eq!(
            retry.delay(0, Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        assert_eq!(
            retry.delay(0, Some(Duration::from_millis(10))),
            Duration::from_secs(1),
            "a server must not be able to shorten the client's own backoff"
        );
    }

    #[test]
    fn retry_after_is_clamped_by_the_policy_ceiling() {
        let retry = Retry::with_policy(RetryPolicy {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            jitter: false,
            ..RetryPolicy::default()
        });
        assert_eq!(
            retry.delay(0, Some(Duration::from_secs(3600))),
            Duration::from_secs(10),
            "an hour-long Retry-After must not strand the caller"
        );
    }

    #[test]
    fn only_the_delay_seconds_form_of_retry_after_is_read() {
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static("120"))),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static(
                "Wed, 21 Oct 2026 07:28:00 GMT"
            ))),
            None,
            "the date form depends on clock agreement and is deliberately ignored"
        );
        assert_eq!(parse_retry_after(None), None);
    }

    #[test]
    fn the_statuses_worth_retrying_are_the_transient_ones() {
        assert!(should_retry_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(should_retry_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(should_retry_status(StatusCode::BAD_GATEWAY));
        assert!(should_retry_status(StatusCode::GATEWAY_TIMEOUT));

        assert!(!should_retry_status(StatusCode::OK));
        assert!(!should_retry_status(StatusCode::NOT_FOUND));
        assert!(
            !should_retry_status(StatusCode::INTERNAL_SERVER_ERROR),
            "a 500 is usually a deterministic fault; replaying it just doubles the load"
        );
    }
}
