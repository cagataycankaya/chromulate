//! Time, behind traits, so the middleware tests do not sleep.
//!
//! A retry policy and a rate limiter are both defined in terms of "how long
//! since" and "wait this long". Tested against the real clock they take as long
//! to run as the delays they implement, which in practice means the delays get
//! tuned down until the test is fast and no longer exercises the policy anyone
//! ships. Both dependencies are traits here, and the tests supply a clock they
//! advance by hand.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromulate_core::BoxFuture;

/// A source of monotonic time.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The process clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A way to wait.
pub trait Sleeper: Send + Sync + 'static {
    /// Completes after `duration` has elapsed.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// Waits on the tokio timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The clock and the timer a policy runs against, bundled because they are
/// always replaced together.
#[derive(Clone)]
pub struct TimeSource {
    clock: Arc<dyn Clock>,
    sleeper: Arc<dyn Sleeper>,
}

impl TimeSource {
    /// Builds a source from a clock and a timer.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, sleeper: Arc<dyn Sleeper>) -> Self {
        Self { clock, sleeper }
    }

    /// The real clock and the tokio timer.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(SystemClock), Arc::new(TokioSleeper))
    }

    /// The current instant.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Waits for `duration`.
    pub fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        self.sleeper.sleep(duration)
    }
}

impl Default for TimeSource {
    fn default() -> Self {
        Self::system()
    }
}

impl fmt::Debug for TimeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeSource").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Mutex;

    use super::*;

    /// A clock that only moves when a test moves it, paired with a timer that
    /// returns immediately and records what it was asked to wait for.
    ///
    /// Recording rather than waiting is what lets a test assert the backoff
    /// schedule exactly instead of asserting that some time passed.
    #[derive(Debug)]
    pub(crate) struct ManualTime {
        state: Mutex<ManualState>,
    }

    #[derive(Debug)]
    struct ManualState {
        now: Instant,
        slept: Vec<Duration>,
    }

    impl ManualTime {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(ManualState {
                    now: Instant::now(),
                    slept: Vec::new(),
                }),
            })
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, ManualState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// Every duration `sleep` was called with, in order.
        pub(crate) fn recorded_sleeps(&self) -> Vec<Duration> {
            self.lock().slept.clone()
        }

        /// Moves the clock forward without waiting.
        pub(crate) fn advance(&self, by: Duration) {
            let mut state = self.lock();
            state.now += by;
        }

        /// A [`TimeSource`] backed by this clock.
        pub(crate) fn source(self: &Arc<Self>) -> TimeSource {
            TimeSource::new(Arc::clone(self) as Arc<dyn Clock>, Arc::clone(self) as _)
        }
    }

    impl Clock for ManualTime {
        fn now(&self) -> Instant {
            self.lock().now
        }
    }

    impl Sleeper for ManualTime {
        /// Records the request, advances the clock by exactly that much, and
        /// returns without yielding to the timer.
        fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
            let mut state = self.lock();
            state.slept.push(duration);
            state.now += duration;
            Box::pin(std::future::ready(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ManualTime;
    use super::*;

    #[tokio::test]
    async fn the_manual_timer_records_a_wait_and_moves_the_clock_without_taking_the_time() {
        let time = ManualTime::new();
        let source = time.source();
        let started = std::time::Instant::now();

        let before = source.now();
        source.sleep(Duration::from_secs(3600)).await;
        let after = source.now();

        assert_eq!(after - before, Duration::from_secs(3600));
        assert_eq!(time.recorded_sleeps(), vec![Duration::from_secs(3600)]);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an hour of simulated waiting must not take a real second"
        );
    }

    #[test]
    fn the_system_clock_moves_forward() {
        let clock = SystemClock;
        let first = clock.now();
        assert!(clock.now() >= first);
    }
}
