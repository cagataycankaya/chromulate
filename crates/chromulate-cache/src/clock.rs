//! Wall-clock time, behind a trait, so freshness is testable.
//!
//! Every freshness decision in RFC 9111 is a comparison against wall-clock
//! time. Tested against the real clock, "this response is fresh for sixty
//! seconds and stale after" takes sixty seconds to prove, so in practice it
//! never gets proved. [`ManualClock`] is what makes the tests in this crate
//! assert the boundary rather than assert that some time passed.
//!
//! This mirrors [`chromulate_http::time::TimeSource`], which does the same for
//! monotonic time. A cache needs `SystemTime` rather than `Instant`, because
//! `Date`, `Expires`, and `Last-Modified` are absolute instants a server chose.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// A source of wall-clock time.
pub trait WallClock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when it is told to.
///
/// ```
/// use std::time::{Duration, SystemTime};
///
/// use chromulate_cache::{ManualClock, WallClock};
///
/// let clock = ManualClock::at(SystemTime::UNIX_EPOCH);
/// let before = clock.now();
/// clock.advance(Duration::from_secs(90));
/// assert_eq!(clock.now().duration_since(before).unwrap(), Duration::from_secs(90));
/// ```
pub struct ManualClock {
    now: Mutex<SystemTime>,
}

impl ManualClock {
    /// A clock stopped at `now`.
    #[must_use]
    pub fn at(now: SystemTime) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            now: Mutex::new(now),
        })
    }

    /// Moves the clock forward.
    ///
    /// Saturating: a test that advances by `Duration::MAX` is asking for "far
    /// enough that nothing is fresh", not for a panic.
    pub fn advance(&self, by: Duration) {
        let mut now = self.lock();
        *now = now.checked_add(by).unwrap_or(*now);
    }

    /// Sets the clock to an absolute instant.
    pub fn set(&self, to: SystemTime) {
        *self.lock() = to;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SystemTime> {
        self.now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl WallClock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.lock()
    }
}

impl fmt::Debug for ManualClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManualClock")
            .field("now", &*self.lock())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_clock_stands_still_until_it_is_advanced() {
        let clock = ManualClock::at(SystemTime::UNIX_EPOCH);
        assert_eq!(clock.now(), clock.now());
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            clock.now().duration_since(SystemTime::UNIX_EPOCH).unwrap(),
            Duration::from_secs(5)
        );
    }

    /// `SystemTime + Duration` panics on overflow. `Age` and `max-age` are
    /// server-controlled, so a test that pushes a clock past what the platform
    /// represents is a test someone will write.
    #[test]
    fn advancing_past_what_the_platform_represents_saturates_instead_of_panicking() {
        let clock = ManualClock::at(SystemTime::UNIX_EPOCH);
        clock.advance(Duration::MAX);
        clock.advance(Duration::MAX);
        assert!(clock.now() >= SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn the_system_clock_moves_forward() {
        let clock = SystemWallClock;
        let first = clock.now();
        assert!(clock.now() >= first);
    }
}
