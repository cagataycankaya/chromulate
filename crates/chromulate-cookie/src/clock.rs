//! An injectable clock, so expiry and eviction logic can be tested deterministically
//! instead of sleeping past real deadlines.

use std::time::SystemTime;

/// A source of the current time.
///
/// [`Jar`](crate::Jar) takes its clock as an `Arc<dyn Clock>` rather than calling
/// [`SystemTime::now`] directly, so tests can inject a fixed or steppable clock and
/// assert expiry behaviour without sleeping.
pub trait Clock: Send + Sync + 'static {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The real wall clock, backed by [`SystemTime::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_reports_a_time_at_or_after_the_unix_epoch() {
        assert!(SystemClock.now() >= std::time::UNIX_EPOCH);
    }
}
