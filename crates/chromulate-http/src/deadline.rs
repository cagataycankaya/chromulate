//! One deadline for the whole request, split across the phases it passes
//! through.
//!
//! A request that is allowed thirty seconds is allowed thirty seconds in total,
//! not thirty per redirect hop and thirty more for the body. Every phase asks
//! this type how much of the budget is left, so the guarantee survives a
//! redirect chain, and the phase that runs out of time is the phase named in
//! the error.

use std::future::Future;
use std::time::{Duration, Instant};

use chromulate_core::{Error, Phase, Result};

/// The remaining budget for a request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    at: Option<Instant>,
}

impl Deadline {
    /// A budget of `total` starting now, or an unbounded one when `total` is
    /// `None`.
    pub(crate) fn starting_now(total: Option<Duration>) -> Self {
        Self {
            at: total.map(|total| Instant::now() + total),
        }
    }

    /// How long is left, or `None` when the budget is unbounded.
    ///
    /// Returns `Some(ZERO)` once the deadline has passed, which callers treat
    /// as expiry rather than as "no limit".
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.at
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// Whether the budget is spent.
    pub(crate) fn is_expired(&self) -> bool {
        self.remaining() == Some(Duration::ZERO)
    }

    /// Fails with `Timeout(phase)` when the budget is already spent.
    pub(crate) fn check(&self, phase: Phase) -> Result<()> {
        if self.is_expired() {
            Err(Error::Timeout(phase))
        } else {
            Ok(())
        }
    }

    /// Runs `future` under the smaller of the remaining budget and `cap`.
    ///
    /// Expiry becomes `Error::Timeout(phase)`, so a caller does not have to
    /// decide which phase a timeout belongs to at the point it fires.
    pub(crate) async fn run<F, T>(
        &self,
        phase: Phase,
        cap: Option<Duration>,
        future: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let limit = match (self.remaining(), cap) {
            (Some(remaining), Some(cap)) => Some(remaining.min(cap)),
            (Some(remaining), None) => Some(remaining),
            (None, cap) => cap,
        };

        match limit {
            None => future.await,
            Some(Duration::ZERO) => Err(Error::Timeout(phase)),
            Some(limit) => match tokio::time::timeout(limit, future).await {
                Ok(result) => result,
                Err(_elapsed) => Err(Error::Timeout(phase)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unbounded_deadline_never_expires() {
        let deadline = Deadline::starting_now(None);
        assert!(deadline.remaining().is_none());
        assert!(!deadline.is_expired());
        let value = deadline
            .run(Phase::Connect, None, async { Ok(7) })
            .await
            .expect("an unbounded deadline must not interfere");
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn a_phase_that_outlives_the_budget_reports_that_phase() {
        let deadline = Deadline::starting_now(Some(Duration::from_millis(20)));
        let error = deadline
            .run(Phase::Handshake, None, async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            })
            .await
            .expect_err("the budget must run out");
        assert!(
            matches!(error, Error::Timeout(Phase::Handshake)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_phase_cap_applies_even_when_the_whole_request_budget_is_larger() {
        let deadline = Deadline::starting_now(Some(Duration::from_secs(60)));
        let error = deadline
            .run(Phase::Connect, Some(Duration::from_millis(20)), async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            })
            .await
            .expect_err("the per-phase cap must bound the phase");
        assert!(matches!(error, Error::Timeout(Phase::Connect)), "{error:?}");
    }

    #[tokio::test]
    async fn the_budget_shrinks_as_phases_consume_it() {
        let deadline = Deadline::starting_now(Some(Duration::from_millis(300)));
        let before = deadline.remaining().expect("bounded");
        tokio::time::sleep(Duration::from_millis(80)).await;
        let after = deadline.remaining().expect("bounded");
        assert!(
            after < before,
            "a later phase must see less budget: {before:?} then {after:?}"
        );
    }

    #[tokio::test]
    async fn an_already_spent_budget_fails_the_next_phase_without_running_it() {
        let deadline = Deadline::starting_now(Some(Duration::from_millis(1)));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(deadline.is_expired());

        let mut ran = false;
        let error = deadline
            .run(Phase::Send, None, async {
                ran = true;
                Ok(())
            })
            .await
            .expect_err("a spent budget must fail immediately");
        assert!(matches!(error, Error::Timeout(Phase::Send)));
        assert!(!ran, "the phase must not start at all");
        assert!(deadline.check(Phase::Send).is_err());
    }
}
