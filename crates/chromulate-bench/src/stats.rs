//! Summary statistics over repeated runs.
//!
//! A single number is not a measurement. Everything the harness prints goes
//! through [`Summary`], so every number it prints carries how many runs it came
//! from and how far apart they were.

#![forbid(unsafe_code)]

use std::fmt;

/// Mean, extremes and relative spread over a set of runs.
#[derive(Debug, Clone, Copy)]
pub struct Summary {
    /// Number of runs the summary covers.
    pub runs: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Middle value, which is what to read when a run may have stalled.
    ///
    /// A shared machine occasionally hands one run a fraction of the CPU it
    /// gave the others. That run is not wrong — it happened — but it says more
    /// about the machine than about the code, and the mean carries it straight
    /// into the headline figure while the median does not.
    pub median: f64,
    /// Smallest observed value.
    pub min: f64,
    /// Largest observed value.
    pub max: f64,
}

impl Summary {
    /// Summarises `samples`.
    ///
    /// # Panics
    ///
    /// Panics when `samples` is empty; a summary of nothing has no honest
    /// value, and every caller in this crate controls the run count.
    #[must_use]
    pub fn of(samples: &[f64]) -> Self {
        assert!(!samples.is_empty(), "a summary needs at least one sample");
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        let middle = sorted.len() / 2;
        let median = if sorted.len() % 2 == 0 {
            (sorted[middle - 1] + sorted[middle]) / 2.0
        } else {
            sorted[middle]
        };
        Self {
            runs: samples.len(),
            mean,
            median,
            min: samples.iter().copied().fold(f64::INFINITY, f64::min),
            max: samples.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        }
    }

    /// Spread as a percentage of the mean, `(max - min) / mean`.
    #[must_use]
    pub fn spread_pct(&self) -> f64 {
        if self.mean == 0.0 {
            0.0
        } else {
            (self.max - self.min) / self.mean * 100.0
        }
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mean {:.0}, median {:.0} (min {:.0}, max {:.0}, spread {:.1}%, n={})",
            self.mean,
            self.median,
            self.min,
            self.max,
            self.spread_pct(),
            self.runs
        )
    }
}
