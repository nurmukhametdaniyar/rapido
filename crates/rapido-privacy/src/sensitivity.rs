//! Sensitivity `Δf`, derived from the measured compute-time range rather than
//! assumed.
//!
//! For a timing mechanism the query is "how long did this verification take",
//! and its sensitivity is how much that can change between two neighbouring
//! inputs. The bounding assumption used here is the conservative one: any two
//! verifications the verifier might perform are neighbouring, so `Δf` is the
//! spread of the compute-time distribution.
//!
//! The raw max−min is *not* used. A single scheduler hiccup or page fault would
//! set `Δf` for the entire experiment and inflate every reported delay. The
//! spread is taken between robust quantiles instead, and both the trimmed and
//! untrimmed values are recorded so the choice is visible rather than buried.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sensitivity {
    /// The value used by the mechanisms: `p_hi − p_lo`, at least 1 ns.
    pub delta_f_ns: u64,
    /// Untrimmed `max − min`, reported so the effect of trimming is visible.
    pub raw_range_ns: u64,
    pub p_lo_ns: u64,
    pub p_hi_ns: u64,
    pub median_ns: u64,
    pub n_samples: usize,
    /// Quantiles used for the trimmed range.
    pub lo_quantile: f64,
    pub hi_quantile: f64,
}

/// Default trim points. 0.1% / 99.9% keeps the genuine tail of the compute-time
/// distribution while discarding the handful of OS-scheduling outliers a
/// userspace benchmark always collects.
pub const DEFAULT_LO_QUANTILE: f64 = 0.001;
pub const DEFAULT_HI_QUANTILE: f64 = 0.999;

impl Sensitivity {
    pub fn from_samples(samples: &[u64]) -> Self {
        Self::from_samples_with(samples, DEFAULT_LO_QUANTILE, DEFAULT_HI_QUANTILE)
    }

    pub fn from_samples_with(samples: &[u64], lo_q: f64, hi_q: f64) -> Self {
        assert!(!samples.is_empty(), "sensitivity needs at least one sample");
        assert!(
            lo_q >= 0.0 && hi_q <= 1.0 && lo_q < hi_q,
            "quantiles must satisfy 0 <= lo < hi <= 1"
        );

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let q = |p: f64| -> u64 {
            let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
            sorted[idx.min(sorted.len() - 1)]
        };
        let (lo, hi) = (q(lo_q), q(hi_q));
        Sensitivity {
            delta_f_ns: hi.saturating_sub(lo).max(1),
            raw_range_ns: sorted[sorted.len() - 1] - sorted[0],
            p_lo_ns: lo,
            p_hi_ns: hi,
            median_ns: q(0.5),
            n_samples: sorted.len(),
            lo_quantile: lo_q,
            hi_quantile: hi_q,
        }
    }

    /// Fraction of the untrimmed range that trimming discarded. A large value
    /// means the tail is heavy and the reported ε is optimistic for the
    /// outliers; it belongs in the results.
    pub fn trimmed_fraction(&self) -> f64 {
        if self.raw_range_ns == 0 {
            return 0.0;
        }
        1.0 - (self.delta_f_ns as f64 / self.raw_range_ns as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_of_a_uniform_sample() {
        let samples: Vec<u64> = (0..10_000).map(|i| 1_000_000 + i).collect();
        let s = Sensitivity::from_samples(&samples);
        assert_eq!(s.raw_range_ns, 9_999);
        assert!(s.delta_f_ns > 9_900 && s.delta_f_ns <= 9_999);
        assert!((s.median_ns as i64 - 1_005_000).abs() < 5);
    }

    #[test]
    fn a_single_outlier_does_not_set_the_sensitivity() {
        let mut samples: Vec<u64> = (0..10_000).map(|_| 100_000).collect();
        samples.push(50_000_000); // one scheduler hiccup
        let s = Sensitivity::from_samples(&samples);
        assert_eq!(s.raw_range_ns, 49_900_000);
        assert!(s.delta_f_ns < 1_000, "trimming must reject the outlier, got {}", s.delta_f_ns);
        assert!(s.trimmed_fraction() > 0.99);
    }

    #[test]
    fn sensitivity_is_never_zero() {
        let s = Sensitivity::from_samples(&[42; 100]);
        assert_eq!(s.delta_f_ns, 1, "a degenerate sample must not divide by zero downstream");
    }

    #[test]
    fn wider_distributions_give_larger_sensitivity() {
        let tight: Vec<u64> = (0..1000).map(|i| 100_000 + i % 10).collect();
        let wide: Vec<u64> = (0..1000).map(|i| 100_000 + (i % 10) * 1_000).collect();
        assert!(
            Sensitivity::from_samples(&wide).delta_f_ns
                > Sensitivity::from_samples(&tight).delta_f_ns
        );
    }

    #[test]
    fn quantile_choice_is_recorded() {
        let samples: Vec<u64> = (0..1000).collect();
        let s = Sensitivity::from_samples_with(&samples, 0.05, 0.95);
        assert_eq!(s.lo_quantile, 0.05);
        assert_eq!(s.hi_quantile, 0.95);
        assert!(s.delta_f_ns < s.raw_range_ns);
    }
}
