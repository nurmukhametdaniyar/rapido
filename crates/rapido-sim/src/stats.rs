//! Latency histograms and adversary-advantage statistics.

use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};

/// Percentile summary of a latency distribution. p50/p90/p99/p99.9 are
/// reported rather than a mean, because a mean hides exactly the tail that
/// decides whether a 100 ms deadline is met.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct LatencySummary {
    pub count: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
}

/// Recorder backed by HdrHistogram.
#[derive(Debug)]
pub struct LatencyRecorder {
    hist: Histogram<u64>,
}

impl Default for LatencyRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyRecorder {
    /// Three significant figures over a 1 ns .. 100 s range: enough resolution
    /// for a p99.9 to be meaningful, small enough to keep per-run memory flat.
    pub fn new() -> Self {
        LatencyRecorder {
            hist: Histogram::new_with_bounds(1, 100_000_000_000, 3)
                .expect("static histogram bounds are valid"),
        }
    }

    pub fn record(&mut self, value_ns: u64) {
        // HdrHistogram cannot record 0 with a low bound of 1; clamp rather than
        // drop, so counts stay honest.
        self.hist.record(value_ns.max(1)).expect("value is within the configured bounds");
    }

    pub fn len(&self) -> u64 {
        self.hist.len()
    }
    pub fn is_empty(&self) -> bool {
        self.hist.is_empty()
    }

    pub fn summary(&self) -> LatencySummary {
        LatencySummary {
            count: self.hist.len(),
            min_ns: self.hist.min(),
            p50_ns: self.hist.value_at_quantile(0.50),
            p90_ns: self.hist.value_at_quantile(0.90),
            p99_ns: self.hist.value_at_quantile(0.99),
            p999_ns: self.hist.value_at_quantile(0.999),
            max_ns: self.hist.max(),
            mean_ns: self.hist.mean(),
        }
    }

    /// Fraction of recorded values at or below a deadline — the completion rate
    /// Scenario 1 reports.
    pub fn fraction_within(&self, deadline_ns: u64) -> f64 {
        if self.hist.is_empty() {
            return 0.0;
        }
        self.hist.count_between(1, deadline_ns) as f64 / self.hist.len() as f64
    }
}

/// Area under the ROC curve, computed exactly from the rank statistic
/// (Mann-Whitney U), with ties counted as half.
///
/// `positive` and `negative` are the adversary's scores for the two classes.
/// AUC 0.5 means the adversary learned nothing; 1.0 means perfect separation.
pub fn auc(positive: &[f64], negative: &[f64]) -> f64 {
    if positive.is_empty() || negative.is_empty() {
        return 0.5;
    }
    let mut all: Vec<(f64, bool)> =
        positive.iter().map(|&s| (s, true)).chain(negative.iter().map(|&s| (s, false))).collect();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    // Average ranks within tied groups so ties contribute exactly 0.5.
    let n = all.len();
    let mut rank_sum_pos = 0.0f64;
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j + 1 < n && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        let avg_rank = ((i + 1) + (j + 1)) as f64 / 2.0;
        for item in all.iter().take(j + 1).skip(i) {
            if item.1 {
                rank_sum_pos += avg_rank;
            }
        }
        i = j + 1;
    }

    let np = positive.len() as f64;
    let nn = negative.len() as f64;
    let u = rank_sum_pos - np * (np + 1.0) / 2.0;
    u / (np * nn)
}

/// Adversary *advantage* over guessing, in `[0, 1]`.
///
/// `|2·AUC − 1|` rather than `AUC − 0.5`: an adversary that reliably guesses
/// backwards has learned just as much as one that guesses forwards, and
/// reporting a negative advantage would understate the leak.
pub fn advantage_from_auc(auc: f64) -> f64 {
    (2.0 * auc - 1.0).abs()
}

/// Advantage of a binary decision procedure, from its confusion counts.
/// `|Pr[say yes | yes] − Pr[say yes | no]|`.
pub fn advantage_from_rates(true_positive_rate: f64, false_positive_rate: f64) -> f64 {
    (true_positive_rate - false_positive_rate).abs()
}

/// Mean and unbiased sample standard deviation.
pub fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    if xs.len() < 2 {
        return (mean, 0.0);
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var.sqrt())
}

/// Normal-approximation 95% confidence interval for a mean over `n` runs.
/// Every scenario result is reported as an interval, not a point estimate.
pub fn ci95(xs: &[f64]) -> (f64, f64, f64) {
    let (mean, sd) = mean_std(xs);
    if xs.len() < 2 {
        return (mean, mean, mean);
    }
    let half = 1.96 * sd / (xs.len() as f64).sqrt();
    (mean, mean - half, mean + half)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_of_a_known_distribution() {
        let mut r = LatencyRecorder::new();
        for i in 1..=1000u64 {
            r.record(i * 1000);
        }
        let s = r.summary();
        assert_eq!(s.count, 1000);
        // 3 significant figures, so allow the histogram's own bucket width.
        assert!((s.p50_ns as i64 - 500_000).abs() < 2_000);
        assert!((s.p99_ns as i64 - 990_000).abs() < 2_000);
        assert!((s.mean_ns - 500_500.0).abs() < 2_000.0);
    }

    #[test]
    fn fraction_within_a_deadline() {
        let mut r = LatencyRecorder::new();
        for i in 0..100u64 {
            r.record(i * 1_000_000);
        }
        // Values 0..49 ms are at or below a 50 ms deadline (0 is clamped to 1).
        let f = r.fraction_within(50_000_000);
        assert!((f - 0.51).abs() < 0.02, "got {f}");
    }

    #[test]
    fn auc_is_half_for_identical_distributions() {
        let a: Vec<f64> = (0..500).map(|i| i as f64).collect();
        let b = a.clone();
        assert!((auc(&a, &b) - 0.5).abs() < 1e-9);
        assert!(advantage_from_auc(auc(&a, &b)) < 1e-9);
    }

    #[test]
    fn auc_is_one_for_perfectly_separated_distributions() {
        let a: Vec<f64> = (0..100).map(|i| 1000.0 + i as f64).collect();
        let b: Vec<f64> = (0..100).map(|i| i as f64).collect();
        assert!((auc(&a, &b) - 1.0).abs() < 1e-9);
        assert!((advantage_from_auc(auc(&a, &b)) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn auc_is_zero_for_perfectly_inverted_separation() {
        let a: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let b: Vec<f64> = (0..100).map(|i| 1000.0 + i as f64).collect();
        assert!(auc(&a, &b) < 1e-9);
        // ...but the adversary still learned everything.
        assert!((advantage_from_auc(auc(&a, &b)) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn all_ties_give_exactly_half() {
        let a = vec![5.0; 50];
        let b = vec![5.0; 50];
        assert!((auc(&a, &b) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn auc_matches_a_brute_force_count() {
        let a = [1.0f64, 3.0, 5.0, 5.0, 9.0];
        let b = [2.0f64, 4.0, 5.0, 6.0];
        let mut wins = 0.0;
        for x in a {
            for y in b {
                wins += match x.partial_cmp(&y).unwrap() {
                    std::cmp::Ordering::Greater => 1.0,
                    std::cmp::Ordering::Equal => 0.5,
                    std::cmp::Ordering::Less => 0.0,
                };
            }
        }
        let expected = wins / (a.len() * b.len()) as f64;
        assert!((auc(&a, &b) - expected).abs() < 1e-12);
    }

    #[test]
    fn empty_input_reports_no_information() {
        assert_eq!(auc(&[], &[1.0]), 0.5);
        assert_eq!(auc(&[1.0], &[]), 0.5);
    }

    #[test]
    fn confidence_interval_brackets_the_mean() {
        let xs: Vec<f64> = (0..100).map(|i| 10.0 + (i % 5) as f64).collect();
        let (mean, lo, hi) = ci95(&xs);
        assert!(lo < mean && mean < hi);
        let (m2, sd) = mean_std(&xs);
        assert!((m2 - mean).abs() < 1e-12);
        assert!(sd > 0.0);
    }
}
