//! Cover-traffic adversary.
//!
//! The adversary observes the merged transmission stream and must decide
//! whether a given window contains genuine activity. Its advantage is measured
//! against the bandwidth overhead the cover traffic costs, which is what turns
//! cover traffic from an assertion into a tradeoff curve.

use rapido_privacy::cover::{bin_counts, merge_and_account, CoverScheduler, Transmission};
use rapido_privacy::mechanism::EventKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Observation window.
    pub window_ns: u64,
    /// Bin width the adversary aggregates over.
    pub bin_ns: u64,
    /// Genuine message rate during an "active" window.
    pub active_rate_hz: f64,
    /// Genuine message rate during an "idle" window.
    pub idle_rate_hz: f64,
    pub cover_rate_hz: f64,
    pub message_bytes: usize,
    /// Windows of each class the adversary is scored over.
    pub trials: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window_ns: 10_000_000_000,
            bin_ns: 1_000_000_000,
            active_rate_hz: 2.0,
            idle_rate_hz: 0.0,
            cover_rate_hz: 0.0,
            message_bytes: 300,
            trials: 400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub cover_rate_hz: f64,
    pub auc: f64,
    /// `|2·AUC − 1|`: how well the adversary tells active windows from idle.
    pub advantage: f64,
    /// **Increase** in bytes caused by cover traffic, as a percentage of
    /// genuine bytes.
    pub bandwidth_overhead_pct: f64,
    pub mean_total_bytes: f64,
    pub trials: usize,
    pub seed: u64,
}

/// Generate a Poisson stream of genuine transmissions at `rate_hz`.
fn genuine_stream<R: rand::Rng + ?Sized>(
    rate_hz: f64,
    window_ns: u64,
    bytes: usize,
    rng: &mut R,
) -> Vec<Transmission> {
    if rate_hz <= 0.0 {
        return Vec::new();
    }
    // Reuse the cover scheduler's Poisson process and relabel: the arrival
    // process is the same, only the label differs, which is precisely the
    // property that makes cover traffic work at all.
    CoverScheduler::new(rate_hz, bytes)
        .schedule(window_ns, rng)
        .into_iter()
        .map(|mut t| {
            t.kind = EventKind::Genuine;
            t
        })
        .collect()
}

/// The adversary's statistic: total observed message count in the window.
///
/// Given Poisson genuine traffic plus Poisson cover, the count is a sufficient
/// statistic for the combined rate, so this is the strongest test available
/// from counts alone.
fn observed_count(stream: &[Transmission], window_ns: u64, bin_ns: u64) -> f64 {
    bin_counts(stream, window_ns, bin_ns).iter().map(|c| *c as f64).sum()
}

pub fn run(config: &Config, seed: u64) -> Outcome {
    let mut rng = rapido_crypto::rng_from_seed(seed);
    let cover = CoverScheduler::new(config.cover_rate_hz, config.message_bytes);

    let mut active_scores = Vec::with_capacity(config.trials);
    let mut idle_scores = Vec::with_capacity(config.trials);
    let mut genuine_bytes_total = 0f64;
    let mut cover_bytes_total = 0f64;
    let mut total_bytes = 0f64;

    for _ in 0..config.trials {
        for (rate, scores) in
            [(config.active_rate_hz, &mut active_scores), (config.idle_rate_hz, &mut idle_scores)]
        {
            let genuine = genuine_stream(rate, config.window_ns, config.message_bytes, &mut rng);
            let cov = cover.schedule(config.window_ns, &mut rng);
            let (stream, stats) = merge_and_account(&genuine, &cov, config.window_ns);
            scores.push(observed_count(&stream, config.window_ns, config.bin_ns));
            genuine_bytes_total += stats.genuine_bytes as f64;
            cover_bytes_total += stats.cover_bytes as f64;
            total_bytes += stats.total_bytes() as f64;
        }
    }

    let auc = crate::stats::auc(&active_scores, &idle_scores);
    Outcome {
        cover_rate_hz: config.cover_rate_hz,
        auc,
        advantage: crate::stats::advantage_from_auc(auc),
        bandwidth_overhead_pct: if genuine_bytes_total == 0.0 {
            f64::INFINITY
        } else {
            100.0 * cover_bytes_total / genuine_bytes_total
        },
        mean_total_bytes: total_bytes / (2 * config.trials) as f64,
        trials: config.trials,
        seed,
    }
}

/// Sweep the cover rate to produce the bandwidth/detectability tradeoff curve.
pub fn sweep(base: &Config, rates_hz: &[f64], seed: u64) -> Vec<Outcome> {
    rates_hz.iter().map(|&cover_rate_hz| run(&Config { cover_rate_hz, ..*base }, seed)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_cover_traffic_activity_is_obvious() {
        let o = run(&Config { cover_rate_hz: 0.0, ..Default::default() }, 1);
        assert!(o.advantage > 0.95, "undefended advantage {}", o.advantage);
        assert_eq!(o.bandwidth_overhead_pct, 0.0);
    }

    #[test]
    fn heavy_cover_traffic_hides_activity() {
        let cfg = Config { cover_rate_hz: 200.0, ..Default::default() };
        let o = run(&cfg, 2);
        assert!(
            o.advantage < 0.35,
            "cover at 200 Hz against 2 Hz of genuine traffic should hide most of it, got {}",
            o.advantage
        );
        assert!(o.bandwidth_overhead_pct > 1_000.0);
    }

    /// The tradeoff curve: more cover, less advantage, more bytes.
    #[test]
    fn advantage_falls_and_overhead_rises_with_the_cover_rate() {
        let base = Config::default();
        let out = sweep(&base, &[0.0, 2.0, 10.0, 50.0, 200.0], 3);
        for w in out.windows(2) {
            assert!(
                w[1].bandwidth_overhead_pct >= w[0].bandwidth_overhead_pct,
                "overhead must be monotone in the cover rate"
            );
        }
        assert!(
            out.last().unwrap().advantage < out[0].advantage,
            "the strongest cover rate must reduce advantage below the undefended case"
        );
    }

    /// Overhead is always an increase, at every cover rate.
    #[test]
    fn bandwidth_overhead_is_never_negative() {
        for rate in [0.0f64, 1.0, 10.0, 100.0] {
            let o = run(&Config { cover_rate_hz: rate, trials: 50, ..Default::default() }, 4);
            assert!(
                o.bandwidth_overhead_pct >= 0.0,
                "cover traffic cannot reduce bandwidth (rate {rate})"
            );
        }
    }

    #[test]
    fn results_are_reproducible() {
        let cfg = Config { trials: 50, cover_rate_hz: 5.0, ..Default::default() };
        assert_eq!(run(&cfg, 9), run(&cfg, 9));
    }
}
