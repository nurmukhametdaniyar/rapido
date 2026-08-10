//! Poisson cover traffic.
//!
//! ## Cover traffic costs bandwidth
//!
//! Cover traffic is extra messages that carry no information, so it
//! **increases** bandwidth consumption by construction: there is no mechanism
//! by which sending more packets sends fewer bytes.
//! [`CoverStats::bandwidth_overhead_pct`] is therefore positive by definition,
//! and the sign is asserted by a test rather than left to convention.
//!
//! ## What cover traffic buys
//!
//! Padding the arrival process toward a constant aggregate rate hides *when* an
//! agent is genuinely active. The tradeoff is measured, not asserted: overhead
//! on one axis, adversary AUC on the other (see `rapido-sim::attack`).

use rand::Rng;
use rand_distr::{Distribution, Exp};
use serde::{Deserialize, Serialize};

use crate::mechanism::EventKind;

/// A scheduled transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transmission {
    pub time_ns: u64,
    pub kind: EventKind,
    pub bytes: usize,
}

/// Poisson cover-traffic scheduler.
///
/// Cover messages are emitted as a Poisson process of rate `lambda_cover`
/// (messages per second) independent of genuine traffic. Independence is the
/// point: a scheduler that reacted to genuine activity would encode it.
#[derive(Debug, Clone, Copy)]
pub struct CoverScheduler {
    /// Cover messages per second.
    pub lambda_cover_hz: f64,
    /// Size of a cover message. Must equal the genuine presentation size, or
    /// the two are trivially distinguishable by length.
    pub message_bytes: usize,
}

impl CoverScheduler {
    pub fn new(lambda_cover_hz: f64, message_bytes: usize) -> Self {
        assert!(lambda_cover_hz >= 0.0, "cover rate must be non-negative");
        CoverScheduler { lambda_cover_hz, message_bytes }
    }

    /// Cover transmission times in `[0, window_ns)`.
    pub fn schedule<R: Rng + ?Sized>(&self, window_ns: u64, rng: &mut R) -> Vec<Transmission> {
        if self.lambda_cover_hz <= 0.0 {
            return Vec::new();
        }
        // Inter-arrival times are Exp(lambda). Sampling gaps rather than a
        // count-then-place keeps the process exactly Poisson over any window.
        let per_ns = self.lambda_cover_hz / 1e9;
        let exp = Exp::new(per_ns).expect("rate is positive and finite");
        let mut out = Vec::new();
        let mut t = 0.0f64;
        loop {
            t += exp.sample(rng);
            if t >= window_ns as f64 {
                break;
            }
            out.push(Transmission {
                time_ns: t as u64,
                kind: EventKind::Cover,
                bytes: self.message_bytes,
            });
        }
        out
    }

    /// The cover rate that brings a genuine rate up to `target_hz`. Returns 0
    /// when genuine traffic already exceeds the target — an aggregate rate
    /// cannot be padded downward.
    pub fn rate_for_constant_aggregate(genuine_hz: f64, target_hz: f64) -> f64 {
        (target_hz - genuine_hz).max(0.0)
    }
}

/// Bandwidth accounting over a measurement window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CoverStats {
    pub window_ns: u64,
    pub genuine_messages: usize,
    pub cover_messages: usize,
    pub genuine_bytes: usize,
    pub cover_bytes: usize,
}

impl CoverStats {
    pub fn total_bytes(&self) -> usize {
        self.genuine_bytes + self.cover_bytes
    }

    /// **Percentage increase** in bytes caused by cover traffic. Positive by
    /// construction — see the module note.
    pub fn bandwidth_overhead_pct(&self) -> f64 {
        if self.genuine_bytes == 0 {
            return if self.cover_bytes == 0 { 0.0 } else { f64::INFINITY };
        }
        100.0 * self.cover_bytes as f64 / self.genuine_bytes as f64
    }

    /// Fraction of all transmitted messages that are cover.
    pub fn cover_fraction(&self) -> f64 {
        let total = self.genuine_messages + self.cover_messages;
        if total == 0 {
            0.0
        } else {
            self.cover_messages as f64 / total as f64
        }
    }

    /// Aggregate message rate in Hz, the quantity a constant-rate policy targets.
    pub fn aggregate_rate_hz(&self) -> f64 {
        if self.window_ns == 0 {
            return 0.0;
        }
        (self.genuine_messages + self.cover_messages) as f64 * 1e9 / self.window_ns as f64
    }
}

/// Merge genuine and cover transmissions into one time-ordered stream and
/// account for it. The merged stream is what an adversary observes.
pub fn merge_and_account(
    genuine: &[Transmission],
    cover: &[Transmission],
    window_ns: u64,
) -> (Vec<Transmission>, CoverStats) {
    let mut all: Vec<Transmission> = genuine.iter().chain(cover).copied().collect();
    all.sort_by_key(|t| t.time_ns);
    let stats = CoverStats {
        window_ns,
        genuine_messages: genuine.len(),
        cover_messages: cover.len(),
        genuine_bytes: genuine.iter().map(|t| t.bytes).sum(),
        cover_bytes: cover.iter().map(|t| t.bytes).sum(),
    };
    (all, stats)
}

/// Count transmissions per fixed-width bin — the summary statistic a traffic
/// adversary works from.
pub fn bin_counts(stream: &[Transmission], window_ns: u64, bin_ns: u64) -> Vec<u32> {
    assert!(bin_ns > 0, "bin width must be positive");
    let n_bins = window_ns.div_ceil(bin_ns) as usize;
    let mut bins = vec![0u32; n_bins];
    for t in stream {
        let i = (t.time_ns / bin_ns) as usize;
        if i < n_bins {
            bins[i] += 1;
        }
    }
    bins
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u64) -> ChaCha20Rng {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        ChaCha20Rng::from_seed(b)
    }

    #[test]
    fn poisson_schedule_has_the_requested_rate() {
        let mut r = rng(1);
        let s = CoverScheduler::new(50.0, 256);
        let window_ns = 20_000_000_000u64; // 20 s
        let sched = s.schedule(window_ns, &mut r);
        let observed = sched.len() as f64 / 20.0;
        assert!((observed - 50.0).abs() < 5.0, "observed rate {observed} Hz");
    }

    #[test]
    fn schedule_is_time_ordered_and_within_the_window() {
        let mut r = rng(2);
        let s = CoverScheduler::new(100.0, 256);
        let window = 1_000_000_000u64;
        let sched = s.schedule(window, &mut r);
        assert!(sched.windows(2).all(|w| w[0].time_ns <= w[1].time_ns));
        assert!(sched.iter().all(|t| t.time_ns < window));
        assert!(sched.iter().all(|t| t.kind == EventKind::Cover));
    }

    #[test]
    fn zero_rate_emits_nothing() {
        let mut r = rng(3);
        assert!(CoverScheduler::new(0.0, 256).schedule(1_000_000_000, &mut r).is_empty());
    }

    /// The overhead is an increase, never a saving.
    #[test]
    fn cover_traffic_increases_bandwidth() {
        let mut r = rng(4);
        let window = 10_000_000_000u64;
        let genuine: Vec<Transmission> = (0..100)
            .map(|i| Transmission {
                time_ns: i * 100_000_000,
                kind: EventKind::Genuine,
                bytes: 300,
            })
            .collect();
        let cover = CoverScheduler::new(20.0, 300).schedule(window, &mut r);
        let (_stream, stats) = merge_and_account(&genuine, &cover, window);

        assert!(stats.cover_bytes > 0);
        assert!(
            stats.bandwidth_overhead_pct() > 0.0,
            "cover traffic must increase bandwidth, not decrease it"
        );
        assert!(stats.total_bytes() > stats.genuine_bytes);
        // ~200 cover messages against 100 genuine ones is ~200% overhead.
        assert!(
            (stats.bandwidth_overhead_pct() - 200.0).abs() < 40.0,
            "overhead {}",
            stats.bandwidth_overhead_pct()
        );
    }

    #[test]
    fn overhead_grows_with_the_cover_rate() {
        let window = 5_000_000_000u64;
        let genuine: Vec<Transmission> = (0..50)
            .map(|i| Transmission {
                time_ns: i * 100_000_000,
                kind: EventKind::Genuine,
                bytes: 300,
            })
            .collect();
        let mut previous = 0.0;
        for (i, lambda) in [1.0f64, 5.0, 20.0, 50.0].iter().enumerate() {
            let mut r = rng(10 + i as u64);
            let cover = CoverScheduler::new(*lambda, 300).schedule(window, &mut r);
            let (_s, stats) = merge_and_account(&genuine, &cover, window);
            let pct = stats.bandwidth_overhead_pct();
            assert!(pct > previous, "lambda {lambda}: overhead {pct} did not exceed {previous}");
            previous = pct;
        }
    }

    #[test]
    fn constant_aggregate_rate_is_computed_correctly() {
        assert_eq!(CoverScheduler::rate_for_constant_aggregate(30.0, 100.0), 70.0);
        // Genuine traffic above the target cannot be padded down.
        assert_eq!(CoverScheduler::rate_for_constant_aggregate(120.0, 100.0), 0.0);
    }

    #[test]
    fn merged_stream_is_ordered_and_complete() {
        let mut r = rng(5);
        let window = 2_000_000_000u64;
        let genuine: Vec<Transmission> = (0..20)
            .map(|i| Transmission { time_ns: i * 90_000_000, kind: EventKind::Genuine, bytes: 300 })
            .collect();
        let cover = CoverScheduler::new(30.0, 300).schedule(window, &mut r);
        let (stream, stats) = merge_and_account(&genuine, &cover, window);
        assert_eq!(stream.len(), genuine.len() + cover.len());
        assert!(stream.windows(2).all(|w| w[0].time_ns <= w[1].time_ns));
        assert_eq!(stats.genuine_messages, 20);
    }

    #[test]
    fn cover_messages_must_be_the_same_size_as_genuine_ones() {
        // Documents the requirement rather than enforcing it in the type: a
        // caller that sizes cover differently makes the two distinguishable by
        // length alone, before any timing analysis.
        let s = CoverScheduler::new(10.0, 300);
        assert_eq!(s.message_bytes, 300);
    }

    #[test]
    fn bin_counts_partition_the_stream() {
        let window = 1_000_000_000u64;
        let stream: Vec<Transmission> = (0..100)
            .map(|i| Transmission { time_ns: i * 10_000_000, kind: EventKind::Genuine, bytes: 1 })
            .collect();
        let bins = bin_counts(&stream, window, 100_000_000);
        assert_eq!(bins.len(), 10);
        assert_eq!(bins.iter().sum::<u32>(), 100);
        assert!(bins.iter().all(|&c| c == 10));
    }
}
