//! Network model.
//!
//! Configurable one-way delay (mean + jitter), loss rate, and MTU. Deliberately
//! simple: **no claim of radio-layer fidelity is made anywhere.** A DSRC or
//! C-V2X channel has contention, capture effects, fading, and hidden terminals
//! that this does not model. What it does capture is that messages take time,
//! sometimes disappear, and get fragmented above the MTU — enough for the
//! latency and bandwidth questions being asked, and no more.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NetworkModel {
    /// Mean one-way delay.
    pub mean_delay_ns: u64,
    /// Standard deviation of the one-way delay.
    pub jitter_ns: u64,
    /// Independent per-message loss probability.
    pub loss_rate: f64,
    /// Bytes per fragment; a larger message costs one delay per fragment.
    pub mtu_bytes: usize,
}

impl Default for NetworkModel {
    /// A short-range V2X link: sub-millisecond, low loss, 1500-byte MTU.
    fn default() -> Self {
        NetworkModel {
            mean_delay_ns: 500_000,
            jitter_ns: 100_000,
            loss_rate: 0.01,
            mtu_bytes: 1500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered { delay_ns: u64, fragments: usize },
    Lost,
}

impl NetworkModel {
    pub fn perfect() -> Self {
        NetworkModel { mean_delay_ns: 0, jitter_ns: 0, loss_rate: 0.0, mtu_bytes: usize::MAX }
    }

    pub fn fragments(&self, bytes: usize) -> usize {
        if self.mtu_bytes == 0 || self.mtu_bytes == usize::MAX {
            1
        } else {
            bytes.div_ceil(self.mtu_bytes).max(1)
        }
    }

    /// Sample a delivery outcome for a message of `bytes`.
    ///
    /// Loss is applied per fragment: a message that needs three fragments is
    /// lost if any one of them is, which is why bigger presentations are more
    /// fragile on a lossy link. That effect is one reason presentation size
    /// matters beyond raw bandwidth.
    pub fn deliver<R: Rng + ?Sized>(&self, bytes: usize, rng: &mut R) -> Delivery {
        let fragments = self.fragments(bytes);
        if self.loss_rate > 0.0 {
            for _ in 0..fragments {
                if rng.gen::<f64>() < self.loss_rate {
                    return Delivery::Lost;
                }
            }
        }
        Delivery::Delivered { delay_ns: self.sample_delay(fragments, rng), fragments }
    }

    fn sample_delay<R: Rng + ?Sized>(&self, fragments: usize, rng: &mut R) -> u64 {
        if self.mean_delay_ns == 0 && self.jitter_ns == 0 {
            return 0;
        }
        let base = if self.jitter_ns == 0 {
            self.mean_delay_ns as f64
        } else {
            let n = Normal::new(self.mean_delay_ns as f64, self.jitter_ns as f64)
                .expect("jitter is a valid standard deviation");
            n.sample(rng)
        };
        // Delay cannot be negative; a Gaussian jitter model can produce one, so
        // it is clamped rather than allowed to travel backwards in time.
        let per_fragment = base.max(0.0);
        (per_fragment * fragments as f64) as u64
    }

    /// Effective probability that a message of `bytes` is lost.
    pub fn message_loss_probability(&self, bytes: usize) -> f64 {
        1.0 - (1.0 - self.loss_rate).powi(self.fragments(bytes) as i32)
    }
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
    fn perfect_network_delivers_instantly() {
        let n = NetworkModel::perfect();
        let mut r = rng(1);
        for _ in 0..100 {
            assert_eq!(
                n.deliver(10_000, &mut r),
                Delivery::Delivered { delay_ns: 0, fragments: 1 }
            );
        }
    }

    #[test]
    fn mean_delay_is_respected() {
        let n = NetworkModel {
            mean_delay_ns: 1_000_000,
            jitter_ns: 200_000,
            loss_rate: 0.0,
            mtu_bytes: 1500,
        };
        let mut r = rng(2);
        let samples: Vec<u64> = (0..10_000)
            .map(|_| match n.deliver(300, &mut r) {
                Delivery::Delivered { delay_ns, .. } => delay_ns,
                Delivery::Lost => unreachable!("loss rate is zero"),
            })
            .collect();
        let mean = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
        assert!((mean - 1_000_000.0).abs() < 20_000.0, "mean {mean}");
    }

    #[test]
    fn loss_rate_is_respected() {
        let n = NetworkModel { mean_delay_ns: 0, jitter_ns: 0, loss_rate: 0.1, mtu_bytes: 1500 };
        let mut r = rng(3);
        let lost = (0..20_000).filter(|_| n.deliver(300, &mut r) == Delivery::Lost).count();
        let rate = lost as f64 / 20_000.0;
        assert!((rate - 0.1).abs() < 0.01, "measured loss {rate}");
    }

    #[test]
    fn fragmentation_multiplies_delay_and_loss() {
        let n =
            NetworkModel { mean_delay_ns: 1_000_000, jitter_ns: 0, loss_rate: 0.1, mtu_bytes: 500 };
        assert_eq!(n.fragments(1_400), 3);
        // Three fragments, each independently lossy.
        let p = n.message_loss_probability(1_400);
        assert!((p - (1.0 - 0.9f64.powi(3))).abs() < 1e-12);

        let mut r = rng(4);
        let mut delays = Vec::new();
        for _ in 0..2_000 {
            if let Delivery::Delivered { delay_ns, fragments } = n.deliver(1_400, &mut r) {
                assert_eq!(fragments, 3);
                delays.push(delay_ns);
            }
        }
        assert!(!delays.is_empty());
        assert!(delays.iter().all(|d| *d == 3_000_000));
    }

    #[test]
    fn delay_is_never_negative_despite_gaussian_jitter() {
        // Jitter far larger than the mean would produce negative samples if
        // they were not clamped.
        let n = NetworkModel {
            mean_delay_ns: 1_000,
            jitter_ns: 10_000,
            loss_rate: 0.0,
            mtu_bytes: 1500,
        };
        let mut r = rng(5);
        for _ in 0..10_000 {
            match n.deliver(100, &mut r) {
                Delivery::Delivered { .. } => {}
                Delivery::Lost => unreachable!(),
            }
        }
    }

    #[test]
    fn delivery_is_reproducible_from_a_seed() {
        let n = NetworkModel::default();
        let run = |seed: u64| {
            let mut r = rng(seed);
            (0..100).map(|_| n.deliver(400, &mut r)).collect::<Vec<_>>()
        };
        assert_eq!(run(9), run(9));
    }
}
