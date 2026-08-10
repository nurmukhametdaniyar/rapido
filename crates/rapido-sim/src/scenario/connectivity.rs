//! Scenario 3 — connectivity loss.
//!
//! **Epoch revocation buys its O(1) check with an availability cost. This
//! experiment measures that cost.**
//!
//! An agent that cannot reach the authority cannot obtain credentials for the
//! next epoch. Under R0 a credential is valid only in the epoch it was issued
//! for, so at the next epoch boundary the agent simply stops being able to
//! authenticate — regardless of how many unused pseudonyms it is holding.
//!
//! Two independent failure modes are modelled, because they trade off in
//! opposite directions:
//!
//! * **Epoch expiry.** Fixed by pre-provisioning `lookahead` future epochs —
//!   which is exactly what SCMS does, pre-loading weeks of certificates. But
//!   pre-provisioning `k` epochs ahead means a revocation cannot take effect
//!   for `k+1` epochs, so it directly undoes the revocation latency that made
//!   R0 attractive. That tension is the finding.
//! * **Batch exhaustion.** An agent that authenticates more often than
//!   `n_batch` times per epoch runs out of pseudonyms early, independent of
//!   connectivity.
//!
//! Sweeping epoch length `T` traces out the revocation-latency vs availability
//! curve directly.

use rand::Rng;
use rapido_core::EpochClock;
use rapido_crypto::rng_from_seed;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub agents: usize,
    /// How long contact with the authority is lost, in minutes.
    pub outage_minutes: u64,
    /// Epoch length `T`, in minutes.
    pub epoch_minutes: u64,
    /// Pseudonyms issued per epoch (Mode A). Mode B issues one credential, so
    /// set this to `u32::MAX` semantics via a large value to disable
    /// exhaustion.
    pub n_batch: usize,
    /// Future epochs the agent holds credentials for at the moment the outage
    /// begins. `0` means it holds only the current epoch.
    pub lookahead_epochs: u64,
    pub interval_min_secs: u64,
    pub interval_max_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            agents: 10_000,
            outage_minutes: 10,
            epoch_minutes: 10,
            n_batch: 100,
            lookahead_epochs: 0,
            interval_min_secs: 30,
            interval_max_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub agents: usize,
    pub outage_minutes: u64,
    pub epoch_minutes: u64,
    pub lookahead_epochs: u64,
    pub n_batch: usize,
    /// Fraction of agents that failed at least one authentication attempt
    /// during the outage. **The availability cost of epoch revocation.**
    pub failure_rate: f64,
    /// Fraction that failed specifically because their credentials expired.
    pub expiry_failure_rate: f64,
    /// Fraction that failed specifically because they ran out of pseudonyms.
    pub exhaustion_failure_rate: f64,
    /// Fraction of all attempted authentications that failed.
    pub attempt_failure_rate: f64,
    /// Mean time from the start of the outage to an agent's first failure.
    pub mean_time_to_failure_secs: f64,
    /// Worst-case revocation latency this epoch length implies, including
    /// pre-provisioned lookahead. The other side of the tradeoff.
    pub revocation_latency_secs: u64,
    pub seed: u64,
}

/// Run one seed.
pub fn run(config: &Config, seed: u64) -> Outcome {
    let mut rng = rng_from_seed(seed);
    let clock = EpochClock::from_minutes(config.epoch_minutes);
    let outage_ns = config.outage_minutes * 60 * 1_000_000_000;

    let mut failed = 0usize;
    let mut expiry_failed = 0usize;
    let mut exhaustion_failed = 0usize;
    let mut attempts = 0u64;
    let mut failed_attempts = 0u64;
    let mut time_to_failure = Vec::new();

    for _ in 0..config.agents {
        // The outage starts at a uniformly random point within an epoch, which
        // is what determines how much of the current epoch is left.
        let start_offset = rng.gen_range(0..clock.epoch_ns);
        let outage_start = start_offset;
        // Credentials cover the current epoch plus `lookahead` more.
        let valid_until = outage_start
            + clock.time_to_rollover(start_offset)
            + config.lookahead_epochs * clock.epoch_ns;

        // Pseudonyms available across the whole covered span.
        let mut remaining = config.n_batch as u64 * (1 + config.lookahead_epochs);
        let mut t = outage_start;
        let mut first_failure: Option<u64> = None;

        loop {
            let gap = rng.gen_range(
                config.interval_min_secs * 1_000_000_000..=config.interval_max_secs * 1_000_000_000,
            );
            t += gap;
            if t >= outage_start + outage_ns {
                break;
            }
            attempts += 1;

            let expired = t >= valid_until;
            let exhausted = remaining == 0;
            if expired || exhausted {
                failed_attempts += 1;
                if first_failure.is_none() {
                    first_failure = Some(t - outage_start);
                    if expired {
                        expiry_failed += 1;
                    } else {
                        exhaustion_failed += 1;
                    }
                }
            } else {
                remaining -= 1;
            }
        }

        if let Some(ttf) = first_failure {
            failed += 1;
            time_to_failure.push(ttf as f64 / 1e9);
        }
    }

    let n = config.agents as f64;
    Outcome {
        agents: config.agents,
        outage_minutes: config.outage_minutes,
        epoch_minutes: config.epoch_minutes,
        lookahead_epochs: config.lookahead_epochs,
        n_batch: config.n_batch,
        failure_rate: failed as f64 / n,
        expiry_failure_rate: expiry_failed as f64 / n,
        exhaustion_failure_rate: exhaustion_failed as f64 / n,
        attempt_failure_rate: if attempts == 0 {
            0.0
        } else {
            failed_attempts as f64 / attempts as f64
        },
        mean_time_to_failure_secs: if time_to_failure.is_empty() {
            f64::NAN
        } else {
            time_to_failure.iter().sum::<f64>() / time_to_failure.len() as f64
        },
        // Pre-provisioning `k` epochs ahead delays revocation by `k+1` epochs.
        revocation_latency_secs: (config.lookahead_epochs + 1) * config.epoch_minutes * 60,
        seed,
    }
}

pub fn run_many(config: &Config, n_seeds: u64, base_seed: u64) -> Vec<Outcome> {
    (0..n_seeds).map(|i| run(config, base_seed + i)).collect()
}

/// The reported sweep: outage `d ∈ {1, 5, 10, 30, 60}` minutes crossed with
/// epoch `T ∈ {1, 5, 10, 30, 60}` minutes.
pub fn sweep(base: &Config, n_seeds: u64, base_seed: u64) -> Vec<Outcome> {
    let mut out = Vec::new();
    for outage_minutes in [1u64, 5, 10, 30, 60] {
        for epoch_minutes in [1u64, 5, 10, 30, 60] {
            out.extend(run_many(
                &Config { outage_minutes, epoch_minutes, ..*base },
                n_seeds,
                base_seed,
            ));
        }
    }
    out
}

/// Sweep pre-provisioning depth, producing the revocation-latency vs
/// availability tradeoff directly.
pub fn sweep_lookahead(base: &Config, n_seeds: u64, base_seed: u64) -> Vec<Outcome> {
    let mut out = Vec::new();
    for lookahead_epochs in [0u64, 1, 2, 6, 12, 144] {
        out.extend(run_many(&Config { lookahead_epochs, ..*base }, n_seeds, base_seed));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_reproducible() {
        let c = Config { agents: 500, ..Default::default() };
        assert_eq!(run(&c, 1), run(&c, 1));
    }

    #[test]
    fn a_short_outage_within_one_epoch_costs_almost_nothing() {
        let c = Config {
            agents: 5_000,
            outage_minutes: 1,
            epoch_minutes: 60,
            n_batch: 1000,
            ..Default::default()
        };
        let o = run(&c, 1);
        assert!(o.failure_rate < 0.05, "failure rate {}", o.failure_rate);
    }

    /// The finding: an outage longer than the epoch means near-total failure.
    #[test]
    fn an_outage_longer_than_the_epoch_fails_nearly_every_agent() {
        let c = Config {
            agents: 5_000,
            outage_minutes: 60,
            epoch_minutes: 10,
            n_batch: 100_000, // exhaustion cannot be the cause
            lookahead_epochs: 0,
            ..Default::default()
        };
        let o = run(&c, 2);
        assert!(
            o.failure_rate > 0.99,
            "epoch revocation should strand nearly everyone, got {}",
            o.failure_rate
        );
        assert!(o.expiry_failure_rate > 0.99, "and the cause must be expiry, not exhaustion");
        assert!(o.exhaustion_failure_rate < 0.01);
        // Failure arrives within one epoch of the outage starting.
        assert!(o.mean_time_to_failure_secs < 600.0);
    }

    #[test]
    fn longer_epochs_improve_availability() {
        let base =
            Config { agents: 4_000, outage_minutes: 30, n_batch: 100_000, ..Default::default() };
        let mut previous = 1.1;
        for epoch_minutes in [1u64, 5, 10, 30, 60] {
            let o = run(&Config { epoch_minutes, ..base }, 3);
            assert!(
                o.failure_rate <= previous,
                "T={epoch_minutes}: failure {} rose above {previous}",
                o.failure_rate
            );
            previous = o.failure_rate;
        }
    }

    /// ...and the price of that availability is revocation latency.
    #[test]
    fn availability_and_revocation_latency_trade_off_directly() {
        let base = Config {
            agents: 3_000,
            outage_minutes: 60,
            epoch_minutes: 10,
            n_batch: 100_000,
            ..Default::default()
        };
        let none = run(&Config { lookahead_epochs: 0, ..base }, 4);
        let deep = run(&Config { lookahead_epochs: 12, ..base }, 4);

        assert!(deep.failure_rate < none.failure_rate, "pre-provisioning must help availability");
        assert!(
            deep.revocation_latency_secs > none.revocation_latency_secs,
            "and must cost revocation latency: {} vs {}",
            deep.revocation_latency_secs,
            none.revocation_latency_secs
        );
        assert_eq!(none.revocation_latency_secs, 600);
        assert_eq!(deep.revocation_latency_secs, 13 * 600);
    }

    #[test]
    fn a_small_batch_exhausts_independently_of_the_epoch() {
        let c = Config {
            agents: 3_000,
            outage_minutes: 10,
            epoch_minutes: 600, // effectively no expiry
            n_batch: 2,
            ..Default::default()
        };
        let o = run(&c, 5);
        assert!(o.exhaustion_failure_rate > 0.9, "got {}", o.exhaustion_failure_rate);
        assert!(o.expiry_failure_rate < 0.05);
    }

    /// With exhaustion ruled out, the residual failure rate is exactly the
    /// probability that the outage straddles an epoch boundary: `outage / T`.
    /// Matching that closed form is what shows the model is doing epoch
    /// expiry and nothing else.
    #[test]
    fn a_large_batch_leaves_only_the_analytic_epoch_boundary_failures() {
        let (outage, epoch) = (10u64, 600u64);
        let c = Config {
            agents: 20_000,
            outage_minutes: outage,
            epoch_minutes: epoch,
            n_batch: 100_000,
            ..Default::default()
        };
        let o = run(&c, 6);
        let expected = outage as f64 / epoch as f64;
        assert!(
            (o.failure_rate - expected).abs() < 0.005,
            "failure rate {} should match the analytic {expected}",
            o.failure_rate
        );
        assert_eq!(o.exhaustion_failure_rate, 0.0, "a large batch cannot exhaust");
    }

    #[test]
    fn sweeps_cover_the_specified_grids() {
        let c = Config { agents: 200, ..Default::default() };
        assert_eq!(sweep(&c, 1, 0).len(), 25);
        assert_eq!(sweep_lookahead(&c, 1, 0).len(), 6);
    }
}
