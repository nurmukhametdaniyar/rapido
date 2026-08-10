//! Scenario 2 — sustained metropolitan load.
//!
//! `A` agents each authenticate every 30-60 s. Measures the verifier throughput
//! ceiling in auths/sec/core, the authority's issuance load for batch
//! pre-computation, and total system bandwidth including cover traffic.
//!
//! The throughput ceiling is derived two ways and both are reported: the
//! analytic `cores / mean_service_time`, and the rate actually achieved under
//! load. They diverge once the system saturates, and the gap is the queueing
//! penalty.

use crate::des::{EventQueue, ServerPool};
use crate::stats::{LatencyRecorder, LatencySummary};
use crate::workload::CostProfile;
use rand::Rng;
use rapido_core::EpochClock;
use rapido_crypto::rng_from_seed;
use rapido_privacy::cover::{CoverScheduler, CoverStats};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Number of agents in the metropolitan area.
    pub agents: usize,
    /// Total verifier cores across the deployment.
    pub cores: usize,
    pub interval_min_secs: u64,
    pub interval_max_secs: u64,
    /// Simulated duration.
    pub duration_secs: u64,
    /// Cover-traffic rate per agent, in messages per second. Zero disables it.
    pub cover_rate_hz: f64,
    pub epoch_secs: u64,
    /// Mode A pseudonyms issued per agent per epoch.
    pub n_batch: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            agents: 10_000,
            cores: 8,
            interval_min_secs: 30,
            interval_max_secs: 60,
            duration_secs: 120,
            cover_rate_hz: 0.0,
            epoch_secs: EpochClock::DEFAULT_EPOCH_SECS,
            n_batch: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub agents: usize,
    pub cores: usize,
    pub duration_secs: u64,
    /// Authentications the verifier completed per second.
    pub achieved_throughput_hz: f64,
    /// `cores / mean_service_time` — the ceiling if queueing were free.
    pub analytic_ceiling_hz: f64,
    /// Achieved rate per core — the figure that scales to other core counts,
    /// unlike the aggregate rate.
    pub throughput_per_core_hz: f64,
    /// Offered load as a fraction of the analytic ceiling. Above 1.0 the system
    /// cannot keep up and the queue grows without bound.
    pub offered_load_ratio: f64,
    pub verifier_utilization: f64,
    pub max_queue_depth: usize,
    pub latency: LatencySummary,
    pub completed: u64,
    pub offered: u64,
    /// Authority-side issuance work, in credential-issuances per second.
    pub issuance_rate_hz: f64,
    /// Authority CPU-seconds per simulated second for batch pre-computation.
    pub issuance_cpu_load: f64,
    pub bandwidth: BandwidthReport,
    pub seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BandwidthReport {
    pub presentation_bytes_total: u64,
    pub issuance_bytes_total: u64,
    pub cover_bytes_total: u64,
    pub total_bytes: u64,
    /// Aggregate bytes per second across the whole deployment.
    pub aggregate_bps: f64,
    /// **Increase** caused by cover traffic, as a percentage of genuine
    /// presentation bytes. Positive by construction — see
    /// `rapido_privacy::cover`.
    pub cover_overhead_pct: f64,
    pub cover: CoverStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Arrival { agent: usize, sent_ns: u64 },
    ServiceDone { sent_ns: u64, service_ns: u64 },
}

pub fn run(config: &Config, profile: &CostProfile, seed: u64) -> Outcome {
    assert!(
        config.interval_min_secs > 0 && config.interval_max_secs >= config.interval_min_secs,
        "authentication interval must be a positive non-empty range"
    );
    let mut rng = rng_from_seed(seed);
    let mut q: EventQueue<Event> = EventQueue::new();
    let mut pool = ServerPool::new(config.cores);
    let mut latency = LatencyRecorder::new();
    let mut waiting: std::collections::VecDeque<u64> = std::collections::VecDeque::new();

    let duration_ns = config.duration_secs * 1_000_000_000;
    let interval_range =
        (config.interval_min_secs * 1_000_000_000)..=(config.interval_max_secs * 1_000_000_000);

    // Stagger first authentications across one interval so the run does not
    // open with an artificial thundering herd.
    for agent in 0..config.agents {
        let first = rng.gen_range(0..*interval_range.end());
        if first < duration_ns {
            q.schedule_at(first, Event::Arrival { agent, sent_ns: first });
        }
    }

    let mut offered = 0u64;
    let mut completed = 0u64;
    let mut presentation_bytes_total = 0u64;

    while let Some((now, event)) = q.next() {
        if now > duration_ns {
            break;
        }
        match event {
            Event::Arrival { agent, sent_ns } => {
                offered += 1;
                presentation_bytes_total += profile.presentation_bytes as u64;

                if pool.offer(now).is_some() {
                    let service_ns = profile.sample_verify(&mut rng);
                    q.schedule_after(service_ns, Event::ServiceDone { sent_ns, service_ns });
                } else {
                    waiting.push_back(sent_ns);
                }

                // Schedule this agent's next authentication.
                let next = now + rng.gen_range(interval_range.clone());
                if next < duration_ns {
                    q.schedule_at(next, Event::Arrival { agent, sent_ns: next });
                }
            }
            Event::ServiceDone { sent_ns, service_ns } => {
                latency.record(now.saturating_sub(sent_ns));
                completed += 1;
                if pool.complete(service_ns).is_some() {
                    let next_sent = waiting.pop_front().expect("waiting mirrors the pool queue");
                    let next_service = profile.sample_verify(&mut rng);
                    q.schedule_after(
                        next_service,
                        Event::ServiceDone { sent_ns: next_sent, service_ns: next_service },
                    );
                }
            }
        }
    }

    // --- issuance load ---
    // Each agent needs a fresh batch every epoch (Mode A) or a fresh credential
    // (Mode B); either way, one issuance per agent per epoch.
    let epochs_per_sec = 1.0 / config.epoch_secs as f64;
    let issuance_rate_hz = config.agents as f64 * epochs_per_sec;
    let issuance_cpu_load = issuance_rate_hz * (profile.issuance_ns as f64 / 1e9);

    // --- bandwidth ---
    let issuance_bytes_total = (issuance_rate_hz
        * config.duration_secs as f64
        * (profile.issuance_download_bytes + profile.issuance_upload_bytes) as f64)
        as u64;

    let cover_messages = if config.cover_rate_hz > 0.0 {
        (config.cover_rate_hz * config.agents as f64 * config.duration_secs as f64) as u64
    } else {
        0
    };
    let cover_bytes_total = cover_messages * profile.presentation_bytes as u64;
    let cover = CoverStats {
        window_ns: duration_ns,
        genuine_messages: offered as usize,
        cover_messages: cover_messages as usize,
        genuine_bytes: presentation_bytes_total as usize,
        cover_bytes: cover_bytes_total as usize,
    };

    let total_bytes = presentation_bytes_total + issuance_bytes_total + cover_bytes_total;
    let mean_service_ns = profile.mean_verify_ns();
    let analytic_ceiling_hz = config.cores as f64 * 1e9 / mean_service_ns;
    let offered_hz = offered as f64 / config.duration_secs as f64;

    Outcome {
        agents: config.agents,
        cores: config.cores,
        duration_secs: config.duration_secs,
        achieved_throughput_hz: completed as f64 / config.duration_secs as f64,
        analytic_ceiling_hz,
        throughput_per_core_hz: completed as f64
            / config.duration_secs as f64
            / config.cores as f64,
        offered_load_ratio: offered_hz / analytic_ceiling_hz,
        verifier_utilization: pool.utilization(duration_ns),
        max_queue_depth: pool.max_queue_depth(),
        latency: latency.summary(),
        completed,
        offered,
        issuance_rate_hz,
        issuance_cpu_load,
        bandwidth: BandwidthReport {
            presentation_bytes_total,
            issuance_bytes_total,
            cover_bytes_total,
            total_bytes,
            aggregate_bps: total_bytes as f64 / config.duration_secs as f64,
            cover_overhead_pct: cover.bandwidth_overhead_pct(),
            cover,
        },
        seed,
    }
}

pub fn run_many(
    config: &Config,
    profile: &CostProfile,
    n_seeds: u64,
    base_seed: u64,
) -> Vec<Outcome> {
    (0..n_seeds).map(|i| run(config, profile, base_seed + i)).collect()
}

/// The reported sweep: `A ∈ {10^3, 10^4, 10^5}`.
pub fn sweep(base: &Config, profile: &CostProfile, n_seeds: u64, base_seed: u64) -> Vec<Outcome> {
    let mut out = Vec::new();
    for agents in [1_000usize, 10_000, 100_000] {
        out.extend(run_many(&Config { agents, ..*base }, profile, n_seeds, base_seed));
    }
    out
}

/// Cover-traffic rate that brings each agent's aggregate message rate to
/// `target_hz`, given the authentication interval.
pub fn cover_rate_for_target(config: &Config, target_hz: f64) -> f64 {
    let mean_interval = (config.interval_min_secs + config.interval_max_secs) as f64 / 2.0;
    CoverScheduler::rate_for_constant_aggregate(1.0 / mean_interval, target_hz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::{calibrate, SystemConfig};

    fn profile() -> CostProfile {
        calibrate(&SystemConfig { n_batch: 8, ..Default::default() }, 32, 11).unwrap()
    }

    fn small() -> Config {
        Config { agents: 500, cores: 4, duration_secs: 60, ..Default::default() }
    }

    #[test]
    fn runs_are_reproducible() {
        let p = profile();
        assert_eq!(run(&small(), &p, 5), run(&small(), &p, 5));
    }

    #[test]
    fn an_underloaded_system_completes_everything_it_is_offered() {
        let p = profile();
        let cfg = Config { agents: 200, cores: 8, duration_secs: 60, ..Default::default() };
        let o = run(&cfg, &p, 1);
        assert!(
            o.offered_load_ratio < 0.5,
            "test should be underloaded, got {}",
            o.offered_load_ratio
        );
        // Allow a small shortfall for requests still in service at cutoff.
        assert!(
            o.completed as f64 >= o.offered as f64 * 0.97,
            "completed {} of {} offered",
            o.completed,
            o.offered
        );
        assert!(o.max_queue_depth < 20);
    }

    #[test]
    fn an_overloaded_system_saturates_rather_than_scaling() {
        let p = profile();
        let cfg = Config { agents: 2_000_000, cores: 1, duration_secs: 5, ..Default::default() };
        let o = run(&cfg, &p, 2);
        assert!(o.offered_load_ratio > 1.0, "test should be overloaded");
        assert!(o.verifier_utilization > 0.95, "a saturated core must be busy");
        // Throughput cannot exceed the analytic ceiling.
        assert!(
            o.achieved_throughput_hz <= o.analytic_ceiling_hz * 1.05,
            "achieved {} exceeded ceiling {}",
            o.achieved_throughput_hz,
            o.analytic_ceiling_hz
        );
        assert!(o.max_queue_depth > 100, "an overloaded system must build a queue");
    }

    #[test]
    fn throughput_scales_with_cores_while_underloaded() {
        let p = profile();
        let base = Config { agents: 200_000, duration_secs: 5, ..Default::default() };
        let one = run(&Config { cores: 1, ..base }, &p, 3);
        let four = run(&Config { cores: 4, ..base }, &p, 3);
        assert!(
            four.achieved_throughput_hz > one.achieved_throughput_hz * 3.0,
            "1 core {} vs 4 cores {}",
            one.achieved_throughput_hz,
            four.achieved_throughput_hz
        );
    }

    #[test]
    fn issuance_load_scales_with_agents_and_inversely_with_epoch_length() {
        let p = profile();
        let a = run(&Config { agents: 1_000, ..small() }, &p, 4);
        let b = run(&Config { agents: 10_000, ..small() }, &p, 4);
        assert!((b.issuance_rate_hz / a.issuance_rate_hz - 10.0).abs() < 1e-6);

        let short_epoch = run(&Config { epoch_secs: 60, agents: 1_000, ..small() }, &p, 4);
        assert!(
            short_epoch.issuance_rate_hz > a.issuance_rate_hz,
            "a shorter epoch means more re-issuance"
        );
    }

    /// Cover traffic adds bytes at the system level too, not just per stream.
    #[test]
    fn cover_traffic_increases_total_bandwidth() {
        let p = profile();
        let without = run(&Config { cover_rate_hz: 0.0, ..small() }, &p, 6);
        let with = run(&Config { cover_rate_hz: 0.05, ..small() }, &p, 6);
        assert_eq!(without.bandwidth.cover_bytes_total, 0);
        assert!(with.bandwidth.cover_bytes_total > 0);
        assert!(
            with.bandwidth.total_bytes > without.bandwidth.total_bytes,
            "cover traffic must increase total bytes"
        );
        assert!(with.bandwidth.cover_overhead_pct > 0.0);
    }

    #[test]
    fn cover_rate_for_target_pads_up_to_the_target() {
        let cfg = small();
        let r = cover_rate_for_target(&cfg, 1.0);
        // Genuine rate is 1/45 Hz, so cover must supply nearly all of the 1 Hz.
        assert!((r - (1.0 - 1.0 / 45.0)).abs() < 1e-9);
    }

    #[test]
    fn sweep_covers_the_specified_agent_counts() {
        let p = profile();
        let cfg = Config { duration_secs: 2, cores: 8, ..Default::default() };
        let out = sweep(&cfg, &p, 1, 20);
        assert_eq!(out.len(), 3);
        assert_eq!(out.iter().map(|o| o.agents).collect::<Vec<_>>(), vec![1_000, 10_000, 100_000]);
    }
}
