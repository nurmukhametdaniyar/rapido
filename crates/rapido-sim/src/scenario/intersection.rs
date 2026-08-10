//! Scenario 1 — intersection burst.
//!
//! `V` vehicles must authenticate to one RSU within a 100 ms window, the
//! deadline a signalized-intersection application has to meet. The RSU is a
//! bounded worker pool; core counts 1/2/4/8 are swept.
//!
//! What this measures is *queueing*, not cryptography. A single verification
//! may be fast, but 100 vehicles arriving inside a 100 ms window against a
//! 1-core verifier is an offered load no amount of pairing optimization
//! rescues. The completion rate within budget is the number that decides
//! whether the deadline is met.

use crate::des::{EventQueue, ServerPool};
use crate::network::{Delivery, NetworkModel};
use crate::stats::{LatencyRecorder, LatencySummary};
use crate::workload::CostProfile;
use rand::Rng;
use rapido_crypto::rng_from_seed;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DEADLINE_NS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Vehicles in the burst.
    pub vehicles: usize,
    /// Verifier cores.
    pub cores: usize,
    /// Deadline every vehicle must finish inside.
    pub deadline_ns: u64,
    /// Window over which vehicles arrive. Zero means a simultaneous burst,
    /// which is the worst case; "all `V` arrive within a 100 ms window" is
    /// modelled by spreading arrivals across the deadline instead.
    pub arrival_window_ns: u64,
    pub network: NetworkModel,
    /// Whether a lost message is retried once.
    pub retry_once: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            vehicles: 50,
            cores: 4,
            deadline_ns: DEFAULT_DEADLINE_NS,
            arrival_window_ns: DEFAULT_DEADLINE_NS,
            network: NetworkModel::default(),
            retry_once: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub vehicles: usize,
    pub cores: usize,
    pub deadline_ns: u64,
    /// Fraction of vehicles that completed within the deadline. **The headline
    /// number.**
    pub completion_rate: f64,
    /// Fraction that never completed at all (lost messages, no retry left).
    pub loss_rate: f64,
    pub latency: LatencySummary,
    pub max_queue_depth: usize,
    pub verifier_utilization: f64,
    pub makespan_ns: u64,
    pub bytes_received: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// A vehicle transmits its presentation.
    Send { vehicle: usize, attempt: u32, sent_ns: u64 },
    /// The presentation reaches the RSU and asks for a core.
    Admit { vehicle: usize, sent_ns: u64 },
    /// A verification finishes, freeing a core.
    ServiceDone { vehicle: usize, sent_ns: u64, service_ns: u64 },
}

/// Run one seed.
pub fn run(config: &Config, profile: &CostProfile, seed: u64) -> Outcome {
    let mut rng = rng_from_seed(seed);
    let mut q: EventQueue<Event> = EventQueue::new();
    let mut pool = ServerPool::new(config.cores);
    let mut latency = LatencyRecorder::new();
    // Mirrors the pool's internal FIFO so a freed core knows which vehicle it
    // is picking up.
    let mut waiting: std::collections::VecDeque<(usize, u64)> = std::collections::VecDeque::new();

    for v in 0..config.vehicles {
        let t = if config.arrival_window_ns == 0 {
            0
        } else {
            rng.gen_range(0..config.arrival_window_ns)
        };
        q.schedule_at(t, Event::Send { vehicle: v, attempt: 0, sent_ns: t });
    }

    let mut completed = 0usize;
    let mut within_deadline = 0usize;
    let mut lost = 0usize;
    let mut bytes_received = 0usize;
    let mut makespan = 0u64;

    while let Some((now, event)) = q.next() {
        match event {
            Event::Send { vehicle, attempt, sent_ns } => {
                match config.network.deliver(profile.presentation_bytes, &mut rng) {
                    Delivery::Lost => {
                        if config.retry_once && attempt == 0 {
                            // One retry after a fixed backoff of one round trip.
                            let backoff = 2 * config.network.mean_delay_ns.max(1);
                            q.schedule_after(backoff, Event::Send { vehicle, attempt: 1, sent_ns });
                        } else {
                            lost += 1;
                        }
                    }
                    Delivery::Delivered { delay_ns, .. } => {
                        bytes_received += profile.presentation_bytes;
                        q.schedule_after(delay_ns, Event::Admit { vehicle, sent_ns });
                    }
                }
            }
            Event::Admit { vehicle, sent_ns } => {
                if pool.offer(now).is_some() {
                    let service_ns = profile.sample_verify(&mut rng);
                    q.schedule_after(
                        service_ns,
                        Event::ServiceDone { vehicle, sent_ns, service_ns },
                    );
                } else {
                    waiting.push_back((vehicle, sent_ns));
                }
            }
            Event::ServiceDone { vehicle: _, sent_ns, service_ns } => {
                let total = now.saturating_sub(sent_ns);
                latency.record(total);
                completed += 1;
                if total <= config.deadline_ns {
                    within_deadline += 1;
                }
                makespan = makespan.max(now);

                if pool.complete(service_ns).is_some() {
                    let (next_vehicle, next_sent) =
                        waiting.pop_front().expect("waiting list mirrors the pool queue");
                    let next_service = profile.sample_verify(&mut rng);
                    q.schedule_after(
                        next_service,
                        Event::ServiceDone {
                            vehicle: next_vehicle,
                            sent_ns: next_sent,
                            service_ns: next_service,
                        },
                    );
                }
            }
        }
    }

    debug_assert!(waiting.is_empty(), "every queued request must eventually be served");
    debug_assert_eq!(completed + lost, config.vehicles, "every vehicle must be accounted for");

    Outcome {
        vehicles: config.vehicles,
        cores: config.cores,
        deadline_ns: config.deadline_ns,
        completion_rate: within_deadline as f64 / config.vehicles as f64,
        loss_rate: lost as f64 / config.vehicles as f64,
        latency: latency.summary(),
        max_queue_depth: pool.max_queue_depth(),
        verifier_utilization: pool.utilization(makespan.max(1)),
        makespan_ns: makespan,
        bytes_received,
        seed,
    }
}

/// Run `n_seeds` independent runs. Every reported scenario uses at least 10, so
/// the confidence interval is over seeds rather than over one lucky run.
pub fn run_many(
    config: &Config,
    profile: &CostProfile,
    n_seeds: u64,
    base_seed: u64,
) -> Vec<Outcome> {
    (0..n_seeds).map(|i| run(config, profile, base_seed + i)).collect()
}

/// The reported sweep: `V ∈ {20, 50, 100}` against 1/2/4/8 cores.
pub fn sweep(base: &Config, profile: &CostProfile, n_seeds: u64, base_seed: u64) -> Vec<Outcome> {
    let mut out = Vec::new();
    for vehicles in [20usize, 50, 100] {
        for cores in [1usize, 2, 4, 8] {
            let cfg = Config { vehicles, cores, ..*base };
            out.extend(run_many(&cfg, profile, n_seeds, base_seed));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::{calibrate, SystemConfig};

    fn profile() -> CostProfile {
        calibrate(&SystemConfig { n_batch: 8, ..Default::default() }, 32, 7).unwrap()
    }

    #[test]
    fn every_vehicle_is_accounted_for() {
        let p = profile();
        let cfg = Config {
            vehicles: 50,
            cores: 4,
            network: NetworkModel::perfect(),
            retry_once: false,
            ..Default::default()
        };
        let o = run(&cfg, &p, 1);
        assert_eq!(o.latency.count as usize + (o.loss_rate * 50.0).round() as usize, 50);
    }

    #[test]
    fn runs_are_reproducible_from_a_seed() {
        let p = profile();
        let cfg = Config::default();
        assert_eq!(run(&cfg, &p, 42), run(&cfg, &p, 42));
    }

    #[test]
    fn different_seeds_give_different_runs() {
        let p = profile();
        let cfg = Config::default();
        assert_ne!(run(&cfg, &p, 1).latency.p99_ns, run(&cfg, &p, 2).latency.p99_ns);
    }

    #[test]
    fn more_cores_never_hurt_and_usually_help() {
        let p = profile();
        let base = Config {
            vehicles: 100,
            arrival_window_ns: 0, // simultaneous burst: the worst case
            network: NetworkModel::perfect(),
            retry_once: false,
            ..Default::default()
        };
        let one = run(&Config { cores: 1, ..base }, &p, 3);
        let eight = run(&Config { cores: 8, ..base }, &p, 3);
        assert!(
            eight.latency.p99_ns <= one.latency.p99_ns,
            "8 cores p99 {} should not exceed 1 core p99 {}",
            eight.latency.p99_ns,
            one.latency.p99_ns
        );
        assert!(eight.max_queue_depth <= one.max_queue_depth);
    }

    #[test]
    fn a_simultaneous_burst_queues_on_one_core() {
        let p = profile();
        let cfg = Config {
            vehicles: 100,
            cores: 1,
            arrival_window_ns: 0,
            network: NetworkModel::perfect(),
            retry_once: false,
            ..Default::default()
        };
        let o = run(&cfg, &p, 4);
        assert!(o.max_queue_depth > 50, "queue depth {}", o.max_queue_depth);
        assert!(o.verifier_utilization > 0.9, "a saturated core should be ~100% busy");
    }

    #[test]
    fn a_lossy_network_costs_completions_when_there_is_no_retry() {
        let p = profile();
        let lossy = NetworkModel { loss_rate: 0.2, ..NetworkModel::default() };
        let cfg = Config { vehicles: 100, network: lossy, retry_once: false, ..Default::default() };
        let o = run(&cfg, &p, 5);
        assert!(o.loss_rate > 0.1, "loss rate {}", o.loss_rate);

        let with_retry = Config { retry_once: true, ..cfg };
        let o2 = run(&with_retry, &p, 5);
        assert!(o2.loss_rate < o.loss_rate, "a retry must recover some losses");
    }

    #[test]
    fn spreading_arrivals_improves_the_completion_rate() {
        let p = profile();
        let base = Config {
            vehicles: 100,
            cores: 2,
            network: NetworkModel::perfect(),
            retry_once: false,
            ..Default::default()
        };
        let burst = run(&Config { arrival_window_ns: 0, ..base }, &p, 6);
        let spread = run(&Config { arrival_window_ns: 100_000_000, ..base }, &p, 6);
        assert!(spread.latency.p99_ns <= burst.latency.p99_ns);
    }

    #[test]
    fn sweep_covers_the_specified_grid() {
        let p = profile();
        let out = sweep(&Config::default(), &p, 2, 100);
        assert_eq!(out.len(), 3 * 4 * 2);
        let cores: std::collections::BTreeSet<usize> = out.iter().map(|o| o.cores).collect();
        assert_eq!(cores, [1usize, 2, 4, 8].into_iter().collect());
    }
}
