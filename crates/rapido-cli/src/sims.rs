//! Scenario and attack runners that produce committed result files.

use rapido_privacy::{
    accounting::Budget,
    mechanism::{AnyMechanism, MBucket, MGeo, MPad, NoMechanism, TimingMechanism},
    Sensitivity,
};
use rapido_sim::attack::{cover as cover_attack, timing as timing_attack};
use rapido_sim::scenario::{connectivity, intersection, linkability, metropolitan};
use rapido_sim::workload::{calibrate, CostProfile, SystemConfig};
use serde::{Deserialize, Serialize};

/// Independent seeds per configuration. Ten is the floor everywhere, so every
/// reported scenario number carries an interval over seeds.
pub const DEFAULT_SEEDS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario1Report {
    pub calibration: CalibrationSummary,
    pub runs: Vec<intersection::Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario2Report {
    pub calibration: CalibrationSummary,
    pub runs: Vec<metropolitan::Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario3Report {
    pub epoch_sweep: Vec<connectivity::Outcome>,
    pub lookahead_sweep: Vec<connectivity::Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario4Report {
    pub runs: Vec<linkability::Outcome>,
}

/// What the simulator's cost model was built from, carried into every result
/// file so the provenance of the service times is never in doubt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationSummary {
    pub config: SystemConfig,
    pub n_samples: usize,
    pub mean_verify_ns: f64,
    pub median_verify_ns: f64,
    pub presentation_bytes: usize,
    pub issuance_download_bytes: usize,
    pub throughput_per_core_hz: f64,
}

impl CalibrationSummary {
    fn from(profile: &CostProfile) -> Self {
        let mut sorted = profile.verify_ns.clone();
        sorted.sort_unstable();
        CalibrationSummary {
            config: profile.config.clone(),
            n_samples: profile.n_calibration_samples(),
            mean_verify_ns: profile.mean_verify_ns(),
            median_verify_ns: sorted[sorted.len() / 2] as f64,
            presentation_bytes: profile.presentation_bytes,
            issuance_download_bytes: profile.issuance_download_bytes,
            throughput_per_core_hz: profile.throughput_per_core_hz(),
        }
    }
}

pub fn scenario1(
    system: &SystemConfig,
    seeds: u64,
    calibration_samples: usize,
    quick: bool,
) -> rapido_core::Result<Scenario1Report> {
    let profile = calibrate(system, calibration_samples, 0xC0FFEE)?;
    let base = intersection::Config::default();
    let runs = if quick {
        intersection::run_many(&base, &profile, seeds.min(3), 1)
    } else {
        intersection::sweep(&base, &profile, seeds, 1)
    };
    Ok(Scenario1Report { calibration: CalibrationSummary::from(&profile), runs })
}

pub fn scenario2(
    system: &SystemConfig,
    seeds: u64,
    calibration_samples: usize,
    quick: bool,
) -> rapido_core::Result<Scenario2Report> {
    let profile = calibrate(system, calibration_samples, 0xC0FFEE)?;
    let base = metropolitan::Config {
        duration_secs: if quick { 10 } else { 120 },
        cores: 8,
        ..Default::default()
    };
    let mut runs = if quick {
        metropolitan::run_many(&metropolitan::Config { agents: 1_000, ..base }, &profile, 1, 1)
    } else {
        metropolitan::sweep(&base, &profile, seeds.min(3), 1)
    };

    // A cover-traffic variant, so the bandwidth table has both rows.
    let with_cover = metropolitan::Config { cover_rate_hz: 0.05, agents: 10_000, ..base };
    runs.extend(metropolitan::run_many(&with_cover, &profile, if quick { 1 } else { 3 }, 500));

    Ok(Scenario2Report { calibration: CalibrationSummary::from(&profile), runs })
}

pub fn scenario3(seeds: u64, quick: bool) -> Scenario3Report {
    let base = connectivity::Config {
        agents: if quick { 1_000 } else { 20_000 },
        n_batch: 100,
        ..Default::default()
    };
    Scenario3Report {
        epoch_sweep: connectivity::sweep(&base, if quick { 1 } else { seeds }, 1),
        lookahead_sweep: connectivity::sweep_lookahead(
            &connectivity::Config { outage_minutes: 60, ..base },
            if quick { 1 } else { seeds },
            100,
        ),
    }
}

pub fn scenario4(seeds: u64, quick: bool) -> rapido_core::Result<Scenario4Report> {
    let cfg = linkability::Config {
        agents: if quick { 8 } else { 25 },
        sessions_per_agent: if quick { 3 } else { 6 },
        trials: if quick { 500 } else { 5_000 },
        ..Default::default()
    };
    Ok(Scenario4Report { runs: linkability::run_many(&cfg, if quick { 1 } else { seeds }, 1)? })
}

// --- attacks ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAttackReport {
    /// Measured verification times for the two populations the adversary is
    /// trying to tell apart.
    pub population_0: PopulationSummary,
    pub population_1: PopulationSummary,
    pub sensitivity: Sensitivity,
    pub results: Vec<timing_attack::AttackResult>,
    /// Composition over a day of authentication, for each ε.
    pub daily_budgets: Vec<Budget>,
}

/// Release-time traces, one entry per mechanism configuration.
///
/// Written to a sibling file so the Python learned-classifier attack in
/// `analysis/attack_classifier.py` can run on the **same defended release
/// times** the Rust attacks saw, rather than re-implementing the
/// discrete-Laplace sampler in Python where it could silently diverge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingTraces {
    pub sensitivity_ns: u64,
    pub traces: Vec<MechanismTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MechanismTrace {
    /// `none`, `m-pad`, `m-geo`, `m-bucket`.
    pub mechanism: String,
    /// `None` for mechanisms that do not have an epsilon.
    pub epsilon: Option<f64>,
    pub delta: Option<f64>,
    /// Release times drawn from the **training** half of the compute-time
    /// samples. The learned classifier fits on these.
    pub train_population_0_ns: Vec<u64>,
    pub train_population_1_ns: Vec<u64>,
    /// Release times drawn from the **evaluation** half. Disjoint from the
    /// training half at the level of the underlying compute-time samples, so a
    /// classifier cannot memorize values it will later be scored on.
    pub test_population_0_ns: Vec<u64>,
    pub test_population_1_ns: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationSummary {
    pub label: String,
    pub config: SystemConfig,
    pub n_samples: usize,
    pub mean_ns: f64,
    pub median_ns: f64,
}

/// The Layer 2 experiment: measured attacker advantage against the timing
/// defences, as a function of ε and the number of observations.
///
/// The two populations differ in the number of **hidden** BBS+ attributes,
/// which is a genuine sensitive property (how much of your credential you are
/// withholding) and which really does change verification time, because it sets
/// the MSM size. The compute-time samples are measured, not modelled.
pub fn timing_attack(
    seeds: u64,
    quick: bool,
) -> rapido_core::Result<(TimingAttackReport, TimingTraces)> {
    let n_samples = if quick { 200 } else { 2_000 };

    // Population 0 discloses most of its attributes; population 1 hides them.
    let cfg0 = SystemConfig {
        mode: rapido_proto::Mode::B,
        n_attributes: 16,
        n_disclosed: 14,
        escrow: rapido_proto::escrow::EscrowMode::E0,
        ..Default::default()
    };
    let cfg1 = SystemConfig { n_disclosed: 0, ..cfg0.clone() };

    let p0 = calibrate(&cfg0, n_samples, 0xA0)?;
    let p1 = calibrate(&cfg1, n_samples, 0xA1)?;

    // Δf comes from the observed spread across *both* populations, which is the
    // range the mechanism actually has to cover.
    let mut all = p0.verify_ns.clone();
    all.extend(&p1.verify_ns);
    let sensitivity = Sensitivity::from_samples(&all);

    // Disjoint train/test halves of the measured compute-time samples. Every
    // attack — the Rust ones here and the Python classifier — calibrates on the
    // train half and is scored on the test half.
    let pools = timing_attack::SplitPools::halve(&p0.verify_ns, &p1.verify_ns);

    let mut results = Vec::new();
    let mut daily_budgets = Vec::new();
    let observation_counts: &[usize] = if quick { &[1, 16] } else { &[1, 4, 16, 64, 256] };
    let epsilons: &[f64] = if quick { &[1.0] } else { &[0.1, 0.5, 1.0, 2.0, 5.0] };
    let trials = if quick { 200 } else { 1_000 };
    let train = if quick { 1_000 } else { 5_000 };

    // The ε = ∞ control and the perfect-privacy control both belong on the
    // curve; without them the middle is uninterpretable.
    let mut mechanisms: Vec<(String, AnyMechanism, Option<f64>)> =
        vec![("none".into(), AnyMechanism::None(NoMechanism), None)];
    mechanisms.push(("m-pad".into(), AnyMechanism::Pad(MPad::from_samples(&all, 100_000)), None));
    for &eps in epsilons {
        mechanisms.push((
            format!("m-geo-eps{eps}"),
            AnyMechanism::Geo(MGeo::new(eps, 1e-6, sensitivity.delta_f_ns)),
            Some(eps),
        ));
        mechanisms.push((
            format!("m-bucket-eps{eps}"),
            AnyMechanism::Bucket(MBucket::new(
                eps,
                1e-6,
                sensitivity.delta_f_ns,
                sensitivity.delta_f_ns.max(1),
                64,
            )),
            Some(eps),
        ));
        daily_budgets.push(Budget::compose(
            rapido_privacy::accounting::releases_in(86_400.0, 45.0),
            eps,
            1e-6,
            1e-6,
        ));
    }

    // Release traces for the Python learned classifier, sampled from the same
    // mechanism instances the Rust attacks use.
    let trace_len = if quick { 500 } else { 4_000 };
    let mut traces = Vec::with_capacity(mechanisms.len());
    for (_label, mechanism, eps) in &mechanisms {
        let mut trng = rapido_crypto::rng_from_seed(0xACE1);
        traces.push(MechanismTrace {
            mechanism: mechanism.kind().to_string(),
            epsilon: *eps,
            delta: mechanism.privacy().map(|p| p.delta),
            train_population_0_ns: timing_attack::apply_mechanism(
                mechanism,
                pools.train0,
                trace_len,
                &mut trng,
            ),
            train_population_1_ns: timing_attack::apply_mechanism(
                mechanism,
                pools.train1,
                trace_len,
                &mut trng,
            ),
            test_population_0_ns: timing_attack::apply_mechanism(
                mechanism,
                pools.test0,
                trace_len,
                &mut trng,
            ),
            test_population_1_ns: timing_attack::apply_mechanism(
                mechanism,
                pools.test1,
                trace_len,
                &mut trng,
            ),
        });
    }

    for (_label, mechanism, _eps) in &mechanisms {
        for &n_obs in observation_counts {
            for attack in
                [timing_attack::Attack::LikelihoodRatio, timing_attack::Attack::MeanThreshold]
            {
                for seed in 0..seeds.min(if quick { 1 } else { 3 }) {
                    let mut rng = rapido_crypto::rng_from_seed(0xD0 + seed);
                    results.push(timing_attack::run_attack(
                        attack, mechanism, &pools, n_obs, trials, train, seed, &mut rng,
                    ));
                }
            }
        }
    }

    let summarize = |label: &str, p: &CostProfile| {
        let mut sorted = p.verify_ns.clone();
        sorted.sort_unstable();
        PopulationSummary {
            label: label.into(),
            config: p.config.clone(),
            n_samples: sorted.len(),
            mean_ns: p.mean_verify_ns(),
            median_ns: sorted[sorted.len() / 2] as f64,
        }
    };

    Ok((
        TimingAttackReport {
            population_0: summarize("disclose-14-of-16", &p0),
            population_1: summarize("disclose-0-of-16", &p1),
            sensitivity,
            results,
            daily_budgets,
        },
        TimingTraces { sensitivity_ns: sensitivity.delta_f_ns, traces },
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverAttackReport {
    pub presentation_bytes: usize,
    pub results: Vec<cover_attack::Outcome>,
}

pub fn cover_attack(quick: bool) -> rapido_core::Result<CoverAttackReport> {
    // Use the real Mode A presentation size, so the bandwidth figures are in
    // bytes this protocol actually sends.
    let profile = calibrate(&SystemConfig { n_batch: 8, ..Default::default() }, 16, 0xB0)?;
    let base = cover_attack::Config {
        message_bytes: profile.presentation_bytes,
        trials: if quick { 100 } else { 1_000 },
        ..Default::default()
    };
    let rates: &[f64] = if quick {
        &[0.0, 5.0, 50.0]
    } else {
        &[0.0, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0]
    };
    Ok(CoverAttackReport {
        presentation_bytes: profile.presentation_bytes,
        results: cover_attack::sweep(&base, rates, 1),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkabilityAttackReport {
    pub runs: Vec<linkability::Outcome>,
}

pub fn linkability_attack(seeds: u64, quick: bool) -> rapido_core::Result<LinkabilityAttackReport> {
    Ok(LinkabilityAttackReport { runs: scenario4(seeds, quick)?.runs })
}
