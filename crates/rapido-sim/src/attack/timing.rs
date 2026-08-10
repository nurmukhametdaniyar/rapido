//! Empirical timing adversary.
//!
//! Turns "we add DP noise" into "we add DP noise, and here is the measured
//! attacker advantage as a function of ε and the number of observations `N`".
//!
//! ## Setup
//!
//! Two agent populations differ in a sensitive attribute that changes how long
//! their verification takes — in RAPIDO terms, the number of hidden attributes
//! in a Mode B presentation, which directly changes the MSM size. Compute-time
//! samples for each population are **measured**, not modelled; the adversary
//! then sees `N` release times drawn from one population and must say which.
//!
//! ## Attacks
//!
//! * [`likelihood_ratio_score`] — a likelihood-ratio test against **empirical,
//!   binned** estimates of both release-time distributions.
//! * [`mean_score`] — a threshold test on the sample mean. Weak, cheap, and
//!   what a real adversary would try first.
//!
//! ## This is not an upper bound on attacker advantage
//!
//! The likelihood-ratio test is Neyman-Pearson optimal only against the *true*
//! densities. What is computed here is a ratio of histogram estimates, and a
//! histogram is a poor density estimate when the noise is wide relative to the
//! bin width — exactly the regime small ε puts the mechanism in. The bin width
//! is therefore chosen adaptively from the training data (Freedman-Diaconis),
//! but the estimate is still not the true density.
//!
//! Measured consequence: the gradient-boosted classifier in
//! `analysis/attack_classifier.py` **beats this test** at small ε, because
//! summary statistics over a window aggregate information that a per-sample
//! binned ratio discards. Any advantage curve derived from this module must
//! therefore be read as the **maximum over all attacks tried**, not as this
//! test's number alone.

use rapido_privacy::mechanism::{EventKind, TimingMechanism};
use serde::{Deserialize, Serialize};

/// One observed population: the release times an adversary sees.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub label: String,
    pub release_ns: Vec<u64>,
}

/// Empirical distribution over release times, quantized into bins.
///
/// Binning is what makes a likelihood ratio computable from samples at all. The
/// bin width is a property of the *adversary*, not the defence, and is reported
/// with the result.
#[derive(Debug, Clone)]
pub struct EmpiricalPmf {
    bin_ns: u64,
    counts: std::collections::HashMap<u64, u64>,
    total: u64,
    n_bins_seen: usize,
}

impl EmpiricalPmf {
    pub fn build(samples: &[u64], bin_ns: u64) -> Self {
        assert!(bin_ns > 0, "bin width must be positive");
        let mut counts = std::collections::HashMap::new();
        for s in samples {
            *counts.entry(s / bin_ns).or_insert(0u64) += 1;
        }
        let n_bins_seen = counts.len();
        EmpiricalPmf { bin_ns, counts, total: samples.len() as u64, n_bins_seen }
    }

    /// Laplace-smoothed probability, so an unseen bin does not produce an
    /// infinite log-likelihood and hand the adversary a free win.
    pub fn prob(&self, value_ns: u64) -> f64 {
        let bin = value_ns / self.bin_ns;
        let c = *self.counts.get(&bin).unwrap_or(&0) as f64;
        (c + 1.0) / (self.total as f64 + self.n_bins_seen.max(1) as f64 + 1.0)
    }

    pub fn log_prob(&self, value_ns: u64) -> f64 {
        self.prob(value_ns).ln()
    }
}

/// Log-likelihood ratio of `observations` under population 1 vs population 0.
/// Positive means "population 1".
pub fn likelihood_ratio_score(observations: &[u64], p0: &EmpiricalPmf, p1: &EmpiricalPmf) -> f64 {
    observations.iter().map(|o| p1.log_prob(*o) - p0.log_prob(*o)).sum()
}

/// Sample mean, the statistic a naive threshold attacker uses.
pub fn mean_score(observations: &[u64]) -> f64 {
    if observations.is_empty() {
        return 0.0;
    }
    observations.iter().sum::<u64>() as f64 / observations.len() as f64
}

/// Compute-time pools split into **disjoint** train and test halves.
///
/// The adversary calibrates on `train*` and is scored on `test*`. Without this
/// split a learned attacker can memorize the specific values in the trace and
/// report an advantage that does not generalize — which is exactly what the
/// non-monotonic advantage-vs-N curve in the first run was a symptom of.
#[derive(Debug, Clone, Copy)]
pub struct SplitPools<'a> {
    pub train0: &'a [u64],
    pub train1: &'a [u64],
    pub test0: &'a [u64],
    pub test1: &'a [u64],
}

impl<'a> SplitPools<'a> {
    /// Split each population in half. The halves share no sample.
    pub fn halve(pop0: &'a [u64], pop1: &'a [u64]) -> Self {
        let (a, b) = pop0.split_at(pop0.len() / 2);
        let (c, d) = pop1.split_at(pop1.len() / 2);
        SplitPools { train0: a, train1: c, test0: b, test1: d }
    }
}

fn advantage_of(auc: f64) -> f64 {
    (2.0 * auc - 1.0).abs()
}

/// Which attack was run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attack {
    LikelihoodRatio,
    MeanThreshold,
}

impl Attack {
    pub fn as_str(&self) -> &'static str {
        match self {
            Attack::LikelihoodRatio => "likelihood-ratio",
            Attack::MeanThreshold => "mean-threshold",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackResult {
    pub attack: Attack,
    /// Observations the adversary is given per decision.
    pub n_observations: usize,
    pub trials: usize,
    pub auc: f64,
    /// Percentile-bootstrap 95% CI on the AUC, over the trial scores.
    pub auc_ci_lo: f64,
    pub auc_ci_hi: f64,
    /// `|2·AUC − 1|`, in `[0, 1]`.
    pub advantage: f64,
    /// The same bootstrap interval mapped through `|2x-1|`. Reported because an
    /// advantage near the noise floor is meaningless without it: 0.04 [0.00,
    /// 0.09] and 0.04 [0.03, 0.05] are very different claims.
    pub advantage_ci_lo: f64,
    pub advantage_ci_hi: f64,
    /// Compute-time samples the adversary trained on. **Disjoint** from the
    /// evaluation pool.
    pub train_pool: usize,
    /// Compute-time samples the adversary was evaluated against.
    pub test_pool: usize,
    /// The ε the defence claimed, if any.
    pub epsilon: Option<f64>,
    pub delta: Option<f64>,
    pub mechanism: String,
    /// Mean release latency the defence cost, in nanoseconds — the other axis
    /// of the tradeoff figure.
    pub mean_release_ns: f64,
    /// Histogram bin width the adversary used, chosen adaptively. Reported
    /// because it is a property of the attack, not of the defence.
    pub bin_ns: u64,
    pub seed: u64,
}

/// Freedman-Diaconis bin width: `2 * IQR * n^(-1/3)`.
///
/// Chosen adaptively rather than fixed, because the release-time spread grows
/// by orders of magnitude as ε shrinks, and a bin width tuned for one ε makes
/// the attack artificially weak at another — which would show up as a defence
/// that works when it is really a measurement artifact.
pub fn freedman_diaconis_bin_ns(samples: &[u64]) -> u64 {
    if samples.len() < 4 {
        return 1;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let q = |p: f64| sorted[(((sorted.len() - 1) as f64) * p).round() as usize] as f64;
    let iqr = q(0.75) - q(0.25);
    if iqr <= 0.0 {
        return 1;
    }
    let width = 2.0 * iqr / (samples.len() as f64).cbrt();
    (width.round() as u64).max(1)
}

/// Percentile bootstrap CI for an AUC, resampling the two score vectors.
///
/// Deterministically seeded so the interval is reproducible from the same
/// scores.
pub fn bootstrap_auc_ci(pos: &[f64], neg: &[f64], resamples: usize, seed: u64) -> (f64, f64) {
    use rand::Rng as _;
    if pos.is_empty() || neg.is_empty() {
        return (0.5, 0.5);
    }
    let mut rng = rapido_crypto::rng_from_seed(seed);
    let mut aucs = Vec::with_capacity(resamples);
    let mut bp = vec![0.0; pos.len()];
    let mut bn = vec![0.0; neg.len()];
    for _ in 0..resamples {
        for slot in bp.iter_mut() {
            *slot = pos[rng.gen_range(0..pos.len())];
        }
        for slot in bn.iter_mut() {
            *slot = neg[rng.gen_range(0..neg.len())];
        }
        aucs.push(crate::stats::auc(&bp, &bn));
    }
    aucs.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let q = |p: f64| aucs[(((aucs.len() - 1) as f64) * p).round() as usize];
    (q(0.025), q(0.975))
}

/// Bootstrap resamples used for every advantage interval.
pub const AUC_BOOTSTRAP_RESAMPLES: usize = 2000;

/// Trials are added in batches until the advantage interval is at least this
/// tight, or [`MAX_TRIALS`] is reached. Sizing by CI width rather than a
/// constant is what makes a near-zero advantage at small epsilon trustworthy:
/// those estimates need far more samples than an advantage near 1.0.
pub const TARGET_CI_HALF_WIDTH: f64 = 0.03;
pub const TRIAL_BATCH: usize = 500;
pub const MAX_TRIALS: usize = 12_000;

/// Apply a timing mechanism to a set of measured compute times, producing the
/// release times an adversary would observe.
///
/// Genuine and cover events go through the same instance; see
/// `rapido_privacy::mechanism`.
pub fn apply_mechanism<M: TimingMechanism, R: rand::Rng + ?Sized>(
    mechanism: &M,
    compute_ns: &[u64],
    n_samples: usize,
    rng: &mut R,
) -> Vec<u64> {
    (0..n_samples)
        .map(|_| {
            let c = compute_ns[rng.gen_range(0..compute_ns.len())];
            c + mechanism.release_delay_ns(c, EventKind::Genuine, rng)
        })
        .collect()
}

/// Run one attack and report its AUC.
///
/// The adversary is given a *training* sample from each population to build its
/// likelihood model, then judged on fresh observations. Training on the same
/// data it is scored on would overstate its advantage.
#[allow(clippy::too_many_arguments)]
pub fn run_attack<M: TimingMechanism, R: rand::Rng + ?Sized>(
    attack: Attack,
    mechanism: &M,
    pools: &SplitPools<'_>,
    n_observations: usize,
    trials: usize,
    train_samples: usize,
    seed: u64,
    rng: &mut R,
) -> AttackResult {
    let (compute_pop0_ns, compute_pop1_ns) = (pools.test0, pools.test1);
    let train0 = apply_mechanism(mechanism, pools.train0, train_samples, rng);
    let train1 = apply_mechanism(mechanism, pools.train1, train_samples, rng);

    // Bin width from the pooled training data, so the adversary is not
    // handicapped at the epsilon values where the noise is widest.
    let mut pooled = train0.clone();
    pooled.extend_from_slice(&train1);
    let bin_ns = freedman_diaconis_bin_ns(&pooled);

    let p0 = EmpiricalPmf::build(&train0, bin_ns);
    let p1 = EmpiricalPmf::build(&train1, bin_ns);

    let mut scores_pop1 = Vec::with_capacity(trials);
    let mut scores_pop0 = Vec::with_capacity(trials);
    let mut release_sum = 0f64;
    let mut release_n = 0usize;

    // Adaptive: keep adding batches until the interval is tight enough. `trials`
    // is the floor, MAX_TRIALS the ceiling.
    let mut budget = trials.max(TRIAL_BATCH);
    loop {
        while scores_pop1.len() < budget {
            let obs1 = apply_mechanism(mechanism, compute_pop1_ns, n_observations, rng);
            let obs0 = apply_mechanism(mechanism, compute_pop0_ns, n_observations, rng);
            release_sum += obs1.iter().chain(&obs0).sum::<u64>() as f64;
            release_n += obs1.len() + obs0.len();

            let (s1, s0) = match attack {
                Attack::LikelihoodRatio => (
                    likelihood_ratio_score(&obs1, &p0, &p1),
                    likelihood_ratio_score(&obs0, &p0, &p1),
                ),
                Attack::MeanThreshold => (mean_score(&obs1), mean_score(&obs0)),
            };
            scores_pop1.push(s1);
            scores_pop0.push(s0);
        }
        let (lo, hi) =
            bootstrap_auc_ci(&scores_pop1, &scores_pop0, AUC_BOOTSTRAP_RESAMPLES, seed ^ 0xC1);
        let half = (advantage_of(hi) - advantage_of(lo)).abs() / 2.0;
        if half <= TARGET_CI_HALF_WIDTH || scores_pop1.len() >= MAX_TRIALS {
            break;
        }
        budget = (budget + TRIAL_BATCH).min(MAX_TRIALS);
    }

    let auc = crate::stats::auc(&scores_pop1, &scores_pop0);
    let (auc_lo, auc_hi) =
        bootstrap_auc_ci(&scores_pop1, &scores_pop0, AUC_BOOTSTRAP_RESAMPLES, seed ^ 0xC1);
    let (adv_lo, adv_hi) = {
        let (a, b) = (advantage_of(auc_lo), advantage_of(auc_hi));
        (a.min(b), a.max(b))
    };
    let privacy = mechanism.privacy();
    AttackResult {
        attack,
        n_observations,
        trials: scores_pop1.len(),
        auc,
        auc_ci_lo: auc_lo,
        auc_ci_hi: auc_hi,
        advantage: crate::stats::advantage_from_auc(auc),
        advantage_ci_lo: adv_lo,
        advantage_ci_hi: adv_hi,
        train_pool: pools.train0.len() + pools.train1.len(),
        test_pool: pools.test0.len() + pools.test1.len(),
        epsilon: privacy.map(|p| p.epsilon),
        delta: privacy.map(|p| p.delta),
        mechanism: mechanism.kind().to_string(),
        mean_release_ns: if release_n == 0 { 0.0 } else { release_sum / release_n as f64 },
        bin_ns,
        seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapido_crypto::rng_from_seed;
    use rapido_privacy::mechanism::{MGeo, MPad, NoMechanism};

    /// Two clearly separated compute-time populations.
    fn populations() -> (Vec<u64>, Vec<u64>) {
        let p0: Vec<u64> = (0..2_000).map(|i| 1_000_000 + (i % 50) * 200).collect();
        let p1: Vec<u64> = (0..2_000).map(|i| 1_400_000 + (i % 50) * 200).collect();
        (p0, p1)
    }

    /// Without a defence, the adversary should win outright. A test suite whose
    /// attacker never succeeds proves nothing about the defence.
    #[test]
    fn an_undefended_system_is_fully_distinguishable() {
        let (p0, p1) = populations();
        let mut rng = rng_from_seed(1);
        let r = run_attack(
            Attack::LikelihoodRatio,
            &NoMechanism,
            &SplitPools::halve(&p0, &p1),
            8,
            400,
            4_000,
            1,
            &mut rng,
        );
        assert!(r.advantage > 0.95, "undefended advantage {}", r.advantage);
    }

    /// M-PAD releases at a constant time, so there is nothing left to observe.
    #[test]
    fn constant_padding_reduces_the_adversary_to_guessing() {
        let (p0, p1) = populations();
        let mut all: Vec<u64> = p0.clone();
        all.extend(&p1);
        let m = MPad::from_samples(&all, 100_000);
        let mut rng = rng_from_seed(2);
        let r = run_attack(
            Attack::LikelihoodRatio,
            &m,
            &SplitPools::halve(&p0, &p1),
            32,
            400,
            4_000,
            2,
            &mut rng,
        );
        assert!(r.advantage < 0.05, "M-PAD advantage {}", r.advantage);
    }

    /// The defining shape of the tradeoff: advantage falls as ε falls.
    #[test]
    fn advantage_decreases_as_epsilon_decreases() {
        let (p0, p1) = populations();
        let sensitivity = 500_000u64;
        let mut results = Vec::new();
        for eps in [5.0f64, 1.0, 0.1] {
            let m = MGeo::new(eps, 1e-6, sensitivity);
            let mut rng = rng_from_seed(10);
            results.push((
                eps,
                run_attack(
                    Attack::LikelihoodRatio,
                    &m,
                    &SplitPools::halve(&p0, &p1),
                    4,
                    300,
                    3_000,
                    10,
                    &mut rng,
                ),
            ));
        }
        let strong_eps = results[0].1.advantage;
        let weak_eps = results[2].1.advantage;
        assert!(
            weak_eps < strong_eps,
            "epsilon=0.1 advantage {weak_eps} should be below epsilon=5.0 advantage {strong_eps}"
        );
        // ...and the latency cost moves the other way.
        assert!(results[2].1.mean_release_ns > results[0].1.mean_release_ns);
    }

    /// More observations recover advantage that one observation does not give.
    #[test]
    fn advantage_increases_with_the_number_of_observations() {
        let (p0, p1) = populations();
        let m = MGeo::new(1.0, 1e-6, 500_000);
        let mut advantages = Vec::new();
        for n in [1usize, 8, 64] {
            let mut rng = rng_from_seed(20);
            advantages.push(
                run_attack(
                    Attack::LikelihoodRatio,
                    &m,
                    &SplitPools::halve(&p0, &p1),
                    n,
                    300,
                    3_000,
                    20,
                    &mut rng,
                )
                .advantage,
            );
        }
        assert!(
            advantages[2] > advantages[0],
            "N=64 advantage {} should exceed N=1 advantage {}",
            advantages[2],
            advantages[0]
        );
    }

    #[test]
    fn the_likelihood_ratio_is_at_least_as_strong_as_a_mean_threshold() {
        let (p0, p1) = populations();
        let m = MGeo::new(1.0, 1e-6, 500_000);
        let mut rng = rng_from_seed(30);
        let lr = run_attack(
            Attack::LikelihoodRatio,
            &m,
            &SplitPools::halve(&p0, &p1),
            16,
            400,
            4_000,
            30,
            &mut rng,
        );
        let mut rng = rng_from_seed(30);
        let mt = run_attack(
            Attack::MeanThreshold,
            &m,
            &SplitPools::halve(&p0, &p1),
            16,
            400,
            4_000,
            30,
            &mut rng,
        );
        assert!(
            lr.advantage >= mt.advantage - 0.1,
            "LR {} should not be much weaker than the mean test {}",
            lr.advantage,
            mt.advantage
        );
    }

    #[test]
    fn identical_populations_yield_no_advantage() {
        let (p0, _) = populations();
        let mut rng = rng_from_seed(40);
        let r = run_attack(
            Attack::LikelihoodRatio,
            &NoMechanism,
            &SplitPools::halve(&p0, &p0),
            16,
            400,
            4_000,
            40,
            &mut rng,
        );
        assert!(r.advantage < 0.1, "advantage against identical populations: {}", r.advantage);
    }

    #[test]
    fn smoothing_prevents_an_unseen_bin_from_dominating() {
        let pmf = EmpiricalPmf::build(&[1_000, 2_000, 3_000], 1_000);
        assert!(pmf.prob(999_999) > 0.0, "an unseen bin must have positive probability");
        assert!(pmf.log_prob(999_999).is_finite());
    }

    /// A calibrated attacker cannot do *worse* with more observations. If this
    /// fails, the attack is overfitting its evaluation set — which is exactly
    /// what the first, un-split run of this experiment was doing.
    ///
    /// Allowance is the two intervals overlapping: adjacent points whose CIs
    /// overlap are not evidence of a real decrease.
    #[test]
    fn advantage_is_monotone_in_observation_count() {
        let (p0, p1) = populations();
        let pools = SplitPools::halve(&p0, &p1);
        for eps in [0.5f64, 1.0, 2.0] {
            let m = MGeo::new(eps, 1e-6, 500_000);
            let mut previous: Option<AttackResult> = None;
            for n in [1usize, 4, 16, 64] {
                let mut rng = rng_from_seed(700 + n as u64);
                let r =
                    run_attack(Attack::LikelihoodRatio, &m, &pools, n, 500, 4_000, 700, &mut rng);
                if let Some(prev) = &previous {
                    let dropped = r.advantage < prev.advantage;
                    let intervals_overlap = r.advantage_ci_hi >= prev.advantage_ci_lo;
                    assert!(
                        !dropped || intervals_overlap,
                        "eps={eps}: advantage fell from {:.3} [{:.3}, {:.3}] at N={} to \
                         {:.3} [{:.3}, {:.3}] at N={n}, with non-overlapping intervals",
                        prev.advantage,
                        prev.advantage_ci_lo,
                        prev.advantage_ci_hi,
                        prev.n_observations,
                        r.advantage,
                        r.advantage_ci_lo,
                        r.advantage_ci_hi,
                    );
                }
                previous = Some(r);
            }
        }
    }

    /// The train and test pools must not share a single compute-time sample.
    #[test]
    fn split_pools_are_disjoint() {
        let (p0, p1) = populations();
        let pools = SplitPools::halve(&p0, &p1);
        assert_eq!(pools.train0.len() + pools.test0.len(), p0.len());
        assert_eq!(pools.train1.len() + pools.test1.len(), p1.len());
        // Slices carved from one array by `split_at` cannot overlap.
        let t0 = pools.train0.as_ptr_range();
        let e0 = pools.test0.as_ptr_range();
        assert!(t0.end <= e0.start || e0.end <= t0.start);
    }

    /// Every advantage must arrive with an interval that brackets it.
    #[test]
    fn advantage_carries_a_bracketing_interval() {
        let (p0, p1) = populations();
        let pools = SplitPools::halve(&p0, &p1);
        let m = MGeo::new(1.0, 1e-6, 500_000);
        let mut rng = rng_from_seed(801);
        let r = run_attack(Attack::LikelihoodRatio, &m, &pools, 8, 500, 4_000, 801, &mut rng);
        assert!(r.advantage_ci_lo <= r.advantage && r.advantage <= r.advantage_ci_hi);
        assert!(r.auc_ci_lo <= r.auc && r.auc <= r.auc_ci_hi);
        assert!(r.train_pool > 0 && r.test_pool > 0);
        // Adaptive sizing must have run at least the requested floor.
        assert!(r.trials >= 500);
    }

    #[test]
    fn results_are_reproducible() {
        let (p0, p1) = populations();
        let m = MGeo::new(1.0, 1e-6, 500_000);
        let run = || {
            let mut rng = rng_from_seed(50);
            run_attack(
                Attack::LikelihoodRatio,
                &m,
                &SplitPools::halve(&p0, &p1),
                8,
                100,
                1_000,
                50,
                &mut rng,
            )
        };
        assert_eq!(run(), run());
    }
}
