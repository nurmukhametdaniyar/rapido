//! Layer 2: differential privacy on response timing.
//!
//! ## Why the mechanism is not "add Laplace noise to the delay"
//!
//! **You cannot delay by −3 ms.** Laplace noise is negative half the time, so
//! half of all releases would have to happen before the computation finished.
//! Any implementation of an unshifted symmetric mechanism must therefore clamp
//! at zero — and clamping destroys the DP guarantee it was supposed to provide,
//! because the clipped mass piles up at exactly the boundary an adversary can
//! observe.
//!
//! The three mechanisms here are implementable as written:
//!
//! | | mechanism | privacy | latency |
//! |---|---|---|---|
//! | **M-PAD** | release at a constant `T_max` | perfect: zero information leaked | always `T_max` |
//! | **M-GEO** | `delay = max(0, s + G)`, `G` two-sided geometric | `(ε, δ)`-DP | unbounded tail, small mean |
//! | **M-BUCKET** | release on a grid of period `q` with geometric slot jitter | `(ε, δ')`-DP, coarser | bounded worst case |
//!
//! M-PAD is the upper bound of the tradeoff and M-GEO the interior; measuring
//! all three is what turns "we add DP noise" into a curve.
//!
//! ## Genuine and dummy traffic share one mechanism instance
//!
//! Cover traffic must pass through the *identical* mechanism instance as real
//! traffic, not a duplicate code path — otherwise the two are distinguishable
//! by their noise, and the cover traffic is worse than useless.
//! [`TimingMechanism::release_delay_ns`] takes an [`EventKind`] purely for
//! accounting and **must not branch on it**; `mechanism_is_blind_to_event_kind`
//! asserts this by construction.

use crate::discrete;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Whether an event carries real work or is cover traffic. Recorded for
/// accounting only; the mechanism never sees a difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    Genuine,
    Cover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MechanismKind {
    /// Fixed padding to a constant release time.
    MPad,
    /// Shifted truncated two-sided geometric.
    MGeo,
    /// Quantized release grid with geometric slot jitter.
    MBucket,
    /// No mechanism at all — the ε = ∞ baseline, needed to show what the
    /// defenses are defending against.
    None,
}

impl MechanismKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MechanismKind::MPad => "m-pad",
            MechanismKind::MGeo => "m-geo",
            MechanismKind::MBucket => "m-bucket",
            MechanismKind::None => "none",
        }
    }
}

impl std::fmt::Display for MechanismKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `(ε, δ)` a mechanism instance actually provides, plus the parameters it
/// was derived from. Every one of these fields travels into the result files:
/// an ε quoted without its δ, its sensitivity, and the shift `s` it was derived
/// under is not a statement anyone can check.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrivacyParams {
    pub epsilon: f64,
    pub delta: f64,
    /// Sensitivity `Δf` in nanoseconds, **measured** from compute-time spread
    /// rather than assumed; see [`crate::sensitivity`].
    pub sensitivity_ns: u64,
    /// The shift `s`, in nanoseconds (M-GEO) or grid slots (M-BUCKET).
    pub shift: u64,
    /// `α = exp(-ε/Δf)`, the geometric ratio.
    pub alpha: f64,
}

/// A per-release timing decision.
pub trait TimingMechanism {
    /// Extra delay, in nanoseconds, to add after the computation finishes.
    ///
    /// Implementations **must not** branch on `kind`.
    fn release_delay_ns<R: Rng + ?Sized>(
        &self,
        compute_ns: u64,
        kind: EventKind,
        rng: &mut R,
    ) -> u64;

    fn kind(&self) -> MechanismKind;

    /// `None` when the mechanism provides no DP guarantee (M-PAD leaks nothing
    /// at all, so ε is not the right description; `MechanismKind::None` leaks
    /// everything).
    fn privacy(&self) -> Option<PrivacyParams>;
}

// --- M-PAD -----------------------------------------------------------------

/// Release at a constant time `T_max >= worst-case compute`.
///
/// Leaks exactly zero information about the computation, because the observable
/// is a constant. The cost is that every response pays worst-case latency. This
/// is the upper bound of the privacy/latency tradeoff, and the point the curve
/// converges to as ε → 0.
#[derive(Debug, Clone, Copy)]
pub struct MPad {
    pub t_max_ns: u64,
}

impl MPad {
    /// Pad to the observed maximum plus a margin, so a compute time longer than
    /// anything seen during calibration does not silently truncate the padding
    /// (which would leak).
    pub fn from_samples(compute_ns: &[u64], margin_ns: u64) -> Self {
        let max = compute_ns.iter().copied().max().unwrap_or(0);
        MPad { t_max_ns: max.saturating_add(margin_ns) }
    }
}

impl TimingMechanism for MPad {
    fn release_delay_ns<R: Rng + ?Sized>(
        &self,
        compute_ns: u64,
        _kind: EventKind,
        _rng: &mut R,
    ) -> u64 {
        // If compute exceeded T_max the padding is exhausted and this release
        // does leak; the overflow is counted by the caller (see `Calibration`).
        self.t_max_ns.saturating_sub(compute_ns)
    }

    fn kind(&self) -> MechanismKind {
        MechanismKind::MPad
    }

    fn privacy(&self) -> Option<PrivacyParams> {
        // ε = 0: the released time is a constant.
        Some(PrivacyParams {
            epsilon: 0.0,
            delta: 0.0,
            sensitivity_ns: 0,
            shift: self.t_max_ns,
            alpha: 0.0,
        })
    }
}

// --- M-GEO -----------------------------------------------------------------

/// Shifted, zero-truncated two-sided geometric delay:
/// `delay = max(0, s + G)` with `G ~ TwoSidedGeometric(ε/Δf)`.
///
/// The shift `s` is chosen so that `Pr[s + G < 0] <= δ`, which is exactly the
/// probability that truncation changes the output. On that event the mechanism
/// differs from the untruncated (ε-DP) one, so the composed guarantee is
/// `(ε, δ)`-DP by the standard "differ on an event of probability ≤ δ"
/// argument. Both parameters and the shift are reported.
#[derive(Debug, Clone, Copy)]
pub struct MGeo {
    /// Rational scale for the sampler: `Pr[G=g] ∝ exp(-|g|·s_num/t_den)`.
    s_num: u128,
    t_den: u128,
    pub params: PrivacyParams,
}

/// Denominator used to turn a floating-point ε into an exact rational for the
/// sampler. 1e-6 resolution in ε is far finer than any reported value.
const EPS_DENOM: u128 = 1_000_000;

impl MGeo {
    /// Build from a measured sensitivity, target ε, and target δ.
    pub fn new(epsilon: f64, delta: f64, sensitivity_ns: u64) -> Self {
        assert!(epsilon > 0.0 && epsilon.is_finite(), "M-GEO needs a finite positive epsilon");
        assert!(delta > 0.0 && delta < 1.0, "delta must be in (0, 1)");
        assert!(sensitivity_ns > 0, "sensitivity must be positive");

        // Want scale Δ/ε, i.e. Pr[G=g] ∝ exp(-|g|·ε/Δ) = exp(-|g|·s_num/t_den).
        let s_num = (epsilon * EPS_DENOM as f64).round().max(1.0) as u128;
        let t_den = sensitivity_ns as u128 * EPS_DENOM;
        let alpha = (-(s_num as f64) / t_den as f64).exp();
        let shift = discrete::shift_for_delta(alpha, delta);

        MGeo {
            s_num,
            t_den,
            params: PrivacyParams { epsilon, delta, sensitivity_ns, shift, alpha },
        }
    }

    /// The mean added delay, for the latency axis of the tradeoff figure.
    /// `E[max(0, s+G)] ≈ s` for the shifts δ forces, and the exact mean of the
    /// untruncated variable is `s`, since `E[G] = 0`.
    pub fn mean_delay_ns(&self) -> f64 {
        self.params.shift as f64
    }
}

impl TimingMechanism for MGeo {
    fn release_delay_ns<R: Rng + ?Sized>(
        &self,
        _compute_ns: u64,
        _kind: EventKind,
        rng: &mut R,
    ) -> u64 {
        let g = discrete::discrete_laplace(self.s_num, self.t_den, rng);
        let shifted = self.params.shift as i128 + g;
        shifted.max(0) as u64
    }

    fn kind(&self) -> MechanismKind {
        MechanismKind::MGeo
    }

    fn privacy(&self) -> Option<PrivacyParams> {
        Some(self.params)
    }
}

// --- M-BUCKET --------------------------------------------------------------

/// Quantized release schedule: releases happen only on a grid of period `q`,
/// with geometric jitter measured in whole grid slots.
///
/// Worst-case latency is bounded by `(max_jitter_slots + 2) · q`, which M-GEO
/// cannot promise. The price is coarser privacy: the sensitivity in slot
/// units is `ceil(Δf / q)`, so a large `q` quantizes away most of the signal
/// but a small `q` needs almost as much noise as M-GEO.
#[derive(Debug, Clone, Copy)]
pub struct MBucket {
    pub quantum_ns: u64,
    /// Jitter is truncated here so worst-case latency is bounded. Truncation
    /// adds to δ; see [`MBucket::truncation_delta`].
    pub max_jitter_slots: u64,
    s_num: u128,
    t_den: u128,
    pub params: PrivacyParams,
}

impl MBucket {
    pub fn new(
        epsilon: f64,
        delta: f64,
        sensitivity_ns: u64,
        quantum_ns: u64,
        max_jitter_slots: u64,
    ) -> Self {
        assert!(quantum_ns > 0, "grid period must be positive");
        assert!(epsilon > 0.0 && epsilon.is_finite(), "M-BUCKET needs a finite positive epsilon");
        assert!(delta > 0.0 && delta < 1.0, "delta must be in (0, 1)");

        // Sensitivity in slots, at least 1 — two inputs one quantum apart can
        // still land in adjacent slots.
        let sensitivity_slots = sensitivity_ns.div_ceil(quantum_ns).max(1);
        let s_num = (epsilon * EPS_DENOM as f64).round().max(1.0) as u128;
        let t_den = sensitivity_slots as u128 * EPS_DENOM;
        let alpha = (-(s_num as f64) / t_den as f64).exp();
        let shift = discrete::shift_for_delta(alpha, delta);

        MBucket {
            quantum_ns,
            max_jitter_slots,
            s_num,
            t_den,
            params: PrivacyParams { epsilon, delta, sensitivity_ns, shift, alpha },
        }
    }

    /// Extra δ contributed by truncating the jitter at `max_jitter_slots`.
    /// Reported alongside the nominal δ; the effective guarantee is
    /// `(ε, δ + this)`.
    pub fn truncation_delta(&self) -> f64 {
        if self.max_jitter_slots <= self.params.shift {
            return 1.0;
        }
        let excess = self.max_jitter_slots - self.params.shift;
        discrete::negative_tail_probability(self.params.alpha, excess.saturating_sub(1))
    }

    /// Worst-case added latency, the guarantee M-GEO cannot make.
    ///
    /// Rounding up to the next grid point costs at most `q - 1`, the mandatory
    /// slot costs `q`, and the jitter costs at most `max_jitter_slots · q`.
    pub fn worst_case_delay_ns(&self) -> u64 {
        (self.max_jitter_slots + 2).saturating_mul(self.quantum_ns)
    }
}

impl TimingMechanism for MBucket {
    fn release_delay_ns<R: Rng + ?Sized>(
        &self,
        compute_ns: u64,
        _kind: EventKind,
        rng: &mut R,
    ) -> u64 {
        let g = discrete::discrete_laplace(self.s_num, self.t_den, rng);
        let jitter = (self.params.shift as i128 + g).clamp(0, self.max_jitter_slots as i128) as u64;
        // Round up to the next grid point, then add whole jitter slots.
        let slots_used = compute_ns.div_ceil(self.quantum_ns) + 1;
        let target = (slots_used + jitter).saturating_mul(self.quantum_ns);
        target.saturating_sub(compute_ns)
    }

    fn kind(&self) -> MechanismKind {
        MechanismKind::MBucket
    }

    fn privacy(&self) -> Option<PrivacyParams> {
        Some(self.params)
    }
}

// --- no mechanism ----------------------------------------------------------

/// The ε = ∞ control: release as soon as the computation finishes. Needed
/// because an attacker-advantage curve is meaningless without the undefended
/// point on it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMechanism;

impl TimingMechanism for NoMechanism {
    fn release_delay_ns<R: Rng + ?Sized>(&self, _c: u64, _k: EventKind, _r: &mut R) -> u64 {
        0
    }
    fn kind(&self) -> MechanismKind {
        MechanismKind::None
    }
    fn privacy(&self) -> Option<PrivacyParams> {
        None
    }
}

/// A mechanism chosen at runtime from a config file.
#[derive(Debug, Clone, Copy)]
pub enum AnyMechanism {
    Pad(MPad),
    Geo(MGeo),
    Bucket(MBucket),
    None(NoMechanism),
}

impl TimingMechanism for AnyMechanism {
    fn release_delay_ns<R: Rng + ?Sized>(
        &self,
        compute_ns: u64,
        kind: EventKind,
        rng: &mut R,
    ) -> u64 {
        match self {
            AnyMechanism::Pad(m) => m.release_delay_ns(compute_ns, kind, rng),
            AnyMechanism::Geo(m) => m.release_delay_ns(compute_ns, kind, rng),
            AnyMechanism::Bucket(m) => m.release_delay_ns(compute_ns, kind, rng),
            AnyMechanism::None(m) => m.release_delay_ns(compute_ns, kind, rng),
        }
    }
    fn kind(&self) -> MechanismKind {
        match self {
            AnyMechanism::Pad(m) => m.kind(),
            AnyMechanism::Geo(m) => m.kind(),
            AnyMechanism::Bucket(m) => m.kind(),
            AnyMechanism::None(m) => m.kind(),
        }
    }
    fn privacy(&self) -> Option<PrivacyParams> {
        match self {
            AnyMechanism::Pad(m) => m.privacy(),
            AnyMechanism::Geo(m) => m.privacy(),
            AnyMechanism::Bucket(m) => m.privacy(),
            AnyMechanism::None(m) => m.privacy(),
        }
    }
}

/// Total observable release time: compute plus the mechanism's delay.
pub fn release_time_ns<M: TimingMechanism, R: Rng + ?Sized>(
    m: &M,
    compute_ns: u64,
    kind: EventKind,
    rng: &mut R,
) -> u64 {
    compute_ns + m.release_delay_ns(compute_ns, kind, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensitivity::Sensitivity;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u64) -> ChaCha20Rng {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        ChaCha20Rng::from_seed(b)
    }

    /// Genuine and cover events must traverse the identical mechanism
    /// instance. Driving both from the same seed must give identical output;
    /// if any implementation branched on `EventKind`, this would fail.
    #[test]
    fn mechanism_is_blind_to_event_kind() {
        let mechanisms: Vec<AnyMechanism> = vec![
            AnyMechanism::Pad(MPad { t_max_ns: 5_000_000 }),
            AnyMechanism::Geo(MGeo::new(1.0, 1e-6, 200_000)),
            AnyMechanism::Bucket(MBucket::new(1.0, 1e-6, 200_000, 100_000, 64)),
            AnyMechanism::None(NoMechanism),
        ];
        for m in &mechanisms {
            for compute in [0u64, 1_000, 250_000, 4_000_000] {
                let genuine = m.release_delay_ns(compute, EventKind::Genuine, &mut rng(42));
                let cover = m.release_delay_ns(compute, EventKind::Cover, &mut rng(42));
                assert_eq!(
                    genuine,
                    cover,
                    "{} branched on EventKind at compute={compute}",
                    m.kind()
                );
            }
        }
    }

    #[test]
    fn m_pad_releases_at_a_constant_time() {
        let m = MPad { t_max_ns: 3_000_000 };
        let mut r = rng(1);
        for compute in [10_000u64, 500_000, 2_999_999] {
            assert_eq!(
                release_time_ns(&m, compute, EventKind::Genuine, &mut r),
                3_000_000,
                "M-PAD must be a constant function of compute time"
            );
        }
    }

    #[test]
    fn m_pad_from_samples_covers_the_observed_maximum() {
        let samples = [100u64, 250, 900, 1_500];
        let m = MPad::from_samples(&samples, 500);
        assert_eq!(m.t_max_ns, 2_000);
        let mut r = rng(2);
        for s in samples {
            assert_eq!(release_time_ns(&m, s, EventKind::Genuine, &mut r), 2_000);
        }
    }

    #[test]
    fn m_geo_delay_is_never_negative_and_averages_the_shift() {
        let m = MGeo::new(1.0, 1e-6, 200_000);
        let mut r = rng(3);
        let n = 20_000;
        let mut sum = 0u128;
        for _ in 0..n {
            let d = m.release_delay_ns(150_000, EventKind::Genuine, &mut r);
            sum += d as u128;
        }
        let mean = sum as f64 / n as f64;
        // Truncation only removes mass below zero, which δ bounds, so the mean
        // sits at (or just above) the shift.
        assert!(
            mean >= m.params.shift as f64 * 0.9 && mean <= m.params.shift as f64 * 1.15,
            "mean {mean} vs shift {}",
            m.params.shift
        );
    }

    #[test]
    fn smaller_epsilon_means_more_noise_and_more_latency() {
        let mut previous = 0.0f64;
        for eps in [5.0f64, 2.0, 1.0, 0.5, 0.1] {
            let m = MGeo::new(eps, 1e-6, 200_000);
            let mean = m.mean_delay_ns();
            assert!(
                mean > previous,
                "epsilon {eps}: mean delay {mean} did not exceed the previous {previous}"
            );
            previous = mean;
        }
    }

    #[test]
    fn m_geo_reports_epsilon_delta_and_shift() {
        let m = MGeo::new(0.5, 1e-9, 300_000);
        let p = m.privacy().unwrap();
        assert_eq!(p.epsilon, 0.5);
        assert_eq!(p.delta, 1e-9);
        assert_eq!(p.sensitivity_ns, 300_000);
        assert!(p.shift > 0, "a meaningful delta forces a positive shift");
        assert!(p.alpha > 0.0 && p.alpha < 1.0);
        // The reported shift really does achieve the reported delta.
        assert!(crate::discrete::negative_tail_probability(p.alpha, p.shift) <= p.delta);
    }

    #[test]
    fn m_bucket_releases_only_on_grid_points() {
        let q = 250_000u64;
        let m = MBucket::new(1.0, 1e-6, 200_000, q, 64);
        let mut r = rng(4);
        for compute in [1u64, 100_000, 249_999, 250_000, 700_000] {
            let t = release_time_ns(&m, compute, EventKind::Genuine, &mut r);
            assert_eq!(t % q, 0, "release at {t} is not on the {q}ns grid");
            assert!(t > compute, "release must be after the computation finishes");
        }
    }

    #[test]
    fn m_bucket_bounds_worst_case_latency() {
        let m = MBucket::new(1.0, 1e-6, 200_000, 100_000, 32);
        let mut r = rng(5);
        let bound = m.worst_case_delay_ns();
        for _ in 0..5_000 {
            let d = m.release_delay_ns(150_000, EventKind::Genuine, &mut r);
            assert!(d <= bound, "delay {d} exceeded the {bound}ns bound");
        }
    }

    #[test]
    fn m_bucket_reports_its_truncation_delta() {
        let generous = MBucket::new(1.0, 1e-6, 200_000, 100_000, 4096);
        let tight = MBucket::new(1.0, 1e-6, 200_000, 100_000, 8);
        assert!(
            generous.truncation_delta() < tight.truncation_delta(),
            "truncating harder must cost more delta"
        );
    }

    #[test]
    fn no_mechanism_adds_nothing_and_claims_nothing() {
        let m = NoMechanism;
        let mut r = rng(6);
        assert_eq!(m.release_delay_ns(12_345, EventKind::Genuine, &mut r), 0);
        assert!(m.privacy().is_none());
    }

    /// End to end with a sensitivity that was measured rather than assumed.
    #[test]
    fn sensitivity_drives_the_noise_scale() {
        let tight: Vec<u64> = (0..1000).map(|i| 100_000 + (i % 50)).collect();
        let wide: Vec<u64> = (0..1000).map(|i| 100_000 + (i % 50) * 4_000).collect();
        let s_tight = Sensitivity::from_samples(&tight);
        let s_wide = Sensitivity::from_samples(&wide);
        assert!(s_wide.delta_f_ns > s_tight.delta_f_ns);

        let m_tight = MGeo::new(1.0, 1e-6, s_tight.delta_f_ns);
        let m_wide = MGeo::new(1.0, 1e-6, s_wide.delta_f_ns);
        assert!(
            m_wide.mean_delay_ns() > m_tight.mean_delay_ns(),
            "a wider compute-time spread must cost more delay"
        );
    }
}
