//! Exact discrete-Laplace sampling with no floating-point arithmetic.
//!
//! ## Why not `rand_distr::Laplace`
//!
//! Reaching for an off-the-shelf continuous Laplace sampler here would be
//! wrong for two independent reasons. The first — that Laplace noise is
//! negative half the time and you cannot delay by −3 ms — is handled in
//! [`crate::mechanism`]. The second is this module's subject.
//!
//! A continuous Laplace sampler implemented on floating-point numbers does not
//! implement the Laplace mechanism. Mironov
//! (CCS 2012, "On Significance of the Least Significant Bits for Differential
//! Privacy") showed that the rounding structure of IEEE-754 output makes the
//! set of representable results depend on the true value, so an adversary can
//! often recover it exactly from a single sample — regardless of ε. Every
//! naive `f64` Laplace or Gaussian sampler is affected.
//!
//! The fix used here is the **discrete Laplace** (two-sided geometric)
//! mechanism sampled by the exact algorithm of Canonne, Kamath and Steinke
//! ("The Discrete Gaussian for Differential Privacy", NeurIPS 2020,
//! Algorithms 1-2). It consumes only unbiased random bits and rational
//! arithmetic on integers; no floating-point value ever touches the sampling
//! path. Delays are integers in nanoseconds, which is what a scheduler can
//! actually implement anyway.
//!
//! Floating point *is* used to derive public parameters (the shift `s`, the
//! reported ε). Those are published constants that do not depend on the
//! sensitive value, so they cannot leak through rounding.

use rand::Rng;

/// `Bernoulli(p/q)` from unbiased integer randomness. Requires `p <= q`.
fn bernoulli_rational<R: Rng + ?Sized>(p: u128, q: u128, rng: &mut R) -> bool {
    debug_assert!(q > 0 && p <= q);
    // Uniform over [0, q) by rejection, so the result is exactly uniform
    // rather than modulo-biased.
    let zone = u128::MAX - (u128::MAX % q);
    loop {
        let r = rng.gen::<u128>();
        if r < zone {
            return r % q < p;
        }
    }
}

/// `Bernoulli(exp(-p/q))` for `0 <= p/q <= 1` (CKS20 Algorithm 1).
fn bernoulli_exp_neg_unit<R: Rng + ?Sized>(p: u128, q: u128, rng: &mut R) -> bool {
    debug_assert!(p <= q);
    let mut k: u128 = 1;
    loop {
        // Bernoulli(p / (q*k)); guard the multiplication rather than wrapping.
        let denom = q.checked_mul(k).expect("k stays small: it is geometric with mean < e");
        if !bernoulli_rational(p, denom, rng) {
            return k % 2 == 1;
        }
        k += 1;
    }
}

/// `Bernoulli(exp(-p/q))` for arbitrary non-negative `p/q` (CKS20 Algorithm 1,
/// general case).
fn bernoulli_exp_neg<R: Rng + ?Sized>(p: u128, q: u128, rng: &mut R) -> bool {
    if p <= q {
        return bernoulli_exp_neg_unit(p, q, rng);
    }
    let whole = p / q;
    let frac = p % q;
    // exp(-γ) = exp(-1)^floor(γ) · exp(-{γ})
    for _ in 0..whole {
        if !bernoulli_exp_neg_unit(1, 1, rng) {
            return false;
        }
    }
    bernoulli_exp_neg_unit(frac, q, rng)
}

/// Two-sided geometric (discrete Laplace) with scale `t/s`:
/// `Pr[Y = y] ∝ exp(-|y| · s / t)` (CKS20 Algorithm 2).
///
/// For an ε-DP mechanism on an integer-valued query of sensitivity `Δ`, use
/// `s/t = ε/Δ`, i.e. scale `Δ/ε`.
pub fn discrete_laplace<R: Rng + ?Sized>(s: u128, t: u128, rng: &mut R) -> i128 {
    assert!(s > 0 && t > 0, "discrete Laplace scale must be positive");
    loop {
        // U uniform on {0,...,t-1}
        let u = uniform_below(t, rng);
        if !bernoulli_exp_neg(u, t, rng) {
            continue;
        }
        // V = number of consecutive successes of Bernoulli(exp(-1))
        let mut v: u128 = 0;
        while bernoulli_exp_neg_unit(1, 1, rng) {
            v += 1;
            // The geometric tail is bounded in practice; this guard keeps a
            // pathological RNG from looping forever.
            if v > 10_000 {
                break;
            }
        }
        let x = u.saturating_add(t.saturating_mul(v));
        let y = x / s;
        let negative = rng.gen::<bool>();
        if negative && y == 0 {
            continue;
        }
        return if negative { -(y as i128) } else { y as i128 };
    }
}

fn uniform_below<R: Rng + ?Sized>(n: u128, rng: &mut R) -> u128 {
    let zone = u128::MAX - (u128::MAX % n);
    loop {
        let r = rng.gen::<u128>();
        if r < zone {
            return r % n;
        }
    }
}

/// Exact tail probability `Pr[Y < -shift]` for a discrete Laplace with ratio
/// `α = exp(-s/t)`:
///
/// ```text
/// Pr[Y <= -(shift+1)] = α^(shift+1) / (1 + α)
/// ```
///
/// Used only to *choose* the public shift, never inside sampling.
pub fn negative_tail_probability(alpha: f64, shift: u64) -> f64 {
    alpha.powi(shift as i32 + 1) / (1.0 + alpha)
}

/// The smallest shift `s` with `Pr[s + Y < 0] <= delta`.
///
/// From `α^(s+1)/(1+α) <= δ`:  `s >= ln(δ(1+α))/ln α − 1`.
pub fn shift_for_delta(alpha: f64, delta: f64) -> u64 {
    assert!((0.0..1.0).contains(&alpha), "alpha must be in [0, 1)");
    assert!(delta > 0.0 && delta < 1.0, "delta must be in (0, 1)");
    if alpha == 0.0 {
        return 0;
    }
    let s = (delta * (1.0 + alpha)).ln() / alpha.ln() - 1.0;
    if s <= 0.0 {
        0
    } else {
        s.ceil() as u64
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
    fn bernoulli_rational_matches_its_parameter() {
        let mut r = rng(1);
        let n = 200_000;
        let hits = (0..n).filter(|_| bernoulli_rational(1, 4, &mut r)).count();
        let p = hits as f64 / n as f64;
        assert!((p - 0.25).abs() < 0.01, "got {p}");
    }

    #[test]
    fn bernoulli_exp_neg_matches_its_parameter() {
        let mut r = rng(2);
        for (p, q) in [(1u128, 2u128), (1, 1), (3, 2), (5, 1)] {
            let n = 100_000;
            let hits = (0..n).filter(|_| bernoulli_exp_neg(p, q, &mut r)).count();
            let measured = hits as f64 / n as f64;
            let expected = (-(p as f64) / q as f64).exp();
            assert!(
                (measured - expected).abs() < 0.01,
                "exp(-{p}/{q}): got {measured}, want {expected}"
            );
        }
    }

    /// The sampled distribution must match `Pr[Y=y] ∝ α^|y|`.
    #[test]
    fn discrete_laplace_matches_the_analytic_pmf() {
        let mut r = rng(3);
        // scale t/s = 4  =>  alpha = exp(-1/4)
        let (s, t) = (1u128, 4u128);
        let alpha = (-(s as f64) / t as f64).exp();
        let n = 400_000;

        let mut counts = std::collections::BTreeMap::new();
        for _ in 0..n {
            *counts.entry(discrete_laplace(s, t, &mut r)).or_insert(0usize) += 1;
        }
        let norm = (1.0 - alpha) / (1.0 + alpha);
        for y in -8i128..=8 {
            let measured = *counts.get(&y).unwrap_or(&0) as f64 / n as f64;
            let expected = norm * alpha.powi(y.unsigned_abs() as i32);
            assert!(
                (measured - expected).abs() < 0.005,
                "y={y}: measured {measured}, expected {expected}"
            );
        }
    }

    #[test]
    fn discrete_laplace_is_symmetric() {
        let mut r = rng(4);
        let n = 200_000;
        let mut sum = 0i128;
        for _ in 0..n {
            sum += discrete_laplace(1, 8, &mut r);
        }
        let mean = sum as f64 / n as f64;
        assert!(mean.abs() < 0.1, "mean {mean} should be ~0");
    }

    #[test]
    fn larger_scale_means_more_spread() {
        let mut r = rng(5);
        let spread = |t: u128, r: &mut ChaCha20Rng| {
            let n = 20_000;
            (0..n).map(|_| discrete_laplace(1, t, r).unsigned_abs() as f64).sum::<f64>() / n as f64
        };
        let tight = spread(2, &mut r);
        let loose = spread(32, &mut r);
        assert!(loose > tight * 4.0, "tight {tight}, loose {loose}");
    }

    #[test]
    fn sampling_is_reproducible_from_a_seed() {
        let a: Vec<i128> = (0..50).map(|_| discrete_laplace(1, 10, &mut rng(7))).collect();
        let b: Vec<i128> = (0..50).map(|_| discrete_laplace(1, 10, &mut rng(7))).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn shift_for_delta_achieves_the_target() {
        for &alpha in &[0.1f64, 0.5, 0.9, 0.99] {
            for &delta in &[1e-3f64, 1e-6, 1e-9] {
                let s = shift_for_delta(alpha, delta);
                let tail = negative_tail_probability(alpha, s);
                assert!(tail <= delta, "alpha={alpha} delta={delta}: tail {tail} > delta");
                if s > 0 {
                    // ...and it is the *smallest* such shift.
                    assert!(
                        negative_tail_probability(alpha, s - 1) > delta,
                        "shift {s} is not minimal for alpha={alpha} delta={delta}"
                    );
                }
            }
        }
    }

    /// The empirical clipping rate must not exceed the δ the shift was
    /// chosen for. This is the property the (ε, δ) claim rests on.
    #[test]
    fn empirical_clipping_rate_respects_delta() {
        let mut r = rng(8);
        let (s, t) = (1u128, 4u128); // alpha = exp(-1/4)
        let alpha = (-0.25f64).exp();
        let delta = 1e-3;
        let shift = shift_for_delta(alpha, delta) as i128;

        let n = 200_000;
        let clipped = (0..n).filter(|_| shift + discrete_laplace(s, t, &mut r) < 0).count();
        let rate = clipped as f64 / n as f64;
        assert!(rate <= delta * 3.0, "clipping rate {rate} vs delta {delta}");
    }
}
