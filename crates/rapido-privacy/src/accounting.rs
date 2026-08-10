//! Privacy accounting over repeated releases.
//!
//! An agent does not authenticate once. In Scenario 2 it authenticates every
//! 30-60 s, which is roughly 1,500 releases per day — and the per-release ε
//! composes. An ε reported without saying "per release" is a number nobody can
//! act on, so both the basic and the advanced composition bounds are computed
//! here and both are reported.

use serde::{Deserialize, Serialize};

/// A composed `(ε, δ)` guarantee over `k` releases.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub k_releases: u64,
    pub epsilon_per_release: f64,
    pub delta_per_release: f64,
    /// Basic (sequential) composition: `kε`, `kδ`.
    pub epsilon_basic: f64,
    pub delta_basic: f64,
    /// Advanced composition at the chosen `delta_prime`.
    pub epsilon_advanced: f64,
    pub delta_advanced: f64,
    /// The `δ'` slack advanced composition was evaluated at.
    pub delta_prime: f64,
}

impl Budget {
    /// Compose `k` releases of an `(ε, δ)` mechanism.
    ///
    /// Basic composition is `(kε, kδ)`.
    ///
    /// Advanced composition (Dwork-Rothblum-Vadhan 2010, as stated in Dwork &
    /// Roth Thm 3.20) gives, for any `δ' > 0`,
    ///
    /// ```text
    /// ε' = sqrt(2k ln(1/δ')) · ε + k · ε · (e^ε − 1)
    /// δ' total = kδ + δ'
    /// ```
    ///
    /// The advanced bound only beats the basic one for small ε and large k;
    /// [`Budget::best_epsilon`] reports whichever actually applies rather than
    /// quoting the flattering one.
    pub fn compose(k: u64, epsilon: f64, delta: f64, delta_prime: f64) -> Self {
        assert!(epsilon >= 0.0, "epsilon must be non-negative");
        assert!((0.0..1.0).contains(&delta), "delta must be in [0, 1)");
        assert!(delta_prime > 0.0 && delta_prime < 1.0, "delta' must be in (0, 1)");

        let kf = k as f64;
        let eps_adv = (2.0 * kf * (1.0 / delta_prime).ln()).sqrt() * epsilon
            + kf * epsilon * (epsilon.exp() - 1.0);

        Budget {
            k_releases: k,
            epsilon_per_release: epsilon,
            delta_per_release: delta,
            epsilon_basic: kf * epsilon,
            delta_basic: kf * delta,
            epsilon_advanced: eps_adv,
            delta_advanced: kf * delta + delta_prime,
            delta_prime,
        }
    }

    /// The tighter of the two ε bounds, with the δ that comes with it.
    pub fn best_epsilon(&self) -> (f64, f64) {
        if self.epsilon_advanced < self.epsilon_basic {
            (self.epsilon_advanced, self.delta_advanced)
        } else {
            (self.epsilon_basic, self.delta_basic)
        }
    }

    /// Whether advanced composition helps here at all.
    pub fn advanced_helps(&self) -> bool {
        self.epsilon_advanced < self.epsilon_basic
    }
}

/// Number of releases in a period, given an authentication interval.
pub fn releases_in(period_secs: f64, interval_secs: f64) -> u64 {
    assert!(interval_secs > 0.0, "authentication interval must be positive");
    (period_secs / interval_secs).floor() as u64
}

/// The per-release ε that keeps a whole-day budget under `epsilon_target`, by
/// basic composition. Useful for reporting the parameter a deployment would
/// actually have to pick.
pub fn per_release_epsilon_for_daily_budget(epsilon_target: f64, interval_secs: f64) -> f64 {
    let k = releases_in(86_400.0, interval_secs).max(1);
    epsilon_target / k as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_composition_is_linear() {
        let b = Budget::compose(100, 0.5, 1e-9, 1e-6);
        assert!((b.epsilon_basic - 50.0).abs() < 1e-12);
        assert!((b.delta_basic - 1e-7).abs() < 1e-18);
    }

    #[test]
    fn advanced_composition_beats_basic_for_small_epsilon_and_large_k() {
        let b = Budget::compose(10_000, 0.01, 1e-9, 1e-6);
        assert!(b.advanced_helps(), "advanced {} vs basic {}", b.epsilon_advanced, b.epsilon_basic);
        let (eps, _) = b.best_epsilon();
        assert_eq!(eps, b.epsilon_advanced);
    }

    #[test]
    fn advanced_composition_does_not_help_for_large_epsilon() {
        let b = Budget::compose(10, 2.0, 1e-9, 1e-6);
        assert!(!b.advanced_helps());
        let (eps, _) = b.best_epsilon();
        assert_eq!(eps, b.epsilon_basic);
    }

    /// The number that matters in deployment: a per-release ε of 1.0 is not a
    /// daily ε of 1.0.
    #[test]
    fn a_days_worth_of_authentication_costs_far_more_than_one_epsilon() {
        let k = releases_in(86_400.0, 45.0);
        assert_eq!(k, 1920);
        let b = Budget::compose(k, 1.0, 1e-9, 1e-6);
        let (eps, _) = b.best_epsilon();
        assert!(
            eps > 100.0,
            "per-release epsilon=1.0 over a day composes to {eps}, which is not a privacy guarantee"
        );
    }

    #[test]
    fn per_release_budget_inverts_composition() {
        let eps = per_release_epsilon_for_daily_budget(1.0, 45.0);
        let k = releases_in(86_400.0, 45.0);
        assert!((eps * k as f64 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn zero_epsilon_composes_to_zero() {
        let b = Budget::compose(1_000_000, 0.0, 0.0, 1e-6);
        assert_eq!(b.epsilon_basic, 0.0);
        assert_eq!(b.epsilon_advanced, 0.0);
    }

    #[test]
    fn release_counts() {
        assert_eq!(releases_in(3600.0, 30.0), 120);
        assert_eq!(releases_in(3600.0, 60.0), 60);
    }
}
