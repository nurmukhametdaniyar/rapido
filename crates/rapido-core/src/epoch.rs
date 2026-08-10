//! Epoch arithmetic. Underpins revocation variant R0 and the connectivity-loss
//! simulation scenario.
//!
//! An epoch is a fixed-length wall-clock window. Credentials are valid only in
//! the epoch they were issued for, which is what makes revocation O(1) — and
//! also what bounds revocation *latency* at one full epoch length. Both sides
//! of that tradeoff are measured; see `rapido-sim` Scenario 3.

use serde::{Deserialize, Serialize};

/// Epoch index. Monotonic, starts at 0 at the system genesis instant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Epoch(pub u64);

impl Epoch {
    pub const fn index(&self) -> u64 {
        self.0
    }
    pub const fn next(&self) -> Epoch {
        Epoch(self.0 + 1)
    }
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maps time (in nanoseconds since genesis) to epoch indices.
///
/// Deterministic and clock-free by design: the simulator drives it with virtual
/// time so runs are reproducible from a seed alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochClock {
    /// Epoch length `T` in nanoseconds. Default throughout: 10 minutes.
    pub epoch_ns: u64,
}

impl EpochClock {
    pub const DEFAULT_EPOCH_SECS: u64 = 600;

    pub fn from_secs(secs: u64) -> Self {
        assert!(secs > 0, "epoch length must be positive");
        EpochClock { epoch_ns: secs * 1_000_000_000 }
    }

    pub fn from_minutes(minutes: u64) -> Self {
        Self::from_secs(minutes * 60)
    }

    pub fn epoch_at(&self, t_ns: u64) -> Epoch {
        Epoch(t_ns / self.epoch_ns)
    }

    /// Nanoseconds from `t_ns` until the epoch rolls over.
    pub fn time_to_rollover(&self, t_ns: u64) -> u64 {
        self.epoch_ns - (t_ns % self.epoch_ns)
    }

    /// Worst-case revocation latency under R0: a credential revoked just after
    /// an epoch boundary stays valid until the next one.
    pub fn worst_case_revocation_latency_ns(&self) -> u64 {
        self.epoch_ns
    }
}

impl Default for EpochClock {
    fn default() -> Self {
        Self::from_secs(Self::DEFAULT_EPOCH_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_boundaries() {
        let c = EpochClock::from_secs(600);
        assert_eq!(c.epoch_at(0), Epoch(0));
        assert_eq!(c.epoch_at(599_999_999_999), Epoch(0));
        assert_eq!(c.epoch_at(600_000_000_000), Epoch(1));
        assert_eq!(c.time_to_rollover(0), 600_000_000_000);
    }

    #[test]
    fn worst_case_latency_is_one_epoch() {
        let c = EpochClock::from_minutes(10);
        assert_eq!(c.worst_case_revocation_latency_ns(), 600 * 1_000_000_000);
    }
}
