//! Revocation variants R0 / R1 / R2.
//!
//! The three occupy different points on a *lookup cost* vs *revocation latency*
//! vs *memory* surface, and all three are measured:
//!
//! * **R0 — epoch only.** `cert.epoch == current_epoch`. An integer comparison,
//!   so the lookup itself costs nanoseconds. Its real price is not time but
//!   **revocation delay**: a credential revoked one instant after an epoch
//!   boundary stays valid for a full epoch `T` (default 10 minutes). That is a
//!   security cost, not a footnote — see
//!   [`EpochOnly::worst_case_revocation_latency_ns`].
//! * **R1 — CRL.** Exact membership against a revocation list. No false
//!   positives, memory linear in `|R|`.
//! * **R2 — Bloom filter.** Sub-linear memory, but a false positive denies
//!   service to an agent that was never revoked. The measured false-positive
//!   rate is reported alongside the memory saving.

use rapido_core::{Epoch, EpochClock};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationMode {
    R0,
    R1,
    R2,
}

impl RevocationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationMode::R0 => "r0-epoch",
            RevocationMode::R1 => "r1-crl",
            RevocationMode::R2 => "r2-bloom",
        }
    }
}

impl std::fmt::Display for RevocationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A revocation check a verifier performs per presentation.
pub trait RevocationCheck {
    /// `true` if the credential must be rejected.
    fn is_revoked(&self, credential_id: &[u8], epoch: Epoch) -> bool;
    /// Bytes the verifier must hold resident.
    fn memory_bytes(&self) -> usize;
    fn mode(&self) -> RevocationMode;
}

// --- R0 --------------------------------------------------------------------

/// Epoch-only revocation: valid iff the certificate is for the current epoch.
#[derive(Debug, Clone, Copy)]
pub struct EpochOnly {
    pub current: Epoch,
    pub clock: EpochClock,
}

impl EpochOnly {
    pub fn new(current: Epoch, clock: EpochClock) -> Self {
        EpochOnly { current, clock }
    }

    /// The security cost of R0: an agent revoked immediately after an epoch
    /// boundary remains able to authenticate for a full epoch.
    pub fn worst_case_revocation_latency_ns(&self) -> u64 {
        self.clock.worst_case_revocation_latency_ns()
    }

    /// Expected latency for a revocation request arriving uniformly at random
    /// within an epoch.
    pub fn mean_revocation_latency_ns(&self) -> u64 {
        self.clock.epoch_ns / 2
    }
}

impl RevocationCheck for EpochOnly {
    fn is_revoked(&self, _credential_id: &[u8], epoch: Epoch) -> bool {
        epoch != self.current
    }
    fn memory_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
    }
    fn mode(&self) -> RevocationMode {
        RevocationMode::R0
    }
}

// --- R1 --------------------------------------------------------------------

/// Exact certificate revocation list, backed by a hash set.
#[derive(Debug, Clone, Default)]
pub struct Crl {
    set: HashSet<Vec<u8>>,
    entry_len: usize,
}

impl Crl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entries<'a, I: IntoIterator<Item = &'a [u8]>>(entries: I) -> Self {
        let mut c = Crl::new();
        for e in entries {
            c.insert(e);
        }
        c
    }

    pub fn insert(&mut self, credential_id: &[u8]) {
        self.entry_len = credential_id.len();
        self.set.insert(credential_id.to_vec());
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl RevocationCheck for Crl {
    fn is_revoked(&self, credential_id: &[u8], _epoch: Epoch) -> bool {
        self.set.contains(credential_id)
    }
    fn memory_bytes(&self) -> usize {
        // Keys plus the table's own per-slot overhead. HashSet keeps load
        // factor around 7/8, and each RawTable slot stores a Vec header
        // (ptr, cap, len) plus a control byte.
        let per_entry = self.entry_len + core::mem::size_of::<Vec<u8>>() + 1;
        (self.set.len() * per_entry * 8) / 7
    }
    fn mode(&self) -> RevocationMode {
        RevocationMode::R1
    }
}

/// Linear-scan CRL, kept so the cost of the naive implementation at
/// `|R| = 10^6` can be reported rather than assumed away as a hash set.
#[derive(Debug, Clone, Default)]
pub struct LinearCrl {
    entries: Vec<Vec<u8>>,
}

impl LinearCrl {
    pub fn with_entries<'a, I: IntoIterator<Item = &'a [u8]>>(entries: I) -> Self {
        LinearCrl { entries: entries.into_iter().map(|e| e.to_vec()).collect() }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl RevocationCheck for LinearCrl {
    fn is_revoked(&self, credential_id: &[u8], _epoch: Epoch) -> bool {
        self.entries.iter().any(|e| e == credential_id)
    }
    fn memory_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.len() + core::mem::size_of::<Vec<u8>>()).sum()
    }
    fn mode(&self) -> RevocationMode {
        RevocationMode::R1
    }
}

// --- R2 --------------------------------------------------------------------

/// Bloom filter over revoked credential identifiers.
///
/// A false positive rejects an agent that was never revoked; the rate is a
/// tunable denial-of-service probability, and it is reported, not hidden.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    n_bits: usize,
    n_hashes: u32,
    inserted: usize,
}

impl BloomFilter {
    /// Size the filter for `n` expected entries at target false-positive rate
    /// `p`, using the standard optimum `m = -n ln p / (ln 2)^2`,
    /// `k = (m/n) ln 2`.
    pub fn with_capacity(n: usize, p: f64) -> Self {
        assert!(p > 0.0 && p < 1.0, "false-positive target must be in (0, 1)");
        let n_eff = n.max(1) as f64;
        let m = (-n_eff * p.ln() / (core::f64::consts::LN_2 * core::f64::consts::LN_2)).ceil();
        let n_bits = (m as usize).max(64);
        let k = ((m / n_eff) * core::f64::consts::LN_2).round().max(1.0) as u32;
        BloomFilter { bits: vec![0u64; n_bits.div_ceil(64)], n_bits, n_hashes: k, inserted: 0 }
    }

    /// Kirsch-Mitzenmacher double hashing: two SHA-256-derived words generate
    /// all `k` indices, instead of `k` independent hashes.
    fn indices(&self, item: &[u8]) -> impl Iterator<Item = usize> + '_ {
        let d: [u8; 32] = Sha256::digest(item).into();
        let h1 = u64::from_le_bytes(d[0..8].try_into().expect("8 bytes"));
        let h2 = u64::from_le_bytes(d[8..16].try_into().expect("8 bytes")) | 1;
        let n_bits = self.n_bits as u64;
        (0..self.n_hashes)
            .map(move |i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % n_bits) as usize)
    }

    pub fn insert(&mut self, item: &[u8]) {
        let idx: Vec<usize> = self.indices(item).collect();
        for i in idx {
            self.bits[i / 64] |= 1u64 << (i % 64);
        }
        self.inserted += 1;
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        self.indices(item).all(|i| self.bits[i / 64] & (1u64 << (i % 64)) != 0)
    }

    pub fn n_bits(&self) -> usize {
        self.n_bits
    }
    pub fn n_hashes(&self) -> u32 {
        self.n_hashes
    }
    pub fn inserted(&self) -> usize {
        self.inserted
    }

    /// Analytic false-positive rate at the current fill level:
    /// `(1 - e^{-kn/m})^k`.
    pub fn expected_false_positive_rate(&self) -> f64 {
        let k = self.n_hashes as f64;
        let n = self.inserted as f64;
        let m = self.n_bits as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

impl RevocationCheck for BloomFilter {
    fn is_revoked(&self, credential_id: &[u8], _epoch: Epoch) -> bool {
        self.contains(credential_id)
    }
    fn memory_bytes(&self) -> usize {
        self.bits.len() * 8
    }
    fn mode(&self) -> RevocationMode {
        RevocationMode::R2
    }
}

/// A `(current-epoch AND not-listed)` composite, which is what a deployment
/// would actually run: R0 alone cannot revoke within an epoch.
#[derive(Debug, Clone)]
pub struct EpochAnd<C: RevocationCheck> {
    pub epoch: EpochOnly,
    pub list: C,
}

impl<C: RevocationCheck> RevocationCheck for EpochAnd<C> {
    fn is_revoked(&self, credential_id: &[u8], epoch: Epoch) -> bool {
        self.epoch.is_revoked(credential_id, epoch) || self.list.is_revoked(credential_id, epoch)
    }
    fn memory_bytes(&self) -> usize {
        self.epoch.memory_bytes() + self.list.memory_bytes()
    }
    fn mode(&self) -> RevocationMode {
        self.list.mode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(i: usize) -> Vec<u8> {
        Sha256::digest(i.to_be_bytes()).to_vec()
    }

    #[test]
    fn r0_accepts_only_the_current_epoch() {
        let r = EpochOnly::new(Epoch(7), EpochClock::from_minutes(10));
        assert!(!r.is_revoked(b"anything", Epoch(7)));
        assert!(r.is_revoked(b"anything", Epoch(6)));
        assert!(r.is_revoked(b"anything", Epoch(8)));
    }

    #[test]
    fn r0_revocation_latency_is_a_full_epoch() {
        let r = EpochOnly::new(Epoch(0), EpochClock::from_minutes(10));
        assert_eq!(r.worst_case_revocation_latency_ns(), 600_000_000_000);
        assert_eq!(r.mean_revocation_latency_ns(), 300_000_000_000);
    }

    #[test]
    fn r1_is_exact() {
        let ids: Vec<Vec<u8>> = (0..1000).map(id).collect();
        let crl = Crl::with_entries(ids.iter().map(|v| v.as_slice()));
        for i in 0..1000 {
            assert!(crl.is_revoked(&id(i), Epoch(0)));
        }
        for i in 1000..2000 {
            assert!(!crl.is_revoked(&id(i), Epoch(0)), "R1 must have no false positives");
        }
        assert_eq!(crl.len(), 1000);
    }

    #[test]
    fn linear_and_hash_crl_agree() {
        let ids: Vec<Vec<u8>> = (0..200).map(id).collect();
        let hash = Crl::with_entries(ids.iter().map(|v| v.as_slice()));
        let linear = LinearCrl::with_entries(ids.iter().map(|v| v.as_slice()));
        for i in 0..400 {
            assert_eq!(hash.is_revoked(&id(i), Epoch(0)), linear.is_revoked(&id(i), Epoch(0)));
        }
    }

    #[test]
    fn r2_has_no_false_negatives() {
        let mut b = BloomFilter::with_capacity(10_000, 0.01);
        for i in 0..10_000 {
            b.insert(&id(i));
        }
        for i in 0..10_000 {
            assert!(b.contains(&id(i)), "Bloom filter must never have a false negative");
        }
    }

    #[test]
    fn r2_false_positive_rate_is_near_the_target() {
        let n = 20_000usize;
        let target = 0.01;
        let mut b = BloomFilter::with_capacity(n, target);
        for i in 0..n {
            b.insert(&id(i));
        }
        let trials = 100_000usize;
        let fp = (n..n + trials).filter(|&i| b.contains(&id(i))).count();
        let measured = fp as f64 / trials as f64;
        // Allow a factor of two around the analytic prediction; the point is
        // that the filter behaves as designed, not that it hits it exactly.
        assert!(measured < target * 2.0, "measured FP rate {measured} far exceeds target {target}");
        let predicted = b.expected_false_positive_rate();
        assert!(predicted < target * 2.0, "analytic FP rate {predicted} off target");
    }

    #[test]
    fn r2_uses_less_memory_than_r1() {
        let n = 100_000usize;
        let ids: Vec<Vec<u8>> = (0..n).map(id).collect();
        let crl = Crl::with_entries(ids.iter().map(|v| v.as_slice()));
        let mut bloom = BloomFilter::with_capacity(n, 0.001);
        for i in &ids {
            bloom.insert(i);
        }
        assert!(
            bloom.memory_bytes() < crl.memory_bytes() / 4,
            "bloom {} vs crl {}",
            bloom.memory_bytes(),
            crl.memory_bytes()
        );
    }

    #[test]
    fn composite_rejects_on_either_condition() {
        let ids: Vec<Vec<u8>> = (0..10).map(id).collect();
        let c = EpochAnd {
            epoch: EpochOnly::new(Epoch(3), EpochClock::default()),
            list: Crl::with_entries(ids.iter().map(|v| v.as_slice())),
        };
        assert!(!c.is_revoked(&id(50), Epoch(3)));
        assert!(c.is_revoked(&id(50), Epoch(2)), "wrong epoch");
        assert!(c.is_revoked(&id(5), Epoch(3)), "listed");
    }
}
