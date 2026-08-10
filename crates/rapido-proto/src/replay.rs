//! Replay protection: a nonce cache with epoch-scoped eviction.
//!
//! A verifier must reject a presentation it has already seen. Because every
//! presentation is bound to the epoch it was made in, entries can be dropped
//! wholesale when the epoch rolls over rather than expired individually — the
//! cache never grows beyond two epochs' worth of traffic.

use rapido_core::{Epoch, Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Nonce cache keyed by (epoch, 16-byte presentation digest).
///
/// Digests are truncated to 128 bits: a collision would let one presentation
/// suppress an unrelated one, and at `2^64` presentations per epoch — orders of
/// magnitude beyond the busiest load modelled in `rapido-sim` Scenario 2 — that
/// probability is negligible. Storing full 32-byte digests would double the
/// memory reported in the results for no practical gain.
#[derive(Debug, Clone)]
pub struct NonceCache {
    current_epoch: Epoch,
    current: HashSet<[u8; 16]>,
    /// Retained so a presentation arriving just after an epoch boundary is
    /// still caught rather than silently accepted twice.
    previous: HashSet<[u8; 16]>,
    max_entries_per_epoch: usize,
}

impl NonceCache {
    pub fn new(epoch: Epoch, max_entries_per_epoch: usize) -> Self {
        NonceCache {
            current_epoch: epoch,
            current: HashSet::new(),
            previous: HashSet::new(),
            max_entries_per_epoch,
        }
    }

    pub fn digest(presentation_bytes: &[u8]) -> [u8; 16] {
        let d: [u8; 32] = Sha256::digest(presentation_bytes).into();
        d[..16].try_into().expect("16 bytes")
    }

    pub fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn memory_bytes(&self) -> usize {
        // 16-byte key plus one control byte per slot, at HashSet's ~7/8 load.
        (self.len() * 17 * 8) / 7
    }

    /// Roll to `epoch`, dropping everything older than one epoch.
    pub fn advance_to(&mut self, epoch: Epoch) {
        if epoch <= self.current_epoch {
            return;
        }
        if epoch.index() == self.current_epoch.index() + 1 {
            self.previous = core::mem::take(&mut self.current);
        } else {
            // Skipped one or more epochs: nothing retained can still be live.
            self.previous.clear();
            self.current.clear();
        }
        self.current_epoch = epoch;
    }

    /// Record a presentation. `Err(Replay)` if it has been seen this epoch or
    /// the previous one.
    pub fn check_and_insert(&mut self, epoch: Epoch, presentation_bytes: &[u8]) -> Result<()> {
        self.advance_to(epoch);
        if epoch < self.current_epoch {
            // Stale epoch; the epoch check (R0) rejects it anyway, but be
            // explicit rather than inserting into a window we no longer keep.
            return Err(Error::EpochMismatch {
                got: epoch.index(),
                want: self.current_epoch.index(),
            });
        }
        let d = Self::digest(presentation_bytes);
        if self.current.contains(&d) || self.previous.contains(&d) {
            return Err(Error::Replay);
        }
        if self.current.len() >= self.max_entries_per_epoch {
            return Err(Error::InvalidParameter("nonce cache: per-epoch capacity exceeded".into()));
        }
        self.current.insert(d);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_is_accepted_and_the_second_is_a_replay() {
        let mut c = NonceCache::new(Epoch(1), 1 << 20);
        assert!(c.check_and_insert(Epoch(1), b"presentation-A").is_ok());
        assert!(matches!(c.check_and_insert(Epoch(1), b"presentation-A"), Err(Error::Replay)));
        assert!(c.check_and_insert(Epoch(1), b"presentation-B").is_ok());
    }

    #[test]
    fn a_replay_across_an_epoch_boundary_is_still_caught() {
        let mut c = NonceCache::new(Epoch(1), 1 << 20);
        c.check_and_insert(Epoch(1), b"P").unwrap();
        assert!(matches!(c.check_and_insert(Epoch(2), b"P"), Err(Error::Replay)));
    }

    #[test]
    fn entries_are_evicted_after_two_epochs() {
        let mut c = NonceCache::new(Epoch(1), 1 << 20);
        c.check_and_insert(Epoch(1), b"P").unwrap();
        c.advance_to(Epoch(2));
        c.advance_to(Epoch(3));
        assert!(c.check_and_insert(Epoch(3), b"P").is_ok(), "entry should have been evicted");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn skipping_epochs_clears_the_whole_cache() {
        let mut c = NonceCache::new(Epoch(1), 1 << 20);
        c.check_and_insert(Epoch(1), b"P").unwrap();
        c.advance_to(Epoch(10));
        assert!(c.is_empty());
    }

    #[test]
    fn a_stale_epoch_is_rejected() {
        let mut c = NonceCache::new(Epoch(5), 1 << 20);
        assert!(matches!(
            c.check_and_insert(Epoch(4), b"P"),
            Err(Error::EpochMismatch { got: 4, want: 5 })
        ));
    }

    #[test]
    fn capacity_is_enforced() {
        let mut c = NonceCache::new(Epoch(1), 4);
        for i in 0..4u8 {
            c.check_and_insert(Epoch(1), &[i]).unwrap();
        }
        assert!(c.check_and_insert(Epoch(1), b"overflow").is_err());
    }

    #[test]
    fn memory_scales_with_entry_count() {
        let mut small = NonceCache::new(Epoch(1), 1 << 20);
        let mut large = NonceCache::new(Epoch(1), 1 << 20);
        for i in 0..1_000u32 {
            small.check_and_insert(Epoch(1), &i.to_be_bytes()).unwrap();
        }
        for i in 0..10_000u32 {
            large.check_and_insert(Epoch(1), &i.to_be_bytes()).unwrap();
        }
        assert!(large.memory_bytes() > small.memory_bytes() * 8);
    }
}
