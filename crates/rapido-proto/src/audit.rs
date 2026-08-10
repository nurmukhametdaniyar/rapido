//! Append-only audit log over de-anonymization events.
//!
//! Each entry commits to the previous entry's hash, so any edit to history
//! invalidates every subsequent link. This does not prevent an authority from
//! discarding the log wholesale — only from rewriting it undetectably. The
//! chain buys tamper-evidence, not availability.

use rapido_core::{dst, Error, Result, Transcript};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn hash_document(bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(dst::AUDIT.as_bytes());
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// One de-anonymization event: who asked, when, under what authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub timestamp_ns: u64,
    /// Indices of the authorities that produced partial decryptions.
    pub authority_set: Vec<u32>,
    /// Hash of the authorization document (warrant, court order, ...).
    pub authorization_hash: Hash,
    /// Hash of the ciphertext that was opened.
    pub ciphertext_hash: Hash,
    /// Whether the opened element resolved to a registered agent.
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub index: u64,
    pub event: Event,
    pub prev: Hash,
    pub hash: Hash,
}

/// A hash chain of audit entries.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<Entry>,
}

/// The chain's genesis link.
pub const GENESIS: Hash = [0u8; 32];

impl AuditLog {
    pub fn new() -> Self {
        AuditLog { entries: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Hash of the most recent entry — the value an external witness would
    /// publish to make truncation detectable.
    pub fn head(&self) -> Hash {
        self.entries.last().map(|e| e.hash).unwrap_or(GENESIS)
    }

    fn link_hash(index: u64, event: &Event, prev: &Hash) -> Hash {
        let mut t = Transcript::new(dst::AUDIT);
        t.push_u64(index);
        t.push_bytes(prev);
        t.push_u64(event.timestamp_ns);
        t.push_usize(event.authority_set.len());
        for a in &event.authority_set {
            t.push_u32(*a);
        }
        t.push_bytes(&event.authorization_hash);
        t.push_bytes(&event.ciphertext_hash);
        t.push_bytes(&[event.resolved as u8]);
        Sha256::digest(t.as_bytes()).into()
    }

    pub fn append(&mut self, event: Event) -> &Entry {
        let index = self.entries.len() as u64;
        let prev = self.head();
        let hash = Self::link_hash(index, &event, &prev);
        self.entries.push(Entry { index, event, prev, hash });
        self.entries.last().expect("just pushed")
    }

    /// Recompute the whole chain. Returns the index of the first broken link.
    pub fn verify(&self) -> Result<()> {
        let mut prev = GENESIS;
        for (i, e) in self.entries.iter().enumerate() {
            if e.index != i as u64 || e.prev != prev {
                return Err(Error::BrokenChain(i));
            }
            if Self::link_hash(e.index, &e.event, &e.prev) != e.hash {
                return Err(Error::BrokenChain(i));
            }
            prev = e.hash;
        }
        Ok(())
    }

    /// Bytes the chain occupies in memory, for the storage figures.
    pub fn size_bytes(&self) -> usize {
        self.entries
            .iter()
            .map(|e| 8 + 8 + 4 * e.event.authority_set.len() + 32 + 32 + 1 + 32 + 32)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(i: u64) -> Event {
        Event {
            timestamp_ns: 1_000 * i,
            authority_set: vec![0, 2, 3],
            authorization_hash: hash_document(format!("warrant-{i}").as_bytes()),
            ciphertext_hash: hash_document(format!("ct-{i}").as_bytes()),
            resolved: true,
        }
    }

    fn chain(n: u64) -> AuditLog {
        let mut log = AuditLog::new();
        for i in 0..n {
            log.append(event(i));
        }
        log
    }

    #[test]
    fn empty_chain_verifies() {
        assert!(AuditLog::new().verify().is_ok());
        assert_eq!(AuditLog::new().head(), GENESIS);
    }

    #[test]
    fn appended_chain_verifies() {
        let log = chain(1000);
        assert_eq!(log.len(), 1000);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn tampering_with_an_event_breaks_the_chain() {
        let mut log = chain(64);
        log.entries[20].event.resolved = false;
        assert!(matches!(log.verify(), Err(Error::BrokenChain(20))));
    }

    #[test]
    fn recomputing_one_hash_still_breaks_the_next_link() {
        // An attacker who edits an entry *and* fixes its own hash still fails,
        // because entry 21 commits to entry 20's original hash.
        let mut log = chain(64);
        log.entries[20].event.timestamp_ns = 0;
        log.entries[20].hash =
            AuditLog::link_hash(20, &log.entries[20].event, &log.entries[20].prev);
        assert!(matches!(log.verify(), Err(Error::BrokenChain(21))));
    }

    #[test]
    fn reordering_entries_is_detected() {
        let mut log = chain(16);
        log.entries.swap(3, 9);
        assert!(log.verify().is_err());
    }

    #[test]
    fn truncation_is_detectable_only_against_a_published_head() {
        // Truncation leaves a self-consistent chain — this is a real limitation
        // of a bare hash chain, and the test states it rather than hides it.
        let full = chain(32);
        let published_head = full.head();
        let mut truncated = full.clone();
        truncated.entries.truncate(20);
        assert!(truncated.verify().is_ok(), "a truncated chain is internally consistent");
        assert_ne!(truncated.head(), published_head, "but its head no longer matches");
    }

    #[test]
    fn distinct_events_produce_distinct_hashes() {
        let mut log = AuditLog::new();
        let a = log.append(event(1)).hash;
        let b = log.append(event(2)).hash;
        assert_ne!(a, b);
    }
}
