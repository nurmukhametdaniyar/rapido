//! Domain separation tags.
//!
//! Every protocol context gets its own DST. A DST is *never* reused across
//! contexts: a signature produced for one context must not verify in another.
//! The `all()` list exists so a test can assert global uniqueness.

/// A domain separation tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dst(pub &'static [u8]);

impl Dst {
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
    pub fn as_str(&self) -> &'static str {
        core::str::from_utf8(self.0).expect("DSTs are ASCII by construction")
    }
}

/// Hash-to-curve suite ID for signatures in G2 (RFC 9380 §8.8.2), with the
/// RAPIDO context appended. Used for BLS message hashing.
pub const SIG_G2: Dst = Dst(b"RAPIDO-v1-SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_");

/// Mode A: authority signature over a pseudonym certificate.
pub const CRED: Dst = Dst(b"RAPIDO-v1-CRED_BLS12381G2_XMD:SHA-256_SSWU_RO_");

/// Mode A: agent signature over the verifier challenge.
pub const PRESENT: Dst = Dst(b"RAPIDO-v1-PRESENT_BLS12381G2_XMD:SHA-256_SSWU_RO_");

/// Proof of possession, binding a one-time public key to its secret key.
pub const POP: Dst = Dst(b"RAPIDO-v1-POP_BLS12381G2_XMD:SHA-256_SSWU_RO_");

/// BBS+ generator derivation (G1 generators H_0..H_L).
pub const BBS_GEN: Dst = Dst(b"RAPIDO-v1-BBSGEN_BLS12381G1_XMD:SHA-256_SSWU_RO_");

/// BBS+ message-to-scalar mapping.
pub const BBS_MSG: Dst = Dst(b"RAPIDO-v1-BBSMSG");

/// BBS+ presentation Fiat-Shamir challenge.
pub const BBS_CHALLENGE: Dst = Dst(b"RAPIDO-v1-BBSCHAL");

/// Layer 3 threshold escrow: ElGamal encoding and Chaum-Pedersen challenge.
pub const ESCROW: Dst = Dst(b"RAPIDO-v1-ESCROW");

/// Chaum-Pedersen Fiat-Shamir challenge for correct-encryption proofs.
pub const ESCROW_CP: Dst = Dst(b"RAPIDO-v1-ESCROWCP");

/// One-time key derivation: the `info` prefix for the per-epoch key HKDF.
pub const KEYDERIV: Dst = Dst(b"RAPIDO-v1-KEY");

/// Audit-log hash chain.
pub const AUDIT: Dst = Dst(b"RAPIDO-v1-AUDIT");

/// Schnorr proof of knowledge of a discrete log (generic).
pub const SCHNORR: Dst = Dst(b"RAPIDO-v1-SCHNORR");

/// Every DST defined by the protocol. Used by `dsts_are_unique`.
pub fn all() -> Vec<Dst> {
    vec![
        SIG_G2,
        CRED,
        PRESENT,
        POP,
        BBS_GEN,
        BBS_MSG,
        BBS_CHALLENGE,
        ESCROW,
        ESCROW_CP,
        KEYDERIV,
        AUDIT,
        SCHNORR,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn dsts_are_unique() {
        let set: HashSet<&[u8]> = all().iter().map(|d| d.0).collect();
        assert_eq!(set.len(), all().len(), "DST collision: a tag is reused");
    }

    #[test]
    fn dsts_are_ascii() {
        for d in all() {
            let _ = d.as_str();
        }
    }
}
