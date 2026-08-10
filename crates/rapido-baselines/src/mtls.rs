//! mTLS-like baseline: certificate-chain verification plus a message signature.
//!
//! Models what a conventional mutual-TLS handshake costs a verifier in
//! *signature* terms: verify a leaf certificate against an intermediate, the
//! intermediate against a root, then the peer's signature over a challenge.
//! Chain depth is 2, i.e. three signature verifications in total.
//!
//! Deliberately excluded: the TLS record layer, key exchange, symmetric setup,
//! and X.509 parsing. Including them would measure a TLS implementation rather
//! than the asymmetric-crypto cost the comparison is about, and would flatter
//! RAPIDO by inflating the baseline. The number produced here is therefore a
//! **lower bound** on real mTLS cost, and must be described that way.

use rapido_core::{Error, Result};

/// A certificate: a subject public key plus the issuer's signature over it.
#[derive(Debug, Clone)]
pub struct Cert<Pk, Sig> {
    pub subject: Pk,
    pub subject_bytes: Vec<u8>,
    pub sig: Sig,
}

/// The bytes an issuer signs. Length-prefixed so a subject key cannot be
/// confused with the surrounding fields.
fn tbs(subject_bytes: &[u8], name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(subject_bytes.len() + name.len() + 16);
    out.extend_from_slice(b"RAPIDO-baseline-mtls-tbs");
    out.extend_from_slice(&(name.len() as u64).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(subject_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(subject_bytes);
    out
}

// --- Ed25519 ---------------------------------------------------------------

pub mod ed25519 {
    use super::*;
    use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

    pub struct Chain {
        pub root: VerifyingKey,
        pub intermediate: Cert<VerifyingKey, Signature>,
        pub leaf: Cert<VerifyingKey, Signature>,
        leaf_key: SigningKey,
    }

    /// Bytes a verifier receives: two certificates plus the message signature.
    pub const WIRE_BYTES: usize = 2 * (32 + 64) + 64;

    pub fn setup<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Chain {
        let root_key = SigningKey::generate(rng);
        let inter_key = SigningKey::generate(rng);
        let leaf_key = SigningKey::generate(rng);

        let inter_pk = inter_key.verifying_key();
        let leaf_pk = leaf_key.verifying_key();
        let inter_bytes = inter_pk.to_bytes().to_vec();
        let leaf_bytes = leaf_pk.to_bytes().to_vec();

        Chain {
            root: root_key.verifying_key(),
            intermediate: Cert {
                subject: inter_pk,
                sig: root_key.sign(&tbs(&inter_bytes, "intermediate")),
                subject_bytes: inter_bytes,
            },
            leaf: Cert {
                subject: leaf_pk,
                sig: inter_key.sign(&tbs(&leaf_bytes, "leaf")),
                subject_bytes: leaf_bytes,
            },
            leaf_key,
        }
    }

    impl Chain {
        pub fn sign_challenge(&self, challenge: &[u8]) -> Signature {
            self.leaf_key.sign(challenge)
        }
    }

    /// Three verifications: intermediate, leaf, then the peer signature.
    pub fn verify(chain: &Chain, challenge: &[u8], sig: &Signature) -> Result<()> {
        chain
            .root
            .verify(
                &tbs(&chain.intermediate.subject_bytes, "intermediate"),
                &chain.intermediate.sig,
            )
            .map_err(|_| Error::BadSignature("mtls ed25519: intermediate certificate"))?;
        chain
            .intermediate
            .subject
            .verify(&tbs(&chain.leaf.subject_bytes, "leaf"), &chain.leaf.sig)
            .map_err(|_| Error::BadSignature("mtls ed25519: leaf certificate"))?;
        chain
            .leaf
            .subject
            .verify(challenge, sig)
            .map_err(|_| Error::BadSignature("mtls ed25519: challenge signature"))?;
        Ok(())
    }
}

// --- ECDSA P-256 -----------------------------------------------------------

pub mod p256_ecdsa {
    use super::*;
    use p256::ecdsa::signature::{Signer as _, Verifier as _};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    pub struct Chain {
        pub root: VerifyingKey,
        pub intermediate: Cert<VerifyingKey, Signature>,
        pub leaf: Cert<VerifyingKey, Signature>,
        leaf_key: SigningKey,
    }

    /// Compressed P-256 keys (33 bytes) and 64-byte signatures.
    pub const WIRE_BYTES: usize = 2 * (33 + 64) + 64;

    pub fn setup<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Chain {
        let root_key = SigningKey::random(rng);
        let inter_key = SigningKey::random(rng);
        let leaf_key = SigningKey::random(rng);

        let inter_pk = *inter_key.verifying_key();
        let leaf_pk = *leaf_key.verifying_key();
        // Compressed SEC1, matching what a size-conscious deployment sends.
        let inter_bytes = inter_pk.to_encoded_point(true).as_bytes().to_vec();
        let leaf_bytes = leaf_pk.to_encoded_point(true).as_bytes().to_vec();

        Chain {
            root: *root_key.verifying_key(),
            intermediate: Cert {
                subject: inter_pk,
                sig: root_key.sign(&tbs(&inter_bytes, "intermediate")),
                subject_bytes: inter_bytes,
            },
            leaf: Cert {
                subject: leaf_pk,
                sig: inter_key.sign(&tbs(&leaf_bytes, "leaf")),
                subject_bytes: leaf_bytes,
            },
            leaf_key,
        }
    }

    impl Chain {
        pub fn sign_challenge(&self, challenge: &[u8]) -> Signature {
            self.leaf_key.sign(challenge)
        }
    }

    pub fn verify(chain: &Chain, challenge: &[u8], sig: &Signature) -> Result<()> {
        chain
            .root
            .verify(
                &tbs(&chain.intermediate.subject_bytes, "intermediate"),
                &chain.intermediate.sig,
            )
            .map_err(|_| Error::BadSignature("mtls p256: intermediate certificate"))?;
        chain
            .intermediate
            .subject
            .verify(&tbs(&chain.leaf.subject_bytes, "leaf"), &chain.leaf.sig)
            .map_err(|_| Error::BadSignature("mtls p256: leaf certificate"))?;
        chain
            .leaf
            .subject
            .verify(challenge, sig)
            .map_err(|_| Error::BadSignature("mtls p256: challenge signature"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng(seed: u64) -> rand_chacha::ChaCha20Rng {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        rand_chacha::ChaCha20Rng::from_seed(b)
    }

    #[test]
    fn ed25519_chain_round_trip() {
        let mut r = rng(1);
        let chain = ed25519::setup(&mut r);
        let sig = chain.sign_challenge(b"challenge");
        assert!(ed25519::verify(&chain, b"challenge", &sig).is_ok());
        assert!(ed25519::verify(&chain, b"other", &sig).is_err());
    }

    #[test]
    fn p256_chain_round_trip() {
        let mut r = rng(2);
        let chain = p256_ecdsa::setup(&mut r);
        let sig = chain.sign_challenge(b"challenge");
        assert!(p256_ecdsa::verify(&chain, b"challenge", &sig).is_ok());
        assert!(p256_ecdsa::verify(&chain, b"other", &sig).is_err());
    }

    #[test]
    fn a_leaf_signed_by_the_wrong_intermediate_is_rejected() {
        let mut r = rng(3);
        let a = ed25519::setup(&mut r);
        let b = ed25519::setup(&mut r);
        let mut spliced = ed25519::setup(&mut r);
        spliced.leaf = a.leaf.clone();
        spliced.intermediate = b.intermediate.clone();
        let sig = a.sign_challenge(b"c");
        assert!(ed25519::verify(&spliced, b"c", &sig).is_err());
    }

    #[test]
    fn wire_sizes_are_as_declared() {
        assert_eq!(ed25519::WIRE_BYTES, 2 * 96 + 64);
        let mut r = rng(4);
        let chain = p256_ecdsa::setup(&mut r);
        assert_eq!(chain.leaf.subject_bytes.len(), 33, "expected compressed SEC1 encoding");
    }
}
