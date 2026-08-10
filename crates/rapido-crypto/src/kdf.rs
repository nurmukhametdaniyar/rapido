//! One-time key derivation.
//!
//! ```text
//! k_i  = HKDF-Expand(PRK = master_secret,
//!                    info = "RAPIDO-v1-KEY" || epoch_be_u64 || counter_be_u32,
//!                    L = 48)
//! sk_i = k_i mod r          // wide reduction from 48 bytes
//! ```
//!
//! `master_secret` is used directly as the HKDF pseudorandom key (Expand only,
//! no Extract): it is already a uniformly random 32-byte value, which is
//! exactly the precondition HKDF-Expand requires.

use crate::ser::fr_from_wide_bytes;
use ark_bls12_381::Fr;
use hkdf::Hkdf;
use rapido_core::{dst, Epoch};
use sha2::Sha256;

/// Agent long-term secret. All one-time keys for all epochs derive from this.
#[derive(Clone)]
pub struct MasterSecret(pub [u8; 32]);

impl MasterSecret {
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        MasterSecret(b)
    }
}

impl core::fmt::Debug for MasterSecret {
    /// Deliberately does not print the secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// `info = DST || epoch_be_u64 || counter_be_u32`.
fn info_bytes(epoch: Epoch, counter: u32) -> Vec<u8> {
    let d = dst::KEYDERIV.as_bytes();
    let mut info = Vec::with_capacity(d.len() + 12);
    info.extend_from_slice(d);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&counter.to_be_bytes());
    info
}

/// Derive the 48-byte block for `(epoch, counter)`.
pub fn derive_bytes(ms: &MasterSecret, epoch: Epoch, counter: u32) -> [u8; 48] {
    let hk = Hkdf::<Sha256>::from_prk(&ms.0).expect("32-byte PRK is long enough for SHA-256");
    let mut okm = [0u8; 48];
    hk.expand(&info_bytes(epoch, counter), &mut okm)
        .expect("48 bytes is well under HKDF's 255*32 limit");
    okm
}

/// Derive the one-time signing key `sk_i` for `(epoch, counter)`.
pub fn derive_scalar(ms: &MasterSecret, epoch: Epoch, counter: u32) -> Fr {
    fr_from_wide_bytes(&derive_bytes(ms, epoch, counter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng_from_seed;
    use ark_ff::Zero;
    use std::collections::HashSet;

    fn ms() -> MasterSecret {
        MasterSecret([42u8; 32])
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(derive_scalar(&ms(), Epoch(3), 7), derive_scalar(&ms(), Epoch(3), 7));
    }

    #[test]
    fn distinct_epoch_counter_pairs_give_distinct_keys() {
        let mut seen = HashSet::new();
        for e in 0..16u64 {
            for c in 0..64u32 {
                let k = derive_scalar(&ms(), Epoch(e), c);
                assert!(!k.is_zero());
                assert!(seen.insert(k.to_string()), "collision at epoch={e} counter={c}");
            }
        }
    }

    #[test]
    fn distinct_master_secrets_give_distinct_keys() {
        let a = MasterSecret([1u8; 32]);
        let b = MasterSecret([2u8; 32]);
        assert_ne!(derive_scalar(&a, Epoch(0), 0), derive_scalar(&b, Epoch(0), 0));
    }

    #[test]
    fn info_encoding_cannot_alias_across_epoch_counter_split() {
        // Fixed-width fields mean (epoch=1, counter=0) and (epoch=0,
        // counter=large) can never produce the same `info` string.
        assert_ne!(info_bytes(Epoch(1), 0), info_bytes(Epoch(0), u32::MAX));
    }

    #[test]
    fn random_master_secrets_differ() {
        let mut rng = rng_from_seed(1);
        let a = MasterSecret::random(&mut rng);
        let b = MasterSecret::random(&mut rng);
        assert_ne!(a.0, b.0);
    }
}

/// RFC 5869 known-answer tests for the HKDF backing this derivation.
#[cfg(test)]
mod rfc5869_kat {
    use hkdf::Hkdf;
    use sha2::Sha256;

    /// RFC 5869 Appendix A.1 (SHA-256, basic test case).
    #[test]
    fn case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// RFC 5869 Appendix A.3 (SHA-256, zero-length salt and info).
    #[test]
    fn case_3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let (prk, hk) = Hkdf::<Sha256>::extract(None, &ikm);
        assert_eq!(
            hex::encode(prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }
}
