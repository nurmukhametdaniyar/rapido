//! Cross-backend agreement between arkworks and `blst`.
//!
//! ## Why this test exists instead of a BLS known-answer test
//!
//! A known-answer test against published vectors would be the natural choice.
//! `draft-irtf-cfrg-bls-signature-05` specifies the scheme but publishes **no**
//! test vectors; the widely-used BLS12-381 signature vectors come from the
//! Ethereum consensus spec, which fixes the DST to
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — a different domain from
//! RAPIDO's, so those vectors cannot validate this code directly.
//!
//! What is checked instead is stronger than a self-generated vector: for the
//! same secret key and message, arkworks and `blst` — two independent
//! implementations, one portable Rust, one assembly-optimized C — must produce
//! **byte-identical** signatures and agree on every verification outcome. The
//! underlying hash-to-curve is separately pinned to the RFC 9380 vectors in
//! `rfc9380_kat.rs`, so the pair together covers what a KAT would.
//!
//! Run with `cargo test -p rapido-crypto --features blst-backend`.

#![cfg(feature = "blst-backend")]

use ark_ff::{BigInteger, PrimeField};
use rapido_core::dst;
use rapido_crypto::{bls, blst_backend as blst, rng_from_seed, Fr};

/// Move an arkworks scalar to `blstrs` via its canonical big-endian encoding.
fn to_blst_key(sk: &bls::SecretKey) -> blst::SecretKey {
    let be = sk.0.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - be.len()..].copy_from_slice(&be);
    blst::SecretKey::from_be_bytes(&bytes).expect("arkworks scalars are canonical")
}

fn messages() -> Vec<Vec<u8>> {
    vec![
        vec![],
        b"abc".to_vec(),
        b"abcdef0123456789".to_vec(),
        vec![0x5a; 256],
        b"RAPIDO presentation challenge || epoch=7 || nonce=deadbeef".to_vec(),
    ]
}

#[test]
fn public_keys_agree() {
    let mut rng = rng_from_seed(0xA11CE);
    for _ in 0..16 {
        let sk = bls::SecretKey::random(&mut rng);
        assert_eq!(
            sk.public().to_bytes().as_slice(),
            blst::public_key_bytes(&to_blst_key(&sk).public()).as_slice(),
            "public key encodings diverge between backends"
        );
    }
}

#[test]
fn signatures_are_byte_identical() {
    let mut rng = rng_from_seed(0xB0B);
    for dst in [dst::PRESENT, dst::CRED, dst::POP] {
        for msg in messages() {
            let sk = bls::SecretKey::random(&mut rng);
            let ark_sig = bls::sign(&sk, dst, &msg);
            let blst_sig = blst::sign(&to_blst_key(&sk), dst, &msg);
            assert_eq!(
                ark_sig.to_bytes().as_slice(),
                blst::signature_bytes(&blst_sig).as_slice(),
                "signature mismatch for DST {} on {}-byte message",
                dst.as_str(),
                msg.len()
            );
        }
    }
}

#[test]
fn each_backend_verifies_the_other() {
    let mut rng = rng_from_seed(0xC0FFEE);
    for msg in messages() {
        let sk = bls::SecretKey::random(&mut rng);
        let ark_sig = bls::sign(&sk, dst::PRESENT, &msg);
        let blst_sig = blst::sign(&to_blst_key(&sk), dst::PRESENT, &msg);

        // blst signature -> arkworks verifier
        let ported = bls::Signature::from_bytes(&blst::signature_bytes(&blst_sig)).unwrap();
        assert!(bls::verify(&sk.public(), dst::PRESENT, &msg, &ported).is_ok());

        // arkworks signature -> blst verifier
        let mut sig_bytes = [0u8; 96];
        sig_bytes.copy_from_slice(&ark_sig.to_bytes());
        let ported = blst::signature_from_bytes(&sig_bytes).unwrap();
        let mut pk_bytes = [0u8; 48];
        pk_bytes.copy_from_slice(&sk.public().to_bytes());
        let pk = blst::public_key_from_bytes(&pk_bytes).unwrap();
        assert!(blst::verify(&pk, dst::PRESENT, &msg, &ported).is_ok());
    }
}

#[test]
fn both_backends_reject_the_same_forgeries() {
    let mut rng = rng_from_seed(0xDEAD);
    let sk = bls::SecretKey::random(&mut rng);
    let other = bls::SecretKey::random(&mut rng);
    let sig = bls::sign(&sk, dst::PRESENT, b"authentic");

    let mut sig_bytes = [0u8; 96];
    sig_bytes.copy_from_slice(&sig.to_bytes());
    let blst_sig = blst::signature_from_bytes(&sig_bytes).unwrap();

    for (label, ark_ok, blst_ok) in [
        (
            "wrong message",
            bls::verify(&sk.public(), dst::PRESENT, b"forged", &sig).is_ok(),
            blst::verify(&to_blst_key(&sk).public(), dst::PRESENT, b"forged", &blst_sig).is_ok(),
        ),
        (
            "wrong key",
            bls::verify(&other.public(), dst::PRESENT, b"authentic", &sig).is_ok(),
            blst::verify(&to_blst_key(&other).public(), dst::PRESENT, b"authentic", &blst_sig)
                .is_ok(),
        ),
        (
            "wrong domain",
            bls::verify(&sk.public(), dst::CRED, b"authentic", &sig).is_ok(),
            blst::verify(&to_blst_key(&sk).public(), dst::CRED, b"authentic", &blst_sig).is_ok(),
        ),
    ] {
        assert!(!ark_ok, "arkworks accepted a forgery: {label}");
        assert!(!blst_ok, "blst accepted a forgery: {label}");
    }
}

#[test]
fn hash_to_curve_agrees() {
    for msg in messages() {
        let ark =
            rapido_crypto::ser::g2_to_bytes(&rapido_crypto::hash::hash_to_g2(dst::SIG_G2, &msg));
        let b = blst::hash_to_g2(dst::SIG_G2, &msg);
        let blst_bytes = blst::signature_bytes(&blst::Signature(b));
        assert_eq!(ark.as_slice(), blst_bytes.as_slice(), "hash-to-G2 diverges");
    }
}

/// Sanity guard on the scalar port itself: a mis-ported key would make every
/// other assertion in this file vacuously agree on garbage.
#[test]
fn scalar_port_is_faithful() {
    let mut rng = rng_from_seed(1);
    for _ in 0..8 {
        let sk = bls::SecretKey::random(&mut rng);
        let round_tripped = to_blst_key(&sk);
        let back = Fr::from_be_bytes_mod_order(&round_tripped.0.to_bytes_be());
        assert_eq!(back, sk.0);
    }
}
