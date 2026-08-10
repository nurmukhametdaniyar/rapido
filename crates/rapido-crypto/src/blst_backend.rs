//! Secondary BLS backend built on `blstrs`/`blst`, behind the `blst-backend`
//! feature.
//!
//! Purpose: a latency number is only as meaningful as the library that produced
//! it. `blst` is the fastest widely-used BLS12-381 implementation and is
//! assembly-optimized per target; arkworks is portable Rust. Measuring both
//! makes the library dependence of the results explicit instead of leaving a
//! reader to wonder about it.
//!
//! Only the raw sign/verify fast path is mirrored here. Everything algebraic
//! (BBS+, threshold ElGamal, the Schnorr relations) stays on arkworks — those
//! need generic field and group arithmetic that `blstrs` does not expose as
//! conveniently, and duplicating them would double the surface for divergence
//! bugs without adding a measurement anyone reports.
//!
//! The DST and signature/public-key group assignment match the arkworks path
//! exactly (pk in G1, sig in G2), which is what makes the cross-backend
//! agreement test in `tests/cross_backend.rs` meaningful.

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use rapido_core::{Dst, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(pub Scalar);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub G1Projective);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub G2Projective);

impl SecretKey {
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        SecretKey(Scalar::random(rng))
    }

    /// Import a scalar from its 32-byte big-endian arkworks encoding, so the
    /// same key can drive both backends.
    pub fn from_be_bytes(b: &[u8; 32]) -> Result<Self> {
        let ct = Scalar::from_bytes_be(b);
        if bool::from(ct.is_some()) {
            Ok(SecretKey(ct.unwrap()))
        } else {
            Err(Error::NonCanonical("blst secret key: not a canonical scalar".into()))
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(G1Projective::generator() * self.0)
    }
}

pub fn hash_to_g2(dst: Dst, msg: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, dst.as_bytes(), &[])
}

pub fn sign(sk: &SecretKey, dst: Dst, msg: &[u8]) -> Signature {
    Signature(hash_to_g2(dst, msg) * sk.0)
}

/// `e(-G1, sigma) * e(pk, H(m)) == 1`, as a single Miller loop pair.
pub fn verify(pk: &PublicKey, dst: Dst, msg: &[u8], sig: &Signature) -> Result<()> {
    if bool::from(pk.0.is_identity()) {
        return Err(Error::IdentityPoint("blst public key"));
    }
    let h = hash_to_g2(dst, msg).to_affine();
    let neg_g1 = (-G1Projective::generator()).to_affine();
    let pk_affine = pk.0.to_affine();
    let sig_affine = sig.0.to_affine();

    let terms: [(&G1Affine, &blstrs::G2Prepared); 2] = [
        (&neg_g1, &blstrs::G2Prepared::from(sig_affine)),
        (&pk_affine, &blstrs::G2Prepared::from(h)),
    ];
    let out = blstrs::Bls12::multi_miller_loop(&terms).final_exponentiation();
    if out == Gt::identity() {
        Ok(())
    } else {
        Err(Error::BadSignature("blst verify"))
    }
}

/// Serialize a public key the same way the arkworks path does (compressed G1).
pub fn public_key_bytes(pk: &PublicKey) -> [u8; 48] {
    pk.0.to_affine().to_compressed()
}

/// Serialize a signature the same way the arkworks path does (compressed G2).
pub fn signature_bytes(sig: &Signature) -> [u8; 96] {
    sig.0.to_affine().to_compressed()
}

pub fn public_key_from_bytes(b: &[u8; 48]) -> Result<PublicKey> {
    let ct = G1Affine::from_compressed(b);
    if bool::from(ct.is_some()) {
        Ok(PublicKey(ct.unwrap().to_curve()))
    } else {
        Err(Error::NonCanonical("blst public key".into()))
    }
}

pub fn signature_from_bytes(b: &[u8; 96]) -> Result<Signature> {
    let ct = G2Affine::from_compressed(b);
    if bool::from(ct.is_some()) {
        Ok(Signature(ct.unwrap().to_curve()))
    } else {
        Err(Error::NonCanonical("blst signature".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapido_core::dst;

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = rand::rngs::OsRng;
        let sk = SecretKey::random(&mut rng);
        let sig = sign(&sk, dst::PRESENT, b"hello");
        assert!(verify(&sk.public(), dst::PRESENT, b"hello", &sig).is_ok());
        assert!(verify(&sk.public(), dst::PRESENT, b"hell0", &sig).is_err());
        assert!(verify(&sk.public(), dst::CRED, b"hello", &sig).is_err());
    }
}
