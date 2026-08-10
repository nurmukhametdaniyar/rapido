//! Canonical compressed serialization with fail-closed parsing.
//!
//! `deserialize_compressed` in arkworks already rejects non-canonical field
//! encodings (x >= p), off-curve points, and points outside the prime-order
//! subgroup. The wrappers here add the checks arkworks deliberately leaves to
//! the caller — rejecting the identity element where the protocol requires a
//! non-trivial point — and normalize every failure into [`rapido_core::Error`].

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rapido_core::{Error, Result};

pub const G1_COMPRESSED_LEN: usize = 48;
pub const G2_COMPRESSED_LEN: usize = 96;
pub const FR_LEN: usize = 32;

pub fn g1_to_bytes(p: &G1Projective) -> Vec<u8> {
    let mut out = Vec::with_capacity(G1_COMPRESSED_LEN);
    p.into_affine().serialize_compressed(&mut out).expect("vec write is infallible");
    out
}

pub fn g2_to_bytes(p: &G2Projective) -> Vec<u8> {
    let mut out = Vec::with_capacity(G2_COMPRESSED_LEN);
    p.into_affine().serialize_compressed(&mut out).expect("vec write is infallible");
    out
}

pub fn fr_to_bytes(s: &Fr) -> Vec<u8> {
    let mut out = Vec::with_capacity(FR_LEN);
    s.serialize_compressed(&mut out).expect("vec write is infallible");
    out
}

/// Parse a compressed G1 point. Validates on-curve, subgroup, and canonical
/// field encoding; rejects the identity.
pub fn g1_from_bytes(b: &[u8], ctx: &'static str) -> Result<G1Projective> {
    let p = G1Affine::deserialize_with_mode(b, Compress::Yes, Validate::Yes)
        .map_err(|e| map_ark_err(e, ctx))?;
    if p.is_zero() {
        return Err(Error::IdentityPoint(ctx));
    }
    Ok(p.into())
}

/// Parse a compressed G2 point, with the same checks as [`g1_from_bytes`].
pub fn g2_from_bytes(b: &[u8], ctx: &'static str) -> Result<G2Projective> {
    let p = G2Affine::deserialize_with_mode(b, Compress::Yes, Validate::Yes)
        .map_err(|e| map_ark_err(e, ctx))?;
    if p.is_zero() {
        return Err(Error::IdentityPoint(ctx));
    }
    Ok(p.into())
}

/// Parse a scalar. Rejects values >= r (non-canonical) and, unlike the point
/// parsers, permits zero — a zero scalar is a legitimate attribute value.
pub fn fr_from_bytes(b: &[u8], ctx: &'static str) -> Result<Fr> {
    if b.len() != FR_LEN {
        return Err(Error::Deserialization(format!(
            "{ctx}: expected {FR_LEN} bytes, got {}",
            b.len()
        )));
    }
    Fr::deserialize_compressed(b).map_err(|e| map_ark_err(e, ctx))
}

/// Wide reduction of 48 bytes into `Fr`.
///
/// Bias is bounded by `2^-(384 - 255) = 2^-129`, i.e. statistically
/// indistinguishable from uniform. Chosen over rejection sampling because it is
/// branch-free on the secret, which is the weaker of the two properties to give
/// up given this crate makes no constant-time claim.
pub fn fr_from_wide_bytes(b: &[u8; 48]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

fn map_ark_err(e: ark_serialize::SerializationError, ctx: &'static str) -> Error {
    use ark_serialize::SerializationError as S;
    match e {
        S::InvalidData => Error::NonCanonical(format!("{ctx}: invalid or non-canonical encoding")),
        S::UnexpectedFlags => {
            Error::NonCanonical(format!("{ctx}: unexpected point-compression flags"))
        }
        S::NotEnoughSpace => Error::Deserialization(format!("{ctx}: truncated input")),
        other => Error::Deserialization(format!("{ctx}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use ark_ec::PrimeGroup;
    use rapido_core::dst;

    #[test]
    fn point_round_trip() {
        let p = hash::hash_to_g2(dst::PRESENT, b"round trip");
        let b = g2_to_bytes(&p);
        assert_eq!(b.len(), G2_COMPRESSED_LEN);
        assert_eq!(g2_from_bytes(&b, "test").unwrap(), p);

        let q = G1Projective::generator();
        assert_eq!(g1_from_bytes(&g1_to_bytes(&q), "test").unwrap(), q);
    }

    #[test]
    fn identity_point_is_rejected() {
        let zero = G1Projective::default();
        let b = g1_to_bytes(&zero);
        assert!(matches!(g1_from_bytes(&b, "test"), Err(Error::IdentityPoint(_))));
    }

    /// Small-subgroup inputs must fail closed.
    ///
    /// BLS12-381's G1 has cofactor `h != 1`, so there are points on the curve
    /// that are *not* in the prime-order subgroup. Accepting one would break
    /// the pairing-based verification equations. A point is constructed here
    /// directly on the curve without cofactor clearing, and must be rejected on
    /// parse rather than merely being unusual.
    #[test]
    fn point_outside_the_prime_order_subgroup_is_rejected() {
        use ark_bls12_381::{Fq, G1Affine};
        use ark_serialize::CanonicalSerialize;

        // Walk x upward until y^2 = x^3 + 4 has a square root; the resulting
        // point is on the curve but almost certainly outside the subgroup.
        let mut x = Fq::from(1u64);
        let point = loop {
            if let Some(p) = G1Affine::get_point_from_x_unchecked(x, false) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    break p;
                }
            }
            x += Fq::from(1u64);
        };
        assert!(point.is_on_curve(), "the constructed point must be on the curve");
        assert!(!point.is_in_correct_subgroup_assuming_on_curve());

        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).expect("vec write is infallible");
        assert!(
            matches!(g1_from_bytes(&bytes, "test"), Err(Error::NonCanonical(_))),
            "a small-subgroup point must be rejected on parse"
        );
    }

    #[test]
    fn non_canonical_field_encoding_is_rejected() {
        // Take a valid encoding and set every x-coordinate bit, producing a
        // field element far above the modulus while preserving the flag bits.
        let p = G1Projective::generator();
        let mut b = g1_to_bytes(&p);
        let flags = b[0] & 0xe0;
        for byte in b.iter_mut() {
            *byte = 0xff;
        }
        b[0] = flags | 0x1f;
        assert!(g1_from_bytes(&b, "test").is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        let p = G1Projective::generator();
        let b = g1_to_bytes(&p);
        assert!(g1_from_bytes(&b[..b.len() - 1], "test").is_err());
    }

    #[test]
    fn scalar_above_modulus_is_rejected() {
        let all_ones = [0xffu8; FR_LEN];
        assert!(fr_from_bytes(&all_ones, "test").is_err());
    }

    #[test]
    fn wide_reduction_is_deterministic() {
        let b = [7u8; 48];
        assert_eq!(fr_from_wide_bytes(&b), fr_from_wide_bytes(&b));
    }
}
