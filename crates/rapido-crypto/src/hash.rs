//! Hash-to-curve and hash-to-scalar (RFC 9380).

use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use rapido_core::Dst;
use sha2::Sha256;

/// RFC 9380 security parameter `k` for `expand_message_xmd`, in bits.
const K: usize = 128;

type G1Hasher = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, K>,
    WBMap<ark_bls12_381::g1::Config>,
>;
type G2Hasher = MapToCurveBasedHasher<
    G2Projective,
    DefaultFieldHasher<Sha256, K>,
    WBMap<ark_bls12_381::g2::Config>,
>;

/// `BLS12381G1_XMD:SHA-256_SSWU_RO_` — used for BBS+ generators and for the
/// escrow identity encoding.
pub fn hash_to_g1(dst: Dst, msg: &[u8]) -> G1Projective {
    let h = G1Hasher::new(dst.as_bytes()).expect("static DST is valid");
    h.hash(msg).expect("SSWU_RO hashing is total").into()
}

/// `BLS12381G2_XMD:SHA-256_SSWU_RO_` — used for BLS message hashing.
pub fn hash_to_g2(dst: Dst, msg: &[u8]) -> G2Projective {
    let h = G2Hasher::new(dst.as_bytes()).expect("static DST is valid");
    h.hash(msg).expect("SSWU_RO hashing is total").into()
}

/// RFC 9380 `hash_to_field` into the scalar field `Fr`.
///
/// Used for Fiat-Shamir challenges and for mapping attribute bytes to BBS+
/// message scalars. `expand_message_xmd` produces `ceil((log2(r)+k)/8) = 48`
/// bytes which are reduced mod `r`; the resulting bias is below `2^-128`.
pub fn hash_to_scalar(dst: Dst, msg: &[u8]) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256, K> as HashToField<Fr>>::new(dst.as_bytes());
    hasher.hash_to_field::<1>(msg)[0]
}

/// Domain-separated derivation of an indexed generator, e.g. BBS+ `H_i`.
pub fn indexed_generator_g1(dst: Dst, label: &str, index: usize) -> G1Projective {
    let mut msg = Vec::with_capacity(label.len() + 8);
    msg.extend_from_slice(label.as_bytes());
    msg.extend_from_slice(&(index as u64).to_be_bytes());
    hash_to_g1(dst, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use rapido_core::dst;

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(hash_to_g2(dst::PRESENT, b"abc"), hash_to_g2(dst::PRESENT, b"abc"));
        assert_eq!(hash_to_scalar(dst::BBS_MSG, b"abc"), hash_to_scalar(dst::BBS_MSG, b"abc"));
    }

    #[test]
    fn dst_separates_domains() {
        // The same message under two DSTs must not map to the same point;
        // otherwise a signature from one context would verify in another.
        assert_ne!(hash_to_g2(dst::PRESENT, b"abc"), hash_to_g2(dst::CRED, b"abc"));
        assert_ne!(hash_to_scalar(dst::BBS_MSG, b"x"), hash_to_scalar(dst::ESCROW, b"x"));
    }

    #[test]
    fn hashed_points_are_in_the_prime_order_subgroup() {
        let p = hash_to_g2(dst::PRESENT, b"subgroup check").into_affine();
        assert!(p.is_on_curve());
        assert!(p.is_in_correct_subgroup_assuming_on_curve());
        let q = hash_to_g1(dst::BBS_GEN, b"subgroup check").into_affine();
        assert!(q.is_on_curve());
        assert!(q.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn indexed_generators_are_distinct() {
        let a = indexed_generator_g1(dst::BBS_GEN, "H", 0);
        let b = indexed_generator_g1(dst::BBS_GEN, "H", 1);
        assert_ne!(a, b);
    }
}
