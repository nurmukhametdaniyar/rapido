//! RFC 9380 known-answer tests for hash-to-curve.
//!
//! Vectors are transcribed from RFC 9380 Appendix J.9.1
//! (`BLS12381G1_XMD:SHA-256_SSWU_RO_`) and J.10.1
//! (`BLS12381G2_XMD:SHA-256_SSWU_RO_`), including the RFC's own DSTs.
//!
//! These pin the hash-to-curve implementation RAPIDO's BLS signatures and BBS+
//! generators are built on. A failure here means every downstream signature is
//! computed over the wrong point, so this is the first test to check when the
//! curve backend changes.

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use rapido_core::Dst;
use rapido_crypto::hash;

const G1_DST: Dst = Dst(b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_");
const G2_DST: Dst = Dst(b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_");

fn fq(hex_str: &str) -> Fq {
    Fq::from_be_bytes_mod_order(&hex::decode(hex_str).expect("vector is valid hex"))
}

/// (msg, P.x, P.y)
const G1_VECTORS: &[(&str, &str, &str)] = &[
    ("", "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1", "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"),
    ("abc", "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903", "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"),
    ("abcdef0123456789", "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98", "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709"),
    ("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488", "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38"),
    ("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe", "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8"),
];

/// (msg, P.x.c0, P.x.c1, P.y.c0, P.y.c1)
const G2_VECTORS: &[(&str, &str, &str, &str, &str)] = &[
    ("", "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a", "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d", "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92", "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6"),
    ("abc", "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6", "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8", "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48", "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16"),
    ("abcdef0123456789", "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0", "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c", "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8", "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be"),
    ("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da", "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91", "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192", "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662"),
    ("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534", "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569", "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e", "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52"),
];

#[test]
fn rfc9380_j9_1_bls12381g1_xmd_sha256_sswu_ro() {
    for (msg, x, y) in G1_VECTORS {
        let got = hash::hash_to_g1(G1_DST, msg.as_bytes()).into_affine();
        let want = G1Affine::new_unchecked(fq(x), fq(y));
        assert!(want.is_on_curve(), "vector for msg len {} is not on the curve", msg.len());
        assert_eq!(got, want, "G1 hash-to-curve mismatch for msg of length {}", msg.len());
    }
}

#[test]
fn rfc9380_j10_1_bls12381g2_xmd_sha256_sswu_ro() {
    for (msg, x0, x1, y0, y1) in G2_VECTORS {
        let got = hash::hash_to_g2(G2_DST, msg.as_bytes()).into_affine();
        let want = G2Affine::new_unchecked(Fq2::new(fq(x0), fq(x1)), Fq2::new(fq(y0), fq(y1)));
        assert!(want.is_on_curve(), "vector for msg len {} is not on the curve", msg.len());
        assert_eq!(got, want, "G2 hash-to-curve mismatch for msg of length {}", msg.len());
    }
}

/// The vectors above cover the RFC's full message-length ladder, including the
/// 128- and 512-byte inputs that exercise `expand_message_xmd`'s multi-block
/// path. Guard against a future edit silently dropping them.
#[test]
fn all_rfc_message_lengths_are_covered() {
    let lens: Vec<usize> = G2_VECTORS.iter().map(|v| v.0.len()).collect();
    assert_eq!(lens, vec![0, 3, 16, 133, 517]);
    assert_eq!(G1_VECTORS.len(), G2_VECTORS.len());
}
