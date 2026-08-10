//! BLS signatures on BLS12-381, minimal-pubkey-size.
//!
//! Public keys are in G1, signatures in G2. Verification is the pairing check
//!
//! ```text
//! e(-G1, sigma) * e(pk, H(m)) == 1
//! ```
//!
//! expressed as a single multi-pairing (one final exponentiation instead of
//! two), which is the standard formulation and the one benchmarked.

use crate::{hash, ser, shamir};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{One, UniformRand, Zero};
use rapido_core::{Dst, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(pub Fr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub G1Projective);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub G2Projective);

impl SecretKey {
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        SecretKey(Fr::rand(rng))
    }
    pub fn public(&self) -> PublicKey {
        PublicKey(G1Projective::generator() * self.0)
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::g1_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(PublicKey(ser::g1_from_bytes(b, "bls public key")?))
    }
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::g2_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(Signature(ser::g2_from_bytes(b, "bls signature")?))
    }
}

/// Sign `msg` in the domain `dst`.
pub fn sign(sk: &SecretKey, dst: Dst, msg: &[u8]) -> Signature {
    Signature(hash::hash_to_g2(dst, msg) * sk.0)
}

/// Verify one signature: `e(-G1, sigma) * e(pk, H(m)) == 1`.
pub fn verify(pk: &PublicKey, dst: Dst, msg: &[u8], sig: &Signature) -> Result<()> {
    if pk.0.is_zero() {
        return Err(Error::IdentityPoint("bls public key"));
    }
    let h = hash::hash_to_g2(dst, msg);
    let neg_g1 = (-G1Projective::generator()).into_affine();
    let out = Bls12_381::multi_pairing(
        [neg_g1, pk.0.into_affine()],
        [sig.0.into_affine(), h.into_affine()],
    );
    if out.0.is_one() {
        Ok(())
    } else {
        Err(Error::BadSignature("bls single verify"))
    }
}

/// Proof of possession over the public key itself.
///
/// Binds a one-time key `P_i` to knowledge of `sk_i`, so the authority cannot
/// be tricked into certifying a key the requester does not control (a rogue-key
/// attack against the aggregate verification path).
pub fn prove_possession(sk: &SecretKey) -> Signature {
    let pk = sk.public();
    sign(sk, rapido_core::dst::POP, &pk.to_bytes())
}

pub fn verify_possession(pk: &PublicKey, pop: &Signature) -> Result<()> {
    verify(pk, rapido_core::dst::POP, &pk.to_bytes(), pop)
        .map_err(|_| Error::BadProof("proof of possession"))
}

// --- aggregate / batch verification ---------------------------------------

/// Verify `n` (pk, msg, sig) triples as one multi-pairing with random
/// coefficients — the "aggregate path" that Mode A verification uses.
///
/// Checks `e(-G1, Σ ρ_i σ_i) * Π e(ρ_i pk_i, H(m_i)) == 1`. The random `ρ_i`
/// prevent an adversary from constructing a set of individually-invalid
/// signatures whose product still passes. Messages may repeat; distinct DSTs
/// are permitted per triple.
pub fn batch_verify<R: rand::Rng + ?Sized>(
    triples: &[(PublicKey, Dst, &[u8], Signature)],
    rng: &mut R,
) -> Result<()> {
    if triples.is_empty() {
        return Ok(());
    }
    let mut g1s: Vec<G1Affine> = Vec::with_capacity(triples.len() + 1);
    let mut g2s: Vec<G2Affine> = Vec::with_capacity(triples.len() + 1);

    let mut sig_acc = G2Projective::zero();
    for (pk, dst, msg, sig) in triples {
        if pk.0.is_zero() {
            return Err(Error::IdentityPoint("bls public key"));
        }
        let rho = Fr::rand(rng);
        sig_acc += sig.0 * rho;
        g1s.push((pk.0 * rho).into_affine());
        g2s.push(hash::hash_to_g2(*dst, msg).into_affine());
    }
    g1s.push((-G1Projective::generator()).into_affine());
    g2s.push(sig_acc.into_affine());

    if Bls12_381::multi_pairing(g1s, g2s).0.is_one() {
        Ok(())
    } else {
        Err(Error::BadSignature("bls batch verify"))
    }
}

/// Aggregate signatures over the *same* message under distinct keys.
/// Sound only because every key carries a proof of possession.
pub fn aggregate(sigs: &[Signature]) -> Signature {
    Signature(sigs.iter().fold(G2Projective::zero(), |a, s| a + s.0))
}

/// Verify an aggregate over one common message: `e(-G1, σ) * e(Σ pk_i, H(m)) == 1`.
pub fn verify_aggregate_same_message(
    pks: &[PublicKey],
    dst: Dst,
    msg: &[u8],
    sig: &Signature,
) -> Result<()> {
    if pks.is_empty() {
        return Err(Error::InvalidParameter("aggregate: empty key set".into()));
    }
    let apk = pks.iter().fold(G1Projective::zero(), |a, p| a + p.0);
    verify(&PublicKey(apk), dst, msg, sig)
}

// --- threshold BLS ---------------------------------------------------------

/// A `(k, n)` threshold BLS key: the group public key plus one share per
/// issuing authority.
#[derive(Debug, Clone)]
pub struct ThresholdKey {
    pub k: usize,
    pub n: usize,
    pub group_public: PublicKey,
    pub shares: Vec<shamir::Share>,
    /// Per-authority public key `s_j G`, for attributing a bad partial signature.
    pub share_publics: Vec<PublicKey>,
}

impl ThresholdKey {
    pub fn generate<R: rand::Rng + ?Sized>(k: usize, n: usize, rng: &mut R) -> Result<Self> {
        let secret = Fr::rand(rng);
        let shares = shamir::split(secret, k, n, rng)?;
        let share_publics =
            shares.iter().map(|s| PublicKey(G1Projective::generator() * s.value)).collect();
        Ok(ThresholdKey { k, n, group_public: SecretKey(secret).public(), shares, share_publics })
    }
}

/// A partial signature from authority `index`.
#[derive(Debug, Clone, Copy)]
pub struct PartialSignature {
    pub index: u32,
    pub sig: Signature,
}

pub fn partial_sign(share: &shamir::Share, dst: Dst, msg: &[u8]) -> PartialSignature {
    PartialSignature { index: share.index, sig: sign(&SecretKey(share.value), dst, msg) }
}

/// Check one partial signature against its authority's public key. Lets a
/// coordinator identify *which* authority misbehaved instead of only learning
/// that the aggregate failed.
pub fn verify_partial(
    share_public: &PublicKey,
    dst: Dst,
    msg: &[u8],
    partial: &PartialSignature,
) -> Result<()> {
    verify(share_public, dst, msg, &partial.sig)
        .map_err(|_| Error::BadSignature("threshold partial signature"))
}

/// Lagrange-combine `k` partial signatures into a signature under the group key.
pub fn combine(partials: &[PartialSignature], k: usize) -> Result<Signature> {
    if partials.len() < k {
        return Err(Error::NotEnoughShares { need: k, got: partials.len() });
    }
    let subset = &partials[..k];
    let idx: Vec<u32> = subset.iter().map(|p| p.index).collect();
    let coeffs = shamir::lagrange_at_zero(&idx)?;
    // Interpolation in the exponent: Σ λ_i · σ_i, an MSM over G2.
    let points: Vec<G2Affine> = subset.iter().map(|p| p.sig.0.into_affine()).collect();
    let agg = G2Projective::msm(&points, &coeffs)
        .map_err(|_| Error::InvalidParameter("threshold combine: length mismatch".into()))?;
    Ok(Signature(agg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng_from_seed;
    use rapido_core::dst;

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = rng_from_seed(1);
        let sk = SecretKey::random(&mut rng);
        let sig = sign(&sk, dst::PRESENT, b"hello");
        assert!(verify(&sk.public(), dst::PRESENT, b"hello", &sig).is_ok());
    }

    #[test]
    fn wrong_message_key_or_domain_fails_closed() {
        let mut rng = rng_from_seed(2);
        let sk = SecretKey::random(&mut rng);
        let other = SecretKey::random(&mut rng);
        let sig = sign(&sk, dst::PRESENT, b"hello");

        assert!(verify(&sk.public(), dst::PRESENT, b"hello!", &sig).is_err());
        assert!(verify(&other.public(), dst::PRESENT, b"hello", &sig).is_err());
        // Domain separation: the same signature must not verify in the
        // credential domain.
        assert!(verify(&sk.public(), dst::CRED, b"hello", &sig).is_err());
    }

    #[test]
    fn identity_public_key_is_rejected() {
        let sk = SecretKey(Fr::zero());
        let sig = sign(&sk, dst::PRESENT, b"m");
        assert!(matches!(
            verify(&sk.public(), dst::PRESENT, b"m", &sig),
            Err(Error::IdentityPoint(_))
        ));
    }

    #[test]
    fn proof_of_possession_round_trip() {
        let mut rng = rng_from_seed(3);
        let sk = SecretKey::random(&mut rng);
        let pop = prove_possession(&sk);
        assert!(verify_possession(&sk.public(), &pop).is_ok());

        let other = SecretKey::random(&mut rng);
        assert!(verify_possession(&other.public(), &pop).is_err());
    }

    #[test]
    fn batch_verify_accepts_valid_and_rejects_one_bad() {
        let mut rng = rng_from_seed(4);
        let msgs: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 16]).collect();
        let sks: Vec<SecretKey> = (0..8).map(|_| SecretKey::random(&mut rng)).collect();
        let sigs: Vec<Signature> =
            sks.iter().zip(&msgs).map(|(sk, m)| sign(sk, dst::PRESENT, m)).collect();

        let good: Vec<_> = sks
            .iter()
            .zip(&msgs)
            .zip(&sigs)
            .map(|((sk, m), s)| (sk.public(), dst::PRESENT, m.as_slice(), *s))
            .collect();
        assert!(batch_verify(&good, &mut rng).is_ok());

        let mut bad = good.clone();
        bad[3].3 = sigs[4];
        assert!(batch_verify(&bad, &mut rng).is_err());
    }

    #[test]
    fn aggregate_over_common_message() {
        let mut rng = rng_from_seed(5);
        let sks: Vec<SecretKey> = (0..5).map(|_| SecretKey::random(&mut rng)).collect();
        let sigs: Vec<Signature> = sks.iter().map(|sk| sign(sk, dst::CRED, b"common")).collect();
        let pks: Vec<PublicKey> = sks.iter().map(|s| s.public()).collect();
        let agg = aggregate(&sigs);
        assert!(verify_aggregate_same_message(&pks, dst::CRED, b"common", &agg).is_ok());
        assert!(verify_aggregate_same_message(&pks[..4], dst::CRED, b"common", &agg).is_err());
    }

    #[test]
    fn threshold_signing_with_every_k_subset() {
        let mut rng = rng_from_seed(6);
        let (k, n) = (3usize, 5usize);
        let tk = ThresholdKey::generate(k, n, &mut rng).unwrap();
        let msg = b"threshold credential";

        let partials: Vec<PartialSignature> =
            tk.shares.iter().map(|s| partial_sign(s, dst::CRED, msg)).collect();

        for (p, spk) in partials.iter().zip(&tk.share_publics) {
            assert!(verify_partial(spk, dst::CRED, msg, p).is_ok());
        }

        for combo in crate::shamir::combinations(&partials, k) {
            let sig = combine(&combo, k).unwrap();
            assert!(
                verify(&tk.group_public, dst::CRED, msg, &sig).is_ok(),
                "subset {:?} failed",
                combo.iter().map(|p| p.index).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn threshold_below_k_does_not_produce_a_valid_signature() {
        let mut rng = rng_from_seed(7);
        let tk = ThresholdKey::generate(3, 5, &mut rng).unwrap();
        let msg = b"m";
        let partials: Vec<PartialSignature> =
            tk.shares.iter().map(|s| partial_sign(s, dst::CRED, msg)).collect();

        assert!(combine(&partials[..2], 3).is_err());
        // Combining 2 shares as if k were 2 interpolates the wrong constant term.
        let forged = combine(&partials[..2], 2).unwrap();
        assert!(verify(&tk.group_public, dst::CRED, msg, &forged).is_err());
    }
}
