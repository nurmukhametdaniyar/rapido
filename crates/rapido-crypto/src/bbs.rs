//! BBS+ signatures with selective disclosure — RAPIDO Mode B.
//!
//! Implemented directly on arkworks following the structure of the IETF BBS
//! draft. This is the `(A, e, s)` BBS+ variant (Au-Susilo-Mu / Camenisch-
//! Drijvers-Lehmann), *not* the newer two-element `(A, e)` BBS of
//! draft-irtf-cfrg-bbs-signatures. See `DEVIATIONS` below and `LIMITATIONS.md`.
//!
//! ## Scheme
//!
//! ```text
//! params : g1, h_0, h_1..h_L  in G1;  g2 in G2
//! key    : x in Fr,  W = x·g2
//! sign   : e,s <- Fr;  B = g1 + s·h_0 + Σ m_i·h_i;  A = (x+e)^-1 · B
//! verify : e(A, W + e·g2) == e(B, g2)
//! ```
//!
//! ## Presentation
//!
//! Re-randomize with `r1 <- Fr*`, `r2 <- Fr`, `r3 = r1^-1`, `s' = s - r2·r3`:
//!
//! ```text
//! A' = r1·A      A_bar = -e·A' + r1·B      d = r1·B - r2·h_0
//! ```
//!
//! Verification is `e(A', W) == e(A_bar, g2)` (two pairings, one multi-pairing
//! call) plus a Schnorr proof over two equations:
//!
//! ```text
//! (1) A_bar - d               = e·(-A') + r2·h_0
//! (2) g1 + Σ_{i∈D} m_i·h_i    = r3·d + s'·(-h_0) + Σ_{i∉D} m_i·(-h_i)
//! ```
//!
//! Equation (2) is the MSM whose size grows with the number of **hidden**
//! attributes. That is the term that makes Mode B presentation cost a function
//! of `L` and the disclosure fraction, and it is swept over both in
//! `rapido-bench`.
//!
//! ## DEVIATIONS from draft-irtf-cfrg-bbs-signatures
//!
//! The draft standardizes the two-element `(A, e)` signature over the
//! `BLS12-381-SHA-256` ciphersuite; its published test vectors therefore do not
//! apply to the three-element BBS+ signature RAPIDO Mode B uses, and no
//! known-answer test against them is possible. The generator derivation here
//! also uses plain indexed hash-to-curve rather than the draft's
//! `create_generators` seed chain. Both deviations are deliberate and recorded
//! in `LIMITATIONS.md`. Correctness is established instead by round-trip,
//! soundness, and property tests in this module.

use crate::{hash, relation, ser};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, One, UniformRand, Zero};
use rapido_core::{dst, Error, Result, Transcript};
use std::collections::{BTreeMap, BTreeSet};

/// Map arbitrary attribute bytes to a message scalar.
pub fn message_from_bytes(b: &[u8]) -> Fr {
    hash::hash_to_scalar(dst::BBS_MSG, b)
}

/// Public parameters for signing `L` messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub l: usize,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub h0: G1Projective,
    /// `h_1..h_L`, one per attribute slot.
    pub h: Vec<G1Projective>,
}

impl Params {
    /// Derive parameters deterministically from the DST. Every party computes
    /// the same generators, and nobody knows a discrete-log relation among them.
    pub fn new(l: usize) -> Self {
        Params {
            l,
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
            h0: hash::indexed_generator_g1(dst::BBS_GEN, "RAPIDO-BBS-h0", 0),
            h: (0..l)
                .map(|i| hash::indexed_generator_g1(dst::BBS_GEN, "RAPIDO-BBS-h", i))
                .collect(),
        }
    }

    /// `B = g1 + s·h_0 + Σ m_i·h_i`.
    fn commitment(&self, s: Fr, msgs: &[Fr]) -> G1Projective {
        let mut bases = Vec::with_capacity(msgs.len() + 1);
        let mut scalars = Vec::with_capacity(msgs.len() + 1);
        bases.push(self.h0);
        scalars.push(s);
        bases.extend_from_slice(&self.h);
        scalars.extend_from_slice(msgs);
        self.g1 + relation::msm(&bases, &scalars)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecretKey(pub Fr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

impl SecretKey {
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        SecretKey(Fr::rand(rng))
    }
    pub fn public(&self) -> PublicKey {
        PublicKey(G2Projective::generator() * self.0)
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::g2_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(PublicKey(ser::g2_from_bytes(b, "bbs public key")?))
    }
}

/// A BBS+ signature `(A, e, s)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub a: G1Projective,
    pub e: Fr,
    pub s: Fr,
}

impl Signature {
    /// Wire size: one compressed G1 point plus two scalars.
    pub const SIZE: usize = ser::G1_COMPRESSED_LEN + 2 * ser::FR_LEN;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = ser::g1_to_bytes(&self.a);
        out.extend_from_slice(&ser::fr_to_bytes(&self.e));
        out.extend_from_slice(&ser::fr_to_bytes(&self.s));
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != Self::SIZE {
            return Err(Error::Deserialization("bbs signature: wrong length".into()));
        }
        Ok(Signature {
            a: ser::g1_from_bytes(&b[..48], "bbs A")?,
            e: ser::fr_from_bytes(&b[48..80], "bbs e")?,
            s: ser::fr_from_bytes(&b[80..], "bbs s")?,
        })
    }
}

/// Sign `msgs` (exactly `params.l` of them).
pub fn sign<R: rand::Rng + ?Sized>(
    params: &Params,
    sk: &SecretKey,
    msgs: &[Fr],
    rng: &mut R,
) -> Result<Signature> {
    if msgs.len() != params.l {
        return Err(Error::InvalidParameter(format!(
            "bbs sign: expected {} messages, got {}",
            params.l,
            msgs.len()
        )));
    }
    let e = Fr::rand(rng);
    let s = Fr::rand(rng);
    let b = params.commitment(s, msgs);
    let denom = (sk.0 + e)
        .inverse()
        .ok_or_else(|| Error::InvalidParameter("bbs sign: x + e == 0".into()))?;
    Ok(Signature { a: b * denom, e, s })
}

/// Verify a signature against the full message vector: `e(A, W + e·g2) == e(B, g2)`.
pub fn verify(params: &Params, pk: &PublicKey, msgs: &[Fr], sig: &Signature) -> Result<()> {
    if msgs.len() != params.l {
        return Err(Error::InvalidParameter("bbs verify: message count mismatch".into()));
    }
    if sig.a.is_zero() {
        return Err(Error::IdentityPoint("bbs signature A"));
    }
    let b = params.commitment(sig.s, msgs);
    let lhs_g2 = pk.0 + params.g2 * sig.e;
    // e(A, W + e·g2) · e(-B, g2) == 1
    let out = Bls12_381::multi_pairing(
        [sig.a.into_affine(), (-b).into_affine()],
        [lhs_g2.into_affine(), params.g2.into_affine()],
    );
    if out.0.is_one() {
        Ok(())
    } else {
        Err(Error::BadSignature("bbs signature"))
    }
}

// --- presentation ----------------------------------------------------------

/// Where each witness sits in the proof's witness vector.
///
/// Exposed so a caller can build *additional* equations that name a BBS+
/// message witness — which is how the E2 escrow proof binds a ciphertext to a
/// hidden credential attribute without ever revealing it.
#[derive(Debug, Clone)]
pub struct WitnessLayout {
    pub e: usize,
    pub r2: usize,
    pub r3: usize,
    pub s_prime: usize,
    /// message index -> witness index, for hidden messages only.
    pub message: BTreeMap<usize, usize>,
    /// Number of witnesses used by the BBS+ proof itself. Extension witnesses
    /// start here.
    pub n_bbs: usize,
}

impl WitnessLayout {
    fn build(hidden: &[usize]) -> Self {
        let mut message = BTreeMap::new();
        for (k, idx) in hidden.iter().enumerate() {
            message.insert(*idx, 4 + k);
        }
        WitnessLayout { e: 0, r2: 1, r3: 2, s_prime: 3, message, n_bbs: 4 + hidden.len() }
    }
}

/// Extra equations and witnesses to prove alongside the BBS+ statement under a
/// single shared Fiat-Shamir challenge.
#[derive(Debug, Clone, Default)]
pub struct ProofExtension {
    /// Values for witness indices `layout.n_bbs .. layout.n_bbs + len`.
    pub extra_witnesses: Vec<Fr>,
    pub equations: Vec<relation::Equation>,
}

/// The verifier's copy of an extension: the same equations, minus the witness
/// values it must not learn.
#[derive(Debug, Clone, Default)]
pub struct ExtensionStatement {
    pub n_extra_witnesses: usize,
    pub equations: Vec<relation::Equation>,
}

/// A selective-disclosure presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    pub a_prime: G1Projective,
    pub a_bar: G1Projective,
    pub d: G1Projective,
    /// Disclosed attributes, by index.
    pub disclosed: BTreeMap<usize, Fr>,
    pub proof: relation::LinearProof,
}

impl Presentation {
    /// Wire size in bytes: three compressed G1 points, the Schnorr proof, and
    /// the disclosed attribute values with their indices.
    pub fn size_bytes(&self) -> usize {
        3 * ser::G1_COMPRESSED_LEN
            + self.proof.size_bytes()
            + self.disclosed.len() * (4 + ser::FR_LEN)
    }

    pub fn hidden_indices(&self, l: usize) -> Vec<usize> {
        (0..l).filter(|i| !self.disclosed.contains_key(i)).collect()
    }
}

/// Bind the presentation to the verifier's nonce and the disclosed set.
fn presentation_aux(nonce: &[u8], disclosed: &BTreeMap<usize, Fr>, l: usize) -> Vec<u8> {
    let mut t = Transcript::new(dst::BBS_CHALLENGE);
    t.push_usize(l);
    t.push_bytes(nonce);
    t.push_usize(disclosed.len());
    for (i, m) in disclosed {
        t.push_usize(*i);
        t.push_bytes(&ser::fr_to_bytes(m));
    }
    t.finish()
}

/// Build the two BBS+ equations. Shared by prover and verifier so the two can
/// never drift apart.
fn bbs_equations(
    params: &Params,
    a_prime: G1Projective,
    a_bar: G1Projective,
    d: G1Projective,
    disclosed: &BTreeMap<usize, Fr>,
    hidden: &[usize],
    layout: &WitnessLayout,
) -> Vec<relation::Equation> {
    // (1) A_bar - d = e·(-A') + r2·h_0
    let eq1 =
        relation::Equation::new(a_bar - d, vec![(layout.e, -a_prime), (layout.r2, params.h0)]);

    // (2) g1 + Σ_{i∈D} m_i·h_i = r3·d + s'·(-h_0) + Σ_{i∉D} m_i·(-h_i)
    let disclosed_bases: Vec<G1Projective> = disclosed.keys().map(|i| params.h[*i]).collect();
    let disclosed_scalars: Vec<Fr> = disclosed.values().copied().collect();
    let lhs2 = params.g1 + relation::msm(&disclosed_bases, &disclosed_scalars);

    let mut terms = vec![(layout.r3, d), (layout.s_prime, -params.h0)];
    for i in hidden {
        terms.push((layout.message[i], -params.h[*i]));
    }
    let eq2 = relation::Equation::new(lhs2, terms);

    vec![eq1, eq2]
}

/// Produce a presentation disclosing exactly the indices in `disclose`.
// Every argument is an independent input to the proof; bundling them into a
// struct would only move the same fields behind one more indirection.
#[allow(clippy::too_many_arguments)]
pub fn present<R: rand::Rng + ?Sized>(
    params: &Params,
    pk: &PublicKey,
    msgs: &[Fr],
    sig: &Signature,
    disclose: &BTreeSet<usize>,
    nonce: &[u8],
    extension: Option<&ProofExtension>,
    rng: &mut R,
) -> Result<Presentation> {
    if msgs.len() != params.l {
        return Err(Error::InvalidParameter("bbs present: message count mismatch".into()));
    }
    if let Some(bad) = disclose.iter().find(|i| **i >= params.l) {
        return Err(Error::BadDisclosure(format!("index {bad} out of range")));
    }
    // A malformed signature would produce a presentation that fails only at the
    // verifier; catching it here keeps failures attributable to the right party.
    verify(params, pk, msgs, sig)?;

    // r1 must be invertible; Fr::rand hits zero with negligible probability but
    // the loop makes the invariant explicit rather than assumed.
    let (r1, r3) = loop {
        let r1 = Fr::rand(rng);
        if let Some(inv) = r1.inverse() {
            break (r1, inv);
        }
    };
    let r2 = Fr::rand(rng);

    let b = params.commitment(sig.s, msgs);
    let a_prime = sig.a * r1;
    let a_bar = a_prime * (-sig.e) + b * r1;
    let d = b * r1 - params.h0 * r2;
    let s_prime = sig.s - r2 * r3;

    let disclosed: BTreeMap<usize, Fr> = disclose.iter().map(|i| (*i, msgs[*i])).collect();
    let hidden: Vec<usize> = (0..params.l).filter(|i| !disclose.contains(i)).collect();
    let layout = WitnessLayout::build(&hidden);

    let mut witnesses = vec![Fr::zero(); layout.n_bbs];
    witnesses[layout.e] = sig.e;
    witnesses[layout.r2] = r2;
    witnesses[layout.r3] = r3;
    witnesses[layout.s_prime] = s_prime;
    for i in &hidden {
        witnesses[layout.message[i]] = msgs[*i];
    }

    let mut equations = bbs_equations(params, a_prime, a_bar, d, &disclosed, &hidden, &layout);
    if let Some(ext) = extension {
        witnesses.extend_from_slice(&ext.extra_witnesses);
        equations.extend(ext.equations.iter().cloned());
    }

    let rel = relation::Relation { n_witnesses: witnesses.len(), equations };
    let aux = presentation_aux(nonce, &disclosed, params.l);
    let proof = rel.prove(dst::BBS_CHALLENGE, &witnesses, &aux, rng)?;

    Ok(Presentation { a_prime, a_bar, d, disclosed, proof })
}

/// Verify a presentation. Returns the disclosed attributes on success.
pub fn verify_presentation(
    params: &Params,
    pk: &PublicKey,
    pres: &Presentation,
    nonce: &[u8],
    extension: Option<&ExtensionStatement>,
) -> Result<BTreeMap<usize, Fr>> {
    if let Some(bad) = pres.disclosed.keys().find(|i| **i >= params.l) {
        return Err(Error::BadDisclosure(format!("index {bad} out of range")));
    }
    // A' = identity would make the pairing check vacuous.
    if pres.a_prime.is_zero() {
        return Err(Error::IdentityPoint("bbs presentation A'"));
    }

    // Pairing check: e(A', W) · e(-A_bar, g2) == 1.
    let out = Bls12_381::multi_pairing(
        [pres.a_prime.into_affine(), (-pres.a_bar).into_affine()],
        [pk.0.into_affine(), params.g2.into_affine()],
    );
    if !out.0.is_one() {
        return Err(Error::BadSignature("bbs presentation pairing check"));
    }

    let hidden = pres.hidden_indices(params.l);
    let layout = WitnessLayout::build(&hidden);
    let mut equations =
        bbs_equations(params, pres.a_prime, pres.a_bar, pres.d, &pres.disclosed, &hidden, &layout);
    let mut n_witnesses = layout.n_bbs;
    if let Some(ext) = extension {
        n_witnesses += ext.n_extra_witnesses;
        equations.extend(ext.equations.iter().cloned());
    }

    let rel = relation::Relation { n_witnesses, equations };
    let aux = presentation_aux(nonce, &pres.disclosed, params.l);
    rel.verify(dst::BBS_CHALLENGE, &pres.proof, &aux)?;

    Ok(pres.disclosed.clone())
}

/// The witness layout a verifier-side extension must target, given which
/// attribute indices the presentation hides.
pub fn witness_layout(l: usize, disclose: &BTreeSet<usize>) -> WitnessLayout {
    let hidden: Vec<usize> = (0..l).filter(|i| !disclose.contains(i)).collect();
    WitnessLayout::build(&hidden)
}

// --- threshold issuance ----------------------------------------------------

/// Threshold BBS+ issuance is **not implemented**; see `LIMITATIONS.md`.
///
/// Unlike threshold BLS, where the signature is `H(m)^x` and is therefore
/// linear in the secret, a BBS+ signature is `A = B^{1/(x+e)}`. Producing it
/// from Shamir shares of `x` requires distributed inversion of the shared
/// secret — an interactive multiparty protocol (Bar-Ilan-Beaver style
/// masked inversion, or a full MPC) with at least two communication rounds
/// among the authorities, plus agreement on `e`. That is out of scope for this
/// implementation, and it is recorded as a limitation rather than papered over:
/// **Mode B in this implementation issues from a single authority**, whereas
/// Mode A issues from a real `(k, n)` threshold. Any comparison of issuance
/// cost between the two modes must state this asymmetry.
pub const THRESHOLD_ISSUANCE_SUPPORTED: bool = false;

/// Helper for benchmarks: the affine forms the pairing check consumes.
pub fn presentation_pairing_inputs(
    params: &Params,
    pk: &PublicKey,
    pres: &Presentation,
) -> ([G1Affine; 2], [G2Affine; 2]) {
    (
        [pres.a_prime.into_affine(), (-pres.a_bar).into_affine()],
        [pk.0.into_affine(), params.g2.into_affine()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng_from_seed;
    use ark_ec::AdditiveGroup;

    fn setup(
        l: usize,
        seed: u64,
    ) -> (Params, SecretKey, PublicKey, Vec<Fr>, Signature, crate::Rng) {
        let mut rng = rng_from_seed(seed);
        let params = Params::new(l);
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public();
        let msgs: Vec<Fr> =
            (0..l).map(|i| message_from_bytes(format!("attribute-{i}").as_bytes())).collect();
        let sig = sign(&params, &sk, &msgs, &mut rng).unwrap();
        (params, sk, pk, msgs, sig, rng)
    }

    #[test]
    fn sign_verify_round_trip() {
        for l in [1usize, 4, 8, 16] {
            let (params, _sk, pk, msgs, sig, _) = setup(l, 100 + l as u64);
            assert!(verify(&params, &pk, &msgs, &sig).is_ok(), "L={l}");
        }
    }

    #[test]
    fn signature_does_not_verify_on_altered_messages() {
        let (params, _sk, pk, mut msgs, sig, _) = setup(4, 1);
        msgs[2] = message_from_bytes(b"different");
        assert!(verify(&params, &pk, &msgs, &sig).is_err());
    }

    #[test]
    fn signature_does_not_verify_under_a_different_key() {
        let (params, _sk, _pk, msgs, sig, mut rng) = setup(4, 2);
        let other = SecretKey::random(&mut rng).public();
        assert!(verify(&params, &other, &msgs, &sig).is_err());
    }

    #[test]
    fn signature_serialization_round_trip() {
        let (_p, _sk, _pk, _m, sig, _) = setup(4, 3);
        let b = sig.to_bytes();
        assert_eq!(b.len(), Signature::SIZE);
        assert_eq!(Signature::from_bytes(&b).unwrap(), sig);
    }

    #[test]
    fn presentation_round_trip_at_every_disclosure_fraction() {
        let l = 8;
        let (params, _sk, pk, msgs, sig, mut rng) = setup(l, 4);
        for n_disclosed in 0..=l {
            let disclose: BTreeSet<usize> = (0..n_disclosed).collect();
            let pres =
                present(&params, &pk, &msgs, &sig, &disclose, b"nonce-1", None, &mut rng).unwrap();
            let got = verify_presentation(&params, &pk, &pres, b"nonce-1", None).unwrap();
            assert_eq!(got.len(), n_disclosed);
            for i in &disclose {
                assert_eq!(got[i], msgs[*i], "disclosed attribute {i} mismatch");
            }
        }
    }

    #[test]
    fn presentation_is_bound_to_the_verifier_nonce() {
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 5);
        let disclose = BTreeSet::from([0usize]);
        let pres =
            present(&params, &pk, &msgs, &sig, &disclose, b"nonce-A", None, &mut rng).unwrap();
        assert!(verify_presentation(&params, &pk, &pres, b"nonce-A", None).is_ok());
        assert!(verify_presentation(&params, &pk, &pres, b"nonce-B", None).is_err());
    }

    /// Negative test: a presentation claiming an undisclosed attribute value
    /// must be rejected.
    #[test]
    fn claiming_a_false_attribute_value_is_rejected() {
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 6);
        let disclose = BTreeSet::from([1usize]);
        let mut pres = present(&params, &pk, &msgs, &sig, &disclose, b"n", None, &mut rng).unwrap();

        // Swap the disclosed value for one the credential does not contain.
        pres.disclosed.insert(1, message_from_bytes(b"emergency-vehicle"));
        assert!(verify_presentation(&params, &pk, &pres, b"n", None).is_err());

        // Move a hidden attribute into the disclosed set without a matching
        // proof: the witness layout changes, so verification must fail.
        let mut pres2 =
            present(&params, &pk, &msgs, &sig, &disclose, b"n", None, &mut rng).unwrap();
        pres2.disclosed.insert(2, msgs[2]);
        assert!(verify_presentation(&params, &pk, &pres2, b"n", None).is_err());
    }

    #[test]
    fn tampered_presentation_points_are_rejected() {
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 7);
        let disclose = BTreeSet::from([0usize]);
        let base = present(&params, &pk, &msgs, &sig, &disclose, b"n", None, &mut rng).unwrap();

        for mutate in [0usize, 1, 2] {
            let mut p = base.clone();
            match mutate {
                0 => p.a_prime = p.a_prime.double(),
                1 => p.a_bar = p.a_bar.double(),
                _ => p.d = p.d.double(),
            }
            assert!(
                verify_presentation(&params, &pk, &p, b"n", None).is_err(),
                "mutation {mutate} accepted"
            );
        }
    }

    #[test]
    fn presentation_from_a_forged_signature_is_rejected() {
        let (params, _sk, pk, msgs, _sig, mut rng) = setup(4, 8);
        let forged = Signature { a: params.g1, e: Fr::rand(&mut rng), s: Fr::rand(&mut rng) };
        let disclose = BTreeSet::from([0usize]);
        assert!(present(&params, &pk, &msgs, &forged, &disclose, b"n", None, &mut rng).is_err());
    }

    #[test]
    fn two_presentations_of_one_credential_are_unlinkable_at_the_bytes() {
        // Every presented element is freshly re-randomized, so a verifier sees
        // no repeated value across sessions. (The statistical version of this
        // claim is measured in rapido-sim Scenario 4.)
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 9);
        let disclose = BTreeSet::from([0usize]);
        let p1 = present(&params, &pk, &msgs, &sig, &disclose, b"n1", None, &mut rng).unwrap();
        let p2 = present(&params, &pk, &msgs, &sig, &disclose, b"n2", None, &mut rng).unwrap();
        assert_ne!(p1.a_prime, p2.a_prime);
        assert_ne!(p1.a_bar, p2.a_bar);
        assert_ne!(p1.d, p2.d);
        assert_ne!(p1.proof, p2.proof);
    }

    #[test]
    fn disclosure_index_out_of_range_is_rejected() {
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 10);
        let disclose = BTreeSet::from([9usize]);
        assert!(matches!(
            present(&params, &pk, &msgs, &sig, &disclose, b"n", None, &mut rng),
            Err(Error::BadDisclosure(_))
        ));
    }

    #[test]
    fn extension_equations_share_the_bbs_witness() {
        // Prove, alongside the presentation, that a Pedersen commitment opens
        // to hidden attribute 2 — the mechanism the E2 escrow proof uses.
        use crate::pedersen;
        let (params, _sk, pk, msgs, sig, mut rng) = setup(4, 11);
        let disclose = BTreeSet::from([0usize]);
        let layout = witness_layout(params.l, &disclose);
        let w_id = layout.message[&2];

        let ped = pedersen::Params::default();
        let blinding = Fr::rand(&mut rng);
        let commitment = ped.commit(msgs[2], blinding);

        let ext = ProofExtension {
            extra_witnesses: vec![blinding],
            equations: vec![ped.equation(&commitment, w_id, layout.n_bbs)],
        };
        let stmt = ExtensionStatement {
            n_extra_witnesses: 1,
            equations: vec![ped.equation(&commitment, w_id, layout.n_bbs)],
        };

        let pres =
            present(&params, &pk, &msgs, &sig, &disclose, b"n", Some(&ext), &mut rng).unwrap();
        assert!(verify_presentation(&params, &pk, &pres, b"n", Some(&stmt)).is_ok());

        // A commitment to a *different* value must not verify against the same
        // proof: the shared witness index is what forces equality.
        let wrong = ped.commit(message_from_bytes(b"someone else"), blinding);
        let bad = ExtensionStatement {
            n_extra_witnesses: 1,
            equations: vec![ped.equation(&wrong, w_id, layout.n_bbs)],
        };
        assert!(verify_presentation(&params, &pk, &pres, b"n", Some(&bad)).is_err());
    }

    #[test]
    fn presentation_size_grows_with_hidden_attribute_count() {
        let l = 16;
        let (params, _sk, pk, msgs, sig, mut rng) = setup(l, 12);
        let all: BTreeSet<usize> = (0..l).collect();
        let none = BTreeSet::new();
        let p_all = present(&params, &pk, &msgs, &sig, &all, b"n", None, &mut rng).unwrap();
        let p_none = present(&params, &pk, &msgs, &sig, &none, b"n", None, &mut rng).unwrap();
        // Hiding everything costs one response scalar per hidden attribute;
        // disclosing everything costs one field element per disclosed one.
        assert_eq!(p_none.proof.responses.len(), 4 + l);
        assert_eq!(p_all.proof.responses.len(), 4);
        assert!(p_all.size_bytes() > 0 && p_none.size_bytes() > 0);
    }

    /// Guards the documented limitation: if threshold BBS+ issuance is ever
    /// implemented, this flag and `LIMITATIONS.md` must be updated together.
    #[test]
    fn threshold_issuance_is_declared_unsupported() {
        let supported: bool = THRESHOLD_ISSUANCE_SUPPORTED;
        assert!(!supported, "see LIMITATIONS.md");
    }
}
