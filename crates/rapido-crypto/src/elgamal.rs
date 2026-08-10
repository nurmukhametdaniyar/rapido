//! Threshold ElGamal over G1 with a proof of correct encryption.
//!
//! Layer 3 identity escrow: an agent attaches an encryption of its identity
//! under a `(k, n)` threshold key held by escrow authorities. De-anonymization
//! requires `k` of them to cooperate.
//!
//! ## Identity encoding
//!
//! The plaintext is the group element `M = id·G`, where `id` is the agent's
//! identity scalar. Recovering `M` does not by itself recover `id` (that would
//! be a discrete log); the escrow authorities resolve `M` through the
//! registration table they already hold from enrolment. This is the standard
//! "encrypt to a registered public element" construction and is why
//! [`Registry`] exists. Hybrid encryption would avoid the table at the cost of
//! making the correctness proof a circuit rather than three Schnorr equations —
//! not worth it here, and the tradeoff is stated in the README.
//!
//! ## E1 vs E2
//!
//! [`encrypt`] alone is variant **E1**, and it is *insecure* — see the
//! documentation on [`escrow_relation`].

use crate::{hash, pedersen, relation, ser, shamir};
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use rapido_core::{dst, Error, Result};
use std::collections::HashMap;

/// An agent identity as a scalar. Derived from the enrolment identifier.
pub fn identity_scalar(agent_id: &[u8]) -> Fr {
    hash::hash_to_scalar(dst::ESCROW, agent_id)
}

/// `M = id·G`, the group element actually encrypted.
pub fn identity_point(id: Fr) -> G1Projective {
    G1Projective::generator() * id
}

/// A `(k, n)` threshold escrow key.
#[derive(Debug, Clone)]
pub struct EscrowKey {
    pub k: usize,
    pub n: usize,
    /// `Y = x·G`, the escrow public key.
    pub public: G1Projective,
    pub shares: Vec<shamir::Share>,
    /// `s_j·G`, so a malformed partial decryption can be attributed.
    pub share_publics: Vec<G1Projective>,
}

impl EscrowKey {
    pub fn generate<R: rand::Rng + ?Sized>(k: usize, n: usize, rng: &mut R) -> Result<Self> {
        let x = Fr::rand(rng);
        let shares = shamir::split(x, k, n, rng)?;
        let g = G1Projective::generator();
        Ok(EscrowKey {
            k,
            n,
            public: g * x,
            share_publics: shares.iter().map(|s| g * s.value).collect(),
            shares,
        })
    }
}

/// ElGamal ciphertext `(R, C) = (r·G, M + r·Y)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext {
    pub r_point: G1Projective,
    pub c: G1Projective,
}

impl Ciphertext {
    /// Wire size: two compressed G1 points.
    pub const SIZE: usize = 2 * ser::G1_COMPRESSED_LEN;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = ser::g1_to_bytes(&self.r_point);
        out.extend_from_slice(&ser::g1_to_bytes(&self.c));
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != Self::SIZE {
            return Err(Error::Deserialization("elgamal ciphertext: wrong length".into()));
        }
        Ok(Ciphertext {
            r_point: ser::g1_from_bytes(&b[..48], "elgamal R")?,
            c: ser::g1_from_bytes(&b[48..], "elgamal C")?,
        })
    }
}

/// Encrypt `m` under escrow public key `y`. Returns the ciphertext and the
/// randomness, which the E2 prover needs as a witness.
pub fn encrypt<R: rand::Rng + ?Sized>(
    y: G1Projective,
    m: G1Projective,
    rng: &mut R,
) -> (Ciphertext, Fr) {
    let r = Fr::rand(rng);
    (Ciphertext { r_point: G1Projective::generator() * r, c: m + y * r }, r)
}

/// One authority's contribution `D_j = s_j·R`.
#[derive(Debug, Clone, Copy)]
pub struct PartialDecryption {
    pub index: u32,
    pub point: G1Projective,
}

pub fn partial_decrypt(share: &shamir::Share, ct: &Ciphertext) -> PartialDecryption {
    PartialDecryption { index: share.index, point: ct.r_point * share.value }
}

/// Check `D_j` against authority `j`'s public key: `log_G(S_j) == log_R(D_j)`.
/// Without this, one authority can silently corrupt the recovered identity.
pub fn verify_partial_decryption<R: rand::Rng + ?Sized>(
    share_public: G1Projective,
    ct: &Ciphertext,
    partial: &PartialDecryption,
    proof: &relation::LinearProof,
    _rng: &mut R,
) -> Result<()> {
    let rel =
        relation::dleq_relation(G1Projective::generator(), share_public, ct.r_point, partial.point);
    rel.verify(dst::ESCROW_CP, proof, b"partial-decryption")
        .map_err(|_| Error::BadProof("escrow partial decryption"))
}

/// Prove a partial decryption was computed with the authority's real share.
pub fn prove_partial_decryption<R: rand::Rng + ?Sized>(
    share: &shamir::Share,
    ct: &Ciphertext,
    rng: &mut R,
) -> Result<relation::LinearProof> {
    let g = G1Projective::generator();
    let rel = relation::dleq_relation(g, g * share.value, ct.r_point, ct.r_point * share.value);
    rel.prove(dst::ESCROW_CP, &[share.value], b"partial-decryption", rng)
}

/// Lagrange-combine `k` partial decryptions and recover `M = C - x·R`.
pub fn combine_decryptions(
    partials: &[PartialDecryption],
    ct: &Ciphertext,
    k: usize,
) -> Result<G1Projective> {
    if partials.len() < k {
        return Err(Error::NotEnoughShares { need: k, got: partials.len() });
    }
    let subset = &partials[..k];
    let idx: Vec<u32> = subset.iter().map(|p| p.index).collect();
    let coeffs = shamir::lagrange_at_zero(&idx)?;
    let bases: Vec<G1Projective> = subset.iter().map(|p| p.point).collect();
    let xr = relation::msm(&bases, &coeffs);
    Ok(ct.c - xr)
}

/// Enrolment table mapping `id·G` back to an agent identifier. Held by the
/// escrow authorities, never by verifiers.
#[derive(Debug, Default, Clone)]
pub struct Registry {
    table: HashMap<Vec<u8>, Vec<u8>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enrol(&mut self, agent_id: &[u8]) -> Fr {
        let id = identity_scalar(agent_id);
        self.table.insert(ser::g1_to_bytes(&identity_point(id)), agent_id.to_vec());
        id
    }

    pub fn resolve(&self, m: &G1Projective) -> Option<&[u8]> {
        self.table.get(&ser::g1_to_bytes(m)).map(|v| v.as_slice())
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

// --- E2: proof of correct encryption ---------------------------------------

/// Witness indices for a standalone escrow proof.
pub const W_ID: usize = 0;
pub const W_R: usize = 1;
pub const W_BLIND: usize = 2;
pub const N_WITNESSES: usize = 3;

/// The statement proved by escrow variant **E2**.
///
/// Three equations over witnesses `(id, r, t)`:
///
/// ```text
/// R    = r·G                  the ciphertext randomness is known
/// C    = id·G + r·Y           the ciphertext encrypts id under the escrow key
/// C_id = id·G + t·H           the same id is the one committed in the credential
/// ```
///
/// The `id` witness appears in both the ciphertext equation and the credential
/// commitment equation, and both are proved under one Fiat-Shamir challenge.
/// That shared witness is the entire security content: it is what makes the
/// ciphertext provably an encryption of *the credentialed identity* rather than
/// of arbitrary bytes.
///
/// # Why E1 is insecure
///
/// Escrow variant **E1** — attaching the ciphertext with no proof at all —
/// **defeats accountability entirely**. A malicious agent encrypts garbage (or another agent's
/// identity, or a random point) instead of its own. Every verifier accepts the
/// presentation, because nothing checks the ciphertext. The agent then acts
/// anonymously with no recourse: when the escrow authorities later cooperate to
/// de-anonymize it, they decrypt to a point that resolves to nobody, or to an
/// innocent third party. E1 provides the appearance of accountable anonymity
/// and none of the substance. It is implemented here only so its cost can be
/// measured as the floor that E2 is compared against; the measured difference
/// `E2 - E1` is the price of an escrow that actually works.
pub fn escrow_relation(
    ped: &pedersen::Params,
    y: G1Projective,
    ct: &Ciphertext,
    commitment: &pedersen::Commitment,
    w_id: usize,
    w_r: usize,
    w_blind: usize,
) -> relation::Relation {
    let g = G1Projective::generator();
    let mut rel = relation::Relation::new(0);
    rel.equations = vec![
        relation::Equation::new(ct.r_point, vec![(w_r, g)]),
        relation::Equation::new(ct.c, vec![(w_id, g), (w_r, y)]),
        ped.equation(commitment, w_id, w_blind),
    ];
    rel
}

/// Standalone E2 proof (Mode A: the credential commitment is signed into the
/// pseudonym certificate).
#[allow(clippy::too_many_arguments)] // the witness and the statement are both irreducible here
pub fn prove_correct_encryption<R: rand::Rng + ?Sized>(
    ped: &pedersen::Params,
    y: G1Projective,
    ct: &Ciphertext,
    commitment: &pedersen::Commitment,
    id: Fr,
    r: Fr,
    blinding: Fr,
    context: &[u8],
    rng: &mut R,
) -> Result<relation::LinearProof> {
    let mut rel = escrow_relation(ped, y, ct, commitment, W_ID, W_R, W_BLIND);
    rel.n_witnesses = N_WITNESSES;
    rel.prove(dst::ESCROW_CP, &[id, r, blinding], context, rng)
}

/// Run the E2 prover on a witness that may not satisfy the statement — what a
/// cheating agent would do. Used by soundness tests and by the simulator's
/// adversary; the proof it returns is expected to fail verification.
#[allow(clippy::too_many_arguments)]
pub fn prove_correct_encryption_unchecked<R: rand::Rng + ?Sized>(
    ped: &pedersen::Params,
    y: G1Projective,
    ct: &Ciphertext,
    commitment: &pedersen::Commitment,
    id: Fr,
    r: Fr,
    blinding: Fr,
    context: &[u8],
    rng: &mut R,
) -> Result<relation::LinearProof> {
    let mut rel = escrow_relation(ped, y, ct, commitment, W_ID, W_R, W_BLIND);
    rel.n_witnesses = N_WITNESSES;
    rel.prove_unchecked(dst::ESCROW_CP, &[id, r, blinding], context, rng)
}

pub fn verify_correct_encryption(
    ped: &pedersen::Params,
    y: G1Projective,
    ct: &Ciphertext,
    commitment: &pedersen::Commitment,
    proof: &relation::LinearProof,
    context: &[u8],
) -> Result<()> {
    let mut rel = escrow_relation(ped, y, ct, commitment, W_ID, W_R, W_BLIND);
    rel.n_witnesses = N_WITNESSES;
    rel.verify(dst::ESCROW_CP, proof, context)
        .map_err(|_| Error::BadEscrow("proof of correct encryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rng_from_seed, shamir::combinations};

    #[test]
    fn threshold_decryption_with_every_k_subset() {
        let mut rng = rng_from_seed(1);
        for (k, n) in [(2usize, 3usize), (3, 5)] {
            let key = EscrowKey::generate(k, n, &mut rng).unwrap();
            let id = identity_scalar(b"agent-42");
            let m = identity_point(id);
            let (ct, _r) = encrypt(key.public, m, &mut rng);

            let partials: Vec<PartialDecryption> =
                key.shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
            for combo in combinations(&partials, k) {
                assert_eq!(combine_decryptions(&combo, &ct, k).unwrap(), m, "k={k} n={n}");
            }
            if k >= 2 {
                assert!(combine_decryptions(&partials[..k - 1], &ct, k).is_err());
            }
        }
    }

    #[test]
    fn partial_decryption_proof_catches_a_lying_authority() {
        let mut rng = rng_from_seed(2);
        let key = EscrowKey::generate(2, 3, &mut rng).unwrap();
        let (ct, _) = encrypt(key.public, identity_point(identity_scalar(b"a")), &mut rng);

        let good = partial_decrypt(&key.shares[0], &ct);
        let proof = prove_partial_decryption(&key.shares[0], &ct, &mut rng).unwrap();
        assert!(
            verify_partial_decryption(key.share_publics[0], &ct, &good, &proof, &mut rng).is_ok()
        );

        // A partial decryption computed with the wrong share fails against the
        // claimed authority's public key.
        assert!(
            verify_partial_decryption(key.share_publics[1], &ct, &good, &proof, &mut rng).is_err()
        );
    }

    #[test]
    fn registry_resolves_a_decrypted_identity() {
        let mut rng = rng_from_seed(3);
        let mut reg = Registry::new();
        for i in 0..64u32 {
            reg.enrol(format!("agent-{i}").as_bytes());
        }
        let key = EscrowKey::generate(2, 3, &mut rng).unwrap();
        let id = identity_scalar(b"agent-17");
        let (ct, _) = encrypt(key.public, identity_point(id), &mut rng);
        let partials: Vec<_> = key.shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        let m = combine_decryptions(&partials, &ct, 2).unwrap();
        assert_eq!(reg.resolve(&m), Some(b"agent-17".as_slice()));
    }

    #[test]
    fn e2_proof_round_trip() {
        let mut rng = rng_from_seed(4);
        let ped = pedersen::Params::default();
        let key = EscrowKey::generate(2, 3, &mut rng).unwrap();
        let id = identity_scalar(b"agent-7");
        let (commitment, opening) = ped.commit_random(id, &mut rng);
        let (ct, r) = encrypt(key.public, identity_point(id), &mut rng);

        let proof = prove_correct_encryption(
            &ped,
            key.public,
            &ct,
            &commitment,
            id,
            r,
            opening.blinding,
            b"ctx",
            &mut rng,
        )
        .unwrap();
        assert!(
            verify_correct_encryption(&ped, key.public, &ct, &commitment, &proof, b"ctx").is_ok()
        );
        assert!(verify_correct_encryption(&ped, key.public, &ct, &commitment, &proof, b"other")
            .is_err());
    }

    /// Build a ciphertext that does **not** encrypt the committed identity.
    /// E2 must reject it; E1 accepts it, and that is precisely the
    /// vulnerability E1 has.
    #[test]
    fn e2_rejects_what_e1_accepts() {
        let mut rng = rng_from_seed(5);
        let ped = pedersen::Params::default();
        let key = EscrowKey::generate(2, 3, &mut rng).unwrap();

        let real_id = identity_scalar(b"honest-agent");
        let (commitment, opening) = ped.commit_random(real_id, &mut rng);

        // The malicious agent encrypts garbage instead of its own identity.
        let garbage = identity_scalar(b"not-my-identity-at-all");
        let (bad_ct, bad_r) = encrypt(key.public, identity_point(garbage), &mut rng);

        // --- E1: no proof is checked, so this presentation is accepted. ---
        // There is nothing to call: E1's verification of the ciphertext is the
        // empty operation. Assert that explicitly so the test documents it.
        let e1_accepts = true;
        assert!(e1_accepts, "E1 attaches the ciphertext without checking it");

        // ...and de-anonymization then resolves to nobody.
        let mut reg = Registry::new();
        reg.enrol(b"honest-agent");
        let partials: Vec<_> = key.shares.iter().map(|s| partial_decrypt(s, &bad_ct)).collect();
        let recovered = combine_decryptions(&partials, &bad_ct, 2).unwrap();
        assert_eq!(
            reg.resolve(&recovered),
            None,
            "E1: escrow opens to an unregistered point — accountability is gone"
        );

        // --- E2: no proof exists for this ciphertext. ---
        // Proving with the true id fails because the ciphertext does not match;
        // proving with the garbage id fails because the commitment does not.
        let honest_attempt = prove_correct_encryption_unchecked(
            &ped,
            key.public,
            &bad_ct,
            &commitment,
            real_id,
            bad_r,
            opening.blinding,
            b"ctx",
            &mut rng,
        );
        if let Ok(p) = honest_attempt {
            assert!(
                verify_correct_encryption(&ped, key.public, &bad_ct, &commitment, &p, b"ctx")
                    .is_err(),
                "E2 must reject a ciphertext that does not encrypt the committed identity"
            );
        }

        let garbage_attempt = prove_correct_encryption_unchecked(
            &ped,
            key.public,
            &bad_ct,
            &commitment,
            garbage,
            bad_r,
            opening.blinding,
            b"ctx",
            &mut rng,
        );
        if let Ok(p) = garbage_attempt {
            assert!(
                verify_correct_encryption(&ped, key.public, &bad_ct, &commitment, &p, b"ctx")
                    .is_err(),
                "E2 must reject when the commitment does not open to the encrypted identity"
            );
        }
    }

    #[test]
    fn ciphertext_round_trip() {
        let mut rng = rng_from_seed(6);
        let key = EscrowKey::generate(2, 3, &mut rng).unwrap();
        let (ct, _) = encrypt(key.public, identity_point(identity_scalar(b"x")), &mut rng);
        assert_eq!(Ciphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        assert_eq!(ct.to_bytes().len(), Ciphertext::SIZE);
    }
}
