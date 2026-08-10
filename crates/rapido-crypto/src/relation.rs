//! Generic Schnorr proof of knowledge for a system of linear relations over G1.
//!
//! A relation is a set of equations
//!
//! ```text
//! L_k = Σ_j  w_{j}  ·  B_{k,j}
//! ```
//!
//! where the `L_k` and bases `B_{k,j}` are public and the scalars `w_j` are the
//! witness. Proving all equations against a *single* Fiat-Shamir challenge is
//! what makes a witness shared between two equations provably the same value —
//! that is the mechanism behind:
//!
//! * the BBS+ presentation proof (Mode B), and
//! * binding an escrow ciphertext to the identity inside a credential
//!   (escrow variant E2) — the escrow equations and the credential equation
//!   name the same witness index, so a proof only verifies if the encrypted
//!   identity is the credentialed one.
//!
//! This subsumes plain Schnorr (one equation, one term) and Chaum-Pedersen
//! discrete-log equality (two equations sharing one witness).

use crate::ser;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use rapido_core::{Dst, Error, Result, Transcript};

/// One equation `lhs = Σ (witness[idx] · base)`.
#[derive(Debug, Clone)]
pub struct Equation {
    pub lhs: G1Projective,
    /// `(witness index, base)` pairs.
    pub terms: Vec<(usize, G1Projective)>,
}

impl Equation {
    pub fn new(lhs: G1Projective, terms: Vec<(usize, G1Projective)>) -> Self {
        Equation { lhs, terms }
    }
}

/// A system of equations over a shared witness vector.
#[derive(Debug, Clone)]
pub struct Relation {
    pub n_witnesses: usize,
    pub equations: Vec<Equation>,
}

/// Non-interactive proof: one challenge, one response per witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearProof {
    pub challenge: Fr,
    pub responses: Vec<Fr>,
}

impl LinearProof {
    /// Wire size in bytes: `32 * (1 + n_witnesses)`.
    pub fn size_bytes(&self) -> usize {
        ser::FR_LEN * (1 + self.responses.len())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = ser::fr_to_bytes(&self.challenge);
        for r in &self.responses {
            out.extend_from_slice(&ser::fr_to_bytes(r));
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() % ser::FR_LEN != 0 || b.is_empty() {
            return Err(Error::Deserialization("linear proof: bad length".into()));
        }
        let mut it = b.chunks_exact(ser::FR_LEN);
        let challenge = ser::fr_from_bytes(it.next().expect("non-empty"), "proof challenge")?;
        let responses =
            it.map(|c| ser::fr_from_bytes(c, "proof response")).collect::<Result<Vec<_>>>()?;
        Ok(LinearProof { challenge, responses })
    }
}

impl Relation {
    pub fn new(n_witnesses: usize) -> Self {
        Relation { n_witnesses, equations: Vec::new() }
    }

    pub fn push(&mut self, eq: Equation) -> &mut Self {
        self.equations.push(eq);
        self
    }

    fn check_wellformed(&self) -> Result<()> {
        if self.equations.is_empty() {
            return Err(Error::InvalidParameter("relation: no equations".into()));
        }
        for eq in &self.equations {
            for (idx, _) in &eq.terms {
                if *idx >= self.n_witnesses {
                    return Err(Error::InvalidParameter(format!(
                        "relation: witness index {idx} out of range"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Evaluate `Σ (scalars[idx] · base)` for one equation, as an MSM.
    fn eval(eq: &Equation, scalars: &[Fr]) -> G1Projective {
        let bases: Vec<G1Affine> = eq.terms.iter().map(|(_, b)| b.into_affine()).collect();
        let s: Vec<Fr> = eq.terms.iter().map(|(i, _)| scalars[*i]).collect();
        G1Projective::msm(&bases, &s).expect("bases and scalars have equal length by construction")
    }

    /// Fiat-Shamir challenge. Binds the DST, the full statement (every lhs,
    /// every base, and the witness index each base is attached to), every
    /// commitment `T_k`, and caller-supplied context.
    fn challenge(&self, dst: Dst, commitments: &[G1Projective], aux: &[u8]) -> Fr {
        let mut t = Transcript::new(dst);
        t.push_usize(self.n_witnesses);
        t.push_usize(self.equations.len());
        for eq in &self.equations {
            t.push_bytes(&ser::g1_to_bytes(&eq.lhs));
            t.push_usize(eq.terms.len());
            for (idx, base) in &eq.terms {
                t.push_usize(*idx);
                t.push_bytes(&ser::g1_to_bytes(base));
            }
        }
        for c in commitments {
            t.push_bytes(&ser::g1_to_bytes(c));
        }
        t.push_bytes(aux);
        crate::hash::hash_to_scalar(dst, t.as_bytes())
    }

    /// Prove knowledge of `witnesses` satisfying every equation.
    ///
    /// Debug builds assert the witness actually satisfies the statement, which
    /// catches statement-construction bugs at their source rather than as an
    /// opaque verification failure later.
    pub fn prove<R: rand::Rng + ?Sized>(
        &self,
        dst: Dst,
        witnesses: &[Fr],
        aux: &[u8],
        rng: &mut R,
    ) -> Result<LinearProof> {
        // Guarded so that a malformed relation surfaces as its own error rather
        // than as an out-of-bounds panic inside the assertion.
        debug_assert!(
            self.check_wellformed().is_err()
                || witnesses.len() != self.n_witnesses
                || self.equations.iter().all(|eq| Self::eval(eq, witnesses) == eq.lhs),
            "relation: witness does not satisfy the statement"
        );
        self.prove_unchecked(dst, witnesses, aux, rng)
    }

    /// Run the prover without checking that the witness satisfies the
    /// statement.
    ///
    /// This is what a *dishonest* prover does, and it exists so that soundness
    /// tests and the simulator's adversaries can construct forgery attempts
    /// through the real code path. The resulting proof will not verify; that is
    /// the point.
    pub fn prove_unchecked<R: rand::Rng + ?Sized>(
        &self,
        dst: Dst,
        witnesses: &[Fr],
        aux: &[u8],
        rng: &mut R,
    ) -> Result<LinearProof> {
        self.check_wellformed()?;
        if witnesses.len() != self.n_witnesses {
            return Err(Error::InvalidParameter(format!(
                "relation: expected {} witnesses, got {}",
                self.n_witnesses,
                witnesses.len()
            )));
        }

        let blinds: Vec<Fr> = (0..self.n_witnesses).map(|_| Fr::rand(rng)).collect();
        let commitments: Vec<G1Projective> =
            self.equations.iter().map(|eq| Self::eval(eq, &blinds)).collect();
        let c = self.challenge(dst, &commitments, aux);
        let responses = blinds.iter().zip(witnesses).map(|(b, w)| *b + c * w).collect();
        Ok(LinearProof { challenge: c, responses })
    }

    /// Verify by recomputing `T_k = Σ resp·B - c·L` and re-deriving the
    /// challenge; a proof is accepted only if the challenge reproduces exactly.
    pub fn verify(&self, dst: Dst, proof: &LinearProof, aux: &[u8]) -> Result<()> {
        self.check_wellformed()?;
        if proof.responses.len() != self.n_witnesses {
            return Err(Error::BadProof("linear proof: wrong number of responses"));
        }
        let recomputed: Vec<G1Projective> = self
            .equations
            .iter()
            .map(|eq| Self::eval(eq, &proof.responses) - eq.lhs * proof.challenge)
            .collect();
        if self.challenge(dst, &recomputed, aux) == proof.challenge {
            Ok(())
        } else {
            Err(Error::BadProof("linear proof: challenge mismatch"))
        }
    }
}

/// Convenience: Chaum-Pedersen discrete-log equality, `log_G(A) == log_H(B)`.
pub fn dleq_relation(
    g: G1Projective,
    a: G1Projective,
    h: G1Projective,
    b: G1Projective,
) -> Relation {
    let mut r = Relation::new(1);
    r.push(Equation::new(a, vec![(0, g)]));
    r.push(Equation::new(b, vec![(0, h)]));
    r
}

/// Convenience: plain Schnorr PoK of `x` in `A = x·G`.
pub fn schnorr_relation(g: G1Projective, a: G1Projective) -> Relation {
    let mut r = Relation::new(1);
    r.push(Equation::new(a, vec![(0, g)]));
    r
}

/// Sum of `scalars[i] · bases[i]`, exposed because callers building statements
/// need the same MSM the prover uses.
pub fn msm(bases: &[G1Projective], scalars: &[Fr]) -> G1Projective {
    if bases.is_empty() {
        return G1Projective::zero();
    }
    let affine: Vec<G1Affine> = bases.iter().map(|b| b.into_affine()).collect();
    G1Projective::msm(&affine, scalars).expect("caller passes equal-length slices")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash, rng_from_seed};
    use ark_ec::PrimeGroup;
    use rapido_core::dst;

    fn bases(n: usize) -> Vec<G1Projective> {
        (0..n).map(|i| hash::indexed_generator_g1(dst::BBS_GEN, "test-base", i)).collect()
    }

    #[test]
    fn schnorr_round_trip() {
        let mut rng = rng_from_seed(1);
        let g = G1Projective::generator();
        let x = Fr::rand(&mut rng);
        let rel = schnorr_relation(g, g * x);
        let p = rel.prove(dst::SCHNORR, &[x], b"ctx", &mut rng).unwrap();
        assert!(rel.verify(dst::SCHNORR, &p, b"ctx").is_ok());
    }

    #[test]
    fn proof_is_bound_to_its_context() {
        let mut rng = rng_from_seed(2);
        let g = G1Projective::generator();
        let x = Fr::rand(&mut rng);
        let rel = schnorr_relation(g, g * x);
        let p = rel.prove(dst::SCHNORR, &[x], b"ctx", &mut rng).unwrap();
        assert!(rel.verify(dst::SCHNORR, &p, b"other ctx").is_err());
        // ...and to its domain.
        assert!(rel.verify(dst::ESCROW_CP, &p, b"ctx").is_err());
    }

    #[test]
    fn dleq_round_trip_and_soundness() {
        let mut rng = rng_from_seed(3);
        let g = G1Projective::generator();
        let h = hash::hash_to_g1(dst::ESCROW, b"h");
        let x = Fr::rand(&mut rng);

        let rel = dleq_relation(g, g * x, h, h * x);
        let p = rel.prove(dst::ESCROW_CP, &[x], b"", &mut rng).unwrap();
        assert!(rel.verify(dst::ESCROW_CP, &p, b"").is_ok());

        // Unequal discrete logs: no witness satisfies both equations, so a
        // proof built from either one alone must fail.
        let y = Fr::rand(&mut rng);
        let bad = dleq_relation(g, g * x, h, h * y);
        assert!(bad.verify(dst::ESCROW_CP, &p, b"").is_err());
    }

    #[test]
    fn shared_witness_across_equations_is_enforced() {
        // Two Pedersen-style equations naming witness 0. A prover who used a
        // different value in the second equation cannot produce a valid proof.
        let mut rng = rng_from_seed(4);
        let b = bases(4);
        let (x, r1, r2) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));

        let mut rel = Relation::new(3);
        rel.push(Equation::new(b[0] * x + b[1] * r1, vec![(0, b[0]), (1, b[1])]));
        rel.push(Equation::new(b[2] * x + b[3] * r2, vec![(0, b[2]), (2, b[3])]));
        let p = rel.prove(dst::SCHNORR, &[x, r1, r2], b"", &mut rng).unwrap();
        assert!(rel.verify(dst::SCHNORR, &p, b"").is_ok());

        let x2 = Fr::rand(&mut rng);
        let mut mismatched = Relation::new(3);
        mismatched.push(Equation::new(b[0] * x + b[1] * r1, vec![(0, b[0]), (1, b[1])]));
        mismatched.push(Equation::new(b[2] * x2 + b[3] * r2, vec![(0, b[2]), (2, b[3])]));
        assert!(mismatched.verify(dst::SCHNORR, &p, b"").is_err());
    }

    #[test]
    fn tampered_response_is_rejected() {
        let mut rng = rng_from_seed(5);
        let g = G1Projective::generator();
        let x = Fr::rand(&mut rng);
        let rel = schnorr_relation(g, g * x);
        let mut p = rel.prove(dst::SCHNORR, &[x], b"", &mut rng).unwrap();
        p.responses[0] += Fr::from(1u64);
        assert!(rel.verify(dst::SCHNORR, &p, b"").is_err());
    }

    #[test]
    fn proof_serialization_round_trip() {
        let mut rng = rng_from_seed(6);
        let g = G1Projective::generator();
        let x = Fr::rand(&mut rng);
        let rel = schnorr_relation(g, g * x);
        let p = rel.prove(dst::SCHNORR, &[x], b"", &mut rng).unwrap();
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), p.size_bytes());
        assert_eq!(LinearProof::from_bytes(&bytes).unwrap(), p);
    }

    #[test]
    fn malformed_relation_is_rejected() {
        let mut rng = rng_from_seed(7);
        let g = G1Projective::generator();
        let mut rel = Relation::new(1);
        rel.push(Equation::new(g, vec![(5, g)]));
        assert!(rel.prove(dst::SCHNORR, &[Fr::from(1u64)], b"", &mut rng).is_err());
    }
}
