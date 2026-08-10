//! Pedersen commitments over G1.
//!
//! `Com(m; r) = m·G + r·H`, with `H` derived by hash-to-curve so that
//! `log_G(H)` is unknown to everyone — the binding property depends on it.

use crate::{hash, relation, ser};
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use rapido_core::{dst, Result};

/// The two commitment bases. `g` is the standard generator; `h` is a
/// nothing-up-my-sleeve point with no known discrete log relative to `g`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub g: G1Projective,
    pub h: G1Projective,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            g: G1Projective::generator(),
            h: hash::hash_to_g1(dst::ESCROW, b"RAPIDO-v1-pedersen-blinding-base"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(pub G1Projective);

impl Commitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        ser::g1_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(Commitment(ser::g1_from_bytes(b, "pedersen commitment")?))
    }
}

/// An opening: the committed value and its blinding factor.
#[derive(Debug, Clone, Copy)]
pub struct Opening {
    pub value: Fr,
    pub blinding: Fr,
}

impl Params {
    pub fn commit(&self, value: Fr, blinding: Fr) -> Commitment {
        Commitment(self.g * value + self.h * blinding)
    }

    pub fn commit_random<R: rand::Rng + ?Sized>(
        &self,
        value: Fr,
        rng: &mut R,
    ) -> (Commitment, Opening) {
        let blinding = Fr::rand(rng);
        (self.commit(value, blinding), Opening { value, blinding })
    }

    pub fn verify_opening(&self, c: &Commitment, o: &Opening) -> bool {
        self.commit(o.value, o.blinding) == *c
    }

    /// The equation `C = value·G + blinding·H` over witness indices
    /// `(value_idx, blinding_idx)`, for composition into a larger relation.
    pub fn equation(
        &self,
        c: &Commitment,
        value_idx: usize,
        blinding_idx: usize,
    ) -> relation::Equation {
        relation::Equation::new(c.0, vec![(value_idx, self.g), (blinding_idx, self.h)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng_from_seed;

    #[test]
    fn commit_and_open() {
        let mut rng = rng_from_seed(1);
        let p = Params::default();
        let v = Fr::rand(&mut rng);
        let (c, o) = p.commit_random(v, &mut rng);
        assert!(p.verify_opening(&c, &o));
        assert!(!p.verify_opening(&c, &Opening { value: v + Fr::from(1u64), blinding: o.blinding }));
    }

    #[test]
    fn hiding_across_blindings() {
        let mut rng = rng_from_seed(2);
        let p = Params::default();
        let v = Fr::rand(&mut rng);
        let (c1, _) = p.commit_random(v, &mut rng);
        let (c2, _) = p.commit_random(v, &mut rng);
        assert_ne!(c1, c2, "same value under fresh blindings must not be equal");
    }

    #[test]
    fn bases_are_distinct() {
        let p = Params::default();
        assert_ne!(p.g, p.h);
    }

    #[test]
    fn commitment_round_trip() {
        let mut rng = rng_from_seed(3);
        let p = Params::default();
        let (c, _) = p.commit_random(Fr::rand(&mut rng), &mut rng);
        assert_eq!(Commitment::from_bytes(&c.to_bytes()).unwrap(), c);
    }
}
