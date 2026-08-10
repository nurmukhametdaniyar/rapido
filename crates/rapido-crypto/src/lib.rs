#![forbid(unsafe_code)]
//! `rapido-crypto` — the algebraic core of RAPIDO on BLS12-381.
//!
//! Conventions, fixed once here and used everywhere:
//! * Signatures live in **G2**, public keys in **G1** (minimal-pubkey-size).
//! * Hash-to-curve is `BLS12381G2_XMD:SHA-256_SSWU_RO_` (RFC 9380) with a
//!   per-context DST from [`rapido_core::dst`].
//! * Points are serialized **compressed** and validated on parse: on-curve,
//!   prime-order subgroup, canonical field encoding, non-identity.
//!
//! ## Constant-time posture
//! Scalar arithmetic and scalar multiplication use arkworks' implementations.
//! arkworks does **not** advertise constant-time scalar multiplication, and
//! this crate does not attempt to add it. No claim of side-channel resistance
//! is made anywhere in this workspace; see the crate README and the top-level
//! `LIMITATIONS.md`. What this crate does guarantee is that no modular
//! arithmetic on secrets is hand-rolled — every operation goes through
//! `ark-ff`/`ark-ec` or, on the `blst-backend` feature path, through `blst`.

pub mod bbs;
pub mod bls;
pub mod elgamal;
pub mod hash;
pub mod kdf;
pub mod pedersen;
pub mod relation;
pub mod ser;
pub mod shamir;

#[cfg(feature = "blst-backend")]
pub mod blst_backend;

pub use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
pub use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero};

/// The RNG used everywhere a seeded, reproducible source is needed.
/// Every experiment is a pure function of its seed: no result in this
/// workspace depends on entropy that is not recorded alongside it.
pub type Rng = rand_chacha::ChaCha20Rng;

/// Construct the workspace RNG from a 64-bit experiment seed.
pub fn rng_from_seed(seed: u64) -> Rng {
    use rand::SeedableRng;
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    Rng::from_seed(bytes)
}
