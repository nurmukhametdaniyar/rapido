//! Idemix-like baseline: CL signatures over RSA-2048 with a Schnorr-style
//! proof of knowledge.
//!
//! RAPIDO's speedup is claimed relative to RSA-based anonymous credentials, so
//! that cost has to be a measurement rather than a citation. This module
//! provides it: a CL-RSA presentation and verification at standard Idemix
//! parameters, measured on the same machine and in the same process as RAPIDO's
//! own numbers, so the ratio between them means something.
//!
//! ## Scheme (Camenisch-Lysyanskaya, strong-RSA)
//!
//! ```text
//! public : n, S, Z, R_1..R_L  in QR_n
//! secret : the factorization of n
//! sign   : pick prime e, random v; A = (Z / (S^v · Π R_i^{m_i}))^{1/e} mod n
//! verify : Z == A^e · S^v · Π R_i^{m_i}  mod n
//! ```
//!
//! ## Presentation (what a verifier actually pays for)
//!
//! The signature is randomized as `A' = A·S^{-r}`, `v' = v + e·r`, so `A'` is
//! fresh each session and the credential is unlinkable. (The textbook form uses
//! `A·S^{r}` and `v' = v - e·r`; the sign is flipped here so every value stays
//! a non-negative integer — see [`present`].) The prover then shows knowledge
//! of `(e, v', {m_i}_{i∉D})` in
//!
//! ```text
//! Z / Π_{i∈D} R_i^{m_i}  ==  A'^e · S^{v'} · Π_{i∉D} R_i^{m_i}   (mod n)
//! ```
//!
//! Verification recomputes the Fiat-Shamir commitment
//!
//! ```text
//! Z_hat = (Z / Π_{i∈D} R_i^{m_i})^{-c} · A'^{ê} · S^{v̂} · Π_{i∉D} R_i^{m̂_i}
//! ```
//!
//! which is `3 + L` modular exponentiations mod a 2048-bit modulus — one for
//! the statement inverse, one for `A'` (a ~853-bit exponent), one for `S`
//! (~3060 bits), one per hidden attribute (~592 bits), and one per disclosed
//! attribute inside the statement (256 bits). That is where the time goes, and
//! it is why cost grows with the number of *hidden* attributes, just as it does
//! for BBS+. See [`verify_modexp_count`].
//!
//! ## Parameters
//!
//! Idemix v2.3.0 specification defaults, which are what published Idemix
//! benchmarks use:
//!
//! | symbol | bits | meaning |
//! |---|---|---|
//! | `ℓ_n` | 2048 | modulus |
//! | `ℓ_m` | 256 | message |
//! | `ℓ_e` | 597 | signature exponent |
//! | `ℓ_e'` | 120 | exponent interval width |
//! | `ℓ_v` | 2724 | signature randomness |
//! | `ℓ_∅` | 80 | statistical hiding |
//! | `ℓ_H` | 256 | challenge |
//!
//! ## DEVIATION — modulus generation
//!
//! A deployable CL instance needs a *special* RSA modulus (`p = 2p'+1`,
//! `q = 2q'+1` with `p', q'` prime), because the security reduction needs the
//! quadratic-residue subgroup to have no small factors. Generating safe primes
//! at 1024 bits takes minutes to hours, which would make the benchmark
//! unrunnable in CI. [`SecretKey::generate`] therefore produces an ordinary
//! 2048-bit RSA modulus by default.
//!
//! **This does not affect any measured number**: verification cost is
//! `(2 + |hidden|)` modexps whose cost depends only on the bit lengths, which
//! are identical either way. It does mean the instance is not cryptographically
//! deployable, and it is recorded in `LIMITATIONS.md`.
//! [`SecretKey::generate_safe_prime`] produces a real special RSA modulus for
//! anyone who wants to confirm the timings are unchanged.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rapido_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const L_N: u64 = 2048;
pub const L_M: u64 = 256;
pub const L_E: u64 = 597;
pub const L_E_PRIME: u64 = 120;
pub const L_V: u64 = 2724;
pub const L_PHI: u64 = 80;
pub const L_H: u64 = 256;

/// Response bit-lengths, which set the exponent sizes in verification.
pub const RESP_E_BITS: u64 = L_E_PRIME + L_PHI + L_H;
pub const RESP_M_BITS: u64 = L_M + L_PHI + L_H;
pub const RESP_V_BITS: u64 = L_V + L_PHI + L_H;

/// Public parameters.
#[derive(Debug, Clone)]
pub struct PublicKey {
    pub n: BigUint,
    pub s: BigUint,
    pub z: BigUint,
    pub r: Vec<BigUint>,
    /// `true` when the modulus is a genuine special RSA modulus.
    pub special_rsa: bool,
}

impl PublicKey {
    pub fn l(&self) -> usize {
        self.r.len()
    }

    /// Bytes a verifier must hold: modulus, `S`, `Z`, and one `R_i` per
    /// attribute, each `ℓ_n` bits.
    pub fn size_bytes(&self) -> usize {
        (3 + self.r.len()) * (L_N as usize / 8)
    }
}

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub public: PublicKey,
    p: BigUint,
    q: BigUint,
}

/// A CL signature `(A, e, v)`.
#[derive(Debug, Clone)]
pub struct Signature {
    pub a: BigUint,
    pub e: BigUint,
    pub v: BigUint,
}

impl Signature {
    /// `A` is `ℓ_n` bits, `e` is `ℓ_e`, `v` is `ℓ_v`.
    pub fn size_bytes(&self) -> usize {
        (L_N + L_E + L_V) as usize / 8
    }
}

/// A presentation proof with selective disclosure.
#[derive(Debug, Clone)]
pub struct Presentation {
    pub a_prime: BigUint,
    pub challenge: BigUint,
    pub e_hat: BigUint,
    pub v_hat: BigUint,
    /// Responses for hidden attributes, by index.
    pub m_hat: BTreeMap<usize, BigUint>,
    /// Values of the disclosed attributes, by index.
    pub disclosed: BTreeMap<usize, BigUint>,
}

impl Presentation {
    /// Wire size: `A'` plus the challenge and one response per hidden
    /// attribute, plus the disclosed values.
    pub fn size_bytes(&self) -> usize {
        let bits = L_N
            + L_H
            + RESP_E_BITS
            + RESP_V_BITS
            + self.m_hat.len() as u64 * RESP_M_BITS
            + self.disclosed.len() as u64 * L_M;
        bits.div_ceil(8) as usize
    }
}

// --- prime generation ------------------------------------------------------

fn is_probable_prime<R: rand::Rng + ?Sized>(n: &BigUint, rounds: u32, rng: &mut R) -> bool {
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    // Trial division by small primes removes ~80% of candidates cheaply.
    const SMALL: [u32; 25] = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97,
    ];
    for p in SMALL {
        let bp = BigUint::from(p);
        if *n == bp {
            return true;
        }
        if (n % &bp).is_zero() {
            return false;
        }
    }
    // Miller-Rabin.
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }
    'outer: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_1);
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

fn random_prime<R: rand::Rng + ?Sized>(bits: u64, rng: &mut R) -> BigUint {
    loop {
        let mut c = rng.gen_biguint(bits);
        // Set the top two bits so that a product of two such primes has
        // exactly `2 * bits` bits, and the low bit so the candidate is odd.
        c.set_bit(bits - 1, true);
        c.set_bit(bits - 2, true);
        c.set_bit(0, true);
        if is_probable_prime(&c, 40, rng) {
            return c;
        }
    }
}

/// A prime `p = 2p' + 1` with `p'` also prime.
fn random_safe_prime<R: rand::Rng + ?Sized>(bits: u64, rng: &mut R) -> BigUint {
    loop {
        let p_prime = random_prime(bits - 1, rng);
        let p = (&p_prime << 1u32) + BigUint::one();
        if is_probable_prime(&p, 40, rng) {
            return p;
        }
    }
}

/// A prime in `[2^(L_E-1), 2^(L_E-1) + 2^(L_E_PRIME-1))`, as CL requires.
fn random_signature_exponent<R: rand::Rng + ?Sized>(rng: &mut R) -> BigUint {
    let base = BigUint::one() << (L_E - 1);
    let width = BigUint::one() << (L_E_PRIME - 1);
    loop {
        let mut e = &base + rng.gen_biguint_below(&width);
        if e.is_even() {
            e += BigUint::one();
        }
        if is_probable_prime(&e, 40, rng) {
            return e;
        }
    }
}

/// A random element of `QR_n`, obtained by squaring.
fn random_qr<R: rand::Rng + ?Sized>(n: &BigUint, rng: &mut R) -> BigUint {
    loop {
        let x = rng.gen_biguint_below(n);
        if x.is_zero() || !x.gcd(n).is_one() {
            continue;
        }
        return x.modpow(&BigUint::from(2u32), n);
    }
}

impl SecretKey {
    /// Generate an issuer key over `l` attributes with an ordinary RSA modulus.
    /// See the module-level DEVIATION note.
    pub fn generate<R: rand::Rng + ?Sized>(l: usize, rng: &mut R) -> Self {
        Self::build(l, rng, false)
    }

    /// Generate with a genuine special RSA modulus. **Slow** — minutes to
    /// hours. Provided so the deviation above can be checked, not for routine
    /// benchmarking.
    pub fn generate_safe_prime<R: rand::Rng + ?Sized>(l: usize, rng: &mut R) -> Self {
        Self::build(l, rng, true)
    }

    fn build<R: rand::Rng + ?Sized>(l: usize, rng: &mut R, safe: bool) -> Self {
        let half = L_N / 2;
        let (p, q) = if safe {
            (random_safe_prime(half, rng), random_safe_prime(half, rng))
        } else {
            (random_prime(half, rng), random_prime(half, rng))
        };
        let n = &p * &q;
        let s = random_qr(&n, rng);
        // Derive Z and the R_i as powers of S so the issuer knows their
        // discrete logs, which is what makes signing possible.
        let z = s.modpow(&rng.gen_biguint_below(&n), &n);
        let r = (0..l).map(|_| s.modpow(&rng.gen_biguint_below(&n), &n)).collect();
        SecretKey { public: PublicKey { n, s, z, r, special_rsa: safe }, p, q }
    }

    fn phi(&self) -> BigUint {
        (&self.p - BigUint::one()) * (&self.q - BigUint::one())
    }

    /// Sign `msgs`, one per attribute slot.
    pub fn sign<R: rand::Rng + ?Sized>(&self, msgs: &[BigUint], rng: &mut R) -> Result<Signature> {
        let pk = &self.public;
        if msgs.len() != pk.l() {
            return Err(Error::InvalidParameter("cl-rsa: message count mismatch".into()));
        }
        let e = random_signature_exponent(rng);
        let v = rng.gen_biguint(L_V);

        // A = (Z / (S^v · Π R_i^m_i))^(1/e) mod n
        let mut denom = pk.s.modpow(&v, &pk.n);
        for (ri, mi) in pk.r.iter().zip(msgs) {
            denom = (denom * ri.modpow(mi, &pk.n)) % &pk.n;
        }
        let base = (&pk.z
            * denom.modinv(&pk.n).ok_or_else(|| {
                Error::InvalidParameter("cl-rsa: non-invertible denominator".into())
            })?)
            % &pk.n;
        let d = e
            .modinv(&self.phi())
            .ok_or_else(|| Error::InvalidParameter("cl-rsa: e not invertible mod phi(n)".into()))?;
        Ok(Signature { a: base.modpow(&d, &pk.n), e, v })
    }
}

/// Verify a signature directly (not a presentation). Used to check issuance.
pub fn verify_signature(pk: &PublicKey, msgs: &[BigUint], sig: &Signature) -> Result<()> {
    if msgs.len() != pk.l() {
        return Err(Error::InvalidParameter("cl-rsa: message count mismatch".into()));
    }
    let mut acc = sig.a.modpow(&sig.e, &pk.n);
    acc = (acc * pk.s.modpow(&sig.v, &pk.n)) % &pk.n;
    for (ri, mi) in pk.r.iter().zip(msgs) {
        acc = (acc * ri.modpow(mi, &pk.n)) % &pk.n;
    }
    if acc == pk.z {
        Ok(())
    } else {
        Err(Error::BadSignature("cl-rsa signature"))
    }
}

/// Map attribute bytes to an `ℓ_m`-bit message.
pub fn message_from_bytes(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&Sha256::digest(b))
}

fn challenge(
    pk: &PublicKey,
    a_prime: &BigUint,
    z_tilde: &BigUint,
    nonce: &[u8],
    disclosed: &BTreeMap<usize, BigUint>,
) -> BigUint {
    let mut h = Sha256::new();
    h.update(b"RAPIDO-baseline-clrsa-fs");
    h.update(pk.n.to_bytes_be());
    h.update(a_prime.to_bytes_be());
    h.update(z_tilde.to_bytes_be());
    h.update((disclosed.len() as u64).to_be_bytes());
    for (i, m) in disclosed {
        h.update((*i as u64).to_be_bytes());
        h.update(m.to_bytes_be());
    }
    h.update((nonce.len() as u64).to_be_bytes());
    h.update(nonce);
    BigUint::from_bytes_be(&h.finalize())
}

/// The value `Z / Π_{i∈D} R_i^{m_i}` both sides compute.
fn statement(pk: &PublicKey, disclosed: &BTreeMap<usize, BigUint>) -> Result<BigUint> {
    let mut d = BigUint::one();
    for (i, m) in disclosed {
        let ri =
            pk.r.get(*i)
                .ok_or_else(|| Error::BadDisclosure(format!("attribute {i} out of range")))?;
        d = (d * ri.modpow(m, &pk.n)) % &pk.n;
    }
    let inv = d
        .modinv(&pk.n)
        .ok_or_else(|| Error::InvalidParameter("cl-rsa: non-invertible statement".into()))?;
    Ok((&pk.z * inv) % &pk.n)
}

/// Produce a presentation disclosing exactly `disclose`.
pub fn present<R: rand::Rng + ?Sized>(
    pk: &PublicKey,
    msgs: &[BigUint],
    sig: &Signature,
    disclose: &[usize],
    nonce: &[u8],
    rng: &mut R,
) -> Result<Presentation> {
    if msgs.len() != pk.l() {
        return Err(Error::InvalidParameter("cl-rsa: message count mismatch".into()));
    }
    let disclosed: BTreeMap<usize, BigUint> = disclose
        .iter()
        .map(|i| {
            msgs.get(*i)
                .cloned()
                .map(|m| (*i, m))
                .ok_or_else(|| Error::BadDisclosure(format!("attribute {i} out of range")))
        })
        .collect::<Result<_>>()?;
    let hidden: Vec<usize> = (0..pk.l()).filter(|i| !disclosed.contains_key(i)).collect();

    // Randomize the signature. The textbook form is `A' = A·S^{r}`, which
    // gives `v' = v - e·r` — a value that is negative about half the time and
    // would force signed big-integer arithmetic through the whole proof.
    // Using `A' = A·S^{-r}` instead gives `v' = v + e·r`, which is always
    // positive and algebraically equivalent: from `Z = A^e·S^v·Π R^m` and
    // `A^e = A'^e·S^{e·r}` we get `Z = A'^e·S^{v + e·r}·Π R^m`.
    let r = rng.gen_biguint(L_N + L_PHI);
    let s_r_inv =
        pk.s.modpow(&r, &pk.n)
            .modinv(&pk.n)
            .ok_or_else(|| Error::InvalidParameter("cl-rsa: S^r not invertible".into()))?;
    let a_prime = (&sig.a * s_r_inv) % &pk.n;
    let e_shift = BigUint::one() << (L_E - 1);
    let e_prime = &sig.e - &e_shift;
    let v_prime = &sig.v + &sig.e * &r;

    // Blinding factors, one bit longer than the witness plus ℓ_∅ + ℓ_H.
    let e_tilde = rng.gen_biguint(RESP_E_BITS);
    let v_tilde = rng.gen_biguint(RESP_V_BITS);
    let m_tilde: BTreeMap<usize, BigUint> =
        hidden.iter().map(|i| (*i, rng.gen_biguint(RESP_M_BITS))).collect();

    // Z_tilde = A'^{ẽ} · S^{ṽ} · Π_{hidden} R_i^{m̃_i}
    let mut z_tilde = a_prime.modpow(&e_tilde, &pk.n);
    z_tilde = (z_tilde * pk.s.modpow(&v_tilde, &pk.n)) % &pk.n;
    for i in &hidden {
        z_tilde = (z_tilde * pk.r[*i].modpow(&m_tilde[i], &pk.n)) % &pk.n;
    }

    let c = challenge(pk, &a_prime, &z_tilde, nonce, &disclosed);

    Ok(Presentation {
        a_prime,
        e_hat: e_tilde + &c * e_prime,
        v_hat: v_tilde + &c * v_prime,
        m_hat: hidden.iter().map(|i| (*i, &m_tilde[i] + &c * &msgs[*i])).collect(),
        challenge: c,
        disclosed,
    })
}

/// Verify a presentation.
///
/// Recomputes
/// `Ẑ = statement^{-c} · A'^{ê + c·2^{ℓ_e-1}} · S^{v̂} · Π_{hidden} R_i^{m̂}`
/// and checks that the challenge reproduces. The `c·2^{ℓ_e-1}` term in the
/// exponent restores the `e = e' + 2^{ℓ_e-1}` shift that keeps the proved
/// exponent inside its required interval.
pub fn verify_presentation(pk: &PublicKey, pres: &Presentation, nonce: &[u8]) -> Result<()> {
    if pres.a_prime.is_zero() || pres.a_prime >= pk.n {
        return Err(Error::NonCanonical("cl-rsa: A' out of range".into()));
    }
    // Response range checks. Without these the proof is not sound: an
    // out-of-range ê would let a prover cheat on the exponent interval.
    if pres.e_hat.bits() > RESP_E_BITS + 1 || pres.v_hat.bits() > RESP_V_BITS + 2 {
        return Err(Error::BadProof("cl-rsa: response out of range"));
    }
    for m in pres.m_hat.values() {
        if m.bits() > RESP_M_BITS + 1 {
            return Err(Error::BadProof("cl-rsa: message response out of range"));
        }
    }

    let stmt = statement(pk, &pres.disclosed)?;
    let inv_stmt = stmt
        .modinv(&pk.n)
        .ok_or_else(|| Error::InvalidParameter("cl-rsa: non-invertible statement".into()))?;

    // Ẑ = statement^{-c} · A'^{ê + c·2^{ℓ_e-1}} · S^{v̂} · Π_{hidden} R_i^{m̂_i}
    let e_exp = &pres.e_hat + &pres.challenge * (BigUint::one() << (L_E - 1));
    let mut z_hat = inv_stmt.modpow(&pres.challenge, &pk.n);
    z_hat = (z_hat * pres.a_prime.modpow(&e_exp, &pk.n)) % &pk.n;
    z_hat = (z_hat * pk.s.modpow(&pres.v_hat, &pk.n)) % &pk.n;
    for (i, m) in &pres.m_hat {
        let ri =
            pk.r.get(*i)
                .ok_or_else(|| Error::BadDisclosure(format!("attribute {i} out of range")))?;
        z_hat = (z_hat * ri.modpow(m, &pk.n)) % &pk.n;
    }

    if challenge(pk, &pres.a_prime, &z_hat, nonce, &pres.disclosed) == pres.challenge {
        Ok(())
    } else {
        Err(Error::BadProof("cl-rsa presentation"))
    }
}

/// Number of modular exponentiations a verification performs: statement
/// inverse, `A'`, `S`, plus one per hidden attribute, plus one per disclosed
/// attribute in `statement`. Reported alongside the timing so the measured
/// cost can be checked against the algebraic cost model.
pub fn verify_modexp_count(l: usize, n_disclosed: usize) -> usize {
    let hidden = l - n_disclosed;
    3 + hidden + n_disclosed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng(seed: u64) -> rand_chacha::ChaCha20Rng {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        rand_chacha::ChaCha20Rng::from_seed(b)
    }

    fn msgs(l: usize) -> Vec<BigUint> {
        (0..l).map(|i| message_from_bytes(format!("attr-{i}").as_bytes())).collect()
    }

    #[test]
    fn prime_generation_produces_primes() {
        let mut r = rng(1);
        for bits in [64u64, 128, 256] {
            let p = random_prime(bits, &mut r);
            assert_eq!(p.bits(), bits);
            assert!(is_probable_prime(&p, 64, &mut r));
        }
    }

    #[test]
    fn safe_prime_generation_is_correct() {
        // Small size only: 1024-bit safe primes are far too slow for a test.
        let mut r = rng(2);
        let p = random_safe_prime(64, &mut r);
        assert!(is_probable_prime(&p, 64, &mut r));
        let p_prime = (&p - BigUint::one()) >> 1u32;
        assert!(is_probable_prime(&p_prime, 64, &mut r), "p = 2p'+1 with p' prime");
    }

    #[test]
    fn signature_exponent_is_a_prime_in_the_required_interval() {
        let mut r = rng(3);
        let e = random_signature_exponent(&mut r);
        assert!(is_probable_prime(&e, 64, &mut r));
        let lo = BigUint::one() << (L_E - 1);
        let hi = &lo + (BigUint::one() << (L_E_PRIME - 1));
        assert!(e >= lo && e < hi);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let mut r = rng(4);
        let sk = SecretKey::generate(4, &mut r);
        let m = msgs(4);
        let sig = sk.sign(&m, &mut r).unwrap();
        assert!(verify_signature(&sk.public, &m, &sig).is_ok());
    }

    #[test]
    fn a_signature_does_not_verify_on_altered_messages() {
        let mut r = rng(5);
        let sk = SecretKey::generate(4, &mut r);
        let mut m = msgs(4);
        let sig = sk.sign(&m, &mut r).unwrap();
        m[1] = message_from_bytes(b"different");
        assert!(verify_signature(&sk.public, &m, &sig).is_err());
    }

    #[test]
    fn presentation_round_trip_at_every_disclosure_fraction() {
        let mut r = rng(6);
        let l = 5;
        let sk = SecretKey::generate(l, &mut r);
        let m = msgs(l);
        let sig = sk.sign(&m, &mut r).unwrap();

        for n_disclosed in 0..=l {
            let d: Vec<usize> = (0..n_disclosed).collect();
            let p = present(&sk.public, &m, &sig, &d, b"nonce", &mut r).unwrap();
            assert!(
                verify_presentation(&sk.public, &p, b"nonce").is_ok(),
                "failed with {n_disclosed} disclosed"
            );
            assert_eq!(p.disclosed.len(), n_disclosed);
            assert_eq!(p.m_hat.len(), l - n_disclosed);
        }
    }

    #[test]
    fn presentation_is_bound_to_the_nonce() {
        let mut r = rng(7);
        let sk = SecretKey::generate(3, &mut r);
        let m = msgs(3);
        let sig = sk.sign(&m, &mut r).unwrap();
        let p = present(&sk.public, &m, &sig, &[0], b"nonce-a", &mut r).unwrap();
        assert!(verify_presentation(&sk.public, &p, b"nonce-a").is_ok());
        assert!(verify_presentation(&sk.public, &p, b"nonce-b").is_err());
    }

    #[test]
    fn claiming_a_false_disclosed_value_is_rejected() {
        let mut r = rng(8);
        let sk = SecretKey::generate(3, &mut r);
        let m = msgs(3);
        let sig = sk.sign(&m, &mut r).unwrap();
        let mut p = present(&sk.public, &m, &sig, &[1], b"n", &mut r).unwrap();
        p.disclosed.insert(1, message_from_bytes(b"a lie"));
        assert!(verify_presentation(&sk.public, &p, b"n").is_err());
    }

    #[test]
    fn tampered_responses_are_rejected() {
        let mut r = rng(9);
        let sk = SecretKey::generate(3, &mut r);
        let m = msgs(3);
        let sig = sk.sign(&m, &mut r).unwrap();
        let base = present(&sk.public, &m, &sig, &[], b"n", &mut r).unwrap();

        let mut p = base.clone();
        p.e_hat += BigUint::one();
        assert!(verify_presentation(&sk.public, &p, b"n").is_err());

        let mut p = base.clone();
        p.v_hat += BigUint::one();
        assert!(verify_presentation(&sk.public, &p, b"n").is_err());

        let mut p = base.clone();
        *p.m_hat.get_mut(&0).unwrap() += BigUint::one();
        assert!(verify_presentation(&sk.public, &p, b"n").is_err());

        let mut p = base;
        p.a_prime = (p.a_prime * BigUint::from(3u32)) % &sk.public.n;
        assert!(verify_presentation(&sk.public, &p, b"n").is_err());
    }

    #[test]
    fn out_of_range_responses_are_rejected() {
        let mut r = rng(10);
        let sk = SecretKey::generate(3, &mut r);
        let m = msgs(3);
        let sig = sk.sign(&m, &mut r).unwrap();
        let mut p = present(&sk.public, &m, &sig, &[], b"n", &mut r).unwrap();
        p.e_hat = BigUint::one() << (RESP_E_BITS + 8);
        assert!(matches!(verify_presentation(&sk.public, &p, b"n"), Err(Error::BadProof(_))));
    }

    #[test]
    fn presentations_are_unlinkable_at_the_bytes() {
        let mut r = rng(11);
        let sk = SecretKey::generate(3, &mut r);
        let m = msgs(3);
        let sig = sk.sign(&m, &mut r).unwrap();
        let p1 = present(&sk.public, &m, &sig, &[], b"n1", &mut r).unwrap();
        let p2 = present(&sk.public, &m, &sig, &[], b"n2", &mut r).unwrap();
        assert_ne!(p1.a_prime, p2.a_prime, "A' must be freshly randomized");
        assert_ne!(p1.a_prime, sig.a, "the raw signature must never appear on the wire");
    }

    #[test]
    fn modulus_is_the_declared_size_and_flagged_as_non_special() {
        let mut r = rng(12);
        let sk = SecretKey::generate(2, &mut r);
        assert_eq!(sk.public.n.bits(), L_N);
        assert!(!sk.public.special_rsa, "default generation is documented as non-special");
    }

    #[test]
    fn modexp_count_matches_the_cost_model() {
        assert_eq!(verify_modexp_count(8, 0), 11);
        assert_eq!(verify_modexp_count(8, 8), 11);
    }
}
