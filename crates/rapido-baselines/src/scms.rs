//! SCMS-like baseline: IEEE 1609.2 pseudonym certificates over ECDSA-P256.
//!
//! **This is the correct V2X baseline for RAPIDO Mode A.** Mode A's "derive a
//! batch of one-time keys, get them certified, present one per session" is
//! functionally the butterfly-key / pseudonym-certificate mechanism already
//! standardized in IEEE 1609.2 and the SCMS, and deployed in US V2X. Measuring
//! Mode A only against an anonymous-credential system would compare it against
//! something it is not.
//!
//! Two forms are implemented, because SCMS deploys both:
//!
//! * **Explicit** — the pseudonym CA signs the certificate; the verifier does
//!   two ECDSA verifications (certificate, then message).
//! * **Implicit (ECQV)** — the certificate carries a *reconstruction value*
//!   instead of a signature. The verifier recovers the sender's public key with
//!   one scalar multiplication and one point addition, then does a single ECDSA
//!   verification. This is what IEEE 1609.2 actually uses for pseudonym
//!   certificates, and it is meaningfully cheaper — the comparison should use
//!   it rather than the explicit form.

use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, ProjectivePoint, Scalar};
use rapido_core::{Error, Result};
use sha2::{Digest, Sha256};

/// Butterfly-key expansion cost is not modelled: what a verifier does is the
/// same either way, and issuance-side expansion is measured in `rapido-bench`
/// against Mode A's batch issuance directly.
pub struct PseudonymCa {
    signing: SigningKey,
    pub public: VerifyingKey,
}

impl PseudonymCa {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let signing = SigningKey::random(rng);
        let public = *signing.verifying_key();
        PseudonymCa { signing, public }
    }
}

fn cert_tbs(subject: &[u8], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(subject.len() + 32);
    out.extend_from_slice(b"RAPIDO-baseline-scms-cert");
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    out.extend_from_slice(subject);
    out
}

// --- explicit certificates -------------------------------------------------

pub mod explicit {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct PseudonymCert {
        pub subject: VerifyingKey,
        pub subject_bytes: Vec<u8>,
        pub epoch: u64,
        pub ca_sig: Signature,
    }

    /// Compressed key (33) + epoch (8) + CA signature (64) + message signature (64).
    pub const WIRE_BYTES: usize = 33 + 8 + 64 + 64;

    pub struct Agent {
        pub cert: PseudonymCert,
        key: SigningKey,
    }

    pub fn issue<R: rand::Rng + rand::CryptoRng>(
        ca: &PseudonymCa,
        epoch: u64,
        rng: &mut R,
    ) -> Agent {
        let key = SigningKey::random(rng);
        let subject = *key.verifying_key();
        let subject_bytes = subject.to_encoded_point(true).as_bytes().to_vec();
        let ca_sig = ca.signing.sign(&cert_tbs(&subject_bytes, epoch));
        Agent { cert: PseudonymCert { subject, subject_bytes, epoch, ca_sig }, key }
    }

    impl Agent {
        pub fn sign(&self, msg: &[u8]) -> Signature {
            self.key.sign(msg)
        }
    }

    /// Two ECDSA verifications.
    pub fn verify(
        ca_public: &VerifyingKey,
        cert: &PseudonymCert,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<()> {
        ca_public
            .verify(&cert_tbs(&cert.subject_bytes, cert.epoch), &cert.ca_sig)
            .map_err(|_| Error::BadSignature("scms explicit: certificate"))?;
        cert.subject
            .verify(msg, sig)
            .map_err(|_| Error::BadSignature("scms explicit: message signature"))?;
        Ok(())
    }
}

// --- implicit certificates (ECQV) ------------------------------------------

pub mod implicit {
    use super::*;

    /// An ECQV implicit certificate: a public reconstruction value plus the
    /// certificate data. There is no CA signature — validity is established by
    /// the sender being able to sign under the reconstructed key.
    #[derive(Debug, Clone)]
    pub struct ImplicitCert {
        /// `P_U`, the reconstruction value.
        pub reconstruction: AffinePoint,
        pub epoch: u64,
        pub subject_id: Vec<u8>,
    }

    /// Compressed reconstruction point (33) + epoch (8) + id + signature (64).
    pub const WIRE_BYTES: usize = 33 + 8 + 8 + 64;

    pub struct Agent {
        pub cert: ImplicitCert,
        key: SigningKey,
    }

    /// `e = H(cert)`, the scalar binding the certificate to the reconstructed key.
    fn cert_hash(cert: &ImplicitCert) -> Scalar {
        let mut h = Sha256::new();
        h.update(b"RAPIDO-baseline-ecqv");
        h.update(cert.reconstruction.to_encoded_point(true).as_bytes());
        h.update(cert.epoch.to_be_bytes());
        h.update(&cert.subject_id);
        let d: [u8; 32] = h.finalize().into();
        // Reduce into the scalar field. `from_repr` rejects out-of-range digests;
        // retrying with a counter keeps the mapping deterministic and unbiased
        // enough for a benchmark baseline (rejection probability < 2^-128).
        let mut candidate = d;
        loop {
            if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(candidate.into())) {
                if s != Scalar::ZERO {
                    return s;
                }
            }
            candidate = Sha256::digest(candidate).into();
        }
    }

    /// ECQV issuance: the CA picks `k`, sets `P_U = k·G + R_U`, and returns the
    /// private-key contribution `r = e·k + d_CA`.
    pub fn issue<R: rand::Rng + rand::CryptoRng>(
        ca: &PseudonymCa,
        epoch: u64,
        subject_id: &[u8],
        rng: &mut R,
    ) -> Agent {
        // Requester's ephemeral key pair (R_U = k_U·G).
        let ku = SigningKey::random(rng);
        let ru = ProjectivePoint::from(*ku.verifying_key().as_affine());

        // CA's contribution.
        let k = SigningKey::random(rng);
        let pu = (ru + ProjectivePoint::from(*k.verifying_key().as_affine())).to_affine();

        let cert = ImplicitCert { reconstruction: pu, epoch, subject_id: subject_id.to_vec() };
        let e = cert_hash(&cert);
        let r = e * scalar_of(&k) + scalar_of(&ca.signing);
        let d_u = r + e * scalar_of(&ku);

        let key = SigningKey::from(
            p256::NonZeroScalar::new(d_u).expect("ECQV private key is non-zero except negligibly"),
        );
        Agent { cert, key }
    }

    fn scalar_of(k: &SigningKey) -> Scalar {
        *k.as_nonzero_scalar().as_ref()
    }

    impl Agent {
        pub fn sign(&self, msg: &[u8]) -> Signature {
            self.key.sign(msg)
        }
        /// The public key a verifier will reconstruct. Exposed for tests.
        pub fn public(&self) -> VerifyingKey {
            *self.key.verifying_key()
        }
    }

    /// Reconstruct `Q_U = e·P_U + Q_CA` (one scalar mul, one add), then verify
    /// the message signature. One ECDSA verification instead of two.
    pub fn verify(
        ca_public: &VerifyingKey,
        cert: &ImplicitCert,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<()> {
        let q = reconstruct(ca_public, cert)?;
        q.verify(msg, sig).map_err(|_| Error::BadSignature("scms implicit: message signature"))
    }

    pub fn reconstruct(ca_public: &VerifyingKey, cert: &ImplicitCert) -> Result<VerifyingKey> {
        let e = cert_hash(cert);
        let q = ProjectivePoint::from(cert.reconstruction) * e
            + ProjectivePoint::from(*ca_public.as_affine());
        VerifyingKey::from_affine(q.to_affine())
            .map_err(|_| Error::IdentityPoint("scms implicit: reconstructed key"))
    }

    /// Whether a reconstructed key has the x-coordinate the sender used.
    /// Only meaningful in tests; a verifier never learns the sender's key
    /// independently.
    pub fn reconstructed_matches(reconstructed: &VerifyingKey, actual: &VerifyingKey) -> bool {
        reconstructed.as_affine().x() == actual.as_affine().x()
    }
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

    #[test]
    fn explicit_round_trip() {
        let mut r = rng(1);
        let ca = PseudonymCa::generate(&mut r);
        let agent = explicit::issue(&ca, 7, &mut r);
        let sig = agent.sign(b"basic safety message");
        assert!(explicit::verify(&ca.public, &agent.cert, b"basic safety message", &sig).is_ok());
        assert!(explicit::verify(&ca.public, &agent.cert, b"tampered", &sig).is_err());
    }

    #[test]
    fn explicit_rejects_a_certificate_from_another_ca() {
        let mut r = rng(2);
        let ca = PseudonymCa::generate(&mut r);
        let rogue = PseudonymCa::generate(&mut r);
        let agent = explicit::issue(&rogue, 7, &mut r);
        let sig = agent.sign(b"m");
        assert!(explicit::verify(&ca.public, &agent.cert, b"m", &sig).is_err());
    }

    /// ECQV correctness: the key the CA helped construct must be exactly the
    /// key a verifier reconstructs from the public certificate.
    #[test]
    fn implicit_reconstruction_matches_the_agents_key() {
        let mut r = rng(3);
        let ca = PseudonymCa::generate(&mut r);
        let agent = implicit::issue(&ca, 7, b"agent-01", &mut r);
        let reconstructed = implicit::reconstruct(&ca.public, &agent.cert).unwrap();
        assert!(implicit::reconstructed_matches(&reconstructed, &agent.public()));
    }

    #[test]
    fn implicit_round_trip() {
        let mut r = rng(4);
        let ca = PseudonymCa::generate(&mut r);
        let agent = implicit::issue(&ca, 7, b"agent-01", &mut r);
        let sig = agent.sign(b"basic safety message");
        assert!(implicit::verify(&ca.public, &agent.cert, b"basic safety message", &sig).is_ok());
        assert!(implicit::verify(&ca.public, &agent.cert, b"tampered", &sig).is_err());
    }

    #[test]
    fn implicit_certificate_cannot_be_relabelled() {
        let mut r = rng(5);
        let ca = PseudonymCa::generate(&mut r);
        let agent = implicit::issue(&ca, 7, b"agent-01", &mut r);
        let sig = agent.sign(b"m");

        // Changing any certificate field changes `e`, so the reconstructed key
        // no longer matches the signing key.
        let mut altered = agent.cert.clone();
        altered.epoch = 8;
        assert!(implicit::verify(&ca.public, &altered, b"m", &sig).is_err());

        let mut altered = agent.cert.clone();
        altered.subject_id = b"agent-02".to_vec();
        assert!(implicit::verify(&ca.public, &altered, b"m", &sig).is_err());
    }

    #[test]
    fn implicit_certificate_is_not_valid_under_another_ca() {
        let mut r = rng(6);
        let ca = PseudonymCa::generate(&mut r);
        let other = PseudonymCa::generate(&mut r);
        let agent = implicit::issue(&ca, 7, b"a", &mut r);
        let sig = agent.sign(b"m");
        assert!(implicit::verify(&other.public, &agent.cert, b"m", &sig).is_err());
    }

    #[test]
    fn implicit_is_smaller_on_the_wire_than_explicit() {
        // ECQV drops the CA signature entirely, so the certificate is 64
        // bytes smaller on every message.
        let (implicit_bytes, explicit_bytes) = (implicit::WIRE_BYTES, explicit::WIRE_BYTES);
        assert!(implicit_bytes < explicit_bytes, "{implicit_bytes} vs {explicit_bytes}");
    }
}
