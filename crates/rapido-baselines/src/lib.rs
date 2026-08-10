#![forbid(unsafe_code)]
//! `rapido-baselines` — comparison systems, re-implemented and measured here.
//!
//! **No latency figure in this workspace is quoted from the literature.** Every
//! system RAPIDO is compared against is implemented in this crate and measured
//! on the same hardware, in the same process, with the same methodology as
//! RAPIDO itself. A number produced any other way is not comparable: two-decade-
//! old timings describe two-decade-old machines, not the algorithms.
//!
//! * [`mtls`] — Ed25519 and ECDSA-P256 certificate-chain verification (depth 2)
//!   plus a message signature. The "conventional PKI" row.
//! * [`scms`] — ECDSA-P256 pseudonym certificate plus message signature, in both
//!   the explicit and the implicit (ECQV) forms. **This is the real V2X
//!   baseline**, standardized as IEEE 1609.2 / SCMS and deployed in US V2X;
//!   RAPIDO Mode A is functionally the same mechanism, so this is the row Mode A
//!   has to be judged against.
//! * [`cl_rsa`] — CL signatures over RSA-2048 with a Schnorr-style proof of
//!   knowledge: a measured stand-in for "an RSA-based anonymous credential",
//!   the class of system RAPIDO's speedup claim is made relative to.
//!
//! ## What is not here
//!
//! A BBS04-style short group signature. It is omitted rather than estimated: an
//! unmeasured row is worse than a missing one, so the row is simply absent from
//! the comparison table. See `LIMITATIONS.md`.

pub mod cl_rsa;
pub mod mtls;
pub mod scms;

/// Identifies a baseline in result files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Baseline {
    MtlsEd25519,
    MtlsP256,
    ScmsExplicit,
    ScmsImplicit,
    ClRsa2048,
}

impl Baseline {
    pub fn as_str(&self) -> &'static str {
        match self {
            Baseline::MtlsEd25519 => "mtls-ed25519",
            Baseline::MtlsP256 => "mtls-p256",
            Baseline::ScmsExplicit => "scms-explicit",
            Baseline::ScmsImplicit => "scms-implicit-ecqv",
            Baseline::ClRsa2048 => "cl-rsa-2048",
        }
    }

    pub fn all() -> Vec<Baseline> {
        vec![
            Baseline::MtlsEd25519,
            Baseline::MtlsP256,
            Baseline::ScmsExplicit,
            Baseline::ScmsImplicit,
            Baseline::ClRsa2048,
        ]
    }
}

impl std::fmt::Display for Baseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
