#![forbid(unsafe_code)]
//! `rapido-proto` — RAPIDO's issuance, presentation, and verification protocols.
//!
//! ## The Layer 1 design question
//!
//! The cheapest imaginable Layer 1 has the agent derive one-time BLS keys
//! `k_i = PRF(master, epoch || counter)`, sign a challenge, and be verified
//! with one pairing. **That authenticates nothing**: verifying a signature
//! under a fresh public key `P_i` proves only that the presenter knows the
//! matching secret key, and anyone can generate a BLS keypair. Nothing binds
//! `P_i` to a credential issued by the authority.
//!
//! Binding it requires an extra mechanism, and there are two candidates. Both
//! are implemented here, so the cost of each can be measured rather than
//! asserted:
//!
//! * [`mode_a`] — the authority pre-signs a batch of PRF-derived one-time
//!   public keys; the agent presents (pseudonym certificate, signature).
//!   **The issuer can link every session it certified.**
//! * [`mode_b`] — a BBS+ credential presented as a re-randomized signature plus
//!   a proof of knowledge with selective disclosure. **Unlinkable even to the
//!   issuer.**
//!
//! Mode A is functionally the butterfly-key / pseudonym-certificate mechanism
//! already standardized in IEEE 1609.2 / SCMS and deployed in US V2X; see the
//! README and `rapido-baselines::scms`.

pub mod audit;
pub mod escrow;
pub mod mode_a;
pub mod mode_b;
pub mod replay;
pub mod revocation;
pub mod verifier;

pub use escrow::{EscrowAttachment, EscrowMode};
pub use revocation::{RevocationCheck, RevocationMode};
pub use verifier::{VerifyOutcome, VerifyPath};

/// Which Layer 1 credential mechanism a run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Batch pseudonym certificates. Issuer-linkable.
    A,
    /// BBS+ presentation. Issuer-unlinkable.
    B,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::A => "mode-a",
            Mode::B => "mode-b",
        }
    }

    /// Whether an adversary who colludes with the issuer can link two sessions
    /// by the same agent. This is the property that separates the two modes,
    /// and it is measured empirically in `rapido-sim` Scenario 4.
    pub fn issuer_can_link(&self) -> bool {
        match self {
            // The authority signed each pseudonym key and therefore holds a
            // list mapping every P_i back to the agent that requested it.
            Mode::A => true,
            // The presentation is a fresh re-randomization; the issuer sees
            // nothing it can correlate with what it signed.
            Mode::B => false,
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
