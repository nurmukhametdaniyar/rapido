//! The verifier pipeline, instrumented per layer.
//!
//! One place where a presentation is checked end to end, so the per-layer
//! latency decomposition that `fig_latency_breakdown` plots comes from the same
//! code path production verification would use — not from summing standalone
//! micro-benchmarks, which would omit the work the pipeline does between them.

use crate::{
    escrow::EscrowConfig, mode_a, mode_b, replay::NonceCache, revocation::RevocationCheck,
};
use rapido_core::{Epoch, Result};
use rapido_crypto::bbs;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Which Mode A verification strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyPath {
    /// Two independent pairing checks.
    Naive,
    /// Both checks folded into one multi-pairing.
    Aggregate,
}

/// Per-layer timing for one verification, in nanoseconds.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct LatencyBreakdown {
    /// Layer 1: credential + challenge verification.
    pub layer1_ns: u64,
    /// Layer 3: escrow check (zero under E0, and under E1 by construction).
    pub escrow_ns: u64,
    /// Revocation check (R0/R1/R2).
    pub revocation_ns: u64,
    /// Replay/nonce-cache lookup.
    pub replay_ns: u64,
}

impl LatencyBreakdown {
    pub fn total_ns(&self) -> u64 {
        self.layer1_ns + self.escrow_ns + self.revocation_ns + self.replay_ns
    }
}

#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub accepted: bool,
    pub breakdown: LatencyBreakdown,
    pub bytes_received: usize,
    /// Populated on rejection, so failure modes can be counted separately.
    pub rejection: Option<String>,
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let t0 = Instant::now();
    let out = f();
    (out, t0.elapsed().as_nanos() as u64)
}

/// Verify a Mode A presentation through every layer.
// The verifier genuinely depends on all of these; grouping them into a config
// struct would just hide the same coupling behind a constructor.
#[allow(clippy::too_many_arguments)]
pub fn verify_mode_a<C: RevocationCheck, R: rand::Rng + ?Sized>(
    authority_pk: &rapido_crypto::bls::PublicKey,
    pres: &mode_a::Presentation,
    challenge: &[u8],
    context: &[u8],
    path: VerifyPath,
    escrow: &EscrowConfig,
    revocation: &C,
    nonces: &mut NonceCache,
    rng: &mut R,
) -> VerifyOutcome {
    let mut b = LatencyBreakdown::default();
    let fail = |b: LatencyBreakdown, why: &str| VerifyOutcome {
        accepted: false,
        breakdown: b,
        bytes_received: pres.size_bytes(),
        rejection: Some(why.to_string()),
    };

    // Revocation first: it is the cheapest check, so rejecting here avoids
    // spending pairings on a credential that cannot be accepted. Ordering
    // matters for the measured p99 under attack traffic.
    let cred_id = pres.cert.p_i.to_bytes();
    let (revoked, ns) = timed(|| revocation.is_revoked(&cred_id, pres.cert.epoch));
    b.revocation_ns = ns;
    if revoked {
        return fail(b, "revoked-or-wrong-epoch");
    }

    let (replay, ns) =
        timed(|| nonces.check_and_insert(pres.cert.epoch, &mode_a::cert_bytes(&pres.cert)));
    b.replay_ns = ns;
    if replay.is_err() {
        return fail(b, "replay");
    }

    let (l1, ns) = timed(|| match path {
        VerifyPath::Naive => mode_a::verify_naive(authority_pk, pres, challenge, context),
        VerifyPath::Aggregate => {
            mode_a::verify_aggregate(authority_pk, pres, challenge, context, rng)
        }
    });
    b.layer1_ns = ns;
    if l1.is_err() {
        return fail(b, "layer1");
    }

    let msg = mode_a::Presentation::challenge_message(challenge, context, pres.cert.epoch);
    let (esc, ns) = timed(|| escrow.check(&pres.escrow, &pres.cert.attr_commitment, &msg));
    b.escrow_ns = ns;
    if esc.is_err() {
        return fail(b, "escrow");
    }

    VerifyOutcome {
        accepted: true,
        breakdown: b,
        bytes_received: pres.size_bytes(),
        rejection: None,
    }
}

/// Verify a Mode B presentation through every layer.
///
/// Under E2 the escrow statement is proved inside the presentation's own
/// Schnorr proof, so `escrow_ns` is attributed to Layer 1 and reported as zero
/// here. The E2 - E1 difference for Mode B therefore shows up as a larger
/// `layer1_ns`, which is the honest place for it.
#[allow(clippy::too_many_arguments)]
pub fn verify_mode_b<C: RevocationCheck>(
    params: &bbs::Params,
    pk: &bbs::PublicKey,
    pres: &mode_b::Presentation,
    challenge: &[u8],
    context: &[u8],
    escrow: &EscrowConfig,
    revocation: &C,
    nonces: &mut NonceCache,
) -> VerifyOutcome {
    let mut b = LatencyBreakdown::default();
    let bytes = pres.size_bytes();
    let fail = |b: LatencyBreakdown, why: &str| VerifyOutcome {
        accepted: false,
        breakdown: b,
        bytes_received: bytes,
        rejection: Some(why.to_string()),
    };

    // Mode B has no stable per-agent identifier for a verifier to look up —
    // that is the point of the mode. Only the epoch check applies, and a CRL
    // must therefore act on something else (see LIMITATIONS.md).
    let (revoked, ns) = timed(|| revocation.is_revoked(&[], pres.epoch));
    b.revocation_ns = ns;
    if revoked {
        return fail(b, "revoked-or-wrong-epoch");
    }

    let digest = presentation_digest(pres);
    let (replay, ns) = timed(|| nonces.check_and_insert(pres.epoch, &digest));
    b.replay_ns = ns;
    if replay.is_err() {
        return fail(b, "replay");
    }

    let (res, ns) = timed(|| mode_b::verify(params, pk, pres, challenge, context, escrow));
    b.layer1_ns = ns;
    match res {
        Ok(_) => {
            VerifyOutcome { accepted: true, breakdown: b, bytes_received: bytes, rejection: None }
        }
        Err(_) => fail(b, "layer1"),
    }
}

/// Bytes uniquely identifying a Mode B presentation, for the nonce cache.
pub fn presentation_digest(pres: &mode_b::Presentation) -> Vec<u8> {
    let mut out = rapido_crypto::ser::g1_to_bytes(&pres.bbs.a_prime);
    out.extend_from_slice(&rapido_crypto::ser::g1_to_bytes(&pres.bbs.a_bar));
    out.extend_from_slice(&rapido_crypto::ser::g1_to_bytes(&pres.bbs.d));
    out.extend_from_slice(&pres.bbs.proof.to_bytes());
    out
}

/// Total presentation bytes for a Mode A session (agent -> verifier).
pub fn mode_a_bytes(pres: &mode_a::Presentation) -> usize {
    pres.size_bytes()
}

/// Total presentation bytes for a Mode B session.
pub fn mode_b_bytes(pres: &mode_b::Presentation) -> usize {
    pres.size_bytes()
}

/// A verifier's per-epoch state, reset when the epoch rolls over.
#[derive(Debug)]
pub struct VerifierState {
    pub nonces: NonceCache,
    pub epoch: Epoch,
}

impl VerifierState {
    pub fn new(epoch: Epoch, nonce_capacity: usize) -> Self {
        VerifierState { nonces: NonceCache::new(epoch, nonce_capacity), epoch }
    }

    pub fn advance_to(&mut self, epoch: Epoch) {
        self.nonces.advance_to(epoch);
        self.epoch = epoch;
    }
}

/// Re-exported so callers can build a verifier without importing the trait.
pub fn check_revocation<C: RevocationCheck>(c: &C, id: &[u8], epoch: Epoch) -> Result<()> {
    if c.is_revoked(id, epoch) {
        Err(rapido_core::Error::Revoked)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::{EscrowAuthorities, EscrowMode};
    use crate::revocation::{Crl, EpochAnd, EpochOnly};
    use rapido_core::EpochClock;
    use rapido_crypto::{elgamal, pedersen, rng_from_seed};
    use std::collections::BTreeSet;

    #[test]
    fn mode_a_end_to_end_accepts_then_rejects_a_replay() {
        let mut rng = rng_from_seed(1);
        let authority = mode_a::Authority::generate(3, 5, &mut rng).unwrap();
        let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let id = escrow_auth.registry.enrol(b"a1");
        let agent = mode_a::Agent::new(&authority.pedersen, id, &mut rng);
        let mut batch = mode_a::provision(&authority, &agent, Epoch(2), 8, &mut rng).unwrap();
        let cfg = EscrowConfig::new(
            EscrowMode::E2,
            Some(escrow_auth.public()),
            pedersen::Params::default(),
        );
        let rev = EpochOnly::new(Epoch(2), EpochClock::default());
        let mut nonces = NonceCache::new(Epoch(2), 1 << 16);

        let pres = mode_a::present(&agent, &mut batch, b"c", b"x", &cfg, &mut rng).unwrap();
        let out = verify_mode_a(
            &authority.public_key(),
            &pres,
            b"c",
            b"x",
            VerifyPath::Aggregate,
            &cfg,
            &rev,
            &mut nonces,
            &mut rng,
        );
        assert!(out.accepted, "{:?}", out.rejection);
        assert!(out.breakdown.layer1_ns > 0);
        assert!(out.breakdown.escrow_ns > 0, "E2 must cost measurable time");
        assert_eq!(out.bytes_received, pres.size_bytes());

        // Same presentation again: caught by the nonce cache.
        let out = verify_mode_a(
            &authority.public_key(),
            &pres,
            b"c",
            b"x",
            VerifyPath::Aggregate,
            &cfg,
            &rev,
            &mut nonces,
            &mut rng,
        );
        assert!(!out.accepted);
        assert_eq!(out.rejection.as_deref(), Some("replay"));
    }

    #[test]
    fn mode_a_rejects_a_revoked_pseudonym() {
        let mut rng = rng_from_seed(2);
        let authority = mode_a::Authority::generate(2, 3, &mut rng).unwrap();
        let agent =
            mode_a::Agent::new(&authority.pedersen, elgamal::identity_scalar(b"a"), &mut rng);
        let mut batch = mode_a::provision(&authority, &agent, Epoch(1), 4, &mut rng).unwrap();
        let cfg = EscrowConfig::new(EscrowMode::E0, None, pedersen::Params::default());

        let pres = mode_a::present(&agent, &mut batch, b"c", b"x", &cfg, &mut rng).unwrap();
        let mut crl = Crl::new();
        crl.insert(&pres.cert.p_i.to_bytes());
        let rev = EpochAnd { epoch: EpochOnly::new(Epoch(1), EpochClock::default()), list: crl };
        let mut nonces = NonceCache::new(Epoch(1), 1 << 16);

        let out = verify_mode_a(
            &authority.public_key(),
            &pres,
            b"c",
            b"x",
            VerifyPath::Naive,
            &cfg,
            &rev,
            &mut nonces,
            &mut rng,
        );
        assert!(!out.accepted);
        assert_eq!(out.rejection.as_deref(), Some("revoked-or-wrong-epoch"));
        // Rejecting early means no pairing was computed.
        assert_eq!(out.breakdown.layer1_ns, 0);
    }

    #[test]
    fn mode_b_end_to_end() {
        let mut rng = rng_from_seed(3);
        let issuer = mode_b::Issuer::generate(8, &mut rng).unwrap();
        let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let id = escrow_auth.registry.enrol(b"b1");
        let cred = mode_b::issue(&issuer, id, Epoch(5), &[], &mut rng).unwrap();
        let cfg = EscrowConfig::new(
            EscrowMode::E2,
            Some(escrow_auth.public()),
            pedersen::Params::default(),
        );
        let rev = EpochOnly::new(Epoch(5), EpochClock::default());
        let mut nonces = NonceCache::new(Epoch(5), 1 << 16);

        let pres = mode_b::present(
            &issuer.params,
            &issuer.pk,
            &cred,
            &BTreeSet::new(),
            b"c",
            b"x",
            &cfg,
            &mut rng,
        )
        .unwrap();
        let out =
            verify_mode_b(&issuer.params, &issuer.pk, &pres, b"c", b"x", &cfg, &rev, &mut nonces);
        assert!(out.accepted, "{:?}", out.rejection);

        let out =
            verify_mode_b(&issuer.params, &issuer.pk, &pres, b"c", b"x", &cfg, &rev, &mut nonces);
        assert_eq!(out.rejection.as_deref(), Some("replay"));
    }

    #[test]
    fn wrong_epoch_is_rejected_in_both_modes() {
        let mut rng = rng_from_seed(4);
        let rev = EpochOnly::new(Epoch(7), EpochClock::default());
        let cfg = EscrowConfig::new(EscrowMode::E0, None, pedersen::Params::default());

        let authority = mode_a::Authority::generate(2, 3, &mut rng).unwrap();
        let agent =
            mode_a::Agent::new(&authority.pedersen, elgamal::identity_scalar(b"a"), &mut rng);
        let mut batch = mode_a::provision(&authority, &agent, Epoch(6), 2, &mut rng).unwrap();
        let pres = mode_a::present(&agent, &mut batch, b"c", b"x", &cfg, &mut rng).unwrap();
        let mut nonces = NonceCache::new(Epoch(7), 1 << 16);
        let out = verify_mode_a(
            &authority.public_key(),
            &pres,
            b"c",
            b"x",
            VerifyPath::Naive,
            &cfg,
            &rev,
            &mut nonces,
            &mut rng,
        );
        assert!(!out.accepted);

        let issuer = mode_b::Issuer::generate(4, &mut rng).unwrap();
        let cred = mode_b::issue(&issuer, elgamal::identity_scalar(b"b"), Epoch(6), &[], &mut rng)
            .unwrap();
        let pres = mode_b::present(
            &issuer.params,
            &issuer.pk,
            &cred,
            &BTreeSet::new(),
            b"c",
            b"x",
            &cfg,
            &mut rng,
        )
        .unwrap();
        let mut nonces = NonceCache::new(Epoch(7), 1 << 16);
        let out =
            verify_mode_b(&issuer.params, &issuer.pk, &pres, b"c", b"x", &cfg, &rev, &mut nonces);
        assert!(!out.accepted);
    }

    #[test]
    fn breakdown_sums_to_the_total() {
        let b = LatencyBreakdown { layer1_ns: 10, escrow_ns: 3, revocation_ns: 1, replay_ns: 2 };
        assert_eq!(b.total_ns(), 16);
    }
}
