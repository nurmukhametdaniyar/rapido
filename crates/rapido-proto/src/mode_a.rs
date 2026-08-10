//! Mode A — batch pseudonym certificates.
//!
//! ```text
//! issuance (offline, per epoch)
//!   agent     : derive (sk_i, P_i) for i in 0..n_batch from PRF(master, epoch||i)
//!               produce a proof of possession for each P_i
//!   authority : verify the agent's long-term credential and each PoP, then
//!               threshold-sign cert_i = Sign_auth(P_i || epoch || attr_commitment)
//!
//! presentation (online)
//!   agent     : send (cert_i, P_i, epoch, sigma = Sign_{sk_i}(challenge || context))
//!
//! verification
//!   verify cert_i under the authority key   (1 pairing)
//!   verify sigma under P_i                  (1 pairing)
//! ```
//!
//! ## Issuer linkability
//!
//! The authority signs each `P_i` individually, so it necessarily holds the map
//! `P_i -> requesting agent`. Any verifier transcript contains `P_i` in the
//! clear. An issuer who observes (or is handed) verifier transcripts can
//! therefore link **every** session of **every** agent, across epochs. Mode A's
//! unlinkability holds against a verifier-only adversary and collapses entirely
//! against an issuer-colluding one. This is measured in `rapido-sim`
//! Scenario 4, and it is the same property the IEEE 1609.2 / SCMS pseudonym
//! certificate mechanism has.

use rapido_core::{dst, Epoch, Error, Result, Transcript};
use rapido_crypto::{
    bls, kdf, pedersen,
    ser::{self, FR_LEN, G1_COMPRESSED_LEN, G2_COMPRESSED_LEN},
    shamir, Fr,
};

/// The `(k, n)` threshold issuing authority.
#[derive(Debug, Clone)]
pub struct Authority {
    pub key: bls::ThresholdKey,
    pub pedersen: pedersen::Params,
}

impl Authority {
    pub fn generate<R: rand::Rng + ?Sized>(k: usize, n: usize, rng: &mut R) -> Result<Self> {
        Ok(Authority {
            key: bls::ThresholdKey::generate(k, n, rng)?,
            pedersen: pedersen::Params::default(),
        })
    }

    pub fn public_key(&self) -> bls::PublicKey {
        self.key.group_public
    }
}

/// A request to certify one pseudonym key.
#[derive(Debug, Clone)]
pub struct CertRequest {
    pub p_i: bls::PublicKey,
    pub pop: bls::Signature,
}

impl CertRequest {
    /// Wire size: one compressed G1 public key plus one compressed G2 PoP.
    pub const SIZE: usize = G1_COMPRESSED_LEN + G2_COMPRESSED_LEN;
}

/// A pseudonym certificate: the authority's signature over
/// `P_i || epoch || attribute_commitment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PseudonymCert {
    pub p_i: bls::PublicKey,
    pub epoch: Epoch,
    /// Pedersen commitment to the agent's identity. Signed by the authority,
    /// which is what lets the E2 escrow proof bind to it.
    pub attr_commitment: pedersen::Commitment,
    pub sig: bls::Signature,
}

impl PseudonymCert {
    /// Wire size: `P_i` + epoch + commitment + authority signature.
    pub const SIZE: usize = G1_COMPRESSED_LEN + 8 + G1_COMPRESSED_LEN + G2_COMPRESSED_LEN;

    /// The exact byte string the authority signs. Length-prefixed so no two
    /// distinct (key, epoch, commitment) triples can produce the same message.
    pub fn signed_message(
        p_i: &bls::PublicKey,
        epoch: Epoch,
        commitment: &pedersen::Commitment,
    ) -> Vec<u8> {
        let mut t = Transcript::new(dst::CRED);
        t.push_bytes(&p_i.to_bytes());
        t.push_u64(epoch.index());
        t.push_bytes(&commitment.to_bytes());
        t.finish()
    }

    fn message(&self) -> Vec<u8> {
        Self::signed_message(&self.p_i, self.epoch, &self.attr_commitment)
    }
}

/// An agent's per-epoch batch of one-time keys and their certificates.
#[derive(Debug, Clone)]
pub struct Batch {
    pub epoch: Epoch,
    pub secrets: Vec<bls::SecretKey>,
    pub certs: Vec<PseudonymCert>,
    /// Index of the next unused pseudonym. A batch is exhausted when this
    /// reaches `certs.len()` — the availability cost measured in Scenario 3.
    pub next: usize,
}

impl Batch {
    pub fn remaining(&self) -> usize {
        self.certs.len().saturating_sub(self.next)
    }
    pub fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }

    /// Total bytes an agent stores for this batch (certificates only; the
    /// secrets are re-derivable from the master secret).
    pub fn stored_bytes(&self) -> usize {
        self.certs.len() * PseudonymCert::SIZE
    }
}

/// Agent-side state.
#[derive(Debug, Clone)]
pub struct Agent {
    pub master: kdf::MasterSecret,
    /// The agent's escrow identity scalar, committed in every certificate.
    pub identity: Fr,
    pub id_blinding: Fr,
    pub commitment: pedersen::Commitment,
}

impl Agent {
    pub fn new<R: rand::Rng + ?Sized>(
        pedersen_params: &pedersen::Params,
        identity: Fr,
        rng: &mut R,
    ) -> Self {
        let (commitment, opening) = pedersen_params.commit_random(identity, rng);
        Agent {
            master: kdf::MasterSecret::random(rng),
            identity,
            id_blinding: opening.blinding,
            commitment,
        }
    }

    /// Derive the `i`-th one-time key for `epoch`.
    pub fn derive_key(&self, epoch: Epoch, counter: u32) -> bls::SecretKey {
        bls::SecretKey(kdf::derive_scalar(&self.master, epoch, counter))
    }

    /// Step 1-2: derive `n_batch` keys and prove possession of each.
    pub fn request_batch(
        &self,
        epoch: Epoch,
        n_batch: usize,
    ) -> (Vec<bls::SecretKey>, Vec<CertRequest>) {
        let secrets: Vec<bls::SecretKey> =
            (0..n_batch as u32).map(|i| self.derive_key(epoch, i)).collect();
        let requests = secrets
            .iter()
            .map(|sk| CertRequest { p_i: sk.public(), pop: bls::prove_possession(sk) })
            .collect();
        (secrets, requests)
    }
}

/// Step 3-4: the authority verifies every proof of possession and threshold-
/// signs each pseudonym key.
///
/// Proofs of possession are verified as one batch — with `n_batch` up to 1000,
/// checking them one at a time dominates issuance cost for no security gain.
pub fn issue_batch<R: rand::Rng + ?Sized>(
    authority: &Authority,
    requests: &[CertRequest],
    epoch: Epoch,
    commitment: &pedersen::Commitment,
    signing_shares: &[shamir::Share],
    rng: &mut R,
) -> Result<Vec<PseudonymCert>> {
    if signing_shares.len() < authority.key.k {
        return Err(Error::NotEnoughShares { need: authority.key.k, got: signing_shares.len() });
    }

    let pop_messages: Vec<Vec<u8>> = requests.iter().map(|r| r.p_i.to_bytes()).collect();
    let triples: Vec<(bls::PublicKey, rapido_core::Dst, &[u8], bls::Signature)> = requests
        .iter()
        .zip(&pop_messages)
        .map(|(r, m)| (r.p_i, dst::POP, m.as_slice(), r.pop))
        .collect();
    bls::batch_verify(&triples, rng).map_err(|_| Error::BadProof("batch proof of possession"))?;

    requests
        .iter()
        .map(|r| {
            let msg = PseudonymCert::signed_message(&r.p_i, epoch, commitment);
            let partials: Vec<bls::PartialSignature> = signing_shares[..authority.key.k]
                .iter()
                .map(|s| bls::partial_sign(s, dst::CRED, &msg))
                .collect();
            Ok(PseudonymCert {
                p_i: r.p_i,
                epoch,
                attr_commitment: *commitment,
                sig: bls::combine(&partials, authority.key.k)?,
            })
        })
        .collect()
}

/// Convenience: run the whole per-epoch issuance for one agent.
pub fn provision<R: rand::Rng + ?Sized>(
    authority: &Authority,
    agent: &Agent,
    epoch: Epoch,
    n_batch: usize,
    rng: &mut R,
) -> Result<Batch> {
    let (secrets, requests) = agent.request_batch(epoch, n_batch);
    let certs =
        issue_batch(authority, &requests, epoch, &agent.commitment, &authority.key.shares, rng)?;
    Ok(Batch { epoch, secrets, certs, next: 0 })
}

/// A Mode A presentation.
#[derive(Debug, Clone)]
pub struct Presentation {
    pub cert: PseudonymCert,
    pub sigma: bls::Signature,
    pub escrow: crate::escrow::EscrowAttachment,
}

impl Presentation {
    /// Bytes on the wire, escrow included.
    pub fn size_bytes(&self) -> usize {
        PseudonymCert::SIZE + G2_COMPRESSED_LEN + self.escrow.size_bytes()
    }

    /// The message the one-time key signs: verifier challenge, context, and the
    /// epoch (so a signature cannot be replayed into a different epoch).
    pub fn challenge_message(challenge: &[u8], context: &[u8], epoch: Epoch) -> Vec<u8> {
        let mut t = Transcript::new(dst::PRESENT);
        t.push_bytes(challenge);
        t.push_bytes(context);
        t.push_u64(epoch.index());
        t.finish()
    }
}

/// Produce a presentation using the next unused pseudonym in the batch.
pub fn present<R: rand::Rng + ?Sized>(
    agent: &Agent,
    batch: &mut Batch,
    challenge: &[u8],
    context: &[u8],
    escrow: &crate::escrow::EscrowConfig,
    rng: &mut R,
) -> Result<Presentation> {
    if batch.is_exhausted() {
        return Err(Error::InvalidParameter("mode A: credential batch exhausted".into()));
    }
    let i = batch.next;
    batch.next += 1;

    let msg = Presentation::challenge_message(challenge, context, batch.epoch);
    let sigma = bls::sign(&batch.secrets[i], dst::PRESENT, &msg);
    let cert = batch.certs[i];

    let attachment =
        escrow.attach(agent.identity, agent.id_blinding, &cert.attr_commitment, &msg, rng)?;

    Ok(Presentation { cert, sigma, escrow: attachment })
}

/// The two pairing checks a Mode A verification consists of, as inputs.
/// Shared between the naive and aggregate paths so they cannot drift.
pub(crate) struct PairingTerms {
    pub cert_msg: Vec<u8>,
    pub challenge_msg: Vec<u8>,
}

pub(crate) fn pairing_terms(pres: &Presentation, challenge: &[u8], context: &[u8]) -> PairingTerms {
    PairingTerms {
        cert_msg: pres.cert.message(),
        challenge_msg: Presentation::challenge_message(challenge, context, pres.cert.epoch),
    }
}

/// Naive verification: two independent pairing checks.
pub fn verify_naive(
    authority_pk: &bls::PublicKey,
    pres: &Presentation,
    challenge: &[u8],
    context: &[u8],
) -> Result<()> {
    let t = pairing_terms(pres, challenge, context);
    bls::verify(authority_pk, dst::CRED, &t.cert_msg, &pres.cert.sig)
        .map_err(|_| Error::BadSignature("mode A pseudonym certificate"))?;
    bls::verify(&pres.cert.p_i, dst::PRESENT, &t.challenge_msg, &pres.sigma)
        .map_err(|_| Error::BadSignature("mode A challenge signature"))?;
    Ok(())
}

/// Aggregate verification: both checks folded into one multi-pairing with
/// random coefficients — three pairings and a single final exponentiation
/// instead of four pairings and two. This is the "aggregate path".
pub fn verify_aggregate<R: rand::Rng + ?Sized>(
    authority_pk: &bls::PublicKey,
    pres: &Presentation,
    challenge: &[u8],
    context: &[u8],
    rng: &mut R,
) -> Result<()> {
    let t = pairing_terms(pres, challenge, context);
    bls::batch_verify(
        &[
            (*authority_pk, dst::CRED, t.cert_msg.as_slice(), pres.cert.sig),
            (pres.cert.p_i, dst::PRESENT, t.challenge_msg.as_slice(), pres.sigma),
        ],
        rng,
    )
    .map_err(|_| Error::BadSignature("mode A aggregate verification"))
}

/// Verify many presentations at once — the RSU's actual workload during an
/// intersection burst, modelled in `rapido-sim` Scenario 1.
pub fn verify_batch<R: rand::Rng + ?Sized>(
    authority_pk: &bls::PublicKey,
    items: &[(&Presentation, &[u8], &[u8])],
    rng: &mut R,
) -> Result<()> {
    let terms: Vec<PairingTerms> =
        items.iter().map(|(p, c, ctx)| pairing_terms(p, c, ctx)).collect();
    let mut triples = Vec::with_capacity(items.len() * 2);
    for ((pres, _, _), t) in items.iter().zip(&terms) {
        triples.push((*authority_pk, dst::CRED, t.cert_msg.as_slice(), pres.cert.sig));
        triples.push((pres.cert.p_i, dst::PRESENT, t.challenge_msg.as_slice(), pres.sigma));
    }
    bls::batch_verify(&triples, rng).map_err(|_| Error::BadSignature("mode A batch verification"))
}

/// Bytes an agent must download per epoch for a batch of `n` pseudonyms.
pub fn issuance_download_bytes(n_batch: usize) -> usize {
    n_batch * PseudonymCert::SIZE
}

/// Bytes an agent must upload per epoch to request `n` pseudonyms.
pub fn issuance_upload_bytes(n_batch: usize) -> usize {
    n_batch * CertRequest::SIZE
}

/// Size of a scalar on the wire, re-exported for size accounting elsewhere.
pub const SCALAR_SIZE: usize = FR_LEN;

/// Byte encoding of a certificate, for transcript hashing and size checks.
pub fn cert_bytes(c: &PseudonymCert) -> Vec<u8> {
    let mut out = c.p_i.to_bytes();
    out.extend_from_slice(&c.epoch.index().to_be_bytes());
    out.extend_from_slice(&c.attr_commitment.to_bytes());
    out.extend_from_slice(&ser::g2_to_bytes(&c.sig.0));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::{EscrowConfig, EscrowMode};
    use rapido_crypto::{elgamal, rng_from_seed};

    struct Fixture {
        authority: Authority,
        agent: Agent,
        batch: Batch,
        rng: rapido_crypto::Rng,
    }

    fn fixture(n_batch: usize, seed: u64) -> Fixture {
        let mut rng = rng_from_seed(seed);
        let authority = Authority::generate(3, 5, &mut rng).unwrap();
        let id = elgamal::identity_scalar(b"agent-1");
        let agent = Agent::new(&authority.pedersen, id, &mut rng);
        let batch = provision(&authority, &agent, Epoch(4), n_batch, &mut rng).unwrap();
        Fixture { authority, agent, batch, rng }
    }

    fn no_escrow() -> EscrowConfig {
        EscrowConfig::new(EscrowMode::E0, None, pedersen::Params::default())
    }

    #[test]
    fn issue_present_verify_round_trip() {
        let mut f = fixture(8, 1);
        let cfg = no_escrow();
        let pres =
            present(&f.agent, &mut f.batch, b"challenge", b"rsu-7", &cfg, &mut f.rng).unwrap();
        let pk = f.authority.public_key();
        assert!(verify_naive(&pk, &pres, b"challenge", b"rsu-7").is_ok());
        assert!(verify_aggregate(&pk, &pres, b"challenge", b"rsu-7", &mut f.rng).is_ok());
    }

    #[test]
    fn naive_and_aggregate_paths_agree() {
        let mut f = fixture(16, 2);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        for i in 0..8 {
            let ch = format!("challenge-{i}");
            let pres =
                present(&f.agent, &mut f.batch, ch.as_bytes(), b"ctx", &cfg, &mut f.rng).unwrap();
            let a = verify_naive(&pk, &pres, ch.as_bytes(), b"ctx").is_ok();
            let b = verify_aggregate(&pk, &pres, ch.as_bytes(), b"ctx", &mut f.rng).is_ok();
            assert_eq!(a, b);
            assert!(a);
        }
    }

    /// The core objection to an uncertified one-time key: a freshly generated
    /// BLS keypair with no certificate must not authenticate.
    #[test]
    fn a_signature_without_a_valid_certificate_is_rejected() {
        let mut f = fixture(4, 3);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        let mut pres = present(&f.agent, &mut f.batch, b"c", b"ctx", &cfg, &mut f.rng).unwrap();

        // The attacker generates their own key and signs the challenge
        // correctly — exactly what a Layer 1 with no certificate binding accepts.
        let rogue = bls::SecretKey::random(&mut f.rng);
        let msg = Presentation::challenge_message(b"c", b"ctx", pres.cert.epoch);
        pres.cert.p_i = rogue.public();
        pres.sigma = bls::sign(&rogue, dst::PRESENT, &msg);

        assert!(verify_naive(&pk, &pres, b"c", b"ctx").is_err());
        assert!(verify_aggregate(&pk, &pres, b"c", b"ctx", &mut f.rng).is_err());
    }

    #[test]
    fn certificate_from_a_different_authority_is_rejected() {
        let mut f = fixture(4, 4);
        let cfg = no_escrow();
        let other = Authority::generate(3, 5, &mut f.rng).unwrap();
        let pres = present(&f.agent, &mut f.batch, b"c", b"ctx", &cfg, &mut f.rng).unwrap();
        assert!(verify_naive(&other.public_key(), &pres, b"c", b"ctx").is_err());
    }

    #[test]
    fn presentation_is_bound_to_challenge_and_context() {
        let mut f = fixture(4, 5);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        let pres = present(&f.agent, &mut f.batch, b"c1", b"rsu-a", &cfg, &mut f.rng).unwrap();
        assert!(verify_naive(&pk, &pres, b"c2", b"rsu-a").is_err());
        assert!(verify_naive(&pk, &pres, b"c1", b"rsu-b").is_err());
    }

    #[test]
    fn a_signature_is_not_transferable_to_another_epoch() {
        let mut f = fixture(4, 6);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        let mut pres = present(&f.agent, &mut f.batch, b"c", b"ctx", &cfg, &mut f.rng).unwrap();
        // Re-label the certificate's epoch: both the certificate signature and
        // the challenge signature are bound to the epoch, so this must fail.
        pres.cert.epoch = Epoch(9);
        assert!(verify_naive(&pk, &pres, b"c", b"ctx").is_err());
    }

    #[test]
    fn tampered_attribute_commitment_is_rejected() {
        let mut f = fixture(4, 7);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        let mut pres = present(&f.agent, &mut f.batch, b"c", b"ctx", &cfg, &mut f.rng).unwrap();
        let (other, _) = f.authority.pedersen.commit_random(Fr::from(77u64), &mut f.rng);
        pres.cert.attr_commitment = other;
        assert!(verify_naive(&pk, &pres, b"c", b"ctx").is_err());
    }

    #[test]
    fn issuance_rejects_a_key_the_requester_does_not_control() {
        let mut f = fixture(2, 8);
        let (_secrets, mut requests) = f.agent.request_batch(Epoch(4), 4);
        // Swap in a public key whose PoP was made for a different key.
        let stranger = bls::SecretKey::random(&mut f.rng);
        requests[2].p_i = stranger.public();
        assert!(issue_batch(
            &f.authority,
            &requests,
            Epoch(4),
            &f.agent.commitment,
            &f.authority.key.shares,
            &mut f.rng
        )
        .is_err());
    }

    #[test]
    fn issuance_needs_k_authority_shares() {
        let mut f = fixture(2, 9);
        let (_s, requests) = f.agent.request_batch(Epoch(4), 2);
        assert!(issue_batch(
            &f.authority,
            &requests,
            Epoch(4),
            &f.agent.commitment,
            &f.authority.key.shares[..2],
            &mut f.rng
        )
        .is_err());
    }

    #[test]
    fn batch_exhausts_after_n_presentations() {
        let n = 5;
        let mut f = fixture(n, 10);
        let cfg = no_escrow();
        for _ in 0..n {
            assert!(present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).is_ok());
        }
        assert!(f.batch.is_exhausted());
        assert!(present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).is_err());
    }

    #[test]
    fn each_presentation_uses_a_fresh_pseudonym() {
        let mut f = fixture(8, 11);
        let cfg = no_escrow();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let p = present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).unwrap();
            assert!(seen.insert(p.cert.p_i.to_bytes()), "pseudonym reused within an epoch");
        }
    }

    /// Mode A's central privacy cost, made concrete: the issuer holds
    /// `P_i -> agent`, so a verifier transcript is directly linkable by it.
    #[test]
    fn issuer_can_link_sessions_from_public_transcripts() {
        let mut f = fixture(8, 12);
        let cfg = no_escrow();
        // What the authority learns at issuance.
        let issuer_table: std::collections::HashMap<Vec<u8>, &str> =
            f.batch.certs.iter().map(|c| (c.p_i.to_bytes(), "agent-1")).collect();

        for _ in 0..4 {
            let p = present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).unwrap();
            assert_eq!(
                issuer_table.get(&p.cert.p_i.to_bytes()),
                Some(&"agent-1"),
                "issuer failed to link a session it certified"
            );
        }
    }

    #[test]
    fn verify_batch_accepts_valid_and_rejects_a_single_bad_member() {
        let mut f = fixture(8, 13);
        let cfg = no_escrow();
        let pk = f.authority.public_key();
        let presentations: Vec<Presentation> = (0..6)
            .map(|_| present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).unwrap())
            .collect();

        let items: Vec<(&Presentation, &[u8], &[u8])> =
            presentations.iter().map(|p| (p, b"c".as_slice(), b"x".as_slice())).collect();
        assert!(verify_batch(&pk, &items, &mut f.rng).is_ok());

        let mut broken = presentations.clone();
        broken[3].sigma = presentations[4].sigma;
        let items: Vec<(&Presentation, &[u8], &[u8])> =
            broken.iter().map(|p| (p, b"c".as_slice(), b"x".as_slice())).collect();
        assert!(verify_batch(&pk, &items, &mut f.rng).is_err());
    }

    #[test]
    fn wire_sizes_match_the_declared_constants() {
        let mut f = fixture(2, 14);
        let cfg = no_escrow();
        let pres = present(&f.agent, &mut f.batch, b"c", b"x", &cfg, &mut f.rng).unwrap();
        assert_eq!(cert_bytes(&pres.cert).len(), PseudonymCert::SIZE);
        assert_eq!(pres.size_bytes(), PseudonymCert::SIZE + G2_COMPRESSED_LEN);
        assert_eq!(issuance_upload_bytes(10), 10 * CertRequest::SIZE);
        assert_eq!(issuance_download_bytes(10), 10 * PseudonymCert::SIZE);
    }

    #[test]
    fn derived_keys_are_reproducible_across_provisioning_runs() {
        let mut f = fixture(4, 15);
        let again = provision(&f.authority, &f.agent, Epoch(4), 4, &mut f.rng).unwrap();
        for (a, b) in f.batch.secrets.iter().zip(&again.secrets) {
            assert_eq!(a.0, b.0, "PRF derivation is not deterministic");
        }
    }
}
