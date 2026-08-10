//! Layer 3 — threshold identity escrow, variants E0/E1/E2.
//!
//! | Variant | What is attached | Sound? | Cost |
//! |---|---|---|---|
//! | `E0` | nothing | n/a — no accountability claimed | the floor |
//! | `E1` | ciphertext, unchecked | **no** | one encryption |
//! | `E2` | ciphertext + proof of correct encryption | yes | encryption + 3-equation Schnorr |
//!
//! The measured difference `E2 - E1` is the price of an escrow that actually
//! delivers accountable anonymity. Reporting it against the E1 floor rather
//! than against E0 isolates the cost of soundness from the cost of escrow.

use rapido_core::{dst, Error, Result};
use rapido_crypto::{elgamal, pedersen, relation, ser, Fr, G1Projective};

/// Which escrow variant a run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscrowMode {
    /// No escrow. Establishes the latency floor.
    E0,
    /// Ciphertext attached, well-formedness **not** checked.
    ///
    /// # This is insecure
    ///
    /// A malicious agent encrypts arbitrary bytes instead of its identity. The
    /// verifier accepts, because under E1 nothing about the ciphertext is ever
    /// checked. The agent then operates with full anonymity and **zero**
    /// accountability: when the escrow authorities later cooperate to
    /// de-anonymize it, they decrypt to a group element that resolves to no
    /// registered agent — or, if the attacker copied another agent's
    /// ciphertext, to an innocent third party who is then framed.
    ///
    /// E1 provides the appearance of accountable anonymity and none of the
    /// substance. It is implemented here **only** so that the cost of E2 can be
    /// measured against it as a floor. It must not be presented as a deployable
    /// configuration.
    E1,
    /// Ciphertext plus a proof that it encrypts the identity committed in the
    /// credential. This is the variant that delivers "Accountable Anonymity".
    E2,
}

impl EscrowMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            EscrowMode::E0 => "e0",
            EscrowMode::E1 => "e1",
            EscrowMode::E2 => "e2",
        }
    }

    /// Whether de-anonymization is guaranteed to name the right agent.
    pub fn is_sound(&self) -> bool {
        matches!(self, EscrowMode::E2)
    }

    /// Whether the variant claims to provide escrow at all.
    pub fn provides_escrow(&self) -> bool {
        !matches!(self, EscrowMode::E0)
    }
}

impl std::fmt::Display for EscrowMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a presentation carries for Layer 3.
#[derive(Debug, Clone)]
pub enum EscrowAttachment {
    None,
    /// E1: ciphertext with nothing binding it to the credential.
    Unproven(elgamal::Ciphertext),
    /// E2: ciphertext plus a **standalone** proof of correct encryption.
    ///
    /// Mode A uses this: the credential's identity lives in a Pedersen
    /// commitment inside the pseudonym certificate, so the escrow statement has
    /// to be proved on its own and travels as its own object.
    Proven {
        ct: elgamal::Ciphertext,
        proof: relation::LinearProof,
    },
    /// E2: ciphertext only — the proof is carried by the **enclosing
    /// presentation's** Schnorr proof.
    ///
    /// Mode B uses this: the identity is already a BBS+ attribute, so the
    /// escrow statement is proved as two extra equations under the
    /// presentation's single Fiat-Shamir challenge. The proof is genuinely
    /// shared, not duplicated — beyond the E0 presentation, only the ciphertext
    /// and one extra response scalar go on the wire.
    ///
    /// This variant exists so that the sharing is recorded in the type rather
    /// than in a comment: a variant that also held a proof would let
    /// [`EscrowAttachment::size_bytes`] count the same bytes twice and overstate
    /// the Mode B + E2 wire size.
    ProvenInPresentation(elgamal::Ciphertext),
}

impl EscrowAttachment {
    /// Bytes this attachment adds to the enclosing presentation.
    pub fn size_bytes(&self) -> usize {
        match self {
            EscrowAttachment::None => 0,
            EscrowAttachment::Unproven(_) => elgamal::Ciphertext::SIZE,
            EscrowAttachment::Proven { proof, .. } => {
                elgamal::Ciphertext::SIZE + proof.size_bytes()
            }
            // The proof lives in the enclosing presentation and is counted
            // there; counting it again here would double-count the same bytes.
            EscrowAttachment::ProvenInPresentation(_) => elgamal::Ciphertext::SIZE,
        }
    }

    pub fn ciphertext(&self) -> Option<&elgamal::Ciphertext> {
        match self {
            EscrowAttachment::None => None,
            EscrowAttachment::Unproven(ct) => Some(ct),
            EscrowAttachment::Proven { ct, .. } => Some(ct),
            EscrowAttachment::ProvenInPresentation(ct) => Some(ct),
        }
    }

    pub fn mode(&self) -> EscrowMode {
        match self {
            EscrowAttachment::None => EscrowMode::E0,
            EscrowAttachment::Unproven(_) => EscrowMode::E1,
            EscrowAttachment::Proven { .. } => EscrowMode::E2,
            EscrowAttachment::ProvenInPresentation(_) => EscrowMode::E2,
        }
    }
}

/// Escrow configuration shared by agents and verifiers.
#[derive(Debug, Clone)]
pub struct EscrowConfig {
    pub mode: EscrowMode,
    /// Escrow public key `Y`. Required for E1 and E2.
    pub escrow_public: Option<G1Projective>,
    pub pedersen: pedersen::Params,
}

impl EscrowConfig {
    pub fn new(
        mode: EscrowMode,
        escrow_public: Option<G1Projective>,
        pedersen: pedersen::Params,
    ) -> Self {
        EscrowConfig { mode, escrow_public, pedersen }
    }

    fn public(&self) -> Result<G1Projective> {
        self.escrow_public.ok_or_else(|| {
            Error::InvalidParameter("escrow: no escrow public key configured".into())
        })
    }

    /// Agent side: build the attachment for a presentation.
    ///
    /// `context` is bound into the E2 proof so the proof cannot be lifted onto
    /// a different session.
    pub fn attach<R: rand::Rng + ?Sized>(
        &self,
        identity: Fr,
        id_blinding: Fr,
        commitment: &pedersen::Commitment,
        context: &[u8],
        rng: &mut R,
    ) -> Result<EscrowAttachment> {
        match self.mode {
            EscrowMode::E0 => Ok(EscrowAttachment::None),
            EscrowMode::E1 => {
                let y = self.public()?;
                let (ct, _r) = elgamal::encrypt(y, elgamal::identity_point(identity), rng);
                Ok(EscrowAttachment::Unproven(ct))
            }
            EscrowMode::E2 => {
                let y = self.public()?;
                let (ct, r) = elgamal::encrypt(y, elgamal::identity_point(identity), rng);
                let proof = elgamal::prove_correct_encryption(
                    &self.pedersen,
                    y,
                    &ct,
                    commitment,
                    identity,
                    r,
                    id_blinding,
                    context,
                    rng,
                )?;
                Ok(EscrowAttachment::Proven { ct, proof })
            }
        }
    }

    /// Verifier side.
    ///
    /// Under E1 this is deliberately a no-op beyond a presence check — that
    /// absence *is* the vulnerability, and making it visible in the code is the
    /// point. Under E2 the ciphertext is checked against the credential's
    /// committed identity.
    pub fn check(
        &self,
        attachment: &EscrowAttachment,
        commitment: &pedersen::Commitment,
        context: &[u8],
    ) -> Result<()> {
        match (self.mode, attachment) {
            (EscrowMode::E0, EscrowAttachment::None) => Ok(()),
            (EscrowMode::E1, EscrowAttachment::Unproven(_)) => {
                // No check performed. See EscrowMode::E1.
                Ok(())
            }
            (EscrowMode::E2, EscrowAttachment::Proven { ct, proof }) => {
                elgamal::verify_correct_encryption(
                    &self.pedersen,
                    self.public()?,
                    ct,
                    commitment,
                    proof,
                    context,
                )
            }
            (expected, got) => Err(Error::BadEscrow(match (expected, got.mode()) {
                (EscrowMode::E2, EscrowMode::E1) => "expected a proven escrow, got an unproven one",
                (EscrowMode::E2, EscrowMode::E0) => "expected a proven escrow, got none",
                (EscrowMode::E1, EscrowMode::E0) => "expected an escrow ciphertext, got none",
                _ => "escrow attachment does not match the configured mode",
            })),
        }
    }
}

/// The escrow authorities, holding `(k, n)` shares of the escrow secret.
#[derive(Debug, Clone)]
pub struct EscrowAuthorities {
    pub key: elgamal::EscrowKey,
    pub registry: elgamal::Registry,
    pub audit: crate::audit::AuditLog,
}

impl EscrowAuthorities {
    pub fn generate<R: rand::Rng + ?Sized>(k: usize, n: usize, rng: &mut R) -> Result<Self> {
        Ok(EscrowAuthorities {
            key: elgamal::EscrowKey::generate(k, n, rng)?,
            registry: elgamal::Registry::new(),
            audit: crate::audit::AuditLog::new(),
        })
    }

    pub fn public(&self) -> G1Projective {
        self.key.public
    }

    /// Cooperate to open one ciphertext, verifying each authority's partial
    /// decryption and appending an audit entry. Returns the resolved agent
    /// identifier, or `None` if the ciphertext opens to an unregistered
    /// element — which is exactly what happens to an E1 ciphertext from a
    /// cheating agent.
    pub fn deanonymize<R: rand::Rng + ?Sized>(
        &mut self,
        ct: &elgamal::Ciphertext,
        authority_indices: &[usize],
        authorization_document: &[u8],
        timestamp_ns: u64,
        rng: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let k = self.key.k;
        if authority_indices.len() < k {
            return Err(Error::NotEnoughShares { need: k, got: authority_indices.len() });
        }
        let mut partials = Vec::with_capacity(k);
        for &j in &authority_indices[..k] {
            let share = *self
                .key
                .shares
                .get(j)
                .ok_or_else(|| Error::InvalidParameter(format!("no escrow authority {j}")))?;
            let partial = elgamal::partial_decrypt(&share, ct);
            let proof = elgamal::prove_partial_decryption(&share, ct, rng)?;
            elgamal::verify_partial_decryption(
                self.key.share_publics[j],
                ct,
                &partial,
                &proof,
                rng,
            )?;
            partials.push(partial);
        }
        let m = elgamal::combine_decryptions(&partials, ct, k)?;
        let resolved = self.registry.resolve(&m).map(|s| s.to_vec());

        self.audit.append(crate::audit::Event {
            timestamp_ns,
            authority_set: authority_indices[..k].iter().map(|i| *i as u32).collect(),
            authorization_hash: crate::audit::hash_document(authorization_document),
            ciphertext_hash: crate::audit::hash_document(&ct.to_bytes()),
            resolved: resolved.is_some(),
        });
        Ok(resolved)
    }
}

/// Domain-separated context string for an escrow proof, so a proof made for one
/// session cannot be replayed into another.
pub fn escrow_context(session_message: &[u8]) -> Vec<u8> {
    let mut t = rapido_core::Transcript::new(dst::ESCROW);
    t.push_bytes(session_message);
    t.finish()
}

/// Size on the wire of an E2 proof, for bandwidth accounting: three Schnorr
/// responses plus the challenge.
pub const E2_PROOF_SIZE: usize = ser::FR_LEN * (1 + elgamal::N_WITNESSES);

#[cfg(test)]
mod tests {
    use super::*;
    use rapido_crypto::rng_from_seed;

    fn setup(
        mode: EscrowMode,
        seed: u64,
    ) -> (EscrowConfig, EscrowAuthorities, Fr, Fr, pedersen::Commitment, rapido_crypto::Rng) {
        let mut rng = rng_from_seed(seed);
        let mut auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let ped = pedersen::Params::default();
        let id = auth.registry.enrol(b"agent-1");
        let (commitment, opening) = ped.commit_random(id, &mut rng);
        let cfg = EscrowConfig::new(mode, Some(auth.public()), ped);
        (cfg, auth, id, opening.blinding, commitment, rng)
    }

    #[test]
    fn e0_attaches_nothing() {
        let (cfg, _a, id, b, c, mut rng) = setup(EscrowMode::E0, 1);
        let att = cfg.attach(id, b, &c, b"ctx", &mut rng).unwrap();
        assert_eq!(att.size_bytes(), 0);
        assert!(cfg.check(&att, &c, b"ctx").is_ok());
    }

    #[test]
    fn e1_and_e2_round_trip_and_open_correctly() {
        for mode in [EscrowMode::E1, EscrowMode::E2] {
            let (cfg, mut auth, id, b, c, mut rng) = setup(mode, 2);
            let att = cfg.attach(id, b, &c, b"ctx", &mut rng).unwrap();
            assert!(cfg.check(&att, &c, b"ctx").is_ok(), "{mode} rejected an honest attachment");

            let ct = att.ciphertext().unwrap();
            let who = auth.deanonymize(ct, &[0, 1], b"warrant-42", 1_000, &mut rng).unwrap();
            assert_eq!(who.as_deref(), Some(b"agent-1".as_slice()));
            assert_eq!(auth.audit.len(), 1);
        }
    }

    #[test]
    fn e2_proof_is_bound_to_the_session() {
        let (cfg, _a, id, b, c, mut rng) = setup(EscrowMode::E2, 3);
        let att = cfg.attach(id, b, &c, b"session-1", &mut rng).unwrap();
        assert!(cfg.check(&att, &c, b"session-1").is_ok());
        assert!(cfg.check(&att, &c, b"session-2").is_err());
    }

    /// The headline security difference between the two escrow variants.
    #[test]
    fn e1_accepts_a_bogus_ciphertext_that_e2_rejects() {
        let mut rng = rng_from_seed(4);
        let mut auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let ped = pedersen::Params::default();
        let id = auth.registry.enrol(b"cheating-agent");
        let (commitment, _opening) = ped.commit_random(id, &mut rng);

        // The cheater encrypts garbage rather than its own identity.
        let (bogus, _r) = rapido_crypto::elgamal::encrypt(
            auth.public(),
            rapido_crypto::elgamal::identity_point(rapido_crypto::elgamal::identity_scalar(
                b"garbage",
            )),
            &mut rng,
        );

        // E1 accepts it...
        let e1 = EscrowConfig::new(EscrowMode::E1, Some(auth.public()), ped);
        let att = EscrowAttachment::Unproven(bogus);
        assert!(
            e1.check(&att, &commitment, b"ctx").is_ok(),
            "E1 performs no check, so it must accept this"
        );

        // ...and de-anonymization then names nobody: accountability is gone.
        let who = auth.deanonymize(&bogus, &[0, 1], b"warrant", 1, &mut rng).unwrap();
        assert_eq!(who, None);

        // E2 cannot even be satisfied: there is no attachment a cheater can
        // build that passes, so the verifier rejects the presentation outright.
        let e2 = EscrowConfig::new(EscrowMode::E2, Some(auth.public()), ped);
        assert!(e2.check(&att, &commitment, b"ctx").is_err());
    }

    #[test]
    fn e2_rejects_a_ciphertext_swapped_from_another_agent() {
        let mut rng = rng_from_seed(5);
        let mut auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let ped = pedersen::Params::default();
        let victim = auth.registry.enrol(b"victim");
        let attacker = auth.registry.enrol(b"attacker");
        let (attacker_commitment, opening) = ped.commit_random(attacker, &mut rng);
        let cfg = EscrowConfig::new(EscrowMode::E2, Some(auth.public()), ped);

        // The attacker copies a ciphertext encrypting the victim's identity and
        // tries to pass it off with its own credential.
        let (victims_ct, _) = rapido_crypto::elgamal::encrypt(
            auth.public(),
            rapido_crypto::elgamal::identity_point(victim),
            &mut rng,
        );
        let honest =
            cfg.attach(attacker, opening.blinding, &attacker_commitment, b"ctx", &mut rng).unwrap();
        let EscrowAttachment::Proven { proof, .. } = honest else { unreachable!() };
        let forged = EscrowAttachment::Proven { ct: victims_ct, proof };
        assert!(cfg.check(&forged, &attacker_commitment, b"ctx").is_err());
    }

    #[test]
    fn mode_mismatch_is_rejected() {
        let (cfg_e2, _a, id, b, c, mut rng) = setup(EscrowMode::E2, 6);
        let cfg_e1 = EscrowConfig::new(EscrowMode::E1, cfg_e2.escrow_public, cfg_e2.pedersen);
        let e1_att = cfg_e1.attach(id, b, &c, b"ctx", &mut rng).unwrap();
        // A verifier configured for E2 must not accept a bare ciphertext.
        assert!(cfg_e2.check(&e1_att, &c, b"ctx").is_err());
        assert!(cfg_e2.check(&EscrowAttachment::None, &c, b"ctx").is_err());
    }

    #[test]
    fn deanonymization_needs_k_authorities() {
        let (cfg, mut auth, id, b, c, mut rng) = setup(EscrowMode::E2, 7);
        let att = cfg.attach(id, b, &c, b"ctx", &mut rng).unwrap();
        let ct = att.ciphertext().unwrap();
        assert!(auth.deanonymize(ct, &[0], b"w", 1, &mut rng).is_err());
        assert!(auth.deanonymize(ct, &[0, 2], b"w", 1, &mut rng).is_ok());
    }

    #[test]
    fn attachment_sizes_are_as_declared() {
        let (cfg, _a, id, b, c, mut rng) = setup(EscrowMode::E2, 8);
        let att = cfg.attach(id, b, &c, b"ctx", &mut rng).unwrap();
        assert_eq!(att.size_bytes(), rapido_crypto::elgamal::Ciphertext::SIZE + E2_PROOF_SIZE);
    }

    #[test]
    fn e1_and_e2_without_an_escrow_key_fail_rather_than_silently_skip() {
        let ped = pedersen::Params::default();
        let mut rng = rng_from_seed(9);
        let (c, o) = ped.commit_random(Fr::from(3u64), &mut rng);
        for mode in [EscrowMode::E1, EscrowMode::E2] {
            let cfg = EscrowConfig::new(mode, None, ped);
            assert!(cfg.attach(Fr::from(3u64), o.blinding, &c, b"x", &mut rng).is_err());
        }
    }
}
