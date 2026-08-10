//! Mode B — BBS+ credential presentation.
//!
//! An agent holds one BBS+ credential over `L` attributes and presents a
//! re-randomized signature plus a proof of knowledge, disclosing a chosen
//! subset. Unlike Mode A there is no per-session artifact the issuer signed, so
//! **the issuer cannot link sessions** — that is the whole point of the mode.
//! What it costs relative to Mode A is measured rather than assumed.
//!
//! ## Attribute layout
//!
//! Two slots are reserved so the rest of the system can bind to them:
//!
//! | index | meaning | disclosure |
//! |---|---|---|
//! | 0 | escrow identity scalar | **always hidden** |
//! | 1 | epoch | **always disclosed** (needed for the R0 check) |
//! | 2.. | application attributes | selectively disclosed |
//!
//! Disclosing the epoch leaks nothing: every agent in an epoch carries the same
//! value.
//!
//! ## Escrow binding is cheaper here than in Mode A
//!
//! The identity is already a BBS+ attribute, so the E2 escrow proof reuses the
//! presentation's own witness for it. Mode A has to carry a separate Pedersen
//! commitment and prove an extra equation about it; Mode B needs only two
//! equations and one extra response scalar. See [`escrow_extension`].
//!
//! ## Threshold issuance
//!
//! Mode B issues from a **single** authority. Threshold BBS+ requires
//! distributed inversion of the shared secret, which is an interactive
//! multiparty protocol and out of scope here. This is recorded in
//! `LIMITATIONS.md`; any issuance-cost comparison against Mode A, which does
//! issue from a real `(k, n)` threshold, must state the asymmetry.

use crate::escrow::{EscrowAttachment, EscrowConfig, EscrowMode};
use rapido_core::{Epoch, Error, Result, Transcript};
use rapido_crypto::{
    bbs, elgamal, relation,
    ser::{self, FR_LEN},
    Fr, G1Projective,
};
use std::collections::{BTreeMap, BTreeSet};

/// Attribute slot holding the escrow identity scalar. Never disclosed.
pub const ATTR_IDENTITY: usize = 0;
/// Attribute slot holding the epoch. Always disclosed.
pub const ATTR_EPOCH: usize = 1;
/// First application-defined attribute slot.
pub const ATTR_FIRST_APP: usize = 2;
/// Smallest credential that still has both reserved slots.
pub const MIN_ATTRIBUTES: usize = 2;

/// The issuing authority for Mode B.
#[derive(Debug, Clone)]
pub struct Issuer {
    pub params: bbs::Params,
    pub sk: bbs::SecretKey,
    pub pk: bbs::PublicKey,
}

impl Issuer {
    pub fn generate<R: rand::Rng + ?Sized>(l: usize, rng: &mut R) -> Result<Self> {
        if l < MIN_ATTRIBUTES {
            return Err(Error::InvalidParameter(format!(
                "mode B: need at least {MIN_ATTRIBUTES} attributes, got {l}"
            )));
        }
        let sk = bbs::SecretKey::random(rng);
        Ok(Issuer { params: bbs::Params::new(l), pk: sk.public(), sk })
    }

    pub fn l(&self) -> usize {
        self.params.l
    }
}

/// An issued credential and the attribute vector it covers.
#[derive(Debug, Clone)]
pub struct Credential {
    pub sig: bbs::Signature,
    pub msgs: Vec<Fr>,
    pub epoch: Epoch,
}

impl Credential {
    /// Bytes an agent stores per credential, versus Mode A's whole batch.
    pub fn stored_bytes(&self) -> usize {
        bbs::Signature::SIZE + self.msgs.len() * FR_LEN
    }
}

/// Build an attribute vector with the reserved slots filled in.
pub fn attributes(l: usize, identity: Fr, epoch: Epoch, app_attributes: &[Fr]) -> Result<Vec<Fr>> {
    if l < MIN_ATTRIBUTES {
        return Err(Error::InvalidParameter("mode B: attribute count too small".into()));
    }
    if app_attributes.len() > l - ATTR_FIRST_APP {
        return Err(Error::InvalidParameter(format!(
            "mode B: {} application attributes do not fit in L={l}",
            app_attributes.len()
        )));
    }
    let mut msgs = vec![Fr::from(0u64); l];
    msgs[ATTR_IDENTITY] = identity;
    msgs[ATTR_EPOCH] = Fr::from(epoch.index());
    for (i, a) in app_attributes.iter().enumerate() {
        msgs[ATTR_FIRST_APP + i] = *a;
    }
    Ok(msgs)
}

/// Issue a credential for `epoch`.
pub fn issue<R: rand::Rng + ?Sized>(
    issuer: &Issuer,
    identity: Fr,
    epoch: Epoch,
    app_attributes: &[Fr],
    rng: &mut R,
) -> Result<Credential> {
    let msgs = attributes(issuer.l(), identity, epoch, app_attributes)?;
    let sig = bbs::sign(&issuer.params, &issuer.sk, &msgs, rng)?;
    Ok(Credential { sig, msgs, epoch })
}

/// A Mode B presentation.
#[derive(Debug, Clone)]
pub struct Presentation {
    pub bbs: bbs::Presentation,
    pub escrow: EscrowAttachment,
    pub epoch: Epoch,
}

impl Presentation {
    pub fn size_bytes(&self) -> usize {
        self.bbs.size_bytes() + 8 + self.escrow.size_bytes()
    }

    /// Number of attributes the verifier learns, excluding the epoch.
    pub fn disclosed_attribute_count(&self) -> usize {
        self.bbs.disclosed.keys().filter(|i| **i != ATTR_EPOCH).count()
    }
}

/// The nonce a Mode B proof is bound to: verifier challenge, context, epoch.
pub fn presentation_nonce(challenge: &[u8], context: &[u8], epoch: Epoch) -> Vec<u8> {
    let mut t = Transcript::new(rapido_core::dst::BBS_CHALLENGE);
    t.push_bytes(challenge);
    t.push_bytes(context);
    t.push_u64(epoch.index());
    t.finish()
}

/// Normalize a requested disclosure set: force the epoch in, force the identity
/// out. Disclosing the identity would defeat the entire construction, so it is
/// rejected rather than silently dropped.
pub fn normalize_disclosure(requested: &BTreeSet<usize>, l: usize) -> Result<BTreeSet<usize>> {
    if requested.contains(&ATTR_IDENTITY) {
        return Err(Error::BadDisclosure(
            "the escrow identity attribute must never be disclosed".into(),
        ));
    }
    if let Some(bad) = requested.iter().find(|i| **i >= l) {
        return Err(Error::BadDisclosure(format!("attribute index {bad} out of range")));
    }
    let mut d = requested.clone();
    d.insert(ATTR_EPOCH);
    Ok(d)
}

/// Escrow equations that share the BBS+ identity witness (E2, Mode B).
///
/// ```text
/// R = r·G              (witness r)
/// C = id·G + r·Y       (witness id — the *same* index the BBS+ proof uses)
/// ```
///
/// Proved under the presentation's single Fiat-Shamir challenge, so a
/// verifying proof establishes that the ciphertext encrypts the identity inside
/// the credential without revealing it.
pub fn escrow_extension(
    ct: &elgamal::Ciphertext,
    escrow_public: G1Projective,
    w_identity: usize,
    w_randomness: usize,
) -> Vec<relation::Equation> {
    let g = <G1Projective as ark_ec::PrimeGroup>::generator();
    vec![
        relation::Equation::new(ct.r_point, vec![(w_randomness, g)]),
        relation::Equation::new(ct.c, vec![(w_identity, g), (w_randomness, escrow_public)]),
    ]
}

/// Produce a presentation.
#[allow(clippy::too_many_arguments)] // mirrors `bbs::present`, plus the escrow config
pub fn present<R: rand::Rng + ?Sized>(
    issuer_params: &bbs::Params,
    issuer_pk: &bbs::PublicKey,
    cred: &Credential,
    disclose: &BTreeSet<usize>,
    challenge: &[u8],
    context: &[u8],
    escrow: &EscrowConfig,
    rng: &mut R,
) -> Result<Presentation> {
    let l = issuer_params.l;
    let disclosed = normalize_disclosure(disclose, l)?;
    let nonce = presentation_nonce(challenge, context, cred.epoch);
    let layout = bbs::witness_layout(l, &disclosed);
    let w_id = *layout
        .message
        .get(&ATTR_IDENTITY)
        .ok_or_else(|| Error::BadDisclosure("identity attribute is not hidden".into()))?;

    let (extension, attachment) = match escrow.mode {
        EscrowMode::E0 => (None, EscrowAttachment::None),
        EscrowMode::E1 => {
            let y = escrow.escrow_public.ok_or_else(|| {
                Error::InvalidParameter("escrow: no escrow public key configured".into())
            })?;
            let (ct, _r) =
                elgamal::encrypt(y, elgamal::identity_point(cred.msgs[ATTR_IDENTITY]), rng);
            (None, EscrowAttachment::Unproven(ct))
        }
        EscrowMode::E2 => {
            let y = escrow.escrow_public.ok_or_else(|| {
                Error::InvalidParameter("escrow: no escrow public key configured".into())
            })?;
            let (ct, r) =
                elgamal::encrypt(y, elgamal::identity_point(cred.msgs[ATTR_IDENTITY]), rng);
            let equations = escrow_extension(&ct, y, w_id, layout.n_bbs);
            (
                Some(bbs::ProofExtension { extra_witnesses: vec![r], equations }),
                // The proof is filled in below, once the presentation exists.
                EscrowAttachment::Unproven(ct),
            )
        }
    };

    let pres = bbs::present(
        issuer_params,
        issuer_pk,
        &cred.msgs,
        &cred.sig,
        &disclosed,
        &nonce,
        extension.as_ref(),
        rng,
    )?;

    // Under E2 the escrow proof *is* the presentation's Schnorr proof, so only
    // the ciphertext travels separately. `ProvenInPresentation` records that
    // sharing in the type; verification re-derives the shared statement.
    let escrow_attachment = match (escrow.mode, attachment) {
        (EscrowMode::E2, EscrowAttachment::Unproven(ct)) => {
            EscrowAttachment::ProvenInPresentation(ct)
        }
        (_, other) => other,
    };

    Ok(Presentation { bbs: pres, escrow: escrow_attachment, epoch: cred.epoch })
}

/// Verify a presentation. Returns the disclosed attributes.
pub fn verify(
    issuer_params: &bbs::Params,
    issuer_pk: &bbs::PublicKey,
    pres: &Presentation,
    challenge: &[u8],
    context: &[u8],
    escrow: &EscrowConfig,
) -> Result<BTreeMap<usize, Fr>> {
    let l = issuer_params.l;
    if pres.bbs.disclosed.contains_key(&ATTR_IDENTITY) {
        return Err(Error::BadDisclosure("identity attribute was disclosed".into()));
    }
    // The epoch must be disclosed, and the epoch attribute *inside the
    // credential* must equal the one the presentation claims. Without this the
    // downstream R0 check would be validating an unbound field: an agent could
    // relabel an expired credential simply by changing `pres.epoch`.
    let credential_epoch = pres
        .bbs
        .disclosed
        .get(&ATTR_EPOCH)
        .ok_or_else(|| Error::BadDisclosure("epoch attribute was not disclosed".into()))?;
    if *credential_epoch != Fr::from(pres.epoch.index()) {
        // `got` is what the presentation claims; the credential's own value is
        // a field element with no faithful u64 form, so it is described rather
        // than printed.
        return Err(Error::BadDisclosure(format!(
            "presentation claims epoch {} but the credential's epoch attribute differs",
            pres.epoch.index()
        )));
    }

    let disclosed_set: BTreeSet<usize> = pres.bbs.disclosed.keys().copied().collect();
    let layout = bbs::witness_layout(l, &disclosed_set);
    let w_id = *layout
        .message
        .get(&ATTR_IDENTITY)
        .ok_or_else(|| Error::BadDisclosure("identity attribute is not hidden".into()))?;

    let statement = match (escrow.mode, &pres.escrow) {
        (EscrowMode::E0, EscrowAttachment::None) => None,
        (EscrowMode::E1, EscrowAttachment::Unproven(_)) => {
            // Nothing is checked. See `EscrowMode::E1`.
            None
        }
        (EscrowMode::E2, EscrowAttachment::ProvenInPresentation(ct)) => {
            let y = escrow.escrow_public.ok_or_else(|| {
                Error::InvalidParameter("escrow: no escrow public key configured".into())
            })?;
            Some(bbs::ExtensionStatement {
                n_extra_witnesses: 1,
                equations: escrow_extension(ct, y, w_id, layout.n_bbs),
            })
        }
        _ => return Err(Error::BadEscrow("escrow attachment does not match the configured mode")),
    };

    let nonce = presentation_nonce(challenge, context, pres.epoch);
    bbs::verify_presentation(issuer_params, issuer_pk, &pres.bbs, &nonce, statement.as_ref())
}

/// Bytes an agent downloads per epoch: one credential, not a batch.
pub fn issuance_download_bytes(l: usize) -> usize {
    bbs::Signature::SIZE + l * ser::FR_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::EscrowAuthorities;
    use rapido_crypto::{pedersen, rng_from_seed};

    struct Fx {
        issuer: Issuer,
        cred: Credential,
        auth: EscrowAuthorities,
        rng: rapido_crypto::Rng,
    }

    fn fixture(l: usize, seed: u64) -> Fx {
        let mut rng = rng_from_seed(seed);
        let issuer = Issuer::generate(l, &mut rng).unwrap();
        let mut auth = EscrowAuthorities::generate(2, 3, &mut rng).unwrap();
        let id = auth.registry.enrol(b"agent-b");
        let app: Vec<Fr> = (0..l - ATTR_FIRST_APP)
            .map(|i| bbs::message_from_bytes(format!("app-attr-{i}").as_bytes()))
            .collect();
        let cred = issue(&issuer, id, Epoch(3), &app, &mut rng).unwrap();
        Fx { issuer, cred, auth, rng }
    }

    fn cfg(mode: EscrowMode, auth: &EscrowAuthorities) -> EscrowConfig {
        EscrowConfig::new(mode, Some(auth.public()), pedersen::Params::default())
    }

    #[test]
    fn issue_present_verify_round_trip() {
        for l in [4usize, 8, 16] {
            let mut f = fixture(l, 100 + l as u64);
            let c = cfg(EscrowMode::E0, &f.auth);
            let disclose = BTreeSet::from([ATTR_FIRST_APP]);
            let p = present(
                &f.issuer.params,
                &f.issuer.pk,
                &f.cred,
                &disclose,
                b"chal",
                b"rsu",
                &c,
                &mut f.rng,
            )
            .unwrap();
            let got = verify(&f.issuer.params, &f.issuer.pk, &p, b"chal", b"rsu", &c).unwrap();
            assert!(got.contains_key(&ATTR_EPOCH), "L={l}");
            assert_eq!(got[&ATTR_FIRST_APP], f.cred.msgs[ATTR_FIRST_APP]);
            assert!(!got.contains_key(&ATTR_IDENTITY));
        }
    }

    #[test]
    fn identity_can_never_be_disclosed() {
        let mut f = fixture(8, 1);
        let c = cfg(EscrowMode::E0, &f.auth);
        let disclose = BTreeSet::from([ATTR_IDENTITY]);
        assert!(matches!(
            present(&f.issuer.params, &f.issuer.pk, &f.cred, &disclose, b"c", b"x", &c, &mut f.rng),
            Err(Error::BadDisclosure(_))
        ));
    }

    #[test]
    fn presentation_is_bound_to_challenge_context_and_epoch() {
        let mut f = fixture(8, 2);
        let c = cfg(EscrowMode::E0, &f.auth);
        let d = BTreeSet::new();
        let p =
            present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c1", b"rsu-a", &c, &mut f.rng)
                .unwrap();
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c1", b"rsu-a", &c).is_ok());
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c2", b"rsu-a", &c).is_err());
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c1", b"rsu-b", &c).is_err());

        let mut wrong_epoch = p.clone();
        wrong_epoch.epoch = Epoch(9);
        assert!(verify(&f.issuer.params, &f.issuer.pk, &wrong_epoch, b"c1", b"rsu-a", &c).is_err());
    }

    #[test]
    fn a_credential_from_another_issuer_is_rejected() {
        let mut f = fixture(8, 3);
        let c = cfg(EscrowMode::E0, &f.auth);
        let other = Issuer::generate(8, &mut f.rng).unwrap();
        let d = BTreeSet::new();
        let p = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &c, &mut f.rng)
            .unwrap();
        assert!(verify(&other.params, &other.pk, &p, b"c", b"x", &c).is_err());
    }

    #[test]
    fn e2_binds_the_ciphertext_to_the_hidden_identity() {
        let mut f = fixture(8, 4);
        let c = cfg(EscrowMode::E2, &f.auth);
        let d = BTreeSet::from([ATTR_FIRST_APP]);
        let p = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &c, &mut f.rng)
            .unwrap();
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c", b"x", &c).is_ok());

        // Opening it must name the right agent.
        let ct = *p.escrow.ciphertext().unwrap();
        let who = f.auth.deanonymize(&ct, &[0, 1], b"warrant", 1, &mut f.rng).unwrap();
        assert_eq!(who.as_deref(), Some(b"agent-b".as_slice()));
    }

    #[test]
    fn e2_rejects_a_substituted_ciphertext() {
        let mut f = fixture(8, 5);
        let c = cfg(EscrowMode::E2, &f.auth);
        let d = BTreeSet::new();
        let mut p =
            present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &c, &mut f.rng)
                .unwrap();

        let (other_ct, _) = elgamal::encrypt(
            f.auth.public(),
            elgamal::identity_point(elgamal::identity_scalar(b"someone-else")),
            &mut f.rng,
        );
        p.escrow = EscrowAttachment::ProvenInPresentation(other_ct);
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c", b"x", &c).is_err());
    }

    /// The security gap E2 closes, in Mode B.
    #[test]
    fn e1_accepts_a_ciphertext_that_opens_to_nobody() {
        let mut f = fixture(8, 6);
        let c = cfg(EscrowMode::E1, &f.auth);
        let d = BTreeSet::new();
        let mut p =
            present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &c, &mut f.rng)
                .unwrap();

        let (garbage, _) = elgamal::encrypt(
            f.auth.public(),
            elgamal::identity_point(elgamal::identity_scalar(b"untraceable")),
            &mut f.rng,
        );
        p.escrow = EscrowAttachment::Unproven(garbage);
        assert!(
            verify(&f.issuer.params, &f.issuer.pk, &p, b"c", b"x", &c).is_ok(),
            "E1 checks nothing, so it accepts a substituted ciphertext"
        );
        let who = f.auth.deanonymize(&garbage, &[0, 1], b"warrant", 1, &mut f.rng).unwrap();
        assert_eq!(who, None, "and de-anonymization names nobody");
    }

    #[test]
    fn escrow_mode_mismatch_is_rejected() {
        let mut f = fixture(8, 7);
        let e0 = cfg(EscrowMode::E0, &f.auth);
        let e2 = cfg(EscrowMode::E2, &f.auth);
        let d = BTreeSet::new();
        let p = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &e0, &mut f.rng)
            .unwrap();
        assert!(verify(&f.issuer.params, &f.issuer.pk, &p, b"c", b"x", &e2).is_err());
    }

    #[test]
    fn issuer_cannot_link_two_presentations() {
        // Everything the issuer holds is (pk, the attribute values it signed).
        // Neither appears in a presentation except for the attributes the agent
        // chose to disclose, which are shared by every agent with those values.
        let mut f = fixture(8, 8);
        let c = cfg(EscrowMode::E0, &f.auth);
        let d = BTreeSet::new();
        let p1 = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c1", b"x", &c, &mut f.rng)
            .unwrap();
        let p2 = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c2", b"x", &c, &mut f.rng)
            .unwrap();
        assert_ne!(p1.bbs.a_prime, p2.bbs.a_prime);
        assert_ne!(p1.bbs.a_bar, p2.bbs.a_bar);
        assert_ne!(p1.bbs.d, p2.bbs.d);
        // And the credential's own signature element never appears on the wire.
        assert_ne!(p1.bbs.a_prime, f.cred.sig.a);
        assert_ne!(p2.bbs.a_prime, f.cred.sig.a);
    }

    #[test]
    fn selective_disclosure_reveals_only_the_chosen_attributes() {
        // The motivating example for selective disclosure: prove
        // emergency-vehicle status without revealing anything else.
        let mut f = fixture(16, 9);
        let c = cfg(EscrowMode::E0, &f.auth);
        let d = BTreeSet::from([ATTR_FIRST_APP]);
        let p = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &c, &mut f.rng)
            .unwrap();
        let got = verify(&f.issuer.params, &f.issuer.pk, &p, b"c", b"x", &c).unwrap();
        assert_eq!(got.len(), 2, "epoch + one application attribute");
        assert_eq!(p.disclosed_attribute_count(), 1);
    }

    #[test]
    fn e2_costs_one_extra_response_scalar_over_e0() {
        let mut f = fixture(8, 10);
        let d = BTreeSet::new();
        let e0 = cfg(EscrowMode::E0, &f.auth);
        let e2 = cfg(EscrowMode::E2, &f.auth);
        let p0 = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &e0, &mut f.rng)
            .unwrap();
        let p2 = present(&f.issuer.params, &f.issuer.pk, &f.cred, &d, b"c", b"x", &e2, &mut f.rng)
            .unwrap();
        assert_eq!(p2.bbs.proof.responses.len(), p0.bbs.proof.responses.len() + 1);
    }

    #[test]
    fn attribute_layout_is_enforced() {
        let mut rng = rng_from_seed(11);
        assert!(Issuer::generate(1, &mut rng).is_err());
        assert!(attributes(4, Fr::from(1u64), Epoch(0), &[Fr::from(2u64); 5]).is_err());
        let a = attributes(4, Fr::from(7u64), Epoch(9), &[]).unwrap();
        assert_eq!(a[ATTR_IDENTITY], Fr::from(7u64));
        assert_eq!(a[ATTR_EPOCH], Fr::from(9u64));
    }
}
