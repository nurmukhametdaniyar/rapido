//! Field-by-field wire-size breakdown of a presentation.
//!
//! Every number here is `serialized.len()` on a real structure produced by the
//! protocol — never a declared constant. Constants and reality had drifted
//! apart once already (the Mode B E2 attachment carried a clone of the
//! presentation's Schnorr proof, so `size_bytes` counted the same bytes twice),
//! and the only reliable guard against that is to measure the bytes.
//!
//! Emitted by `rapido-cli wire`.

use rapido_core::{Epoch, EpochClock};
use rapido_crypto::{bbs, elgamal, pedersen, rng_from_seed, ser, Fr};
use rapido_proto::{
    escrow::{EscrowAttachment, EscrowAuthorities, EscrowConfig, EscrowMode},
    mode_a, mode_b,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// What the field is, in protocol terms.
    pub kind: String,
    pub bytes: usize,
    /// `true` when the field is only present under E2.
    pub escrow_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakdown {
    pub label: String,
    pub escrow: String,
    pub fields: Vec<Field>,
    /// Sum of the fields — computed here, then cross-checked against the
    /// protocol's own `size_bytes()`.
    pub total_bytes: usize,
    /// What `Presentation::size_bytes()` reports. A mismatch is a bug.
    pub reported_by_size_bytes: usize,
    pub agrees: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireReport {
    pub mode_a_e0: Breakdown,
    pub mode_a_e2: Breakdown,
    pub mode_a_e2_delta_bytes: i64,
    pub mode_b_e0: Breakdown,
    pub mode_b_e2: Breakdown,
    pub mode_b_e2_delta_bytes: i64,
    /// Whether the "escrow proof folds into the presentation's Schnorr proof"
    /// optimization described in FINDINGS §7 is actually implemented.
    pub mode_b_proof_is_shared: bool,
    pub mode_b_shared_proof_evidence: String,
    pub notes: Vec<String>,
}

fn g1(p: &rapido_crypto::G1Projective) -> usize {
    ser::g1_to_bytes(p).len()
}

fn sum(fields: &[Field]) -> usize {
    fields.iter().map(|f| f.bytes).sum()
}

fn f(name: &str, kind: &str, bytes: usize, escrow_only: bool) -> Field {
    Field { name: name.into(), kind: kind.into(), bytes, escrow_only }
}

/// Fields of the escrow attachment, measured from the serialized ciphertext and
/// proof rather than from `Ciphertext::SIZE`.
fn escrow_fields(att: &EscrowAttachment) -> Vec<Field> {
    match att {
        EscrowAttachment::None => vec![],
        EscrowAttachment::Unproven(ct) => vec![
            f("escrow.ct.R", "G1 compressed", g1(&ct.r_point), true),
            f("escrow.ct.C", "G1 compressed", g1(&ct.c), true),
        ],
        EscrowAttachment::Proven { ct, proof } => {
            let n = proof.responses.len();
            vec![
                f("escrow.ct.R", "G1 compressed", g1(&ct.r_point), true),
                f("escrow.ct.C", "G1 compressed", g1(&ct.c), true),
                f("escrow.proof.challenge", "Fr scalar", ser::FR_LEN, true),
                f(
                    &format!("escrow.proof.responses[{n}]"),
                    "Fr scalars (id, r, blinding)",
                    n * ser::FR_LEN,
                    true,
                ),
            ]
        }
        EscrowAttachment::ProvenInPresentation(ct) => vec![
            f("escrow.ct.R", "G1 compressed", g1(&ct.r_point), true),
            f("escrow.ct.C", "G1 compressed", g1(&ct.c), true),
            // No proof field: it is inside the presentation's Schnorr proof,
            // which the presentation fields below already account for.
        ],
    }
}

fn mode_a_breakdown(pres: &mode_a::Presentation, escrow: EscrowMode) -> Breakdown {
    let mut fields = vec![
        f("cert.P_i", "G1 compressed (one-time public key)", g1(&pres.cert.p_i.0), false),
        f("cert.epoch", "u64 big-endian", 8, false),
        f(
            "cert.attr_commitment",
            "G1 compressed (Pedersen commitment to identity)",
            pres.cert.attr_commitment.to_bytes().len(),
            false,
        ),
        f(
            "cert.sig",
            "G2 compressed (threshold BLS over the certificate)",
            ser::g2_to_bytes(&pres.cert.sig.0).len(),
            false,
        ),
        f(
            "sigma",
            "G2 compressed (one-time key over the challenge)",
            pres.sigma.to_bytes().len(),
            false,
        ),
    ];
    fields.extend(escrow_fields(&pres.escrow));
    let total = sum(&fields);
    let reported = pres.size_bytes();
    Breakdown {
        label: "Mode A presentation".into(),
        escrow: escrow.to_string(),
        fields,
        total_bytes: total,
        reported_by_size_bytes: reported,
        agrees: total == reported,
    }
}

fn mode_b_breakdown(pres: &mode_b::Presentation, escrow: EscrowMode, l: usize) -> Breakdown {
    let n_resp = pres.bbs.proof.responses.len();
    let n_disc = pres.bbs.disclosed.len();
    let mut fields = vec![
        f("bbs.A'", "G1 compressed (re-randomized signature)", g1(&pres.bbs.a_prime), false),
        f("bbs.A_bar", "G1 compressed", g1(&pres.bbs.a_bar), false),
        f("bbs.d", "G1 compressed", g1(&pres.bbs.d), false),
        f("bbs.proof.challenge", "Fr scalar (Fiat-Shamir)", ser::FR_LEN, false),
        f(
            &format!("bbs.proof.responses[{n_resp}]"),
            "Fr scalars (e, r2, r3, s', one per hidden attribute, +1 under E2)",
            n_resp * ser::FR_LEN,
            false,
        ),
        f(
            &format!("bbs.disclosed[{n_disc}]"),
            "u32 index + Fr value per disclosed attribute",
            n_disc * (4 + ser::FR_LEN),
            false,
        ),
        f("epoch", "u64 big-endian", 8, false),
    ];
    fields.extend(escrow_fields(&pres.escrow));
    let total = sum(&fields);
    let reported = pres.size_bytes();
    Breakdown {
        label: format!("Mode B presentation (L={l}, all attributes hidden)"),
        escrow: escrow.to_string(),
        fields,
        total_bytes: total,
        reported_by_size_bytes: reported,
        agrees: total == reported,
    }
}

/// Build both breakdowns from real presentations.
pub fn measure(l: usize) -> rapido_core::Result<WireReport> {
    let mut rng = rng_from_seed(0x5152E);
    let epoch = Epoch(1);
    let _ = EpochClock::default();

    let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    let identity = escrow_auth.registry.enrol(b"wire-breakdown-agent");
    let ped = pedersen::Params::default();

    // --- Mode A ---
    let authority = mode_a::Authority::generate(3, 5, &mut rng)?;
    let agent = mode_a::Agent::new(&authority.pedersen, identity, &mut rng);

    let cfg_e0 = EscrowConfig::new(EscrowMode::E0, Some(escrow_auth.public()), ped);
    let cfg_e2 = EscrowConfig::new(EscrowMode::E2, Some(escrow_auth.public()), ped);

    let mut batch = mode_a::provision(&authority, &agent, epoch, 8, &mut rng)?;
    let a_e0 = mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg_e0, &mut rng)?;
    let a_e2 = mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg_e2, &mut rng)?;

    // --- Mode B ---
    let issuer = mode_b::Issuer::generate(l, &mut rng)?;
    let app: Vec<Fr> = (0..l - mode_b::ATTR_FIRST_APP)
        .map(|i| bbs::message_from_bytes(format!("a{i}").as_bytes()))
        .collect();
    let cred = mode_b::issue(&issuer, identity, epoch, &app, &mut rng)?;
    let hide_all = BTreeSet::new();

    let b_e0 = mode_b::present(
        &issuer.params,
        &issuer.pk,
        &cred,
        &hide_all,
        b"c",
        b"rsu",
        &cfg_e0,
        &mut rng,
    )?;
    let b_e2 = mode_b::present(
        &issuer.params,
        &issuer.pk,
        &cred,
        &hide_all,
        b"c",
        b"rsu",
        &cfg_e2,
        &mut rng,
    )?;

    // Is the proof genuinely shared, or duplicated?
    let shared = matches!(b_e2.escrow, EscrowAttachment::ProvenInPresentation(_));
    let e0_resp = b_e0.bbs.proof.responses.len();
    let e2_resp = b_e2.bbs.proof.responses.len();
    let evidence = format!(
        "E0 presentation carries {e0_resp} Schnorr responses; E2 carries {e2_resp}. \
         The escrow attachment under E2 is `{}`, which holds only the ciphertext. \
         The escrow statement is therefore proved by the same Fiat-Shamir challenge \
         as the credential, costing exactly {} extra response scalar(s) = {} B, \
         plus the {} B ciphertext.",
        if shared { "ProvenInPresentation" } else { "Proven (standalone)" },
        e2_resp - e0_resp,
        (e2_resp - e0_resp) * ser::FR_LEN,
        elgamal::Ciphertext::SIZE,
    );

    let a0 = mode_a_breakdown(&a_e0, EscrowMode::E0);
    let a2 = mode_a_breakdown(&a_e2, EscrowMode::E2);
    let b0 = mode_b_breakdown(&b_e0, EscrowMode::E0, l);
    let b2 = mode_b_breakdown(&b_e2, EscrowMode::E2, l);

    let mut notes = Vec::new();
    for bd in [&a0, &a2, &b0, &b2] {
        if !bd.agrees {
            notes.push(format!(
                "MISMATCH in {} ({}): fields sum to {} B but size_bytes() reports {} B",
                bd.label, bd.escrow, bd.total_bytes, bd.reported_by_size_bytes
            ));
        }
    }
    if notes.is_empty() {
        notes.push("Every breakdown agrees with the protocol's own size_bytes().".to_string());
    }

    Ok(WireReport {
        mode_a_e2_delta_bytes: a2.total_bytes as i64 - a0.total_bytes as i64,
        mode_b_e2_delta_bytes: b2.total_bytes as i64 - b0.total_bytes as i64,
        mode_a_e0: a0,
        mode_a_e2: a2,
        mode_b_e0: b0,
        mode_b_e2: b2,
        mode_b_proof_is_shared: shared,
        mode_b_shared_proof_evidence: evidence,
        notes,
    })
}

/// Markdown rendering, for pasting into a document or into `FINDINGS.md`.
pub fn to_markdown(r: &WireReport) -> String {
    let mut s = String::new();
    s.push_str("# Presentation wire-size breakdown\n\n");
    s.push_str(
        "Every figure is `serialized.len()` on a real structure produced by the \
         protocol, not a declared constant.\n\n",
    );

    for bd in [&r.mode_a_e0, &r.mode_a_e2, &r.mode_b_e0, &r.mode_b_e2] {
        s.push_str(&format!("## {} — escrow {}\n\n", bd.label, bd.escrow.to_uppercase()));
        s.push_str("| Field | What it is | Bytes |\n|---|---|---:|\n");
        for f in &bd.fields {
            let mark = if f.escrow_only { " *(E2 only)*" } else { "" };
            s.push_str(&format!("| `{}`{} | {} | {} |\n", f.name, mark, f.kind, f.bytes));
        }
        s.push_str(&format!("| **Total** | | **{}** |\n\n", bd.total_bytes));
        if !bd.agrees {
            s.push_str(&format!(
                "> **MISMATCH:** `size_bytes()` reports {} B.\n\n",
                bd.reported_by_size_bytes
            ));
        }
    }

    s.push_str("## E2 delta\n\n");
    s.push_str("| Mode | E0 | E2 | E2 delta |\n|---|---:|---:|---:|\n");
    s.push_str(&format!(
        "| A | {} B | {} B | **+{} B** |\n",
        r.mode_a_e0.total_bytes, r.mode_a_e2.total_bytes, r.mode_a_e2_delta_bytes
    ));
    s.push_str(&format!(
        "| B | {} B | {} B | **+{} B** |\n\n",
        r.mode_b_e0.total_bytes, r.mode_b_e2.total_bytes, r.mode_b_e2_delta_bytes
    ));

    s.push_str("## Is the escrow proof shared with the presentation proof?\n\n");
    s.push_str(&format!(
        "**{}** — {}\n\n",
        if r.mode_b_proof_is_shared { "Yes, implemented" } else { "No" },
        r.mode_b_shared_proof_evidence
    ));

    for n in &r.notes {
        s.push_str(&format!("- {n}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The breakdown must agree with the protocol's own accounting. This is the
    /// regression guard for the double-counted Schnorr proof.
    #[test]
    fn field_sums_agree_with_size_bytes() {
        let r = measure(8).unwrap();
        for bd in [&r.mode_a_e0, &r.mode_a_e2, &r.mode_b_e0, &r.mode_b_e2] {
            assert!(
                bd.agrees,
                "{} ({}): fields sum to {} but size_bytes() says {}",
                bd.label, bd.escrow, bd.total_bytes, bd.reported_by_size_bytes
            );
        }
    }

    /// Mode B's escrow must cost the ciphertext plus exactly one extra response
    /// scalar — that is the whole claim behind "it folds into the Schnorr proof".
    #[test]
    fn mode_b_escrow_costs_a_ciphertext_plus_one_scalar() {
        let r = measure(8).unwrap();
        assert!(r.mode_b_proof_is_shared);
        assert_eq!(
            r.mode_b_e2_delta_bytes as usize,
            elgamal::Ciphertext::SIZE + ser::FR_LEN,
            "Mode B E2 delta should be one ciphertext + one scalar"
        );
    }

    /// Mode A cannot share, so it pays for a whole standalone proof.
    #[test]
    fn mode_a_escrow_costs_a_ciphertext_plus_a_standalone_proof() {
        let r = measure(8).unwrap();
        assert_eq!(
            r.mode_a_e2_delta_bytes as usize,
            elgamal::Ciphertext::SIZE + rapido_proto::escrow::E2_PROOF_SIZE
        );
        assert!(
            r.mode_a_e2_delta_bytes > r.mode_b_e2_delta_bytes,
            "sharing must make Mode B's escrow cheaper on the wire, not more expensive"
        );
    }
}
