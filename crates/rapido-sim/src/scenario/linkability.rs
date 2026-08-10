//! Scenario 4 — the linkability experiment.
//!
//! Runs the unlinkability game on transcripts produced by the **real**
//! protocol, over the four (mode, adversary) cells:
//!
//! | mode | adversary | expected |
//! |---|---|---|
//! | A | verifier-only | ~0 |
//! | A | issuer-colluding | **~1.0 — this is the finding** |
//! | B | verifier-only | ~0 |
//! | B | issuer-colluding | ~0 |
//!
//! The measured advantage is what gets reported. Mode A's issuer cell is a
//! self-check on the harness as much as a result: the issuer holds the
//! pseudonym-to-agent map by construction, so anything short of ~1.0 there
//! means the transcripts or the adversary are wired up wrong.

use crate::attack::linkability::{
    play, GameResult, IssuanceRecord, IssuerColluding, LinkAdversary, Transcript, VerifierOnly,
};
use rapido_core::Epoch;
use rapido_crypto::{pedersen, rng_from_seed};
use rapido_proto::{
    escrow::{EscrowConfig, EscrowMode},
    mode_a, mode_b,
    verifier::presentation_digest,
    Mode,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub agents: usize,
    pub sessions_per_agent: usize,
    pub trials: usize,
    /// Mode B only.
    pub n_attributes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::A, agents: 20, sessions_per_agent: 5, trials: 4_000, n_attributes: 8 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub mode: Mode,
    pub adversary: String,
    pub agents: usize,
    pub sessions_per_agent: usize,
    pub result: GameResult,
    pub seed: u64,
}

/// Generate real transcripts, plus the issuance record the issuer would hold.
fn generate(config: &Config, seed: u64) -> rapido_core::Result<(Vec<Transcript>, IssuanceRecord)> {
    let mut rng = rng_from_seed(seed);
    let epoch = Epoch(1);
    let escrow = EscrowConfig::new(EscrowMode::E0, None, pedersen::Params::default());
    let mut transcripts = Vec::new();
    let mut record = IssuanceRecord::new();

    match config.mode {
        Mode::A => {
            let authority = mode_a::Authority::generate(2, 3, &mut rng)?;
            for agent_idx in 0..config.agents {
                let id = rapido_crypto::elgamal::identity_scalar(
                    format!("agent-{agent_idx}").as_bytes(),
                );
                let agent = mode_a::Agent::new(&authority.pedersen, id, &mut rng);
                let mut batch = mode_a::provision(
                    &authority,
                    &agent,
                    epoch,
                    config.sessions_per_agent,
                    &mut rng,
                )?;
                // What the authority necessarily learns at issuance.
                for cert in &batch.certs {
                    record.record(cert.p_i.to_bytes(), agent_idx);
                }
                for s in 0..config.sessions_per_agent {
                    let challenge = format!("challenge-{agent_idx}-{s}");
                    let pres = mode_a::present(
                        &agent,
                        &mut batch,
                        challenge.as_bytes(),
                        b"rsu",
                        &escrow,
                        &mut rng,
                    )?;
                    transcripts.push(Transcript {
                        wire_bytes: mode_a::cert_bytes(&pres.cert),
                        // Mode A puts the pseudonym public key on the wire.
                        public_credential_id: Some(pres.cert.p_i.to_bytes()),
                        agent: agent_idx,
                    });
                }
            }
        }
        Mode::B => {
            let issuer = mode_b::Issuer::generate(config.n_attributes, &mut rng)?;
            let disclose = BTreeSet::new();
            for agent_idx in 0..config.agents {
                let id = rapido_crypto::elgamal::identity_scalar(
                    format!("agent-{agent_idx}").as_bytes(),
                );
                let cred = mode_b::issue(&issuer, id, epoch, &[], &mut rng)?;
                // The issuer holds the signature it produced. It is *not* a
                // credential identifier a verifier ever sees, which is exactly
                // why the issuer-colluding adversary gains nothing here.
                record.record(cred.sig.to_bytes(), agent_idx);
                for s in 0..config.sessions_per_agent {
                    let challenge = format!("challenge-{agent_idx}-{s}");
                    let pres = mode_b::present(
                        &issuer.params,
                        &issuer.pk,
                        &cred,
                        &disclose,
                        challenge.as_bytes(),
                        b"rsu",
                        &escrow,
                        &mut rng,
                    )?;
                    transcripts.push(Transcript {
                        wire_bytes: presentation_digest(&pres),
                        // Nothing stable is exposed. That is the point.
                        public_credential_id: None,
                        agent: agent_idx,
                    });
                }
            }
        }
    }
    Ok((transcripts, record))
}

/// Run both adversaries against one mode.
pub fn run(config: &Config, seed: u64) -> rapido_core::Result<Vec<Outcome>> {
    let (transcripts, record) = generate(config, seed)?;
    let mut rng = rng_from_seed(seed ^ 0x5eed);

    let verifier_only = play(&VerifierOnly, &transcripts, config.trials, &mut rng);
    let issuer = IssuerColluding { record: &record };
    let issuer_result = play(&issuer, &transcripts, config.trials, &mut rng);

    Ok(vec![
        Outcome {
            mode: config.mode,
            adversary: VerifierOnly.name().to_string(),
            agents: config.agents,
            sessions_per_agent: config.sessions_per_agent,
            result: verifier_only,
            seed,
        },
        Outcome {
            mode: config.mode,
            adversary: issuer.name().to_string(),
            agents: config.agents,
            sessions_per_agent: config.sessions_per_agent,
            result: issuer_result,
            seed,
        },
    ])
}

/// All four cells of the mode × adversary table.
pub fn run_all(config: &Config, seed: u64) -> rapido_core::Result<Vec<Outcome>> {
    let mut out = Vec::new();
    for mode in [Mode::A, Mode::B] {
        out.extend(run(&Config { mode, ..*config }, seed)?);
    }
    Ok(out)
}

pub fn run_many(
    config: &Config,
    n_seeds: u64,
    base_seed: u64,
) -> rapido_core::Result<Vec<Outcome>> {
    let mut out = Vec::new();
    for i in 0..n_seeds {
        out.extend(run_all(config, base_seed + i)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(outcomes: &[Outcome], mode: Mode, adversary: &str) -> GameResult {
        outcomes
            .iter()
            .find(|o| o.mode == mode && o.adversary == adversary)
            .unwrap_or_else(|| panic!("no result for {mode}/{adversary}"))
            .result
    }

    #[test]
    fn the_four_cells_come_out_as_the_spec_predicts() {
        let cfg = Config { agents: 12, sessions_per_agent: 4, trials: 3_000, ..Default::default() };
        let out = run_all(&cfg, 1).unwrap();
        assert_eq!(out.len(), 4);

        let a_verifier = cell(&out, Mode::A, "verifier-only");
        let a_issuer = cell(&out, Mode::A, "issuer-colluding");
        let b_verifier = cell(&out, Mode::B, "verifier-only");
        let b_issuer = cell(&out, Mode::B, "issuer-colluding");

        assert!(a_verifier.advantage < 0.05, "A/verifier {}", a_verifier.advantage);
        assert!(
            a_issuer.advantage > 0.95,
            "A/issuer should link everything, got {}",
            a_issuer.advantage
        );
        assert!(b_verifier.advantage < 0.05, "B/verifier {}", b_verifier.advantage);
        assert!(
            b_issuer.advantage < 0.05,
            "B/issuer must gain nothing, got {}",
            b_issuer.advantage
        );
    }

    #[test]
    fn mode_a_transcripts_expose_a_pseudonym_and_mode_b_transcripts_do_not() {
        let (a, _) = generate(
            &Config { mode: Mode::A, agents: 3, sessions_per_agent: 2, ..Default::default() },
            2,
        )
        .unwrap();
        assert!(a.iter().all(|t| t.public_credential_id.is_some()));
        let (b, _) = generate(
            &Config { mode: Mode::B, agents: 3, sessions_per_agent: 2, ..Default::default() },
            2,
        )
        .unwrap();
        assert!(b.iter().all(|t| t.public_credential_id.is_none()));
    }

    #[test]
    fn no_transcript_repeats_across_sessions_in_either_mode() {
        for mode in [Mode::A, Mode::B] {
            let (ts, _) = generate(
                &Config { mode, agents: 5, sessions_per_agent: 4, ..Default::default() },
                3,
            )
            .unwrap();
            let unique: std::collections::HashSet<&Vec<u8>> =
                ts.iter().map(|t| &t.wire_bytes).collect();
            assert_eq!(unique.len(), ts.len(), "{mode}: a transcript repeated");
        }
    }

    #[test]
    fn results_are_reproducible() {
        let cfg = Config {
            agents: 6,
            sessions_per_agent: 3,
            trials: 400,
            n_attributes: 4,
            ..Default::default()
        };
        assert_eq!(run_all(&cfg, 7).unwrap(), run_all(&cfg, 7).unwrap());
    }
}
