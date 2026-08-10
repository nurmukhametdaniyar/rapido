//! The unlinkability game and the two adversaries that play it.
//!
//! The adversary is handed two presentation transcripts and must answer "same
//! agent or different agent". Advantage over guessing is
//! `|Pr[yes | same] − Pr[yes | different]|`.
//!
//! Two adversaries, differing only in what they know:
//!
//! * [`VerifierOnly`] sees exactly what a roadside unit sees: the bytes on the
//!   wire.
//! * [`IssuerColluding`] additionally holds the issuance record — for Mode A,
//!   the map from every certified pseudonym key back to the agent that
//!   requested it. **This is the adversary that separates Mode A from Mode B.**
//!
//! Both adversaries work on real transcripts produced by `rapido-proto`, not on
//! a model of them.

use std::collections::HashMap;

/// What an adversary observes for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// The presentation as it appears on the wire.
    pub wire_bytes: Vec<u8>,
    /// A stable per-session identifier visible to a verifier, when the protocol
    /// exposes one. Mode A puts `P_i` here; Mode B has nothing to put.
    pub public_credential_id: Option<Vec<u8>>,
    /// Ground truth, used only for scoring.
    pub agent: usize,
}

/// The issuance record an issuer necessarily holds.
#[derive(Debug, Clone, Default)]
pub struct IssuanceRecord {
    /// certified credential id -> agent.
    map: HashMap<Vec<u8>, usize>,
}

impl IssuanceRecord {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, credential_id: Vec<u8>, agent: usize) {
        self.map.insert(credential_id, agent);
    }
    pub fn lookup(&self, credential_id: &[u8]) -> Option<usize> {
        self.map.get(credential_id).copied()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// An adversary in the unlinkability game.
pub trait LinkAdversary {
    /// `true` if the adversary claims the two transcripts are from one agent.
    fn same_agent(&self, a: &Transcript, b: &Transcript) -> bool;
    fn name(&self) -> &'static str;
}

/// Sees only the wire. The best it can do is look for a repeated value.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifierOnly;

impl LinkAdversary for VerifierOnly {
    fn same_agent(&self, a: &Transcript, b: &Transcript) -> bool {
        // Any repeated public identifier, or byte-identical transcripts, is a
        // link. Against a correct protocol neither ever happens.
        match (&a.public_credential_id, &b.public_credential_id) {
            (Some(x), Some(y)) if x == y => true,
            _ => a.wire_bytes == b.wire_bytes,
        }
    }
    fn name(&self) -> &'static str {
        "verifier-only"
    }
}

/// Colludes with the issuer, so it can resolve any certified identifier back to
/// the agent that asked for it.
#[derive(Debug, Clone)]
pub struct IssuerColluding<'a> {
    pub record: &'a IssuanceRecord,
}

impl LinkAdversary for IssuerColluding<'_> {
    fn same_agent(&self, a: &Transcript, b: &Transcript) -> bool {
        let resolve =
            |t: &Transcript| t.public_credential_id.as_ref().and_then(|id| self.record.lookup(id));
        match (resolve(a), resolve(b)) {
            (Some(x), Some(y)) => x == y,
            // Nothing to resolve: fall back to what a verifier could do.
            _ => VerifierOnly.same_agent(a, b),
        }
    }
    fn name(&self) -> &'static str {
        "issuer-colluding"
    }
}

/// The outcome of playing the game `n_trials` times.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GameResult {
    pub trials: usize,
    /// `Pr[says "same" | same agent]`.
    pub true_positive_rate: f64,
    /// `Pr[says "same" | different agents]`.
    pub false_positive_rate: f64,
    /// `|TPR − FPR|`. Zero means the adversary learned nothing; one means it
    /// linked perfectly.
    pub advantage: f64,
    pub accuracy: f64,
}

/// Play the game. Half the trials present two transcripts from one agent, half
/// from two different agents.
pub fn play<A: LinkAdversary, R: rand::Rng + ?Sized>(
    adversary: &A,
    transcripts: &[Transcript],
    trials: usize,
    rng: &mut R,
) -> GameResult {
    // Index transcripts by agent so a "same" challenge is constructible.
    let mut by_agent: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, t) in transcripts.iter().enumerate() {
        by_agent.entry(t.agent).or_default().push(i);
    }
    let agents: Vec<usize> =
        by_agent.iter().filter(|(_, v)| v.len() >= 2).map(|(k, _)| *k).collect();
    assert!(agents.len() >= 2, "the game needs at least two agents with two transcripts each");

    let (mut tp, mut fp, mut n_same, mut n_diff, mut correct) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    for _ in 0..trials {
        let same_challenge = rng.gen::<bool>();
        let (i, j) = if same_challenge {
            let a = agents[rng.gen_range(0..agents.len())];
            let list = &by_agent[&a];
            let i = list[rng.gen_range(0..list.len())];
            let mut j = list[rng.gen_range(0..list.len())];
            while j == i {
                j = list[rng.gen_range(0..list.len())];
            }
            (i, j)
        } else {
            let a = agents[rng.gen_range(0..agents.len())];
            let mut b = agents[rng.gen_range(0..agents.len())];
            while b == a {
                b = agents[rng.gen_range(0..agents.len())];
            }
            let i = by_agent[&a][rng.gen_range(0..by_agent[&a].len())];
            let j = by_agent[&b][rng.gen_range(0..by_agent[&b].len())];
            (i, j)
        };

        let guess = adversary.same_agent(&transcripts[i], &transcripts[j]);
        if same_challenge {
            n_same += 1;
            if guess {
                tp += 1;
                correct += 1;
            }
        } else {
            n_diff += 1;
            if guess {
                fp += 1;
            } else {
                correct += 1;
            }
        }
    }

    let tpr = if n_same == 0 { 0.0 } else { tp as f64 / n_same as f64 };
    let fpr = if n_diff == 0 { 0.0 } else { fp as f64 / n_diff as f64 };
    GameResult {
        trials,
        true_positive_rate: tpr,
        false_positive_rate: fpr,
        advantage: crate::stats::advantage_from_rates(tpr, fpr),
        accuracy: correct as f64 / trials as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapido_crypto::rng_from_seed;

    fn transcripts_with_stable_ids(
        n_agents: usize,
        per_agent: usize,
    ) -> (Vec<Transcript>, IssuanceRecord) {
        let mut ts = Vec::new();
        let mut record = IssuanceRecord::new();
        for a in 0..n_agents {
            for s in 0..per_agent {
                let id = format!("agent{a}-pseudonym{s}").into_bytes();
                record.record(id.clone(), a);
                ts.push(Transcript {
                    wire_bytes: format!("session-{a}-{s}").into_bytes(),
                    public_credential_id: Some(id),
                    agent: a,
                });
            }
        }
        (ts, record)
    }

    fn transcripts_without_ids(n_agents: usize, per_agent: usize) -> Vec<Transcript> {
        (0..n_agents)
            .flat_map(|a| {
                (0..per_agent).map(move |s| Transcript {
                    wire_bytes: format!("rerandomized-{a}-{s}").into_bytes(),
                    public_credential_id: None,
                    agent: a,
                })
            })
            .collect()
    }

    #[test]
    fn a_verifier_learns_nothing_from_fresh_pseudonyms() {
        let (ts, _r) = transcripts_with_stable_ids(20, 5);
        let mut rng = rng_from_seed(1);
        let g = play(&VerifierOnly, &ts, 4_000, &mut rng);
        assert!(g.advantage < 0.02, "advantage {}", g.advantage);
        assert!((g.accuracy - 0.5).abs() < 0.05);
    }

    /// Mode A's headline weakness: the issuer links every session.
    #[test]
    fn an_issuer_links_every_session_it_certified() {
        let (ts, record) = transcripts_with_stable_ids(20, 5);
        let adv = IssuerColluding { record: &record };
        let mut rng = rng_from_seed(2);
        let g = play(&adv, &ts, 4_000, &mut rng);
        assert!(g.advantage > 0.99, "advantage {}", g.advantage);
        assert!(g.accuracy > 0.99);
        assert!(g.true_positive_rate > 0.99);
        assert!(g.false_positive_rate < 0.01);
    }

    #[test]
    fn without_a_public_identifier_even_the_issuer_learns_nothing() {
        let ts = transcripts_without_ids(20, 5);
        let record = IssuanceRecord::new();
        let adv = IssuerColluding { record: &record };
        let mut rng = rng_from_seed(3);
        let g = play(&adv, &ts, 4_000, &mut rng);
        assert!(g.advantage < 0.02, "advantage {}", g.advantage);
    }

    #[test]
    fn a_reused_pseudonym_is_caught_by_a_plain_verifier() {
        // Negative control: if the protocol reused an identifier, the game must
        // detect it. A test that only ever reports ~0 proves nothing.
        let mut ts = Vec::new();
        for a in 0..10 {
            for s in 0..4 {
                ts.push(Transcript {
                    wire_bytes: format!("s{a}-{s}").into_bytes(),
                    public_credential_id: Some(format!("reused-by-agent-{a}").into_bytes()),
                    agent: a,
                });
            }
        }
        let mut rng = rng_from_seed(4);
        let g = play(&VerifierOnly, &ts, 2_000, &mut rng);
        assert!(g.advantage > 0.99, "a reused identifier must be detected: {}", g.advantage);
    }

    #[test]
    fn game_is_reproducible_from_a_seed() {
        let (ts, _r) = transcripts_with_stable_ids(10, 4);
        let a = play(&VerifierOnly, &ts, 500, &mut rng_from_seed(9));
        let b = play(&VerifierOnly, &ts, 500, &mut rng_from_seed(9));
        assert_eq!(a, b);
    }
}
