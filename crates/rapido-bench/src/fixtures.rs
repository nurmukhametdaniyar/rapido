//! Fixtures shared by the criterion benches.
//!
//! Everything is built from a fixed seed so two `cargo bench` runs measure the
//! same inputs and criterion's regression detection is meaningful.

use rapido_core::Epoch;
use rapido_crypto::{bbs, elgamal, pedersen, rng_from_seed, Fr, Rng};
use rapido_proto::{
    escrow::{EscrowAuthorities, EscrowConfig, EscrowMode},
    mode_a, mode_b,
};
use std::collections::BTreeSet;

pub const EPOCH: Epoch = Epoch(1);

pub struct ModeAFixture {
    pub authority: mode_a::Authority,
    pub agent: mode_a::Agent,
    pub batch: mode_a::Batch,
    pub escrow_auth: EscrowAuthorities,
    pub rng: Rng,
}

impl ModeAFixture {
    pub fn new(n_batch: usize, escrow: EscrowMode) -> (Self, EscrowConfig) {
        let mut rng = rng_from_seed(0xA0);
        let mut escrow_auth =
            EscrowAuthorities::generate(2, 3, &mut rng).expect("valid threshold parameters");
        let identity = escrow_auth.registry.enrol(b"bench-agent");
        let authority =
            mode_a::Authority::generate(3, 5, &mut rng).expect("valid threshold parameters");
        let agent = mode_a::Agent::new(&authority.pedersen, identity, &mut rng);
        let batch = mode_a::provision(&authority, &agent, EPOCH, n_batch, &mut rng)
            .expect("provisioning succeeds");
        let cfg =
            EscrowConfig::new(escrow, Some(escrow_auth.public()), pedersen::Params::default());
        (ModeAFixture { authority, agent, batch, escrow_auth, rng }, cfg)
    }

    pub fn presentation(&mut self, cfg: &EscrowConfig) -> mode_a::Presentation {
        if self.batch.is_exhausted() {
            self.batch = mode_a::provision(&self.authority, &self.agent, EPOCH, 256, &mut self.rng)
                .expect("re-provisioning succeeds");
        }
        mode_a::present(&self.agent, &mut self.batch, b"c", b"rsu", cfg, &mut self.rng)
            .expect("presentation succeeds")
    }
}

pub struct ModeBFixture {
    pub issuer: mode_b::Issuer,
    pub cred: mode_b::Credential,
    pub disclose: BTreeSet<usize>,
    pub escrow_auth: EscrowAuthorities,
    pub rng: Rng,
}

impl ModeBFixture {
    /// `disclosure_fraction` applies to the application attributes; the identity
    /// is always hidden and the epoch is always disclosed (see `mode_b`).
    pub fn new(l: usize, disclosure_fraction: f64, escrow: EscrowMode) -> (Self, EscrowConfig) {
        let mut rng = rng_from_seed(0xB0);
        let mut escrow_auth =
            EscrowAuthorities::generate(2, 3, &mut rng).expect("valid threshold parameters");
        let identity = escrow_auth.registry.enrol(b"bench-agent");
        let issuer = mode_b::Issuer::generate(l, &mut rng).expect("valid attribute count");
        let app: Vec<Fr> = (0..l - mode_b::ATTR_FIRST_APP)
            .map(|i| bbs::message_from_bytes(format!("a{i}").as_bytes()))
            .collect();
        let cred =
            mode_b::issue(&issuer, identity, EPOCH, &app, &mut rng).expect("issuance succeeds");

        let n_app = l - mode_b::ATTR_FIRST_APP;
        let n_disclosed = (disclosure_fraction * n_app as f64).round() as usize;
        let disclose: BTreeSet<usize> =
            (0..n_disclosed).map(|i| mode_b::ATTR_FIRST_APP + i).collect();
        let cfg =
            EscrowConfig::new(escrow, Some(escrow_auth.public()), pedersen::Params::default());
        (ModeBFixture { issuer, cred, disclose, escrow_auth, rng }, cfg)
    }

    pub fn presentation(&mut self, cfg: &EscrowConfig) -> mode_b::Presentation {
        mode_b::present(
            &self.issuer.params,
            &self.issuer.pk,
            &self.cred,
            &self.disclose,
            b"c",
            b"rsu",
            cfg,
            &mut self.rng,
        )
        .expect("presentation succeeds")
    }
}

/// Escrow fixture for Layer 3 benchmarks.
pub struct EscrowFixture {
    pub auth: EscrowAuthorities,
    pub ped: pedersen::Params,
    pub identity: Fr,
    pub blinding: Fr,
    pub commitment: pedersen::Commitment,
    pub ciphertext: elgamal::Ciphertext,
    pub rng: Rng,
}

impl EscrowFixture {
    pub fn new() -> Self {
        let mut rng = rng_from_seed(0xC0);
        let mut auth =
            EscrowAuthorities::generate(2, 3, &mut rng).expect("valid threshold parameters");
        let ped = pedersen::Params::default();
        let identity = auth.registry.enrol(b"bench-agent");
        let (commitment, opening) = ped.commit_random(identity, &mut rng);
        let (ciphertext, _r) =
            elgamal::encrypt(auth.public(), elgamal::identity_point(identity), &mut rng);
        EscrowFixture {
            auth,
            ped,
            identity,
            blinding: opening.blinding,
            commitment,
            ciphertext,
            rng,
        }
    }
}

impl Default for EscrowFixture {
    fn default() -> Self {
        Self::new()
    }
}
