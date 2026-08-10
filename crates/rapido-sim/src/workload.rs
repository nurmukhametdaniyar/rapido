//! Configuration and cost calibration for the simulator.
//!
//! ## How verification cost enters the simulation
//!
//! Scenario 1 has at most 100 vehicles and runs the **real** cryptography.
//! Scenario 2 has up to 10^5 agents authenticating for simulated hours; running
//! real pairings for every one of those would take days of wall-clock time and
//! would measure nothing extra.
//!
//! So the simulator uses a [`CostProfile`]: a set of verification latencies
//! **measured by this codebase, on this machine, in this run**, resampled
//! during the simulation. It is not a fitted distribution and not a figure
//! quoted from elsewhere — it is the empirical distribution of real
//! verifications, recorded at calibration time and carried in the result file
//! so the provenance is visible. `n_calibration_samples` is reported with every
//! scenario result.

use rand::Rng;
use rapido_core::{Epoch, EpochClock};
use rapido_crypto::{elgamal, pedersen, rng_from_seed};
use rapido_privacy::mechanism::MechanismKind;
use rapido_proto::{
    escrow::{EscrowAuthorities, EscrowConfig, EscrowMode},
    mode_a, mode_b,
    replay::NonceCache,
    revocation::EpochOnly,
    verifier::{self, VerifyPath},
    Mode,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Everything that defines a simulated system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemConfig {
    pub mode: Mode,
    pub escrow: EscrowMode,
    pub verify_path: VerifyPath,
    /// Mode A only: pseudonyms issued per epoch.
    pub n_batch: usize,
    /// Mode B only: credential attribute count.
    pub n_attributes: usize,
    /// Mode B only: how many attributes a presentation discloses.
    pub n_disclosed: usize,
    /// Threshold parameters for the issuing authority.
    pub authority_k: usize,
    pub authority_n: usize,
    pub epoch_secs: u64,
    pub timing_mechanism: MechanismKind,
}

impl Default for SystemConfig {
    fn default() -> Self {
        SystemConfig {
            mode: Mode::A,
            escrow: EscrowMode::E2,
            verify_path: VerifyPath::Aggregate,
            n_batch: 100,
            n_attributes: 8,
            n_disclosed: 1,
            authority_k: 3,
            authority_n: 5,
            epoch_secs: EpochClock::DEFAULT_EPOCH_SECS,
            timing_mechanism: MechanismKind::None,
        }
    }
}

impl SystemConfig {
    pub fn clock(&self) -> EpochClock {
        EpochClock::from_secs(self.epoch_secs)
    }

    pub fn label(&self) -> String {
        format!("{}-{}-{:?}", self.mode, self.escrow, self.verify_path).to_lowercase()
    }
}

/// Empirical verification latencies plus the presentation size that produced
/// them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostProfile {
    pub config: SystemConfig,
    /// Measured end-to-end verification latencies, in nanoseconds.
    pub verify_ns: Vec<u64>,
    /// Measured presentation-generation latencies, in nanoseconds.
    pub present_ns: Vec<u64>,
    /// Bytes an agent sends per authentication.
    pub presentation_bytes: usize,
    /// Bytes an agent downloads per epoch for issuance.
    pub issuance_download_bytes: usize,
    /// Bytes an agent uploads per epoch for issuance.
    pub issuance_upload_bytes: usize,
    /// Measured cost of issuing one epoch's credentials for one agent.
    pub issuance_ns: u64,
}

impl CostProfile {
    pub fn n_calibration_samples(&self) -> usize {
        self.verify_ns.len()
    }

    /// Resample a verification latency.
    pub fn sample_verify<R: Rng + ?Sized>(&self, rng: &mut R) -> u64 {
        self.verify_ns[rng.gen_range(0..self.verify_ns.len())]
    }

    pub fn sample_present<R: Rng + ?Sized>(&self, rng: &mut R) -> u64 {
        self.present_ns[rng.gen_range(0..self.present_ns.len())]
    }

    pub fn mean_verify_ns(&self) -> f64 {
        self.verify_ns.iter().sum::<u64>() as f64 / self.verify_ns.len() as f64
    }

    /// Single-core throughput ceiling implied by the measured mean.
    pub fn throughput_per_core_hz(&self) -> f64 {
        1e9 / self.mean_verify_ns()
    }
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let t0 = std::time::Instant::now();
    let out = f();
    (out, t0.elapsed().as_nanos() as u64)
}

/// Run `n` real authentications and record what they cost.
///
/// Both modes are calibrated through [`rapido_proto::verifier`], the same code
/// path a deployment would use, so the numbers include the revocation and
/// replay checks rather than the pairing alone.
pub fn calibrate(config: &SystemConfig, n: usize, seed: u64) -> rapido_core::Result<CostProfile> {
    assert!(n > 0, "calibration needs at least one sample");
    let mut rng = rng_from_seed(seed);
    let epoch = Epoch(1);
    let clock = config.clock();
    let revocation = EpochOnly::new(epoch, clock);
    let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    let identity = escrow_auth.registry.enrol(b"calibration-agent");
    let escrow_cfg =
        EscrowConfig::new(config.escrow, Some(escrow_auth.public()), pedersen::Params::default());

    let mut verify_ns = Vec::with_capacity(n);
    let mut present_ns = Vec::with_capacity(n);

    match config.mode {
        Mode::A => {
            let authority =
                mode_a::Authority::generate(config.authority_k, config.authority_n, &mut rng)?;
            let agent = mode_a::Agent::new(&authority.pedersen, identity, &mut rng);
            let pk = authority.public_key();

            let (batch, issuance_ns) =
                timed(|| mode_a::provision(&authority, &agent, epoch, config.n_batch, &mut rng));
            let mut batch = batch?;
            let mut presentation_bytes = 0;

            for i in 0..n {
                // Re-provision when the batch runs out, exactly as an agent must.
                if batch.is_exhausted() {
                    batch = mode_a::provision(&authority, &agent, epoch, config.n_batch, &mut rng)?;
                }
                let challenge = (i as u64).to_be_bytes();
                let (pres, p_ns) = timed(|| {
                    mode_a::present(&agent, &mut batch, &challenge, b"calib", &escrow_cfg, &mut rng)
                });
                let pres = pres?;
                present_ns.push(p_ns);
                presentation_bytes = pres.size_bytes();

                // A fresh nonce cache per sample: the cache is measured
                // separately, and letting it fill here would make later
                // samples slower for a reason unrelated to verification.
                let mut nonces = NonceCache::new(epoch, 1 << 20);
                let (outcome, v_ns) = timed(|| {
                    verifier::verify_mode_a(
                        &pk,
                        &pres,
                        &challenge,
                        b"calib",
                        config.verify_path,
                        &escrow_cfg,
                        &revocation,
                        &mut nonces,
                        &mut rng,
                    )
                });
                if !outcome.accepted {
                    return Err(rapido_core::Error::InvalidParameter(format!(
                        "calibration produced a rejected presentation: {:?}",
                        outcome.rejection
                    )));
                }
                verify_ns.push(v_ns);
            }

            Ok(CostProfile {
                config: config.clone(),
                verify_ns,
                present_ns,
                presentation_bytes,
                issuance_download_bytes: mode_a::issuance_download_bytes(config.n_batch),
                issuance_upload_bytes: mode_a::issuance_upload_bytes(config.n_batch),
                issuance_ns,
            })
        }
        Mode::B => {
            let issuer = mode_b::Issuer::generate(config.n_attributes, &mut rng)?;
            let app: Vec<rapido_crypto::Fr> =
                (0..config.n_attributes.saturating_sub(mode_b::ATTR_FIRST_APP))
                    .map(|i| rapido_crypto::bbs::message_from_bytes(format!("attr-{i}").as_bytes()))
                    .collect();
            let (cred, issuance_ns) =
                timed(|| mode_b::issue(&issuer, identity, epoch, &app, &mut rng));
            let cred = cred?;

            let disclose: BTreeSet<usize> = (0..config.n_disclosed)
                .map(|i| mode_b::ATTR_FIRST_APP + i)
                .filter(|i| *i < config.n_attributes)
                .collect();
            let mut presentation_bytes = 0;

            for i in 0..n {
                let challenge = (i as u64).to_be_bytes();
                let (pres, p_ns) = timed(|| {
                    mode_b::present(
                        &issuer.params,
                        &issuer.pk,
                        &cred,
                        &disclose,
                        &challenge,
                        b"calib",
                        &escrow_cfg,
                        &mut rng,
                    )
                });
                let pres = pres?;
                present_ns.push(p_ns);
                presentation_bytes = pres.size_bytes();

                let mut nonces = NonceCache::new(epoch, 1 << 20);
                let (outcome, v_ns) = timed(|| {
                    verifier::verify_mode_b(
                        &issuer.params,
                        &issuer.pk,
                        &pres,
                        &challenge,
                        b"calib",
                        &escrow_cfg,
                        &revocation,
                        &mut nonces,
                    )
                });
                if !outcome.accepted {
                    return Err(rapido_core::Error::InvalidParameter(format!(
                        "calibration produced a rejected presentation: {:?}",
                        outcome.rejection
                    )));
                }
                verify_ns.push(v_ns);
            }

            Ok(CostProfile {
                config: config.clone(),
                verify_ns,
                present_ns,
                presentation_bytes,
                issuance_download_bytes: mode_b::issuance_download_bytes(config.n_attributes),
                // Mode B uploads only a request; the credential is the download.
                issuance_upload_bytes: 64,
                issuance_ns,
            })
        }
    }
}

/// Escrow key material shared by scenarios that need to de-anonymize.
pub fn escrow_setup(seed: u64) -> rapido_core::Result<(EscrowAuthorities, elgamal::Registry)> {
    let mut rng = rng_from_seed(seed);
    let auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    Ok((auth, elgamal::Registry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_produces_usable_samples_for_mode_a() {
        let cfg = SystemConfig { n_batch: 8, ..Default::default() };
        let p = calibrate(&cfg, 16, 1).unwrap();
        assert_eq!(p.n_calibration_samples(), 16);
        assert!(p.verify_ns.iter().all(|v| *v > 0));
        assert!(p.presentation_bytes > 0);
        assert!(p.throughput_per_core_hz() > 0.0);
    }

    #[test]
    fn calibration_produces_usable_samples_for_mode_b() {
        let cfg = SystemConfig { mode: Mode::B, n_attributes: 8, ..Default::default() };
        let p = calibrate(&cfg, 8, 2).unwrap();
        assert_eq!(p.n_calibration_samples(), 8);
        assert!(p.presentation_bytes > 0);
    }

    #[test]
    fn calibration_re_provisions_when_the_batch_runs_out() {
        // 16 authentications against a batch of 4 forces three re-provisions;
        // if that path were broken, calibration would error.
        let cfg = SystemConfig { n_batch: 4, ..Default::default() };
        let p = calibrate(&cfg, 16, 3).unwrap();
        assert_eq!(p.verify_ns.len(), 16);
    }

    #[test]
    fn resampling_stays_within_the_measured_set() {
        let cfg = SystemConfig { n_batch: 4, ..Default::default() };
        let p = calibrate(&cfg, 8, 4).unwrap();
        let mut rng = rng_from_seed(99);
        for _ in 0..200 {
            assert!(p.verify_ns.contains(&p.sample_verify(&mut rng)));
        }
    }

    #[test]
    fn escrow_variants_all_calibrate() {
        for escrow in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
            let cfg = SystemConfig { escrow, n_batch: 4, ..Default::default() };
            assert!(calibrate(&cfg, 4, 5).is_ok(), "{escrow} failed to calibrate");
        }
    }
}
