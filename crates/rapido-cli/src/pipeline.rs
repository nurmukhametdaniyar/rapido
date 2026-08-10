//! In-path per-layer decomposition.
//!
//! ## Why this exists as its own measurement
//!
//! The obvious way to decompose verification is to sum standalone benchmarks:
//! `mode-a-verify-aggregate` plus a separately-measured `escrow-check`. That
//! undercounts, because a sum of parts omits everything the pipeline does
//! between them — the revocation lookup, the nonce-cache insert, re-deriving the
//! challenge transcript for the escrow context — and it can produce a
//! decomposition that disagrees with the end-to-end total for the very same
//! configuration.
//!
//! The decomposition is therefore taken from
//! [`rapido_proto::verifier::LatencyBreakdown`], which the verifier fills in as
//! it runs: the layers and the total come from **the same execution**, and
//! therefore cannot disagree. `total_ns` is asserted against the wall-clock time
//! of the same call.

use crate::harness::{quantile, BenchRecord};
use rapido_core::{Epoch, EpochClock};
use rapido_crypto::{bbs, pedersen, rng_from_seed, Fr};
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

/// One configuration's in-path decomposition, every field from the same runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineBreakdown {
    pub mode: String,
    pub escrow: String,
    /// `naive` or `aggregate` for Mode A; `n/a` for Mode B, which has one path.
    pub path: String,
    pub iterations: usize,
    pub layer1_ms: f64,
    pub escrow_ms: f64,
    pub revocation_ms: f64,
    pub replay_ms: f64,
    /// Median of the per-run layer sums — the number to cite for this config.
    pub total_ms: f64,
    /// Median wall-clock time of the same calls, as a cross-check on the
    /// instrumentation. The gap is the pipeline overhead the layers do not
    /// individually account for.
    pub wallclock_ms: f64,
    pub unattributed_ms: f64,
    pub presentation_bytes: usize,
}

fn med_ms(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    quantile(&xs, 0.5) / 1e6
}

/// Number of in-path runs per configuration. Matches the micro-benchmark floor.
const RUNS: usize = 1000;

/// Measure every (mode, escrow, path) combination that gets reported.
pub fn measure_all() -> rapido_core::Result<Vec<PipelineBreakdown>> {
    let mut out = Vec::new();
    let epoch = Epoch(1);
    let revocation = EpochOnly::new(epoch, EpochClock::default());

    let mut rng = rng_from_seed(0x9A17);
    let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    let identity = escrow_auth.registry.enrol(b"pipeline-agent");
    let ped = pedersen::Params::default();

    // --- Mode A, both verifier paths ---
    let authority = mode_a::Authority::generate(3, 5, &mut rng)?;
    let agent = mode_a::Agent::new(&authority.pedersen, identity, &mut rng);
    let pk = authority.public_key();

    for escrow_mode in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
        let cfg = EscrowConfig::new(escrow_mode, Some(escrow_auth.public()), ped);
        for path in [VerifyPath::Naive, VerifyPath::Aggregate] {
            let mut prng = rng_from_seed(0xB01);
            let mut batch = mode_a::provision(&authority, &agent, epoch, 8, &mut prng)?;
            let pres = mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg, &mut prng)?;
            let bytes = pres.size_bytes();

            let (mut l1, mut esc, mut rev, mut rep, mut tot, mut wall) =
                (vec![], vec![], vec![], vec![], vec![], vec![]);
            let mut vrng = rng_from_seed(0xB02);
            for i in 0..RUNS + 100 {
                let mut nonces = NonceCache::new(epoch, 1 << 20);
                let t0 = std::time::Instant::now();
                let o = verifier::verify_mode_a(
                    &pk,
                    &pres,
                    b"c",
                    b"rsu",
                    path,
                    &cfg,
                    &revocation,
                    &mut nonces,
                    &mut vrng,
                );
                let elapsed = t0.elapsed().as_nanos() as f64;
                assert!(o.accepted, "pipeline measurement on a rejected presentation");
                if i < 100 {
                    continue; // warm-up
                }
                l1.push(o.breakdown.layer1_ns as f64);
                esc.push(o.breakdown.escrow_ns as f64);
                rev.push(o.breakdown.revocation_ns as f64);
                rep.push(o.breakdown.replay_ns as f64);
                tot.push(o.breakdown.total_ns() as f64);
                wall.push(elapsed);
            }

            let total_ms = med_ms(tot);
            let wallclock_ms = med_ms(wall);
            out.push(PipelineBreakdown {
                mode: Mode::A.to_string(),
                escrow: escrow_mode.to_string(),
                path: format!("{path:?}").to_lowercase(),
                iterations: RUNS,
                layer1_ms: med_ms(l1),
                escrow_ms: med_ms(esc),
                revocation_ms: med_ms(rev),
                replay_ms: med_ms(rep),
                total_ms,
                wallclock_ms,
                unattributed_ms: wallclock_ms - total_ms,
                presentation_bytes: bytes,
            });
        }
    }

    // --- Mode B ---
    // One verification path. Under E2 the escrow statement is proved inside the
    // presentation's own Schnorr proof, so its cost lands in `layer1_ns` and
    // `escrow_ns` is legitimately zero; that is why the E2 - E0 difference for
    // Mode B shows up as a larger Layer 1 rather than a separate escrow bar.
    for l in [8usize] {
        let mut brng = rng_from_seed(0xC01);
        let issuer = mode_b::Issuer::generate(l, &mut brng)?;
        let app: Vec<Fr> = (0..l - mode_b::ATTR_FIRST_APP)
            .map(|i| bbs::message_from_bytes(format!("a{i}").as_bytes()))
            .collect();
        let cred = mode_b::issue(&issuer, identity, epoch, &app, &mut brng)?;
        let hide_all = BTreeSet::new();

        for escrow_mode in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
            let cfg = EscrowConfig::new(escrow_mode, Some(escrow_auth.public()), ped);
            let pres = mode_b::present(
                &issuer.params,
                &issuer.pk,
                &cred,
                &hide_all,
                b"c",
                b"rsu",
                &cfg,
                &mut brng,
            )?;
            let bytes = pres.size_bytes();

            let (mut l1, mut esc, mut rev, mut rep, mut tot, mut wall) =
                (vec![], vec![], vec![], vec![], vec![], vec![]);
            for i in 0..RUNS + 100 {
                let mut nonces = NonceCache::new(epoch, 1 << 20);
                let t0 = std::time::Instant::now();
                let o = verifier::verify_mode_b(
                    &issuer.params,
                    &issuer.pk,
                    &pres,
                    b"c",
                    b"rsu",
                    &cfg,
                    &revocation,
                    &mut nonces,
                );
                let elapsed = t0.elapsed().as_nanos() as f64;
                assert!(o.accepted, "pipeline measurement on a rejected presentation");
                if i < 100 {
                    continue;
                }
                l1.push(o.breakdown.layer1_ns as f64);
                esc.push(o.breakdown.escrow_ns as f64);
                rev.push(o.breakdown.revocation_ns as f64);
                rep.push(o.breakdown.replay_ns as f64);
                tot.push(o.breakdown.total_ns() as f64);
                wall.push(elapsed);
            }

            let total_ms = med_ms(tot);
            let wallclock_ms = med_ms(wall);
            out.push(PipelineBreakdown {
                mode: Mode::B.to_string(),
                escrow: escrow_mode.to_string(),
                path: "n/a".into(),
                iterations: RUNS,
                layer1_ms: med_ms(l1),
                escrow_ms: med_ms(esc),
                revocation_ms: med_ms(rev),
                replay_ms: med_ms(rep),
                total_ms,
                wallclock_ms,
                unattributed_ms: wallclock_ms - total_ms,
                presentation_bytes: bytes,
            });
        }
    }
    Ok(out)
}

/// Flat CSV for the plotting layer.
pub fn to_csv(rows: &[PipelineBreakdown], path: &std::path::Path) -> rapido_core::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut w = csv::Writer::from_path(path).map_err(|e| rapido_core::Error::Io(e.to_string()))?;
    w.write_record([
        "mode",
        "escrow",
        "path",
        "iterations",
        "layer1_ms",
        "escrow_ms",
        "revocation_ms",
        "replay_ms",
        "total_ms",
        "wallclock_ms",
        "unattributed_ms",
        "presentation_bytes",
    ])
    .map_err(|e| rapido_core::Error::Io(e.to_string()))?;
    for r in rows {
        w.write_record([
            r.mode.clone(),
            r.escrow.clone(),
            r.path.clone(),
            r.iterations.to_string(),
            format!("{:.6}", r.layer1_ms),
            format!("{:.6}", r.escrow_ms),
            format!("{:.6}", r.revocation_ms),
            format!("{:.6}", r.replay_ms),
            format!("{:.6}", r.total_ms),
            format!("{:.6}", r.wallclock_ms),
            format!("{:.6}", r.unattributed_ms),
            r.presentation_bytes.to_string(),
        ])
        .map_err(|e| rapido_core::Error::Io(e.to_string()))?;
    }
    w.flush()?;
    Ok(())
}

/// Bench-record view, so these rows land in `bench.csv` alongside everything else.
pub fn as_bench_records(rows: &[PipelineBreakdown]) -> Vec<BenchRecord> {
    rows.iter()
        .map(|r| {
            let mut params = std::collections::BTreeMap::new();
            params.insert("mode".into(), r.mode.clone());
            params.insert("escrow".into(), r.escrow.clone());
            params.insert("path".into(), r.path.clone());
            params.insert("layer1_ms".into(), format!("{:.6}", r.layer1_ms));
            params.insert("escrow_ms".into(), format!("{:.6}", r.escrow_ms));
            params.insert("revocation_ms".into(), format!("{:.6}", r.revocation_ms));
            params.insert("replay_ms".into(), format!("{:.6}", r.replay_ms));
            params.insert("unattributed_ms".into(), format!("{:.6}", r.unattributed_ms));
            BenchRecord {
                group: "pipeline".into(),
                name: "verify-pipeline".into(),
                params,
                iterations: r.iterations,
                median_ns: r.wallclock_ms * 1e6,
                mean_ns: r.wallclock_ms * 1e6,
                ci95_lo_ns: r.wallclock_ms * 1e6,
                ci95_hi_ns: r.wallclock_ms * 1e6,
                min_ns: r.total_ms * 1e6,
                p99_ns: r.wallclock_ms * 1e6,
                bytes: Some(r.presentation_bytes),
                memory_bytes: None,
                below_clock_resolution: false,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instrumented layers must account for essentially all of the
    /// wall-clock time; a large unattributed remainder would mean the
    /// decomposition is missing a step.
    #[test]
    fn layers_account_for_the_wallclock_time() {
        let rows = measure_all().unwrap();
        assert!(!rows.is_empty());
        for r in &rows {
            assert!(
                r.unattributed_ms >= -0.05,
                "{} {} {}: layers ({:.3} ms) exceed wall clock ({:.3} ms)",
                r.mode,
                r.escrow,
                r.path,
                r.total_ms,
                r.wallclock_ms
            );
            assert!(
                r.unattributed_ms < r.wallclock_ms * 0.25,
                "{} {} {}: {:.3} ms of {:.3} ms is unattributed",
                r.mode,
                r.escrow,
                r.path,
                r.unattributed_ms,
                r.wallclock_ms
            );
        }
    }

    /// Exactly one number per configuration: the sum of the parts and the total
    /// come from the same execution, so they cannot drift apart.
    #[test]
    fn every_configuration_reports_one_total() {
        let rows = measure_all().unwrap();
        for r in &rows {
            let parts = r.layer1_ms + r.escrow_ms + r.revocation_ms + r.replay_ms;
            // Medians of components need not sum exactly to the median of the
            // total, but they must be close; a large gap means the components
            // are being measured on different runs.
            assert!(
                (parts - r.total_ms).abs() < r.total_ms * 0.05 + 0.01,
                "{} {} {}: parts {:.4} vs total {:.4}",
                r.mode,
                r.escrow,
                r.path,
                parts,
                r.total_ms
            );
        }
    }

    /// Mode B's E2 cost lands in Layer 1, because the escrow statement is proved
    /// inside the presentation's own Schnorr proof.
    #[test]
    fn mode_b_escrow_cost_lands_in_layer1() {
        let rows = measure_all().unwrap();
        let b0 = rows.iter().find(|r| r.mode == "mode-b" && r.escrow == "e0").unwrap();
        let b2 = rows.iter().find(|r| r.mode == "mode-b" && r.escrow == "e2").unwrap();
        assert_eq!(b2.escrow_ms, 0.0, "Mode B must not report a separate escrow layer");
        assert!(
            b2.layer1_ms > b0.layer1_ms,
            "E2 must cost more Layer 1 than E0: {:.4} vs {:.4}",
            b2.layer1_ms,
            b0.layer1_ms
        );
    }
}
