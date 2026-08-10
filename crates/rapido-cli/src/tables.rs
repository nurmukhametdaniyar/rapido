//! Flat CSV emitters and LaTeX table generation.
//!
//! No reported number is ever typed by hand. `emit_latex` reads the committed
//! result files and writes `.tex` fragments that a document `\input`s, so every
//! published figure is traceable to a result file and a commit.

use crate::harness::BenchRecord;
use crate::sims::{
    CoverAttackReport, Scenario1Report, Scenario2Report, Scenario3Report, TimingAttackReport,
};
use rapido_sim::scenario::linkability;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type Res<T> = rapido_core::Result<T>;

fn writer(path: &Path) -> Res<csv::Writer<std::fs::File>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    csv::Writer::from_path(path).map_err(|e| rapido_core::Error::Io(e.to_string()))
}

fn wr<W: std::io::Write>(w: &mut csv::Writer<W>, row: &[String]) -> Res<()> {
    w.write_record(row).map_err(|e| rapido_core::Error::Io(e.to_string()))
}

// --- CSV emitters ----------------------------------------------------------

pub fn scenario1_csv(r: &Scenario1Report, path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "vehicles",
            "cores",
            "seed",
            "completion_rate",
            "loss_rate",
            "p50_ns",
            "p90_ns",
            "p99_ns",
            "p999_ns",
            "max_ns",
            "max_queue_depth",
            "utilization",
            "deadline_ns",
            "mean_verify_ns",
        ]
        .map(String::from),
    )?;
    for o in &r.runs {
        wr(
            &mut w,
            &[
                o.vehicles.to_string(),
                o.cores.to_string(),
                o.seed.to_string(),
                format!("{:.6}", o.completion_rate),
                format!("{:.6}", o.loss_rate),
                o.latency.p50_ns.to_string(),
                o.latency.p90_ns.to_string(),
                o.latency.p99_ns.to_string(),
                o.latency.p999_ns.to_string(),
                o.latency.max_ns.to_string(),
                o.max_queue_depth.to_string(),
                format!("{:.6}", o.verifier_utilization),
                o.deadline_ns.to_string(),
                format!("{:.1}", r.calibration.mean_verify_ns),
            ],
        )?;
    }
    w.flush()?;
    Ok(())
}

pub fn scenario2_csv(r: &Scenario2Report, path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "agents",
            "cores",
            "seed",
            "achieved_throughput_hz",
            "analytic_ceiling_hz",
            "throughput_per_core_hz",
            "offered_load_ratio",
            "utilization",
            "max_queue_depth",
            "p50_ns",
            "p99_ns",
            "issuance_rate_hz",
            "issuance_cpu_load",
            "presentation_bytes",
            "issuance_bytes",
            "cover_bytes",
            "total_bytes",
            "aggregate_bps",
            "cover_overhead_pct",
        ]
        .map(String::from),
    )?;
    for o in &r.runs {
        wr(
            &mut w,
            &[
                o.agents.to_string(),
                o.cores.to_string(),
                o.seed.to_string(),
                format!("{:.3}", o.achieved_throughput_hz),
                format!("{:.3}", o.analytic_ceiling_hz),
                format!("{:.3}", o.throughput_per_core_hz),
                format!("{:.4}", o.offered_load_ratio),
                format!("{:.4}", o.verifier_utilization),
                o.max_queue_depth.to_string(),
                o.latency.p50_ns.to_string(),
                o.latency.p99_ns.to_string(),
                format!("{:.3}", o.issuance_rate_hz),
                format!("{:.4}", o.issuance_cpu_load),
                o.bandwidth.presentation_bytes_total.to_string(),
                o.bandwidth.issuance_bytes_total.to_string(),
                o.bandwidth.cover_bytes_total.to_string(),
                o.bandwidth.total_bytes.to_string(),
                format!("{:.1}", o.bandwidth.aggregate_bps),
                format!("{:.3}", o.bandwidth.cover_overhead_pct),
            ],
        )?;
    }
    w.flush()?;
    Ok(())
}

pub fn scenario3_csv(r: &Scenario3Report, path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "sweep",
            "outage_minutes",
            "epoch_minutes",
            "lookahead_epochs",
            "n_batch",
            "seed",
            "failure_rate",
            "expiry_failure_rate",
            "exhaustion_failure_rate",
            "attempt_failure_rate",
            "mean_time_to_failure_secs",
            "revocation_latency_secs",
        ]
        .map(String::from),
    )?;
    for (label, runs) in [("epoch", &r.epoch_sweep), ("lookahead", &r.lookahead_sweep)] {
        for o in runs {
            wr(
                &mut w,
                &[
                    label.to_string(),
                    o.outage_minutes.to_string(),
                    o.epoch_minutes.to_string(),
                    o.lookahead_epochs.to_string(),
                    o.n_batch.to_string(),
                    o.seed.to_string(),
                    format!("{:.6}", o.failure_rate),
                    format!("{:.6}", o.expiry_failure_rate),
                    format!("{:.6}", o.exhaustion_failure_rate),
                    format!("{:.6}", o.attempt_failure_rate),
                    format!("{:.3}", o.mean_time_to_failure_secs),
                    o.revocation_latency_secs.to_string(),
                ],
            )?;
        }
    }
    w.flush()?;
    Ok(())
}

pub fn scenario4_csv(runs: &[linkability::Outcome], path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "mode",
            "adversary",
            "agents",
            "sessions_per_agent",
            "seed",
            "trials",
            "advantage",
            "accuracy",
            "true_positive_rate",
            "false_positive_rate",
        ]
        .map(String::from),
    )?;
    for o in runs {
        wr(
            &mut w,
            &[
                o.mode.to_string(),
                o.adversary.clone(),
                o.agents.to_string(),
                o.sessions_per_agent.to_string(),
                o.seed.to_string(),
                o.result.trials.to_string(),
                format!("{:.6}", o.result.advantage),
                format!("{:.6}", o.result.accuracy),
                format!("{:.6}", o.result.true_positive_rate),
                format!("{:.6}", o.result.false_positive_rate),
            ],
        )?;
    }
    w.flush()?;
    Ok(())
}

pub fn timing_attack_csv(r: &TimingAttackReport, path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "mechanism",
            "attack",
            "epsilon",
            "delta",
            "n_observations",
            "trials",
            "seed",
            "auc",
            "advantage",
            "advantage_ci_lo",
            "advantage_ci_hi",
            "auc_ci_lo",
            "auc_ci_hi",
            "train_pool",
            "test_pool",
            "mean_release_ns",
            "sensitivity_ns",
            "bin_ns",
        ]
        .map(String::from),
    )?;
    for o in &r.results {
        wr(
            &mut w,
            &[
                o.mechanism.clone(),
                o.attack.as_str().to_string(),
                o.epsilon.map(|e| format!("{e}")).unwrap_or_else(|| "inf".into()),
                o.delta.map(|d| format!("{d}")).unwrap_or_default(),
                o.n_observations.to_string(),
                o.trials.to_string(),
                o.seed.to_string(),
                format!("{:.6}", o.auc),
                format!("{:.6}", o.advantage),
                format!("{:.6}", o.advantage_ci_lo),
                format!("{:.6}", o.advantage_ci_hi),
                format!("{:.6}", o.auc_ci_lo),
                format!("{:.6}", o.auc_ci_hi),
                o.train_pool.to_string(),
                o.test_pool.to_string(),
                format!("{:.1}", o.mean_release_ns),
                r.sensitivity.delta_f_ns.to_string(),
                o.bin_ns.to_string(),
            ],
        )?;
    }
    w.flush()?;
    Ok(())
}

pub fn cover_attack_csv(r: &CoverAttackReport, path: &Path) -> Res<()> {
    let mut w = writer(path)?;
    wr(
        &mut w,
        &[
            "cover_rate_hz",
            "auc",
            "advantage",
            "bandwidth_overhead_pct",
            "mean_total_bytes",
            "message_bytes",
            "trials",
        ]
        .map(String::from),
    )?;
    for o in &r.results {
        wr(
            &mut w,
            &[
                format!("{:.3}", o.cover_rate_hz),
                format!("{:.6}", o.auc),
                format!("{:.6}", o.advantage),
                format!("{:.3}", o.bandwidth_overhead_pct),
                format!("{:.1}", o.mean_total_bytes),
                r.presentation_bytes.to_string(),
                o.trials.to_string(),
            ],
        )?;
    }
    w.flush()?;
    Ok(())
}

// --- LaTeX -----------------------------------------------------------------

#[derive(serde::Deserialize)]
struct BenchFile {
    meta: rapido_core::EnvMeta,
    data: Vec<BenchRecord>,
}

/// Read every `bench.json` under `results/` and emit the LaTeX tables.
///
/// Returns the paths written. If no results are present the caller gets an
/// error rather than an empty file that looks like a valid table.
pub fn emit_latex(results_dir: &Path, out_dir: &Path) -> Res<Vec<PathBuf>> {
    let mut per_profile: BTreeMap<String, BenchFile> = BTreeMap::new();
    for entry in std::fs::read_dir(results_dir)? {
        let dir = entry?.path();
        let f = dir.join("bench.json");
        if f.is_file() {
            let text = std::fs::read_to_string(&f)?;
            let parsed: BenchFile = serde_json::from_str(&text)
                .map_err(|e| rapido_core::Error::Io(format!("{}: {e}", f.display())))?;
            per_profile.insert(parsed.meta.profile_label.clone(), parsed);
        }
    }
    if per_profile.is_empty() {
        return Err(rapido_core::Error::Io(format!(
            "no bench.json found under {}; run `rapido-cli bench` first",
            results_dir.display()
        )));
    }
    std::fs::create_dir_all(out_dir)?;

    Ok(vec![
        write_table1(&per_profile, out_dir)?,
        write_table2(&per_profile, out_dir)?,
        write_env_table(&per_profile, out_dir)?,
    ])
}

fn fmt_ms(r: &BenchRecord) -> String {
    let ms = r.median_ms();
    let lo = r.ci95_lo_ns / 1e6;
    let hi = r.ci95_hi_ns / 1e6;
    if ms < 0.001 {
        format!("{:.4}", ms)
    } else if ms < 1.0 {
        format!("{ms:.3} [{lo:.3}, {hi:.3}]")
    } else {
        format!("{ms:.2} [{lo:.2}, {hi:.2}]")
    }
}

/// Compare a recorded parameter against a wanted value, numerically when both
/// parse as numbers.
///
/// Parameters are stored as whatever `Display` produced, so a disclosure
/// fraction of `0.0` is stored as `"0"` while a caller may reasonably write
/// `"0.0"`. A pure string comparison would silently drop the row and emit a
/// table with a missing line rather than a visible error.
fn param_matches(recorded: Option<&String>, wanted: &str) -> bool {
    match recorded {
        None => false,
        Some(got) => match (got.parse::<f64>(), wanted.parse::<f64>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => got == wanted,
        },
    }
}

fn find<'a>(
    records: &'a [BenchRecord],
    name: &str,
    params: &[(&str, &str)],
) -> Option<&'a BenchRecord> {
    records
        .iter()
        .find(|r| r.name == name && params.iter().all(|(k, v)| param_matches(r.params.get(*k), v)))
}

/// One row of Table 1: (system, variant, benchmark name, parameter filter).
type TableRow = (&'static str, &'static str, &'static str, &'static [(&'static str, &'static str)]);
/// One row of Table 2: (label, benchmark name, parameter filter).
type ComponentRow = (&'static str, &'static str, &'static [(&'static str, &'static str)]);

/// Table 1: RAPIDO Mode A / Mode B against every baseline, same hardware.
fn write_table1(profiles: &BTreeMap<String, BenchFile>, out_dir: &Path) -> Res<PathBuf> {
    let path = out_dir.join("table1_mode_comparison.tex");
    let mut s = String::new();
    s.push_str("% Generated by `rapido-cli tables`. Do not edit by hand.\n");
    s.push_str("\\begin{tabular}{llrr}\n\\toprule\n");
    s.push_str("System & Variant & Verify (ms, median [95\\% CI]) & Wire (B) \\\\\n\\midrule\n");

    let rows: &[TableRow] = &[
        ("RAPIDO Mode A", "naive, no escrow", "mode-a-verify-naive", &[("escrow", "e0")]),
        ("RAPIDO Mode A", "aggregate, no escrow", "mode-a-verify-aggregate", &[("escrow", "e0")]),
        (
            "RAPIDO Mode A",
            "aggregate, E2 escrow",
            "mode-a-verify-full-pipeline",
            &[("escrow", "e2")],
        ),
        (
            "RAPIDO Mode B",
            "$L=8$, 0\\% disclosed, E0",
            "mode-b-verify",
            &[("L", "8"), ("disclosure_fraction", "0"), ("escrow", "e0")],
        ),
        (
            "RAPIDO Mode B",
            "$L=8$, 0\\% disclosed, E2",
            "mode-b-verify",
            &[("L", "8"), ("disclosure_fraction", "0"), ("escrow", "e2")],
        ),
        ("mTLS-like", "Ed25519, depth 2", "mtls-ed25519-verify", &[]),
        ("mTLS-like", "ECDSA P-256, depth 2", "mtls-p256-verify", &[]),
        ("SCMS / IEEE 1609.2", "explicit certificate", "scms-explicit-verify", &[]),
        ("SCMS / IEEE 1609.2", "implicit (ECQV)", "scms-implicit-verify", &[]),
        ("Idemix-like", "CL-RSA-2048, $L=5$", "cl-rsa-verify", &[("L", "5"), ("n_disclosed", "0")]),
    ];

    for (system, variant, name, params) in rows {
        for (label, file) in profiles {
            if let Some(r) = find(&file.data, name, params) {
                s.push_str(&format!(
                    "{system} ({label}) & {variant} & {} & {} \\\\\n",
                    fmt_ms(r),
                    r.bytes.map(|b| b.to_string()).unwrap_or_else(|| "--".into())
                ));
            }
        }
    }
    s.push_str("\\bottomrule\n\\end{tabular}\n");
    std::fs::write(&path, s)?;
    Ok(path)
}

/// Table 2: measured per-layer decomposition of verification cost.
fn write_table2(profiles: &BTreeMap<String, BenchFile>, out_dir: &Path) -> Res<PathBuf> {
    let path = out_dir.join("table2_layer_breakdown.tex");
    let mut s = String::new();
    s.push_str("% Generated by `rapido-cli tables`. Do not edit by hand.\n");
    s.push_str("\\begin{tabular}{llrr}\n\\toprule\n");
    s.push_str("Profile & Component & Median (ms) & 95\\% CI (ms) \\\\\n\\midrule\n");

    let components: &[ComponentRow] = &[
        ("Layer 1: Mode A verify (aggregate)", "mode-a-verify-aggregate", &[("escrow", "e0")]),
        (
            "Layer 1: Mode B verify ($L=8$)",
            "mode-b-verify",
            &[("L", "8"), ("disclosure_fraction", "0"), ("escrow", "e0")],
        ),
        ("Layer 3: escrow check (E1)", "escrow-check", &[("escrow", "e1")]),
        ("Layer 3: escrow check (E2)", "escrow-check", &[("escrow", "e2")]),
        ("Revocation: R0 epoch check", "r0-epoch-check", &[]),
        ("Revocation: R1 CRL ($|R|=10^6$)", "r1-crl-hashset-miss", &[("R", "1000000")]),
        (
            "Revocation: R2 Bloom ($|R|=10^6$)",
            "r2-bloom-miss",
            &[("R", "1000000"), ("fp_target", "0.01")],
        ),
        ("Replay: nonce cache insert ($10^6$)", "nonce-cache-insert", &[("entries", "1000000")]),
    ];

    for (label, file) in profiles {
        for (component, name, params) in components {
            if let Some(r) = find(&file.data, name, params) {
                s.push_str(&format!(
                    "{label} & {component} & {:.4} & [{:.4}, {:.4}] \\\\\n",
                    r.median_ns / 1e6,
                    r.ci95_lo_ns / 1e6,
                    r.ci95_hi_ns / 1e6
                ));
            }
        }
    }
    s.push_str("\\bottomrule\n\\end{tabular}\n");
    std::fs::write(&path, s)?;
    Ok(path)
}

/// The measurement-environment table. A results section without it is not
/// reproducible: latencies mean nothing without the machine that produced them.
fn write_env_table(profiles: &BTreeMap<String, BenchFile>, out_dir: &Path) -> Res<PathBuf> {
    let path = out_dir.join("table_environment.tex");
    let mut s = String::new();
    s.push_str("% Generated by `rapido-cli tables`. Do not edit by hand.\n");
    s.push_str("\\begin{tabular}{ll}\n\\toprule\nProperty & Value \\\\\n\\midrule\n");
    for (label, file) in profiles {
        let m = &file.meta;
        let esc = |x: &str| x.replace('_', "\\_").replace('&', "\\&");
        s.push_str(&format!("\\multicolumn{{2}}{{l}}{{\\textbf{{{label}}}}} \\\\\n"));
        s.push_str(&format!("CPU & {} \\\\\n", esc(&m.cpu_model)));
        s.push_str(&format!(
            "Cores & {} logical{} \\\\\n",
            m.cpu_cores_logical,
            m.cpu_cores_physical.map(|p| format!(", {p} physical")).unwrap_or_default()
        ));
        s.push_str(&format!(
            "RAM & {} \\\\\n",
            m.ram_bytes
                .map(|b| format!("{:.1} GiB", b as f64 / 1024f64.powi(3)))
                .unwrap_or("--".into())
        ));
        s.push_str(&format!("OS / kernel & {} / {} \\\\\n", esc(&m.os), esc(&m.kernel)));
        s.push_str(&format!("Target & {} \\\\\n", esc(&m.target_triple)));
        s.push_str(&format!("Toolchain & {} \\\\\n", esc(&m.rustc_version)));
        s.push_str(&format!(
            "Build & {}, opt-level {}, target-cpu {} \\\\\n",
            esc(&m.build_profile),
            esc(&m.opt_level),
            esc(&m.target_cpu)
        ));
        s.push_str(&format!("CPU governor & {} \\\\\n", esc(&m.cpu_governor)));
        s.push_str(&format!("Commit & \\texttt{{{}}} \\\\\n", esc(&m.git_commit)));
        s.push_str(&format!("Emulated & {} \\\\\n", if m.emulated { "yes" } else { "no" }));
        for (name, version) in &m.crypto_crate_versions {
            s.push_str(&format!("\\quad {} & {} \\\\\n", esc(name), esc(version)));
        }
        s.push_str("\\midrule\n");
    }
    s.push_str("\\bottomrule\n\\end{tabular}\n");
    std::fs::write(&path, s)?;
    Ok(path)
}
