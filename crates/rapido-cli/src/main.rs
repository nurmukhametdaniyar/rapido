#![forbid(unsafe_code)]
//! `rapido-cli` — the experiment runner.
//!
//! ```text
//! rapido-cli bench  --profile <p1|p2> --out results/<profile>/
//! rapido-cli sim    --scenario <1|2|3|4> --seed <n> --out results/<profile>/
//! rapido-cli attack --target <timing|cover|linkability> --out results/<profile>/
//! rapido-cli tables --results results/ --out analysis/tables/
//! ```
//!
//! Every output file is JSON with the environment-metadata header, plus a flat
//! CSV sibling for plotting.

mod benches;
mod harness;
mod pipeline;
mod sims;
mod tables;
mod wire;

use clap::{Parser, Subcommand, ValueEnum};
use rapido_core::{EnvMeta, ResultFile};
use rapido_sim::workload::SystemConfig;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "rapido-cli",
    about = "RAPIDO reference implementation: benchmarks, simulations, and adversary experiments",
    long_about = "Produces the measured numbers for the RAPIDO paper. Every result file carries \
                  a metadata header recording the machine, toolchain, and commit it came from."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum Profile {
    /// x86_64 workstation or laptop.
    P1,
    /// aarch64 single-board computer, used as an on-board-unit proxy.
    P2,
}

impl Profile {
    fn as_str(&self) -> &'static str {
        match self {
            Profile::P1 => "p1",
            Profile::P2 => "p2",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum Target {
    Timing,
    Cover,
    Linkability,
}

#[derive(Subcommand)]
enum Command {
    /// Run every micro-benchmark and write the result files.
    Bench {
        #[arg(long, value_enum, default_value_t = Profile::P1)]
        profile: Profile,
        #[arg(long, default_value = "results/p1")]
        out: PathBuf,
        /// Mark the run as emulated. Timings taken under QEMU are not credible
        /// as absolute latencies, so they are labelled in the result file
        /// rather than silently mixed in with native ones.
        #[arg(long)]
        emulated: bool,
        /// Trim the heaviest sweeps. For smoke tests only — never for a result
        /// that gets committed or cited.
        #[arg(long)]
        quick: bool,
    },
    /// Run a simulation scenario.
    Sim {
        #[arg(long)]
        scenario: u8,
        #[arg(long, value_enum, default_value_t = Profile::P1)]
        profile: Profile,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = sims::DEFAULT_SEEDS)]
        seeds: u64,
        #[arg(long, default_value = "results/p1")]
        out: PathBuf,
        #[arg(long)]
        emulated: bool,
        #[arg(long)]
        quick: bool,
    },
    /// Run an adversary experiment.
    Attack {
        #[arg(long, value_enum)]
        target: Target,
        #[arg(long, value_enum, default_value_t = Profile::P1)]
        profile: Profile,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = sims::DEFAULT_SEEDS)]
        seeds: u64,
        #[arg(long, default_value = "results/p1")]
        out: PathBuf,
        #[arg(long)]
        emulated: bool,
        #[arg(long)]
        quick: bool,
    },
    /// Emit LaTeX tables from committed results.
    Tables {
        #[arg(long, default_value = "results")]
        results: PathBuf,
        #[arg(long, default_value = "analysis/tables")]
        out: PathBuf,
    },
    /// Emit a field-by-field wire-size breakdown of a presentation.
    Wire {
        #[arg(long, value_enum, default_value_t = Profile::P1)]
        profile: Profile,
        /// Mode B attribute count.
        #[arg(long, default_value_t = 8)]
        attributes: usize,
        #[arg(long, default_value = "results/p1")]
        out: PathBuf,
    },
    /// Print the environment metadata that would be recorded, and exit.
    Env {
        #[arg(long, value_enum, default_value_t = Profile::P1)]
        profile: Profile,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Bench { profile, out, emulated, quick } => {
            let meta = EnvMeta::capture(profile.as_str(), emulated);
            warn_if_unpinned(&meta, quick);
            eprintln!("running micro-benchmarks (quick={quick})...");
            let mut all = benches::run_all(quick)?;
            all.extend(benches::shamir_costs());

            // In-path per-layer decomposition. Measured here rather than
            // summed from standalone rows, so a configuration cannot end up
            // with two different totals.
            eprintln!("measuring the in-path pipeline decomposition...");
            let pipeline = pipeline::measure_all()?;
            pipeline::to_csv(&pipeline, &out.join("pipeline_breakdown.csv"))?;
            let pmeta = EnvMeta::capture(profile.as_str(), emulated);
            ResultFile::new(pmeta, "pipeline-breakdown", &pipeline)
                .write_json(&out.join("pipeline_breakdown.json"))?;
            all.extend(pipeline::as_bench_records(&pipeline));
            eprintln!("  {} measurements", all.len());

            write_pair(&out, "bench", meta, &all)?;
            let sizes = benches::wire_sizes()?;
            let meta2 = EnvMeta::capture(profile.as_str(), emulated);
            ResultFile::new(meta2, "wire-sizes", &sizes)
                .write_json(&out.join("wire_sizes.json"))?;
            eprintln!("wrote {}", out.display());
        }

        Command::Sim { scenario, profile, config, seed, seeds, out, emulated, quick } => {
            let system = load_system_config(config.as_deref())?;
            let meta = EnvMeta::capture(profile.as_str(), emulated);
            warn_if_unpinned(&meta, quick);
            let calibration_samples = if quick { 64 } else { 1000 };
            let _ = seed;

            match scenario {
                1 => {
                    let r = sims::scenario1(&system, seeds, calibration_samples, quick)?;
                    write_json(&out, "scenario1_intersection", meta, &r)?;
                    tables::scenario1_csv(&r, &out.join("scenario1_intersection.csv"))?;
                }
                2 => {
                    let r = sims::scenario2(&system, seeds, calibration_samples, quick)?;
                    write_json(&out, "scenario2_metropolitan", meta, &r)?;
                    tables::scenario2_csv(&r, &out.join("scenario2_metropolitan.csv"))?;
                }
                3 => {
                    let r = sims::scenario3(seeds, quick);
                    write_json(&out, "scenario3_connectivity", meta, &r)?;
                    tables::scenario3_csv(&r, &out.join("scenario3_connectivity.csv"))?;
                }
                4 => {
                    let r = sims::scenario4(seeds, quick)?;
                    write_json(&out, "scenario4_linkability", meta, &r)?;
                    tables::scenario4_csv(&r.runs, &out.join("scenario4_linkability.csv"))?;
                }
                other => return Err(format!("unknown scenario {other}; expected 1-4").into()),
            }
            eprintln!("wrote {}", out.display());
        }

        Command::Attack { target, profile, config, seeds, out, emulated, quick } => {
            let _ = config;
            let meta = EnvMeta::capture(profile.as_str(), emulated);
            warn_if_unpinned(&meta, quick);
            match target {
                Target::Timing => {
                    let (r, traces) = sims::timing_attack(seeds, quick)?;
                    write_json(&out, "attack_timing", meta, &r)?;
                    tables::timing_attack_csv(&r, &out.join("attack_timing.csv"))?;
                    // Raw defended release times, so the Python learned
                    // classifier attacks the same data the Rust attacks did.
                    let meta2 = EnvMeta::capture(profile.as_str(), emulated);
                    ResultFile::new(meta2, "attack-timing-traces", &traces)
                        .write_json(&out.join("attack_timing_traces.json"))?;
                }
                Target::Cover => {
                    let r = sims::cover_attack(quick)?;
                    write_json(&out, "attack_cover", meta, &r)?;
                    tables::cover_attack_csv(&r, &out.join("attack_cover.csv"))?;
                }
                Target::Linkability => {
                    let r = sims::linkability_attack(seeds, quick)?;
                    write_json(&out, "attack_linkability", meta, &r)?;
                    tables::scenario4_csv(&r.runs, &out.join("attack_linkability.csv"))?;
                }
            }
            eprintln!("wrote {}", out.display());
        }

        Command::Tables { results, out } => {
            let written = tables::emit_latex(&results, &out)?;
            for p in written {
                eprintln!("wrote {}", p.display());
            }
        }

        Command::Wire { profile, attributes, out } => {
            let report = wire::measure(attributes)?;
            let meta = EnvMeta::capture(profile.as_str(), false);
            write_json(&out, "wire_breakdown", meta, &report)?;
            let md = wire::to_markdown(&report);
            std::fs::write(out.join("wire_breakdown.md"), &md)?;
            println!("{md}");
            for n in &report.notes {
                if n.starts_with("MISMATCH") {
                    return Err(format!("wire accounting is inconsistent: {n}").into());
                }
            }
        }

        Command::Env { profile } => {
            let meta = EnvMeta::capture(profile.as_str(), false);
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
    }
    Ok(())
}

/// Load a system configuration from TOML, or use the default.
fn load_system_config(path: Option<&Path>) -> Result<SystemConfig, Box<dyn std::error::Error>> {
    match path {
        None => Ok(SystemConfig::default()),
        Some(p) => {
            let text = std::fs::read_to_string(p)?;
            Ok(toml::from_str(&text)?)
        }
    }
}

fn write_json<T: serde::Serialize>(
    dir: &Path,
    name: &str,
    meta: EnvMeta,
    data: &T,
) -> rapido_core::Result<()> {
    ResultFile::new(meta, name, data).write_json(&dir.join(format!("{name}.json")))
}

fn write_pair(
    dir: &Path,
    name: &str,
    meta: EnvMeta,
    records: &[harness::BenchRecord],
) -> rapido_core::Result<()> {
    ResultFile::new(meta, name, records).write_json(&dir.join(format!("{name}.json")))?;
    harness::write_csv(records, &dir.join(format!("{name}.csv")))
}

/// The CPU governor state goes into the metadata header, but a reader is not
/// guaranteed to look there. If a run is on a machine where frequency cannot be
/// pinned, say so once, loudly, at the point the numbers are produced.
fn warn_if_unpinned(meta: &EnvMeta, quick: bool) {
    if quick {
        eprintln!(
            "WARNING: --quick trims sweeps and iteration counts. These results are for smoke \
             testing and must not be cited."
        );
    }
    if meta.emulated {
        eprintln!(
            "WARNING: run marked as emulated. Absolute latencies from emulation are not credible \
             and must be labelled as such in any write-up."
        );
    }
    if meta.cpu_governor.starts_with("not-controllable") {
        eprintln!(
            "NOTE: CPU frequency is not pinnable on this platform ({}). Turbo and thermal \
             throttling are uncontrolled; the recorded governor field says so.",
            meta.os
        );
    }
}
