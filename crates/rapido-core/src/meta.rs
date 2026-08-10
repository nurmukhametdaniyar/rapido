//! Environment metadata header.
//!
//! Every result file carries enough provenance to reproduce it: CPU, RAM, OS,
//! kernel, rustc, target triple, opt flags, `target-cpu`, git commit, and the
//! pinned versions of the crypto crates whose speed the numbers depend on.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvMeta {
    pub schema: String,
    pub captured_at_unix: u64,
    pub cpu_model: String,
    pub cpu_cores_physical: Option<u32>,
    pub cpu_cores_logical: u32,
    pub cpu_governor: String,
    pub ram_bytes: Option<u64>,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub target_triple: String,
    pub build_profile: String,
    pub opt_level: String,
    pub rustflags: String,
    pub target_cpu: String,
    pub rustc_version: String,
    pub git_commit: String,
    pub git_dirty: String,
    pub crypto_crate_versions: Vec<(String, String)>,
    /// Set when the run is under emulation rather than on native hardware.
    /// Results carrying `emulated: true` are not credible as absolute
    /// latencies; they are kept only for relative comparisons.
    pub emulated: bool,
    pub profile_label: String,
}

impl EnvMeta {
    /// Collect metadata for the current machine. `profile_label` is `p1`/`p2`.
    pub fn capture(profile_label: &str, emulated: bool) -> Self {
        EnvMeta {
            schema: "rapido-result-v1".into(),
            captured_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            cpu_model: cpu_model(),
            cpu_cores_physical: physical_cores(),
            cpu_cores_logical: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(0),
            cpu_governor: cpu_governor(),
            ram_bytes: ram_bytes(),
            os: os_name(),
            kernel: run("uname", &["-r"]).unwrap_or_else(|| "unknown".into()),
            arch: std::env::consts::ARCH.into(),
            target_triple: env!("RAPIDO_TARGET").into(),
            build_profile: env!("RAPIDO_PROFILE").into(),
            opt_level: env!("RAPIDO_OPT_LEVEL").into(),
            rustflags: env!("RAPIDO_RUSTFLAGS").into(),
            target_cpu: env!("RAPIDO_TARGET_CPU").into(),
            rustc_version: env!("RAPIDO_RUSTC_VERSION").into(),
            git_commit: git_commit(),
            git_dirty: git_dirty(),
            crypto_crate_versions: crypto_crate_versions(),
            emulated,
            profile_label: profile_label.into(),
        }
    }
}

/// A result file: metadata header plus a payload. Written as JSON; the CLI also
/// emits a flat CSV sibling for plotting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultFile<T> {
    pub meta: EnvMeta,
    pub experiment: String,
    pub data: T,
}

impl<T: Serialize> ResultFile<T> {
    pub fn new(meta: EnvMeta, experiment: impl Into<String>, data: T) -> Self {
        ResultFile { meta, experiment: experiment.into(), data }
    }

    pub fn write_json(&self, path: &std::path::Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(f, self).map_err(|e| crate::Error::Io(e.to_string()))?;
        Ok(())
    }
}

// --- platform probes -------------------------------------------------------
//
// Best-effort. Every probe degrades to "unknown" rather than failing the run,
// but the fields are recorded so a reader can tell what was and wasn't captured.

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Commit that produced this run, read at **runtime**.
///
/// Deliberately not a build-time constant: a build script re-runs only when its
/// declared inputs change, so a baked-in hash goes stale after the next commit
/// and the result file would then cite a commit that did not produce it.
fn git_commit() -> String {
    run("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "not-a-git-repo".into())
}

/// Whether the working tree had uncommitted changes at run time.
///
/// `git_dirty: "true"` means the result is **not** reproducible from
/// `git_commit` alone, which is exactly what a reader needs to know.
fn git_dirty() -> String {
    match Command::new("git").args(["status", "--porcelain"]).output() {
        Ok(out) if out.status.success() => {
            if out.stdout.is_empty() {
                "false".into()
            } else {
                "true".into()
            }
        }
        _ => "unknown".into(),
    }
}

fn cpu_model() -> String {
    if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "machdep.cpu.brand_string"])
    } else {
        std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
    }
    .unwrap_or_else(|| "unknown".into())
}

fn physical_cores() -> Option<u32> {
    if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "hw.physicalcpu"])?.parse().ok()
    } else {
        let s = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let n = s
            .lines()
            .filter(|l| l.starts_with("core id"))
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        (n > 0).then_some(n as u32)
    }
}

fn ram_bytes() -> Option<u64> {
    if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "hw.memsize"])?.parse().ok()
    } else {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb: u64 = s
            .lines()
            .find(|l| l.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
}

/// CPU frequency governor / turbo state. Recorded because a timing result is
/// only interpretable alongside the clock policy that produced it.
fn cpu_governor() -> String {
    if cfg!(target_os = "linux") {
        let gov = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .ok()
            .map(|s| s.trim().to_string());
        let turbo = std::fs::read_to_string("/sys/devices/system/cpu/intel_pstate/no_turbo")
            .ok()
            .map(|s| format!(" no_turbo={}", s.trim()))
            .unwrap_or_default();
        match gov {
            Some(g) => format!("{g}{turbo}"),
            None => "unavailable".into(),
        }
    } else {
        // macOS exposes no governor knob; frequency is managed by the SMC and
        // cannot be pinned from userspace. Recorded honestly rather than faked.
        "not-controllable (macOS)".into()
    }
}

fn os_name() -> String {
    if cfg!(target_os = "macos") {
        let v = run("sw_vers", &["-productVersion"]).unwrap_or_else(|| "?".into());
        format!("macOS {v}")
    } else {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_else(|| std::env::consts::OS.into())
    }
}

/// Versions of the crypto crates the numbers depend on, read from the committed
/// `Cargo.lock` so the record matches what was actually linked.
fn crypto_crate_versions() -> Vec<(String, String)> {
    const WATCHED: &[&str] = &[
        "ark-bls12-381",
        "ark-ec",
        "ark-ff",
        "ark-serialize",
        "ark-std",
        "blstrs",
        "blst",
        "ed25519-dalek",
        "p256",
        "num-bigint",
        "sha2",
        "hkdf",
    ];
    let lock = find_cargo_lock().and_then(|p| std::fs::read_to_string(p).ok());
    let Some(lock) = lock else { return vec![] };

    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(v) = line.strip_prefix("name = ") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                if WATCHED.contains(&n.as_str()) {
                    out.push((n, v.trim_matches('"').to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

fn find_cargo_lock() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("Cargo.lock");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Provenance must be self-describing: a reader should be able to tell
    /// whether the run is reproducible from the recorded commit alone.
    #[test]
    fn git_provenance_is_captured_or_explicitly_absent() {
        let m = EnvMeta::capture("p1", false);
        assert!(!m.git_commit.is_empty());
        assert!(
            m.git_commit == "not-a-git-repo" || m.git_commit.len() == 40,
            "git_commit should be a full SHA or the explicit not-a-repo marker, got {:?}",
            m.git_commit
        );
        assert!(
            ["true", "false", "unknown"].contains(&m.git_dirty.as_str()),
            "git_dirty must be tri-state, got {:?}",
            m.git_dirty
        );
    }

    #[test]
    fn capture_populates_build_provenance() {
        let m = EnvMeta::capture("p1", false);
        assert_ne!(m.target_triple, "unknown");
        assert!(m.rustc_version.starts_with("rustc"));
        assert!(m.cpu_cores_logical >= 1);
    }
}
