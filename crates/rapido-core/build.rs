//! Captures build-time provenance for the result-file metadata header:
//! target triple, opt flags, `target-cpu`, rustc version.
//!
//! The **git commit is deliberately not captured here.** A build script only
//! re-runs when one of its declared dependencies changes, so a commit hash
//! baked in at first build would go stale on every subsequent commit — and a
//! result file that cites the wrong commit is worse than one that cites none.
//! The commit is read at runtime instead; see `meta.rs`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    emit("RAPIDO_TARGET", std::env::var("TARGET").unwrap_or_else(|_| "unknown".into()));
    emit("RAPIDO_PROFILE", std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into()));
    emit("RAPIDO_OPT_LEVEL", std::env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".into()));

    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .map(|s| s.split('\u{1f}').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let target_cpu = flags
        .split_whitespace()
        .find_map(|f| f.strip_prefix("target-cpu=").map(str::to_string))
        .unwrap_or_else(|| "default".into());
    emit("RAPIDO_RUSTFLAGS", flags);
    emit("RAPIDO_TARGET_CPU", target_cpu);

    emit("RAPIDO_RUSTC_VERSION", run("rustc", &["--version"]).unwrap_or_else(|| "unknown".into()));
}

fn emit(key: &str, val: String) {
    println!("cargo:rustc-env={key}={val}");
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
