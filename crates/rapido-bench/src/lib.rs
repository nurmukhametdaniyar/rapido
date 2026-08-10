#![forbid(unsafe_code)]
//! `rapido-bench` — criterion micro-benchmarks.
//!
//! These drive `cargo bench` for interactive work: criterion reports the median
//! with a 95% confidence interval and detects regressions between runs.
//!
//! The numbers under `results/` come from `rapido-cli bench` instead, which
//! writes result files carrying the environment-metadata header. The two
//! harnesses measure the same operations through the same APIs; criterion is
//! for development, the CLI is for the committed record.

/// Shared fixture construction, so the criterion benches and the CLI measure
/// identically-constructed inputs.
pub mod fixtures;
