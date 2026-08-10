//! Measurement harness for the committed result files.
//!
//! Criterion drives `cargo bench` for interactive work. This harness exists
//! separately because the committed result files must be reproducible from one
//! command, must carry the environment metadata header, and must report a
//! median with a 95% confidence interval rather than a mean — a mean over a
//! right-skewed latency distribution is dominated by outliers.
//!
//! Rules enforced here:
//!
//! * warm-up before measurement,
//! * at least 1000 iterations per micro-benchmark,
//! * the confidence interval comes from a **bootstrap over the sample**, which
//!   makes no normality assumption — latency distributions are right-skewed and
//!   a normal interval would understate the upper bound.

use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

/// Minimum iterations per micro-benchmark. Enough that the median is stable
/// against scheduler noise on an unpinned machine.
pub const MIN_ITERATIONS: usize = 1000;
/// Warm-up iterations, discarded.
pub const WARMUP_ITERATIONS: usize = 100;
/// Bootstrap resamples for the confidence interval.
pub const BOOTSTRAP_RESAMPLES: usize = 2000;

/// One measured operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchRecord {
    /// Coarse grouping used by the plotting scripts: `layer1`, `layer3`,
    /// `revocation`, `replay`, `baseline`, `primitive`, `issuance`.
    pub group: String,
    pub name: String,
    /// Free-form parameters (mode, escrow variant, `L`, `|R|`, ...).
    pub params: BTreeMap<String, String>,
    pub iterations: usize,
    pub median_ns: f64,
    pub mean_ns: f64,
    pub ci95_lo_ns: f64,
    pub ci95_hi_ns: f64,
    pub min_ns: f64,
    pub p99_ns: f64,
    /// Bytes on the wire for this operation, where the notion applies.
    pub bytes: Option<usize>,
    /// Memory the operation requires resident, where it applies (CRL, Bloom
    /// filter, nonce cache).
    pub memory_bytes: Option<usize>,
    /// Set when the median came out at zero, i.e. the operation is faster than
    /// the clock can resolve.
    ///
    /// A zero here is not a measurement of "instant"; it means this row cannot
    /// be read as a latency and the batched measurement of the same operation
    /// is the one to cite. Recorded rather than silently emitted as
    /// `0.0000 ms`.
    #[serde(default)]
    pub below_clock_resolution: bool,
}

impl BenchRecord {
    /// Median in milliseconds, the unit the generated tables use.
    pub fn median_ms(&self) -> f64 {
        self.median_ns / 1e6
    }
}

/// Builder for a single measurement.
pub struct Bench<'a> {
    group: &'a str,
    name: &'a str,
    params: BTreeMap<String, String>,
    iterations: usize,
    bytes: Option<usize>,
    memory_bytes: Option<usize>,
}

impl<'a> Bench<'a> {
    pub fn new(group: &'a str, name: &'a str) -> Self {
        Bench {
            group,
            name,
            params: BTreeMap::new(),
            iterations: MIN_ITERATIONS,
            bytes: None,
            memory_bytes: None,
        }
    }

    pub fn param(mut self, k: &str, v: impl std::fmt::Display) -> Self {
        self.params.insert(k.to_string(), v.to_string());
        self
    }

    /// Override the iteration count. Values below [`MIN_ITERATIONS`] are
    /// rejected rather than silently accepted: a quietly under-sampled
    /// benchmark is indistinguishable in the result file from a well-sampled
    /// one. Use [`Bench::slow_operation_iterations`] to go below the floor
    /// deliberately, which records the reduced count in the result file.
    pub fn iterations(mut self, n: usize) -> Self {
        assert!(n >= MIN_ITERATIONS, "at least {MIN_ITERATIONS} iterations are required; got {n}");
        self.iterations = n;
        self
    }

    /// For operations so slow that 1000 iterations is impractical (RSA key
    /// generation, issuing 1000 pseudonyms). The reduced count is recorded in
    /// the result file so a reader can see it.
    pub fn slow_operation_iterations(mut self, n: usize) -> Self {
        assert!(n > 0);
        self.iterations = n;
        self.params.insert("reduced_iterations".into(), "true".into());
        self
    }

    pub fn bytes(mut self, b: usize) -> Self {
        self.bytes = Some(b);
        self
    }

    pub fn memory_bytes(mut self, b: usize) -> Self {
        self.memory_bytes = Some(b);
        self
    }

    /// Run `f`, timing each iteration separately.
    ///
    /// `f`'s return value is fed to [`black_box`] so the optimizer cannot
    /// delete the work being measured.
    pub fn run<T>(self, mut f: impl FnMut() -> T) -> BenchRecord {
        for _ in 0..WARMUP_ITERATIONS {
            std::hint::black_box(f());
        }
        let mut samples = Vec::with_capacity(self.iterations);
        for _ in 0..self.iterations {
            let t0 = Instant::now();
            let out = f();
            let dt = t0.elapsed();
            std::hint::black_box(out);
            samples.push(dt.as_nanos() as f64);
        }
        self.finish(samples)
    }

    /// Run a batch of `batch_size` operations per timed sample, dividing the
    /// elapsed time by the batch size.
    ///
    /// Necessary for operations faster than the clock's resolution — an
    /// integer comparison (R0) measured one at a time is dominated by
    /// `Instant::now` itself.
    pub fn run_batched<T>(self, batch_size: usize, mut f: impl FnMut() -> T) -> BenchRecord {
        assert!(batch_size > 0);
        for _ in 0..WARMUP_ITERATIONS {
            std::hint::black_box(f());
        }
        let mut samples = Vec::with_capacity(self.iterations);
        for _ in 0..self.iterations {
            let t0 = Instant::now();
            for _ in 0..batch_size {
                std::hint::black_box(f());
            }
            samples.push(t0.elapsed().as_nanos() as f64 / batch_size as f64);
        }
        let mut rec = self.finish(samples);
        rec.params.insert("batch_size".into(), batch_size.to_string());
        rec
    }

    #[cfg_attr(not(test), doc(hidden))]
    fn finish(self, mut samples: Vec<f64>) -> BenchRecord {
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        samples.sort_by(|a, b| a.partial_cmp(b).expect("timings are finite"));
        let median = quantile(&samples, 0.5);
        let (lo, hi) = bootstrap_median_ci(&samples);
        BenchRecord {
            group: self.group.to_string(),
            name: self.name.to_string(),
            params: self.params,
            iterations: samples.len(),
            median_ns: median,
            mean_ns: mean,
            ci95_lo_ns: lo,
            ci95_hi_ns: hi,
            min_ns: samples[0],
            p99_ns: quantile(&samples, 0.99),
            bytes: self.bytes,
            memory_bytes: self.memory_bytes,
            below_clock_resolution: median == 0.0,
        }
    }
}

/// Quantile of a **sorted** slice, by nearest rank.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Percentile bootstrap 95% CI for the median.
///
/// Deterministically seeded so re-running the analysis on the same samples
/// gives the same interval.
pub fn bootstrap_median_ci(sorted: &[f64]) -> (f64, f64) {
    if sorted.len() < 2 {
        return (sorted.first().copied().unwrap_or(0.0), sorted.first().copied().unwrap_or(0.0));
    }
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB007_5747);
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut buf = vec![0.0f64; sorted.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for slot in buf.iter_mut() {
            *slot = sorted[rng.gen_range(0..sorted.len())];
        }
        buf.sort_by(|a, b| a.partial_cmp(b).expect("timings are finite"));
        medians.push(quantile(&buf, 0.5));
    }
    medians.sort_by(|a, b| a.partial_cmp(b).expect("medians are finite"));
    (quantile(&medians, 0.025), quantile(&medians, 0.975))
}

/// Write records as a flat CSV alongside the JSON.
pub fn write_csv(records: &[BenchRecord], path: &std::path::Path) -> rapido_core::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Union of all parameter keys, so every row has the same columns.
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in records {
        keys.extend(r.params.keys().cloned());
    }

    let mut w = csv::Writer::from_path(path).map_err(|e| rapido_core::Error::Io(e.to_string()))?;
    let mut header = vec![
        "group".to_string(),
        "name".to_string(),
        "iterations".to_string(),
        "median_ns".to_string(),
        "mean_ns".to_string(),
        "ci95_lo_ns".to_string(),
        "ci95_hi_ns".to_string(),
        "min_ns".to_string(),
        "p99_ns".to_string(),
        "bytes".to_string(),
        "memory_bytes".to_string(),
        "below_clock_resolution".to_string(),
    ];
    header.extend(keys.iter().cloned());
    w.write_record(&header).map_err(|e| rapido_core::Error::Io(e.to_string()))?;

    for r in records {
        let mut row = vec![
            r.group.clone(),
            r.name.clone(),
            r.iterations.to_string(),
            format!("{:.3}", r.median_ns),
            format!("{:.3}", r.mean_ns),
            format!("{:.3}", r.ci95_lo_ns),
            format!("{:.3}", r.ci95_hi_ns),
            format!("{:.3}", r.min_ns),
            format!("{:.3}", r.p99_ns),
            r.bytes.map(|b| b.to_string()).unwrap_or_default(),
            r.memory_bytes.map(|b| b.to_string()).unwrap_or_default(),
            r.below_clock_resolution.to_string(),
        ];
        for k in &keys {
            row.push(r.params.get(k).cloned().unwrap_or_default());
        }
        w.write_record(&row).map_err(|e| rapido_core::Error::Io(e.to_string()))?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_of_a_sorted_slice() {
        let xs: Vec<f64> = (0..=100).map(|i| i as f64).collect();
        assert_eq!(quantile(&xs, 0.0), 0.0);
        assert_eq!(quantile(&xs, 0.5), 50.0);
        assert_eq!(quantile(&xs, 1.0), 100.0);
    }

    #[test]
    fn bootstrap_interval_brackets_the_median_and_is_deterministic() {
        let xs: Vec<f64> = (0..1000).map(|i| (i % 100) as f64).collect();
        let mut sorted = xs.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (lo, hi) = bootstrap_median_ci(&sorted);
        let median = quantile(&sorted, 0.5);
        assert!(lo <= median && median <= hi, "median {median} outside [{lo}, {hi}]");
        assert_eq!(bootstrap_median_ci(&sorted), (lo, hi), "CI must be reproducible");
    }

    #[test]
    fn a_measurement_records_the_required_statistics() {
        // Deliberately not a trivial closure: an operation faster than the
        // clock's granularity measures as 0 ns, which would make this test
        // pass or fail depending on machine load. Hashing 4 KiB is always
        // above the timer floor.
        let data = vec![0xa5u8; 4096];
        let r = Bench::new("test", "sha256-4k")
            .param("kind", "hash")
            .run(|| <sha2::Sha256 as sha2::Digest>::digest(&data));
        assert_eq!(r.iterations, MIN_ITERATIONS);
        assert!(r.median_ns > 0.0);
        assert!(!r.below_clock_resolution);
        assert!(r.ci95_lo_ns <= r.median_ns && r.median_ns <= r.ci95_hi_ns);
        assert_eq!(r.params["kind"], "hash");
    }

    /// Racing two live measurements against each other would be flaky under
    /// load, so the division itself is checked against a synthetic sample set
    /// rather than against the clock.
    #[test]
    fn batched_measurement_divides_by_the_batch_size() {
        let batched =
            Bench::new("test", "batched").run_batched(1000, || std::hint::black_box(1u64 + 1));
        assert_eq!(batched.params["batch_size"], "1000");
        assert_eq!(batched.iterations, MIN_ITERATIONS);
        // Per-operation time, not per-batch: an addition cannot take a
        // microsecond, so a missing division would show up immediately.
        assert!(batched.median_ns < 1_000.0, "median {} looks undivided", batched.median_ns);
    }

    /// An operation faster than the clock reports a median of zero. That must
    /// be *visible* in the result file rather than silently published as
    /// "0.0000 ms" — the flag is what tells a reader to look for a batched
    /// measurement of the same operation instead.
    #[test]
    fn sub_clock_resolution_measurements_are_flagged() {
        let below = Bench::new("test", "noop").finish(vec![0.0; MIN_ITERATIONS]);
        assert!(below.below_clock_resolution);
        assert_eq!(below.median_ns, 0.0);

        let above = Bench::new("test", "real").finish(vec![42.0; MIN_ITERATIONS]);
        assert!(!above.below_clock_resolution);
    }

    #[test]
    #[should_panic(expected = "at least 1000 iterations")]
    fn too_few_iterations_is_rejected() {
        Bench::new("test", "x").iterations(10);
    }

    #[test]
    fn csv_has_one_column_set_across_heterogeneous_records() {
        let dir = std::env::temp_dir().join("rapido-harness-test");
        let path = dir.join("out.csv");
        let mut a = Bench::new("g", "a").param("mode", "A").run(|| 1u8);
        let b = Bench::new("g", "b").param("epsilon", "1.0").run(|| 2u8);
        a.params.insert("mode".into(), "A".into());
        write_csv(&[a, b], &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let header = text.lines().next().unwrap();
        assert!(header.contains("epsilon") && header.contains("mode"));
        assert_eq!(text.lines().count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
