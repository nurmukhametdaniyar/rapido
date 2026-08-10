//! Layer 1 criterion benchmarks: Mode A vs Mode B.
//!
//! The headline question these answer: **what does issuer-unlinkability
//! cost?** Run `cargo bench --bench layer1` and compare
//! `mode_a/verify_aggregate` against `mode_b/verify` at the same escrow
//! variant.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rapido_bench::fixtures::{ModeAFixture, ModeBFixture};
use rapido_crypto::rng_from_seed;
use rapido_proto::{escrow::EscrowMode, mode_a, mode_b, verifier::VerifyPath};

fn mode_a_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("mode_a");
    for escrow in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
        let (mut fx, cfg) = ModeAFixture::new(512, escrow);
        let pres = fx.presentation(&cfg);
        let pk = fx.authority.public_key();
        g.throughput(Throughput::Bytes(pres.size_bytes() as u64));

        g.bench_with_input(BenchmarkId::new("present", escrow), &escrow, |b, _| {
            b.iter(|| fx.presentation(&cfg))
        });
        g.bench_with_input(BenchmarkId::new("verify_naive", escrow), &escrow, |b, _| {
            b.iter(|| mode_a::verify_naive(&pk, &pres, b"c", b"rsu"))
        });
        let mut rng = rng_from_seed(1);
        g.bench_with_input(BenchmarkId::new("verify_aggregate", escrow), &escrow, |b, _| {
            b.iter(|| mode_a::verify_aggregate(&pk, &pres, b"c", b"rsu", &mut rng))
        });
    }
    let _ = VerifyPath::Aggregate;
    g.finish();
}

fn mode_b_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("mode_b");
    for l in [4usize, 8, 16, 32] {
        for frac in [0.0f64, 0.25, 0.5] {
            for escrow in [EscrowMode::E0, EscrowMode::E2] {
                let (mut fx, cfg) = ModeBFixture::new(l, frac, escrow);
                let pres = fx.presentation(&cfg);
                let id = format!("L{l}_disclose{}_", (frac * 100.0) as u32);

                g.bench_function(BenchmarkId::new("present", format!("{id}{escrow}")), |b| {
                    b.iter(|| fx.presentation(&cfg))
                });
                g.bench_function(BenchmarkId::new("verify", format!("{id}{escrow}")), |b| {
                    b.iter(|| {
                        mode_b::verify(&fx.issuer.params, &fx.issuer.pk, &pres, b"c", b"rsu", &cfg)
                    })
                });
            }
        }
    }
    g.finish();
}

fn issuance_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("issuance");
    // Batch sizes bracket the "100 pseudonyms per epoch" operating point.
    // Provisioning is slow enough that criterion's default sample count would
    // make the bench run for minutes.
    g.sample_size(10);
    for n_batch in [10usize, 50, 100, 500] {
        let (fx, _cfg) = ModeAFixture::new(1, EscrowMode::E0);
        let mut rng = rng_from_seed(2);
        g.bench_with_input(BenchmarkId::new("mode_a_batch", n_batch), &n_batch, |b, &n| {
            b.iter(|| {
                mode_a::provision(
                    &fx.authority,
                    &fx.agent,
                    rapido_bench::fixtures::EPOCH,
                    n,
                    &mut rng,
                )
            })
        });
    }
    g.finish();
}

criterion_group!(benches, mode_a_bench, mode_b_bench, issuance_bench);
criterion_main!(benches);
