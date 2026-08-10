//! Baseline criterion benchmarks.
//!
//! Every comparison system, measured on the same hardware in the same process
//! as RAPIDO. The CL-RSA row is the one that sets RAPIDO's speedup over
//! anonymous credentials.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigUint;
use rapido_baselines::{cl_rsa, mtls, scms};
use rapido_crypto::rng_from_seed;

fn mtls_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("mtls");
    let mut rng = rng_from_seed(1);
    let ed = mtls::ed25519::setup(&mut rng);
    let ed_sig = ed.sign_challenge(b"challenge");
    g.bench_function("ed25519_chain_depth2", |b| {
        b.iter(|| mtls::ed25519::verify(&ed, b"challenge", &ed_sig))
    });
    let p = mtls::p256_ecdsa::setup(&mut rng);
    let p_sig = p.sign_challenge(b"challenge");
    g.bench_function("p256_chain_depth2", |b| {
        b.iter(|| mtls::p256_ecdsa::verify(&p, b"challenge", &p_sig))
    });
    g.finish();
}

fn scms_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("scms");
    let mut rng = rng_from_seed(2);
    let ca = scms::PseudonymCa::generate(&mut rng);

    let explicit = scms::explicit::issue(&ca, 7, &mut rng);
    let esig = explicit.sign(b"bsm");
    g.bench_function("explicit_verify", |b| {
        b.iter(|| scms::explicit::verify(&ca.public, &explicit.cert, b"bsm", &esig))
    });

    let implicit = scms::implicit::issue(&ca, 7, b"agent-01", &mut rng);
    let isig = implicit.sign(b"bsm");
    g.bench_function("implicit_ecqv_verify", |b| {
        b.iter(|| scms::implicit::verify(&ca.public, &implicit.cert, b"bsm", &isig))
    });
    g.bench_function("implicit_ecqv_reconstruct", |b| {
        b.iter(|| scms::implicit::reconstruct(&ca.public, &implicit.cert))
    });
    g.finish();
}

fn cl_rsa_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("cl_rsa");
    // Key generation is minutes-scale; keep the sample count low.
    g.sample_size(20);
    let mut rng = rng_from_seed(3);
    for l in [5usize, 10] {
        let sk = cl_rsa::SecretKey::generate(l, &mut rng);
        let msgs: Vec<BigUint> =
            (0..l).map(|i| cl_rsa::message_from_bytes(format!("a{i}").as_bytes())).collect();
        let sig = sk.sign(&msgs, &mut rng).expect("issuance succeeds");
        for n_disclosed in [0usize, l / 2] {
            let disclose: Vec<usize> = (0..n_disclosed).collect();
            let pres = cl_rsa::present(&sk.public, &msgs, &sig, &disclose, b"n", &mut rng)
                .expect("presentation succeeds");
            let id = format!("L{l}_disclosed{n_disclosed}");
            g.bench_function(BenchmarkId::new("present", &id), |b| {
                b.iter(|| cl_rsa::present(&sk.public, &msgs, &sig, &disclose, b"n", &mut rng))
            });
            g.bench_function(BenchmarkId::new("verify", &id), |b| {
                b.iter(|| cl_rsa::verify_presentation(&sk.public, &pres, b"n"))
            });
        }
    }
    g.finish();
}

criterion_group!(benches, mtls_bench, scms_bench, cl_rsa_bench);
criterion_main!(benches);
