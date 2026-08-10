//! Layer 3 criterion benchmarks: escrow, revocation, replay.
//!
//! The headline question: **what does a sound escrow proof cost?** Compare
//! `escrow/check_e1` against `escrow/check_e2`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rapido_bench::fixtures::EscrowFixture;
use rapido_core::{Epoch, EpochClock};
use rapido_crypto::elgamal;
use rapido_proto::{
    escrow::{EscrowConfig, EscrowMode},
    replay::NonceCache,
    revocation::{BloomFilter, Crl, EpochOnly, RevocationCheck},
};
use sha2::{Digest, Sha256};

fn escrow_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("escrow");
    let mut fx = EscrowFixture::new();
    for mode in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
        let cfg = EscrowConfig::new(mode, Some(fx.auth.public()), fx.ped);
        let attachment = cfg
            .attach(fx.identity, fx.blinding, &fx.commitment, b"ctx", &mut fx.rng)
            .expect("attachment succeeds");
        g.bench_function(BenchmarkId::new("attach", mode), |b| {
            b.iter(|| cfg.attach(fx.identity, fx.blinding, &fx.commitment, b"ctx", &mut fx.rng))
        });
        g.bench_function(BenchmarkId::new("check", mode), |b| {
            b.iter(|| cfg.check(&attachment, &fx.commitment, b"ctx"))
        });
    }
    g.finish();
}

fn deanonymize_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("deanonymize");
    let mut fx = EscrowFixture::new();
    let ct = fx.ciphertext;
    g.bench_function("threshold_2of3", |b| {
        b.iter(|| fx.auth.deanonymize(&ct, &[0, 1], b"warrant", 1, &mut fx.rng))
    });
    let key = elgamal::EscrowKey::generate(3, 5, &mut fx.rng).expect("valid parameters");
    let partials: Vec<_> = key.shares.iter().map(|s| elgamal::partial_decrypt(s, &ct)).collect();
    g.bench_function("combine_3of5", |b| {
        b.iter(|| elgamal::combine_decryptions(&partials, &ct, 3))
    });
    g.finish();
}

fn revocation_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("revocation");
    let epoch = Epoch(3);
    let id = |i: usize| Sha256::digest(i.to_be_bytes()).to_vec();

    // R0 is an integer comparison against the current epoch; its cost is not
    // latency but revocation delay, which Scenario 3 measures instead.
    let r0 = EpochOnly::new(epoch, EpochClock::default());
    g.bench_function("r0_epoch_check", |b| b.iter(|| r0.is_revoked(b"cred", epoch)));

    for n in [1_000usize, 10_000, 100_000, 1_000_000] {
        let ids: Vec<Vec<u8>> = (0..n).map(id).collect();
        let miss = id(n * 2);

        let crl = Crl::with_entries(ids.iter().map(|v| v.as_slice()));
        g.bench_with_input(BenchmarkId::new("r1_crl", n), &n, |b, _| {
            b.iter(|| crl.is_revoked(&miss, epoch))
        });

        let mut bloom = BloomFilter::with_capacity(n, 0.01);
        for i in &ids {
            bloom.insert(i);
        }
        g.bench_with_input(BenchmarkId::new("r2_bloom", n), &n, |b, _| {
            b.iter(|| bloom.is_revoked(&miss, epoch))
        });
    }
    g.finish();
}

fn replay_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("replay");
    let epoch = Epoch(1);
    for n in [10_000usize, 1_000_000] {
        let mut cache = NonceCache::new(epoch, n * 4);
        for i in 0..n as u64 {
            cache.check_and_insert(epoch, &i.to_be_bytes()).expect("fresh nonce");
        }
        let mut counter = n as u64;
        g.bench_with_input(BenchmarkId::new("nonce_cache_insert", n), &n, |b, _| {
            b.iter(|| {
                counter += 1;
                cache.check_and_insert(epoch, &counter.to_be_bytes())
            })
        });
    }
    g.finish();
}

criterion_group!(benches, escrow_bench, deanonymize_bench, revocation_bench, replay_bench);
criterion_main!(benches);
