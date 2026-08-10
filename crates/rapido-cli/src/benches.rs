//! Every micro-benchmark the generated tables draw on.
//!
//! Organized by the `group` field so the plotting scripts can select without
//! string-matching on names:
//!
//! * `primitive` — BLS, hash-to-curve, threshold combine
//! * `issuance` — Mode A batch issuance across `n_batch`, Mode B issuance
//! * `layer1` — credential presentation and verification, both modes
//! * `layer3` — escrow E0/E1/E2, threshold decryption, audit log
//! * `revocation` — R0/R1/R2 across `|R|`
//! * `replay` — nonce cache
//! * `baseline` — mTLS, SCMS, CL-RSA

use crate::harness::{Bench, BenchRecord};
use rapido_baselines::{cl_rsa, mtls, scms};
use rapido_core::{dst, Epoch, EpochClock};
use rapido_crypto::{bbs, bls, elgamal, hash, pedersen, rng_from_seed, shamir, Fr};
use rapido_privacy::{
    mechanism::{EventKind, MBucket, MGeo, MPad, TimingMechanism},
    Sensitivity,
};
use rapido_proto::{
    escrow::{EscrowAuthorities, EscrowConfig, EscrowMode},
    mode_a, mode_b,
    replay::NonceCache,
    revocation::{BloomFilter, Crl, EpochOnly, LinearCrl, RevocationCheck},
    verifier::{self, VerifyPath},
    Mode,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Reduced iteration counts for operations where 1000 repetitions would take
/// minutes. Recorded in the result file via `reduced_iterations`.
const SLOW_ITERS: usize = 30;
const MEDIUM_ITERS: usize = 200;
/// Pseudonyms provisioned before a presentation benchmark: warm-up plus the
/// measured iterations, with headroom, so re-provisioning never lands inside a
/// timed sample.
const PRESENT_BATCH: usize = 1300;

/// Run everything. `quick` trims the heaviest sweeps for smoke-testing.
pub fn run_all(quick: bool) -> rapido_core::Result<Vec<BenchRecord>> {
    let mut out = Vec::new();
    out.extend(primitives());
    out.extend(issuance(quick)?);
    out.extend(layer1(quick)?);
    out.extend(layer3()?);
    out.extend(revocation(quick));
    out.extend(replay(quick));
    out.extend(timing_mechanisms());
    out.extend(baselines(quick));
    Ok(out)
}

// --- primitives ------------------------------------------------------------

pub fn primitives() -> Vec<BenchRecord> {
    let mut rng = rng_from_seed(1);
    let sk = bls::SecretKey::random(&mut rng);
    let pk = sk.public();
    let msg = b"RAPIDO benchmark message";
    let sig = bls::sign(&sk, dst::PRESENT, msg);
    let mut out = vec![
        Bench::new("primitive", "hash-to-g2")
            .param("backend", "arkworks")
            .run(|| hash::hash_to_g2(dst::PRESENT, msg)),
        Bench::new("primitive", "hash-to-g1")
            .param("backend", "arkworks")
            .run(|| hash::hash_to_g1(dst::BBS_GEN, msg)),
        Bench::new("primitive", "bls-sign")
            .param("backend", "arkworks")
            .run(|| bls::sign(&sk, dst::PRESENT, msg)),
        Bench::new("primitive", "bls-verify")
            .param("backend", "arkworks")
            .run(|| bls::verify(&pk, dst::PRESENT, msg, &sig)),
    ];

    // Batch verification amortizes the final exponentiation across many
    // signatures, so `n` is swept and the per-signature cost is what the tables
    // report — the cost of a single batched call scales with `n` and says
    // nothing on its own.
    for n in [1usize, 10, 50, 100] {
        let sks: Vec<bls::SecretKey> = (0..n).map(|_| bls::SecretKey::random(&mut rng)).collect();
        let msgs: Vec<Vec<u8>> = (0..n).map(|i| format!("msg-{i}").into_bytes()).collect();
        let sigs: Vec<bls::Signature> =
            sks.iter().zip(&msgs).map(|(sk, m)| bls::sign(sk, dst::PRESENT, m)).collect();
        let triples: Vec<(bls::PublicKey, rapido_core::Dst, &[u8], bls::Signature)> = sks
            .iter()
            .zip(&msgs)
            .zip(&sigs)
            .map(|((sk, m), s)| (sk.public(), dst::PRESENT, m.as_slice(), *s))
            .collect();
        let mut brng = rng_from_seed(99);
        out.push(
            Bench::new("primitive", "bls-batch-verify")
                .param("n", n)
                .param("backend", "arkworks")
                .run(|| bls::batch_verify(&triples, &mut brng)),
        );
    }

    // Threshold BLS: partial signing and Lagrange combination.
    for (k, n) in [(2usize, 3usize), (3, 5), (5, 9)] {
        let tk = bls::ThresholdKey::generate(k, n, &mut rng).expect("valid threshold parameters");
        let partials: Vec<bls::PartialSignature> =
            tk.shares.iter().map(|s| bls::partial_sign(s, dst::CRED, msg)).collect();
        out.push(
            Bench::new("primitive", "threshold-bls-partial-sign")
                .param("k", k)
                .param("n", n)
                .run(|| bls::partial_sign(&tk.shares[0], dst::CRED, msg)),
        );
        out.push(
            Bench::new("primitive", "threshold-bls-combine")
                .param("k", k)
                .param("n", n)
                .run(|| bls::combine(&partials, k)),
        );
    }

    #[cfg(feature = "blst-backend")]
    {
        use ark_ff::{BigInteger, PrimeField};
        use rapido_crypto::blst_backend as blst;
        let be = sk.0.into_bigint().to_bytes_be();
        let mut bytes = [0u8; 32];
        bytes[32 - be.len()..].copy_from_slice(&be);
        let bsk = blst::SecretKey::from_be_bytes(&bytes).expect("canonical scalar");
        let bpk = bsk.public();
        let bsig = blst::sign(&bsk, dst::PRESENT, msg);
        out.push(
            Bench::new("primitive", "bls-sign")
                .param("backend", "blst")
                .run(|| blst::sign(&bsk, dst::PRESENT, msg)),
        );
        out.push(
            Bench::new("primitive", "bls-verify")
                .param("backend", "blst")
                .run(|| blst::verify(&bpk, dst::PRESENT, msg, &bsig)),
        );
        out.push(
            Bench::new("primitive", "hash-to-g2")
                .param("backend", "blst")
                .run(|| blst::hash_to_g2(dst::PRESENT, msg)),
        );
    }

    out
}

// --- issuance --------------------------------------------------------------

/// Batch issuance cost as a function of `n_batch`. The sweep brackets the
/// nominal operating point of 100 pseudonyms per epoch, so the per-token cost
/// and its scaling are both visible rather than assumed linear.
pub fn issuance(quick: bool) -> rapido_core::Result<Vec<BenchRecord>> {
    let mut rng = rng_from_seed(2);
    let authority = mode_a::Authority::generate(3, 5, &mut rng)?;
    let agent = mode_a::Agent::new(&authority.pedersen, elgamal::identity_scalar(b"a"), &mut rng);
    let mut out = Vec::new();

    let batches: &[usize] = if quick { &[10, 100] } else { &[10, 50, 100, 500, 1000] };
    for &n_batch in batches {
        let mut irng = rng_from_seed(3);
        out.push(
            Bench::new("issuance", "mode-a-issue-batch")
                .param("mode", Mode::A)
                .param("n_batch", n_batch)
                .param("k", 3)
                .param("n_authorities", 5)
                .bytes(mode_a::issuance_download_bytes(n_batch))
                .slow_operation_iterations(if n_batch >= 500 { 5 } else { SLOW_ITERS })
                .run(|| mode_a::provision(&authority, &agent, Epoch(1), n_batch, &mut irng)),
        );
        // Agent-side key derivation and proof of possession, separately, so the
        // split between agent and authority work is visible.
        let mut arng = rng_from_seed(4);
        let _ = &mut arng;
        out.push(
            Bench::new("issuance", "mode-a-agent-request-batch")
                .param("mode", Mode::A)
                .param("n_batch", n_batch)
                .bytes(mode_a::issuance_upload_bytes(n_batch))
                .slow_operation_iterations(if n_batch >= 500 { 10 } else { SLOW_ITERS })
                .run(|| agent.request_batch(Epoch(1), n_batch)),
        );
    }

    let attrs: &[usize] = if quick { &[8] } else { &[4, 8, 16, 32] };
    for &l in attrs {
        let issuer = mode_b::Issuer::generate(l, &mut rng)?;
        let app: Vec<Fr> = (0..l - mode_b::ATTR_FIRST_APP)
            .map(|i| bbs::message_from_bytes(format!("a{i}").as_bytes()))
            .collect();
        let mut irng = rng_from_seed(5);
        out.push(
            Bench::new("issuance", "mode-b-issue-credential")
                .param("mode", Mode::B)
                .param("L", l)
                .bytes(mode_b::issuance_download_bytes(l))
                .run(|| {
                    mode_b::issue(
                        &issuer,
                        elgamal::identity_scalar(b"a"),
                        Epoch(1),
                        &app,
                        &mut irng,
                    )
                }),
        );
    }
    Ok(out)
}

// --- Layer 1 ---------------------------------------------------------------

pub fn layer1(quick: bool) -> rapido_core::Result<Vec<BenchRecord>> {
    let mut out = Vec::new();
    let epoch = Epoch(1);
    let clock = EpochClock::default();
    let revocation = EpochOnly::new(epoch, clock);

    // --- Mode A ---
    let mut rng = rng_from_seed(6);
    let mut escrow_auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    let identity = escrow_auth.registry.enrol(b"bench-agent");
    let authority = mode_a::Authority::generate(3, 5, &mut rng)?;
    let agent = mode_a::Agent::new(&authority.pedersen, identity, &mut rng);
    let pk = authority.public_key();

    for escrow_mode in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
        let cfg =
            EscrowConfig::new(escrow_mode, Some(escrow_auth.public()), pedersen::Params::default());

        // Presentation (agent side).
        let mut prng = rng_from_seed(7);
        let mut batch = mode_a::provision(&authority, &agent, epoch, PRESENT_BATCH, &mut prng)?;
        let sample = mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg, &mut prng)?;
        let bytes = sample.size_bytes();
        out.push(
            Bench::new("layer1", "mode-a-present")
                .param("mode", Mode::A)
                .param("escrow", escrow_mode)
                .bytes(bytes)
                .run(|| {
                    if batch.is_exhausted() {
                        batch =
                            mode_a::provision(&authority, &agent, epoch, PRESENT_BATCH, &mut prng)
                                .expect("re-provisioning succeeds");
                    }
                    mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg, &mut prng)
                }),
        );

        for path in [VerifyPath::Naive, VerifyPath::Aggregate] {
            let mut vrng = rng_from_seed(8);
            let name = match path {
                VerifyPath::Naive => "mode-a-verify-naive",
                VerifyPath::Aggregate => "mode-a-verify-aggregate",
            };
            out.push(
                Bench::new("layer1", name)
                    .param("mode", Mode::A)
                    .param("escrow", escrow_mode)
                    .param("path", format!("{path:?}").to_lowercase())
                    .bytes(bytes)
                    .run(|| match path {
                        VerifyPath::Naive => mode_a::verify_naive(&pk, &sample, b"c", b"rsu"),
                        VerifyPath::Aggregate => {
                            mode_a::verify_aggregate(&pk, &sample, b"c", b"rsu", &mut vrng)
                        }
                    }),
            );
        }

        // Full pipeline through the verifier, which is what the per-layer
        // decomposition is built from. Layers and total therefore come from the
        // same execution and cannot disagree with each other.
        //
        // The nonce cache is constructed fresh per iteration, because the same
        // presentation is verified repeatedly and a persistent cache would
        // reject every repeat as a replay. `HashSet::new` does not allocate
        // until first insert, so the overhead is one small allocation on a
        // millisecond-scale measurement — but it does mean the replay lookup
        // here is measured against an *empty* cache, i.e. its best case. The
        // realistic replay cost at 10^4 and 10^6 entries is measured
        // separately by `nonce-cache-insert`, and that is the row Table 2
        // draws on.
        let mut vrng = rng_from_seed(9);
        out.push(
            Bench::new("layer1", "mode-a-verify-full-pipeline")
                .param("mode", Mode::A)
                .param("escrow", escrow_mode)
                .bytes(bytes)
                .run(|| {
                    let mut nonces = NonceCache::new(epoch, 1 << 20);
                    verifier::verify_mode_a(
                        &pk,
                        &sample,
                        b"c",
                        b"rsu",
                        VerifyPath::Aggregate,
                        &cfg,
                        &revocation,
                        &mut nonces,
                        &mut vrng,
                    )
                }),
        );
    }

    // Batched verification across many presentations: the RSU's real workload.
    let cfg0 = EscrowConfig::new(EscrowMode::E0, None, pedersen::Params::default());
    let mut prng = rng_from_seed(10);
    let mut batch = mode_a::provision(&authority, &agent, epoch, 200, &mut prng)?;
    let presentations: Vec<mode_a::Presentation> = (0..100)
        .map(|_| mode_a::present(&agent, &mut batch, b"c", b"rsu", &cfg0, &mut prng))
        .collect::<rapido_core::Result<_>>()?;
    for n in [1usize, 10, 50, 100] {
        let items: Vec<(&mode_a::Presentation, &[u8], &[u8])> =
            presentations[..n].iter().map(|p| (p, b"c".as_slice(), b"rsu".as_slice())).collect();
        let mut vrng = rng_from_seed(11);
        out.push(
            Bench::new("layer1", "mode-a-verify-batched")
                .param("mode", Mode::A)
                .param("n", n)
                .run(|| mode_a::verify_batch(&pk, &items, &mut vrng)),
        );
    }

    // --- Mode B: sweep L and the disclosure fraction ---
    let attrs: &[usize] = if quick { &[8] } else { &[4, 8, 16, 32] };
    let fractions: &[f64] = &[0.0, 0.25, 0.5];
    for &l in attrs {
        let mut brng = rng_from_seed(12);
        let issuer = mode_b::Issuer::generate(l, &mut brng)?;
        let app: Vec<Fr> = (0..l - mode_b::ATTR_FIRST_APP)
            .map(|i| bbs::message_from_bytes(format!("a{i}").as_bytes()))
            .collect();
        let cred = mode_b::issue(&issuer, identity, epoch, &app, &mut brng)?;

        for &frac in fractions {
            // The fraction applies to the application attributes; the identity
            // is always hidden and the epoch is always disclosed.
            let n_app = l - mode_b::ATTR_FIRST_APP;
            let n_disclosed = (frac * n_app as f64).round() as usize;
            let disclose: BTreeSet<usize> =
                (0..n_disclosed).map(|i| mode_b::ATTR_FIRST_APP + i).collect();

            for escrow_mode in [EscrowMode::E0, EscrowMode::E2] {
                let cfg = EscrowConfig::new(
                    escrow_mode,
                    Some(escrow_auth.public()),
                    pedersen::Params::default(),
                );
                let mut prng = rng_from_seed(13);
                let sample = mode_b::present(
                    &issuer.params,
                    &issuer.pk,
                    &cred,
                    &disclose,
                    b"c",
                    b"rsu",
                    &cfg,
                    &mut prng,
                )?;
                let bytes = sample.size_bytes();

                out.push(
                    Bench::new("layer1", "mode-b-present")
                        .param("mode", Mode::B)
                        .param("L", l)
                        .param("disclosure_fraction", frac)
                        .param("n_disclosed", n_disclosed)
                        .param("escrow", escrow_mode)
                        .bytes(bytes)
                        .run(|| {
                            mode_b::present(
                                &issuer.params,
                                &issuer.pk,
                                &cred,
                                &disclose,
                                b"c",
                                b"rsu",
                                &cfg,
                                &mut prng,
                            )
                        }),
                );
                out.push(
                    Bench::new("layer1", "mode-b-verify")
                        .param("mode", Mode::B)
                        .param("L", l)
                        .param("disclosure_fraction", frac)
                        .param("n_disclosed", n_disclosed)
                        .param("escrow", escrow_mode)
                        .bytes(bytes)
                        .run(|| {
                            mode_b::verify(&issuer.params, &issuer.pk, &sample, b"c", b"rsu", &cfg)
                        }),
                );
                out.push(
                    Bench::new("layer1", "mode-b-verify-full-pipeline")
                        .param("mode", Mode::B)
                        .param("L", l)
                        .param("disclosure_fraction", frac)
                        .param("escrow", escrow_mode)
                        .bytes(bytes)
                        .run(|| {
                            let mut nonces = NonceCache::new(epoch, 1 << 20);
                            verifier::verify_mode_b(
                                &issuer.params,
                                &issuer.pk,
                                &sample,
                                b"c",
                                b"rsu",
                                &cfg,
                                &revocation,
                                &mut nonces,
                            )
                        }),
                );
            }
        }
    }
    let _ = &mut escrow_auth;
    Ok(out)
}

// --- Layer 3 ---------------------------------------------------------------

pub fn layer3() -> rapido_core::Result<Vec<BenchRecord>> {
    let mut rng = rng_from_seed(14);
    let mut out = Vec::new();
    let ped = pedersen::Params::default();
    let mut auth = EscrowAuthorities::generate(2, 3, &mut rng)?;
    let id = auth.registry.enrol(b"escrow-bench");
    let (commitment, opening) = ped.commit_random(id, &mut rng);

    // E0/E1/E2 attach and check, in isolation. The E2 - E1 difference is the
    // price of a sound escrow, and isolating it here keeps it separate from the
    // cost of attaching a ciphertext at all.
    for mode in [EscrowMode::E0, EscrowMode::E1, EscrowMode::E2] {
        let cfg = EscrowConfig::new(mode, Some(auth.public()), ped);
        let mut arng = rng_from_seed(15);
        let attachment = cfg.attach(id, opening.blinding, &commitment, b"ctx", &mut arng)?;
        out.push(
            Bench::new("layer3", "escrow-attach")
                .param("escrow", mode)
                .bytes(attachment.size_bytes())
                .run(|| cfg.attach(id, opening.blinding, &commitment, b"ctx", &mut arng)),
        );
        out.push(
            Bench::new("layer3", "escrow-check")
                .param("escrow", mode)
                .bytes(attachment.size_bytes())
                .run(|| cfg.check(&attachment, &commitment, b"ctx")),
        );
    }

    // Threshold de-anonymization.
    let (ct, _r) = elgamal::encrypt(auth.public(), elgamal::identity_point(id), &mut rng);
    for (k, n) in [(2usize, 3usize), (3, 5)] {
        let key = elgamal::EscrowKey::generate(k, n, &mut rng)?;
        let (ct_k, _) = elgamal::encrypt(key.public, elgamal::identity_point(id), &mut rng);
        let partials: Vec<elgamal::PartialDecryption> =
            key.shares.iter().map(|s| elgamal::partial_decrypt(s, &ct_k)).collect();
        out.push(
            Bench::new("layer3", "escrow-partial-decrypt")
                .param("k", k)
                .param("n", n)
                .run(|| elgamal::partial_decrypt(&key.shares[0], &ct_k)),
        );
        out.push(
            Bench::new("layer3", "escrow-combine-decryptions")
                .param("k", k)
                .param("n", n)
                .run(|| elgamal::combine_decryptions(&partials, &ct_k, k)),
        );
    }

    let mut drng = rng_from_seed(16);
    out.push(
        Bench::new("layer3", "escrow-deanonymize-full")
            .param("k", 2)
            .param("n", 3)
            .iterations(1000)
            .run(|| auth.deanonymize(&ct, &[0, 1], b"warrant", 1, &mut drng)),
    );

    // Audit log: append and full-chain verification at 10^3 and 10^5 entries.
    for n in [1_000usize, 100_000] {
        let mut log = rapido_proto::audit::AuditLog::new();
        let event = rapido_proto::audit::Event {
            timestamp_ns: 1,
            authority_set: vec![0, 1],
            authorization_hash: rapido_proto::audit::hash_document(b"warrant"),
            ciphertext_hash: rapido_proto::audit::hash_document(b"ct"),
            resolved: true,
        };
        for _ in 0..n {
            log.append(event.clone());
        }
        out.push(
            Bench::new("layer3", "audit-log-append")
                .param("entries", n)
                .memory_bytes(log.size_bytes())
                .run(|| {
                    log.append(event.clone());
                }),
        );
        out.push(
            Bench::new("layer3", "audit-log-verify-chain")
                .param("entries", n)
                .memory_bytes(log.size_bytes())
                .slow_operation_iterations(if n >= 100_000 { 20 } else { MEDIUM_ITERS })
                .run(|| log.verify()),
        );
    }
    Ok(out)
}

// --- revocation ------------------------------------------------------------

pub fn revocation(quick: bool) -> Vec<BenchRecord> {
    let mut out = Vec::new();
    let epoch = Epoch(3);

    // R0: an integer comparison against the current epoch. Its cost is not
    // latency but revocation delay, which Scenario 3 measures instead.
    let r0 = EpochOnly::new(epoch, EpochClock::default());
    out.push(
        Bench::new("revocation", "r0-epoch-check")
            .param("variant", "r0")
            .memory_bytes(r0.memory_bytes())
            .run_batched(1000, || r0.is_revoked(b"credential-id", epoch)),
    );

    let sizes: &[usize] =
        if quick { &[1_000, 10_000] } else { &[1_000, 10_000, 100_000, 1_000_000] };
    let id = |i: usize| Sha256::digest(i.to_be_bytes()).to_vec();

    for &n in sizes {
        let ids: Vec<Vec<u8>> = (0..n).map(id).collect();

        let crl = Crl::with_entries(ids.iter().map(|v| v.as_slice()));
        let hit = id(n / 2);
        let miss = id(n * 2);
        out.push(
            Bench::new("revocation", "r1-crl-hashset-hit")
                .param("variant", "r1")
                .param("R", n)
                .memory_bytes(crl.memory_bytes())
                .run_batched(100, || crl.is_revoked(&hit, epoch)),
        );
        out.push(
            Bench::new("revocation", "r1-crl-hashset-miss")
                .param("variant", "r1")
                .param("R", n)
                .memory_bytes(crl.memory_bytes())
                .run_batched(100, || crl.is_revoked(&miss, epoch)),
        );

        // Linear scan, so the cost of the naive CRL is reported rather than
        // assumed away as a hash set.
        if n <= 100_000 {
            let linear = LinearCrl::with_entries(ids.iter().map(|v| v.as_slice()));
            out.push(
                Bench::new("revocation", "r1-crl-linear-miss")
                    .param("variant", "r1-linear")
                    .param("R", n)
                    .memory_bytes(linear.memory_bytes())
                    .slow_operation_iterations(if n >= 100_000 { 50 } else { MEDIUM_ITERS })
                    .run(|| linear.is_revoked(&miss, epoch)),
            );
        }

        for fp_target in [0.01f64, 0.001] {
            let mut bloom = BloomFilter::with_capacity(n, fp_target);
            for i in &ids {
                bloom.insert(i);
            }
            // Measured false-positive rate over 10k probes that were never
            // inserted — reported rather than assumed from the formula.
            let probes = 10_000usize;
            let fp = (n..n + probes).filter(|&i| bloom.contains(&id(i))).count();
            let measured_fp = fp as f64 / probes as f64;
            out.push(
                Bench::new("revocation", "r2-bloom-miss")
                    .param("variant", "r2")
                    .param("R", n)
                    .param("fp_target", fp_target)
                    .param("fp_measured", measured_fp)
                    .param("fp_analytic", bloom.expected_false_positive_rate())
                    .param("n_hashes", bloom.n_hashes())
                    .memory_bytes(bloom.memory_bytes())
                    .run_batched(100, || bloom.is_revoked(&miss, epoch)),
            );
        }
    }
    out
}

// --- replay ----------------------------------------------------------------

pub fn replay(quick: bool) -> Vec<BenchRecord> {
    let sizes: &[usize] = if quick { &[10_000] } else { &[10_000, 1_000_000] };
    let epoch = Epoch(1);
    sizes
        .iter()
        .map(|&n| {
            let mut cache = NonceCache::new(epoch, n * 4);
            for i in 0..n as u64 {
                cache.check_and_insert(epoch, &i.to_be_bytes()).expect("fresh nonce");
            }
            let mut counter = n as u64;
            let memory = cache.memory_bytes();
            Bench::new("replay", "nonce-cache-insert").param("entries", n).memory_bytes(memory).run(
                || {
                    counter += 1;
                    cache.check_and_insert(epoch, &counter.to_be_bytes())
                },
            )
        })
        .collect()
}

// --- Layer 2 mechanisms ----------------------------------------------------

pub fn timing_mechanisms() -> Vec<BenchRecord> {
    // Sensitivity is measured from a real spread of verification times rather
    // than assumed.
    let samples: Vec<u64> = (0..2000).map(|i| 1_000_000 + (i % 137) * 900).collect();
    let sens = Sensitivity::from_samples(&samples);
    let mut out = Vec::new();

    let pad = MPad::from_samples(&samples, 100_000);
    let mut rng = rng_from_seed(17);
    out.push(
        Bench::new("layer2", "m-pad-delay")
            .param("mechanism", "m-pad")
            .param("t_max_ns", pad.t_max_ns)
            .run(|| pad.release_delay_ns(1_200_000, EventKind::Genuine, &mut rng)),
    );

    for eps in [0.1f64, 0.5, 1.0, 2.0, 5.0] {
        let geo = MGeo::new(eps, 1e-6, sens.delta_f_ns);
        let mut grng = rng_from_seed(18);
        out.push(
            Bench::new("layer2", "m-geo-delay")
                .param("mechanism", "m-geo")
                .param("epsilon", eps)
                .param("delta", 1e-6)
                .param("shift_ns", geo.params.shift)
                .param("sensitivity_ns", sens.delta_f_ns)
                .param("mean_delay_ns", geo.mean_delay_ns())
                .run(|| geo.release_delay_ns(1_200_000, EventKind::Genuine, &mut grng)),
        );

        let bucket = MBucket::new(eps, 1e-6, sens.delta_f_ns, 250_000, 64);
        let mut brng = rng_from_seed(19);
        out.push(
            Bench::new("layer2", "m-bucket-delay")
                .param("mechanism", "m-bucket")
                .param("epsilon", eps)
                .param("delta", 1e-6)
                .param("quantum_ns", bucket.quantum_ns)
                .param("truncation_delta", bucket.truncation_delta())
                .param("worst_case_delay_ns", bucket.worst_case_delay_ns())
                .run(|| bucket.release_delay_ns(1_200_000, EventKind::Genuine, &mut brng)),
        );
    }
    out
}

// --- baselines -------------------------------------------------------------

pub fn baselines(quick: bool) -> Vec<BenchRecord> {
    let mut rng = rng_from_seed(20);
    let mut out = Vec::new();

    let ed = mtls::ed25519::setup(&mut rng);
    let ed_sig = ed.sign_challenge(b"challenge");
    out.push(
        Bench::new("baseline", "mtls-ed25519-verify")
            .param("baseline", "mtls-ed25519")
            .param("chain_depth", 2)
            .bytes(mtls::ed25519::WIRE_BYTES)
            .run(|| mtls::ed25519::verify(&ed, b"challenge", &ed_sig)),
    );

    let p = mtls::p256_ecdsa::setup(&mut rng);
    let p_sig = p.sign_challenge(b"challenge");
    out.push(
        Bench::new("baseline", "mtls-p256-verify")
            .param("baseline", "mtls-p256")
            .param("chain_depth", 2)
            .bytes(mtls::p256_ecdsa::WIRE_BYTES)
            .run(|| mtls::p256_ecdsa::verify(&p, b"challenge", &p_sig)),
    );

    let ca = scms::PseudonymCa::generate(&mut rng);
    let explicit = scms::explicit::issue(&ca, 7, &mut rng);
    let explicit_sig = explicit.sign(b"basic safety message");
    out.push(
        Bench::new("baseline", "scms-explicit-verify")
            .param("baseline", "scms-explicit")
            .bytes(scms::explicit::WIRE_BYTES)
            .run(|| {
                scms::explicit::verify(
                    &ca.public,
                    &explicit.cert,
                    b"basic safety message",
                    &explicit_sig,
                )
            }),
    );

    let implicit = scms::implicit::issue(&ca, 7, b"agent-01", &mut rng);
    let implicit_sig = implicit.sign(b"basic safety message");
    out.push(
        Bench::new("baseline", "scms-implicit-verify")
            .param("baseline", "scms-implicit-ecqv")
            .bytes(scms::implicit::WIRE_BYTES)
            .run(|| {
                scms::implicit::verify(
                    &ca.public,
                    &implicit.cert,
                    b"basic safety message",
                    &implicit_sig,
                )
            }),
    );

    // CL-RSA: the denominator of RAPIDO's speedup over anonymous credentials,
    // measured on this CPU rather than quoted.
    let attrs: &[usize] = if quick { &[5] } else { &[5, 10] };
    for &l in attrs {
        let sk = cl_rsa::SecretKey::generate(l, &mut rng);
        let msgs: Vec<num_bigint::BigUint> =
            (0..l).map(|i| cl_rsa::message_from_bytes(format!("a{i}").as_bytes())).collect();
        let sig = sk.sign(&msgs, &mut rng).expect("issuance succeeds");

        for n_disclosed in [0usize, l / 2] {
            let disclose: Vec<usize> = (0..n_disclosed).collect();
            let mut prng = rng_from_seed(21);
            let pres = cl_rsa::present(&sk.public, &msgs, &sig, &disclose, b"nonce", &mut prng)
                .expect("presentation succeeds");
            out.push(
                Bench::new("baseline", "cl-rsa-present")
                    .param("baseline", "cl-rsa-2048")
                    .param("L", l)
                    .param("n_disclosed", n_disclosed)
                    .bytes(pres.size_bytes())
                    .run(|| {
                        cl_rsa::present(&sk.public, &msgs, &sig, &disclose, b"nonce", &mut prng)
                    }),
            );
            out.push(
                Bench::new("baseline", "cl-rsa-verify")
                    .param("baseline", "cl-rsa-2048")
                    .param("L", l)
                    .param("n_disclosed", n_disclosed)
                    .param("modexps", cl_rsa::verify_modexp_count(l, n_disclosed))
                    .param("special_rsa_modulus", sk.public.special_rsa)
                    .bytes(pres.size_bytes())
                    .run(|| cl_rsa::verify_presentation(&sk.public, &pres, b"nonce")),
            );
        }
    }
    out
}

/// Additionally record every wire size as its own zero-time row, so the
/// bandwidth table can be generated without re-deriving sizes in Python.
pub fn wire_sizes() -> rapido_core::Result<Vec<(String, usize)>> {
    Ok(vec![
        ("mode-a-pseudonym-cert".into(), mode_a::PseudonymCert::SIZE),
        ("mode-a-cert-request".into(), mode_a::CertRequest::SIZE),
        ("bbs-signature".into(), bbs::Signature::SIZE),
        ("elgamal-ciphertext".into(), elgamal::Ciphertext::SIZE),
        ("e2-proof".into(), rapido_proto::escrow::E2_PROOF_SIZE),
        ("mtls-ed25519".into(), mtls::ed25519::WIRE_BYTES),
        ("mtls-p256".into(), mtls::p256_ecdsa::WIRE_BYTES),
        ("scms-explicit".into(), scms::explicit::WIRE_BYTES),
        ("scms-implicit".into(), scms::implicit::WIRE_BYTES),
    ])
}

/// Shamir sharing, exposed for completeness of the threshold cost model.
pub fn shamir_costs() -> Vec<BenchRecord> {
    let mut rng = rng_from_seed(22);
    let secret = Fr::from(12345u64);
    [(2usize, 3usize), (3, 5), (5, 9)]
        .into_iter()
        .map(|(k, n)| {
            Bench::new("primitive", "shamir-split")
                .param("k", k)
                .param("n", n)
                .run(|| shamir::split(secret, k, n, &mut rng))
        })
        .collect()
}
