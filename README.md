# RAPIDO reference implementation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21875222.svg)](https://doi.org/10.5281/zenodo.21875222)

A measured, reproducible implementation of the RAPIDO protocol. Every number it
reports is produced by running this code, on a recorded machine, from a
committed result file — none is projected, estimated, or quoted.

Archived at [10.5281/zenodo.21875222](https://doi.org/10.5281/zenodo.21875222),
which always resolves to the latest version. Cite that DOI rather than a
per-version one unless you need to pin an exact snapshot.

**The purpose of this codebase is to find out whether RAPIDO works. It is not to
demonstrate that it does.** `FINDINGS.md` records where the measurements landed,
including where they came out worse than expected.

---

## The design question this project exists to settle

The cheapest conceivable Layer 1 has an agent derive one-time BLS signing keys
`k_i = PRF(master_secret, epoch || counter)`, sign a challenge, and be verified
with one pairing.

**That authenticates nothing.** Verifying a BLS signature under a fresh public
key `P_i` proves only that the presenter holds the matching secret key — and
anyone can generate a BLS keypair. Nothing binds `P_i` to a credential issued by
the threshold authority. `crates/rapido-proto/src/mode_a.rs` contains a test,
`a_signature_without_a_valid_certificate_is_rejected`, that constructs exactly
this attack.

Two ways of binding `P_i` to an issued credential are implemented, so their
costs can be compared rather than argued about:

| Mode | Mechanism | Issuer can link sessions? | Verifier cost |
|---|---|---|---|
| **A** — batch pseudonym | authority pre-signs PRF-derived one-time public keys | **Yes** — it signed every one of them | 2 pairings (3 in the aggregate path, 1 final exponentiation) |
| **B** — BBS+ presentation | re-randomized signature + Schnorr PoK with selective disclosure | **No** | 2 pairings + an MSM in the hidden-attribute count |

`rapido-sim` Scenario 4 plays the unlinkability game on real transcripts and
measures the advantage of a verifier-only and an issuer-colluding adversary in
both modes. Run it before believing either row.

Mode A's issuer-colluding advantage comes out near 1.0, which is what the
construction predicts: RAPIDO's Layer 1 in Mode A is functionally the
butterfly-key / pseudonym-certificate mechanism already standardized in **IEEE
1609.2 / SCMS** and deployed in US V2X. Mode A's Layer 1 is therefore not novel,
SCMS rather than an anonymous-credential system is the baseline it has to be
judged against, and the interesting contribution is Mode B together with the
Layer 2 / Layer 3 composition. `rapido-baselines::scms` implements that
baseline, in both its explicit and its implicit (ECQV) forms, so the comparison
can be made directly.

---

## Positions this implementation takes

Each is implemented, tested, and measured — not merely asserted. `FINDINGS.md`
gives the numbers.

1. **A BLS signature under a fresh key is not authentication.** See above.
2. **You cannot add Laplace noise to a delay.** Laplace noise is negative half
   the time. `rapido-privacy` implements a shifted, zero-truncated **discrete**
   two-sided geometric mechanism instead, reports the `(ε, δ)` it actually
   achieves, and reports the shift `s`.
3. **A floating-point Laplace sampler leaks the true value regardless of ε**
   (Mironov, CCS 2012). Sampling here is exact integer arithmetic via the
   Canonne–Kamath–Steinke discrete-Laplace algorithm; no `f64` touches the
   sampling path.
4. **Cover traffic increases bandwidth.** It is extra messages carrying no
   work, so the overhead is always positive. `rapido-privacy::cover` measures
   how much, against what it buys in adversary advantage.
5. **Escrow without a proof of correct encryption is not accountable
   anonymity.** Under variant E1 a malicious agent encrypts garbage, stays
   anonymous, and cannot be de-anonymized by anyone. E1 is implemented **only**
   so E2's cost can be measured against it as a floor; a test
   (`e1_accepts_a_bogus_ciphertext_that_e2_rejects`) demonstrates the attack.
6. **Epoch revocation is not free.** It costs up to a full epoch of revocation
   latency, and protecting availability by pre-provisioning future epochs makes
   that latency worse. Scenario 3 measures both sides.
7. **Baseline latencies must be measured, not cited.** Every comparison system
   is re-implemented in `rapido-baselines` and measured on the same hardware in
   the same process.

---

## Reproducing the results

The short path — correctness, then measurement, then tables:

```sh
cargo test && cargo run --release -p rapido-cli -- bench && python analysis/gen_tables.py
```

Longer form:

```sh
# 1. Correctness. Includes RFC 9380 and RFC 5869 known-answer tests.
cargo test --workspace

# ...and the cross-backend agreement test (arkworks vs blst).
cargo test -p rapido-crypto --features blst-backend

# 2. Micro-benchmarks -> results/p1/{bench.json,bench.csv}
cargo run --release -p rapido-cli -- bench --profile p1 --out results/p1

# 3. Simulations -> results/p1/scenario*.json + .csv
for s in 1 2 3 4; do
  cargo run --release -p rapido-cli -- sim --scenario $s --profile p1 --out results/p1
done

# 4. Adversary experiments
for t in timing cover linkability; do
  cargo run --release -p rapido-cli -- attack --target $t --profile p1 --out results/p1
done

# 5. Figures and LaTeX tables
python3 -m venv analysis/.venv
analysis/.venv/bin/pip install -r analysis/requirements.txt
analysis/.venv/bin/python analysis/gen_tables.py
for f in analysis/fig_*.py; do analysis/.venv/bin/python "$f"; done
analysis/.venv/bin/python analysis/attack_classifier.py   # learned timing attack
```

Add `--quick` to any `rapido-cli` command for a smoke test. **Quick results are
not citable** and the CLI prints a warning saying so.

`cargo bench` runs the criterion suite in `rapido-bench` for interactive work.
The committed numbers under `results/` come from `rapido-cli bench`, which
additionally writes the environment-metadata header.

### Second hardware profile

Only `p1` is committed here; see `LIMITATIONS.md` §L12. To add an aarch64
profile on a board:

```sh
cargo run --release -p rapido-cli -- bench --profile p2 --out results/p2
```

Under QEMU, add `--emulated`. That flag is recorded in every result file, and
the analysis scripts stamp any figure containing emulated data. **Emulated
timings are not credible as absolute latencies** and must be labelled wherever
they appear.

---

## Layout

```
crates/
  rapido-core/       epochs, canonical encoding, DSTs, errors, result metadata
  rapido-crypto/     BLS, PRF/KDF, BBS+, Pedersen, Schnorr relations, threshold ElGamal
  rapido-proto/      Mode A / Mode B, escrow E0-E2, revocation R0-R2, replay, audit log
  rapido-privacy/    discrete-Laplace timing mechanisms, cover traffic, DP accounting
  rapido-baselines/  mTLS-like, SCMS-like (explicit + ECQV), Idemix-like CL-RSA
  rapido-sim/        discrete-event simulator, four scenarios, three adversaries
  rapido-bench/      criterion micro-benchmarks
  rapido-cli/        experiment runner; writes results/ and analysis/tables/
experiments/         experiment definitions (TOML)
results/<profile>/   committed measured output; every file carries its provenance
analysis/            plain-Python plotting and LaTeX generation (no notebooks)
```

Every crate is `#![forbid(unsafe_code)]`.

---

## Cryptographic conventions

* Curve **BLS12-381**; signatures in **G2**, public keys in **G1**
  (minimal-pubkey-size).
* Hash-to-curve `BLS12381G2_XMD:SHA-256_SSWU_RO_` per RFC 9380, pinned to the
  RFC's own vectors at all five specified message lengths.
* A distinct domain separation tag per protocol context, never reused; a test
  asserts global uniqueness.
* Compressed points, canonical encoding, fail-closed parsing: on-curve,
  prime-order subgroup, non-identity, canonical field element.

### Constant-time posture

**No operation in this workspace has been verified constant-time, and no
side-channel resistance is claimed.** arkworks does not advertise constant-time
scalar multiplication and this implementation does not add it. What is
guaranteed is that no modular arithmetic on secrets is hand-rolled — every
operation goes through `ark-ff`/`ark-ec`, or `blst` on the `blst-backend`
feature path. The `num-bigint` arithmetic in the CL-RSA baseline is definitely
not constant-time; it is a benchmark baseline, not a deployable implementation.
See `LIMITATIONS.md` §L7.

### Two curve backends

`rapido-crypto` uses **arkworks** for all custom algebra. The `blst-backend`
feature adds a second BLS sign/verify path built on **blst**, so the library
dependence of the reported latencies is measurable rather than assumed away. The
two produce byte-identical signatures; `tests/cross_backend.rs` asserts it.

---

## Reading the results

Every result file is JSON with a metadata header recording CPU model, core
count, RAM, OS and kernel, rustc version, target triple, optimization flags,
`target-cpu`, CPU governor state, git commit, and the pinned versions of every
crypto crate the timings depend on — plus a flat CSV sibling for plotting.

Two headline numbers, both printed by the analysis scripts and emitted into
`analysis/tables/table_headline_answers.tex`:

* **What does issuer-unlinkability cost?** Mode B verification minus Mode A
  verification, at the same escrow variant.
* **What does a sound escrow proof cost?** E2 minus E1.

---

## Limitations

`LIMITATIONS.md` records every component that could not be implemented as
designed, and every caveat that has to travel with the numbers. The most
consequential:

* Threshold BBS+ issuance is **not** implemented; Mode B issues from a single
  authority, so issuance-cost comparisons between the modes are not
  like-for-like.
* Mode B cannot be revoked by a CRL — there is no stable identifier to look up.
  The R1/R2 numbers apply to Mode A only.
* No BBS04 group-signature baseline. That row is **absent** from the comparison
  table rather than filled in from the literature.
* The CL-RSA baseline uses an ordinary rather than a special RSA modulus. This
  does not change any timing (cost depends only on bit lengths) but does mean
  the instance is not deployable.
