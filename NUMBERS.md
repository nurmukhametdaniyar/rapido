# NUMBERS.md — every reported figure, and where it came from

A reader should be able to take any number this project reports and reach the
file that produced it, the command that wrote that file, and the test that
guards the code behind it. That is what this table is for.

Regenerate everything with `./reproduce.sh`. Every result file opens with a
metadata header recording the machine, OS, toolchain, build flags, and CPU
governor state.

**On the `git_commit` field.** The committed results record
`git_commit: not-a-git-repo`, because they were measured before this repository
had any commits. They were produced by the measurement code as it stands at the
initial commit: the only changes made between measurement and commit were to
comments and to analysis scripts, neither of which affects `results/`. Re-running
would stamp a real hash but would also move every latency in the third
significant figure, so the measurements are left as taken. Any future run will
record the commit it was produced under.

**Read this first:** the committed results are **profile p1 only** — an Apple
M4 Max. See [§ Profile p2](#profile-p2-not-measured) below; there is no
aarch64 single-board-computer measurement in this repository, and none of the
absolute latencies should be read as on-board-unit costs.

---

## Conventions

* **Layer 1 verification** (the cross-system comparison) is the credential check
  alone, measured the same way for RAPIDO and for every baseline. Baselines have
  no revocation, replay or escrow layer, so including RAPIDO's would not be a
  like-for-like comparison.
* **Pipeline totals** (the per-layer table) come from
  `results/p1/pipeline_breakdown.*`, which records the layers and the total from
  **the same execution**, so a decomposition can never disagree with its own
  total.
* **Latencies are quoted to three significant figures.** The measurement host
  records its own CPU governor as `not-controllable (macOS)`, so a tighter quote
  would claim precision the platform cannot deliver.
* **Mode A headline = the naive verifier**, which is measurably faster than the
  aggregate one for a single presentation. `analysis/gen_tables.py` asserts this
  via `common.HeadlineVariants.assert_uses_minimum`, so it cannot silently
  regress.

---

## Headline quantities

| Quantity | Value | Result file | Produced by | Guarded by |
|---|---|---|---|---|
| Cost of issuer-unlinkability | Mode B − Mode A (naive) | `results/p1/bench.csv` | `rapido-cli bench` | `gen_tables.py::table_headline` + `HeadlineVariants.assert_uses_minimum` |
| Cost of a sound escrow proof | E2 − E1 | `results/p1/bench.csv` (`escrow-check`) | `rapido-cli bench` | `escrow::tests::e1_accepts_a_bogus_ciphertext_that_e2_rejects` |
| Speedup over CL-RSA | Mode A, Mode B | `results/p1/bench.csv` | `rapido-cli bench` | `cl_rsa::tests::presentation_round_trip_at_every_disclosure_fraction` |
| RAPIDO vs SCMS-ECQV | latency and bytes | `results/p1/bench.csv` | `rapido-cli bench` | `scms::tests::implicit_reconstruction_matches_the_agents_key` |
| Mode A / Mode B E2 wire delta | +224 B / +128 B | `results/p1/wire_breakdown.json` | `rapido-cli wire` | `wire::tests::mode_b_escrow_costs_a_ciphertext_plus_one_scalar` |

## Figures

| Figure | Script | Reads | Notes |
|---|---|---|---|
| Fig 1 — protocol diagram | `analysis/journal_figures.py::figure1_protocol` | — | The only figure not generated from data. |
| Fig 2 — verification cost | `analysis/journal_figures.py::figure2_verification_cost` | `results/*/bench.csv` | Dot plot; marker shape distinguishes RAPIDO from comparison systems. |
| Fig 3 — timing defence | `analysis/journal_figures.py::figure3_timing_defence` | `results/*/attack_timing.csv`, `results/attack_classifier.csv` | Max over all three attacks, with bootstrap CI bands. |
| Fig 4 — revocation trade | `analysis/journal_figures.py::figure4_revocation_trade` | `results/*/scenario3_connectivity.csv` | Feasibility of the two targets is computed, not asserted. |

Presentation-style raster versions of the same data, plus three further figures
(per-layer breakdown, cover traffic, intersection burst, linkability), are in
`analysis/figures/` from `analysis/fig_*.py`.

## Tables

| Table | Emitted to | By |
|---|---|---|
| Mode comparison | `analysis/tables/table1_mode_comparison.tex` | `gen_tables.py::table1` |
| Per-layer breakdown | `analysis/tables/table2_layer_breakdown.tex` | `gen_tables.py::table2` |
| Mode B sweep (`L` × disclosure) | `analysis/tables/table3_mode_b_sweep.tex` | `gen_tables.py::table_mode_b_sweep` |
| Headline answers | `analysis/tables/table_headline_answers.tex` | `gen_tables.py::table_headline` |
| Measurement environment | `analysis/tables/table_environment.tex` | `gen_tables.py::main` |

## Experiments → result files

| Experiment | Command | Writes |
|---|---|---|
| Micro-benchmarks | `rapido-cli bench --profile p1 --out results/p1` | `bench.{json,csv}`, `wire_sizes.json`, `pipeline_breakdown.{json,csv}` |
| Wire breakdown | `rapido-cli wire --profile p1 --out results/p1` | `wire_breakdown.{json,md}` |
| Scenario 1 — intersection burst | `rapido-cli sim --scenario 1` | `scenario1_intersection.{json,csv}` |
| Scenario 2 — metropolitan load | `rapido-cli sim --scenario 2` | `scenario2_metropolitan.{json,csv}` |
| Scenario 3 — connectivity loss | `rapido-cli sim --scenario 3` | `scenario3_connectivity.{json,csv}` |
| Scenario 4 — linkability game | `rapido-cli sim --scenario 4` | `scenario4_linkability.{json,csv}` |
| Timing adversary | `rapido-cli attack --target timing` | `attack_timing.{json,csv}`, `attack_timing_traces.json` |
| Cover-traffic adversary | `rapido-cli attack --target cover` | `attack_cover.{json,csv}` |
| Learned classifier | `python analysis/attack_classifier.py` | `results/attack_classifier.csv` |

## Correctness evidence

| Claim | Evidence |
|---|---|
| Hash-to-curve is RFC 9380 conformant | `crates/rapido-crypto/tests/rfc9380_kat.rs` — G1 and G2 vectors, all five message lengths |
| HKDF is RFC 5869 conformant | `crates/rapido-crypto/src/kdf.rs::rfc5869_kat` |
| BLS matches an independent implementation | `crates/rapido-crypto/tests/cross_backend.rs` — arkworks vs blst, byte-identical signatures |
| A fresh keypair does not authenticate | `mode_a::tests::a_signature_without_a_valid_certificate_is_rejected` |
| E1 escrow is unsound | `escrow::tests::e1_accepts_a_bogus_ciphertext_that_e2_rejects` |
| Mode A's issuer can link every session | `attack::linkability` + `scenario::linkability::tests::the_four_cells_come_out_as_the_spec_predicts` |
| Timing attacks are not overfitting | `attack::timing::tests::advantage_is_monotone_in_observation_count`, `::split_pools_are_disjoint` |
| Wire accounting is not double-counting | `wire::tests::field_sums_agree_with_size_bytes` |
| One latency per configuration | `pipeline::tests::every_configuration_reports_one_total` |

## Profile p2 (not measured)

Two hardware profiles were planned. **Only p1 exists in this repository.**

The measurement host is an Apple M4 Max — already `aarch64`, but a
desktop-class core. An automotive on-board or roadside unit is a far slower
embedded part, and no such hardware was available. The options considered and
why each was rejected:

* **A `linux/arm64` container on this host** runs natively on the same M4
  silicon. It would be a genuine second *software* profile (different OS, libc,
  allocator, toolchain target, and a readable CPU governor) but the cores are
  unchanged, so it says nothing about on-board-unit cost.
* **QEMU TCG emulation** produces timings that reflect QEMU's interpreter
  overhead per instruction class, not an embedded microarchitecture. Building
  the workspace and running the suite under TCG was also estimated in hours.
* **Scaling p1 by a factor** was explicitly ruled out. An estimated aarch64
  number is worse than none, because it reads as a measurement.

What is ready for when hardware appears: `rapido-cli bench --profile p2 --out
results/p2` (add `--emulated` under emulation). Any run so flagged is stamped on
**every** figure automatically — `common.save` applies the stamp from loaded
provenance, so an individual script cannot forget it.

Until then, treat every absolute latency here as desktop-class, and rely on the
*ratios* between systems, which were all measured in the same process on the
same machine.
