# Measured findings

Every number here was produced by this codebase on one machine, in one session,
and is traceable to `results/p1/`. Regenerate with `./reproduce.sh`.

**Profile p1:** Apple M4 Max, 14 physical / 14 logical cores, 36 GiB, macOS
26.5.2, rustc 1.97.1, `aarch64-apple-darwin`, release + fat LTO +
`codegen-units=1`. CPU frequency is not pinnable from userspace on macOS; the
metadata header records this, and run-to-run variance is correspondingly wider
than the confidence intervals alone suggest.

**Profile p2 has not been run.** There is **one** hardware profile here, not the
two originally planned. See `LIMITATIONS.md` §L12 and
`NUMBERS.md` § Profile p2 for why an SBC number is absent rather than estimated.

**Latencies are quoted to three significant figures.** The measurement host
records its own CPU governor as `not-controllable (macOS)`, so a tighter
interval would claim precision the platform cannot deliver.

**Headline comparisons use the fastest measured variant of each system.** For
Mode A that is the *naive* verifier, which is measurably faster than the
aggregate one for a single presentation (§9). `analysis/gen_tables.py` asserts
this so it cannot silently regress.

---

## 1. Mode A's issuer links every session; Mode B's cannot

Scenario 4 plays the unlinkability game on real protocol transcripts,
10 seeds × 5,000 trials.

| Mode | Adversary | Measured advantage |
|---|---|---|
| A | verifier-only | **0.0000** |
| A | **issuer-colluding** | **1.0000** |
| B | verifier-only | **0.0000** |
| B | issuer-colluding | **0.0000** |

Mode A's issuer links **every** session it certified, perfectly, with no error.
This is not a weakness in the implementation; it is what the construction says:
the authority signs each `P_i`, so it necessarily holds `P_i → agent`, and `P_i`
appears in the clear in every presentation.

**Consequence.** Mode A's Layer 1 *is* the butterfly-key / pseudonym-certificate
mechanism of IEEE 1609.2 / SCMS, so SCMS rather than an anonymous-credential
system is the baseline it has to be judged against. It is in fact weaker than
deployed SCMS here, because SCMS separates the Registration Authority from the
Pseudonym CA precisely so that no single issuing party can perform this linking.
Threshold issuance distributes trust quantitatively but does not restore that
separation: every share-holder participates in signing the pseudonym it later
observes.

Any unlinkability claim for a batch-pseudonym construction therefore has to name
the adversary it excludes.

---

## 2. Issuer-unlinkability is free in time and costs 1.35x in bandwidth

Layer-1 verification, both systems measured the same way:

| | Mode A (naive, fastest) | Mode B (L=8, all hidden) |
|---|---|---|
| Verification | 1.88 ms | **1.32 ms** |
| Presentation on the wire, no escrow | 296 B | 572 B |
| Presentation on the wire, with E2 escrow | 520 B | **700 B** |

**Mode B is 0.564 ms *faster* than Mode A.** The cost of issuer-unlinkability,
in milliseconds, is **−0.564 ms**: it is free.

Why: Mode A verification computes two hash-to-G2 operations on top of its two
pairings. Mode B's pairing check uses points already on the wire and hashes
nothing to a curve; its extra work is a G1 MSM, which is far cheaper.

On the wire, Mode B costs **1.93x** Mode A without escrow and **1.35x** with it.
An earlier run of this codebase gave 2.1x, which came from a double-counted
Schnorr proof; see §7 for the fix and the regression test that pins it. The
finding is unchanged in substance: unlinkability costs bandwidth, not latency.

---

## 3. Anonymous credentials are not a hundred-millisecond primitive

The figure usually attached to anonymous credentials in applied work traces back
to RSA-based constructions on hardware a decade or more old. Re-measured here in
the same process as everything else:

| Quantity | Measured |
|---|---|
| Idemix-like CL-RSA-2048 verification (L = 5) | **8.77 ms** |
| Speedup of Mode A over CL-RSA | **4.66×** |
| Speedup of Mode B over CL-RSA | **6.66×** |

CL-RSA verification is `3 + L` modular exponentiations, which on a contemporary
core is a single-digit-millisecond operation, not 100–200 ms. The pairing-based
constructions are faster, but by a factor of five to seven, not one of ten to
twenty.

Two further quantities that are easy to over-budget, both measured:

* **Epoch validation (R0) is an integer comparison: 0.25 ns.** It should not
  appear as a latency line item at all. Its real cost is revocation *latency*
  (§5).
* **Batch issuance of 100 pseudonyms under a (3,5) threshold: 351 ms.**

---

## 4. RAPIDO is ~8x slower than the V2X baseline it should be compared against

Layer-1 verification, same hardware, same process:

| System | Verify | Wire |
|---|---|---|
| mTLS Ed25519, chain depth 2 | 0.0533 ms | 256 B |
| **SCMS implicit (ECQV)** | **0.213 ms** | **113 B** |
| SCMS explicit | 0.264 ms | 169 B |
| mTLS ECDSA P-256, depth 2 | 0.397 ms | 258 B |
| RAPIDO Mode B (L=8) | 1.32 ms | 572 B |
| RAPIDO Mode B + E2 | 1.76 ms | 700 B |
| RAPIDO Mode A (naive) | 1.88 ms | 296 B |
| RAPIDO Mode A (aggregate) | 2.10 ms | 296 B |
| Idemix-like CL-RSA-2048 | 8.77 ms | 1,098 B |

Against the deployed V2X standard:

* **Mode A is 8.84x slower and 2.6x larger** than ECQV pseudonym certificates —
  while providing, per §1, the same unlinkability property.
* **Mode B + E2 is 8.26x slower and 6.19x larger** than ECQV — but provides
  issuer-unlinkability, selective disclosure and accountable escrow, none of
  which ECQV offers.

That is the honest statement of cost. The case for the layered design rests on
the properties ECQV does *not* provide, not on speed.

---

## 5. Epoch revocation is not free — and the fix undoes it

Scenario 3, 20,000 agents, 10 seeds.

Any outage at least as long as the epoch strands essentially every agent:

| Epoch `T` | Failure rate under a 60-min outage | Worst-case revocation latency |
|---|---|---|
| 1 min | 1.0000 | 60 s |
| 10 min | 1.0000 | 600 s |
| 60 min | 0.9935 | 3600 s |

Pre-provisioning future epochs restores availability and destroys the revocation
latency that motivated R0 in the first place:

| Lookahead | Failure rate | Worst-case revocation latency |
|---|---|---|
| 0 epochs | 1.0000 | 10 min |
| 2 epochs | 1.0000 | 30 min |
| **6 epochs** | **0.0000** | **70 min** |
| 144 epochs | 0.0000 | 24 h |

Against a 5%-stranded availability target and a 30-minute revocation target,
only the 1-minute-outage case admits a configuration satisfying both
(`T` = 30 min); every longer outage admits none. Epoch revocation is a direct
trade against availability, and the curve is
`analysis/figures/fig_revocation.png`.

Lookup costs, for completeness: R0 **0.25 ns**; R1 hash-set CRL at |R| = 10⁶
**9.58 ns** (miss) but 65 MB resident; R2 Bloom **107 ns** in 1.2 MB, with a
measured false-positive rate of 0.85% against a 1% target — i.e. R2 buys a 54×
memory saving at the price of denying service to 0.85% of unrevoked agents.

---

## 6. Layer 2 is what actually threatens the latency budget

The crypto is fast (1.32–2.82 ms). The DP timing defence is not. Advantage is
the **maximum over all three attacks** (likelihood ratio, mean threshold,
learned classifier), with percentile-bootstrap 95% intervals:

| ε | Max attacker advantage | at | Mean added latency |
|---|---|---|---|
| 5.0 | 1.000 [1.000, 1.000] | N=256 | 3.1 ms |
| 2.0 | 0.996 [0.994, 0.998] | N=256 | 5.1 ms |
| 1.0 | 0.892 [0.876, 0.907] | N=256 | 8.4 ms |
| 0.5 | 0.615 [0.583, 0.645] | N=256 | 15.1 ms |
| 0.1 | 0.116 [0.076, 0.156] | N=256 | 68.6 ms |
| M-PAD (ε = 0) | 0.000 | — | worst-case padding |

At ε = 1.0 an adversary with 256 observations still wins ~89% of the time.
Driving advantage below 0.5 costs ~15 ms — roughly ten times the entire
cryptographic budget. **Layer 2, not Layer 1, decides whether RAPIDO meets a
latency target**, and it does not meet one at any setting providing meaningful
protection.

### The learned-attack finding did not survive validation

An earlier run of this codebase reported the gradient-boosted classifier beating
the likelihood-ratio test "by an order of magnitude" at ε = 0.1, on an advantage
of **0.432** at N = 64. That number was an artifact. The classifier was fit and
scored on windows resampled from **the same trace array**, so it could memorize
values it would later be tested on. The symptom was visible in the data: the
advantage was not monotone in N, which a calibrated attacker cannot be.

Re-run with strict separation — train and test traces generated from **disjoint
halves of the measured compute-time samples** (8,000 samples and 3,000 windows
per side), bootstrap intervals on every estimate, and trial counts sized from
the interval width rather than a constant:

| | ε = 0.1, N = 64 |
|---|---|
| Before (shared traces) | 0.432 |
| **After (disjoint train/test)** | **0.031 [0.011, 0.075]** |

An order of magnitude lower, and indistinguishable from the noise floor.
**Monotonicity violations after validation: 0.**

The learned attack does still beat the likelihood-ratio test, but modestly and
mostly at moderate ε — at ε = 0.5, N = 256 it reaches 0.615 against the LR
test's 0.256. What survives is the methodological point: the LR test is **not**
the strongest attack, so a published advantage curve has to be a maximum over
attacks attempted, computed on held-out data, with intervals. The "order of
magnitude at small ε" result does not survive and is not claimed anywhere.

Two further points that must travel with any ε quoted from this codebase:

* **ε is per release.** At one authentication per 45 s, a day is 1,920 releases;
  ε = 1.0 per release composes to ε > 100 per day under either basic or advanced
  composition. Quoting a per-release ε as a system guarantee is not defensible.
* **Advantage near the noise floor needs an interval.** 0.031 [0.011, 0.075] and
  0.031 [0.029, 0.033] are very different claims; only the second would support
  a statement about the defence.

---

## 7. A sound escrow proof costs 0.605 ms, and 128–224 B depending on mode

| Variant | Verifier cost | Sound? |
|---|---|---|
| E0 (none) | 0 | n/a |
| E1 (ciphertext, unchecked) | **0 ns — nothing is checked** | **no** |
| E2 (ciphertext + proof) | **0.605 ms** | yes |

E1 provides no accountability at all: a test
(`e1_accepts_a_bogus_ciphertext_that_e2_rejects`) shows a cheating agent
encrypting garbage, being accepted by every verifier, and later de-anonymizing to
**nobody**. Any design that attaches an unchecked ciphertext and calls the result
accountable anonymity is claiming a property it does not deliver. E1 is
implemented **only** so E2's cost can be measured against it as a floor.

### Wire cost, measured field by field

Earlier drafts of this codebase gave three different numbers for E2's wire cost
(128 B, 32 B, +224 B, +544 B). Only one set is right, and it comes from
`results/p1/wire_breakdown.json`, which measures `serialized.len()` on real
structures rather than trusting declared constants:

| Mode | E0 | E2 | E2 delta | composition |
|---|---:|---:|---:|---|
| A | 296 B | 520 B | **+224 B** | 96 B ciphertext + 128 B standalone proof |
| B | 572 B | 700 B | **+128 B** | 96 B ciphertext + 32 B (one extra response scalar) |

**The "folds into the Schnorr proof" optimization is real and implemented.** The
Mode B E0 presentation carries 11 Schnorr responses; E2 carries 12. The escrow
statement is proved under the presentation's own Fiat-Shamir challenge, so it
costs exactly one extra scalar. Accountability is therefore cheapest in the
construction that also provides issuer-unlinkability — a composition result that
is not evident from the primitives in isolation.

The previously reported 1,116 B for Mode B + E2 was a **double-count**: the
escrow attachment held a *clone* of the presentation's Schnorr proof, and
`size_bytes()` added both copies. The attachment now has a distinct type
(`EscrowAttachment::ProvenInPresentation`) that carries only the ciphertext, so
the sharing is recorded in the type rather than in a comment, and
`wire::tests::field_sums_agree_with_size_bytes` fails if the two ever diverge
again.

---

## 8. Cover traffic increases bandwidth, and the exchange rate is terrible

Cover traffic is extra messages carrying no work, so its bandwidth overhead is
always positive; any design that budgets it as a saving has the sign wrong.
Measured (`fig_cover_tradeoff.png`):

| Cover rate | Bandwidth **increase** | Adversary advantage |
|---|---|---|
| 0 Hz | 0% | 1.000 |
| 5 Hz | +506% | 0.937 |
| 50 Hz | +5,025% | 0.478 |
| 200 Hz | +20,078% | 0.257 |

Halving the adversary's advantage costs a **50× increase** in bytes.

---

## 9. The 100 ms intersection requirement is a core-count question

Scenario 1, 10 seeds, real cryptography:

| Vehicles | 1 core | 2 cores | 4 cores | 8 cores |
|---|---|---|---|---|
| 20 | 0.995 | 0.995 | 0.995 | 0.995 |
| 50 | 0.998 | 1.000 | 1.000 | 1.000 |
| **100** | **0.500** (p99 191 ms) | 1.000 (p99 50 ms) | 1.000 (p99 6.4 ms) | 1.000 |

A single-core RSU misses the 100 ms deadline at 100 vehicles, completing half of
them. Two cores fix it. The 100 ms requirement is a statement about verifier
parallelism, not about per-verification latency, and should be specified that
way.

Sustained throughput (Scenario 2): the verifier saturates at roughly **344
auths/sec/core**; 100,000 agents authenticating every 30–60 s drive 8 cores to
76% utilization.

Also measured: the aggregate verification path is **slower** than the naive one
for a single presentation (2.10 ms vs 1.88 ms — the random scalar
multiplications cost more than the saved final exponentiation). It only pays off
when batching across presentations. It is a batching optimization, not a
per-verification one, and the naive figure is the correct one wherever Mode A is
compared against another system.

---

## What generalizes beyond this design

Three of these findings are about method rather than about RAPIDO, and hold for
any comparable evaluation:

1. **A performance claim needs a baseline measured on the same hardware.**
   Re-measuring CL-RSA moved the comparison ratio by a factor of two to three
   without changing a line of protocol code (§3).
2. **Unlinkability must be stated against a named adversary.** Mode A satisfies
   it against verifiers and fails completely against the issuer (§1).
3. **A privacy mechanism that has not been attacked has not been evaluated.**
   The timing layer was specifiable in a form that is not implementable —
   continuous Laplace noise on a non-negative delay — and its ineffectiveness
   was invisible until an adversary was built (§6). Whether an *attack* has been
   evaluated is the same question: the learned attack's headline result
   evaporated under train/test separation.
</content>
</invoke>
