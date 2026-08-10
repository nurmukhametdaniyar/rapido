# Limitations

Any component that could not be implemented as designed is recorded here.
Nothing in this file is a to-do note: each item is either a claim this work does
not support, or a caveat that has to travel with the numbers wherever they are
quoted.

---

## L1. Threshold BBS+ issuance is not implemented (Mode B issues from a single authority)

Threshold BLS works because a BLS signature is `H(m)^x`, which is *linear* in
the secret: partial signatures under Shamir shares of `x` Lagrange-combine
directly in the exponent. A BBS+ signature is `A = B^{1/(x+e)}`, which is not.
Producing it from shares of `x` requires distributed inversion of a shared
secret — a Bar-Ilan–Beaver style masked-inversion protocol or a general MPC,
with at least two rounds of communication among the authorities plus agreement
on the nonce `e`. That is squarely out of scope for this project.

**Consequence.** Mode A issues from a real `(k, n)` threshold authority;
**Mode B issues from a single authority**. Any comparison of *issuance* cost
between the two modes is not like-for-like and must say so. Verification costs
are unaffected, because verification uses only the group public key either way.

Marked in code by `rapido_crypto::bbs::THRESHOLD_ISSUANCE_SUPPORTED = false`,
with a test that fails if the flag changes without this file being updated.

---

## L2. BBS+ has no known-answer test against the IETF draft vectors

`draft-irtf-cfrg-bbs-signatures` standardizes the **two-element** `(A, e)` BBS
signature. RAPIDO Mode B uses the **three-element** `(A, e, s)` BBS+ signature
(Au–Susilo–Mu / Camenisch–Drijvers–Lehmann), which is a different scheme; the
draft's vectors do not apply to it and cannot be made to. The generator
derivation here also uses plain indexed hash-to-curve rather than the draft's
`create_generators` seed chain.

**What is tested instead:** round-trip correctness across `L ∈ {1,4,8,16}`,
soundness against forged signatures, tampered presentation elements, false
attribute claims, and nonce rebinding; plus RFC 9380 known-answer tests on the
underlying hash-to-curve at all five specified message lengths.

**Consequence.** This BBS+ implementation is not interoperable with an
IETF-conformant BBS implementation, and must not be described as if it were.

---

## L3. BLS has no official known-answer test vectors

`draft-irtf-cfrg-bls-signature-05` publishes no test vectors. The widely-used
BLS12-381 signature vectors come from the Ethereum consensus specification,
which fixes the DST to `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — a
different domain from RAPIDO's, so they cannot validate this code directly.

**What is tested instead:** `crates/rapido-crypto/tests/cross_backend.rs`
checks that arkworks and `blst` — two independent implementations — produce
**byte-identical** signatures for the same key and message across three DSTs
and five message lengths, agree on every verification outcome, and reject the
same forgeries. Combined with the RFC 9380 hash-to-curve KATs, this covers what
a vector-based KAT would.

---

## L4. The CL-RSA baseline uses an ordinary RSA modulus, not a special one

A deployable Camenisch–Lysyanskaya instance needs a *special* RSA modulus
(`p = 2p'+1`, `q = 2q'+1`, `p'`/`q'` prime). Generating 1024-bit safe primes
takes minutes to hours, which would make the benchmark unrunnable in CI, so
`cl_rsa::SecretKey::generate` produces an ordinary 2048-bit modulus by default
and records `special_rsa: false` in every result row.

**This does not affect any measured number.** Verification is `3 + L` modular
exponentiations whose cost depends only on the bit lengths, which are identical
either way. It does mean the instance is not cryptographically deployable.
`SecretKey::generate_safe_prime` produces a real special RSA modulus for anyone
who wants to confirm the timings are unchanged.

---

## L5. No BBS04-style short group signature baseline

Not implemented, and therefore **absent from the comparison table** rather
than filled in from the literature. An unmeasured row that looks like a
measurement is worse than a missing one.

---

## L6. Mode B cannot be revoked by a certificate revocation list

Mode B's whole purpose is that no stable per-agent identifier appears in a
presentation. A verifier therefore has nothing to look up in a CRL, and
`verifier::verify_mode_b` applies only the epoch check (R0).

Revoking a Mode B agent within an epoch requires a mechanism this
implementation does not have — a revocation accumulator, a per-epoch
allow-list, or verifier-local blocklisting of the escrow-opened identity after
the fact. **R1/R2 are not available in Mode B**, and the measured R1/R2
numbers apply to Mode A only.

---

## L7. No claim of side-channel resistance

arkworks does not advertise constant-time scalar multiplication, and this
implementation does not add it. No operation in this workspace has been
verified constant-time, and no such claim is made anywhere. What *is*
guaranteed is that no modular arithmetic on secrets is hand-rolled: every
operation goes through `ark-ff`/`ark-ec`, or through `blst` on the
`blst-backend` feature path.

The `num-bigint` arithmetic in the CL-RSA baseline is definitely **not**
constant-time. It is a benchmark baseline, not a deployable implementation.

---

## L8. The network model does not claim radio-layer fidelity

`rapido_sim::network` models one-way delay (mean + Gaussian jitter, clamped at
zero), independent per-fragment loss, and MTU fragmentation. It does **not**
model channel contention, capture effects, fading, hidden terminals, or
CSMA/CA backoff. Scenario 1's queueing results are about verifier capacity, not
about whether a DSRC channel can carry the traffic.

---

## L9. Scenario 2 resamples measured latencies rather than running live crypto

Scenario 1 (≤100 vehicles) runs the real cryptography. Scenario 2 simulates up
to 10^5 agents over simulated hours; running real pairings for every
authentication would take longer than the experiment is worth and would measure
nothing extra.

Scenario 2 therefore resamples from a `CostProfile`: the empirical distribution
of **real verifications measured by this codebase on this machine at the start
of the run**. It is not a fitted distribution and not a literature number. The
calibration sample count and its mean/median are recorded in every scenario
result file. What this misses is correlation between consecutive verifications
(cache warmth, frequency scaling), which resampling treats as independent.

---

## L10. The audit log detects rewriting, not deletion

`rapido_proto::audit` is a hash chain: any edit to a past entry invalidates
every subsequent link. It cannot detect an authority that **discards the log
wholesale or truncates it**, because a truncated chain is internally
consistent. Detecting truncation requires publishing the head to an external
witness. The guarantee is tamper-evidence against rewriting, not an
append-only guarantee, and must be described that way.

---

## L11. The escrow ciphertext opens to a group element, not directly to an identity

`rapido_crypto::elgamal` encrypts `M = id·G`. Recovering `M` does not recover
`id` (that is a discrete log); the escrow authorities resolve `M` through the
registration table they hold from enrolment (`elgamal::Registry`). This is the
standard "encrypt to a registered public element" construction, and it means
**de-anonymization requires the enrolment registry in addition to `k` escrow
shares**. Hybrid encryption would remove the table dependency at the cost of
turning the E2 correctness proof from three Schnorr equations into a circuit.

---

## L12. Only one hardware profile is measured — and p2 is *not measurable here*

Two hardware profiles were planned: `p1` (a workstation) and `p2` (an
aarch64 single-board computer, as an on-board-unit proxy). Only `p1` exists.

The committed `results/p1/` directory contains whatever machine the maintainer
ran `rapido-cli bench --profile p1` on; its full specification is in the
metadata header of every result file. A P2 (aarch64) run must be produced
separately, on real hardware or under QEMU with `--emulated`. **Results
produced under emulation carry `emulated: true`, the analysis scripts label
every figure containing them, and they are not credible as absolute
latencies** — only as a rough ratio between operations.

`results/p2/` is absent. Every latency in this repository is therefore from
one machine, and must be read as such.

### Why it was not filled in

The measurement host is an Apple M4 Max: already `aarch64`, but a desktop-class
core. An automotive on-board or roadside unit is a far slower embedded part. No
such hardware was available, and each substitute was rejected for a stated
reason rather than used and caveated:

* **A `linux/arm64` container on this host** runs natively on the same M4
  silicon. It would be a real second *software* profile — different OS, libc,
  allocator, toolchain target, and a readable CPU governor — but the cores are
  unchanged, so it would say nothing about on-board-unit cost while looking like
  it did.
* **QEMU TCG emulation** yields timings dominated by the interpreter's
  per-instruction-class overhead. That overhead does not track an embedded
  microarchitecture, so a "p1/p2 ratio" derived from it would not transfer —
  and transferability is the entire reason to report a ratio at all.
* **Scaling p1 by a factor** was ruled out outright. An estimated aarch64 number
  is worse than none, because it reads as a measurement.

Consequently **no p1/p2 ratio is reported**. Every absolute latency in this
repository is desktop-class. The *ratios between systems* were all measured in
one process on one machine and are the numbers that carry.

The tooling is ready: `rapido-cli bench --profile p2 --out results/p2`, adding
`--emulated` under emulation. Any run so flagged is stamped on **every** figure
automatically — `common.save` applies the stamp from loaded provenance, so an
individual plotting script cannot forget it.

---

## L13. Privacy accounting is per-release; composition is reported but not enforced

`rapido_privacy::accounting` computes both basic and advanced composition over
`k` releases, and the timing-attack report includes the daily budget for each ε.
Nothing in the implementation *enforces* a budget: an agent may authenticate as
often as it likes. A per-release ε of 1.0 composes to a daily ε in the hundreds
(see `a_days_worth_of_authentication_costs_far_more_than_one_epsilon`). **An ε
from this implementation is per release**; the composed daily figure is the
system-level number, and the per-release value must not be quoted in its place.
