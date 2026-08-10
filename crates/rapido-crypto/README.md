# rapido-crypto

The algebraic core: BLS, PRF/KDF, BBS+, Pedersen commitments, generic Schnorr
linear-relation proofs, Shamir sharing, and threshold ElGamal on BLS12-381.

## `unsafe` policy

This crate is `#![forbid(unsafe_code)]`, with **no exception in its own source**.

The `blst-backend` feature pulls in `blstrs` → `blst`, which is a C library with
assembly kernels and therefore contains `unsafe` in its Rust bindings. That is a
dependency, not code in this crate; the `forbid` attribute still holds here. The
feature is **off by default**, and nothing in the default build path links it.
The backend exists so the reported numbers can be shown to be library-dependent
rather than intrinsic, and `tests/cross_backend.rs` asserts that the two
backends produce byte-identical signatures.

## Constant-time posture

**Nothing here is verified constant-time and no side-channel resistance is
claimed.** arkworks does not advertise constant-time scalar multiplication, and
this crate does not add it.

What is guaranteed: no modular arithmetic on secrets is hand-rolled. Every field
and group operation goes through `ark-ff`/`ark-ec` (or `blst` on the feature
path). Scalar derivation uses wide reduction rather than rejection sampling
specifically because it is branch-free on the secret — the weaker of the two
properties to give up given no constant-time claim is being made.

See `LIMITATIONS.md` §L7 at the repository root.

## Conventions

* Signatures in **G2**, public keys in **G1** (minimal-pubkey-size).
* Hash-to-curve `BLS12381G2_XMD:SHA-256_SSWU_RO_` (RFC 9380), pinned to the
  RFC's vectors in `tests/rfc9380_kat.rs`.
* One domain separation tag per protocol context, never reused.
* Compressed, canonical serialization; parsing rejects off-curve points,
  small-subgroup points, the identity, and non-canonical field encodings.
