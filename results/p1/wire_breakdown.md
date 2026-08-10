# Presentation wire-size breakdown

Every figure is `serialized.len()` on a real structure produced by the protocol, not a declared constant.

## Mode A presentation — escrow E0

| Field | What it is | Bytes |
|---|---|---:|
| `cert.P_i` | G1 compressed (one-time public key) | 48 |
| `cert.epoch` | u64 big-endian | 8 |
| `cert.attr_commitment` | G1 compressed (Pedersen commitment to identity) | 48 |
| `cert.sig` | G2 compressed (threshold BLS over the certificate) | 96 |
| `sigma` | G2 compressed (one-time key over the challenge) | 96 |
| **Total** | | **296** |

## Mode A presentation — escrow E2

| Field | What it is | Bytes |
|---|---|---:|
| `cert.P_i` | G1 compressed (one-time public key) | 48 |
| `cert.epoch` | u64 big-endian | 8 |
| `cert.attr_commitment` | G1 compressed (Pedersen commitment to identity) | 48 |
| `cert.sig` | G2 compressed (threshold BLS over the certificate) | 96 |
| `sigma` | G2 compressed (one-time key over the challenge) | 96 |
| `escrow.ct.R` *(E2 only)* | G1 compressed | 48 |
| `escrow.ct.C` *(E2 only)* | G1 compressed | 48 |
| `escrow.proof.challenge` *(E2 only)* | Fr scalar | 32 |
| `escrow.proof.responses[3]` *(E2 only)* | Fr scalars (id, r, blinding) | 96 |
| **Total** | | **520** |

## Mode B presentation (L=8, all attributes hidden) — escrow E0

| Field | What it is | Bytes |
|---|---|---:|
| `bbs.A'` | G1 compressed (re-randomized signature) | 48 |
| `bbs.A_bar` | G1 compressed | 48 |
| `bbs.d` | G1 compressed | 48 |
| `bbs.proof.challenge` | Fr scalar (Fiat-Shamir) | 32 |
| `bbs.proof.responses[11]` | Fr scalars (e, r2, r3, s', one per hidden attribute, +1 under E2) | 352 |
| `bbs.disclosed[1]` | u32 index + Fr value per disclosed attribute | 36 |
| `epoch` | u64 big-endian | 8 |
| **Total** | | **572** |

## Mode B presentation (L=8, all attributes hidden) — escrow E2

| Field | What it is | Bytes |
|---|---|---:|
| `bbs.A'` | G1 compressed (re-randomized signature) | 48 |
| `bbs.A_bar` | G1 compressed | 48 |
| `bbs.d` | G1 compressed | 48 |
| `bbs.proof.challenge` | Fr scalar (Fiat-Shamir) | 32 |
| `bbs.proof.responses[12]` | Fr scalars (e, r2, r3, s', one per hidden attribute, +1 under E2) | 384 |
| `bbs.disclosed[1]` | u32 index + Fr value per disclosed attribute | 36 |
| `epoch` | u64 big-endian | 8 |
| `escrow.ct.R` *(E2 only)* | G1 compressed | 48 |
| `escrow.ct.C` *(E2 only)* | G1 compressed | 48 |
| **Total** | | **700** |

## E2 delta

| Mode | E0 | E2 | E2 delta |
|---|---:|---:|---:|
| A | 296 B | 520 B | **+224 B** |
| B | 572 B | 700 B | **+128 B** |

## Is the escrow proof shared with the presentation proof?

**Yes, implemented** — E0 presentation carries 11 Schnorr responses; E2 carries 12. The escrow attachment under E2 is `ProvenInPresentation`, which holds only the ciphertext. The escrow statement is therefore proved by the same Fiat-Shamir challenge as the credential, costing exactly 1 extra response scalar(s) = 32 B, plus the 96 B ciphertext.

- Every breakdown agrees with the protocol's own size_bytes().
