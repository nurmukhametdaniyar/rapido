# results/

Committed measured output, one directory per hardware profile. **These files are
the provenance of every number this project reports**, which is why they live in
the repository rather than being regenerated on demand.

```
results/
  p1/    x86_64 workstation/laptop
  p2/    aarch64 SBC (on-board-unit proxy) — may be absent; see LIMITATIONS.md L12
```

Per profile:

| file | produced by |
|---|---|
| `bench.json` / `bench.csv` | `rapido-cli bench` |
| `wire_sizes.json` | `rapido-cli bench` |
| `scenario1_intersection.*` | `rapido-cli sim --scenario 1` |
| `scenario2_metropolitan.*` | `rapido-cli sim --scenario 2` |
| `scenario3_connectivity.*` | `rapido-cli sim --scenario 3` |
| `scenario4_linkability.*` | `rapido-cli sim --scenario 4` |
| `attack_timing.*` | `rapido-cli attack --target timing` |
| `attack_cover.*` | `rapido-cli attack --target cover` |
| `attack_linkability.*` | `rapido-cli attack --target linkability` |

Every JSON file opens with a `meta` header recording the machine, OS and kernel,
toolchain, target triple, optimization flags, `target-cpu`, CPU governor state,
git commit, and the pinned versions of every crypto crate the timings depend on.
A number without that header is not traceable and should not be cited.

## Reading the metadata before reading the numbers

Two fields decide whether a result means anything:

* **`emulated`** — `true` means the run was under QEMU. Absolute latencies from
  emulation are not credible; only rough ratios between operations are. The
  analysis scripts stamp every figure containing such data.
* **`cpu_governor`** — on Linux this is the scaling governor and turbo state. On
  macOS frequency is not controllable from userspace, and the field says
  `not-controllable (macOS)`. Runs on an unpinned machine carry more
  run-to-run variance than the confidence intervals alone suggest.

Rows whose `reduced_iterations` parameter is `true` were measured with fewer
than the usual floor of 1000, because the operation is too slow for that many
(batch issuance of 1000 pseudonyms, full audit-chain verification).
The actual count is in the `iterations` column.

A row with `below_clock_resolution = true` is faster than the clock can resolve,
so its median came out at zero. **That is not a measurement of "instant"** — cite
the batched measurement of the same operation instead. The committed files here
predate that column; it is emitted from the next `rapido-cli bench` run onward,
and its absence changes none of the measured values (the field is derived from
the same samples, not from a different measurement path).
