#!/usr/bin/env python3
"""Figure: measured per-layer verification cost.

Reads `pipeline_breakdown.csv`, which records each layer **and** the total from
the same execution of the verifier, so a decomposition can never disagree with
its own total. Summing separately-measured micro-benchmarks instead would omit
the work the pipeline does between the layers, and would let one configuration
end up with two different latencies.

Also prints the answer to: what does a sound escrow proof cost? (E2 minus E1.)
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt
import numpy as np

# (mode, escrow, path) -> column label
CONFIGS = [
    ("mode-a", "e0", "naive", "Mode A\nnaive, no escrow"),
    ("mode-a", "e0", "aggregate", "Mode A\naggregate, no escrow"),
    ("mode-a", "e2", "naive", "Mode A\nnaive + E2"),
    ("mode-a", "e2", "aggregate", "Mode A\naggregate + E2"),
    ("mode-b", "e0", "n/a", "Mode B\nno escrow"),
    ("mode-b", "e2", "n/a", "Mode B\n+ E2"),
]


def main() -> int:
    common.setup_style()
    df = common.load_csv("pipeline_breakdown")
    profile = sorted(df["profile"].unique())[0]
    sub = df[df["profile"] == profile]

    rows, labels = [], []
    for mode, escrow, path, label in CONFIGS:
        hit = sub[(sub["mode"] == mode) & (sub["escrow"] == escrow) & (sub["path"] == path)]
        if hit.empty:
            continue
        rows.append(hit.iloc[0])
        labels.append(label)
    if not rows:
        raise common.MissingResults("no pipeline_breakdown rows")

    layer1 = np.array([float(r["layer1_ms"]) for r in rows])
    escrow = np.array([float(r["escrow_ms"]) for r in rows])
    totals = np.array([float(r["wallclock_ms"]) for r in rows])
    # Whatever the instrumented layers do not account for, shown rather than
    # dropped, so the bars add up to the number that gets cited.
    other = totals - layer1 - escrow

    fig, ax = plt.subplots(figsize=(8.0, 4.6))
    x = np.arange(len(labels))
    gap = 0.012

    ax.bar(x, layer1, width=0.58, color=common.SERIES_1,
           label="Layer 1 — credential verification")
    ax.bar(x, escrow, width=0.58, bottom=layer1 + gap, color=common.SERIES_2,
           label="Layer 3 — escrow proof check")
    ax.bar(x, other, width=0.58, bottom=layer1 + escrow + 2 * gap,
           color=common.DEEMPHASIS,
           label="revocation, replay, pipeline overhead")
    ax.grid(False, axis="x")

    for xi, (t, a, b) in zip(x, zip(totals, layer1, escrow)):
        ax.annotate(f"{common.sig3(t)} ms", (xi, t), textcoords="offset points",
                    xytext=(0, 6), ha="center", fontsize=9.5, fontweight="bold",
                    color=common.INK_PRIMARY)
        if b > 0.35:
            ax.annotate(f"+{common.sig3(b)}", (xi, a + b / 2), ha="center", va="center",
                        fontsize=8, color="white", fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8.5)
    ax.tick_params(axis="x", length=0)
    ax.set_ylabel("verification latency (ms)")
    ax.set_ylim(0, max(totals) * 1.22)
    ax.set_title(
        f"In-path per-layer verification cost — profile {profile}", pad=12
    )
    ax.legend(fontsize=8.5, loc="upper left")

    bench = common.bench_frame()
    bsub = bench[bench["profile"] == profile]

    def med(name, **cond):
        hit = common.select(bsub[bsub["name"] == name], **cond)
        return float(hit.iloc[0]["median_ms"]) if not hit.empty else float("nan")

    rev_ns = med("r0-epoch-check") * 1e6
    replay_ns = med("nonce-cache-insert", entries=1000000) * 1e6
    e1, e2 = med("escrow-check", escrow="e1"), med("escrow-check", escrow="e2")

    foot = (
        f"Layers and totals come from the same verifier execution, so a "
        f"decomposition cannot disagree with its own total.\n"
        f"Revocation (R0) measures {common.sig3(rev_ns)} ns and the replay check "
        f"{common.sig3(replay_ns)} ns at 10⁶ entries — together under 0.01% of "
        f"every bar, hence the third segment is barely visible."
    )
    if np.isfinite(e1) and np.isfinite(e2):
        foot += f"  A sound escrow proof (E2 − E1) costs {e2 - e1:+.3f} ms."
    fig.text(0.5, -0.07, foot, ha="center", fontsize=8, color=common.INK_SECONDARY)

    common.save(fig, "fig_latency_breakdown.png")

    if np.isfinite(e1) and np.isfinite(e2):
        print(f"[{profile}] a sound escrow proof (E2 - E1) costs {e2 - e1:+.4f} ms")
    print(f"[{profile}] revocation R0 = {rev_ns:.2f} ns, replay = {replay_ns:.0f} ns")
    for lab, r, t in zip(labels, rows, totals):
        print(f"[{profile}] {lab.replace(chr(10), ' '):<28} total {t:.3f} ms "
              f"(unattributed {float(r['unattributed_ms']):.4f} ms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
