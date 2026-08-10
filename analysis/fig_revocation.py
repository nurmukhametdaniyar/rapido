#!/usr/bin/env python3
"""Figures: revocation lookup cost, and the tradeoff behind it.

Left: what each revocation variant costs to check, against |R|.
Right: why R0's O(1) check is not free — it is paid for with up to a full epoch
of revocation latency, and the epoch length that keeps agents available through
an outage is exactly the one that makes revocation slow.

Colour: the left panel's three variants are *identity* (categorical slots 1-3,
validated all-pairs). The right panel's outage durations are *ordered*, so they
take the one-hue ordinal ramp — never categorical hues for an ordered series.
Every series is direct-labelled, which is also the relief the aqua slot needs
(it sits below 3:1 on the light surface).
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt

VARIANTS = [
    ("r1-crl-hashset-miss", "R1: CRL (hash set)", common.SERIES_1, {}),
    ("r1-crl-linear-miss", "R1: CRL (linear scan)", common.SERIES_2, {}),
    ("r2-bloom-miss", "R2: Bloom filter", common.SERIES_3, {"fp_target": 0.01}),
]


def cost_panel(ax, df) -> None:
    for name, label, colour, cond in VARIANTS:
        sub = df[df["name"] == name]
        if cond:
            sub = common.select(sub, **cond)
        if sub.empty:
            continue
        sub = sub.copy()
        sub["R"] = sub["R"].astype(float)
        sub = sub.sort_values("R")
        ax.plot(sub["R"], sub["median_ns"], marker="o", markersize=7, linewidth=2,
                color=colour, markeredgecolor=common.SURFACE, markeredgewidth=1.4,
                zorder=3)
        last = sub.iloc[-1]
        ax.annotate(label, (last["R"], last["median_ns"]), textcoords="offset points",
                    xytext=(-6, 12), ha="right", fontsize=8.5, fontweight="bold",
                    color=colour)

    r0 = df[df["name"] == "r0-epoch-check"]
    if not r0.empty:
        v = float(r0.iloc[0]["median_ns"])
        ax.axhline(v, color=common.INK_MUTED, linewidth=1.2, zorder=2)
        ax.annotate(f"R0: epoch check — {v:.1f} ns, O(1)",
                    (1.05e3, v * 1.25), fontsize=8.5, color=common.INK_SECONDARY,
                    fontweight="bold")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("|R|  (revoked credentials)")
    ax.set_ylabel("lookup latency (ns, log)")
    ax.set_title("What a revocation check costs", pad=10)


def availability_panel(ax) -> None:
    df = common.load_csv("scenario3_connectivity")
    epoch_sweep = df[df["sweep"] == "epoch"]
    if epoch_sweep.empty:
        return
    agg = epoch_sweep.groupby(["epoch_minutes", "outage_minutes"], as_index=False).agg(
        failure_rate=("failure_rate", "mean")
    )
    outages = sorted(agg["outage_minutes"].unique())
    for i, outage in enumerate(outages):
        sub = agg[agg["outage_minutes"] == outage].sort_values("epoch_minutes")
        colour = common.ORDINAL_BLUE[min(i, len(common.ORDINAL_BLUE) - 1)]
        ax.plot(sub["epoch_minutes"] * 60, sub["failure_rate"], marker="o", markersize=6,
                linewidth=2, color=colour, markeredgecolor=common.SURFACE,
                markeredgewidth=1.4, zorder=3 + i, label=f"{int(outage)} min outage")
    ax.set_xscale("log")
    ax.set_xlabel("worst-case revocation latency = epoch length T  (s, log)")
    ax.set_ylabel("fraction of agents unable to authenticate")
    ax.set_title("...and what that O(1) check costs in availability", pad=10)
    # Headroom so the callout clears the saturated lines at 1.0, but the ticks
    # stop at 1.0 — this is a fraction, and a 1.2 tick would imply otherwise.
    ax.set_ylim(-0.04, 1.30)
    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    leg = ax.legend(fontsize=8, loc="lower left", title="connectivity outage")
    leg.get_title().set_fontsize(8)
    leg.get_title().set_color(common.INK_SECONDARY)
    ax.annotate(
        "an outage longer than T\nstrands essentially everyone",
        (0.97, 0.99), xycoords="axes fraction", ha="right", va="top",
        fontsize=8, color=common.CRITICAL, fontweight="bold",
    )


def main() -> int:
    common.setup_style()
    bench = common.bench_frame()
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6))
    cost_panel(axes[0], bench)
    try:
        availability_panel(axes[1])
    except common.MissingResults as exc:
        print(f"skipping availability panel: {exc}", file=sys.stderr)
    fig.tight_layout()
    common.save(fig, "fig_revocation.png")

    r0 = bench[bench["name"] == "r0-epoch-check"]
    if not r0.empty:
        ns = float(r0.iloc[0]["median_ns"])
        print(f"R0 epoch check measured at {ns:.2f} ns = {ns / 1e6:.7f} ms. "
              f"Its real cost is revocation delay, not lookup time.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
