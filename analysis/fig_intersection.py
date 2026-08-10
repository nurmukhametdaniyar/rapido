#!/usr/bin/env python3
"""Figure: does the RSU meet the 100 ms intersection deadline?

Scenario 1 — V vehicles authenticate to one RSU inside a 100 ms window, with
real cryptography, 10 seeds per point.

Colour: core count is an *ordered* variable, so it takes the one-hue ordinal
ramp (light = fewest cores), never categorical hues. One legend serves both
panels — repeating it twice would spend space on nothing.
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt


def main() -> int:
    common.setup_style()
    df = common.load_csv("scenario1_intersection")
    agg = df.groupby(["vehicles", "cores"], as_index=False).agg(
        completion_rate=("completion_rate", "mean"),
        completion_std=("completion_rate", "std"),
        p99_ns=("p99_ns", "mean"),
        queue=("max_queue_depth", "mean"),
    )
    core_counts = sorted(agg["cores"].unique())
    ramp = common.ORDINAL_BLUE
    colour_of = {
        c: ramp[min(int(i * (len(ramp) - 1) / max(len(core_counts) - 1, 1)), len(ramp) - 1)]
        for i, c in enumerate(core_counts)
    }

    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.6))
    deadline_ms = df["deadline_ns"].iloc[0] / 1e6

    for cores in core_counts:
        sub = agg[agg["cores"] == cores].sort_values("vehicles")
        colour = colour_of[cores]
        axes[0].errorbar(
            sub["vehicles"], sub["completion_rate"],
            yerr=sub["completion_std"].fillna(0.0), marker="o", markersize=7,
            linewidth=2, capsize=3, color=colour,
            markeredgecolor=common.SURFACE, markeredgewidth=1.4,
            label=f"{int(cores)} core" + ("s" if cores != 1 else ""), zorder=3,
        )
        axes[1].plot(
            sub["vehicles"], sub["p99_ns"] / 1e6, marker="o", markersize=7,
            linewidth=2, color=colour, markeredgecolor=common.SURFACE,
            markeredgewidth=1.4, zorder=3,
        )

    # --- left: deadline compliance ---
    axes[0].set_xlabel("vehicles in the burst")
    axes[0].set_ylabel(f"fraction completing within {deadline_ms:.0f} ms")
    axes[0].set_ylim(-0.04, 1.06)
    axes[0].set_xticks([20, 50, 100])
    axes[0].set_title("Deadline compliance", pad=10)
    worst = agg[(agg["cores"] == min(core_counts)) & (agg["vehicles"] == max(agg["vehicles"]))]
    if not worst.empty:
        w = worst.iloc[0]
        axes[0].annotate(
            f"1 core / {int(w['vehicles'])} vehicles:\nonly {w['completion_rate']:.0%} make the deadline",
            (w["vehicles"], w["completion_rate"]),
            textcoords="offset points", xytext=(-12, 18), ha="right",
            fontsize=8.5, color=common.CRITICAL, fontweight="bold",
        )
    # Right side, below the saturated 1.0 lines: the only free region.
    axes[0].annotate(
        "2 cores and above:\nevery vehicle completes",
        (0.97, 0.90), xycoords="axes fraction", ha="right", va="top",
        fontsize=8.5, color=common.GOOD, fontweight="bold",
    )
    leg = axes[0].legend(fontsize=8.5, loc="lower left", title="verifier cores")
    leg.get_title().set_fontsize(8.5)
    leg.get_title().set_color(common.INK_SECONDARY)

    # --- right: tail latency ---
    axes[1].axhline(deadline_ms, color=common.CRITICAL, linewidth=1.4, zorder=2)
    axes[1].annotate(
        f"{deadline_ms:.0f} ms deadline", (0.02, deadline_ms * 1.12),
        xycoords=("axes fraction", "data"), fontsize=8.5,
        color=common.CRITICAL, fontweight="bold",
    )
    axes[1].set_xlabel("vehicles in the burst")
    axes[1].set_ylabel("p99 authentication latency (ms, log)")
    axes[1].set_yscale("log")
    axes[1].set_xticks([20, 50, 100])
    axes[1].set_title("Tail latency under burst load", pad=10)
    for cores in core_counts:
        sub = agg[agg["cores"] == cores].sort_values("vehicles").iloc[-1]
        axes[1].annotate(
            f"{int(cores)}c", (sub["vehicles"], sub["p99_ns"] / 1e6),
            textcoords="offset points", xytext=(8, 0), va="center",
            fontsize=8, fontweight="bold", color=colour_of[cores],
        )

    fig.tight_layout()
    common.save(fig, "fig_intersection.png")

    for _, r in agg.sort_values(["vehicles", "cores"]).iterrows():
        print(f"V={int(r['vehicles']):>4} cores={int(r['cores'])}: "
              f"completion {r['completion_rate']:.3f}, p99 {r['p99_ns'] / 1e6:.2f} ms, "
              f"max queue {r['queue']:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
