#!/usr/bin/env python3
"""Figure: attacker AUC vs cover-traffic bandwidth overhead.

Note the sign. Cover traffic is extra messages that carry no work, so it
increases bandwidth; there is no configuration in which it saves bytes. The
x-axis here is a measured **increase**, and the script asserts that it is.
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt


def main() -> int:
    common.setup_style()
    df = common.load_csv("attack_cover").sort_values("cover_rate_hz")

    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    ax.plot(
        df["bandwidth_overhead_pct"],
        df["advantage"],
        marker="o",
        markersize=8,
        linewidth=2,
        color=common.SERIES_1,
        markeredgecolor=common.SURFACE,
        markeredgewidth=1.6,
        zorder=3,
    )
    # Direct-label selectively: the left-hand points sit within a few hundred
    # percent of each other and would otherwise overprint into an unreadable
    # smear.
    for _, row in df.iterrows():
        if row["cover_rate_hz"] not in (0.0, 5.0, 25.0, 50.0, 100.0, 200.0):
            continue
        label = "no cover" if row["cover_rate_hz"] == 0 else f"{row['cover_rate_hz']:.0f} Hz"
        ax.annotate(
            label,
            (row["bandwidth_overhead_pct"], row["advantage"]),
            textcoords="offset points",
            xytext=(10, 7),
            fontsize=8.5,
            color=common.INK_SECONDARY,
        )
    ax.set_xlabel("bandwidth overhead  (% INCREASE over genuine traffic)")
    ax.set_ylabel("adversary advantage at detecting activity")
    ax.set_ylim(-0.03, 1.12)
    ax.set_title("Cover traffic: what hiding activity costs in bytes", pad=12)

    # The exchange rate is the finding; put it on the chart.
    half = df[df["advantage"] <= 0.5]
    if not half.empty:
        pt = half.iloc[0]
        ax.annotate(
            f"halving the adversary's advantage\ncosts a {pt['bandwidth_overhead_pct'] / 100:.0f}x"
            " increase in bytes",
            (pt["bandwidth_overhead_pct"], pt["advantage"]),
            textcoords="offset points",
            xytext=(35, 55),
            fontsize=8.5,
            color=common.CRITICAL,
            fontweight="bold",
            arrowprops=dict(arrowstyle="-", color=common.CRITICAL, linewidth=1.0),
        )
    fig.text(
        0.5,
        -0.04,
        "Cover traffic is extra messages carrying no work, so it always INCREASES "
        "bandwidth;\nevery point on this curve is a measured increase.",
        ha="center",
        fontsize=8,
        color=common.INK_SECONDARY,
    )
    common.save(fig, "fig_cover_tradeoff.png")

    print("cover_rate_hz, bandwidth_overhead_pct (INCREASE), advantage")
    for _, r in df.iterrows():
        print(f"{r['cover_rate_hz']:>8.1f}, {r['bandwidth_overhead_pct']:>10.1f}, {r['advantage']:.3f}")
    if (df["bandwidth_overhead_pct"] < 0).any():
        raise AssertionError("cover traffic cannot reduce bandwidth; check the measurement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
