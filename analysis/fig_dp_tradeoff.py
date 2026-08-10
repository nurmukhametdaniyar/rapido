#!/usr/bin/env python3
"""Figure: what the Layer 2 timing defence buys, and what it costs.

The curve that turns "we add DP noise" into "we add DP noise and here is the
measured attacker advantage".

Two things must be read together: how much advantage the adversary retains, and
how much latency the defence added. They are on completely different scales
(a 0–1 probability and milliseconds), so they get **two stacked panels sharing
one x-axis**, never two y-scales on one plot — a dual-axis chart invents a
visual correlation that is not in the data.

The advantage plotted is the MAXIMUM over every attack tried (likelihood ratio,
mean threshold, and the learned classifier). Reporting the likelihood-ratio
curve alone understates the leak: the learned classifier beats it at small ε.
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt
import pandas as pd


def load_max_advantage() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Per (epsilon, N) advantage, maximized over every attack that was run."""
    rust = common.load_csv("attack_timing")
    geo = rust[rust["mechanism"] == "m-geo"].copy()
    if geo.empty:
        raise common.MissingResults("no m-geo rows in attack_timing.csv")
    geo["epsilon"] = geo["epsilon"].astype(float)

    best = geo.groupby(["epsilon", "n_observations"], as_index=False).agg(
        advantage=("advantage", "max")
    )

    learned_path = common.RESULTS_DIR / "attack_classifier.csv"
    if learned_path.exists():
        learned = pd.read_csv(learned_path)
        learned = learned[learned["mechanism"] == "m-geo"].copy()
        if not learned.empty:
            learned["epsilon"] = learned["epsilon"].astype(float)
            lagg = learned.groupby(["epsilon", "n_observations"], as_index=False).agg(
                learned=("advantage", "max")
            )
            best = best.merge(lagg, on=["epsilon", "n_observations"], how="outer")
            best["advantage"] = best[["advantage", "learned"]].max(axis=1)
    else:
        print(
            "attack_classifier.csv not found: plotting the Rust attacks only. "
            "The curve may understate attacker advantage.",
            file=sys.stderr,
        )

    latency = geo.groupby("epsilon", as_index=False).agg(
        mean_release_ns=("mean_release_ns", "mean")
    )
    return best.dropna(subset=["advantage"]), latency.sort_values("epsilon")


def main() -> int:
    common.setup_style()
    best, latency = load_max_advantage()
    rust = common.load_csv("attack_timing")

    fig, (ax, ax2) = plt.subplots(
        2, 1, figsize=(7.2, 6.4), sharex=True, height_ratios=[2.0, 1.0]
    )

    # --- panel 1: advantage retained ---------------------------------------
    # N is ordered, so it takes an ordinal ramp (one hue, light->dark), never
    # categorical hues.
    counts = sorted(best["n_observations"].unique())
    ramp = common.ORDINAL_BLUE
    for i, n_obs in enumerate(counts):
        sub = best[best["n_observations"] == n_obs].sort_values("epsilon")
        colour = ramp[min(i, len(ramp) - 1)]
        ax.plot(
            sub["epsilon"],
            sub["advantage"],
            marker="o",
            markersize=5,
            linewidth=2,
            color=colour,
            markeredgecolor=common.SURFACE,
            markeredgewidth=1.5,
            label=f"N = {n_obs}",
            zorder=3 + i,
        )

    undefended = rust[(rust["mechanism"] == "none")]["advantage"].max()
    ax.axhline(undefended, color=common.CRITICAL, linewidth=1.2, zorder=2)
    ax.annotate(
        f"no defence — adversary wins ({undefended:.2f})",
        (0.015, 0.955),
        xycoords="axes fraction",
        fontsize=8,
        color=common.CRITICAL,
        va="bottom",
        fontweight="bold",
    )
    pad = rust[rust["mechanism"] == "m-pad"]["advantage"].max()
    ax.axhline(pad, color=common.GOOD, linewidth=1.2, zorder=2)
    ax.annotate(
        f"M-PAD, constant release ({pad:.2f}) — perfect timing privacy",
        (0.985, 0.028),
        xycoords="axes fraction",
        ha="right",
        fontsize=8,
        color=common.GOOD,
        va="bottom",
        fontweight="bold",
    )

    ax.set_xscale("log")
    ax.set_ylim(-0.04, 1.14)
    ax.set_ylabel("attacker advantage  |2·AUC − 1|")
    ax.set_title(
        r"M-GEO timing defence: advantage retained vs $\varepsilon$ "
        r"($\delta=10^{-6}$), max over all attacks",
        pad=10,
    )
    # Lower-right is the one region no series occupies.
    # Upper-left: the one region neither the series nor the reference labels use.
    leg = ax.legend(
        fontsize=8,
        loc="upper left",
        bbox_to_anchor=(0.015, 0.93),
        ncols=2,
        title="observations per decision N",
    )
    leg.get_title().set_fontsize(8)
    leg.get_title().set_color(common.INK_SECONDARY)

    # --- panel 2: what it cost ---------------------------------------------
    ax2.plot(
        latency["epsilon"],
        latency["mean_release_ns"] / 1e6,
        marker="s",
        markersize=6,
        linewidth=2,
        color=common.SERIES_2,
        markeredgecolor=common.SURFACE,
        markeredgewidth=1.5,
        zorder=3,
    )
    for _, r in latency.iterrows():
        ax2.annotate(
            f"{r['mean_release_ns'] / 1e6:.1f} ms",
            (r["epsilon"], r["mean_release_ns"] / 1e6),
            textcoords="offset points",
            xytext=(0, 8),
            ha="center",
            fontsize=8,
            color=common.INK_SECONDARY,
        )
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_yticks([3, 5, 10, 20, 40, 60])
    ax2.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax2.get_yaxis().set_minor_formatter(plt.NullFormatter())
    ax2.set_ylim(2.2, 95)
    ax2.set_xticks([0.1, 0.5, 1.0, 2.0, 5.0])
    ax2.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax2.get_xaxis().set_minor_formatter(plt.NullFormatter())
    ax2.set_xlabel(r"privacy parameter $\varepsilon$  (per release — see composition note)")
    ax2.set_ylabel("added latency (ms, log)")
    ax2.set_title("...and what it cost in latency", pad=8, fontsize=9)

    fig.text(
        0.5,
        -0.02,
        "Crypto verification is 1.3–2.1 ms. Pushing attacker advantage below 0.5 costs "
        "~13 ms —\nfive times the entire cryptographic budget. Layer 2, not Layer 1, "
        "sets the latency envelope.",
        ha="center",
        fontsize=8,
        color=common.INK_SECONDARY,
    )
    fig.tight_layout()
    common.save(fig, "fig_dp_tradeoff.png")

    print("epsilon | max advantage (any attack, any N) | mean added latency")
    for eps, sub in best.groupby("epsilon"):
        lat = latency[latency["epsilon"] == eps]["mean_release_ns"].mean() / 1e6
        print(f"  {eps:<6} {sub['advantage'].max():>8.3f} {lat:>22.2f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
