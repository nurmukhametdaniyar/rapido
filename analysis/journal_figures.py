#!/usr/bin/env python3
"""Journal-style figures: vector output, greyscale-legible, self-contained.

These are deliberately separate from the `fig_*.py` presentation graphics. The
differences are not cosmetic:

* **Vector** (PDF for LaTeX, SVG for the web) rather than raster.
* **Greyscale-legible.** Every series is separated by marker shape and line
  style as well as by tone, and the tones are chosen for distinct luminance, so
  a black-and-white print stays readable. Colour never carries meaning alone.
* **No argument with prior work.** A journal figure has to stand on its own for
  a reader with no other context, so nothing here annotates what anyone else
  claimed. The measured value is the whole statement.
* **Single-column sizing.** 3.4 in wide with 7-8 pt type, checked at that size.

Run after the experiments:

    python analysis/journal_figures.py

Writes `analysis/figures/journal/fig{1..4}.{pdf,svg}`.
"""

from __future__ import annotations

import sys

import common
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

OUT = common.FIGURES_DIR / "journal"

# Single-column width for a two-column journal page.
COL_W = 3.4
DOUBLE_W = 7.0

# Luminance-separated tones. These read as distinct greys when printed in
# black and white, which colour hues alone would not. The lightest step stops
# well short of the page so it stays visible on paper.
INK = "#000000"
TONE = ["#000000", "#3d3d3d", "#6b6b6b", "#949494", "#b4b4b4"]

#: Tone order for an *ordered* series where a later step means a stronger
#: effect: darker reads as stronger, so the ramp runs light -> dark with the
#: series, not the other way round.
def ordered_tone(i: int, n: int) -> str:
    if n <= 1:
        return TONE[0]
    step = int(round((n - 1 - i) * (len(TONE) - 1) / (n - 1)))
    return TONE[step]
FILL_LIGHT = "#e8e8e8"
HATCH_EDGE = "#5a5a5a"

MARKERS = ["o", "s", "^", "D", "v"]
LINESTYLES = ["-", "--", "-.", ":", (0, (3, 1, 1, 1, 1, 1))]


def journal_style() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 150,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
            "font.size": 7.5,
            "font.family": "sans-serif",
            "axes.labelsize": 7.5,
            "axes.titlesize": 8,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "legend.fontsize": 6.8,
            "axes.linewidth": 0.6,
            "xtick.major.width": 0.6,
            "ytick.major.width": 0.6,
            "xtick.major.size": 2.5,
            "ytick.major.size": 2.5,
            "axes.edgecolor": "#333333",
            "axes.labelcolor": INK,
            "text.color": INK,
            "xtick.color": "#333333",
            "ytick.color": "#333333",
            "axes.grid": True,
            "grid.color": "#d9d9d9",
            "grid.linewidth": 0.4,
            "grid.linestyle": "-",
            "axes.axisbelow": True,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,  # embed TrueType, not Type 3
            "svg.fonttype": "none",  # keep text as text in the SVG
        }
    )


def save_vector(fig, stem: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if common.emulated_profiles():
        which = ", ".join(sorted(common.emulated_profiles()))
        fig.text(
            0.5, 0.995, f"contains emulated results ({which})",
            ha="center", va="top", fontsize=6.5, style="italic", color="#333333",
        )
    for ext in ("pdf", "svg"):
        path = OUT / f"{stem}.{ext}"
        fig.savefig(path)
        print(f"wrote {path}")
    plt.close(fig)


# --- Figure 1: protocol diagram ---------------------------------------------


def _box(ax, x, y, w, h, label, sub=None, tone=INK, fill="white"):
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.012,rounding_size=0.02",
            linewidth=0.8, edgecolor=tone, facecolor=fill,
        )
    )
    ax.text(x + w / 2, y + h / 2 + (0.028 if sub else 0), label,
            ha="center", va="center", fontsize=7.2, color=INK)
    if sub:
        ax.text(x + w / 2, y + h / 2 - 0.038, sub, ha="center", va="center",
                fontsize=6.2, color="#4a4a4a", style="italic")


def _arrow(ax, xy_from, xy_to, label=None, style="-", tone="#4a4a4a", rad=0.0, lw=0.8):
    ax.annotate(
        "", xy=xy_to, xytext=xy_from,
        arrowprops=dict(arrowstyle="-|>", linestyle=style, color=tone,
                        linewidth=lw, shrinkA=2, shrinkB=2,
                        connectionstyle=f"arc3,rad={rad}"),
    )
    if label:
        mx = (xy_from[0] + xy_to[0]) / 2
        my = (xy_from[1] + xy_to[1]) / 2
        ax.text(mx, my + 0.028, label, ha="center", va="bottom",
                fontsize=6.2, color="#333333")


def figure1_protocol() -> None:
    """Mode A and Mode B side by side, same visual grammar.

    Issuance on top, presentation below, verifier on the right. The point the
    figure has to make is structural: in Mode A the issuer retains a link from
    each certified one-time key back to the agent, and in Mode B there is no
    such link to retain.
    """
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_W, 2.9))

    for ax, mode in zip(axes, ("A", "B")):
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")

        _box(ax, 0.02, 0.62, 0.26, 0.20, "Issuer", "(k, n) threshold" if mode == "A" else "single authority")
        _box(ax, 0.02, 0.16, 0.26, 0.20, "Agent")
        _box(ax, 0.72, 0.16, 0.26, 0.20, "Verifier")

        if mode == "A":
            _arrow(ax, (0.15, 0.36), (0.15, 0.62), r"$\{P_i\}$ + PoP")
            _arrow(ax, (0.24, 0.62), (0.24, 0.36), None, style="--")
            ax.text(0.30, 0.49, r"cert$_i$ = Sign$_{\mathrm{auth}}$", fontsize=6.2,
                    color="#333333", va="center")
            _arrow(ax, (0.28, 0.26), (0.72, 0.26), r"(cert$_i$, $P_i$, $\sigma$)")

            # The retained link: issuer -> the pseudonym that appears on the wire.
            _arrow(ax, (0.28, 0.72), (0.86, 0.36), None, style=":", tone=INK,
                   rad=-0.32, lw=1.1)
            ax.text(0.60, 0.70,
                    "issuer retains $P_i \\rightarrow$ agent\nfor every certified key",
                    ha="center", va="center", fontsize=6.4, color=INK,
                    bbox=dict(boxstyle="round,pad=0.25", facecolor=FILL_LIGHT,
                              edgecolor=HATCH_EDGE, linewidth=0.5))
            ax.set_title("(a) Mode A — batch pseudonym certificates", fontsize=8, pad=6)
        else:
            _arrow(ax, (0.15, 0.36), (0.15, 0.62), "attributes")
            _arrow(ax, (0.24, 0.62), (0.24, 0.36), None, style="--")
            ax.text(0.30, 0.49, "BBS+ credential", fontsize=6.2,
                    color="#333333", va="center")
            _arrow(ax, (0.28, 0.26), (0.72, 0.26),
                   r"re-randomized $(A', \bar{A}, d)$ + PoK")

            ax.text(0.60, 0.70,
                    "nothing the issuer signed\nappears on the wire",
                    ha="center", va="center", fontsize=6.4, color=INK,
                    bbox=dict(boxstyle="round,pad=0.25", facecolor="white",
                              edgecolor=HATCH_EDGE, linewidth=0.5,
                              linestyle="--"))
            ax.set_title("(b) Mode B — BBS+ presentation", fontsize=8, pad=6)

    fig.tight_layout()
    save_vector(fig, "fig1_protocol")


# --- Figure 2: verification cost --------------------------------------------

ROWS = [
    ("Idemix-like CL-RSA-2048", "cl-rsa-verify", {"L": 5, "n_disclosed": 0}, True),
    ("RAPIDO Mode A + E2", "mode-a-verify-full-pipeline", {"escrow": "e2"}, True),
    ("RAPIDO Mode A, aggregate", "mode-a-verify-aggregate", {"escrow": "e0"}, True),
    ("RAPIDO Mode A, naive", "mode-a-verify-naive", {"escrow": "e0"}, True),
    ("RAPIDO Mode B + E2", "mode-b-verify",
     {"L": 8, "disclosure_fraction": 0.0, "escrow": "e2"}, True),
    ("RAPIDO Mode B, $L{=}8$", "mode-b-verify",
     {"L": 8, "disclosure_fraction": 0.0, "escrow": "e0"}, True),
    ("mTLS ECDSA P-256", "mtls-p256-verify", {}, False),
    ("SCMS explicit", "scms-explicit-verify", {}, False),
    ("SCMS implicit (ECQV)", "scms-implicit-verify", {}, False),
    ("mTLS Ed25519", "mtls-ed25519-verify", {}, False),
]


def figure2_verification_cost() -> None:
    df = common.bench_frame()
    profile = sorted(df["profile"].unique())[0]
    sub = df[df["profile"] == profile]

    points = []
    for label, name, cond, is_rapido in ROWS:
        hit = common.select(sub[sub["name"] == name], **cond)
        if hit.empty:
            continue
        r = hit.iloc[0]
        nbytes = None if pd.isna(r.get("bytes")) else int(r["bytes"])
        points.append((label, float(r["median_ms"]), nbytes, is_rapido))
    if not points:
        raise common.MissingResults("no verification rows in bench.csv")

    points.sort(key=lambda p: -p[1])

    fig, ax = plt.subplots(figsize=(COL_W, 3.1))
    for y, (label, ms, nbytes, is_rapido) in enumerate(points):
        # Shape carries the RAPIDO/comparison distinction, so it survives
        # greyscale printing; tone reinforces it.
        marker = "o" if is_rapido else "s"
        face = INK if is_rapido else "white"
        edge = INK if is_rapido else TONE[1]
        ax.plot([0.03, ms], [y, y], color="#cccccc", linewidth=0.5, zorder=1)
        ax.plot([ms], [y], marker=marker, markersize=4.2, markerfacecolor=face,
                markeredgecolor=edge, markeredgewidth=0.9, zorder=3)
        txt = f"{common.sig3(ms)}"
        if nbytes is not None:
            txt += f"  ({nbytes} B)"
        ax.annotate(txt, (ms, y), textcoords="offset points", xytext=(6, 0),
                    va="center", fontsize=6.4, color=INK)

    ax.set_yticks(range(len(points)))
    ax.set_yticklabels([p[0] for p in points])
    ax.tick_params(axis="y", length=0)
    ax.set_xscale("log")
    # Right-hand headroom for the value labels themselves.
    ax.set_xlim(0.03, 90)
    ax.set_xticks([0.05, 0.2, 1, 5, 20])
    ax.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.get_xaxis().set_minor_formatter(plt.NullFormatter())
    ax.set_xlabel("verification latency (ms, log scale)")
    ax.grid(True, axis="x")
    ax.grid(False, axis="y")

    ax.legend(
        handles=[
            Line2D([], [], marker="o", linestyle="", markersize=4.2,
                   markerfacecolor=INK, markeredgecolor=INK, label="RAPIDO"),
            Line2D([], [], marker="s", linestyle="", markersize=4.2,
                   markerfacecolor="white", markeredgecolor=TONE[1],
                   label="comparison system"),
        ],
        # Below the axes, not inside it. The value labels are placed in display
        # offsets from each marker, so their extent does not shrink when the
        # data range widens — an in-axes legend at any corner eventually
        # collides with one. Putting it outside removes the failure mode
        # instead of tuning around it.
        loc="upper center", bbox_to_anchor=(0.5, -0.16), ncols=2,
        handletextpad=0.4, columnspacing=1.6,
    )
    fig.tight_layout()
    save_vector(fig, "fig2_verification_cost")


# --- Figure 3: timing defence ------------------------------------------------


def _advantage_surface() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Max-over-attacks advantage with CI, plus the latency series."""
    rust = common.load_csv("attack_timing")
    geo = rust[rust["mechanism"] == "m-geo"].copy()
    if geo.empty:
        raise common.MissingResults("no m-geo rows in attack_timing.csv")
    geo["epsilon"] = geo["epsilon"].astype(float)

    frames = [geo[["epsilon", "n_observations", "advantage",
                   "advantage_ci_lo", "advantage_ci_hi"]]]
    learned_path = common.RESULTS_DIR / "attack_classifier.csv"
    if learned_path.exists():
        learned = pd.read_csv(learned_path)
        learned = learned[learned["mechanism"] == "m-geo"].copy()
        if not learned.empty:
            learned["epsilon"] = learned["epsilon"].astype(float)
            frames.append(learned[["epsilon", "n_observations", "advantage",
                                   "advantage_ci_lo", "advantage_ci_hi"]])
    allatt = pd.concat(frames, ignore_index=True)

    # Max over attacks at each (epsilon, N); the interval travels with the
    # winning estimate rather than being recomputed across attacks.
    idx = allatt.groupby(["epsilon", "n_observations"])["advantage"].idxmax()
    best = allatt.loc[idx].reset_index(drop=True)

    latency = geo.groupby("epsilon", as_index=False).agg(
        mean_release_ns=("mean_release_ns", "mean")
    ).sort_values("epsilon")
    return best, latency


def figure3_timing_defence() -> None:
    best, latency = _advantage_surface()
    rust = common.load_csv("attack_timing")

    fig, (ax, ax2) = plt.subplots(
        2, 1, figsize=(COL_W, 3.7), sharex=True, height_ratios=[2.1, 1.0]
    )

    counts = sorted(best["n_observations"].unique())
    for i, n in enumerate(counts):
        s = best[best["n_observations"] == n].sort_values("epsilon")
        # More observations = stronger attacker = darker line.
        tone = ordered_tone(i, len(counts))
        ax.fill_between(s["epsilon"], s["advantage_ci_lo"], s["advantage_ci_hi"],
                        color=tone, alpha=0.22, linewidth=0)
        ax.plot(s["epsilon"], s["advantage"],
                marker=MARKERS[i % len(MARKERS)], markersize=3.4,
                linestyle=LINESTYLES[i % len(LINESTYLES)], linewidth=1.0,
                color=tone, markerfacecolor="white", markeredgewidth=0.8,
                label=f"$N={n}$")

    pad = rust[rust["mechanism"] == "m-pad"]["advantage"].max()
    ax.axhline(pad, color=INK, linewidth=0.8, linestyle=(0, (6, 2)))
    ax.annotate("constant-release mechanism", (0.985, pad + 0.03),
                xycoords=("axes fraction", "data"), ha="right",
                fontsize=6.3, color=INK)

    ax.set_xscale("log")
    ax.set_ylim(-0.04, 1.1)
    ax.set_ylabel("adversary advantage")
    ax.legend(ncols=2, loc="upper left", handlelength=2.4, columnspacing=1.0)

    ax2.plot(latency["epsilon"], latency["mean_release_ns"] / 1e6,
             marker="o", markersize=3.4, linewidth=1.0, color=INK,
             markerfacecolor="white", markeredgewidth=0.8)
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel(r"privacy parameter $\varepsilon$ per release")
    ax2.set_ylabel("added latency (ms)")
    ax2.set_xticks([0.1, 0.5, 1, 2, 5])
    ax2.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax2.get_xaxis().set_minor_formatter(plt.NullFormatter())
    ax2.set_yticks([3, 10, 30, 60])
    ax2.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax2.get_yaxis().set_minor_formatter(plt.NullFormatter())

    fig.tight_layout()
    save_vector(fig, "fig3_timing_defence")


# --- Figure 4: revocation trade ----------------------------------------------


def figure4_revocation_trade(
    availability_outage_min: int = 60, revocation_target_min: int = 30
) -> None:
    """Epoch length against stranded agents, with the feasible region shaded.

    The shaded band is the set of epoch lengths meeting a revocation-latency
    target; the horizontal band is an availability target. Their intersection is
    what a deployment would need, and the figure shows whether one exists.
    """
    df = common.load_csv("scenario3_connectivity")
    sweep = df[df["sweep"] == "epoch"]
    if sweep.empty:
        raise common.MissingResults("no epoch sweep in scenario3")
    agg = sweep.groupby(["epoch_minutes", "outage_minutes"], as_index=False).agg(
        failure_rate=("failure_rate", "mean")
    )

    fig, ax = plt.subplots(figsize=(COL_W, 2.8))

    avail_limit = 0.05          # at most 5% of agents stranded
    revoc_limit_s = revocation_target_min * 60

    outages = sorted(agg["outage_minutes"].unique())
    xs = sorted(agg["epoch_minutes"].unique() * 60)
    ax.set_xlim(min(xs) * 0.75, max(xs) * 1.4)

    # The region a deployment would have to land in: fast enough to revoke AND
    # available enough to keep agents online. Shaded lightly so the data stays
    # readable on top of it; the boundaries are the informative part.
    ax.axvspan(ax.get_xlim()[0], revoc_limit_s, ymin=0, ymax=1,
               facecolor=FILL_LIGHT, alpha=0.55, linewidth=0, zorder=0)
    ax.axhline(avail_limit, color=INK, linewidth=0.7, linestyle=(0, (4, 2)), zorder=2)
    ax.axvline(revoc_limit_s, color=INK, linewidth=0.7, linestyle=(0, (4, 2)), zorder=2)

    for i, outage in enumerate(outages):
        sdf = agg[agg["outage_minutes"] == outage].sort_values("epoch_minutes")
        tone = ordered_tone(i, len(outages))
        ax.plot(sdf["epoch_minutes"] * 60, sdf["failure_rate"],
                marker=MARKERS[i % len(MARKERS)], markersize=3.4,
                linestyle=LINESTYLES[i % len(LINESTYLES)], linewidth=1.0,
                color=tone, markerfacecolor="white", markeredgewidth=0.8,
                label=f"{int(outage)} min", zorder=3)

    ax.set_xscale("log")
    ax.set_xlabel("epoch length $T$ = worst-case revocation latency (s)")
    ax.set_ylabel("agents unable to authenticate")
    ax.set_ylim(-0.05, 1.18)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])

    ax.annotate(f"$T \\leq$ {revocation_target_min} min", (revoc_limit_s * 0.93, 1.14),
                ha="right", va="top", fontsize=6.3, color=INK)
    ax.annotate(f"$\\leq${int(avail_limit * 100)}% stranded",
                (ax.get_xlim()[1] * 0.97, avail_limit + 0.03),
                ha="right", va="bottom", fontsize=6.3, color=INK)

    # Does any measured epoch length satisfy both targets at the worst outage?
    target = agg[agg["outage_minutes"] == availability_outage_min]
    feasible = target[(target["epoch_minutes"] * 60 <= revoc_limit_s)
                      & (target["failure_rate"] <= avail_limit)]
    if feasible.empty:
        ax.annotate(
            f"no $T$ survives a {availability_outage_min} min outage\n"
            f"within a {revocation_target_min} min revocation target",
            (revoc_limit_s * 0.42, 0.30), ha="center", va="center",
            fontsize=6.4, color=INK,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                      edgecolor=HATCH_EDGE, linewidth=0.5),
            zorder=6,
        )

    # Legend below the axes: every quadrant inside the plot carries data or a
    # target boundary, so an inset legend would sit on top of one of them.
    leg = ax.legend(title="connectivity outage", ncols=5, loc="upper center",
                    bbox_to_anchor=(0.5, -0.30), handlelength=1.8,
                    columnspacing=0.8, borderpad=0.2, handletextpad=0.4)
    leg.get_title().set_fontsize(6.5)

    print(
        f"epoch lengths meeting both a {availability_outage_min}-min-outage "
        f"availability target (<={avail_limit:.0%} stranded) and a "
        f"{revocation_target_min}-min revocation target: {len(feasible)}"
    )
    fig.tight_layout()
    save_vector(fig, "fig4_revocation_trade")


def main() -> int:
    journal_style()
    figure1_protocol()
    figure2_verification_cost()
    try:
        figure3_timing_defence()
    except common.MissingResults as exc:
        print(f"skipping figure 3: {exc}", file=sys.stderr)
    figure4_revocation_trade()
    print(f"\nvector output in {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
