#!/usr/bin/env python3
"""Figure: the unlinkability game (Scenario 4).

The four-cell result: mode crossed with adversary, measured advantage in each
cell.

Form note: the story here is *one* number — Mode A's issuer links perfectly,
everything else leaks nothing. A four-bar chart of {1, 0, 0, 0} is three empty
bars and a wall of whitespace, so this is drawn as a 2x2 outcome matrix with the
one hot cell emphasized. Colour carries state (critical / good), and every cell
is also labelled, so the encoding is never colour-alone.
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt

MODES = ["mode-a", "mode-b"]
ADVERSARIES = ["verifier-only", "issuer-colluding"]

MODE_LABEL = {
    "mode-a": "Mode A\nbatch pseudonym certs",
    "mode-b": "Mode B\nBBS+ presentation",
}
ADV_LABEL = {
    "verifier-only": "Verifier-only\nadversary",
    "issuer-colluding": "Issuer-colluding\nadversary",
}


def main() -> int:
    common.setup_style()
    df = common.load_csv("scenario4_linkability")
    agg = df.groupby(["mode", "adversary"], as_index=False).agg(
        advantage=("advantage", "mean"),
        tpr=("true_positive_rate", "mean"),
        fpr=("false_positive_rate", "mean"),
        seeds=("seed", "nunique"),
        trials=("trials", "sum"),
    )
    lookup = {(r["mode"], r["adversary"]): r for _, r in agg.iterrows()}

    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    ax.grid(False)

    for col, mode in enumerate(MODES):
        for row, adversary in enumerate(ADVERSARIES):
            r = lookup.get((mode, adversary))
            if r is None:
                continue
            adv = float(r["advantage"])
            broken = adv > 0.5
            face = common.CRITICAL if broken else common.GOOD
            # Tint the cell, keep the number in ink: text wears text tokens.
            ax.add_patch(
                plt.Rectangle(
                    (col + 0.03, row + 0.03),
                    0.94,
                    0.94,
                    facecolor=face,
                    alpha=0.16 if not broken else 0.22,
                    edgecolor=face,
                    linewidth=1.6,
                )
            )
            ax.text(
                col + 0.5,
                row + 0.62,
                f"{adv:.3f}",
                ha="center",
                va="center",
                fontsize=30 if broken else 22,
                fontweight="bold",
                color=common.INK_PRIMARY,
            )
            ax.text(
                col + 0.5,
                row + 0.33,
                "LINKS EVERY SESSION" if broken else "no advantage",
                ha="center",
                va="center",
                fontsize=9,
                fontweight="bold" if broken else "normal",
                color=face if broken else common.INK_SECONDARY,
            )
            ax.text(
                col + 0.5,
                row + 0.16,
                f"TPR {float(r['tpr']):.2f} · FPR {float(r['fpr']):.2f} · "
                f"{int(r['seeds'])} seeds x {int(r['trials']) // int(r['seeds']):,} trials",
                ha="center",
                va="center",
                fontsize=7,
                color=common.INK_MUTED,
            )

    ax.set_xlim(0, len(MODES))
    ax.set_ylim(0, len(ADVERSARIES))
    ax.set_xticks([i + 0.5 for i in range(len(MODES))])
    ax.set_xticklabels([MODE_LABEL[m] for m in MODES], fontsize=9)
    ax.set_yticks([i + 0.5 for i in range(len(ADVERSARIES))])
    ax.set_yticklabels([ADV_LABEL[a] for a in ADVERSARIES], fontsize=9)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)

    ax.set_title(
        "Unlinkability game: measured linking advantage  |TPR − FPR|", pad=14
    )
    fig.text(
        0.5,
        -0.04,
        "Mode A's issuer signed every pseudonym, so it holds P_i → agent and links "
        "perfectly.\nThat is the IEEE 1609.2 / SCMS property — not a novel one.",
        ha="center",
        fontsize=8,
        color=common.INK_SECONDARY,
    )
    common.save(fig, "fig_linkability.png")

    for _, r in agg.iterrows():
        print(f"{r['mode']:>8} / {r['adversary']:>18}: advantage {r['advantage']:.4f}")
    a_issuer = agg[(agg["mode"] == "mode-a") & (agg["adversary"] == "issuer-colluding")]
    if not a_issuer.empty and float(a_issuer.iloc[0]["advantage"]) > 0.9:
        print("\nFINDING: Mode A provides no unlinkability against the issuer. "
              "Its Layer 1 is the IEEE 1609.2 / SCMS pseudonym-certificate mechanism; "
              "SCMS is therefore the baseline it has to be compared against.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
