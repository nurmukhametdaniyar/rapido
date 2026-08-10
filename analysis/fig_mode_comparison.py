#!/usr/bin/env python3
"""Figure: RAPIDO vs every baseline, measured on the same hardware.

Answers directly: **what does issuer-unlinkability cost, in milliseconds?** —
Mode B minus Mode A at the same escrow variant, printed to stdout as well as
plotted.

Form note: this is a **dot plot on a log axis**, not bars. Bar *length* is only
meaningful on a linear scale; a bar drawn to a log axis encodes the logarithm as
a length and reads as a much smaller difference than it is. A dot encodes
position, which a log axis handles honestly. The measured range here is 160x
(0.05 ms to 8.5 ms), so a linear axis would collapse every baseline into the
origin — hence log, hence dots.

Colour is emphasis, not identity: RAPIDO in the accent hue, every comparison
system in the de-emphasis gray.
"""

from __future__ import annotations

import sys

import common
import matplotlib.pyplot as plt

# (label, benchmark name, filter, is_rapido)
ROWS = [
    ("Idemix-like CL-RSA-2048", "cl-rsa-verify", {"L": 5, "n_disclosed": 0}, False),
    ("RAPIDO Mode A + E2 escrow", "mode-a-verify-full-pipeline", {"escrow": "e2"}, True),
    ("RAPIDO Mode A (aggregate)", "mode-a-verify-aggregate", {"escrow": "e0"}, True),
    ("RAPIDO Mode A (naive)", "mode-a-verify-naive", {"escrow": "e0"}, True),
    ("RAPIDO Mode B + E2 escrow", "mode-b-verify",
     {"L": 8, "disclosure_fraction": 0.0, "escrow": "e2"}, True),
    ("RAPIDO Mode B (L=8)", "mode-b-verify",
     {"L": 8, "disclosure_fraction": 0.0, "escrow": "e0"}, True),
    ("mTLS ECDSA P-256, depth 2", "mtls-p256-verify", {}, False),
    ("SCMS explicit cert", "scms-explicit-verify", {}, False),
    ("SCMS implicit (ECQV)  ← the real V2X baseline", "scms-implicit-verify", {}, False),
    ("mTLS Ed25519, depth 2", "mtls-ed25519-verify", {}, False),
]


def main() -> int:
    common.setup_style()
    df = common.bench_frame()
    profiles = sorted(df["profile"].unique())
    if len(profiles) != 1:
        print(f"note: {len(profiles)} profiles present; plotting {profiles[0]}", file=sys.stderr)
    sub = df[df["profile"] == profiles[0]]

    points = []
    for label, name, cond, is_rapido in ROWS:
        hit = common.select(sub[sub["name"] == name], **cond)
        if hit.empty:
            continue
        r = hit.iloc[0]
        points.append((label, float(r["median_ms"]), r.get("bytes"), is_rapido))
    if not points:
        raise common.MissingResults("no comparable verification rows in bench.csv")

    fig, ax = plt.subplots(figsize=(8.0, 4.8))
    ax.grid(True, axis="x")
    ax.grid(False, axis="y")

    ys = range(len(points))
    for y, (label, ms, nbytes, is_rapido) in zip(ys, points):
        colour = common.SERIES_1 if is_rapido else common.DEEMPHASIS
        # Hairline leader from the axis so the eye can track the row.
        ax.plot([0.04, ms], [y, y], color=common.GRIDLINE, linewidth=1.0, zorder=1)
        ax.plot(
            [ms], [y],
            marker="o", markersize=10 if is_rapido else 8,
            color=colour, markeredgecolor=common.SURFACE, markeredgewidth=1.6,
            zorder=3,
        )
        ax.annotate(
            f"{ms:.3f} ms" if ms < 1 else f"{ms:.2f} ms",
            (ms, y), textcoords="offset points", xytext=(13, 0),
            va="center", fontsize=8.5,
            color=common.INK_PRIMARY if is_rapido else common.INK_SECONDARY,
            fontweight="bold" if is_rapido else "normal",
        )
        if nbytes is not None and str(nbytes) != "nan":
            ax.annotate(
                f"{int(float(nbytes))} B",
                (ms, y), textcoords="offset points", xytext=(13, -11),
                va="center", fontsize=7, color=common.INK_MUTED,
            )

    ax.set_yticks(list(ys))
    ax.set_yticklabels([p[0] for p in points], fontsize=9)
    for tick, (_, _, _, is_rapido) in zip(ax.get_yticklabels(), points):
        tick.set_color(common.INK_PRIMARY if is_rapido else common.INK_SECONDARY)
        if is_rapido:
            tick.set_fontweight("bold")
    ax.tick_params(axis="y", length=0)
    ax.set_xscale("log")
    ax.set_xlim(0.035, 30)
    ax.set_xticks([0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25])
    ax.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.get_xaxis().set_minor_formatter(plt.NullFormatter())
    ax.set_xlabel("verification latency (ms, log scale) — median of 1,000 iterations")
    ax.set_title("Verification cost: RAPIDO vs baselines, same hardware, same process", pad=12)

    # Identity is never colour-alone: the two classes are also named.
    handles = [
        plt.Line2D([], [], marker="o", linestyle="", markersize=9,
                   color=common.SERIES_1, label="RAPIDO"),
        plt.Line2D([], [], marker="o", linestyle="", markersize=8,
                   color=common.DEEMPHASIS, label="comparison systems"),
    ]
    # Upper-right: the fastest rows sit far left, so this corner is empty.
    ax.legend(handles=handles, fontsize=8, loc="upper right")

    by = {p[0]: p[1] for p in points}
    note = []
    scms = next((v for k, v in by.items() if k.startswith("SCMS implicit")), None)
    # Headline ratios use the fastest measured Mode A variant, which is the
    # naive verifier; `gen_tables.py` asserts the same choice for the tables.
    mode_a = by.get("RAPIDO Mode A (naive)")
    mode_b = by.get("RAPIDO Mode B (L=8)")
    cl = by.get("Idemix-like CL-RSA-2048")
    if scms and mode_a:
        note.append(f"RAPIDO Mode A is {mode_a / scms:.1f}x slower than SCMS-ECQV, "
                    "which provides the same unlinkability property (Scenario 4).")
    if cl and mode_a and mode_b:
        note.append(f"Measured speedup over CL-RSA: {cl / mode_a:.1f}x (Mode A), "
                    f"{cl / mode_b:.1f}x (Mode B).")
    if note:
        fig.text(0.5, -0.03, "\n".join(note), ha="center", fontsize=8,
                 color=common.INK_SECONDARY)

    common.save(fig, "fig_mode_comparison.png")

    if mode_a and mode_b:
        print(f"[{profiles[0]}] issuer-unlinkability costs {mode_b - mode_a:+.3f} ms "
              f"(Mode B {mode_b:.3f} ms - Mode A {mode_a:.3f} ms, {mode_b / mode_a:.2f}x)")
    if cl and mode_a:
        print(f"[{profiles[0]}] CL-RSA verification measured at {cl:.3f} ms; "
              f"speedup over Mode A is {cl / mode_a:.1f}x "
              f"(measured on this machine, not quoted from the literature)")
    if scms and mode_a:
        print(f"[{profiles[0]}] SCMS-ECQV is {mode_a / scms:.1f}x FASTER than RAPIDO Mode A")
    return 0


if __name__ == "__main__":
    sys.exit(main())
