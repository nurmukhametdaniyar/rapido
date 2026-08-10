"""Shared loading and styling for the RAPIDO analysis scripts.

Every figure and table is generated from the committed result files under
`results/`. Nothing here recomputes a measurement; if a number is missing, the
fix is to run the experiment, not to fill it in.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")  # no display needed; scripts run in CI
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
FIGURES_DIR = REPO_ROOT / "analysis" / "figures"
TABLES_DIR = REPO_ROOT / "analysis" / "tables"

NS_PER_MS = 1e6


class MissingResults(RuntimeError):
    """Raised when a script is asked to plot data that was never measured.

    Deliberately fatal: a figure built from an empty frame looks like a result
    and is not one.
    """


@dataclass(frozen=True)
class ResultFile:
    """A result file: the environment-metadata header plus its payload."""

    path: Path
    meta: dict
    experiment: str
    data: object

    @property
    def profile(self) -> str:
        return self.meta.get("profile_label", "unknown")

    @property
    def emulated(self) -> bool:
        return bool(self.meta.get("emulated", False))

    def label(self) -> str:
        """Profile label, marked when the numbers came from emulation.

        Emulated timings are not credible as absolute latencies, so they are
        labelled wherever they appear rather than only in the metadata header.
        """
        return f"{self.profile} (EMULATED)" if self.emulated else self.profile


#: Profiles whose data has been loaded in this process and was produced under
#: emulation. Populated by every loader, consumed by `save`, so that stamping a
#: figure is not something an individual script can forget to do.
_EMULATED_PROFILES: set[str] = set()


def emulated_profiles() -> set[str]:
    return set(_EMULATED_PROFILES)


def _note_provenance(meta: dict, profile: str | None = None) -> None:
    if meta.get("emulated"):
        _EMULATED_PROFILES.add(profile or meta.get("profile_label", "unknown"))


def load_result(path: Path) -> ResultFile:
    with path.open() as fh:
        blob = json.load(fh)
    _note_provenance(blob["meta"])
    return ResultFile(
        path=path,
        meta=blob["meta"],
        experiment=blob.get("experiment", path.stem),
        data=blob["data"],
    )


def find_results(name: str, results_dir: Path = RESULTS_DIR) -> list[ResultFile]:
    """Every `<profile>/<name>.json` under `results/`, sorted by profile."""
    if not results_dir.exists():
        raise MissingResults(f"{results_dir} does not exist; run `rapido-cli bench` first")
    found = [load_result(p) for p in sorted(results_dir.glob(f"*/{name}.json"))]
    if not found:
        raise MissingResults(
            f"no {name}.json under {results_dir}/*/ — run the corresponding "
            f"`rapido-cli` command first"
        )
    return found


def load_csv(name: str, results_dir: Path = RESULTS_DIR) -> pd.DataFrame:
    """Concatenate every `<profile>/<name>.csv`, tagging rows with the profile."""
    frames = []
    for path in sorted(results_dir.glob(f"*/{name}.csv")):
        df = pd.read_csv(path)
        df["profile"] = path.parent.name
        # A CSV carries no metadata header, so provenance comes from its JSON
        # sibling. Without this an emulated run could reach a figure unstamped.
        sibling = path.with_suffix(".json")
        if sibling.exists():
            with sibling.open() as fh:
                _note_provenance(json.load(fh)["meta"], path.parent.name)
        frames.append(df)
    if not frames:
        raise MissingResults(f"no {name}.csv under {results_dir}/*/")
    return pd.concat(frames, ignore_index=True)


def bench_frame(results_dir: Path = RESULTS_DIR) -> pd.DataFrame:
    """The micro-benchmark table, with millisecond columns added."""
    df = load_csv("bench", results_dir)
    for col in ("median", "mean", "ci95_lo", "ci95_hi", "min", "p99"):
        df[f"{col}_ms"] = df[f"{col}_ns"] / NS_PER_MS
    return df


def _matches(cell, wanted) -> bool:
    """Compare a CSV cell against a wanted value, numerically when possible.

    Parameter columns arrive as whatever Rust's `Display` produced, so a
    disclosure fraction of `0.0` is written `"0"` while Python's `str(0.0)` is
    `"0.0"`. A pure string comparison silently matches nothing and yields an
    empty plot that looks like a missing measurement. Comparing numerically
    when both sides parse as numbers removes that whole class of bug.
    """
    try:
        return float(cell) == float(wanted)
    except (TypeError, ValueError):
        return str(cell) == str(wanted)


def select(df: pd.DataFrame, **conditions) -> pd.DataFrame:
    """Filter by parameter-column equality."""
    out = df
    for key, value in conditions.items():
        if key not in out.columns:
            return out.iloc[0:0]
        out = out[out[key].map(lambda cell, v=value: _matches(cell, v))]
    return out


def require(df: pd.DataFrame, what: str) -> pd.DataFrame:
    if df.empty:
        raise MissingResults(f"no rows for {what}")
    return df


def sig3(x: float) -> str:
    """Round to three significant figures.

    The measurement machine's own metadata records that its clock frequency is
    not controllable, so a `2.103 ms [2.101, 2.105]` interval claims a precision
    of +/-0.1% that the platform cannot support. Three significant figures is
    what these measurements actually carry.
    """
    if x == 0 or not np.isfinite(x):
        return "0"
    from decimal import Decimal

    d = Decimal(x)
    exp = d.adjusted()
    quant = Decimal(1).scaleb(exp - 2)
    return f"{d.quantize(quant):f}"


class HeadlineVariants:
    """The minimum-latency variant of each system, resolved from measurements.

    A cross-system comparison must use the best available configuration of each
    system. Mode A's aggregate verifier turned out to be *slower* than its naive
    one for a single presentation, so quoting the aggregate figure understated
    Mode A against every baseline. `assert_uses_minimum` re-derives the winner
    from the data and fails if a caller pinned the wrong one, so this cannot
    silently regress.
    """

    #: Candidate benchmark rows per system, as (name, filter) pairs.
    CANDIDATES = {
        "mode-a": [
            ("mode-a-verify-naive", {"escrow": "e0"}),
            ("mode-a-verify-aggregate", {"escrow": "e0"}),
        ],
        "mode-b": [
            ("mode-b-verify", {"L": 8, "disclosure_fraction": 0.0, "escrow": "e0"}),
        ],
    }

    @staticmethod
    def fastest(df: pd.DataFrame, system: str) -> tuple[str, dict, float]:
        best = None
        for name, cond in HeadlineVariants.CANDIDATES[system]:
            hit = select(df[df["name"] == name], **cond)
            if hit.empty:
                continue
            ms = float(hit.iloc[0]["median_ms"])
            if best is None or ms < best[2]:
                best = (name, cond, ms)
        if best is None:
            raise MissingResults(f"no measured variant for {system}")
        return best

    @staticmethod
    def assert_uses_minimum(df: pd.DataFrame, system: str, used_name: str) -> None:
        name, _, ms = HeadlineVariants.fastest(df, system)
        if name != used_name:
            raise AssertionError(
                f"headline for {system} uses '{used_name}', but '{name}' is faster "
                f"({ms:.4f} ms). A comparison must use the best available "
                f"configuration of each system."
            )


# --- palette -----------------------------------------------------------------
#
# Validated with the dataviz skill's `validate_palette.js`, not chosen by eye:
#   * ORDINAL_BLUE (N = 1..256)  -> ordinal ramp, ALL CHECKS PASS
#   * (SERIES_1, SERIES_2)       -> categorical pair, ALL CHECKS PASS
#   * DEEMPHASIS is deliberately achromatic; it is the emphasis-form gray, not a
#     categorical series, so the chroma floor does not apply to it.

SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS = "#c3c2b7"

SERIES_1 = "#2a78d6"   # blue  — RAPIDO / Layer 1
SERIES_2 = "#eb6834"   # orange — Layer 3 escrow
SERIES_3 = "#1baf7a"   # aqua — third categorical slot (sub-3:1 on the light
                       # surface, so it always ships with a visible direct label)
DEEMPHASIS = "#898781"  # baselines and context marks
CRITICAL = "#d03b3b"   # status: a defence that failed
GOOD = "#0ca30c"       # status: a defence that held

#: Ordered ramp for the observation-count series (N is ordered, so one hue
#: light->dark, never categorical hues).
ORDINAL_BLUE = ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#0d366b"]


#: Output resolution. 200 dpi is the print default; set RAPIDO_FIG_DPI lower to
#: render lightweight copies for the web (re-rendering keeps flat colour
#: regions, which compress far better than downsampling a 200 dpi PNG).
FIG_DPI = int(os.environ.get("RAPIDO_FIG_DPI", "200"))

#: Where figures are written. Overridable so a web build does not clobber the
#: committed print-resolution set.
FIGURES_OUT = Path(os.environ.get("RAPIDO_FIG_DIR", str(FIGURES_DIR)))


def setup_style() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (7.0, 4.2),
            "figure.dpi": FIG_DPI,
            "savefig.bbox": "tight",
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "font.size": 9,
            "font.family": "sans-serif",
            "text.color": INK_PRIMARY,
            "axes.labelcolor": INK_SECONDARY,
            "axes.edgecolor": AXIS,
            "axes.linewidth": 0.8,
            "xtick.color": INK_MUTED,
            "ytick.color": INK_MUTED,
            "xtick.labelcolor": INK_SECONDARY,
            "ytick.labelcolor": INK_SECONDARY,
            "axes.grid": True,
            # Hairline, solid, one shade off the surface — never dashed.
            "grid.color": GRIDLINE,
            "grid.linewidth": 0.6,
            "grid.linestyle": "-",
            "axes.axisbelow": True,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "legend.frameon": False,
            "axes.titlesize": 10,
            "axes.titleweight": "bold",
            "axes.titlecolor": INK_PRIMARY,
        }
    )


def save(fig, name: str) -> Path:
    """Write a figure, stamping it if any loaded result came from emulation.

    The stamp is applied here rather than per-script because "every affected
    figure carries the stamp" has to be true by construction: a script that
    forgets to call `annotate_emulated` would otherwise publish an emulated
    latency as though it were measured on real hardware.
    """
    FIGURES_OUT.mkdir(parents=True, exist_ok=True)
    if _EMULATED_PROFILES:
        which = ", ".join(sorted(_EMULATED_PROFILES))
        fig.text(
            0.5,
            0.985,
            f"CONTAINS EMULATED RESULTS ({which}) — absolute latencies are not credible",
            ha="center",
            va="top",
            fontsize=8,
            color="#c23434",
            fontweight="bold",
        )
    path = FIGURES_OUT / name
    fig.savefig(path)
    plt.close(fig)
    print(f"wrote {path}")
    return path


def write_tex(name: str, body: str) -> Path:
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    path = TABLES_DIR / name
    path.write_text(body)
    print(f"wrote {path}")
    return path


def tex_escape(text: str) -> str:
    for a, b in (("\\", r"\textbackslash{}"), ("_", r"\_"), ("&", r"\&"), ("%", r"\%"), ("#", r"\#")):
        text = text.replace(a, b)
    return text


def annotate_emulated(ax, results: list[ResultFile]) -> None:
    """Stamp a figure whose data came from emulation."""
    if any(r.emulated for r in results):
        ax.text(
            0.99,
            0.02,
            "contains EMULATED results — absolute latencies not credible",
            transform=ax.transAxes,
            ha="right",
            va="bottom",
            fontsize=7,
            color="crimson",
        )
