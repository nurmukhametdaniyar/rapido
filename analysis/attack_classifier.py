#!/usr/bin/env python3
"""A learned classifier attacking the timing traces.

The Rust side implements the likelihood-ratio and mean-threshold attacks. This
is the third: gradient-boosted stumps over summary features, which is what an
adversary with samples but no distributional model would actually do.

It attacks the **same defended release times** the Rust attacks saw, read from
`attack_timing_traces.json`, rather than re-implementing the discrete-Laplace
sampler in Python where it could silently diverge from the Rust one.

Dependencies are optional. Without scikit-learn the script reports that the
learned attack was not run rather than silently substituting a weaker one — a
missing attack must never look like a defended system.
"""

from __future__ import annotations

import json
import sys

import common
import numpy as np

#: Evaluation windows per class. Sized for the small-advantage regime: an
#: advantage near the noise floor needs far more samples to resolve than one
#: near 1.0.
N_WINDOWS = 1500


def summary_features(sample: np.ndarray) -> list[float]:
    """Order statistics an attacker can compute from a handful of observations."""
    return [
        float(np.mean(sample)),
        float(np.std(sample)),
        float(np.min(sample)),
        float(np.max(sample)),
        float(np.median(sample)),
        float(np.percentile(sample, 25)),
        float(np.percentile(sample, 75)),
    ]


def build_dataset(pop0: np.ndarray, pop1: np.ndarray, n_obs: int, n_windows: int, rng):
    """Windows of `n_obs` observations each, labelled by population."""
    x, y = [], []
    for label, pop in ((0, pop0), (1, pop1)):
        for _ in range(n_windows):
            sample = rng.choice(pop, size=n_obs, replace=True)
            x.append(summary_features(sample))
            y.append(label)
    return np.array(x), np.array(y)


def bootstrap_auc_ci(y_true, scores, rng, resamples: int = 2000):
    """Percentile bootstrap CI for an AUC.

    An advantage near the noise floor is meaningless without one: 0.04
    [0.00, 0.09] and 0.04 [0.03, 0.05] are very different claims.
    """
    from sklearn.metrics import roc_auc_score

    y_true = np.asarray(y_true)
    scores = np.asarray(scores)
    n = len(y_true)
    aucs = []
    for _ in range(resamples):
        idx = rng.integers(0, n, size=n)
        # A resample that lost one class entirely carries no information.
        if len(np.unique(y_true[idx])) < 2:
            continue
        aucs.append(roc_auc_score(y_true[idx], scores[idx]))
    if not aucs:
        return 0.5, 0.5
    return float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))


def advantage(auc: float) -> float:
    return abs(2 * auc - 1)


def main() -> int:
    try:
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import roc_auc_score
    except ImportError:
        print(
            "scikit-learn is not installed, so the learned attack was NOT run. "
            "Install it with `pip install scikit-learn` and re-run. "
            "Do not report the likelihood-ratio result as if it were the only attack tried.",
            file=sys.stderr,
        )
        return 2

    trace_files = sorted(common.RESULTS_DIR.glob("*/attack_timing_traces.json"))
    if not trace_files:
        raise common.MissingResults(
            "no attack_timing_traces.json under results/*/ — run "
            "`rapido-cli attack --target timing` first"
        )

    rng = np.random.default_rng(20240801)
    observation_counts = (1, 4, 16, 64, 256)
    rows = []

    for path in trace_files:
        profile = path.parent.name
        blob = json.loads(path.read_text())
        emulated = blob["meta"].get("emulated", False)

        for tr in blob["data"]["traces"]:
            # STRICT train/test separation. The train and test traces are
            # generated from disjoint halves of the measured compute-time
            # samples, so no compute-time sample the classifier fit on can
            # reappear in its evaluation set. Fitting and scoring on resamples
            # of one shared trace array measures memorization, not attacker
            # advantage, and shows up as a non-monotonic advantage-vs-N curve.
            tr0 = np.asarray(tr["train_population_0_ns"], dtype=float)
            tr1 = np.asarray(tr["train_population_1_ns"], dtype=float)
            te0 = np.asarray(tr["test_population_0_ns"], dtype=float)
            te1 = np.asarray(tr["test_population_1_ns"], dtype=float)
            eps = tr["epsilon"]
            label = tr["mechanism"] if eps is None else f"{tr['mechanism']} (eps={eps})"

            for n_obs in observation_counts:
                xtr, ytr = build_dataset(tr0, tr1, n_obs, N_WINDOWS, rng)
                xte, yte = build_dataset(te0, te1, n_obs, N_WINDOWS, rng)
                clf = GradientBoostingClassifier(n_estimators=100, max_depth=1, random_state=0)
                clf.fit(xtr, ytr)
                scores = clf.predict_proba(xte)[:, 1]
                auc = float(roc_auc_score(yte, scores))
                lo, hi = bootstrap_auc_ci(yte, scores, rng)
                adv_lo, adv_hi = sorted((advantage(lo), advantage(hi)))
                rows.append(
                    {
                        "profile": profile,
                        "mechanism": tr["mechanism"],
                        "epsilon": "" if eps is None else eps,
                        "delta": "" if tr["delta"] is None else tr["delta"],
                        "n_observations": n_obs,
                        "auc": auc,
                        "auc_ci_lo": lo,
                        "auc_ci_hi": hi,
                        "advantage": advantage(auc),
                        "advantage_ci_lo": adv_lo,
                        "advantage_ci_hi": adv_hi,
                        "train_windows": N_WINDOWS * 2,
                        "test_windows": N_WINDOWS * 2,
                        "train_pool": len(tr0) + len(tr1),
                        "test_pool": len(te0) + len(te1),
                        "emulated": emulated,
                    }
                )
                print(
                    f"[{profile}] {label:<22} N={n_obs:>3}: "
                    f"AUC {auc:.4f}, advantage {advantage(auc):.4f} "
                    f"[{adv_lo:.4f}, {adv_hi:.4f}]"
                )

    out = common.RESULTS_DIR / "attack_classifier.csv"
    cols = [
        "profile", "mechanism", "epsilon", "delta", "n_observations", "auc",
        "auc_ci_lo", "auc_ci_hi", "advantage", "advantage_ci_lo", "advantage_ci_hi",
        "train_windows", "test_windows", "train_pool", "test_pool", "emulated",
    ]
    with out.open("w") as fh:
        fh.write(",".join(cols) + "\n")
        for r in rows:
            fh.write(",".join(str(r[c]) for c in cols) + "\n")
    print(f"\nwrote {out}")

    # Monotonicity check. A calibrated attacker cannot do worse with more
    # observations; a drop whose intervals do not overlap is evidence the
    # classifier is still overfitting, and is reported rather than smoothed.
    print("\nmonotonicity in N (per mechanism/epsilon):")
    violations = 0
    keyed = {}
    for r in rows:
        keyed.setdefault((r["mechanism"], r["epsilon"]), []).append(r)
    for key, group in sorted(keyed.items(), key=lambda kv: str(kv[0])):
        group.sort(key=lambda r: r["n_observations"])
        for prev, cur in zip(group, group[1:]):
            if cur["advantage"] < prev["advantage"] and cur["advantage_ci_hi"] < prev["advantage_ci_lo"]:
                violations += 1
                print(
                    f"  VIOLATION {key}: N={prev['n_observations']} "
                    f"{prev['advantage']:.3f} [{prev['advantage_ci_lo']:.3f},"
                    f"{prev['advantage_ci_hi']:.3f}] -> N={cur['n_observations']} "
                    f"{cur['advantage']:.3f} [{cur['advantage_ci_lo']:.3f},"
                    f"{cur['advantage_ci_hi']:.3f}]"
                )
    print(f"  {violations} violation(s) with non-overlapping intervals")

    # The comparison that matters: does the learned attacker beat the
    # likelihood-ratio attack the Rust side already ran? If it does, the
    # advantage curve in fig_dp_tradeoff is optimistic and must be redrawn.
    try:
        lr = common.load_csv("attack_timing")
        lr = lr[(lr["attack"] == "likelihood-ratio") & (lr["mechanism"] == "m-geo")]
        print("\nlearned classifier vs likelihood-ratio (M-GEO, matched N):")
        worse = False
        epsilons = sorted({r["epsilon"] for r in rows if r["mechanism"] == "m-geo"})
        for eps in epsilons:
            for n_obs in observation_counts:
                mine = [
                    r["advantage"]
                    for r in rows
                    if r["mechanism"] == "m-geo"
                    and r["epsilon"] == eps
                    and r["n_observations"] == n_obs
                ]
                theirs = lr[
                    (lr["epsilon"].astype(float) == float(eps))
                    & (lr["n_observations"] == n_obs)
                ]["advantage"]
                if mine and not theirs.empty:
                    m, t = float(np.mean(mine)), float(theirs.mean())
                    flag = ""
                    if m > t + 0.05:
                        flag = "  <-- learned attack is STRONGER"
                        worse = True
                    print(f"  eps={eps:<5} N={n_obs:>3}: learned {m:.3f}  vs LR {t:.3f}{flag}")
        if worse:
            print(
                "\nNOTE: the learned classifier beat the likelihood-ratio attack somewhere. "
                "Report the larger advantage; the LR curve alone understates the leak."
            )
    except common.MissingResults as exc:
        print(f"(skipping comparison: {exc})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
