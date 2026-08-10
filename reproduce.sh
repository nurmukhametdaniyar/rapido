#!/usr/bin/env bash
# Reproduce every measured number in this repository from source.
#
#   ./reproduce.sh            full run  (tens of minutes)
#   ./reproduce.sh --quick    smoke test (a few minutes; NOT citable)
#
# Everything lands in results/<profile>/ and analysis/{figures,tables}/.
set -euo pipefail

START_EPOCH=$(date +%s)
step() { printf "\n==> %s  (t+%ds)\n" "$1" "$(( $(date +%s) - START_EPOCH ))"; }

PROFILE="${PROFILE:-p1}"
QUICK=""
EXTRA_FLAGS=()
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK="--quick" ;;
    --emulated) EXTRA_FLAGS+=(--emulated) ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

OUT="results/${PROFILE}"
CLI=(cargo run --release -q -p rapido-cli --)

step "correctness"
cargo test --workspace --release
# The second backend is feature-gated; this is what catches arkworks/blst drift.
cargo test -p rapido-crypto --release --features blst-backend

step "micro-benchmarks (the long pole: tens of minutes)"
"${CLI[@]}" bench --profile "$PROFILE" --out "$OUT" $QUICK "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}"

step "simulations"
for s in 1 2 3 4; do
  "${CLI[@]}" sim --scenario "$s" --profile "$PROFILE" --out "$OUT" $QUICK \
    "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}"
done

step "adversary experiments"
for t in timing cover linkability; do
  "${CLI[@]}" attack --target "$t" --profile "$PROFILE" --out "$OUT" $QUICK \
    "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}"
done

step "wire-size breakdown"
"${CLI[@]}" wire --profile "$PROFILE" --out "$OUT"

step "tables and figures"
"${CLI[@]}" tables --results results --out analysis/tables

# Use analysis/.venv if it exists, so the scripts run against pinned versions.
PY_BIN="python3"
[ -x analysis/.venv/bin/python ] && PY_BIN="analysis/.venv/bin/python"
"$PY_BIN" analysis/gen_tables.py
for f in analysis/fig_*.py; do "$PY_BIN" "$f"; done
# Optional third attack; reports loudly if scikit-learn is missing.
"$PY_BIN" analysis/attack_classifier.py || true
# Journal-style vector figures (PDF + SVG).
"$PY_BIN" analysis/journal_figures.py

ELAPSED=$(( $(date +%s) - START_EPOCH ))
echo
printf "Done in %dm %ds.\n" $((ELAPSED / 60)) $((ELAPSED % 60))
echo "  results  ${OUT}/"
echo "  figures  analysis/figures/  (raster)  analysis/figures/journal/  (PDF + SVG)"
echo "  tables   analysis/tables/"
if [ -n "$QUICK" ]; then
  echo "WARNING: --quick was used. These numbers are a smoke test and must not be cited."
fi
