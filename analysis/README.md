# analysis/

Plain Python — no notebooks, so everything here runs in CI.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python gen_tables.py          # -> tables/*.tex
for f in fig_*.py; do .venv/bin/python "$f"; done   # -> figures/*.png
.venv/bin/python attack_classifier.py   # learned attack on the timing traces
.venv/bin/python journal_figures.py     # -> figures/journal/*.{pdf,svg}
```

`fig_*.py` write raster figures for presentation; `journal_figures.py` writes
vector versions of the same measurements, sized for a single journal column and
legible in greyscale.

| script | produces | question it answers |
|---|---|---|
| `fig_mode_comparison.py` | Mode A vs Mode B vs every baseline | how do the two modes compare, and to what? |
| `fig_latency_breakdown.py` | measured per-layer stack | where does verification time actually go? |
| `fig_dp_tradeoff.py` | attacker AUC vs ε, latency on the second axis | what does timing privacy cost in latency? |
| `fig_cover_tradeoff.py` | attacker AUC vs bandwidth **increase** | what does cover traffic cost in bytes? |
| `fig_revocation.py` | lookup cost vs \|R\|; revocation latency vs availability | which revocation variant, and at what price? |
| `fig_intersection.py` | completion rate within 100 ms vs vehicle count | is the intersection deadline met? |
| `fig_linkability.py` | the four-cell unlinkability game | can the issuer link sessions? |
| `attack_classifier.py` | learned-classifier attack on timing traces | does a stronger attacker beat the analytic one? |
| `gen_tables.py` | every `.tex` fragment a document `\input`s | all tables |
| `journal_figures.py` | `figures/journal/fig{1..4}.{pdf,svg}` | the four figures the article prints |

Two scripts print their headline answer to stdout, in addition to plotting it:

* `fig_mode_comparison.py` — **what does issuer-unlinkability cost, in ms?**
* `fig_latency_breakdown.py` — **what does a sound escrow proof cost?**

## Design rules

* **A missing measurement is an error, not an empty plot.** `common.MissingResults`
  is raised rather than rendering a blank figure, because a blank figure looks
  like a result.
* **Emulated data is labelled.** Any figure containing a run with
  `emulated: true` is stamped; those numbers are not credible as absolute
  latencies.
* **Nothing is recomputed here.** These scripts read committed result files. If
  a number is missing, run the experiment.
