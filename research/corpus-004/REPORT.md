# corpus-004 — runtime baseline

**Round:** corpus-004 · **Date:** 2026-11-07 · **Pre-registration:**
[PREREGISTRATION.md](PREREGISTRATION.md), frozen before the first run.
Corpus and harness rule unchanged; only the runtime changed.

## What was added

A hermetic runtime overlay, built **without root** by
`scripts/provision_runtime.sh --bootstrap` and mounted read-only at
`/usr/local` inside the sandbox via the new `AIRLOCK_RUNTIME_OVERLAY` hook:

- Node **v20.18.1**
- pip 26.3, `python-docx==1.1.2`, `python-pptx==1.0.2`, `openpyxl==3.1.5`,
  `reportlab==4.2.5` (+ lxml 6.1.3, Pillow 13.0.0)
- pinned in `scripts/runtime-baseline.txt`

No host packages were modified and no administrator rights were used.

## Delta

| Metric | corpus-003 | corpus-004 | Change |
|---|---|---|---|
| Coverage (launched / 21) | 21/21 = 100 % | 21/21 = 100 % | — |
| **Clean start (exit 0)** | **4/21 = 19.0 %** | **4/21 = 19.0 %** | **no change** |
| Exit 127 (command not found) | 4 | **0** | ✅ eliminated |
| Positive findings | 0 | 0 | — |

**The overlay did what it was designed to do and the clean-start rate did not
move.** Both statements are true, and the second is the finding.

## Hypothesis scorecard

| # | Hypothesis | Outcome |
|---|---|---|
| 1 | Clean start rises from 4/21 to ≥ 10/21 | ❌ **Wrong** — stayed at 4/21 |
| 2 | No package exits 127 | ✅ **Correct** — 4 → 0 |
| 3 | Zero positive findings on real code | ✅ Correct — 0/21 |
| 4 | ≥ 2 packages still fail on missing input | ✅ Correct — 17 still fail |

## Why clean start did not move — the next wall

The exit codes changed shape rather than improving:

| Exit | corpus-003 | corpus-004 | Meaning |
|---|---|---|---|
| 0 | 4 | 4 | ran cleanly |
| 1 | 12 | 12 | Python error: import or argument |
| 2 | 1 | 1 | shell usage |
| 127 | 4 | 0 | command not found — **fixed by the overlay** |
| **-5 (SIGTRAP)** | 0 | **3** | **Node.js aborts under the sandbox's per-process limits** |
| 133 | 0 | 1 | exit 133 (128+5) from a shell wrapper |

Two distinct new facts:

1. **Node now starts (the 127s are gone) but crashes with SIGTRAP under the
   sandbox's resource limits.** The per-process address-space cap (512 MB,
   `coverage.resource_limits.address_space_bytes`) is below what V8 reserves at
   startup. Supplying a runtime is not enough; the sandbox's resource policy must
   be per-runtime, not one-size-fits-all. This is a real product decision with a
   security trade-off: loosening address space weakens a containment control.
2. **The twelve Python failures are unchanged.** The overlay made the document
   libraries importable in principle, but these scripts still exit 1. This round
   did not isolate whether that is an import-visibility problem in the sandbox
   (module not on the sandbox's `sys.path`) or the expected "no input document
   provided" usage error. Recorded as unresolved rather than assumed.

## What this round establishes

- **Root-free, pinned, read-only runtimes are mechanically feasible** and mount
  correctly inside the sandbox: the `node` command-not-found class is gone.
- **Runtime supply is necessary but not sufficient.** The remaining blockers are
  (a) resource policy that Node's VM cannot satisfy, and (b) input materialisation
  — arguments and documents — which no runtime work addresses.

## Next levers, in order

1. **Isolate the twelve Python exit-1 causes** by capturing specimen stderr per
   package (one instrumentation change, no new runtimes). This is cheap and
   decides whether the next work is `sys.path` plumbing or usage harnesses.
2. **Per-runtime resource policy**: allow a documented, bounded higher address
   space for `.js` entrypoints, with the containment consequence written down and
   tested.
3. **Input materialisation**: generate a fixture per document family so a script
   receives a real input instead of `--help`.

## Reproduction

```sh
./scripts/provision_runtime.sh --bootstrap
export AIRLOCK_RUNTIME_OVERLAY="$HOME/.airlock/runtime"
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-004/results/harness-coverage.json
```
