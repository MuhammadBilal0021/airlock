# Pre-registration — corpus-004 (runtime baseline)

**Status: FROZEN before the first harness run with the overlay.** Written 2026-11-07.

## 1. What changed

corpus-003 reached **100 % coverage of the 21 addressable packages** but only
**4/21 clean starts**. The exit-code table identified two causes, and this round
addresses the first:

| Exit | Count | Cause |
|---|---|---|
| 127 | 4 | command not found — `node` absent from the sandbox image |
| 1 | 12 | missing dependency or required argument |
| 0 | 4 | ran cleanly |

**Change:** a hermetic runtime overlay
(`scripts/provision_runtime.sh --bootstrap`) is mounted read-only at
`/usr/local` inside the sandbox when `AIRLOCK_RUNTIME_OVERLAY` is set. It
contains Node **v20.18.1**, pip, and pinned `python-docx==1.1.2`,
`python-pptx==1.0.2`, `openpyxl==3.1.5`, `reportlab==4.2.5` (+ lxml, Pillow).
No root is used; the overlay lives outside the repository and is pinned in
`scripts/runtime-baseline.txt`.

The harness rule from corpus-003 is **unchanged and re-used verbatim**; the
corpus is unchanged (245 packages, 21 addressable). Only the runtime changed.

## 2. Question

Does supplying the runtimes the code demonstrably needs raise the **clean-start**
rate — and does running real third-party code with dependencies present produce
any false positive?

## 3. Metrics (frozen)

- **Coverage** = launched / 21 (expected to stay 21/21).
- **Clean start** = exit code 0 / 21.
- **Exit-code distribution**, compared package by package against corpus-003.
- **Findings** by rule, positive rule as before.
- **Behavioural false positives** = positives / launched, with Wilson interval.

## 4. Hypotheses (recorded before measuring)

1. Clean start rises from **4/21 to ≥ 10/21**.
2. **No package exits 127** any more (the `node` and missing-command class is
   eliminated by the overlay).
3. Still **zero** positive findings on real code. Any positive is a false
   positive and must be published individually.
4. At least **2 packages still fail** on missing input material (arguments,
   documents, servers) — proving the remaining gap is inputs, not runtimes.

## 5. Reporting commitments

Publish the per-package before/after table. If clean start does not improve, that
is the finding and the overlay claim is withdrawn. Do not describe a clean start
as a security verdict.

## 6. Reproduction

```sh
# no root required
./scripts/provision_runtime.sh --bootstrap
export AIRLOCK_RUNTIME_OVERLAY="$HOME/.airlock/runtime"
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-004/results/harness-coverage.json
```
