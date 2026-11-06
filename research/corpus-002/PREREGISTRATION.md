# Pre-registration — corpus-002 (fix round)

**Status: FROZEN before the first corpus-002 scan.** Written 2026-11-07.

Round 1 ([corpus-001](../corpus-001/PREREGISTRATION.md)) measured the detector and
published its failures. This round asks a different question: **did fixing the
measured defects change the numbers, and did anything get worse?**

## 1. What changed between rounds

Only the detector and the harness. The corpora are byte-identical: the same
frozen `benign/manifest.json` (245 packages) and `adversarial/manifest.json`
(100 packages) with the same per-file SHA-256, reused in place. No sample was
added, removed, relabelled or re-authored for this round.

| Change | Driven by |
|---|---|
| `detect_entry()` now discovers `scripts/`, `bin/`, `tools/`, `hooks/` entrypoints under a conservative rule | all 245 real skills fell back to declaration-only |
| `ALK-009` masks fenced code blocks and markdown headings | 6/245 false positives, all documentation prose |
| `ALK-009` requires an action verb for system-prompt references | `skill-creator`, `writing-skills` FPs |
| `ALK-009` negation window widened to cover "never ask the user to send …" | `1password` FP |
| New `ALK-013` evidence-destruction rule on deletions of history/audit paths | B12 behavioural recall 0/5 |
| `classify()` no longer treats a non-zero specimen exit as a failed observation | hostile code that crashes left the numerator |

## 2. Frozen prediction rule and metrics

Identical to round 1, section 3 and 4: positive = any finding of severity
critical/high/medium excluding ALK-090/091/092/093; Wilson 95 % intervals;
separate denominators; failures excluded and reported; precision at 1/5/10/50 %
prevalence.

## 3. New measurement, declared in advance

Round 1 could not measure behavioural false positives on real skills. Round 2
can, and will: **all 245 benign packages are run through the behavioural path**
with a 10 s per-specimen timeout, inside the namespace sandbox with no network
route. Samples that time out are recorded as `timed_out` and excluded from the
denominator; samples whose entry discovery finds nothing remain `static_only`
and are excluded. The resulting
**behavioural false-positive rate on real public skills** is reported with its
Wilson interval.

## 4. Directional hypotheses (recorded before measuring)

Stated so that a wrong guess is evidence, not embarrassment:

1. `ALK-009` false positives on B0 drop from 6 to **0–2**.
2. Static recall on the I stratum falls slightly (narrowed system-prompt pattern)
   — a trade accepted for precision, and reported honestly if it falls.
3. Behavioural recall on B12 rises to **5/5**; B11 is unchanged (environmental:
   `pip` is absent from the sandbox image).
4. At least 20 of the 245 real skills gain an executable entrypoint; most then
   complete with **zero** behavioural findings.
5. Behavioural false-positive rate on real skills is **below 5 %**.

If any hypothesis is wrong, the measured number is the finding.

## 5. Reporting commitments

Same as round 1, plus: a **delta table** against corpus-001 must be published in
full, including any metric that got worse. Round-1 artefacts stay untouched; no
round-1 result may be edited or removed.

## 6. Reproduction

```sh
# corpora are unchanged; re-acquisition is not required
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-002/results/benign --static-only
python3 scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-002/results/benign-behavioural --timeout 10
python scripts/scan_dataset.py research/corpus-001/adversarial/manifest.json \
    --output research/corpus-002/results/adversarial --static-only
python3 scripts/scan_dataset.py research/corpus-001/adversarial/manifest.json \
    --output research/corpus-002/results/adversarial-behavioural --timeout 15
python scripts/measure.py research/corpus-001 \
    --results research/corpus-002/results --out research/corpus-002
```

Machines: WSL2 Ubuntu, Python 3.14.4, kernel 6.18.33.2.
