# corpus-002 — fix round, measured delta

**Round:** corpus-002 · **Date:** 2026-11-07 · **Pre-registration:**
[PREREGISTRATION.md](PREREGISTRATION.md), frozen before the first scan.
**Corpora: byte-identical to corpus-001** (same manifests, same per-file SHA-256).
No sample was added, removed, relabelled or re-authored. Only the detector changed.

## Delta

| Metric | corpus-001 | corpus-002 | Change |
|---|---|---|---|
| Static false-positive rate (245 real skills) | **2.45 %** (6/245) | **0.00 %** (0/245) | **−2.45 pp** · CI [0.0, 1.54] |
| Static recall (100 adversarial) | 22.0 % (22/100) | 22.0 % (22/100) | unchanged |
| Static recall, instruction level | 55.0 % (22/40) | 55.0 % (22/40) | unchanged |
| Behavioural recall (60 executable adversarial) | 83.3 % (50/60) | **91.7 %** (55/60) | **+8.4 pp** · CI [81.9, 96.4] |
| Behavioural false positives on real skills | not measurable | **0/5 executed** | still not measurable |

**The precision fix cost nothing.** Six false positives eliminated, zero recall
lost on the adversarial side — and the narrowed system-prompt rule did not reduce
instruction-level recall as the pre-registration feared it might.

## Hypothesis scorecard

Recorded before measuring. Two right, one right-for-the-wrong-reason, two wrong.

| # | Hypothesis | Outcome |
|---|---|---|
| 1 | `ALK-009` FPs drop from 6 to 0–2 | ✅ **Correct** — 0/245 |
| 2 | Static recall on I stratum falls slightly | ❌ **Wrong** — unchanged at 55 % |
| 3 | B12 behavioural recall becomes 5/5; B11 unchanged | ✅ **Correct** — `ALK-013` fires on all 5; B11 still 0/5 |
| 4 | ≥20 of 245 real skills gain an executable entrypoint | ❌ **Badly wrong** — only **5** did |
| 5 | Behavioural FPR on real skills below 5 % | ⚠️ **Untestable** — n=5, CI [0, 43.4]. Reporting 0 % as a rate would be dishonest. |

Hypothesis 4 is the important failure. The conservative entry-discovery rule
(recognised stem, or a single unambiguous script) found an entrypoint in only 5
of 245 real packages, because real skills keep **multiple** conventionally-named
scripts (`fill_fillable_fields.py`, `thumbnail.py`, `new_notebook.py`) and rarely
one called `main.py`. The behavioural path therefore remains effectively
unmeasured on real registry code — the same gap as round 1, only mildly narrowed.

This is exactly why the round was pre-registered: the fix *felt* sufficient, and
the measurement says it was not.

## What the behavioural pass did manage to show

Of the 5 real packages that could be executed, all 5 completed cleanly in the
sandbox and 4 produced no findings. The fifth (`anthropics/skills:xlsx`) produced
`ALK-007` (a write outside the declared scope) which is **not** a positive under
the pre-registered severity rule — the skill writes a workbook, which is what it
is for. Nothing was classified malicious. That is a good signal but far too small
a sample to be a rate; it is reported as 0/5, not as "0 %".

## Anti-forensics is now visible

`ALK-013` fired on 5/5 B12 samples (delete `.bash_history`, truncate audit log).
Behavioural rule detections: `ALK-004` egress 35, `ALK-002` sensitive read 20,
`ALK-010` trifecta 20, `ALK-005` persistence 10, `ALK-003` metadata SSRF 5,
`ALK-013` evidence destruction 5.

## Still open (carried forward, not fixed this round)

1. **B11** supply-chain install still 0/5 — `pip` is absent from the sandbox
   image, so the command never reaches the network stage. An attacker calling
   `ensurepip` first would still evade.
2. **I2 / I4** static near-misses unchanged — the rule set still keys on specific
   connectives; re-phrasing evades.
3. **I8** zero-width obfuscation still 0/5 — lexical matching cannot survive it.
4. **Entry discovery remains the binding constraint** on behavioural coverage of
   real skills. Round 3 should widen it deliberately (for example: run each
   plausible script, or honour a declared entrypoint in `SKILL.md`) and must
   pre-register which rule it is testing.
5. A0 recall remains an optimistic upper bound (rule-aware authorship).

## Reproduction

```sh
python scripts/measure.py research/corpus-001 \
    --results research/corpus-002/results --out research/corpus-002
```

Full generated tables in [MEASUREMENT.md](MEASUREMENT.md); raw data in
`measurement.json` and `results/`. Round-1 artefacts are untouched.
