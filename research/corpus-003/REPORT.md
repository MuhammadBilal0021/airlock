# corpus-003 — addressable behavioural coverage

**Round:** corpus-003 · **Date:** 2026-11-07 · **Pre-registration:**
[PREREGISTRATION.md](PREREGISTRATION.md), frozen before the first harness ran.
Corpus unchanged: the frozen 245-package B0 manifest from corpus-001.

## Correction first

Rounds 1 and 2 reported "5 of 245 real skills executed" as 2 % coverage. That
denominator was wrong and it understated the product. Measured on the frozen
corpus (`scripts/measure_invocation_evidence.py`):

| Property | Count | Share |
|---|---|---|
| Packages shipping at least one executable file | **21** | 8.6 % |
| Packages that are text/markdown only | 224 | 91.4 % |

A sandbox cannot execute a package that contains nothing executable. The
defensible denominator is **21**, and round-2 coverage on it was **5/21 = 23.8 %**.
The earlier 2 % figure is superseded; rounds 1 and 2 are left unedited and this
notice is the correction.

The 91 % text majority is not a coverage failure — it is a different product
problem (semantic analysis of instructions), and it is out of scope for this
round.

## Results

| Metric | Value |
|---|---|
| Addressable packages | 21 / 245 |
| **Behavioural coverage (launched)** | **21 / 21 = 100 %** |
| Clean start (exit 0) | **4 / 21 = 19.0 %** |
| Timed out | 0 |
| Positive findings on real code | **0** |
| Unreachable under the frozen rule | 0 |

Harness provenance: 6 from documented invocation in `SKILL.md`, 6 single
artefact, 9 by priority rule. Every harness is recorded in
`results/harness-coverage.json` and replays identically.

## Hypothesis scorecard

| # | Hypothesis | Outcome |
|---|---|---|
| 1 | Coverage ≥ 80 % of the 21 | ✅ **Correct** — 100 % |
| 2 | Clean start ≤ 60 % | ✅ **Correct, sharply** — 19 % |
| 3 | Zero positive findings on real code | ✅ **Correct** — 0/21 |
| 4 | ≥ 2 packages unreachable | ❌ **Wrong** — every package launched |

Hypothesis 4 was wrong in the useful direction: harness synthesis is solved for
this corpus. The interesting failure is hypothesis 2.

## Why 17 of 21 crash immediately

| Exit code | Count | Meaning |
|---|---|---|
| 0 | 4 | script ran and exited cleanly on `--help` |
| 1 | 12 | Python error — missing third-party dependency or required argument |
| 127 | 4 | command not found: **`node` is absent from the sandbox image**, and one shell script calls an external tool |
| 2 | 1 | shell usage error |

Two different problems are hiding in that table:

1. **The sandbox image is too thin.** `node` is missing entirely, so 3 packages
   could never run regardless of harness quality. This is the same class of
   failure as corpus-001's B11 miss (`pip` absent). A security sandbox that
   cannot start a Node program cannot inspect the growing share of skills written
   in JavaScript/TypeScript.
2. **Arguments and inputs are not materialised.** `--help` executes the startup
   path but not the work. Twelve scripts exit 1 because real invocation needs a
   document, a chart, or a server.

## What this round actually establishes

**Established:** given a frozen, deterministic harness rule, airlock can start
**every executable package** in the sample, reproducibly, with **zero false
positives** on real code. That is a real coverage claim and it is the first time
the project has one.

**Not established:** that those packages were *verified*. A skill that crashes on
`--help` has not been behaviourally analysed in any meaningful sense; it has been
observed to start. Calling this "100 % coverage" without the 19 % clean-start
number beside it would be exactly the kind of claim that dies in due diligence.

## The next two levers, in order

1. **Runtime baseline.** Ship a sandbox image with `node`, `pip` + a pinned
   wheel cache, and the common document libraries, so code that assumes a
   runtime can actually run. Est. +4 packages immediately (node), more once
   Python deps resolve.
2. **Input materialisation.** Generate synthetic fixtures per skill family (a
   docx, a pdf, an xlsx, a chart spec) so `--help` becomes a real invocation.
   This is where harness synthesis should get smarter — an agent that reads
   `SKILL.md` and writes a *call*, not just a command.

Order matters: runtime first, because no amount of argument cleverness fixes a
missing interpreter.

## Reproduction

```sh
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-003/results/harness-coverage.json
python3 scripts/measure_invocation_evidence.py
```
