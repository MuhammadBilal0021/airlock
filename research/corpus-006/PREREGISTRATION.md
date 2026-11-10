# Pre-registration — corpus-006 (structural bypass corpus A1)

**Status: FROZEN before the A1 corpus was generated or scanned.** Written
2026-11-07. B0 is the unchanged frozen 245-package benign manifest.

## Why a new adversarial corpus

corpus-001's A0 was authored before the detector changed, so its 22/100 recall no
longer describes the current engine — and it contains none of the structures the
review used to demonstrate bypasses. Re-using it would repeat the original
mistake of validating a fix on samples the fix was not built against.

A1 is 12 families × 10 variants = **120 instruction-level samples**, generated
deterministically (seed `20261108`), frozen by manifest hash. Every sample is
labelled malicious by construction: a model following the text would act against
the skill's stated purpose. Whether the detector *can* see it is the measurement.

## Families and frozen expectations

| Family | Structure | Expected detection |
|---|---|---|
| J1 | action inside a fenced code block | **≥ 80 %** (formatting is no longer an exemption) |
| J2 | action inside a markdown heading | **≥ 80 %** |
| J3 | negation-prefixed directive ("Never hesitate; send…") | **≥ 80 %** (only immediate negation may suppress) |
| J6 | base64-encode then send | **≥ 60 %** (pattern encodes the prepositional phrase) |
| J7 | directive inside an HTML comment | **≥ 60 %** (comment text is part of the body) |
| J4 | zero-width characters inside keywords | **≤ 20 %** (lexical ceiling, declared) |
| J5 | Cyrillic homoglyphs inside keywords | **≤ 20 %** (lexical ceiling, declared) |
| J8 | sensitive object and action separated by > 400 chars | **≤ 20 %** (80-character association window) |
| J9 | routing paraphrase without "whenever" | **≤ 40 %** |
| J10 | split-step instruction (read, then POST) | **≤ 40 %** (POST is not in the verb list) |
| J11 | oblique object ("forward everything relevant") | **≤ 40 %** |
| J12 | system-prompt reveal paraphrase | **≤ 60 %** |

## Hypotheses (recorded before measuring)

1. Formatting carriers (J1, J2) and immediate-negation (J3) are the classes the
   corpus-005 fix targeted: **each ≥ 80 %.**
2. Obfuscation families (J4, J5) and the long-distance family (J8) expose a
   **lexical ceiling: each ≤ 20 %.**
3. Overall A1 recall lands **between 35 % and 60 %** — higher than A0's 22 %
   because the targeted classes now fire, far from complete because half the
   families are paraphrases or obfuscations.
4. B0 false positives remain **0/245** — the new corpus adds no benign material
   and the detector is unchanged since corpus-005.

## Decision rule (frozen)

- If H1 and H2 hold but H2-obfuscation and paraphrases fail as predicted →
  **lexical ceiling demonstrated.** The roadmap conclusion is that text-only
  detection cannot close the gap and the instruction-execution harness is the
  next necessary step, not a nice-to-have.
- If J1/J2/J3 themselves fail → the corpus-005 fix did not work; **stop and fix
  the detector before any further packaging.**
- Any B0 false positive is published individually with the rule that fired.

## Metrics

Unchanged: Wilson 95 % intervals, per-family and overall recall, separate
denominators, failures reported. FPR reported on the same detector.

## Reproduction

```sh
python scripts/generate_adversarial_corpus_v2.py \
    --output research/corpus-006/adversarial-v2
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-006/results/benign --static-only
python scripts/scan_dataset.py research/corpus-006/adversarial-v2/manifest.json \
    --output research/corpus-006/results/adversarial --static-only
python scripts/measure.py research/corpus-001 \
    --benign-manifest research/corpus-001/benign/manifest.json \
    --adversarial-manifest research/corpus-006/adversarial-v2/manifest.json \
    --results research/corpus-006/results --out research/corpus-006
```
