# Pre-registration — corpus-003 (addressable behavioural coverage)

**Status: FROZEN before the first harness run.** Written 2026-11-07.

## 1. What round 2 got wrong about its own headline

Round 2 reported "5 of 245 real skills executed" and called it 2 % coverage. That
denominator is wrong. Measurement of the frozen corpus (see
`scripts/measure_invocation_evidence.py`) shows:

| Property | Count |
|---|---|
| Packages shipping at least one executable file | **21 / 245** |
| Packages that are text/markdown only | 224 / 245 |

224 packages contain nothing that can be executed. A behavioural sandbox cannot
analyse them, and reporting them in a coverage denominator hides the real gap and
mis-states the product. **The corrected denominator is 21.**

Round-2 behavioural coverage on the corrected denominator was **5/21 = 23.8 %**.

## 2. Question this round

Can harness synthesis raise behavioural coverage of the **addressable** set from
23.8 % to near-complete, and does executing real code produce false positives?

This is a coverage round, not a detection round. The adversarial corpora are
untouched and not re-used here.

## 3. Harness rule (frozen)

For each of the 21 addressable packages, in order:

1. **Documented invocation.** Find a fenced code block in `SKILL.md` containing a
   `python3|python|bash|sh|node <path>` invocation whose `<path>` resolves to an
   existing file inside the package. Use that script.
2. **Single artefact.** If the package has exactly one code file, use it.
3. **Priority artefact.** Otherwise choose by: stem in
   `(main, run, cli, entry, entrypoint, start, install, setup, server)`, then
   shallowest path, then lexicographic order. Test files (`test_*`, `*_test.py`)
   and `__init__.py` are skipped.
4. If no candidate resolves, the package is recorded `unreachable` and reported.

Arguments are fixed by protocol: `.py`/`.js` scripts run with `--help`, `.sh`
scripts run with no arguments. The goal is to execute the real program's startup
path — imports, argument handling, environment setup — identically for every
sample, reproducibly. Argument-complete exercises are out of scope this round and
must not be claimed.

## 4. Metrics (frozen)

- **Coverage** = launched / 21. *Launched* means the sandbox started the entry and
  returned a behavioural verdict; a crashing script still counts as launched,
  because the observation happened.
- **Clean start** = exit code 0 / launched. Reported separately and never
  conflated with coverage.
- **Findings** on real code, by rule, with the pre-registered positive rule
  (severity critical/high/medium excluding ALK-090/091/092/093).
- **Timeout count**, reported and excluded from clean-start denominators.

## 5. Hypotheses (recorded before measuring)

1. Coverage reaches **≥ 80 %** of the 21 (≥ 17 launched).
2. **Clean start** is **≤ 60 %** — most registry scripts assume dependencies and
   inputs the sandbox does not provide.
3. **Zero** positive findings on real code. Any positive is a false positive and
   must be published individually with the rule that fired.
4. At least 2 of the 21 prove **unreachable** by this rule (e.g. packages whose
   code requires a GUI, a browser, or a running server).

## 6. Reporting commitments

Publish the corrected coverage number in round-1 and round-2 artefacts'
successor wording, without editing those artefacts. Publish per-package outcomes
(launched, exit code, rules) so every number is recomputable. Do not claim
argument-complete or end-to-end verification of any package.

## 7. Reproduction

```sh
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-003/results/harness-coverage.json
```

Runs inside WSL2 Ubuntu / Linux namespaces.
