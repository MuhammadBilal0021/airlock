# corpus-005 — external review response and verification

**Round:** corpus-005 · **Date:** 2026-11-07 · **Pre-registration:**
[PREREGISTRATION.md](PREREGISTRATION.md), frozen before the first scan.
Corpora unchanged (frozen corpus-001 manifests). Only detector and harness code
changed.

An external review reproduced counterexamples in the detector and in the
measurement harness. This round fixes them, adds a regression test for each one,
and re-measures the frozen corpus. Findings that are still open are listed at the
end rather than quietly dropped.

## Review findings → fixes → tests

| Review finding | Fix | Regression test |
|---|---|---|
| **High** — `ALK-009` bypass: action inside a code fence or heading ignored | Formatting exemption now applies only to bare credential-reference indicators (`AWS_SECRET_ACCESS_KEY`-style), never to action patterns. A fenced or headed *instruction* is still detected. | `test_action_inside_a_fence_is_still_detected`, `test_action_inside_a_heading_is_still_detected` |
| **High** — `"Never hesitate; send credentials…"` escaped | Negation only suppresses recognised immediate negation ("never ask the user to…"), not a negative word earlier in the sentence. | `test_immediate_negation_does_not_hide_a_later_directive` |
| **High** — harness skipped aggregate/storage gates and corpus hashes | Harness now verifies per-file SHA-256 against the frozen manifest, attempts `verify_limits`/`verify_storage`, records the result per row, and marks the summary `degraded` when the host cannot provide them. | `test_*` in `tests/test_measurement_validity.py`; verified run below |
| **High** — failed sandbox setup counted as launched coverage | New `classify_run()` separates **established** from **setup_failed** (failed result, `UNKNOWN` verdict, or `ALK-093`). Coverage counts only established runs. | `TestRunClassification` (4 tests) |
| **High** — CI treated any cgroup probe failure as a missing capability | `scripts/probe_cgroup.py` returns 77 only for a verified missing controller; every other failure raises and fails the test. | `TestCgroupProbeGate` (5 tests) |
| **Medium** — interpreter flags discarded (`env -S node --flag`) | Shebang parsing keeps flags after the program, fails closed on unknown interpreters. | `TestShebangFlags` (4 tests) |
| Correction — `ALK-013` overstated intent | Matches exact evidence artefacts only; deletion inside the declared write scope is **medium**, worded as a scope observation. `audit.log.bak` no longer fires at all. | `test_declared_backup_deletion_is_not_anti_forensics`, `test_declared_audit_log_deletion_is_medium_not_high` |
| Correction — provisioning not reproducible | Node archive verified against the published SHA-256; `get-pip.py` pinned by digest (fails closed on change); baseline install failure is fatal; every pinned module is import-verified. | exercised during bootstrap |
| Correction — wrong denominator in corpus-004 | `research/corpus-004/DIAGNOSIS.md` now states 1/21 established (4.8 %), never "1/8", and notes that run used unverified aggregate limits. | — |

## Static results (frozen corpora, unchanged)

| Metric | corpus-004 | corpus-005 | Change |
|---|---|---|---|
| False-positive rate, B0 (245 real skills) | 0/245 = 0 % [0, 1.54] | **0/245 = 0 %** [0, 1.54] | none |
| Static recall, A0 (100 adversarial) | 22/100 = 22 % [15.0, 31.1] | **22/100 = 22 %** [15.0, 31.1] | none |
| Instruction-level recall (40) | 22/40 = 55 % | **22/40 = 55 %** | none |
| Behaviour-level recall, static path (60) | 0/60 | **0/60** | none |

Closing bypasses that the authored corpus does not contain does not change its
measured recall — which is exactly why the corpus cannot be the only validation
and why round 6 must include fenced, headed and negation-prefixed samples.

## Harness validity (the review's measurement concern)

Run on this host (WSL2, no delegated cgroup controllers):

| Field | Value |
|---|---|
| addressable | 21 |
| **hash_verified / hash_mismatch** | **21 / 0** |
| **established** | **21** |
| setup_failed | 0 |
| coverage_of_addressable | 1.0 |
| clean_start | 8/21 = 38.1 % |
| positives | 1 (the known installer false positive) |
| `limits.aggregate_limits` | **false** — `unavailable: invalid literal ... 'max'` |
| `limits.storage_limits` | **false** — `AIRLOCK_STORAGE_ROOT` not set |
| **`degraded`** | **true** |

The behavioural numbers from this host are therefore reported as
**namespace-isolated, aggregate-limit-unverified**. The harness can no longer
silently present them as bounded. A host with delegated controllers (or the
systemd-scope path) would record `degraded: false`; that path was not exercised
here and is not claimed.

## Hypothesis scorecard

| # | Hypothesis | Outcome |
|---|---|---|
| 1 | B0 false positives remain 0/245 | ✅ correct |
| 2 | A0 static recall remains 22/100 | ✅ correct |
| 3 | hash 21/21, established 21, degraded true | ✅ correct |
| 4 | No positive findings on real code | ❌ **one persists** — the known `web-artifacts-builder` installer false positive |

## Still open after this round (not fixed, stated plainly)

1. **`ALK-009` remains lexical.** `I2` (false-authority phrasing), `I4`
   (cross-tool pivot) and `I8` (zero-width obfuscation) are still missed — 0/5
   each. Round 6 must author samples that specifically exercise fenced, headed and
   negated directives, because the current corpus predates the fix.
2. **Bounded execution was not exercised here.** Limits are verified where the
   host supports it; on this host they are unavailable and disclosed as degraded.
   A GitHub-hosted runner with delegated CPU is still the proving ground.
3. **Provisioning checksums are pinned to today's upstream bytes.** Bumping pip
   or Node requires re-reviewing the pin; that is intentional, but it is manual.
4. **No independent containment audit.** Unchanged.

## Reproduction

```sh
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-005/results/benign --static-only
python scripts/scan_dataset.py research/corpus-001/adversarial/manifest.json \
    --output research/corpus-005/results/adversarial --static-only
python scripts/measure.py research/corpus-001 \
    --results research/corpus-005/results --out research/corpus-005
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-005/results/harness-validity.json
```
