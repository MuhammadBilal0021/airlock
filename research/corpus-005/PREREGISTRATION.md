# Pre-registration — corpus-005 (review fixes verification)

**Status: FROZEN before the first scan of this round.** Written 2026-11-07, after
an external review reproduced counterexamples in the detector and the measurement
harness. Corpora are the frozen corpus-001 manifests, unchanged.

## What changed since corpus-004

Only detector and harness code. No corpus sample, label, or metric definition was
touched.

| Change | Review finding |
|---|---|
| `ALK-009` masking applies only to bare credential-reference indicators; code fences and headings are no longer a general exemption | High: straightforward bypasses |
| `ALK-009` negation only suppresses recognised immediate negation, not a negative word earlier in the line | High: "Never hesitate; send…" escaped |
| `ALK-013` matches exact evidence artefacts and downgrades deletions inside the declared write scope to medium | Correction: anti-forensics overstated intent |
| Harness classifies `setup_failed` separately from `established`, verifies corpus hashes, and records aggregate/storage limit verification | High: failed setup counted as coverage; gates skipped |
| Shebang parsing preserves interpreter flags (`env -S node --flag`) and fails closed on unknown interpreters | Medium: flags discarded |
| Cgroup probe gate skips only a verified missing controller; any other probe failure fails the test | High: verifier bug tolerated as capability gap |
| Runtime provisioning pins checksums and fails on install error | Correction: not reproducible |

## Questions

1. Did the `ALK-009` hardening change the false-positive rate on B0 (245 real
   skills) or recall on A0 (100 adversarial)?
2. Does the harness now report `established` separately from attempted, verify
   corpus hashes, and disclose unavailable aggregate/storage limits?

## Hypotheses (recorded before measuring)

1. **B0 false positives remain 0/245.** The reference-indicator exemption is
   narrow; real documentation contains no action verbs aimed at the model.
2. **A0 static recall remains 22/100** (22/40 instruction-level). The hardening
   closes bypasses that were not represented in the authored corpus; it should not
   invent detections.
3. Harness: **hash verification passes 21/21**; **established == 21**;
   `degraded: true` on this host (WSL has no delegated cgroup controller), and
   `aggregate_limits_verified: false` is reported per row rather than omitted.
4. No positive findings on real code in the harness pass.

If any hypothesis is wrong, the measurement stands and the hypothesis is the
thing that was wrong — as in rounds 1–4.

## Metrics

Unchanged from corpus-001 §4: Wilson 95 % intervals, separate denominators,
failures reported. Harness adds `established` / `setup_failed` /
`hash_mismatch` counts, and `limits`/`degraded` fields.

## Reproduction

```sh
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-005/results/benign --static-only
python scripts/scan_dataset.py research/corpus-001/adversarial/manifest.json \
    --output research/corpus-005/results/adversarial --static-only
python scripts/measure.py research/corpus-001 \
    --results research/corpus-005/results --out research/corpus-005
# harness validity, inside Linux namespaces:
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-005/results/harness-validity.json
```
