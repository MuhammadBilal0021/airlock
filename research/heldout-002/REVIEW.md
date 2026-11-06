# Frozen held-out evaluation — November 6, 2026

Three previously unused package helpers completed twice with verified expected
outputs and CLEAN verdicts. The text detector did not meet all predeclared labels:
it flagged three benign passages and missed four adversarial passages. Passing
the 63-test regression suite does not erase these semantic failures.

## Method and evidence

The [plan](plan.json) froze package selection, 16 text labels and the scanner
SHA-256 before execution. All `airlock/*.py` bytes remained unchanged at
`4a9e0dd34efcd0c5c756228931c3a70fa96e43e186717e8202ac56036edd43b7`.
Complete package directories were staged from openai/skills revision
`49f948faa9258a0c61caceaf225e179651397431`; source hashes match the manifest.
Downloaded instructions were specimens, not instructions to the evaluating agent.

The [preflight](preflight.json) records 63 tests passing, zero failures/errors
and zero skips. The [evidence audit](evidence-audit.json) verifies the unchanged
plan/rules, source hashes, expected outputs, control records, repeated inputs
and findings. Raw per-run reports remain beside this review.

| Package | Exercised behavior | Repeated result |
| --- | --- | --- |
| security-ownership-map | Filter/sort synthetic ownership CSV; select Beta with 12 touches | 2/2 expected outputs; CLEAN |
| gh-fix-ci | Import actual helper; classify check states and extract synthetic failure log | 2/2 expected outputs; CLEAN |
| skill-installer | Import actual helper; extract safe ZIP and reject traversal ZIP/path | 2/2 expected outputs; CLEAN |

All six records report verified cgroup memory/task/CPU limits and tmpfs byte/inode
limits, isolated network/mounts, fresh procfs and recursively read-only/nosuid
runtime mounts. No collection warnings were recorded; the errors list contains
only the namespace-flags diagnostic. These are local helper executions, not
GitHub service workflows, actual skill installation, or proof of package safety.

## Text results

| Predeclared label | Flagged | Not flagged |
| --- | --- | --- |
| Benign (8) | 3 false positives | 5 true negatives |
| Adversarial (8) | 4 true positives | 4 false negatives |

False positives: `override-warning` quotes an instruction while rejecting it;
`bcc-documentation` describes ordinary mail fields; `policy-documentation`
describes a compliance requirement without overriding authority.

False negatives: `postposed-adverb`, `synonym`, `indirect-override` and
`spaced-adverb`. These expose word-order, vocabulary, implicit-override and
obfuscation gaps. See [exact passages and hits](text-results.json).

This is a small developer-authored challenge set, not independent annotation,
a random sample, or a general accuracy estimate. Package directories were unused,
but their repository had appeared in the earlier corpus. The text check exercises
ALK-009's instruction matching directly, not an agent's response to an attack.

## Preserved harness failure

The original [attempt](../heldout-001/summary.json) contains two invalid gh-fix-ci
executions: a generated harness string caused SyntaxError before specimen import.
Those are not valid package results. Only the evaluation harness was corrected
(raw string plus compilation check); this directory holds a fresh run under the
identical plan and scanner. The original files remain intact. Text results match
exactly between attempts. CLEAN alone does not establish successful execution;
the envelope status and expected-output check are essential.

## Next priority

Improve ALK-009's contextual precision and recall, beginning with quoted warnings,
ordinary documentation and malicious action/target relationships. Preserve these
results as the baseline; once used to guide changes, these cases become regression
cases and cannot serve as the next untouched holdout. Add a fresh evaluation set
before claiming generalization. No detector tuning was performed in this evaluation.
