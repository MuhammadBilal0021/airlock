# Scoring calibration: same inputs, revised interpretation

On November 6, 2026, the revised implementation passed **63 tests with no skips**
in 43.295 seconds, including all existing malicious behavioural fixtures and
eight new calibration controls. The ten pinned package scenarios then ran twice:
**20/20 expected outputs confirmed**, no timeouts or collection-limit warnings.

Comparison against `execution-002` verifies identical original provenance,
generated input hashes and entrypoints for every run. The observed written-path
sets also match for all 20 pairs. Original reports remain unchanged.

| Case | Previous verdict / score | Revised verdict / score | Evidence retained |
| --- | --- | --- | --- |
| figma-design-rules | ELEVATED / 20 | CLEAN / 0 | Both helper branches still exercised; ordinary heading no longer matches ALK-009 |
| anthropic-pptx | HIGH / 60 | CLEAN / 0 | ALK-007 retains one cache event and four deck-write events as two informational groups |
| migrate-to-codex | CRITICAL / 100 | CLEAN / 0 | ALK-007 retains all 14 bytecode-cache writes in one informational group |
| Other seven packages | CLEAN / 0 | CLEAN / 0 | Expected outputs and repeated verdicts remain consistent |

## Changes

- Declaration extraction distinguishes an absent write policy from an explicit
  empty list or `false` (no writes allowed), and from `true` (wildcard allow).
  Coverage reports whether a write policy was declared. Missing policy is not
  silently represented as an explicit prohibition.
- ALK-007 groups related writes rather than adding a medium-severity contribution
  for every file. Missing-policy observations are informational. Writes outside
  an explicit allowlist remain medium; explicit deny rules take precedence over
  allowlists and default scratch/output locations and are high.
- Cache-shaped paths are classified heuristically, never exempted from explicit
  restrictions. All raw events and written-path summaries remain available.
- ALK-009's broad `silently` and `always include/add` triggers now require action
  or sensitive side-effect context. Ordinary API documentation and headings no
  longer trigger those patterns. Actionable concealment, recipient insertion,
  credential transfer and instruction overrides remain regression-tested.

No package-name allowlists were added. The specimen code and containment settings
were not changed to obtain the new scores. The existing canary-exfiltration,
silent-BCC, persistence/rug-pull and remote-fetch tests pass; an additional
missing-policy persistence test and explicit-denial/cache tests also pass.

## What CLEAN means here

It means no scored finding under these rules for these narrow invocations. It
does not establish safety or complete workflow coverage. Missing write policy
remains an information gap, and the text detector remains a heuristic with
possible false positives and false negatives. These cases motivated the changes,
so this is calibration evidence, not an independent generalization benchmark.

Next validation should use a held-out corpus and additional adversarial phrasing
without changing rules to match individual package names. Read-only policies and
explicit denials must continue to be tested separately from missing metadata.

## Artifacts

- [Before/after comparison](calibration-comparison.json): 20 matched input/entrypoint pairs.
- [Evidence audit](evidence-audit.json): limits, output checks, source hashes and repeat agreement.
- [Preflight result](preflight.json) and [full test log](preflight-tests.log).
- [Summary](summary.json), [environment](environment.json), and the 20 raw report envelopes.
- [Original review](../execution-002/REVIEW.md): preserved findings and interpretation before calibration.

The WSL startup failure was recovered using the previously authorized WSL
shutdown; no Windows reboot was needed. Changes are local and unmerged.
