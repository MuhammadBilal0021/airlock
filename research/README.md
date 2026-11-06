# Research evidence and reproduction

This source release contains curated summaries, synthetic text labels and a
pinned provenance manifest. Downloaded third-party packages, full upstream Git
trees and raw runtime captures are excluded. Historical raw files remain local;
readers cannot independently audit them from these summaries alone.

## Real helper executions

- [Pinned input manifest](published/executable-manifest.json): source repositories,
  immutable revisions and SHA-256 hashes. tmux is staged but not executed.
- [Original results](execution-002/summary.json) and
  [calibrated results](execution-003/summary.json): ten helpers, twice each.
- [Calibration comparison](execution-003/calibration-comparison.json) and
  [recorded evidence audit](execution-003/evidence-audit.json).

These selected helpers do not exercise full Figma, GitHub or model workflows.
Counts are not registry-wide prevalence estimates or proof of package safety.

## Detection evaluation

[The frozen plan](heldout-002/plan.json), [text outcomes](heldout-002/text-results.json)
and [helper summary](heldout-002/summary.json) retain the first evaluation's
failures: 3/8 benign texts flagged and 4/8 adversarial texts missed. A generated
harness SyntaxError invalidated the first gh-fix-ci attempt; only the harness
was corrected, with unchanged scanner rules, for the reported helper rerun.

[Subsequent calibration](instruction-context-001/results.json) corrected the
known text errors. These developer-labeled cases now serve as regressions;
they cannot support a fresh holdout or general accuracy claim.

## Reproduce a new run

Use a disposable Linux/WSL environment with user namespaces, systemd user scopes,
and delegated memory, CPU and task controllers. No real credentials are needed.
The download step fetches pinned source as data and never installs it.

```sh
python3 scripts/stage_release_corpus.py
python3 scripts/execute_candidates.py --output research/my-new-run --repeats 2
python3 scripts/validate_mcp_execution.py --output research/my-new-mcp-run
```

The execution harness requires a fresh full test pass with no skips, checks
source hashes and verified cgroup/tmpfs gates, and checks expected outputs.
Output directories must be new. The resulting raw reports are local artifacts;
review/redact them before any publication. Upstream code retains its own license.

To validate code without downloading the corpus, run `python3 scripts/run_tests.py`.
Skipped required tests fail this gate. A hosted CI environment without the
necessary kernel/controller features must fail visibly, not report full coverage.
