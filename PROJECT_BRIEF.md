# Airlock technical roadmap

Airlock observes selected agent-skill entry points in a Linux namespace against
synthetic credentials, then compares the evidence with declared permissions.
It is a research prototype. A clean result covers one invocation, not every
behavior of a package, and is not a security certification.

## Current development work

- Fail-closed namespace setup, observer readiness and runtime mount verification.
- Bounded execution using verified cgroups and private tmpfs storage.
- MCP access to the shared scan path with executable-call containment gates.
- Context-aware instruction heuristics with explicit false-positive/miss reporting.
- Pinned real-helper scenarios, expected-output checks and preserved raw evidence.

See [validation checkpoints](docs/TEN-PACKAGE-MILESTONE.md) for local development
results and their limitations. Those results do not automatically describe an
older release or the current public default branch.

## Next milestones

1. Review and publish the containment changes with reproducible tests.
2. Evaluate frozen detection rules on fresh, independently reviewed cases.
3. Improve syscall-level observation and test adversarial observer interference.
4. Exercise complete MCP workflows, beyond selected local helper functions.
5. Publish a curated, redacted corpus with provenance, licenses and methodology.

## Release criteria

Required controls must fail closed. Reports must expose incomplete coverage.
Regression tests must include benign and malicious behavior, and evaluation
failures must remain visible. Security claims must match the implementation and
validation for the released revision. Cross-host behavior and independent
containment review remain outstanding work.
