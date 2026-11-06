# Preparing a public change

The current working tree includes research and local diagnostics. Select files
deliberately; do not publish it with a blanket `git add .`.

- `.local-notes/PROJECT_BRIEF.original.md` preserves the original planning brief
  and is ignored. The tracked PROJECT_BRIEF.md is now a technical roadmap.
  This does not remove older copies from public Git history.
- Root probe/process logs and environment files are ignored. Review any new
  capture for host paths, personal data, credentials and source contents before
  publication. Synthetic canaries should be clearly identified as such.
- Keep reproducible tests and their required inputs. In particular,
  tests/test_instruction_context.py reads research/heldout-002/plan.json; include
  that frozen plan with the test. Retain the reports linked from documentation,
  or update the links when preparing a smaller release.
- Publish upstream source copies only after checking their licenses and keeping
  required notices, revision pins and file hashes. Prefer provenance manifests
  and reproduction scripts where redistribution is unnecessary.
- Confirm GitHub private vulnerability reporting is enabled before publishing
  SECURITY.md as a verified reporting route. No mailbox or response-time promise
  is assumed. The maintainer has agreed to perform this check.
- Match README claims to the revision being released. Local test results do not
  validate older public code. Preserve evaluation failures and coverage limits.

The Action input-hardening check executes its actual Bash blocks with inert
stubs. Three focused tests pass: shell-looking inputs remain literal, scan
failure survives the tee pipeline, and only a successful scan passes the final
gate. This is local validation, not a claim that a GitHub-hosted workflow ran.
