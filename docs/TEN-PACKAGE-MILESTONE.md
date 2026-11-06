# Ten-package behavioral milestone

Ten pinned real package helpers were exercised twice with independently checked
expected outputs. This covers selected helper invocations, not full agent or
service workflows. A CLEAN verdict is not a package-safety certification.

The corpus includes OpenClaw model-usage and skill-creator; OpenAI Figma code
connect, design rules, notebook, plugin-creator and migration helpers; and
Anthropic PDF, PPTX and webapp-testing helpers. tmux was staged but excluded
because the device policy does not provide devpts.

The original ten-package run exposed scoring problems. A calibrated rerun
completed all 20 output checks. A subsequent frozen text challenge flagged 3/8
benign passages and missed 4/8 adversarial passages. Later fixes addressed those
known cases; they are now development regressions, not independent validation.
Three additional unused helper packages also passed twice in that held-out run.

The runner subsequently gained a fail-closed listener-readiness handshake and
separate loopback-only topology checks. On November 6, 89 Linux tests passed
without skips and a bounded MCP request captured the expected weather domain.
The three Action input tests passed separately after publication cleanup.
Release-candidate validation must rerun the combined suite on its exact sources.

See [curated evidence and reproduction](../research/README.md). Historical raw
captures are retained locally and excluded from this source release; published
summaries are not a replacement for an independent audit of those captures.

Remaining review areas include adversarial observer interference, kernel attack
surface, portability, independent detection evaluation, and complete workflows.
ALK-012 remains subject to the owner review described in its draft PR.
