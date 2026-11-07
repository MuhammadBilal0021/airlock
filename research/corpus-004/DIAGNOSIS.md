# corpus-004 diagnosis — why the executable skills fail

**Purpose:** corpus-004 measured clean start at 4/21 (19 %) and could not say why
twelve packages exited 1. This is the instrumented follow-up: the harness now
records each specimen's stderr, so every failure has a cause instead of a guess.

**Method:** `scripts/harness_coverage.py` now calls `run_skill` + `analyse`
directly (the same primitives `run_target` uses) and records `stderr`, `stdout`
and runner errors per package. Three fixable classes were then addressed and the
same 21 packages re-run. Raw data:
`results/harness-diagnostics.json` (before) and
`results/harness-diagnostics-after.json` (after).

## Result

| Metric | corpus-004 round | after diagnosis + fixes |
|---|---|---|
| Coverage (launched / 21) | 21/21 = 100 % | 21/21 = 100 % |
| **Clean start (exit 0)** | **4/21 = 19.0 %** | **8/21 = 38.1 %** |
| Exit 127 (command not found) | 2 | **0** |
| SIGTRAP (-5 / 133) | 4 | **0** |
| Timed out | 0 | 1 |
| **Positive findings on real code** | 0 | **1** (investigated below) |

## Failure taxonomy (the actual answer to "why")

| # | Cause | Packages | Status |
|---|---|---|---|
| A | **Runtime absent** — `node` not in the image | 3–4 | ✅ **fixed** by the runtime overlay |
| B | **Resource limit** — Node aborts with SIGTRAP under the 512 MiB address-space cap | 4 | ✅ **fixed** by a disclosed 2 GiB override |
| C | **Harness ignored the shebang** — `run.sh` written for bash run under `/bin/sh`; `#!/usr/bin/env -S node` run as `env script` | 2 | ✅ **fixed** (harness bug, not a skill bug) |
| D | **Missing Python dependency** — `defusedxml`, `numpy` | 3 | ✅ **fixed** by adding to the pinned baseline |
| E | **Missing external binary/service** — `soffice` (LibreOffice), `nvidia-smi`, a running `tmux` server | 3 | ❌ open — environment services, not libraries |
| F | **Input materialisation** — scripts need a real document; `--help` is parsed as a filename (`FileNotFoundError: '--help'`) | 3 | ❌ open — the next big lever |
| G | **ES-module semantics** — script uses `import` but is run as CommonJS | 1 | ❌ open — needs package context (`.mjs`/`type: module`) |
| H | **Timeout** — `init-artifact.sh` runs a package install with no network route | 1 | ❌ open — expected without network |
| I | **Genuine usage failure** — `tmux` correctly reports "No tmux server found" | 1 | ✅ correct behaviour, not a defect |

Cause C is worth naming plainly: two "broken packages" were a broken harness. The
rule now honours `#!` including `env -S` and resolves `bash`/`node` to their
absolute paths, because the sandbox execs the entry directly (no PATH search).

## The one positive finding on real code

`anthropics/skills:skills:web-artifacts-builder` — verdict **CRITICAL**, rules
`ALK-002` (undeclared credential read), `ALK-004` (undeclared egress), `ALK-010`
(lethal trifecta) — and it **timed out** at 10 s, so the observation is partial.

What actually happened: `scripts/init-artifact.sh` is a scaffolding helper that
runs a package-manager install. With no network route, the installer retried
until the timeout while reading its own config (which the decoy home populates
with canary credentials) and attempting registry egress.

**This is a false positive for the security claim, and an important one.** Benign
developer tooling behaviourally resembles supply-chain attack: it fetches remote
code, reads credential config, and talks to registries. The finding is real
(those behaviours occurred) but the intent is not malicious. Detection must
distinguish "declared install step" from "undeclared install", which is exactly
the declared-vs-observed comparison the tool already has — the harness just
never declared that this package runs an installer.

Publishing it as a true positive would be dishonest; publishing it as noise
without explanation would be too. The correct denominator is the **21 established
runs**, not the eight clean exits (the flagged package timed out and was never a
clean exit): that is **1/21 = 4.8 %**, and 1/20 = 5.0 % excluding the timeout.
Both are far too small a sample to publish as a rate, and they mix a
timed-out observation with completed ones, so no rate is claimed.

Separately, this measurement was taken with **aggregate cgroup limits and storage
limits unverified** (`run_skill` was called directly). Namespace isolation still
applied, but the bounded-execution guarantee did not; corpus-005 records those
fields explicitly and labels a host that cannot provide them as degraded.

## The containment trade-off in cause B

Fixing SIGTRAP required raising the per-process address-space cap from 512 MiB to
2 GiB for these runs. That **weakens a containment control** — a runaway
allocation can now reserve four times as much address space. The change is:

- opt-in via `AIRLOCK_ADDRESS_SPACE_BYTES`;
- **default unchanged at 512 MiB**;
- the applied value is always reported in
  `coverage.resource_limits.address_space_bytes`, so a result can never claim a
  limit it did not apply.

A production decision on whether JS entrypoints get a documented, bounded higher
cap belongs in the containment contract, not in a measurement script.

## What this justifies saying

- **"2 % coverage" was never the real problem**; coverage of the addressable set
  is 100 %, and after three harness/runtime fixes the clean-start rate doubled to
  38 % with the remaining failures fully attributed.
- **Every remaining failure is input, service or semantics — not detection.**
  The next lever with the largest payoff is input materialisation (F), then
  environment services (E).
- **The first behavioural false positive on real code is documented**: benign
  installer scaffolding looks like an attack. That is a precision problem with a
  known shape, not a mystery.

## Reproduction

```sh
./scripts/provision_runtime.sh --bootstrap
export AIRLOCK_RUNTIME_OVERLAY="$HOME/.airlock/runtime"
export AIRLOCK_ADDRESS_SPACE_BYTES=2147483648   # disclosed containment trade-off
python3 scripts/harness_coverage.py \
    --manifest research/corpus-001/benign/manifest.json \
    --output research/corpus-004/results/harness-diagnostics-after.json
```
