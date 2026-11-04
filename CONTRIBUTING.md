# Contributing to airlock

Thanks for being here. airlock is deliberately small and deliberately
dependency-free, and both of those are things a contribution can accidentally
break — so please read the ground rules before opening a PR. They exist to keep
the tool trustworthy, not to keep people out.

## The three rules

**1. No runtime dependencies.** `pyproject.toml` has `dependencies = []` and
that is not an oversight. A scanner that installs a dependency tree is itself a
supply-chain risk, and `pipx install airlock-scanner` / `uvx airlock-scanner`
with nothing to resolve is what makes it usable in a CI job someone else owns.
If you need YAML parsing, HTTP, DNS or TLS handling, it gets hand-rolled in the
standard library the way `declared.py`, `sinkhole.py` and `canary.py` already do
it. Dev-only tooling (test runners, linters) is fine.

**2. No finding without an artefact.** Every rule must point at something
observed: a canary string in captured bytes, an `atime` delta, a file on disk, a
DNS query, a process command line. If your rule can only say "this text looks
suspicious", it is still welcome — but it must set
`confidence="heuristic"`, and the renderer will label it as a reason to look
rather than proof. `ALK-009` is the model to follow.

**3. Every new rule ships with a fixture and a test.** A rule with no fixture
that triggers it and no test that asserts it will silently rot, and a scanner
that quietly stops detecting things is worse than no scanner. See below.

## Getting set up

airlock needs Linux with unprivileged user namespaces. On Windows that means
WSL2, not PowerShell.

```bash
git clone https://github.com/MuhammadBilal0021/airlock.git
cd airlock
python3 -m unittest discover -s tests -v     # 19 tests, no install step needed
python3 -m airlock demo --timeout 25         # run every fixture, print the table
```

Check your kernel allows the sandbox before debugging anything else:

```bash
unshare --user --map-root-user --mount --net --pid --fork true && echo "namespaces OK"
```

If that fails, the seven `TestSandboxBehaviour` tests skip and the pure-logic
tests still run — but you will not be able to develop detection rules. Inside
nested containers a fresh `procfs` mount is often refused; airlock falls back to
an inert `/proc` and reports `ALK-091` rather than pretending it saw the process
tree. That is expected, and it resolves on a normal host or WSL2.

## Where things live

| file | responsibility |
|---|---|
| `airlock/canary.py` | canary generation and the encoding variants indexed for detection |
| `airlock/decoys.py` | the synthetic machine: fake secrets, `atime` anchoring, planted paths |
| `airlock/sinkhole.py` | DNS responder, TCP listeners, TLS ClientHello SNI parser, HTTP proxy, JSONL capture |
| `airlock/_nsinit.py` | PID 1 inside the namespace: mounts, `procfs`, process sampling |
| `airlock/sandbox.py` | builds the run directory, takes the stat-only baseline, runs the skill, diffs the filesystem |
| `airlock/declared.py` | parses manifests (OWASP Universal Skill Format subset) and finds embedded instructions |
| `airlock/engine.py` | turns evidence into findings and a risk score — **most rules are added here** |
| `airlock/render.py` | terminal and Markdown output |
| `airlock/sarif.py` | SARIF 2.1.0 for GitHub code scanning |
| `airlock/cli.py` | `scan`, `policy`, `demo` |

The data flow is one direction: `sandbox.py` produces a `RunResult`, `declared.py`
produces a `CapabilityDeclaration`, and `engine.analyse()` joins them into a
`Verdict`. Renderers only read a `Verdict`; they never reach back into raw
events. Keep it that way — it is what makes the output formats cheap to add.

## Adding a detection rule

1. Pick the next free ID in the `ALK-0xx` band. **IDs are permanent.** Never
   renumber or reuse one, because people pin CI gates to them.
2. Map it to an OWASP Agentic Skills Top 10 category (`AST01`–`AST10`) and put
   that in the `ast=` field. If nothing fits, that is worth saying in the PR
   description — it may mean the taxonomy has a gap.
3. Choose a severity and be conservative. `critical` means confirmed
   exfiltration, remote code execution, or a metadata-endpoint probe. Weights are
   `crit 40 / high 20 / medium 8 / low 3 / info 0`, capped at 100.
4. Write the evidence strings so a reviewer can verify the claim without running
   anything: the captured payload, the path, the command line.
5. Add a fixture under `fixtures/` that triggers it, and — just as important —
   check it does **not** trigger on `01-benign-weather` or `06-over-broad`.
6. Add a test to `tests/test_airlock.py` asserting the rule fires on your fixture
   and stays quiet on the honest ones.
7. Add a row to the findings table in `README.md` and a `_RULE_HELP` entry in
   `sarif.py`.

## Adding a fixture

Fixtures are inert specimens that model real published attack patterns. Rules for
new ones:

- **No working exploit, no live domain, no real credential.** Use reserved TLDs
  (`*.test`) and let the decoy machine supply the secrets.
- Give it a number and a name that says what it models (`07-imds-probe`).
- State the expected verdict in `fixtures/README.md`, including when the expected
  verdict is *clean*. Half the value of the fixture set is the false-positive
  control: `01` (honest) and `06` (greedy manifest, honest code) must stay quiet.
- If your fixture models a real incident, cite it in the SKILL.md body the way
  `05-drift-v1.0.17` cites the `postmark-mcp` rug pull.

## Reporting a false positive

False positives are bugs. The fastest useful report includes:

```bash
python3 -m airlock scan /path/to/skill --format json -o report.json --keep
```

Attach `report.json` (it contains the declared scope, the observed summary and
the coverage block) and say what you expected instead. If a rule is firing on
benign behaviour in the wild, we would rather narrow it or demote it to
`info` than leave it noisy — a scanner that cries wolf gets uninstalled in week
two.

## Style

- Python 3.9+ compatible: no `match`, no `X | Y` at runtime outside annotations
  (the modules use `from __future__ import annotations`).
- Comments explain *why*, especially where a workaround exists for a kernel or
  container quirk. Several of those workarounds look like mistakes and are not.
- Keep line length around 100. No formatter is enforced, but the existing files
  are consistent and reviewers will notice.

## Roadmap pointers

If you want something substantial to pick up, these are the open directions and
they are all welcome:

- **Landlock / seccomp-notify syscall filtering** as a second isolation layer
  (needs kernel ≥ 5.13; WSL2 qualifies).
- **MCP server mode** — run a server over stdio, enumerate its tools, and diff
  each tool's behaviour separately instead of one aggregate run.
- **`airlock verify`** — deterministic re-scan of a published version, plus a
  diff between two versions of the same skill name. The rug-pull case
  (`04` vs `05`) is currently two manual runs; it should be one command.
- **Registry-scale harness** for the ClawHub research dataset, so a
  1,000-skill report is reproducible by anyone.
- **Coverage improvements**: input fuzzing, multiple runs with different
  environment shapes, and delay-aware timeouts so time-gated payloads fire.

Open an issue before starting anything large so we can agree on the shape first.

## Code of conduct

Be direct about the work and kind to the person. Security research attracts
strong opinions; the argument that wins here is the one with a fixture and a
failing test attached.

## License

By contributing, you agree your contributions will be licensed under
**Apache-2.0**, the same as the project.
