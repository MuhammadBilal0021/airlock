# Security policy

airlock is a security tool that executes untrusted code. That makes its own
security posture part of its product, so this file is specific rather than
boilerplate.

## Reporting a vulnerability

Email **`airlock-security@bilal.dev`** — or, if that address is not yet live,
open a GitHub Security Advisory on this repository (**Security → Report a
vulnerability → Private**). Please do not open a public issue for anything that
is not yet fixed.

Include:

- the airlock version and how it was installed (`pipx`, `git`, GitHub Action);
- `uname -a` and whether you are on bare Linux, WSL2, or inside a container;
- a minimal skill directory or script that reproduces the problem;
- what you expected airlock to do versus what it did.

We acknowledge reports within **72 hours** and aim to ship a fix or a documented
mitigation within **14 days** for anything that breaks the isolation guarantee,
and within **90 days** otherwise. Coordinated disclosure is welcome: tell us if
you want credit in the release notes and we will add it.

## What counts as a security bug here

The properties airlock claims, in priority order. Breaking any of these is a
vulnerability, not a feature request:

| # | guarantee | what breaking it means |
|---|---|---|
| 1 | **The scanned skill cannot reach the host filesystem.** Only the decoy home and a copy of the skill are bind-mounted into the namespace. | Any read or write of a path outside the run directory is critical. |
| 2 | **The scanned skill cannot reach the network.** The net namespace has loopback only; DNS is answered by the sinkhole. | Any packet leaving the host, or any real DNS resolution, is critical. |
| 3 | **airlock never runs a skill outside a namespace.** If `unshare` fails, it reports `UNKNOWN` and refuses. | Silent fallback to unsandboxed execution is critical. |
| 4 | **Decoy secrets are inert.** They are random canary strings that authenticate nothing. | A decoy that is a real, usable credential anywhere is high. |
| 5 | **Findings are not fabricated.** Every `confirmed` finding rests on an observed artefact. | A rule that reports exfiltration without a captured canary is high — false positives destroy the tool's value. |
| 6 | **No telemetry.** airlock makes no network call of its own, ever. | Any outbound connection from the scanner process itself is critical. |

## Known limitations (not vulnerabilities, but read them)

These are honest gaps, tracked in the README's *Limitations* section. They are
listed here too so a report about them can be closed quickly as by-design:

- **A clean run is not proof of safety.** Behaviour gated on a credential, a
  date, an environment variable, or an input the run did not supply will not
  fire. airlock reports coverage explicitly (`ALK-090` timeout, `ALK-091`
  limited `/proc`, `ALK-092` static-only, `ALK-093` sandbox failure) precisely so
  a clean result can be read with its blind spots attached.
- **`atime`-based read detection is heuristic.** It proves access, not intent, so
  `ALK-002` is marked `confidence: likely` rather than `confirmed`.
- **`ALK-008` (remote code fetch) needs a sampled process tree.** Inside nested
  containers where a fresh `procfs` mount is refused, that rule degrades and
  `ALK-091` says so.
- **`ALK-009` (embedded instructions) reads intent from text.** It is labelled
  `confidence: heuristic` and is expected to produce the occasional false
  positive on prose that merely mentions an attack. Suppressing those entirely
  would mean missing the real ones.
- **User namespaces are required.** On a kernel with
  `unprivileged_userns_clone=0` and no `CAP_SYS_ADMIN`, airlock exits with
  `UNKNOWN` rather than guessing.
- **Windows is supported through WSL2 only.** The native Windows build has no
  namespaces; `airlock` refuses to run there with an explicit message.

## Fixtures in this repository

Everything under `fixtures/` is an **inert test specimen**. The "malicious"
fixtures model real published attack patterns — credential harvesting, DNS
tunnelling, a version-to-version rug pull, persistence writes — but they contain
no working exploit, no live domain, and no real credential. Every address they
touch (`*.evil.test`, `*.attacker.test`, `postmark-analytics.test`) is in a
reserved TLD, and the secrets they steal are canary strings generated at runtime
that exist nowhere else. They are safe to read, safe to run inside the sandbox,
and safe to fork.

If you believe a fixture is dangerous rather than illustrative, that is itself a
security report — please send it through the channel above.

## Scope of testing

You may scan anything you are allowed to run, including your own skills and MCP
servers. Please do not point airlock at third-party code you have no right to
execute, and do not use it to attack a registry: the correct response to a
malicious published skill is a report to the registry and to us, not a scan of
someone else's infrastructure.

## Supported versions

| version | status |
|---|---|
| `0.1.x` | supported — current development line |
| anything older | unsupported; upgrade |

airlock is pre-1.0. Rule IDs (`ALK-001` … `ALK-093`) are treated as stable and
will not be renumbered; finding *wording*, scoring weights and report layout may
change between minor versions.
