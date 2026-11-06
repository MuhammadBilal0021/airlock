# Security policy

Airlock executes untrusted code to collect behavioral evidence. It is a
pre-1.0 research tool, not an independently audited isolation boundary. Run
untrusted specimens in a disposable Linux environment without valuable secrets.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/MuhammadBilal0021/airlock/security/advisories/new)
(Security → Report a vulnerability). The maintainer has selected this channel,
but the GitHub API reported it disabled on November 7, 2026. Enabling it remains
a release prerequisite. If the button is unavailable,
open an issue requesting a private contact **without vulnerability details,
exploit code, credentials or sensitive logs**. Do not disclose an unfixed
vulnerability in a public issue.

Include the revision, installation method, Linux/WSL environment, minimal
reproduction and expected versus observed behavior. Use synthetic data and
redact logs. Response and remediation times depend on maintainer availability;
no fixed response-time commitment is currently offered. Coordinated disclosure
and credit preferences are welcome.

## Intended boundaries and evidence

- The default specimen sees a copied target and synthetic home. Selected host
  runtime directories are bound recursively read-only/nosuid to provide binaries
  and libraries. These mounts are intended access, not a claim that no host
  filesystem content is visible. Arbitrary host access or mutation is a bug.
- The runner requires new user, mount, network and PID namespaces. Required setup
  failures abort execution. Network topology is checked for loopback only;
  observer readiness is checked separately. Neither check proves absence of all
  kernel-level escapes.
- Specimen capabilities are dropped and no_new_privs is set. Supervisor access,
  mount setup and selected escape attempts have regression tests. This is not an
  exhaustive adversarial audit, and namespaces share the host kernel.
- Per-process limits apply inside the runner. Aggregate memory/task/CPU limits
  and bounded writable storage require the bounded launcher and kernel support.
  Executable MCP calls require those verified gates. Ordinary CLI scans do not
  automatically enable the aggregate wrapper; inspect report coverage.
- Decoy credentials are synthetic, inert canaries. A real usable credential in
  a decoy would be a security bug. Confirmed findings must identify an observed
  artifact; static instruction matching remains heuristic.
- The core scanner has no telemetry. Research staging scripts explicitly fetch
  upstream source when invoked; that is separate from specimen execution.

## Coverage limitations

One run exercises one code path. A clean result is not proof of package safety.
A timed-out or failed run cannot establish full coverage. Reports expose setup
failure, static-only checks, missing process observations and collection limits.

Read detection uses access-time evidence, not complete syscall tracing. Process
sampling can miss short-lived activity. TLS bodies are not decrypted. Text
heuristics can miss attacks and flag benign prose; evaluation failures are
retained rather than treated as proof of safety. Filesystem metadata checks and
bounded collection can miss activity, with disclosed limitations.

Linux namespaces are required for execution; WSL2 is the Windows path. The MCP
server can answer declaration-only requests elsewhere, but cannot provide
Linux runtime assurance there. Hostile interference, kernel attack surface and
portability across hosts still need further review.

## Test fixtures

Fixtures model credential access, persistence writes, exfiltration attempts and
other behavior using synthetic inputs. They are source artifacts for review and
sandbox testing, not commands to run directly on a real home directory. Some
benign fixtures name real services; the sandbox redirects their traffic locally.
Malicious destinations use reserved test names. Do not describe a fixture as
harmless outside the controlled environment merely because it is a test.

## Supported development line

The active development line is 0.1.x. Use revision-specific validation evidence;
local working-tree results do not automatically apply to a published release.
Rule IDs are intended to remain stable, while wording, scoring and report layout
may change. Security corrections take priority over compatibility where needed.
