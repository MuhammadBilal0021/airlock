# Runner and observer repair — 6 November 2026

Restored one namespace-runner entry point after an overlapping local edit had
introduced a second `main()` with undefined setup variables. Removed the invalid
UDP/capture-size probe. A successful loopback exchange would not establish
isolation, and port 3128's sinkhole listener uses TCP.

The runner now waits on a private inherited pipe. The sinkhole signals only
after loopback setup and every required DNS/TCP bind succeed. A missing, invalid
or late readiness signal aborts before specimen launch and reaps the observer.
Network isolation is recorded separately, based on the mandatory new network
namespace and the kernel interface inventory containing only `lo`. This is
topology evidence, not an independent sandbox-escape audit. Both the readiness
flag and topology basis are exposed in JSON coverage.

MCP keeps the shared CLI scan path. Malformed initialize parameters return a
protocol error rather than killing the stream; nonfinite timeouts are refused.
Executable MCP requests additionally require verified cgroup and bounded-tmpfs
gates, including checking that scanner temporary files use that tmpfs. Direct
unbounded serving can still perform declaration-only checks. The README shows
the bounded server launcher and its explicit session deadline.

Validation:

- `python3 -m unittest discover -s tests -v`: **89 passed, zero skips**, 37.493s
  in Ubuntu/WSL. Includes actual weather DNS observations on three repeated runs,
  a delayed readiness signal beyond the old 0.6-second sleep, bind failures,
  invalid/missing signals, extra-interface refusal, and existing malicious and
  containment fixtures.
- `python3 scripts/validate_mcp_execution.py`: real stdio initialize/scan/ping
  succeeded through the bounded launcher. CLEAN weather report, expected domain,
  readiness, aggregate limits and tmpfs verification were checked. Raw protocol
  output is preserved in [mcp-execution.json](mcp-execution.json).

The fixed startup race is a plausible cause of the earlier missing weather
observation, not a retrospectively proven cause. This validation does not claim
that all possible observer-interference races are eliminated. Detector patterns
were not changed in this repair, and prior frozen evaluation artifacts remain
unchanged. No remote commit, release or merge was performed.
