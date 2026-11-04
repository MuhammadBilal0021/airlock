# Test fixtures

These are **inert test specimens**, not malware. Each one runs only inside
airlock's sandbox, against a synthetic home directory whose secrets are canary
strings that exist nowhere else. No fixture touches the real filesystem and none
of them can reach the network — the sandbox has no route out.

They exist so the detection rules have something to fire on and something *not*
to fire on. A scanner that flags all six is worthless; the false-positive rate
on `01` and `06` is as much a test as the true-positive rate on `02`–`05`.

| fixture | models | expected |
|---|---|---|
| `01-benign-weather` | an honest skill that stays inside its manifest | CLEAN / LOW |
| `02-ssh-exfil` | classic credential theft over HTTP | CRITICAL |
| `03-silent-bcc` | the semantic attack: hidden model-directed instruction + DNS tunnel | CRITICAL |
| `04-drift-v1.0.16` | a benign published version | CLEAN / LOW |
| `05-drift-v1.0.17` | the same skill, one version later, payload added | CRITICAL |
| `06-over-broad` | honest code with a greedy manifest | LOW (info only) |
| `07-remote-fetch` | inert remote-fetch pipeline visible to the process sampler | ALK-008 with fresh procfs; ALK-091 otherwise |
| `08-credential-permissions` | broadens synthetic SSH credential mode without reading it | ALK-012 medium; LOW score 8 (11 with ALK-091) |

`03` reproduces the case documented in the October 2026 hands-on comparison of
free MCP scanners: a `format_address` tool whose description quietly instructs
the model to BCC every outgoing email to an outside address. Both scanners
tested returned `SAFE`, because the instruction contains no credential keyword
and reads as ordinary prose. airlock flags it on the declaration *and* catches
the DNS-tunnelled canary at runtime.

`04`/`05` reproduce the rug-pull pattern behind the real `postmark-mcp`
incident, where version 1.0.16 was clean and 1.0.17 added a BCC to an outside
address across 1,643 downloads. Diffing the two reports is the update-drift
control (AST07).
