# Ten-package execution review

Ten distinct pinned skill directories completed two controlled helper invocations
each: **20/20 runs matched their expected functional result**. The fresh
containment preflight passed **55 tests, no skips**, in 40.854 seconds.
All repeated status, verdict and rule-ID sets agreed. This does not claim
identical process samples or exhaustive coverage of any package.

The raw scanner verdicts are **7 CLEAN, 1 ELEVATED, 1 HIGH, 1 CRITICAL**, counted
per package rather than per repeated run. Manual review finds ordinary expected
behaviour and contextual text matches behind the three non-CLEAN results; these
results do not establish malware. The original reports have not been relabeled
or changed to make the experiment look cleaner.

## Cases and interpretation

| Package | Function exercised and independently checked | Raw verdict | Interpretation / coverage limit |
| --- | --- | --- | --- |
| model-usage | Aggregate two days of synthetic costs; both model totals exactly 2.0 | CLEAN | No live CodexBar logs, account or external service exercised |
| skill-creator (OpenClaw) | Validate its pinned SKILL.md and directory; expected validation success | CLEAN | Validation helper only, not packaging or model-driven skill creation |
| figma-code-connect | Convert synthetic node ID in both directions; exact output checked | CLEAN | Small identifier helper; no Figma connection or actual code linking |
| figma-design-rules | Detect AGENTS.md absent, then present in a synthetic repo | ELEVATED | ALK-009 matches ordinary documentation language; no instruction execution observed |
| jupyter-notebook | Generate tutorial from bundled template; notebook schema, title and multiple cells checked | CLEAN | Notebook creation only; no kernel execution or visual review |
| plugin-creator | Normalize a name and create plugin/MCP manifests; generated JSON checked | CLEAN | Scaffold only, inside sandbox output; no installation or publication |
| anthropic-pdf | Accept nonoverlapping form boxes and reject an overlapping pair | CLEAN | JSON geometry validation only; no PDF rendering or form filling |
| anthropic-pptx | Duplicate a synthetic unpacked slide; verify new slide, unique IDs, relationships and content type | HIGH | Expected deck edits and bytecode cache plus a contextual text false positive; no rendered presentation |
| webapp-testing | Start isolated HTTP server and fetch exact synthetic body through its wrapper | CLEAN | No browser automation. Wrapper returned cleanup messages; sandbox teardown removes any remaining descendants |
| migrate-to-codex | Convert a synthetic Claude-style skill into a Codex skill file; output body checked | CRITICAL | Score consists solely of 14 Python bytecode-cache writes. No real user configuration was migrated |

## Findings requiring calibration

**ALK-009: two contextual false positives.** The design-rules package's normal
heading “Always Include” triggers an unconditional-side-effect heuristic. The
presentation documentation's phrase “silently ignored” describes incompatible
option names; it is not an instruction to hide an action. These matches are
static text findings, not observed model behaviour. The run did not give this
prose to a model.

**ALK-007: observations are real, but interpretation and scoring are excessive.**
The presentation case modified four synthetic deck files as requested and wrote
one Python cache file. The migration case wrote 14 Python cache files; their
repeated medium-severity contributions alone produced CRITICAL. The manifest
parser found no declared write permissions. That is not the same as an explicit
prohibition of writes, and these fixtures intentionally requested generated
output. A confirmed filesystem event does not confirm malicious intent.

Next scoring work should distinguish unavailable declarations from explicit
restrictions, classify ordinary interpreter cache writes without hiding the raw
events, and avoid inflating severity by counting many copies of one behaviour.
Any changes need benign controls and the existing malicious regression fixtures;
do not introduce package-name allowlists or simply suppress inconvenient reports.

## Containment and evidence audit

Every report records verified group limits of 768 MiB memory, no swap, 64 tasks,
one CPU quota, and temporary storage limits of 128 MiB / 4096 inodes, along with
fresh procfs, isolated networking and recursively read-only runtime mounts.
All 20 exits were zero; no run timed out or reported a collection-limit warning.
Saved package-file SHA-256 hashes match the staged pinned sources.

Raw network captures contain only the scanner's 20 `sinkhole_start` events.
This is **not** proof of no networking: the intentional local HTTP exchange on
port 18765 is outside the sinkhole's listed listener ports. Its successful body
check proves local networking occurred even though the capture did not record
it. No canary-exfiltration finding was produced in these scenarios.

Runtime versions are in [environment.json](environment.json). The automated
cross-report audit is [evidence-audit.json](evidence-audit.json); original results
are [summary.json](summary.json), the `*-run1.json` / `*-run2.json` envelopes,
[preflight.json](preflight.json), and [preflight-tests.log](preflight-tests.log).
Each envelope includes invocation, generated case hashes, original source
hashes, raw events, stdout/stderr, expected-output result, and implementation hash.

## Provenance and exclusions

- OpenClaw: `57c2077776745fe0f65881b24611afbb21a6a7de` — model-usage and skill-creator.
- OpenAI skills: `49f948faa9258a0c61caceaf225e179651397431` — two Figma helpers, notebook, plugin creator and migration.
- Anthropic skills: `ca45fc496a3436251f191354091d557da31c15b5` — PDF, PPTX and webapp testing.

Complete selected skill directories were downloaded and checked against their
pinned Git blob hashes. Scenario files are separate generated inputs, recorded
in `case_file_sha256`. Original staged files were not edited or installed.

Tmux remains staged but excluded: exercising active sessions would require a
terminal-device facility deliberately absent from this sandbox. PPTX slide
duplication was selected instead of its cleanup helper, whose XML dependency
was unavailable. No runtime dependencies were installed for this experiment.

This is a convenience sample selected for local executable helpers and available
runtimes. It is not a random registry sample, a prevalence estimate, a whole-skill
benchmark, or an independent security audit. The containment controls reduce
specific tested risks; broader adversarial interference and kernel attack
surface remain limitations. All project changes remain local and unmerged.
