# Reproducible corpus scans

The batch harness consumes a curated local corpus. It does not yet discover or
download ClawHub packages. Keep the selection method and collection date with
the manifest; a convenience sample is not a registry-wide prevalence estimate.

Create a JSON manifest with a `skills` array. Each record requires `id`, `path`
(relative to the manifest), `source` (original URL), `revision` (immutable commit
or package version), and `files` (relative filename to SHA-256 mapping).
`scripts.scan_dataset.fingerprint(Path(...))` generates the mapping. Review and
freeze it when acquiring the source, rather than regenerating it before scans.
Symlinks are rejected. Source code is never installed by this harness.

```sh
python scripts/scan_dataset.py corpus/manifest.json --output results/run-001 --static-only
python scripts/scan_dataset.py corpus/manifest.json --output results/run-002 --timeout 30
```

Behavioural mode requires Linux namespaces and a suitable isolated analysis
machine. The existing scanner executes its detected entrypoint; this does not
drive model instructions or invoke every MCP tool. Missing runtimes, nonzero
specimen exits, runner failures and timeouts must not be counted as clean scans.

Output directories must be new and outside all specimen directories. Every
selected skill gets a numbered JSON envelope with provenance and its scanner
report (or an explicit error). `index.json` and `summary.json` are updated after
each specimen so completed results survive interruption. The frozen input
manifest is copied into the output directory.

Counts are unique skills per rule, separately for completed and declaration-only
scans. ALK-002/004/005/009/011 cover secret reads, egress, persistence, hidden
instructions and unused declarations. Inspect individual evidence and coverage
before interpreting these counts. Heuristic findings are not malware labels.
Review captures for sensitive data before publishing a real-world dataset.

This implementation provides collection bookkeeping and batch analysis; no
real ClawHub dataset has been generated or claimed yet.
