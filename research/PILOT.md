# First real-skill pilot

50 OpenClaw bundled skill manifests were acquired from commit
`57c2077776745fe0f65881b24611afbb21a6a7de` and scanned in declaration-only mode.
The former `openclaw/skills` archive URL returned 404, so this pilot uses
`openclaw/openclaw`. It is not a ClawHub registry prevalence study.

Results: 50 declaration-only reports, zero failed reports, one skill with an
ALK-009 text-heuristic finding. ALK-092 appears in all 50 reports to disclose
the absence of dynamic analysis. No behavioural clean verdicts, exfiltration
measurements or malicious-skill counts are established by this pilot.

The frozen manifest in `manifest-sample/manifest.json` contains source URLs,
commit revision and per-file SHA-256 hashes. Selection takes the first 50
eligible paths ordered by SHA-256(path); this is a convenience sample.
Only SKILL.md files were collected, not full packages or supporting code.

Per-skill evidence is in `first-reports/0000.json` through `0049.json`.
`first-reports/index.json` maps those files to source identities, and
`first-reports/summary.json` contains the aggregate counts. Findings require
human review; a heuristic match is not a malware label.

Re-run without downloading or executing third-party code:

```sh
python scripts/scan_dataset.py research/manifest-sample/manifest.json --static-only --output research/reports-next
```

Next: acquire full version-pinned ClawHub packages and run behavioural analysis
in a validated isolated Linux environment, preserving coverage and failure counts.
