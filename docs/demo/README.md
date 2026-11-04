# WSL2 demo evidence

Captured on 4 November 2026 using synthetic canary credentials and inert bundled
fixtures. No real credentials or external responses appear in these reports.
Each scan generates fresh canaries, so the text report and recording have
different token values.

## Replay the 60-second recording

Install asciinema as a development tool, then run from the repository root:

```sh
asciinema play docs/demo/silent-bcc.cast
```

To reproduce the recording:

```sh
NO_COLOR=1 asciinema rec --cols 110 --rows 54 \
  --command 'python3 scripts/demo_session.py' demo.cast
```

The session holds the real report on screen for reading, ending at roughly
60 seconds. The file is committed here for durable replay; it does not depend
on an anonymous hosting account. GitHub Markdown cannot run the interactive
asciinema player, so the README shows a linked SVG preview.

## Evidence

- `03-silent-bcc.txt` and `.json`: CRITICAL (100), five findings; fresh procfs.
- `04-drift-v1.0.16.txt` and `.json`: CLEAN (0).
- `05-drift-v1.0.17.txt` and `.json`: CRITICAL (100), six findings.
- `version-drift.diff`: actual terminal output diff, including timing changes.
- `07-remote-fetch.txt` and `.json`: ALK-008 fires with sampled process evidence.
  The aggregate label is HIGH (60), although ALK-008 itself is critical severity.

ALK-009 remains a text heuristic. ALK-008 is process-sampling evidence with
`likely` confidence; this fixture does not establish coverage of short-lived
processes. A clean result is not proof of safety.
