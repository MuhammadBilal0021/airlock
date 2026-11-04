# Local verification — 4 November 2026

Baseline checked in Ubuntu on WSL2 from `/mnt/d/Bilal_projects/airlock`,
before changing implementation code.

- Full user/mount/network/PID namespace probe: passed.
- `python3 -m unittest discover -s tests -v`: 19 tests passed (10.683 seconds).
- `python3 -m airlock --version`: `airlock 0.1.0`.
- JSON, Markdown and SARIF benign scans: emitted successfully, exit 0.
- Benign `--fail-on medium`: exit 0.
- Version 1.0.17 `--fail-on critical`: exit 1.
- Policy generation: succeeded; observed `/home/notes.md` and `api.weather.gov`.

| Fixture | Handoff score / findings | Local score / findings |
|---|---|---|
| 01-benign-weather | LOW 3 / 1 | CLEAN 0 / 0 |
| 02-ssh-exfil | CRITICAL 100 / 15 | CRITICAL 100 / 14 |
| 03-silent-bcc | CRITICAL 100 / 6 | CRITICAL 100 / 6 |
| 04-drift-v1.0.16 | LOW 3 / 1 | CLEAN 0 / 0 |
| 05-drift-v1.0.17 | CRITICAL 100 / 7 | CRITICAL 100 / 7 |
| 06-over-broad | LOW 3 / 6 | CLEAN 0 / 5 |

Fresh procfs and process sampling work on this WSL2 machine; ALK-091 disappears.
ALK-008 has process data available, but its detection has not yet been exercised
by a dedicated remote-fetch fixture. Availability is not a detection test.

## Discrepancies requiring follow-up

- On this Windows-backed filesystem, the declaration parser loads `SKILL.md`
  again as `skill.md`. Fixtures 03 and 05 therefore gain a duplicate ALK-009
  while losing ALK-091. Their unchanged finding counts hide this difference.
- Process sampling includes airlock's namespace init and sinkhole, not just the
  specimen. Policy generation sets `shell: true` whenever any process is seen.
- Source inspection: `run_skill()` breaks after a nonzero `unshare` result and
  returns `ok=True` even without successful runner metadata. This contradicts
  the handoff's UNKNOWN/ALK-093 guarantee. No unsandboxed execution was observed.
- Source inspection: CI accepts any nonzero malicious-scan exit, including
  scanner errors, instead of requiring findings exit code 1.

These baseline results do not validate resistance to sandbox escape or justify
running arbitrary real-world specimens. No real registry skills were run.
