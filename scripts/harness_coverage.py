"""Synthesise invocation harnesses for real skills and measure behavioural coverage.

Implements research/corpus-003/PREREGISTRATION.md exactly: the frozen harness
rule, the corrected denominator (packages that ship code), and per-package
outcome recording.

This is the coverage engine in its deterministic form. The harness choice is a
frozen, reviewable artefact -- no model decides the verdict, and the same rule
produces the same harness on every run.

    python3 scripts/harness_coverage.py \
        --manifest research/corpus-001/benign/manifest.json \
        --output research/corpus-003/results/harness-coverage.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from airlock.declared import scan_tree  # noqa: E402
from airlock.engine import analyse  # noqa: E402
from airlock.sandbox import run_skill  # noqa: E402

CODE_SUFFIXES = ('.py', '.sh', '.js')
# Absolute paths only: the sandbox executes the entry directly rather than
# through a shell, so a bare `node` is not resolved against PATH (corpus-004
# measured exit 127 for it while /usr/local/bin/node returned 0).
INTERPRETER = {'.py': '/usr/bin/python3', '.sh': '/bin/sh',
               '.js': '/usr/local/bin/node'}
ENTRY_STEMS = ('main', 'run', 'cli', 'entry', 'entrypoint', 'start', 'install',
               'setup', 'server')
DISCLOSURE_RULES = {'ALK-090', 'ALK-091', 'ALK-092', 'ALK-093'}
POSITIVE_SEVERITIES = {'critical', 'high', 'medium'}
DOCUMENTED = re.compile(
    r'(?:python3?|bash|sh|node)\s+([\w./-]+\.(?:py|sh|js))', re.IGNORECASE)


def code_files(package: Path):
    found = []
    for path in package.rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix not in CODE_SUFFIXES:
            continue
        relative = path.relative_to(package)
        if any(part.startswith('.') or part == 'node_modules' for part in relative.parts):
            continue
        if path.name == '__init__.py' or path.stem.startswith('test_') \
                or path.stem.endswith('_test'):
            continue
        found.append(relative)
    return sorted(found)


def choose(package: Path, files):
    """Frozen harness rule: documented, then single, then priority artefact."""
    skill_md = package / 'SKILL.md'
    if skill_md.exists():
        text = skill_md.read_text(encoding='utf-8', errors='replace')
        for match in DOCUMENTED.finditer(text):
            candidate = package / match.group(1)
            if candidate.is_file() and candidate.suffix in CODE_SUFFIXES:
                return candidate.relative_to(package), 'documented'
    if len(files) == 1:
        return files[0], 'single_artefact'
    def priority(relative: Path):
        return (relative.stem not in ENTRY_STEMS, len(relative.parts),
                relative.as_posix())
    return sorted(files, key=priority)[0], 'priority_artefact'


KNOWN_SHEBANG = {'node': '/usr/local/bin/node', 'bash': '/bin/bash',
                 'sh': '/bin/sh', 'python3': '/usr/bin/python3',
                 'python': '/usr/bin/python3'}


def shebang_argv(first_line: str):
    """Resolve a shebang to (program, leading arguments).

    Handles ``#!/bin/bash``, ``#!/usr/bin/env bash`` and
    ``#!/usr/bin/env -S node --flag``. corpus-004 caught the last two being run
    as ``/usr/bin/env script``, which the kernel refuses ("use -[v]S to pass
    options in shebang lines") -- a harness bug that looked like a broken skill.
    """
    tokens = first_line[2:].strip().split()
    if not tokens:
        return None, []
    if tokens[0].rsplit('/', 1)[-1] == 'env':
        rest = [token for token in tokens[1:] if not token.startswith('-')]
        if not rest:
            return None, []
        return KNOWN_SHEBANG.get(rest[0], rest[0]), rest[1:]
    return tokens[0], tokens[1:]


def entry_argv(package: Path, relative: Path):
    """Build the argv, honouring a shebang when the author wrote one.

    corpus-004 found a package whose ``run.sh`` uses bash syntax; running it
    under ``/bin/sh`` produced "Syntax error: unexpected word" and looked like a
    broken skill. It was a broken harness: the package declared its own
    interpreter and the harness ignored it.
    """
    interpreter = INTERPRETER[relative.suffix]
    leading = []
    try:
        first_line = (package / relative).read_text(
            encoding='utf-8', errors='replace').splitlines()[0]
        if first_line.startswith('#!'):
            resolved, leading = shebang_argv(first_line)
            if resolved:
                interpreter = resolved
    except (IndexError, OSError):
        leading = []
    argv = [interpreter, *leading, relative.as_posix()]
    if relative.suffix in ('.py', '.js'):
        argv.append('--help')
    return argv


def positive_findings(verdict):
    return [finding for finding in verdict.findings
            if finding.severity in POSITIVE_SEVERITIES
            and finding.rule_id not in DISCLOSURE_RULES]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    spec = json.loads(manifest_path.read_text(encoding='utf-8'))
    corpus = manifest_path.parent

    rows = []
    for item in spec['skills']:
        package = corpus / item['path']
        files = code_files(package)
        if not files:
            rows.append({'id': item['id'], 'addressable': False,
                         'status': 'no_code'})
            continue
        relative, why = choose(package, files)
        argv = entry_argv(package, relative)
        row = {'id': item['id'], 'addressable': True, 'harness': ' '.join(argv),
               'harness_source': why, 'code_files': len(files)}
        try:
            # Call the same primitives run_target() uses, but keep the RunResult:
            # the specimen's stderr is what distinguishes "missing dependency"
            # from "no input document provided". Without it, twelve exit-1
            # packages are indistinguishable and the next work item is a guess.
            declaration = scan_tree(package)
            result = run_skill(package, entry=list(argv), timeout=args.timeout)
            verdict = analyse(result, declaration)
            observed = verdict.observed_summary or {}
            coverage = verdict.coverage or {}
            positives = positive_findings(verdict)
            row.update({
                'status': 'launched',
                'verdict': verdict.label,
                'exit_code': observed.get('exit_code'),
                'timed_out': bool(coverage.get('timed_out')),
                'duration_s': round(float(coverage.get('duration_s') or 0.0), 3),
                'positive': bool(positives),
                'rules': sorted({f.rule_id for f in positives}),
                'severities': sorted({f.severity for f in positives}),
                'stderr': (result.stderr or '')[:1500],
                'stdout': (result.stdout or '')[:600],
                'runner_errors': list(result.errors or [])[:5],
            })
        except Exception as exc:  # noqa: BLE001 - recorded, never lost
            row.update({'status': 'unreachable',
                        'error': f'{type(exc).__name__}: {exc}',
                        'trace': traceback.format_exc(limit=2)})
        rows.append(row)
        state = row['status'] + ('' if row.get('timed_out') is not True else ' (timeout)')
        print(f"{row['id']}: {state} harness={row['harness']}", flush=True)

    addressable = [r for r in rows if r['addressable']]
    launched = [r for r in addressable if r['status'] == 'launched']
    timed_out = [r for r in launched if r.get('timed_out')]
    clean = [r for r in launched if r.get('exit_code') == 0 and not r.get('timed_out')]
    positives = [r for r in launched if r.get('positive')]
    summary = {
        'corpus': str(manifest_path),
        'total_packages': len(rows),
        'addressable': len(addressable),
        'no_code': len(rows) - len(addressable),
        'launched': len(launched),
        'coverage_of_addressable': (len(launched) / len(addressable)
                                    if addressable else None),
        'clean_start': len(clean),
        'clean_of_launched': len(clean) / len(launched) if launched else None,
        'timed_out': len(timed_out),
        'positives': len(positives),
        'positive_ids': [r['id'] for r in positives],
        'harness_sources': {source: sum(1 for r in addressable
                                        if r.get('harness_source') == source)
                            for source in ('documented', 'single_artefact',
                                           'priority_artefact')},
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'summary': summary, 'rows': rows}, indent=2),
                      encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
