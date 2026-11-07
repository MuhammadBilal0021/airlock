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
import hashlib
import json
import math
import os
import re
import shlex
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from airlock.declared import scan_tree  # noqa: E402
from airlock.engine import analyse  # noqa: E402
from airlock.sandbox import run_skill  # noqa: E402
from scripts.scan_dataset import fingerprint  # noqa: E402
from airlock.bounded import verify_limits, DEFAULTS  # noqa: E402
from airlock.storage import verify_storage  # noqa: E402

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
                relative = candidate.resolve().relative_to(package.resolve())
                if relative in files:
                    return relative, 'documented'
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
    tokens = shlex.split(first_line[2:].strip())
    if not tokens:
        return None, []
    if tokens[0].rsplit('/', 1)[-1] == 'env':
        rest = tokens[1:]
        if rest and rest[0] in ('-S', '--split-string'):
            rest = rest[1:]
        if rest and rest[0] == '--':
            rest = rest[1:]
        if not rest:
            return None, []
        if rest[0] not in KNOWN_SHEBANG:
            raise ValueError('unsupported env shebang: ' + first_line)
        return KNOWN_SHEBANG[rest[0]], rest[1:]
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


def preflight_limits():
    """Verify the aggregate and storage limits the bounded path establishes.

    corpus-003/004 reports presented behavioural coverage while both limits were
    unverified. The harness may not silently inherit that weakness: it must try
    to verify, record the result, and let the summary say "degraded" when the
    host cannot provide them. Namespace isolation is separate and still applies.
    """
    limits = {'aggregate_limits': False, 'storage_limits': False}
    try:
        limits['aggregate_limits_detail'] = str(verify_limits(DEFAULTS))
        limits['aggregate_limits'] = True
    except Exception as exc:  # noqa: BLE001 - recorded, not fatal
        limits['aggregate_limits_detail'] = f'unavailable: {exc}'[:240]
    storage_root = os.environ.get('AIRLOCK_STORAGE_ROOT')
    if not storage_root:
        limits['storage_limits_detail'] = 'AIRLOCK_STORAGE_ROOT not set'
    else:
        try:
            limits['storage_limits_detail'] = str(verify_storage(storage_root))
            limits['storage_limits'] = True
        except Exception as exc:  # noqa: BLE001
            limits['storage_limits_detail'] = f'unavailable: {exc}'[:240]
    limits['degraded'] = not limits['aggregate_limits']
    return limits


def classify_run(result, verdict):
    """Separate established execution from a merely attempted one.

    coverage must not count a failed sandbox setup as a successful launch: a
    runner that returns UNKNOWN (ALK-093) produced no behavioural assurance even
    though a process started.
    """
    has_alk_093 = any(finding.rule_id == 'ALK-093' for finding in verdict.findings)
    if not result.ok or verdict.label == 'UNKNOWN' or has_alk_093:
        return 'setup_failed'
    return 'established'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    spec = json.loads(manifest_path.read_text(encoding='utf-8'))
    corpus = manifest_path.parent
    limits = preflight_limits()

    rows = []
    for item in spec['skills']:
        package = corpus / item['path']
        files = code_files(package)
        if not files:
            rows.append({'id': item['id'], 'addressable': False,
                         'status': 'no_code'})
            continue
        # The corpus is pinned by per-file SHA-256. A run against changed bytes
        # is not a run against the frozen corpus and must not count as coverage.
        try:
            if fingerprint(package) != item['files']:
                rows.append({'id': item['id'], 'addressable': True,
                             'status': 'hash_mismatch'})
                continue
        except Exception as exc:  # noqa: BLE001
            rows.append({'id': item['id'], 'addressable': True,
                         'status': 'hash_mismatch', 'error': str(exc)[:240]})
            continue
        relative, why = choose(package, files)
        argv = entry_argv(package, relative)
        row = {'id': item['id'], 'addressable': True, 'harness': ' '.join(argv),
               'harness_source': why, 'code_files': len(files),
               'aggregate_limits_verified': limits['aggregate_limits'],
               'storage_limits_verified': limits['storage_limits']}
        try:
            # Call the same primitives run_target() uses, but keep the RunResult:
            # the specimen's stderr is what distinguishes "missing dependency"
            # from "no input document provided".
            declaration = scan_tree(package)
            result = run_skill(package, entry=list(argv), timeout=args.timeout)
            verdict = analyse(result, declaration)
            observed = verdict.observed_summary or {}
            coverage = verdict.coverage or {}
            positives = positive_findings(verdict) if result.ok else []
            row.update({
                'status': classify_run(result, verdict),
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
    established = [r for r in addressable if r['status'] == 'established']
    timed_out = [r for r in established if r.get('timed_out')]
    clean = [r for r in established
             if r.get('exit_code') == 0 and not r.get('timed_out')]
    positives = [r for r in established if r.get('positive')]
    setup_failed = sum(1 for r in addressable
                       if r['status'] in ('setup_failed', 'unreachable'))
    attempted = len(established) + setup_failed
    summary = {
        'corpus': str(manifest_path),
        'total_packages': len(rows),
        'addressable': len(addressable),
        'no_code': len(rows) - len(addressable),
        'hash_verified': sum(1 for r in addressable
                             if r['status'] != 'hash_mismatch'),
        'hash_mismatch': sum(1 for r in addressable
                             if r['status'] == 'hash_mismatch'),
        'established': len(established),
        'setup_failed': setup_failed,
        'coverage_of_addressable': (len(established) / len(addressable)
                                    if addressable else None),
        'attempted_of_addressable': (attempted / len(addressable)
                                     if addressable else None),
        'clean_start': len(clean),
        'clean_of_established': len(clean) / len(established) if established else None,
        'timed_out': len(timed_out),
        'positives': len(positives),
        'positive_ids': [r['id'] for r in positives],
        'harness_sources': {source: sum(1 for r in addressable
                                        if r.get('harness_source') == source)
                            for source in ('documented', 'single_artefact',
                                           'priority_artefact')},
        'limits': limits,
        'degraded': limits['degraded'],
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'summary': summary, 'rows': rows}, indent=2),
                      encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
