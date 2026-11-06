"""Reproducible, dependency-free batch scans of an explicitly selected corpus."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def fingerprint(root):
    """Hash names and bytes; reject links rather than ingest files outside a skill."""
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlinks are not accepted in the corpus')
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def classify(report, returncode):
    """Classify coverage, not specimen success.

    A hostile specimen that crashes *after* attempting exfiltration is still an
    observation, and corpus-001 showed that requiring exit 0 moved exactly that
    class — CRLF-broken or failing payloads — out of the detection numerator.
    The specimen's exit code stays recorded in the report itself.
    """
    if returncode != 0 or report.get('verdict') == 'UNKNOWN':
        return 'failed'
    coverage = report.get('coverage', {})
    if coverage.get('static_only'):
        return 'static_only'
    if coverage.get('timed_out'):
        return 'timed_out'
    if not coverage.get('network_isolated'):
        return 'failed'
    return 'completed'


def summarize(records):
    counts = Counter(r['status'] for r in records)
    rules = {'completed': Counter(), 'static_only': Counter()}
    for record in records:
        if record['status'] in rules:
            rules[record['status']].update(set(record.get('rule_ids', [])))
    return {'total': len(records), 'statuses': dict(counts),
            'skills_per_rule': {k: dict(v) for k, v in rules.items()},
            'denominator_note': 'Rule counts are unique skills, separated by coverage. '
                                'Completed means exit 0, not proof of safety.'}


def run(manifest, output, timeout=30, static_only=False):
    from airlock.cli import _static_only_verdict, _verdict_json
    from airlock.declared import scan_tree
    manifest = Path(manifest).resolve()
    spec = json.loads(manifest.read_text(encoding='utf-8'))
    skills = spec['skills']
    ids = [s['id'] for s in skills]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate skill IDs')
    for item in skills:
        if not item.get('source') or not item.get('revision') or not item.get('files'):
            raise ValueError('each skill needs source, pinned revision and file SHA-256 hashes')
    output = Path(output).resolve()
    targets = [(manifest.parent / s['path']).resolve() for s in skills]
    if any(output == p or p in output.parents for p in targets):
        raise ValueError('output must be outside all skill directories')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'manifest.json').write_text(json.dumps(spec, indent=2), encoding='utf-8')
    records = []
    for index, (item, target) in enumerate(zip(skills, targets)):
        name = f'{index:04d}.json'
        record = {'id': item['id'], 'source': item['source'], 'revision': item['revision'],
                  'report': name, 'status': 'failed'}
        report = None
        try:
            if not target.is_dir() or target.is_symlink():
                raise ValueError('skill directory is missing or is a symlink')
            if fingerprint(target) != item['files']:
                raise ValueError('source hashes differ from pinned manifest')
            if static_only:
                report = _verdict_json(_static_only_verdict(scan_tree(target), item['id'],
                                      'Dataset requested declaration-only analysis'), item['id'])
                code = 0
            else:
                process = subprocess.run(
                    [sys.executable, '-m', 'airlock', 'scan', str(target), '--format', 'json',
                     '--fail-on', 'none', '--timeout', str(timeout)], cwd=ROOT,
                    capture_output=True, text=True, encoding='utf-8', errors='replace',
                    timeout=timeout + 150)
                code = process.returncode
                record['returncode'] = code
                if process.stderr:
                    record['stderr'] = process.stderr[:4000]
                report = json.loads(process.stdout)
            record['status'] = classify(report, code)
            record['rule_ids'] = sorted({f['rule_id'] for f in report['findings']})
        except Exception as exc:
            record['error'] = f'{type(exc).__name__}: {exc}'
        envelope = {'provenance': record, 'airlock_report': report}
        (output / name).write_text(json.dumps(envelope, indent=2), encoding='utf-8')
        records.append(record)
        (output / 'index.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
        (output / 'summary.json').write_text(json.dumps(summarize(records), indent=2), encoding='utf-8')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest')
    parser.add_argument('--output', required=True)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--static-only', action='store_true')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    records = run(args.manifest, args.output, args.timeout, args.static_only)
    print(json.dumps(summarize(records), indent=2))
    raise SystemExit(1 if any(r['status'] == 'failed' for r in records) else 0)
