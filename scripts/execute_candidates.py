"""Run pinned real-skill cases only after fresh, no-skip containment tests.

Source packages are data until the bounded specimen entrypoint executes them.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def implementation_hash():
    paths = sorted(list((ROOT / 'airlock').glob('*.py')) +
                   list((ROOT / 'tests').glob('test_*.py')) + [Path(__file__), ROOT / 'scripts/package_cases.py'])
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + path.read_bytes())
    return digest.hexdigest()


def execute(output, repeats):
    from scripts.package_cases import IDS, prepare, validate
    from airlock.bounded import verify_limits, DEFAULTS
    from airlock.storage import verify_storage
    from airlock.sandbox import run_skill, cleanup
    from airlock.declared import scan_tree
    from airlock.engine import analyse
    from airlock.cli import _verdict_json
    from scripts.scan_dataset import fingerprint
    preflight = json.loads((output / 'preflight.json').read_text())
    if not preflight['passed'] or preflight['implementation_sha256'] != implementation_hash():
        raise RuntimeError('preflight is missing, failed or stale for this implementation')
    verify_limits(DEFAULTS)
    verify_storage(os.environ['AIRLOCK_STORAGE_ROOT'])
    source = ROOT / 'research/executable-candidates'
    manifest = json.loads((source / 'manifest.json').read_text())
    records = []
    for item, repetition in ((s, r) for s in manifest['skills'] for r in range(1, repeats + 1)):
        if item['id'] not in IDS | {'model-usage', 'skill-creator'}:
            continue
        original = source / item['path']
        if fingerprint(original) != item['files']:
            raise RuntimeError('pinned package hash mismatch: ' + item['id'])
        with tempfile.TemporaryDirectory(prefix='airlock-case-') as tmp:
            package = Path(tmp) / 'package'
            shutil.copytree(original, package)
            scenario = None
            if item['id'] == 'model-usage':
                scenario = {'daily': [
                    {'date': '2026-01-01', 'modelBreakdowns': [
                        {'modelName': 'synthetic-a', 'cost': 1.25},
                        {'modelName': 'synthetic-b', 'cost': 2}]},
                    {'date': '2026-01-02', 'modelBreakdowns': [
                        {'modelName': 'synthetic-a', 'cost': '0.75'}]}]}
                (package / 'airlock-synthetic-input.json').write_text(json.dumps(scenario))
                entry = ['/usr/bin/python3', 'scripts/model_usage.py', '--input',
                         'airlock-synthetic-input.json', '--mode', 'all', '--format', 'json']
                purpose = 'Aggregate synthetic local costs for two models across two days'
            elif item['id'] == 'skill-creator':
                entry = ['/usr/bin/python3', 'scripts/quick_validate.py', '.']
                purpose = 'Validate the complete pinned skill directory and its SKILL.md'
            else:
                entry, purpose, scenario = prepare(package, item['id'])
            case_hashes = fingerprint(package)
            result = run_skill(package, entry=entry, timeout=10)
            try:
                cov = result.meta.get('coverage', {})
                controls = (cov.get('storage_limits', {}).get('verified') and
                            cov.get('aggregate_resources', {}).get('verified') and
                            cov.get('proc') == 'fresh-procfs')
                expected = False
                validation_error = None
                if result.ok and result.exit_code == 0:
                    try:
                        if item['id'] == 'model-usage':
                            parsed = json.loads(result.stdout)
                            expected = {m['model']: m['totalCostUSD'] for m in parsed['models']} == {
                                'synthetic-a': 2.0, 'synthetic-b': 2.0}
                        elif item['id'] == 'skill-creator':
                            expected = 'Skill is valid!' in result.stdout
                        else:
                            expected = validate(item['id'], result)
                    except (KeyError, ValueError, TypeError) as exc:
                        validation_error = str(exc)
                completed = bool(result.ok and not result.timed_out and controls and expected)
                verdict = _verdict_json(analyse(result, scan_tree(package)), item['id'])
                envelope = {
                    'status': 'completed' if completed else 'failed',
                    'provenance': item, 'entry': entry, 'scenario': scenario,
                    'repetition': repetition, 'case_file_sha256': case_hashes,
                    'validation_error': validation_error,
                    'exercised': purpose, 'expected_output_confirmed': expected,
                    'implementation_sha256': preflight['implementation_sha256'],
                    'limitations': ['Scoped helper invocation, not exhaustive behaviour or a safety certification',
                                    'No live accounts, external APIs, full GUI workflows or integrations exercised'],
                    'airlock_report': verdict,
                    'raw': {'stdout': result.stdout, 'stderr': result.stderr,
                            'exit_code': result.exit_code, 'meta': result.meta,
                            'errors': result.errors, 'network': result.net_events,
                            'filesystem': [asdict(event) for event in result.fs_events]}}
                (output / (item['id'] + '-run' + str(repetition) + '.json')).write_text(json.dumps(envelope, indent=2))
                records.append({'id': item['id'], 'status': envelope['status'],
                                'repetition': repetition, 'verdict': verdict['verdict'],
                                'rule_ids': sorted({f['rule_id'] for f in verdict['findings']}),
                                'expected_output_confirmed': expected})
            finally:
                cleanup(result.run_dir)
    completed = sorted({r['id'] for r in records if all(
        x['status'] == 'completed' for x in records if x['id'] == r['id'])})
    repeatable = {name: len({(r['status'], r['verdict'], tuple(r['rule_ids']))
                            for r in records if r['id'] == name}) == 1
                  for name in sorted({r['id'] for r in records})}
    (output / 'summary.json').write_text(json.dumps({'cases': records,
        'completed_packages': completed, 'completed_count': len(completed),
        'repeat_agreement': repeatable, 'repetitions': repeats,
        'staged_not_run': ['tmux'], 'scope': 'controlled real skill helper invocations'}, indent=2))
    print(json.dumps(records))
    return 0 if records and all(r['status'] == 'completed' for r in records) else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--inner', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--repeats', type=int, default=2, choices=(1, 2))
    args = parser.parse_args()
    output = args.output.resolve()
    if args.inner:
        return execute(output, args.repeats)
    output.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    with (output / 'preflight-tests.log').open('w') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    passed = result.wasSuccessful() and not result.skipped and result.testsRun >= 55
    preflight = {'passed': passed, 'tests': result.testsRun, 'skipped': result.skipped,
                 'failures': len(result.failures), 'errors': len(result.errors),
                 'implementation_sha256': implementation_hash(),
                 'time_utc': datetime.now(timezone.utc).isoformat()}
    (output / 'preflight.json').write_text(json.dumps(preflight, indent=2))
    if not passed:
        print('Execution refused: preflight failed; see ' + str(output / 'preflight-tests.log'))
        return 2
    from airlock.bounded import run_bounded
    launch = ('from airlock.storage import run_storage; import sys; '
              'sys.exit(run_storage(sys.argv[1:]))')
    command = [sys.executable, '-c', launch, sys.executable, str(Path(__file__).resolve()),
               '--inner', '--output', str(output), '--repeats', str(args.repeats)]
    return run_bounded(command, timeout=180)


if __name__ == '__main__':
    raise SystemExit(main())
