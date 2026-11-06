"""Prospective, frozen-rule evaluation; failures are results, not tuning prompts."""
import argparse
from collections import Counter
from dataclasses import asdict
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
from scripts.prepare_holdout import rule_hash
from scripts.scan_dataset import fingerprint


def prepare(package, name):
    def write(path, body):
        dest = package / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body)
    if name == 'security-ownership-map':
        write('_input/people.csv', 'person_id,name,email,touches,commit_count,sensitive_touches\n'
              'a,Alpha,alpha@example.test,3,1,0\nb,Beta,beta@example.test,12,4,2\n'
              'c,Gamma,gamma@example.test,7,2,1\n')
        entry = ['/usr/bin/python3', 'scripts/query_ownership.py', '--data-dir', '_input',
                 'people', '--min-touches', '5', '--limit', '1']
        purpose = 'Filter and sort synthetic ownership records; return only Beta with 12 touches'
    elif name == 'gh-fix-ci':
        write('_case.py', r'''import json, sys
sys.path.insert(0, '/work/scripts')
import inspect_pr_checks as specimen
log = 'setup ok\ncompile ok\nERROR: synthetic build failure\ncontext line\nfinished\n'
print(json.dumps({'failed': specimen.is_failing({'conclusion':'failure'}),
                  'passed': specimen.is_failing({'conclusion':'success'}),
                  'snippet': specimen.extract_failure_snippet(log, 3, 1)}))
''')
        entry = ['/usr/bin/python3', '_case.py']
        purpose = 'Classify synthetic check states and extract a bounded failure-log snippet; no GitHub API'
    else:
        write('_case.py', '''import importlib.util, io, json, sys, zipfile
from pathlib import Path
sys.path.insert(0, '/work/scripts')
spec = importlib.util.spec_from_file_location('specimen', '/work/scripts/install-skill-from-github.py')
module = importlib.util.module_from_spec(spec)
sys.modules['specimen'] = module
spec.loader.exec_module(module)
def archive(name):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z: z.writestr(name, 'synthetic')
    stream.seek(0)
    return zipfile.ZipFile(stream)
with archive('hello.txt') as z: module._safe_extract_zip(z, '/output/safe')
rejected = False
with archive('../escape.txt') as z:
    try: module._safe_extract_zip(z, '/output/unsafe')
    except module.InstallError: rejected = True
bad_path = False
try: module._validate_relative_path('../outside')
except module.InstallError: bad_path = True
print(json.dumps({'content': Path('/output/safe/hello.txt').read_text(),
                  'traversal_rejected': rejected, 'invalid_path_rejected': bad_path,
                  'escaped_file_exists': Path('/output/escape.txt').exists()}))
''')
        entry = ['/usr/bin/python3', '_case.py']
        purpose = 'Extract a safe synthetic ZIP and reject traversal ZIP/path inputs; no skill installation'
    if (package / '_case.py').exists():
        compile((package / '_case.py').read_text(), '_case.py', 'exec')
    return entry, purpose


def check_output(name, stdout):
    value = json.loads(stdout)
    if name == 'security-ownership-map':
        return len(value) == 1 and value[0]['person_id'] == 'b' and value[0]['touches'] == 12
    if name == 'gh-fix-ci':
        return value == {'failed': True, 'passed': False,
                         'snippet': 'compile ok\nERROR: synthetic build failure'}
    return value == {'content': 'synthetic', 'traversal_rejected': True,
                     'invalid_path_rejected': True, 'escaped_file_exists': False}


def evaluate_text(plan, directory):
    from airlock.declared import CapabilityDeclaration, find_embedded_instructions
    rows, counts = [], Counter()
    for case in plan['text_cases']:
        hits = find_embedded_instructions(CapabilityDeclaration(
            instruction_surface=[('synthetic:body', case['text'])]))
        observed = bool(hits)
        key = ('true_positive' if observed else 'false_negative') if case['expected_instruction'] else (
               'false_positive' if observed else 'true_negative')
        counts[key] += 1
        rows.append({**case, 'observed_instruction': observed, 'classification': key, 'hits': hits})
    (directory / 'text-results.json').write_text(json.dumps({'counts': dict(counts), 'cases': rows}, indent=2))
    return dict(counts)


def execute(directory):
    from airlock.bounded import verify_limits, DEFAULTS
    from airlock.storage import verify_storage
    from airlock.sandbox import run_skill, cleanup
    from airlock.declared import scan_tree
    from airlock.engine import analyse
    from airlock.cli import _verdict_json
    plan = json.loads((directory / 'plan.json').read_text())
    preflight = json.loads((directory / 'preflight.json').read_text())
    assert preflight['passed'] and rule_hash() == plan['rules_sha256']
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == preflight['harness_sha256']
    verify_limits(DEFAULTS)
    verify_storage(os.environ['AIRLOCK_STORAGE_ROOT'])
    counts = evaluate_text(plan, directory)
    source = ROOT / 'research/heldout-candidates'
    manifest = json.loads((source / 'manifest.json').read_text())
    rows = []
    for item in manifest['skills']:
        assert fingerprint(source / item['path']) == item['files']
        for repetition in (1, 2):
            with tempfile.TemporaryDirectory(prefix='airlock-holdout-') as tmp:
                package = Path(tmp) / 'package'
                shutil.copytree(source / item['path'], package)
                entry, purpose = prepare(package, item['id'])
                input_hashes = fingerprint(package)
                result = run_skill(package, entry=entry, timeout=10)
                try:
                    expected, error = False, None
                    if result.ok and result.exit_code == 0:
                        try: expected = check_output(item['id'], result.stdout)
                        except (ValueError, TypeError, KeyError) as exc: error = str(exc)
                    cov = result.meta.get('coverage', {})
                    controlled = cov.get('aggregate_resources', {}).get('verified') and cov.get('storage_limits', {}).get('verified')
                    completed = bool(result.ok and expected and controlled and not result.timed_out)
                    report = _verdict_json(analyse(result, scan_tree(package)), item['id'])
                    record = {'provenance': item, 'repetition': repetition, 'entry': entry,
                              'exercised': purpose, 'case_file_sha256': input_hashes,
                              'rules_sha256': rule_hash(), 'expected_output_confirmed': expected,
                              'validation_error': error, 'status': 'completed' if completed else 'failed',
                              'airlock_report': report,
                              'raw': {'stdout': result.stdout, 'stderr': result.stderr,
                                      'exit_code': result.exit_code, 'meta': result.meta,
                                      'errors': result.errors, 'network': result.net_events,
                                      'filesystem': [asdict(e) for e in result.fs_events]}}
                    (directory / (item['id'] + '-run' + str(repetition) + '.json')).write_text(json.dumps(record, indent=2))
                    rows.append({'id': item['id'], 'repetition': repetition, 'status': record['status'],
                                 'verdict': report['verdict'],
                                 'scored_rules': sorted({f['rule_id'] for f in report['findings'] if f['severity'] != 'info'})})
                finally:
                    cleanup(result.run_dir)
    assert rule_hash() == plan['rules_sha256']
    summary = {'rules_unchanged': True, 'text_confusion_counts': counts, 'real_helper_runs': rows,
               'limitations': ['Developer-authored labels, not independent annotation',
                              'Unused package directories from a previously used repository',
                              'Local helpers only, not full service workflows or prevalence estimates']}
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if all(r['status'] == 'completed' for r in rows) else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inner', action='store_true')
    parser.add_argument('--directory', type=Path, default=ROOT / 'research/heldout-001')
    args = parser.parse_args()
    directory = args.directory.resolve()
    plan = json.loads((directory / 'plan.json').read_text())
    assert rule_hash() == plan['rules_sha256'], 'scanner changed after freeze'
    if args.inner:
        return execute(directory)
    assert not (directory / 'preflight.json').exists(), 'do not overwrite prior evaluation'
    with (directory / 'preflight-tests.log').open('w') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(
            unittest.defaultTestLoader.discover(str(ROOT / 'tests')))
    passed = result.wasSuccessful() and not result.skipped and result.testsRun >= 63
    preflight = {'passed': passed, 'tests': result.testsRun, 'skipped': result.skipped,
                 'failures': len(result.failures), 'errors': len(result.errors),
                 'rules_sha256': rule_hash(), 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (directory / 'preflight.json').write_text(json.dumps(preflight, indent=2))
    if not passed: return 2
    from airlock.bounded import run_bounded
    launch = 'from airlock.storage import run_storage; import sys; sys.exit(run_storage(sys.argv[1:]))'
    return run_bounded([sys.executable, '-c', launch, sys.executable,
                        str(Path(__file__).resolve()), '--inner', '--directory', str(directory)], timeout=90)


if __name__ == '__main__':
    raise SystemExit(main())
