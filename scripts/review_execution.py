"""Audit saved execution evidence without importing or re-running specimens."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    summary = json.loads((directory / 'summary.json').read_text())
    preflight = json.loads((directory / 'preflight.json').read_text())
    assert preflight['passed'] and not preflight['skipped']
    records = [json.loads(p.read_text()) for p in sorted(directory.glob('*-run*.json'))]
    assert len(records) == 20
    verdicts = Counter()
    rules = Counter()
    network = Counter()
    for record in records:
        assert record['status'] == 'completed' and record['expected_output_confirmed']
        assert record['implementation_sha256'] == preflight['implementation_sha256']
        assert record['raw']['exit_code'] == 0
        cov = record['airlock_report']['coverage']
        assert cov['aggregate_resources']['verified'] and cov['storage_limits']['verified']
        assert cov['proc'] == 'fresh-procfs' and not cov['timed_out']
        assert not [e for e in record['raw']['errors'] if not e.startswith('namespace flags:')]
        assert not any(e['truncated'] for e in record['raw']['filesystem'])
        original = directory.parent / 'executable-candidates' / record['provenance']['path']
        for name, expected in record['provenance']['files'].items():
            assert hashlib.sha256((original / name).read_bytes()).hexdigest() == expected
        network.update(e.get('type', 'unknown') for e in record['raw']['network'])
        if record['repetition'] == 1:
            verdicts[record['airlock_report']['verdict']] += 1
            rules.update(set(f['rule_id'] for f in record['airlock_report']['findings']))
    assert summary['completed_count'] == 10 and all(summary['repeat_agreement'].values())
    audit = {'checked_runs': len(records), 'unique_packages': 10,
             'preflight_tests': preflight['tests'], 'verdict_counts_per_package': dict(verdicts),
             'packages_per_rule': dict(rules), 'raw_network_event_types': dict(network),
             'source_hashes_match': True, 'all_expected_outputs_confirmed': True,
             'all_resource_controls_verified': True, 'collection_limit_warnings': 0,
             'status_verdict_rule_sets_agree_across_repeats': True,
             'not_claimed': ['identical sampled process traces', 'full package workflow coverage',
                             'malware prevalence', 'proof packages are safe']}
    (directory / 'evidence-audit.json').write_text(json.dumps(audit, indent=2))
    environment = {'scanner_python': sys.version, 'kernel': platform.release(),
                   'platform': platform.platform(), 'machine': platform.machine()}
    for name, command in [('specimen_python', ['/usr/bin/python3', '--version']),
                          ('util_linux', ['unshare', '--version']),
                          ('systemd', ['systemctl', '--version'])]:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        environment[name] = result.stdout.splitlines()[0] if result.stdout else result.stderr.strip()
    (directory / 'environment.json').write_text(json.dumps(environment, indent=2))
    print(json.dumps(audit, indent=2))


if __name__ == '__main__':
    main()
