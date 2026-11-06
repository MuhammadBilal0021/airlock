"""Exercise the real stdio MCP path under verified aggregate/storage bounds."""
import json
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'research/observer-readiness-001')
    directory = parser.parse_args().output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / 'mcp-execution.json'
    if output.exists():
        raise SystemExit('Refusing to overwrite previous execution evidence')
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {
            'name': 'scan_skill', 'arguments': {'target': str(ROOT / 'fixtures/01-benign-weather'), 'timeout': 15}}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'ping'},
    ]
    process = subprocess.run([sys.executable, '-m', 'airlock.bounded', '--wall-timeout', '60', 'serve'],
                             input=''.join(json.dumps(m) + '\n' for m in messages),
                             capture_output=True, text=True, cwd=ROOT, timeout=75)
    record = {'exit_code': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr}
    output.write_text(json.dumps(record, indent=2))
    assert process.returncode == 0, record
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert [r['id'] for r in responses] == [1, 2, 3]
    assert not responses[1]['result']['isError'], responses[1]
    report = json.loads(responses[1]['result']['content'][0]['text'])
    coverage = report['coverage']
    assert report['verdict'] == 'CLEAN', report
    assert coverage['network_observer_ready'] and coverage['network_isolated']
    assert coverage['aggregate_resources']['verified'] and coverage['storage_limits']['verified']
    assert 'api.weather.gov' in report['observed']['domains']
    print('MCP execution passed: actual DNS observed; observer, cgroup and storage gates verified')


if __name__ == '__main__':
    main()
