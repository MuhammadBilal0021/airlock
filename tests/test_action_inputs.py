"""Execute the actual composite-action shell blocks with inert local stubs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def script(step):
    body = (ROOT / 'action.yml').read_text().split('    - name: ' + step + '\n', 1)[1]
    body = body.split('\n    - name:', 1)[0]
    lines = body.split('      run: |\n', 1)[1].splitlines()
    return '\n'.join(line[8:] for line in lines if line.strip())


@unittest.skipUnless(sys.platform == 'linux', 'Action runs in Bash on Linux')
class TestActionInputs(unittest.TestCase):
    def test_shell_syntax_in_inputs_is_literal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / 'airlock'
            stub.write_text('#!/usr/bin/python3\nimport json,sys\n'
                            'from pathlib import Path\n'
                            'Path("argv.json").write_text(json.dumps(sys.argv[1:]))\n')
            stub.chmod(0o700)
            values = ['--help $(touch injected) `touch injected2` "quoted"',
                      '60$(touch injected3)', 'high; touch injected4']
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       AIRLOCK_TARGET=values[0], AIRLOCK_TIMEOUT=values[1], AIRLOCK_FAIL_ON=values[2])
            result = subprocess.run(['bash', '-c', script('Scan')], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads((root / 'argv.json').read_text())
            self.assertEqual(args[-2:], ['--', values[0]])
            self.assertEqual(args[args.index('--timeout') + 1], values[1])
            self.assertEqual(args[args.index('--fail-on') + 1], values[2])
            self.assertFalse(list(root.glob('injected*')))

    def test_scan_failure_survives_tee(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / 'airlock'
            stub.write_text('#!/bin/sh\nexit 2\n'); stub.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       AIRLOCK_TARGET='.', AIRLOCK_TIMEOUT='5', AIRLOCK_FAIL_ON='high')
            result = subprocess.run(['bash', '-c', script('Scan')], cwd=root, env=env,
                                    capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_only_success_passes_final_gate(self):
        for outcome in ('success', 'failure', 'skipped', 'cancelled', ''):
            result = subprocess.run(['bash', '-c', script('Enforce verdict')],
                                    env=dict(os.environ, AIRLOCK_SCAN_OUTCOME=outcome),
                                    capture_output=True)
            self.assertEqual(result.returncode, 0 if outcome == 'success' else 1)
