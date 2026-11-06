"""Fail-closed startup and actual DNS evidence, without host egress."""
import ast
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@unittest.skipUnless(sys.platform == 'linux', 'Linux namespace runner')
class TestObserverReadiness(unittest.TestCase):
    def test_single_runner_entrypoint(self):
        tree = ast.parse((ROOT / 'airlock/_nsinit.py').read_text())
        self.assertEqual(sum(isinstance(n, ast.FunctionDef) and n.name == 'main'
                             for n in tree.body), 1)

    def test_delayed_ready_waits_beyond_old_fixed_delay(self):
        from airlock._nsinit import start_observer
        code = 'import os,sys,time; time.sleep(0.8); os.write(int(sys.argv[-1]),b"R"); time.sleep(5)'
        start = time.monotonic()
        proc = start_observer([sys.executable, '-c', code], dict(os.environ), ready_timeout=3)
        try:
            self.assertGreaterEqual(time.monotonic() - start, 0.8)
        finally:
            proc.kill(); proc.wait()

    def test_missing_or_invalid_readiness_refuses_launch(self):
        from airlock._nsinit import start_observer
        for code in ['pass', 'import time; time.sleep(5)',
                     'import os,sys,time; os.write(int(sys.argv[-1]),b"X"); time.sleep(5)']:
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'did not become ready'):
                start_observer([sys.executable, '-c', code], dict(os.environ), ready_timeout=0.1)

    def test_extra_interface_refuses_isolation_claim(self):
        from airlock._nsinit import verify_network_interfaces
        with patch('socket.if_nameindex', return_value=[(1, 'lo'), (2, 'eth0')]):
            with self.assertRaisesRegex(RuntimeError, 'not loopback-only'):
                verify_network_interfaces()

    def test_failed_bind_never_signals_readiness(self):
        from airlock.sinkhole import run_dns, run_tcp
        for listener in (run_dns, run_tcp):
            ready = threading.Event()
            sock = MagicMock()
            sock.bind.side_effect = OSError('synthetic bind failure')
            with patch('airlock.sinkhole.socket.socket', return_value=sock), \
                 patch('airlock.sinkhole.emit'):
                listener('/unused', threading.Event(), ready)
            self.assertFalse(ready.is_set())

    def test_repeated_weather_runs_capture_actual_queries(self):
        from airlock.sandbox import run_skill, cleanup
        for repetition in range(3):
            result = run_skill(ROOT / 'fixtures/01-benign-weather', entry=['/bin/sh', 'run.sh'], timeout=15)
            try:
                self.assertTrue(result.ok, result.errors)
                self.assertEqual(result.exit_code, 0, result.stderr)
                self.assertTrue(result.meta['coverage']['network_observer_ready'])
                self.assertTrue(result.meta['coverage']['network_isolated'])
                self.assertTrue(any(e.get('type') == 'dns_query' and e.get('qname') == 'api.weather.gov'
                                    for e in result.net_events), (repetition, result.net_events))
            finally:
                cleanup(result.run_dir)
