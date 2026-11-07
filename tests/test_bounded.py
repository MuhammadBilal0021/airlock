import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock.bounded import verify_limits, run_bounded, DEFAULTS


class TestLimitVerification(unittest.TestCase):
    def test_refuses_missing_or_weaker_kernel_limits(self):
        actual = {'memory_bytes': DEFAULTS['memory_bytes'], 'swap_bytes': 0,
                  'tasks': 64, 'cpu_max': '100000 100000'}
        for key, value in [('memory_bytes', 2**40), ('tasks', 65),
                           ('swap_bytes', 1), ('cpu_max', 'max 100000'),
                           ('cpu_max', '200000 100000')]:
            with self.subTest(key=key, value=value), patch(
                    'airlock.bounded.inspect_limits', return_value={**actual, key: value}):
                with self.assertRaises((RuntimeError, ValueError)):
                    verify_limits(DEFAULTS)

    def test_guard_does_not_execute_without_limits(self):
        with patch('sys.argv', ['bounded', '--guard', '{"memory_bytes":1,"tasks":1}',
                                '--', '/bin/true']), \
             patch('airlock.bounded.inspect_limits', side_effect=OSError('no controller')), \
             patch('airlock.bounded.os.execvp') as execute:
            from airlock.bounded import main
            self.assertEqual(main(), 2)
            execute.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux', 'Linux cgroup v2')
class TestBoundedRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            check = subprocess.run(['systemctl', '--user', 'is-system-running'],
                                   capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            raise unittest.SkipTest('systemd user manager unavailable')
        if check.stdout.strip() not in (b'running', b'degraded'):
            raise unittest.SkipTest('systemd user manager unavailable')
        # A user manager can exist without carrying delegated controllers, which
        # is what a GitHub-hosted runner looks like: memory and pids are
        # delegated, cpu is not, so the launcher refuses and every test below
        # would fail with nothing but "2". Check the precondition the tests
        # actually need and name the missing capability instead.
        probe = subprocess.run(
            ['systemd-run', '--user', '--scope', '--quiet',
             '--unit=airlock-probe-%d' % os.getpid(),
             '-p', 'MemoryMax=%d' % DEFAULTS['memory_bytes'],
             '-p', 'MemorySwapMax=0',
             '-p', 'TasksMax=%d' % DEFAULTS['tasks'],
             '-p', 'CPUQuota=100%',
             sys.executable, str(Path(__file__).resolve().parents[1] / 'scripts/probe_cgroup.py')],
            capture_output=True, text=True, timeout=60)
        from scripts.probe_cgroup import check_probe_result, MissingControllers
        try:
            check_probe_result(probe.returncode, probe.stdout, probe.stderr)
        except MissingControllers as exc:
            raise unittest.SkipTest('cgroup capability missing: ' + str(exc))

    def test_kernel_task_limit_refuses_bounded_child_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'result'
            # At most 24 attempted children, all sleeping; no unbounded fork loop.
            source = '''import subprocess, sys
from pathlib import Path
children = []
refused = False
try:
    for _ in range(24):
        try:
            children.append(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)']))
        except BlockingIOError:
            refused = True
            break
    assert refused, 'kernel did not enforce task limit'
    Path(sys.argv[1]).write_text('refused')
finally:
    for child in children: child.kill()
    for child in children: child.wait()
'''
            status = run_bounded([sys.executable, '-c', source, str(marker)],
                                 limits={'memory_bytes': 256 * 1024 * 1024, 'tasks': 16},
                                 timeout=15)
            self.assertEqual(status, 0)
            self.assertEqual(marker.read_text(), 'refused')

    def test_kernel_memory_limit_kills_bounded_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'result'
            source = '''import os, sys
from pathlib import Path
from airlock.bounded import verify_limits
verify_limits({'memory_bytes': 64 * 1024 * 1024, 'tasks': 16})
Path(sys.argv[1]).write_text('limits verified; allocation starting')
data = bytearray(96 * 1024 * 1024)
Path(sys.argv[1]).write_text('allocation unexpectedly succeeded')
'''
            status = run_bounded([sys.executable, '-c', source, str(marker)],
                                 limits={'memory_bytes': 64 * 1024 * 1024, 'tasks': 16},
                                 timeout=15)
            # systemd may stop the whole scope on OOM, so no in-scope observer
            # is assumed to survive. Both SIGKILL and scope-stop SIGTERM count.
            self.assertIn(status, (-9, -15, 137, 143))
            self.assertEqual(marker.read_text(), 'limits verified; allocation starting')

    def test_scope_deadline_stops_detached_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'heartbeat'
            source = '''import os, sys, time
os.setsid()
while True:
    with open(sys.argv[1], 'a') as stream: stream.write('x')
    time.sleep(0.05)
'''
            status = run_bounded([sys.executable, '-c', source, str(marker)], timeout=2)
            self.assertNotEqual(status, 0)
            self.assertTrue(marker.exists())
            size = marker.stat().st_size
            import time
            time.sleep(0.3)
            self.assertEqual(marker.stat().st_size, size)

    def test_cpu_quota_actually_throttles(self):
        source = '''import time
from pathlib import Path
relative = next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
stats = Path('/sys/fs/cgroup') / relative.lstrip('/') / 'cpu.stat'
def throttled(): return int(dict(line.split() for line in stats.read_text().splitlines())['nr_throttled'])
before = throttled()
deadline = time.monotonic() + 0.7
while time.monotonic() < deadline: pass
assert throttled() > before, 'no kernel throttling observed'
'''
        self.assertEqual(run_bounded([sys.executable, '-c', source],
                         limits={**DEFAULTS, 'cpu_percent': 10}, timeout=15), 0)

    def test_scope_deadline_survives_wrapper_death(self):
        import signal
        import time
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'heartbeat'
            writer = ('import time,sys\n'
                      'while True:\n'
                      ' with open(sys.argv[1], "a") as f: f.write("x")\n'
                      ' time.sleep(0.05)\n')
            wrapper = ('from airlock.bounded import run_bounded; import sys; '
                       'raise SystemExit(run_bounded([sys.executable,"-c",sys.argv[1],sys.argv[2]],timeout=2))')
            process = subprocess.Popen([sys.executable, '-c', wrapper, writer, str(marker)],
                                       start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    self.assertIsNone(process.poll())
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                process.kill()
                process.wait(timeout=2)
                time.sleep(2.3)
                size = marker.stat().st_size
                time.sleep(0.3)
                self.assertEqual(marker.stat().st_size, size)
            finally:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=2)
