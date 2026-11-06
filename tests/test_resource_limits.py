"""Bounded synthetic probes; never use a fork bomb or exhaust host memory."""
import shutil
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock.sandbox import run_skill, _unshare_variants


@unittest.skipUnless(sys.platform == 'linux', 'Linux resource controls')
class TestResourceLimits(unittest.TestCase):
    def run_probe(self, source, timeout=3):
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp)
            (skill / 'run.py').write_text(source, encoding='utf-8')
            result = run_skill(skill, entry=['/usr/bin/python3', 'run.py'], timeout=timeout)
        self.addCleanup(shutil.rmtree, result.run_dir, ignore_errors=True)
        self.assertTrue(result.ok, result.errors)
        return result

    def test_output_file_and_memory_limits_are_enforced(self):
        result = self.run_probe(
            'import os, resource\n'
            'assert resource.getrlimit(resource.RLIMIT_NOFILE) == (128, 128)\n'
            'assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)\n'
            'try: resource.setrlimit(resource.RLIMIT_FSIZE, (16777216, 16777216))\n'
            'except (ValueError, OSError): pass\n'
            'else: raise AssertionError("raised hard limit")\n'
            'try: bytearray(600 * 1024 * 1024)\n'
            'except MemoryError: pass\n'
            'else: raise AssertionError("allocation exceeded limit")\n'
            'try:\n'
            ' for i in range(9): os.write(1, b"x" * (1024 * 1024))\n'
            'except OSError: pass\n')
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual((result.run_dir / 'stdout.txt').stat().st_size, 8 * 1024 * 1024)
        self.assertTrue(any('byte limit): stdout' in error for error in result.errors))
        self.assertFalse(result.meta['coverage']['resource_limits']['aggregate_limits'])

    def test_detached_descendant_stops_on_exit_and_timeout(self):
        for wait in (False, True):
            with self.subTest(timeout=wait):
                result = self.run_probe(
                    'import os, time\n'
                    'pid = os.fork()\n'
                    'if pid == 0:\n'
                    ' os.setsid()\n'
                    ' while True:\n'
                    '  with open("/output/heartbeat", "a") as f: f.write("x")\n'
                    '  time.sleep(0.05)\n'
                    'time.sleep(' + ('5' if wait else '0.2') + ')\n', timeout=0.5)
                self.assertEqual(result.timed_out, wait)
                marker = result.run_dir / 'out' / 'heartbeat'
                size = marker.stat().st_size
                self.assertGreater(size, 0)
                time.sleep(0.3)
                self.assertEqual(marker.stat().st_size, size)

    def test_launcher_requires_child_cleanup(self):
        for command in _unshare_variants():
            self.assertIn('--kill-child=SIGKILL', command)

    def test_helper_descriptors_memory_and_ptrace_are_denied(self):
        result = self.run_probe('''import ctypes, os
from pathlib import Path
helpers = [1]
for path in Path('/proc').iterdir():
    if path.name.isdigit():
        try: argv = (path / 'cmdline').read_bytes()
        except OSError: continue
        if b'airlock.sinkhole' in argv: helpers.append(int(path.name))
assert len(helpers) == 2
libc = ctypes.CDLL('libc.so.6', use_errno=True)
for pid in helpers:
    for descriptor in os.listdir('/proc/%s/fd' % pid):
        try: fd = os.open('/proc/%s/fd/%s' % (pid, descriptor), os.O_RDONLY | os.O_NONBLOCK)
        except PermissionError: pass
        except FileNotFoundError: pass
        else:
            os.close(fd)
            raise AssertionError('helper descriptor accessible')
    try: fd = os.open('/proc/%s/mem' % pid, os.O_RDONLY)
    except PermissionError: pass
    else:
        os.close(fd)
        raise AssertionError('helper memory accessible')
    assert libc.ptrace(16, pid, 0, 0) == -1
''')
        self.assertEqual(result.exit_code, 0, result.stderr)

    def test_observer_termination_invalidates_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp)
            # Record what the specimen can see and do. Without this, a failure
            # cannot separate "the observer is invisible in this sandbox" from
            # "the signal was refused" from "the observer ignored SIGTERM".
            (skill / 'run.py').write_text('''import os, signal, time
from pathlib import Path
seen = []
for path in Path('/proc').iterdir():
    if not path.name.isdigit():
        continue
    try:
        argv = (path / 'cmdline').read_bytes()
    except OSError as exc:
        seen.append('%s read-error %r' % (path.name, exc))
        continue
    seen.append('%s %r' % (path.name, argv[:60]))
    if b'airlock.sinkhole' not in argv:
        continue
    pid = int(path.name)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        seen.append('kill %d refused %r' % (pid, exc))
        continue
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            stat = Path('/proc/%d/stat' % pid).read_text()
        except OSError:
            seen.append('pid %d gone' % pid)
            break
        if stat.rsplit(')', 1)[1].split()[0] == 'Z':
            seen.append('pid %d zombie' % pid)
            break
        time.sleep(0.02)
    else:
        seen.append('pid %d survived 2s' % pid)
report = 'uid=%d euid=%d\n' % (os.getuid(), os.geteuid()) + '\n'.join(seen)
try:
    Path('/output/probe.txt').write_text(report)
except OSError as exc:
    report += '\noutput write failed %r' % (exc,)
Path('/tmp/probe.txt').write_text(report)
''')
            result = run_skill(skill, entry=['/usr/bin/python3', 'run.py'], timeout=3)
            self.addCleanup(shutil.rmtree, result.run_dir, ignore_errors=True)
            # Carry the evidence: a bare "True is not false" cannot separate a
            # specimen that failed to signal the observer from a runner that
            # stopped noticing the observer died.
            seen = 'no probe output'
            for probe in (result.run_dir / 'out' / 'probe.txt',
                          result.run_dir / 'scratch' / 'probe.txt'):
                if probe.exists():
                    seen = probe.read_text(errors='replace')[:700]
                    break
            self.assertFalse(result.ok, f'exit={result.exit_code} '
                                        f'errors={result.errors} '
                                        f'stderr={result.stderr[-400:]!r} '
                                        f'probe={seen}')
            self.assertTrue(any('observer exited' in error for error in result.errors),
                            f'errors={result.errors}')

    def test_killing_outer_launcher_stops_detached_descendant(self):
        from airlock.sandbox import build_sandbox
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp)
            (skill / 'run.py').write_text(
                'import os, time\n'
                'if os.fork() == 0:\n'
                ' os.setsid()\n'
                ' while True:\n'
                '  with open("/output/heartbeat", "a") as f: f.write("x")\n'
                '  time.sleep(0.02)\n'
                'time.sleep(10)\n', encoding='utf-8')
            run, _ = build_sandbox(skill)
        self.addCleanup(shutil.rmtree, run, ignore_errors=True)
        root = str(Path(__file__).resolve().parents[1])
        cfg = run / 'nsinit.json'
        cfg.write_text(json.dumps({'run_dir': str(run), 'rootfs': str(run / 'rootfs'),
                                  'repo_root': root, 'timeout': 10,
                                  'entry': ['/usr/bin/python3', 'run.py']}))
        env = dict(os.environ, PYTHONPATH=root, AIRLOCK_RUN_DIR=str(run))
        command = _unshare_variants()[0] + [sys.executable, '-m', 'airlock._nsinit',
                                           '--config', str(cfg)]
        launcher = subprocess.Popen(command, env=env, start_new_session=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            marker = run / 'out' / 'heartbeat'
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                self.assertIsNone(launcher.poll(), 'namespace runner exited before probe')
                time.sleep(0.02)
            self.assertTrue(marker.exists(), 'probe never started')
            launcher.kill()
            launcher.wait(timeout=3)
            time.sleep(0.2)
            size = marker.stat().st_size
            time.sleep(0.3)
            self.assertEqual(marker.stat().st_size, size)
            self.assertFalse((run / 'meta.json').exists(), 'aborted run claimed completion')
        finally:
            # Only this test's new process group, never the invoking shell.
            try:
                os.killpg(launcher.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            launcher.wait(timeout=3)
