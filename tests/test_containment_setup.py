"""Fail-closed setup checks that never execute a specimen."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
import json
import tempfile
import shutil

from airlock.sandbox import _unshare_variants


class TestNamespaceRequirements(unittest.TestCase):
    def test_every_launch_requires_every_namespace(self):
        for command in _unshare_variants():
            for flag in ('--user', '--map-root-user', '--mount', '--net', '--pid'):
                self.assertIn(flag, command)


@unittest.skipUnless(sys.platform == 'linux', 'Linux mount implementation')
class TestRequiredMount(unittest.TestCase):
    def test_minimal_devices_work_without_host_device_tree(self):
        from airlock.sandbox import run_skill
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp)
            (skill / 'run.py').write_text(
                'import os\n'
                'assert set(os.listdir("/dev")) == '
                '{"null", "zero", "random", "urandom", "fd", "stdin", "stdout", "stderr"}\n'
                'with open("/dev/null", "wb") as f: f.write(b"test")\n'
                'with open("/dev/zero", "rb") as f: assert f.read(4) == bytes(4)\n'
                'with open("/dev/urandom", "rb") as f: assert len(f.read(16)) == 16\n'
                'try: open("/dev/injected", "w")\n'
                'except OSError: pass\n'
                'else: raise AssertionError("device directory writable")\n', encoding='utf-8')
            result = run_skill(skill, entry=['/usr/bin/python3', 'run.py'], timeout=5)
            try:
                self.assertTrue(result.ok, result.errors)
                self.assertEqual(result.exit_code, 0, result.stderr)
                self.assertEqual(result.meta['coverage']['dev'], 'minimal')
            finally:
                shutil.rmtree(result.run_dir, ignore_errors=True)

    def test_supervisor_root_cannot_read_host_sentinel(self):
        from scripts.check_containment import main
        output = StringIO()
        with redirect_stdout(output):
            status = main()
        report = json.loads(output.getvalue())
        if status == 2 and report['coverage'].get('proc') != 'fresh-procfs':
            self.skipTest('fresh procfs unavailable; sentinel probe inconclusive')
        self.assertEqual(status, 0, report)

    def test_refused_mount_aborts_setup(self):
        from airlock._nsinit import _required_mount
        with patch('airlock._nsinit._mount', return_value=(False, 'denied')):
            with self.assertRaisesRegex(RuntimeError, 'required mount failed'):
                _required_mount(None, '/synthetic', None, 0)

    def test_read_only_remount_failure_is_fatal(self):
        from pathlib import Path
        from airlock._nsinit import setup_mounts, MountLog
        with patch('airlock._nsinit.os.path.isdir', return_value=True), \
             patch('airlock._nsinit._mount', side_effect=[(True, ''), (True, ''),
                                                        (False, 'readonly denied')]):
            with self.assertRaisesRegex(RuntimeError, 'readonly denied'):
                setup_mounts({'rootfs': '/synthetic', 'run_dir': '/unused'}, MountLog())
