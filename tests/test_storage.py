import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock.storage import run_storage, verify_storage


@unittest.skipUnless(sys.platform == 'linux', 'Linux tmpfs quotas')
class TestStorage(unittest.TestCase):
    def test_directory_without_mount_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(RuntimeError):
                verify_storage(root)

    def test_bytes_and_inodes_enforced_without_host_fill(self):
        source = '''import errno, os, tempfile
from pathlib import Path
from airlock.storage import verify_storage
root = Path(os.environ['TMPDIR'])
verify_storage(root, {'bytes': 1024 * 1024, 'inodes': 32})
assert Path(tempfile.gettempdir()) == root
try:
    with (root / 'large').open('wb') as f:
        for _ in range(32): f.write(b'x' * 65536)
except OSError as exc:
    assert exc.errno == errno.ENOSPC
else: raise AssertionError('byte quota not enforced')
(root / 'large').unlink()
try:
    for i in range(40): (root / str(i)).touch()
except OSError as exc:
    assert exc.errno == errno.ENOSPC
else: raise AssertionError('inode quota not enforced')
'''
        self.assertEqual(run_storage([sys.executable, '-c', source],
                         {'bytes': 1024 * 1024, 'inodes': 32}), 0)

    def test_nested_runtime_mount_and_bind_are_readonly(self):
        source = '''import errno, os
from pathlib import Path
from airlock._nsinit import _required_mount, bind_runtime
root = Path(os.environ['TMPDIR'])
original, target = root / 'source', root / 'target'
(original / 'nested').mkdir(parents=True)
target.mkdir()
(original / 'nested' / 'underlying').write_text('synthetic')
_required_mount('tmpfs', str(original / 'nested'), 'tmpfs', 0, 'size=64k,nr_inodes=16')
(original / 'nested' / 'mounted').write_text('synthetic')
bind_runtime(str(original), target)
assert (target / 'nested' / 'mounted').read_text() == 'synthetic'
for where in (target / 'write', target / 'nested' / 'write'):
    try: where.write_text('blocked')
    except OSError as exc: assert exc.errno == errno.EROFS
    else: raise AssertionError('runtime bind writable')
'''
        self.assertEqual(run_storage([sys.executable, '-c', source]), 0)
