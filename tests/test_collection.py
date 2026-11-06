"""Host collection must not follow specimen-controlled paths or block on FIFOs."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock.sandbox import _read_text, snapshot_dir


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor-based collection')
class TestCollection(unittest.TestCase):
    def test_capture_and_event_limits_are_disclosed(self):
        from airlock.sandbox import _read_capture
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'capture.jsonl'
            path.write_text('{"type":"dns"}\n' * 4)
            issues = []
            with patch('airlock.sandbox._MAX_ENTRIES', 2):
                self.assertEqual(len(_read_capture(path, issues)), 2)
            self.assertIn('event count limit', issues[0])
            issues = []
            with patch('airlock.sandbox._MAX_CAPTURE_BYTES', 16):
                _read_capture(path, issues)
            self.assertIn('capture limit', issues[0])

    def test_entry_limit_rejects_baseline_and_discloses_partial_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(3): (root / str(i)).touch()
            with patch('airlock.sandbox._MAX_ENTRIES', 2):
                with self.assertRaises(ValueError): snapshot_dir(root)
                issues = []
                self.assertEqual(len(snapshot_dir(root, issues)), 2)
                self.assertIn('entry limit', issues[0])

    def test_sinkhole_stops_writing_at_capture_budget(self):
        from airlock.sinkhole import emit
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'capture.jsonl'
            with patch('airlock.sinkhole.MAX_CAPTURE_FILE', 120):
                for _ in range(5): emit(str(path), {'type': 'test', 'body': 'x' * 50})
            self.assertLessEqual(path.stat().st_size, 120)
            self.assertTrue(path.with_suffix('.truncated').exists())

    def test_symlink_file_and_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'sentinel').write_text('synthetic sentinel')
            work = root / 'work'
            work.mkdir()
            (work / 'link').symlink_to(outside / 'sentinel')
            (work / 'parent').symlink_to(outside, target_is_directory=True)
            self.assertEqual(_read_text(work / 'link'), ('', True))
            self.assertEqual(_read_text(work / 'parent' / 'sentinel'), ('', True))
            issues = []
            self.assertEqual(snapshot_dir(work, issues), {})
            self.assertEqual(len(issues), 2)
            self.assertEqual(snapshot_dir(work / 'parent', issues), {})
            self.assertIn('inaccessible directory', issues[-1])

    def test_fifo_is_refused_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / 'pipe'
            os.mkfifo(fifo)
            self.assertEqual(_read_text(fifo), ('', True))
            issues = []
            self.assertEqual(snapshot_dir(Path(tmp), issues), {})
            self.assertIn('special file', issues[0])

    def test_reads_at_most_limit_plus_one_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'large'
            with path.open('wb') as stream:
                stream.truncate(1024 * 1024 * 1024)
            real_read = os.read
            sizes = []
            def tracked_read(fd, size):
                sizes.append(size)
                return real_read(fd, size)
            with patch('airlock.sandbox.os.read', side_effect=tracked_read):
                content, truncated = _read_text(path, 1024)
            self.assertEqual(len(content), 1024)
            self.assertTrue(truncated)
            self.assertEqual(sum(sizes), 1025)
            path.write_bytes(b'x' * 1024)
            self.assertEqual(_read_text(path, 1024), ('x' * 1024, False))

    def test_snapshot_does_not_read_file_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'credential'
            path.write_text('synthetic')
            os.utime(path, ns=(1000000000, 2000000000))
            with patch('airlock.sandbox.os.read', side_effect=AssertionError('content read')):
                snapshot = snapshot_dir(Path(tmp))
            self.assertEqual(snapshot[str(path)].atime_ns, 1000000000)
            self.assertEqual(path.stat().st_atime_ns, 1000000000)
