import json
from pathlib import Path
import tempfile
import unittest

from scripts.scan_dataset import classify, fingerprint, run, summarize


class TestDataset(unittest.TestCase):
    def test_failures_and_timeouts_are_not_completed(self):
        report = {'verdict': 'CLEAN', 'coverage': {'network_isolated': True},
                  'observed': {'exit_code': 0}}
        self.assertEqual(classify(report, 0), 'completed')
        self.assertEqual(classify(report, 2), 'failed')
        report['coverage']['timed_out'] = True
        self.assertEqual(classify(report, 0), 'timed_out')

    def test_unique_counts_and_separate_denominators(self):
        result = summarize([{'status': 'completed', 'rule_ids': ['ALK-001', 'ALK-001']},
                            {'status': 'failed', 'rule_ids': ['ALK-001']},
                            {'status': 'static_only', 'rule_ids': ['ALK-009']}])
        self.assertEqual(result['skills_per_rule']['completed'], {'ALK-001': 1})
        self.assertEqual(result['skills_per_rule']['static_only'], {'ALK-009': 1})

    def test_static_corpus_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill = root / 'skill'; skill.mkdir()
            (skill / 'SKILL.md').write_text('---\nname: demo\n---\n', encoding='utf-8')
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'skills': [{'id': 'demo', 'path': 'skill',
                'source': 'test fixture', 'revision': 'v1', 'files': fingerprint(skill)}]}))
            records = run(manifest, root / 'first', static_only=True)
            self.assertEqual(records[0]['status'], 'static_only')
            (skill / 'SKILL.md').write_text('changed')
            records = run(manifest, root / 'second', static_only=True)
            self.assertEqual(records[0]['status'], 'failed')
            self.assertIn('hashes differ', records[0]['error'])
