"""Regression tests for the measurement-validity review findings.

Each test corresponds to a reproduced counterexample: a failed sandbox counted as
coverage, discarded interpreter flags, and a cgroup gate that treated every probe
failure as a missing kernel capability.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.harness_coverage import classify_run, shebang_argv  # noqa: E402
from scripts.probe_cgroup import MissingControllers, check_probe_result  # noqa: E402


class FakeResult:
    def __init__(self, ok: bool):
        self.ok = ok


class FakeFinding:
    def __init__(self, rule_id: str):
        self.rule_id = rule_id


class FakeVerdict:
    def __init__(self, label: str, rules=()):
        self.label = label
        self.findings = [FakeFinding(rule) for rule in rules]


class TestRunClassification(unittest.TestCase):
    """A failed setup is not established coverage."""

    def test_failed_setup_is_not_established(self):
        self.assertEqual(classify_run(FakeResult(False), FakeVerdict('UNKNOWN')),
                         'setup_failed')

    def test_unknown_verdict_is_not_established(self):
        self.assertEqual(classify_run(FakeResult(True), FakeVerdict('UNKNOWN')),
                         'setup_failed')

    def test_alk_093_is_not_established(self):
        self.assertEqual(
            classify_run(FakeResult(True), FakeVerdict('ELEVATED', ['ALK-093'])),
            'setup_failed')

    def test_completed_run_is_established(self):
        self.assertEqual(classify_run(FakeResult(True), FakeVerdict('CLEAN')),
                         'established')


class TestShebangFlags(unittest.TestCase):
    """Interpreter flags change package behaviour and must not be dropped."""

    def test_env_split_string_preserves_flags(self):
        program, flags = shebang_argv(
            '#!/usr/bin/env -S node --experimental-default-type=module')
        self.assertEqual(program, '/usr/local/bin/node')
        self.assertEqual(flags, ['--experimental-default-type=module'])

    def test_env_bash_without_flags(self):
        self.assertEqual(shebang_argv('#!/usr/bin/env bash'), ('/bin/bash', []))

    def test_direct_interpreter_with_flag(self):
        self.assertEqual(shebang_argv('#!/bin/bash -e'), ('/bin/bash', ['-e']))

    def test_unsupported_env_program_fails_closed(self):
        with self.assertRaises(ValueError):
            shebang_argv('#!/usr/bin/env fish')


class TestCgroupProbeGate(unittest.TestCase):
    """Only a verified missing controller may become a skipped capability."""

    def test_verified_probe_passes(self):
        check_probe_result(0, '', '')

    def test_missing_controllers_are_a_capability_gap(self):
        payload = json.dumps({'missing_controller_files': ['cpu.max']})
        with self.assertRaises(MissingControllers):
            check_probe_result(77, payload, '')

    def test_unknown_failure_is_not_a_capability_gap(self):
        with self.assertRaises(RuntimeError) as caught:
            check_probe_result(1, '', 'boom')
        self.assertNotIsInstance(caught.exception, MissingControllers)

    def test_malformed_payload_is_not_a_capability_gap(self):
        with self.assertRaises(RuntimeError):
            check_probe_result(77, '{"weird": true}', '')

    def test_unexpected_controller_name_is_not_a_capability_gap(self):
        payload = json.dumps({'missing_controller_files': ['io.max']})
        with self.assertRaises(RuntimeError):
            check_probe_result(77, payload, '')


if __name__ == '__main__':
    unittest.main()
