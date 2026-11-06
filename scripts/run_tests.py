"""Run the complete suite; an unreported skip is a validation failure.

Some tests need a capability the machine may not have at all — a delegated cpu
controller for the bounded launcher, for instance. GitHub-hosted runners have a
systemd user manager but delegate only memory and pids. Collapsing that into a
failed assertion tells nobody whether the scanner broke or the environment is
thinner than documented, so a skip whose reason starts with an allow-listed
capability string is reported as a coverage gap instead of a red gate.
Everything else still fails.
"""
from pathlib import Path
import os
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _last_line(traceback_text):
    lines = [line.strip() for line in traceback_text.strip().splitlines() if line.strip()]
    return lines[-1][:900] if lines else 'no detail'


def annotate(result, tolerated):
    """Surface the verdict in the checks UI.

    The job log is the only place a failure normally appears, and it is not
    readable by anyone without repository access. Annotations are, so a red run
    on a public branch still says which test broke and why.
    """
    if not os.environ.get('GITHUB_ACTIONS'):
        return
    for test, traceback_text in result.failures + result.errors:
        print(f'::error title={test}::{_last_line(traceback_text)}')
    for test, reason in result.skipped:
        level = 'notice' if id(test) in tolerated else 'error'
        print(f'::{level} title=skipped {test}::{reason}')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    allowed = os.environ.get('AIRLOCK_ALLOW_ENV_SKIPS', '').strip()
    tolerated = {id(test) for test, reason in result.skipped
                 if allowed and reason.startswith(allowed)}
    annotate(result, tolerated)
    unexpected = [f'{test}: {reason}' for test, reason in result.skipped
                  if id(test) not in tolerated]
    if tolerated:
        print('Coverage gap, not verified on this machine:', file=sys.stderr)
        for test, reason in result.skipped:
            if id(test) in tolerated:
                print(f'  {test}: {reason}', file=sys.stderr)
    if unexpected:
        print('Validation failed: required tests were skipped.', file=sys.stderr)
        for entry in unexpected:
            print(f'  {entry}', file=sys.stderr)
    raise SystemExit(0 if result.wasSuccessful() and not unexpected and result.testsRun else 1)
