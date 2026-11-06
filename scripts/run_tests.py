"""Run the complete suite; skips are a validation failure, never a green gate."""
from pathlib import Path
import os
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _last_line(traceback_text):
    lines = [line.strip() for line in traceback_text.strip().splitlines() if line.strip()]
    return lines[-1][:900] if lines else 'no detail'


def annotate(result):
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
        print(f'::error title=skipped {test}::{reason}')


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    annotate(result)
    if result.skipped:
        print('Validation failed: required tests were skipped.', file=sys.stderr)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped and result.testsRun else 1)
