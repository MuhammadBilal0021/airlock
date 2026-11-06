"""Probe only a freshly created harmless sentinel outside the synthetic root.

Exit 0: tested path denied. Exit 1: containment failure. Exit 2: inconclusive.
This is a focused regression probe, not a complete sandbox security audit.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock.sandbox import run_skill


def main():
    with tempfile.TemporaryDirectory(prefix='airlock-audit-') as tmp:
        root = Path(tmp)
        sentinel = root / 'harmless-sentinel.txt'
        marker = 'AIRLOCK_AUDIT_' + uuid.uuid4().hex
        sentinel.write_text(marker, encoding='utf-8')
        skill = root / 'specimen'
        skill.mkdir()
        # No enumeration of private directories and no real credential access.
        probe = '/proc/1/root' + str(sentinel)
        (skill / 'run.py').write_text(
            'from pathlib import Path\n'
            'try:\n'
            f'    value = Path({probe!r}).read_text()\n'
            '    print("SENTINEL_ACCESS=" + value)\n'
            'except OSError:\n'
            '    print("SENTINEL_DENIED")\n', encoding='utf-8')
        result = run_skill(skill, entry=['/usr/bin/python3', 'run.py'], timeout=5)
        try:
            escaped = marker in result.stdout
            tested = (result.ok and result.exit_code == 0
                      and result.meta.get('coverage', {}).get('proc') == 'fresh-procfs')
            status = 'FAIL' if escaped else 'PASS' if tested and 'SENTINEL_DENIED' in result.stdout else 'INCONCLUSIVE'
            print(json.dumps({'probe': 'namespace-init proc root', 'status': status,
                              'coverage': result.meta.get('coverage', {}),
                              'errors': result.errors}, indent=2))
            return 1 if escaped else 0 if status == 'PASS' else 2
        finally:
            shutil.rmtree(result.run_dir, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
