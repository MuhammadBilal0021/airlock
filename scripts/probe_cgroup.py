"""Distinguish missing kernel controller files from verifier failures."""
import json
from pathlib import Path
import sys

FILES = ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')


class MissingControllers(RuntimeError):
    pass


def check_probe_result(returncode, stdout, stderr):
    if returncode == 0:
        return
    if returncode == 77:
        try:
            message = json.loads(stdout)
            missing = message['missing_controller_files']
            if (isinstance(missing, list) and missing
                    and all(isinstance(name, str) and name in FILES for name in missing)):
                raise MissingControllers(', '.join(missing))
        except (ValueError, KeyError, TypeError):
            pass
    raise RuntimeError('cgroup probe failed (not a verified capability gap): '
                       + str(returncode) + ' ' + stderr[-1000:])


def main():
    relative = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                    if line.startswith('0::'))
    if '..' in Path(relative).parts:
        raise ValueError('invalid cgroup path')
    root = Path('/sys/fs/cgroup') / relative.lstrip('/')
    missing = [name for name in FILES if not (root / name).exists()]
    if missing:
        print(json.dumps({'missing_controller_files': missing}))
        return 77
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from airlock.bounded import verify_limits, DEFAULTS
    verify_limits(DEFAULTS)  # Any bug or ineffective limit is a failure, not a skip.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
