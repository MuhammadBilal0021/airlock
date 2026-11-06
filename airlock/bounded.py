"""Opt-in cgroup-v2 launcher: python -m airlock.bounded scan PATH ...

Requires a systemd user manager with delegated memory, pids and CPU controllers.
Never falls back to execution without the requested aggregate limits.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

DEFAULTS = {'memory_bytes': 768 * 1024 * 1024, 'tasks': 64}


def inspect_limits():
    entries = Path('/proc/self/cgroup').read_text().splitlines()
    relative = next(line[3:] for line in entries if line.startswith('0::'))
    if '..' in Path(relative).parts:
        raise ValueError('invalid cgroup path')
    root = Path('/sys/fs/cgroup') / relative.lstrip('/')
    return {'memory_bytes': int((root / 'memory.max').read_text()),
            'swap_bytes': int((root / 'memory.swap.max').read_text()),
            'tasks': int((root / 'pids.max').read_text()),
            'cpu_max': (root / 'cpu.max').read_text().strip(),
            'scope': 'scanner and descendants', 'backend': 'cgroup-v2', 'verified': True}


def verify_limits(requested):
    actual = inspect_limits()
    quota, period = map(int, actual['cpu_max'].split())
    if not (0 < actual['memory_bytes'] <= requested['memory_bytes']
            and actual['swap_bytes'] == 0
            and 0 < actual['tasks'] <= requested['tasks']
            and 0 < quota * 100 <= period * requested.get('cpu_percent', 100)):
        raise RuntimeError('kernel cgroup limits do not match requested bounds')
    return actual


def run_bounded(command, *, limits=None, timeout=120):
    limits = dict(DEFAULTS if limits is None else limits)
    unit = 'airlock-' + uuid.uuid4().hex + '.scope'
    argv = ['systemd-run', '--user', '--scope', '--quiet', '--unit=' + unit,
            '-p', 'MemoryMax=' + str(limits['memory_bytes']),
            '-p', 'MemorySwapMax=0', '-p', 'TasksMax=' + str(limits['tasks']),
            '-p', 'CPUQuota=' + str(limits.get('cpu_percent', 100)) + '%',
            '-p', 'RuntimeMaxSec=' + str(timeout),
            sys.executable, '-m', 'airlock.bounded',
            '--guard', json.dumps(limits), '--'] + list(command)
    try:
        return subprocess.run(argv, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print('airlock: aggregate run exceeded wall timeout', file=sys.stderr)
        return 2
    except OSError as exc:
        print(f'airlock: bounded launch unavailable: {exc}', file=sys.stderr)
        return 2
    finally:
        # Stop only this uniquely named scope, including detached descendants.
        try:
            subprocess.run(['systemctl', '--user', 'stop', unit], timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            print('airlock: scope cleanup could not be confirmed: ' + unit,
                  file=sys.stderr)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--guard':
        try:
            verify_limits(json.loads(sys.argv[2]))
            if sys.argv[3] != '--' or not sys.argv[4:]:
                raise ValueError('missing guarded command')
            os.execvp(sys.argv[4], sys.argv[4:])
        except (OSError, ValueError, RuntimeError, StopIteration) as exc:
            print(f'airlock: aggregate limit verification failed: {exc}', file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wall-timeout', type=float, default=120)
    parser.add_argument('airlock_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.airlock_args or args.wall_timeout <= 0:
        parser.error('provide airlock arguments and a positive wall timeout')
    if '--keep' in args.airlock_args:
        parser.error('--keep is unavailable with ephemeral bounded storage; use --output for the report')
    return run_bounded([sys.executable, '-m', 'airlock.storage', '--launch'] + args.airlock_args,
                       timeout=args.wall_timeout)


if __name__ == '__main__':
    raise SystemExit(main())
