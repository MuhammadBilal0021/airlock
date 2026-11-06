"""Private, quota-limited temporary storage for the bounded scanner."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

DEFAULTS = {'bytes': 128 * 1024 * 1024, 'inodes': 4096}


def verify_storage(path, limits=DEFAULTS):
    path = Path(path).resolve()
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    entry = next((line.split() for line in mounts if line.split()[4] == str(path)), None)
    if entry is None or entry[entry.index('-') + 1] != 'tmpfs':
        raise RuntimeError('private tmpfs mount is missing')
    info = os.statvfs(path)
    size = info.f_blocks * info.f_frsize
    if not (0 < size <= limits['bytes'] and 0 < info.f_files <= limits['inodes']):
        raise RuntimeError('storage limits are absent or too large')
    return {'verified': True, 'backend': 'tmpfs', 'bytes': size,
            'inodes': info.f_files, 'scope': 'run directories and scanner temporary files'}


def run_storage(command, limits=None):
    limits = dict(DEFAULTS if limits is None else limits)
    with tempfile.TemporaryDirectory(prefix='airlock-storage-') as root:
        return subprocess.run(['unshare', '--user', '--map-root-user', '--mount',
                               '--fork', '--kill-child=SIGKILL', sys.executable,
                               '-m', 'airlock.storage', root, json.dumps(limits),
                               '--'] + list(command)).returncode


def main():
    if sys.argv[1:2] == ['--launch']:
        raise SystemExit(run_storage([sys.executable, '-m', 'airlock'] + sys.argv[2:]))
    root, encoded, separator, *command = sys.argv[1:]
    if separator != '--' or not command:
        raise ValueError('missing scanner command')
    limits = json.loads(encoded)
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    def mount(source, target, kind, flags, data=None):
        if libc.mount(source, target, kind, flags, data) != 0:
            raise OSError(ctypes.get_errno(), 'private storage mount failed')
    mount(None, b'/', None, 16384 | (1 << 18))
    mount(b'tmpfs', os.fsencode(root), b'tmpfs', 2 | 4,
          f"size={limits['bytes']},nr_inodes={limits['inodes']},mode=700".encode())
    verify_storage(root, limits)
    os.environ['TMPDIR'] = root
    os.environ['AIRLOCK_STORAGE_ROOT'] = root
    os.execvp(command[0], command)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'airlock: bounded storage refused: {exc}', file=sys.stderr)
        raise SystemExit(2)
