"""Stage complete selected skill directories from an already pinned tree; never execute them."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('model-usage', 'skill-creator', 'tmux')


def main():
    tree = json.loads((ROOT / 'research/tree.json').read_text())
    revision = tree['sha']
    if tree.get('truncated') or len(revision) != 40:
        raise ValueError('need a complete pinned source tree')
    output = ROOT / 'research/executable-candidates'
    output.mkdir(exist_ok=True)
    records = []
    total = 0
    for name in NAMES:
        prefix = 'skills/' + name + '/'
        entries = [e for e in tree['tree'] if e['path'].startswith(prefix) and e['type'] == 'blob']
        files = {}
        for entry in entries:
            relative = Path(entry['path'][len(prefix):])
            if relative.is_absolute() or '..' in relative.parts or entry.get('mode') == '120000':
                raise ValueError('unsafe source path or symlink')
            url = 'https://raw.githubusercontent.com/openclaw/openclaw/' + revision + '/' + entry['path']
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(512 * 1024 + 1)
            total += len(data)
            if len(data) > 512 * 1024 or total > 5 * 1024 * 1024:
                raise ValueError('download budget exceeded')
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if blob != entry['sha']:
                raise ValueError('download does not match pinned Git blob')
            dest = output / name / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        records.append({'id': name, 'path': name, 'source': 'https://github.com/openclaw/openclaw',
                        'revision': revision, 'files': files, 'status': 'staged_not_executed'})
    (output / 'manifest.json').write_text(json.dumps({'skills': records}, indent=2))
    print(json.dumps({'staged': len(records), 'bytes': total, 'revision': revision}))


if __name__ == '__main__':
    main()
