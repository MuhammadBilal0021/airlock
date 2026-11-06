"""Download pinned corpus files as data; never install or execute specimens."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / 'research/published/executable-manifest.json').read_text())
    target = ROOT / 'research/executable-candidates'
    target.mkdir(parents=True, exist_ok=True)
    total = 0
    for item in manifest['skills']:
        repository = item['source'].removeprefix('https://github.com/')
        if repository not in ('openclaw/openclaw', 'openai/skills', 'anthropics/skills'):
            raise ValueError('unexpected source repository')
        prefix = item.get('source_path', 'skills/' + item['id'])
        for name, expected in item['files'].items():
            path = Path(item['path']) / name
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('unsafe corpus path')
            dest = target / path
            if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected:
                continue
            url = 'https://raw.githubusercontent.com/' + repository + '/' + item['revision'] + '/' + prefix + '/' + name
            with urllib.request.urlopen(url, timeout=30) as response:
                body = response.read(4 * 1024 * 1024 + 1)
            total += len(body)
            if len(body) > 4 * 1024 * 1024 or total > 20 * 1024 * 1024:
                raise ValueError('download budget exceeded')
            if hashlib.sha256(body).hexdigest() != expected:
                raise ValueError('source hash mismatch: ' + name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
        print(item['id'], 'verified', flush=True)
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
