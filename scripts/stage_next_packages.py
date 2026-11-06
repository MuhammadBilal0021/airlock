"""Stage pinned complete skill packages as specimens, without executing them."""
import hashlib
import json
from pathlib import Path
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
SELECTION = [
    ('openai/skills', 'skills/.curated/figma-code-connect-components', 'figma-code-connect'),
    ('openai/skills', 'skills/.curated/figma-create-design-system-rules', 'figma-design-rules'),
    ('openai/skills', 'skills/.curated/jupyter-notebook', 'jupyter-notebook'),
    ('openai/skills', 'skills/.system/plugin-creator', 'plugin-creator'),
    ('openai/skills', 'skills/.curated/migrate-to-codex', 'migrate-to-codex'),
    ('anthropics/skills', 'skills/pdf', 'anthropic-pdf'),
    ('anthropics/skills', 'skills/pptx', 'anthropic-pptx'),
    ('anthropics/skills', 'skills/webapp-testing', 'webapp-testing'),
]


def main(selection=SELECTION, output=None):
    output = output or ROOT / 'research/executable-candidates'
    output.mkdir(parents=True, exist_ok=True)
    manifest = (json.loads((output / 'manifest.json').read_text())
                if (output / 'manifest.json').exists() else {'skills': []})
    total = 0
    for repo, prefix, name in selection:
        tree = json.loads((ROOT / 'research' / (repo.replace('/', '-') + '-tree.json')).read_text())
        revision = tree['sha']
        entries = [e for e in tree['tree'] if e['path'].startswith(prefix + '/') and e['type'] == 'blob']
        if tree.get('truncated') or not entries:
            raise ValueError('incomplete tree')
        existing = next((s for s in manifest['skills'] if s['id'] == name and
                         s['revision'] == revision), None)
        if existing and all((output / name / p).is_file() and
                            hashlib.sha256((output / name / p).read_bytes()).hexdigest() == h
                            for p, h in existing['files'].items()):
            print(name, 'already staged', flush=True)
            continue
        def fetch(entry):
            relative = Path(entry['path'][len(prefix) + 1:])
            if relative.is_absolute() or '..' in relative.parts or entry.get('mode') == '120000':
                raise ValueError('unsafe path')
            url = 'https://raw.githubusercontent.com/' + repo + '/' + revision + '/' + entry['path']
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('file budget exceeded')
            if hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != entry['sha']:
                raise ValueError('Git blob mismatch')
            return relative, data
        files = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            for relative, data in pool.map(fetch, entries):
                total += len(data)
                if total > 20 * 1024 * 1024:
                    raise ValueError('total budget exceeded')
                target = output / name / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        manifest['skills'] = [s for s in manifest['skills'] if s['id'] != name]
        manifest['skills'].append({'id': name, 'path': name, 'source': 'https://github.com/' + repo,
                                  'source_path': prefix, 'revision': revision, 'files': files,
                                  'status': 'staged_not_executed'})
        print(name, len(files), flush=True)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print('staged bytes:', total)


if __name__ == '__main__':
    main()
