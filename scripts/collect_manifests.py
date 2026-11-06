"""Collect a pinned declaration-only pilot from OpenClaw's bundled skills."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.scan_dataset import run


def main():
    root = ROOT / 'research'
    tree = json.loads((root / 'tree.json').read_text(encoding='utf-8-sig'))
    revision = tree['sha']
    candidates = sorted(x['path'] for x in tree['tree']
                        if x['type'] == 'blob' and x['path'].startswith('skills/')
                        and x['path'].endswith('/SKILL.md'))
    # Deterministic sample of the returned tree, explicitly not a prevalence sample.
    chosen = sorted(candidates, key=lambda p: hashlib.sha256(p.encode()).hexdigest())[:50]
    corpus = root / 'manifest-sample'
    corpus.mkdir(exist_ok=False)

    def fetch(pair):
        index, path = pair
        url = 'https://raw.githubusercontent.com/openclaw/openclaw/' + revision + '/' + path
        with urllib.request.urlopen(url, timeout=45) as response:
            data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('manifest exceeds size limit')
        folder = corpus / str(index)
        folder.mkdir()
        (folder / 'SKILL.md').write_bytes(data)
        return {'id': path, 'path': str(index), 'source': url, 'revision': revision,
                'files': {'SKILL.md': hashlib.sha256(data).hexdigest()}}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        skills = list(pool.map(fetch, enumerate(chosen)))
    manifest = {'population': 'OpenClaw bundled skills, not the ClawHub registry',
                'scope': 'SKILL.md only; supporting code not collected or executed',
                'selection': 'first 50 by SHA-256(path) from returned GitHub tree',
                'tree_truncated': tree.get('truncated', False),
                'candidate_count': len(candidates), 'skills': skills}
    path = corpus / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    run(path, root / 'first-reports', static_only=True)
    print((root / 'first-reports' / 'summary.json').read_text())


if __name__ == '__main__':
    main()
