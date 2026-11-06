"""Read-only GitHub tree inventory; no downloaded code is executed."""
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

for repo in ('openai/skills', 'anthropics/skills'):
    req = urllib.request.Request('https://api.github.com/repos/' + repo + '/git/trees/main?recursive=1',
                                 headers={'User-Agent': 'airlock-research'})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError('tree exceeds budget')
    tree = json.loads(data)
    if tree.get('truncated'):
        raise ValueError('truncated tree')
    target = ROOT / 'research' / (repo.replace('/', '-') + '-tree.json')
    if target.exists():
        tree = json.loads(target.read_text())
    else:
        target.write_text(json.dumps(tree, indent=2))
    print(repo, tree['sha'])
    for entry in tree['tree']:
        if entry['type'] == 'blob' and '/scripts/' in entry['path'] and entry['path'].endswith(('.py', '.sh', '.js')):
            print(entry['path'])
