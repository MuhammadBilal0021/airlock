"""Trusted synthetic scenarios and output oracles; never import specimen code."""
import json
import xml.etree.ElementTree as ET

IDS = {'figma-code-connect', 'figma-design-rules', 'jupyter-notebook',
       'plugin-creator', 'migrate-to-codex', 'anthropic-pdf', 'anthropic-pptx',
       'webapp-testing'}
PY = '/usr/bin/python3'


def prepare(package, name):
    def write(path, body):
        target = package / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding='utf-8')

    if name == 'figma-code-connect':
        write('_airlock_case.py', '''import subprocess
for value in ('123-456', '123:456'):
    subprocess.run(['/usr/bin/python3', 'scripts/normalize_node_id.py', value], check=True)
''')
        entry = [PY, '_airlock_case.py']
        purpose = 'Convert a synthetic Figma node ID in both URL/tool directions'
    elif name == 'figma-design-rules':
        write('_airlock_case.py', '''import subprocess
from pathlib import Path
root = Path('/tmp/synthetic-repository')
root.mkdir()
command = ['/bin/bash', '/work/scripts/check_agents_md.sh']
subprocess.run(command, cwd=root, check=True)
(root / 'AGENTS.md').write_text('# Synthetic repository instructions')
subprocess.run(command, cwd=root, check=True)
''')
        entry = [PY, '_airlock_case.py']
        purpose = 'Check both absent and present AGENTS.md branches in a synthetic repository'
    elif name == 'jupyter-notebook':
        entry = [PY, 'scripts/new_notebook.py', '--kind', 'tutorial', '--title',
                 'Airlock synthetic tutorial', '--out', '/output/tutorial.ipynb']
        purpose = 'Create a tutorial notebook from the real bundled template'
    elif name == 'plugin-creator':
        entry = [PY, 'scripts/create_basic_plugin.py', 'Airlock Sample', '--path',
                 '/output/plugins', '--with-skills', '--with-mcp']
        purpose = 'Generate a normalized plugin skeleton and an empty MCP configuration'
    elif name == 'migrate-to-codex':
        write('_source/.claude/skills/synthetic-skill/SKILL.md',
              '---\nname: synthetic-skill\ndescription: Synthetic migration input.\n---\n\nSYNTHETIC_MIGRATION_BODY\n')
        entry = [PY, 'scripts/migrate-to-codex.py', '--source', '/work/_source',
                 '--target', '/output/migrated', '--skills']
        purpose = 'Convert a synthetic Claude-style skill into a Codex skill directory'
    elif name == 'anthropic-pdf':
        fields = {'form_fields': [{'page_number': 1, 'description': 'Synthetic field',
            'label_bounding_box': [0, 0, 40, 20], 'entry_bounding_box': [50, 0, 100, 20],
            'entry_text': {'font_size': 12}}]}
        write('_valid.json', json.dumps(fields))
        fields['form_fields'][0]['entry_bounding_box'] = [20, 0, 100, 20]
        write('_overlap.json', json.dumps(fields))
        write('_airlock_case.py', '''import subprocess
for path in ('_valid.json', '_overlap.json'):
    print('CASE=' + path, flush=True)
    subprocess.run(['/usr/bin/python3', 'scripts/check_bounding_boxes.py', path], check=True)
''')
        entry = [PY, '_airlock_case.py']
        purpose = 'Validate disjoint PDF field boxes and detect a deliberately overlapping pair (JSON geometry only)'
    elif name == 'anthropic-pptx':
        presentation = ('<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                        '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>')
        write('_deck/ppt/presentation.xml', presentation)
        write('_deck/ppt/_rels/presentation.xml.rels',
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
              'Target="slides/slide1.xml"/></Relationships>')
        write('_deck/[Content_Types].xml',
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
              '<Override PartName="/ppt/slides/slide1.xml" '
              'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>')
        write('_deck/ppt/slides/slide1.xml',
              '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
              '<p:cSld name="Synthetic slide"/></p:sld>')
        entry = [PY, 'scripts/add_slide.py', '_deck', 'slide1.xml']
        purpose = 'Duplicate a synthetic unpacked slide and update slide IDs, relationships and content types'
    elif name == 'webapp-testing':
        write('_web/index.html', 'AIRLOCK_SYNTHETIC_HTTP_BODY')
        write('_client.py', '''import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open('http://127.0.0.1:18765/', timeout=3) as response:
    body = response.read(1024).decode()
assert body == 'AIRLOCK_SYNTHETIC_HTTP_BODY', repr(body)
print('HTTP_BODY_CONFIRMED')
''')
        entry = [PY, 'scripts/with_server.py', '--server',
                 '/usr/bin/python3 -m http.server 18765 --bind 127.0.0.1 --directory /work/_web',
                 '--port', '18765', '--timeout', '4', '--', PY, '_client.py']
        purpose = 'Start an isolated local HTTP server, wait for readiness, fetch exact synthetic content and stop'
    else:
        raise ValueError(name)
    return entry, purpose, {'type': 'synthetic', 'description': purpose}


def validate(name, result):
    contents = {e.sandbox_path: e.content for e in result.fs_events
                if e.change in ('created', 'modified') and not e.truncated}
    if name == 'figma-code-connect':
        return result.stdout.splitlines() == ['123:456', '123-456']
    if name == 'figma-design-rules':
        return result.stdout.splitlines() == ['AGENTS.md not found', 'AGENTS.md found']
    if name == 'jupyter-notebook':
        doc = json.loads(contents['/output/tutorial.ipynb'])
        return (doc['nbformat'] == 4 and doc['cells'][0]['cell_type'] == 'markdown' and
                doc['cells'][0]['source'][0] == '# Tutorial: Airlock synthetic tutorial\n' and len(doc['cells']) > 1)
    if name == 'plugin-creator':
        doc = json.loads(contents['/output/plugins/airlock-sample/.codex-plugin/plugin.json'])
        return (doc['name'] == 'airlock-sample' and
                json.loads(contents['/output/plugins/airlock-sample/.mcp.json']) == {'mcpServers': {}})
    if name == 'migrate-to-codex':
        return any(path.startswith('/output/migrated/') and path.endswith('/synthetic-skill/SKILL.md')
                   and 'SYNTHETIC_MIGRATION_BODY' in content for path, content in contents.items())
    if name == 'anthropic-pdf':
        good, bad = result.stdout.split('CASE=_overlap.json')
        return ('SUCCESS: All bounding boxes are valid' in good and 'FAILURE:' not in good
                and 'FAILURE: intersection between label and entry' in bad)
    if name == 'anthropic-pptx':
        ns = {'p': 'http://schemas.openxmlformats.org/presentationml/2006/main'}
        slides = ET.fromstring(contents['/work/_deck/ppt/presentation.xml']).findall('.//p:sldId', ns)
        return (len(slides) == 2 and len({s.attrib['id'] for s in slides}) == 2
                and 'Synthetic slide' in contents['/work/_deck/ppt/slides/slide2.xml']
                and 'slides/slide2.xml' in contents['/work/_deck/ppt/_rels/presentation.xml.rels']
                and '/ppt/slides/slide2.xml' in contents['/work/_deck/[Content_Types].xml'])
    if name == 'webapp-testing':
        return all(value in result.stdout for value in
                   ('HTTP_BODY_CONFIRMED', 'Server ready on port 18765', 'All servers stopped'))
    raise ValueError(name)
