"""Measure how much behavioural coverage is reachable without any LLM.

For each benign package: does it ship code, and does its SKILL.md document a
concrete invocation we could synthesise a harness from? This is a ceiling
estimate, not a scanner.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

CORPUS = Path('research/corpus-001/benign')

# A documented invocation: a fenced block line that runs a script with python,
# bash/sh or node, or an indented `$ python ...` example.
COMMAND = re.compile(
    r'(?:^|[\s$>])(?:python3?|bash|sh|node)\s+(?P<script>[\w./-]+\.(?:py|sh|js))'
    r'|(?:^|[\s$>])(?P<bare>[\w./-]+\.(?:py|sh|js))\s+(?:--|-|[\w./-]+)',
    re.MULTILINE)


def main() -> None:
    manifest = json.loads((CORPUS / 'manifest.json').read_text(encoding='utf-8'))
    stats = Counter()
    examples = []
    for skill in manifest['skills']:
        root = CORPUS / skill['path']
        tree = root.rglob('*')
        code = [p for p in tree if p.is_file()
                and p.suffix in ('.py', '.sh', '.js')
                and not p.is_symlink()]
        skill_md = root / 'SKILL.md'
        text = skill_md.read_text(encoding='utf-8', errors='replace') if skill_md.exists() else ''
        commands = [m.group('script') or m.group('bare') for m in COMMAND.finditer(text)]

        stats['total'] += 1
        if code:
            stats['ships_code'] += 1
        if commands:
            stats['documents_invocation'] += 1
        if code and commands:
            stats['both'] += 1
            if len(examples) < 12:
                examples.append((skill['id'], commands[0], len(code)))

    print(json.dumps(dict(stats), indent=2))
    print(f"\nreachable ceiling (code + documented invocation): "
          f"{stats['both']}/{stats['total']} = "
          f"{100 * stats['both'] / stats['total']:.1f} %")
    print("\nexamples:")
    for identifier, command, n in examples:
        print(f"  {identifier}\n    -> {command}   ({n} code files)")


if __name__ == '__main__':
    main()
