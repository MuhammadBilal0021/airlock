"""Acquire a pinned, hash-frozen benign skill corpus from public repositories.

Deterministic by construction: sources are pinned to a commit SHA, candidates are
ordered by SHA-256 of their repository-relative path, and selection takes the
first N per source. Re-running against the same commit SHA reproduces the same
bytes and therefore the same manifest.

Only text artefacts are acquired. Symlinks are refused, never followed. The
script never installs or executes what it downloads.

    python scripts/acquire_corpus.py --output research/corpus-001/benign

Requires network access; the resulting corpus is self-contained and does not.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

TEXT_SUFFIXES = {'.md', '.py', '.sh', '.js', '.ts', '.json', '.yaml', '.yml',
                 '.txt', '.toml'}
MAX_FILE_BYTES = 256 * 1024
MAX_PACKAGE_BYTES = 1024 * 1024
USER_AGENT = 'airlock-corpus-acquisition'
# Hidden directories are legitimate skill locations (``.claude/skills``,
# ``.agents/skills``); only version-control internals are skipped.
SKIP_PARTS = {'.git'}

# quota per source; total target 200 after duplicate removal.
# Availability measured 2026-11-07: wshobson 185, openclaw 137, anthropics 20,
# obra 15, modelcontextprotocol 11.
SOURCES = [
    {'repo': 'wshobson/agents', 'ref': 'main', 'quota': 110},
    {'repo': 'openclaw/openclaw', 'ref': 'main', 'quota': 90},
    {'repo': 'anthropics/skills', 'ref': 'main', 'quota': 20},
    {'repo': 'obra/superpowers', 'ref': 'main', 'quota': 15},
    {'repo': 'modelcontextprotocol/servers', 'ref': 'main', 'quota': 11},
]


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def resolve_commit(repo: str, ref: str) -> str:
    payload = json.loads(get(f'https://api.github.com/repos/{repo}/commits/{ref}'))
    return payload['sha']


def tarball_bytes(repo: str, sha: str) -> bytes:
    return get(f'https://codeload.github.com/{repo}/tar.gz/{sha}')


def safe_members(tar: tarfile.TarFile, root: str):
    """Yield regular files under the archive's single top directory only."""
    for member in tar.getmembers():
        if member.issym() or member.islnk():
            continue
        if not member.isfile():
            continue
        path = PurePosixPath(member.name)
        if path.parts[0] != root or len(path.parts) < 2:
            continue
        if any(part in SKIP_PARTS for part in path.parts[1:]):
            continue
        yield member, path


def fingerprint(root: Path) -> dict:
    hashes = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink present in acquired package')
        if path.is_file():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()).hexdigest()
    return hashes


def select(tar: tarfile.TarFile, root: str, quota: int):
    """Return selected skill directories plus exclusion records."""
    skill_dirs = set()
    files_by_dir = {}
    excluded = []
    for member, path in safe_members(tar, root):
        parts = path.parts[1:]
        if parts[-1].lower() not in ('skill.md',):
            continue
        skill_dir = '/'.join(parts[:-1])
        if skill_dir:
            skill_dirs.add(skill_dir)

    for member, path in safe_members(tar, root):
        parts = path.parts[1:]
        parent = '/'.join(parts[:-1])
        for candidate in skill_dirs:
            if parent == candidate or parent.startswith(candidate + '/'):
                files_by_dir.setdefault(candidate, []).append((member, path))
                break

    ordered = sorted(skill_dirs, key=lambda d: hashlib.sha256(d.encode()).hexdigest())
    chosen, per_dir_index = [], {}
    for skill_dir in ordered:
        if len(chosen) >= quota:
            break
        entries = files_by_dir.get(skill_dir, [])
        kept, total, reason = [], 0, None
        for member, path in sorted(entries, key=lambda e: e[1].as_posix()):
            relative = path.as_posix()[len(root) + 1 + len(skill_dir) + 1:]
            if PurePosixPath(relative).suffix.lower() not in TEXT_SUFFIXES:
                continue
            if member.size > MAX_FILE_BYTES:
                reason = f'file exceeds {MAX_FILE_BYTES} bytes: {relative}'
                continue
            total += member.size
            if total > MAX_PACKAGE_BYTES:
                reason = f'package exceeds {MAX_PACKAGE_BYTES} bytes of text'
                break
            kept.append((member, path, relative))
        if not kept:
            excluded.append({'skill_dir': skill_dir, 'reason': reason or 'no text files'})
            continue
        if reason:
            excluded.append({'skill_dir': skill_dir, 'reason': reason})
            continue
        chosen.append((skill_dir, kept))
        per_dir_index[skill_dir] = len(chosen) - 1
    return chosen, ordered, excluded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()

    output = Path(args.output).resolve()
    if output.exists():
        if not args.force:
            print(f'{output} already exists; pass --force to rebuild', file=sys.stderr)
            return 2
        shutil.rmtree(output)
    output.mkdir(parents=True)

    skills, exclusions, revisions = [], [], {}
    seen_skill_md: set[str] = set()
    counter = 0
    for source in SOURCES:
        repo, ref = source['repo'], source['ref']
        sha = resolve_commit(repo, ref)
        revisions[repo] = sha
        print(f'[{repo}@{sha[:12]}] downloading tarball', flush=True)
        with tempfile.TemporaryDirectory() as tmp:
            blob = tarball_bytes(repo, sha)
            with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as tar:
                root = tar.getmembers()[0].name.split('/')[0]
                chosen, ordered, excluded = select(tar, root, source['quota'])
                print(f'  {len(ordered)} skill dirs available, {len(chosen)} selected, '
                      f'{len(excluded)} excluded', flush=True)
                for reason in excluded:
                    exclusions.append({'repo': repo, **reason})
                for skill_dir, kept in chosen:
                    # Identical SKILL.md text means the same skill republished;
                    # counting it twice would inflate n without adding evidence.
                    skill_md = next((entry for entry in kept
                                     if entry[2].lower() == 'skill.md'), None)
                    if skill_md is not None:
                        digest = hashlib.sha256(
                            tar.extractfile(skill_md[0]).read()).hexdigest()
                        if digest in seen_skill_md:
                            exclusions.append({'repo': repo, 'skill_dir': skill_dir,
                                               'reason': 'duplicate SKILL.md content'})
                            continue
                        seen_skill_md.add(digest)
                    slug = f'{counter:03d}'
                    destination = output / slug
                    for member, path, relative in kept:
                        target = destination / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(tar.extractfile(member).read())
                    skills.append({
                        'id': f'{repo}:{skill_dir}',
                        'path': slug,
                        'source': f'https://github.com/{repo}/tree/{sha}/{skill_dir}',
                        'revision': sha,
                        'files': fingerprint(destination),
                        'label': 'benign',
                    })
                    counter += 1

    (output / 'manifest.json').write_text(json.dumps({
        'population': 'public agent-skill packages, five repositories',
        'scope': 'text artefacts only; nothing installed or executed',
        'selection': 'first N repository-relative skill dirs ordered by '
                     'sha256(path) within each source; packages whose SKILL.md '
                     'content duplicates an earlier package are dropped',
        'target_n': 200,
        'acquired_n': len(skills),
        'revisions': revisions,
        'skills': skills,
    }, indent=2), encoding='utf-8')
    (output / 'exclusions.json').write_text(json.dumps(exclusions, indent=2),
                                            encoding='utf-8')
    print(f'acquired {len(skills)} packages, {len(exclusions)} exclusions')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
