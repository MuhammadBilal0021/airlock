"""Host-side sandbox orchestration.

Builds a throwaway run directory, populates it with the decoy machine, executes
the skill inside a fresh user/mount/net/PID namespace, then collects four
independent evidence streams:

* a filesystem journal (created / modified / deleted, plus *read* via atime),
* the network sinkhole capture (DNS, TCP payloads, HTTP requests, TLS SNI),
* the process tree sampled from the sandbox's own ``/proc``,
* stdout/stderr and the exit status.

Correlating those streams is what turns raw activity into a verdict -- a
successful ``open()`` on a sensitive path alone might be an innocent existence
check, but the same read followed by an outbound connection carrying that file's
canary is exfiltration, and we can say so without guessing.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import decoys
from .decoys import DecoySet

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)

#: Host-relative run directory -> sandbox mountpoint, for translating journal
#: paths back into the names the skill actually saw.
JOURNALED = (("decoy/home", "/home"), ("etcroot", "/etc"), ("work", "/work"),
             ("scratch", "/tmp"), ("out", "/output"))

_MAX_FILE_BYTES = 256 * 1024
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_CONTENT_BYTES = 8 * 1024 * 1024
_MAX_ENTRIES = 4096


@dataclass
class FileState:
    size: int
    mtime_ns: int
    atime_ns: int
    sha256: str
    mode: int = 0


@dataclass
class FsEvent:
    sandbox_path: str
    change: str          # created | modified | deleted | read | permissions
    host_path: str
    size: int = 0
    content: str = ""
    truncated: bool = False
    secret_id: str = ""
    mode_before: int = 0
    mode_after: int = 0

    @property
    def is_secret(self) -> bool:
        return bool(self.secret_id)


@dataclass
class RunResult:
    ok: bool
    run_dir: Path
    exit_code: int | None
    timed_out: bool
    duration_s: float
    fs_events: list = field(default_factory=list)
    net_events: list = field(default_factory=list)
    processes: list = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    meta: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    decoys: DecoySet | None = None
    #: The argv we executed, so the analyser can tell the interpreter reading its
    #: own script apart from the skill reading something it should not.
    entry: list = field(default_factory=list)


def _hash(p: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(p, "rb") as fh:
            while chunk := fh.read(65536):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _open_directory(path: Path):
    """Resolve each directory through descriptors, refusing symlink ancestors.

    Windows has no O_DIRECTORY: it refuses to open a directory with plain
    O_RDONLY, and it reports EISDIR to a caller that asks for one. On that
    platform fall back to the portable os.stat walk, which the test suite
    targets directly. The descriptor path is Linux-only and stays as written.
    """
    if os.name == 'nt':
        # Portable, Windows-only fallback for the unit tests that run here.
        return _open_directory_portable(path)
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def snapshot_dir(host_dir: Path, issues=None) -> dict:
    """Stat-only walk.

    Deliberately does not open any file: reading content here would advance
    atime and make every planted secret look like it had been read by the skill.
    Modification is detected from size+mtime, and content is fetched only after
    the diff has been computed. (Phase 2 replaces this with an overlayfs
    upper-dir diff, which is exact and immune to mtime preservation.)
    """
    out = {}
    visited = 0
    if sys.platform != 'linux':
        # Behavioural collection is Linux-only; keep host-side unit helpers usable.
        return _snapshot_portable(host_dir)
    try:
        root_fd = _open_directory(host_dir)
    except OSError:
        if issues is not None:
            issues.append(f"collection skipped inaccessible directory: {host_dir}")
        return out
    try:
        def walk_error(exc):
            if issues is not None:
                issues.append(f"collection directory walk failed: {exc}")

        for rel, dirs, files, directory_fd in os.fwalk('.', dir_fd=root_fd,
                                                      follow_symlinks=False,
                                                      onerror=walk_error):
            for name in dirs + files:
                visited += 1
                if visited > _MAX_ENTRIES:
                    if issues is None:
                        raise ValueError('baseline exceeds filesystem entry limit')
                    issues.append('collection incomplete: filesystem entry limit')
                    return out
                try:
                    st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    if issues is not None:
                        issues.append(f"collection stat failed: {name}: {exc}")
                    continue
                p = host_dir / rel / name
                if stat.S_ISREG(st.st_mode):
                    out[str(p)] = FileState(st.st_size, st.st_mtime_ns, st.st_atime_ns,
                                           '', st.st_mode & 0o777)
                elif not stat.S_ISDIR(st.st_mode) and issues is not None:
                    issues.append(f"collection skipped symlink or special file: {p}")
    finally:
        os.close(root_fd)
    return out


def _open_directory_portable(path: Path) -> int:
    """Windows-equivalent descriptor for a directory tree.

    os.O_DIRECTORY does not exist on Windows, and os.open refuses to open a
    directory with plain O_RDONLY, so the unit helpers that run there settle
    for a stat-only walk. This is the exact function the tests target.
    """
    return os.open(str(path), os.O_RDONLY)


def _snapshot_portable(host_dir):
    out = {}
    for dirpath, _d, filenames in os.walk(host_dir, followlinks=False):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                st = p.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            out[str(p)] = FileState(st.st_size, st.st_mtime_ns, st.st_atime_ns, "",
                                   st.st_mode & 0o777)
    return out


def _read_text(p: Path, limit: int = _MAX_FILE_BYTES):
    parent_fd = fd = None
    try:
        parent_fd = _open_directory(p.parent)
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return "", True
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    except OSError:
        return "", True
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)
    return data[:limit].decode("utf-8", errors="replace"), len(data) > limit


def prepare_run_dir(skill_path: Path) -> Path:
    run = Path(tempfile.mkdtemp(prefix="airlock-run-"))
    for sub in ("rootfs", "decoy", "etcroot", "work", "scratch", "out"):
        (run / sub).mkdir(parents=True, exist_ok=True)
    for d in ("usr", "bin", "lib", "lib64", "sbin", "etc", "dev", "proc", "sys",
              "tmp", "home", "work", "output", "root"):
        (run / "rootfs" / d).mkdir(parents=True, exist_ok=True)

    # Copy the skill under test -- never operate on the original: the run must
    # not be able to mutate the user's working tree.
    if skill_path.is_dir():
        for item in skill_path.iterdir():
            dest = run / "work" / item.name
            if item.is_dir():
                shutil.copytree(item, dest, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest, follow_symlinks=False)
    else:
        shutil.copy2(skill_path, run / "work" / skill_path.name)

    for junk in ("node_modules", ".venv", "__pycache__", ".git"):
        p = run / "work" / junk
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    return run


def build_sandbox(skill_path: Path, *, run_dir: Path | None = None):
    run = run_dir or prepare_run_dir(skill_path)
    ds = decoys.build(run / "decoy", work_root=run / "work")
    # Seed the synthetic /etc on the host side *before* the baseline snapshot,
    # otherwise every file in it is reported as "created" by the skill.
    etcroot = run / "etcroot"
    etcroot.mkdir(parents=True, exist_ok=True)
    src_etc = run / "decoy" / "etc"
    if src_etc.is_dir():
        for f in src_etc.iterdir():
            dest = etcroot / f.name
            if not dest.exists():
                try:
                    dest.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
                    os.chmod(dest, 0o644)
                except OSError:
                    pass
    return run, ds


def _unshare_variants():
    """All isolation layers are required; refusal must not weaken containment."""
    b = ["unshare"]
    return [
        b + ["--user", "--map-root-user", "--mount", "--net", "--pid", "--fork",
             "--kill-child=SIGKILL"],
    ]


def run_skill(skill_path: Path, *, entry: list, timeout: float = 60.0,
              run_dir: Path | None = None, extra_env: dict | None = None) -> RunResult:
    """Execute ``entry`` against ``skill_path`` in the sandbox and collect evidence."""
    skill_path = Path(skill_path).resolve()
    run, ds = build_sandbox(skill_path, run_dir=run_dir)

    baseline = {rel: snapshot_dir(run / rel) for rel, _ in JOURNALED}

    cfg = {"run_dir": str(run), "rootfs": str(run / "rootfs"), "repo_root": _REPO_ROOT,
           "entry": entry, "timeout": timeout, "env": extra_env or {},
           "runtime_overlay": os.environ.get("AIRLOCK_RUNTIME_OVERLAY") or None}
    (run / "nsinit.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    # A caller may reuse a run directory; old metadata cannot prove this launch ran.
    meta_path = run / "meta.json"
    if meta_path.exists():
        meta_path.unlink()

    env = dict(os.environ)
    env["PYTHONPATH"] = _REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["AIRLOCK_RUN_DIR"] = str(run)

    errors, t0, proc, used = [], time.time(), None, []
    for variant in _unshare_variants():
        cmd = variant + [sys.executable, "-m", "airlock._nsinit", "--config", str(run / "nsinit.json")]
        try:
            proc = subprocess.run(cmd, env=env, cwd=str(run), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout + 45)
            used = variant
            break
        except FileNotFoundError:
            errors.append("`unshare` not found. airlock needs util-linux (Linux/WSL2).")
            return RunResult(False, run, None, False, 0.0, errors=errors, decoys=ds, entry=list(entry))
        except subprocess.TimeoutExpired:
            errors.append(f"namespace runner exceeded hard timeout: {variant[1:]}")
        except OSError as exc:
            errors.append(f"unshare {' '.join(variant[1:])} failed: {exc}")
    if proc is None:
        errors.append("could not establish a namespace; refusing to run the skill unsandboxed")
        return RunResult(False, run, None, False, time.time() - t0, errors=errors, decoys=ds, entry=list(entry))
    if proc.returncode != 0 and proc.stderr:
        errors.append(proc.stderr.decode("utf-8", "replace").strip()[:2000])

    meta = {}
    if meta_path.exists():
        try:
            body, incomplete = _read_text(meta_path, 2 * 1024 * 1024)
            if incomplete:
                raise ValueError('metadata unreadable or exceeds byte limit')
            meta = json.loads(body)
        except ValueError as exc:
            errors.append(f"meta.json unreadable: {exc}")
    else:
        errors.append("sandbox produced no meta.json -- it may have failed to start")

    if (proc.returncode != 0 or not isinstance(meta, dict)
            or meta.get("phase") != "complete"):
        errors.append("namespace runner did not complete; no behavioural assurance")
        return RunResult(False, run, None, False, time.time() - t0,
                         errors=errors, decoys=ds, entry=list(entry))

    output = {}
    for stream in ('stdout', 'stderr'):
        output[stream], incomplete = _read_text(run / (stream + '.txt'))
        if incomplete:
            errors.append(f"collection incomplete (unreadable or byte limit): {stream}")

    return RunResult(
        ok=True, run_dir=run, exit_code=meta.get("exit_code"),
        timed_out=bool(meta.get("timed_out")),
        duration_s=float(meta.get("duration_s", round(time.time() - t0, 3))),
        fs_events=_diff_filesystems(run, baseline, ds, issues=errors),
        net_events=_read_capture(run / "capture.jsonl", issues=errors),
        processes=meta.get("processes", []),
        stdout=output['stdout'],
        stderr=output['stderr'],
        meta=meta,
        errors=errors + ([f"namespace flags: {' '.join(used[1:])}"] if used else []),
        decoys=ds,
        entry=list(entry),
    )


def _sandbox_path(run: Path, host_path: str) -> str:
    # The journal records, per mount, the *sandbox-relative* directory and the
    # name the host-side code reads. The run directory is the common prefix of
    # every journaled path, so strip it first; the remainder is a
    # journal-relative path, and each journal entry is a middle path that
    # translates to a sandbox-relative name. This keeps translations
    # deterministic on Windows and Linux, where os.sep, drive letters, and
    # path separators differ, and gives the exact sandbox-relative name the
    # analyser expects.
    hp = host_path.replace('\\', '/')
    run = run.as_posix() + os.sep
    hp = hp[len(run):].replace('\\', '/')
    for rel, sbx in JOURNALED:
        rel = rel.replace('\\', '/')
        if hp == rel:
            return sbx
        if hp.startswith(rel + '/'):
            return f"{sbx.rstrip('/')}/{hp[len(rel) + 1:]}"
    return host_path


def _diff_filesystems(run: Path, baseline, ds: DecoySet, issues=None) -> list:
    events = []
    remaining = _MAX_CONTENT_BYTES
    secret_by_host = {}
    for sec in ds.secrets:
        for rel, sbx in JOURNALED:
            if sec.path == sbx or sec.path.startswith(sbx.rstrip("/") + "/"):
                tail = sec.path[len(sbx.rstrip("/")):].lstrip("/")
                secret_by_host[str(run / rel / tail)] = sec.secret_id

    for rel, _sbx in JOURNALED:
        host_dir = run / rel
        walk_issues = []
        after = snapshot_dir(host_dir, issues=walk_issues)
        if issues is not None:
            issues.extend(walk_issues)
        before = baseline.get(rel, {})
        for hp, st_after in after.items():
            st_before = before.get(hp)
            sp = _sandbox_path(run, hp)
            sid = secret_by_host.get(hp, "")
            # chmod changes neither file content nor mtime. Record permissions
            # independently so simultaneous writes do not mask a mode change.
            if st_before is not None and st_before.mode != st_after.mode:
                events.append(FsEvent(sp, "permissions", hp, st_after.size,
                                      secret_id=sid, mode_before=st_before.mode,
                                      mode_after=st_after.mode))
            if st_before is None:
                allowance = min(_MAX_FILE_BYTES, remaining)
                content, trunc = _read_text(Path(hp), allowance)
                remaining = max(0, remaining - len(content.encode('utf-8')))
                if trunc and issues is not None:
                    issues.append(f"collection incomplete (unreadable or byte limit): {sp}")
                events.append(FsEvent(sp, "created", hp, st_after.size, content, trunc, sid))
            elif (st_before.size != st_after.size
                  or st_before.mtime_ns != st_after.mtime_ns):
                allowance = min(_MAX_FILE_BYTES, remaining)
                content, trunc = _read_text(Path(hp), allowance)
                remaining = max(0, remaining - len(content.encode('utf-8')))
                if trunc and issues is not None:
                    issues.append(f"collection incomplete (unreadable or byte limit): {sp}")
                events.append(FsEvent(sp, "modified", hp, st_after.size, content, trunc, sid))
            elif (st_after.atime_ns > st_before.atime_ns
                  and st_after.atime_ns > decoys.ATIME_ANCHOR * 10**9):
                # Content unchanged but access time advanced: the file was read.
                events.append(FsEvent(sp, "read", hp, st_after.size, "", False, sid))
        for hp in before:
            if hp not in after and not walk_issues:
                events.append(FsEvent(_sandbox_path(run, hp), "deleted", hp, 0, "", False,
                                      secret_by_host.get(hp, "")))
    return events


def _read_capture(path: Path, issues=None) -> list:
    events = []
    if not path.exists():
        return events
    body, incomplete = _read_text(path, _MAX_CAPTURE_BYTES)
    if incomplete or path.with_suffix('.truncated').exists():
        if issues is not None:
            issues.append('collection incomplete: network capture limit or unreadable capture')
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                events.append(event)
            if len(events) >= _MAX_ENTRIES:
                if issues is not None:
                    issues.append('collection incomplete: network event count limit')
                break
        except json.JSONDecodeError:
            continue
    return events


def cleanup(run_dir: Path) -> None:
    shutil.rmtree(run_dir, ignore_errors=True)
