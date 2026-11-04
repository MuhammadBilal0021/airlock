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


@dataclass
class FileState:
    size: int
    mtime_ns: int
    atime_ns: int
    sha256: str


@dataclass
class FsEvent:
    sandbox_path: str
    change: str          # created | modified | deleted | read
    host_path: str
    size: int = 0
    content: str = ""
    truncated: bool = False
    secret_id: str = ""

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


def snapshot_dir(host_dir: Path) -> dict:
    """Stat-only walk.

    Deliberately does not open any file: reading content here would advance
    atime and make every planted secret look like it had been read by the skill.
    Modification is detected from size+mtime, and content is fetched only after
    the diff has been computed. (Phase 2 replaces this with an overlayfs
    upper-dir diff, which is exact and immune to mtime preservation.)
    """
    out = {}
    if not host_dir.exists():
        return out
    for dirpath, _d, filenames in os.walk(host_dir):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                st = p.lstat()
            except OSError:
                continue
            if not p.is_file():
                continue
            out[str(p)] = FileState(st.st_size, st.st_mtime_ns, st.st_atime_ns, "")
    return out


def _read_text(p: Path, limit: int = _MAX_FILE_BYTES):
    try:
        data = p.read_bytes()[:limit]
    except OSError:
        return "", False
    return data.decode("utf-8", errors="replace"), len(data) >= limit


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
    """Most isolated first; fall back only if the kernel refuses."""
    b = ["unshare"]
    return [
        b + ["--user", "--map-root-user", "--mount", "--net", "--pid", "--fork"],
        b + ["--mount", "--net", "--pid", "--fork"],
        b + ["--user", "--map-root-user", "--mount", "--net", "--fork"],
    ]


def run_skill(skill_path: Path, *, entry: list, timeout: float = 60.0,
              run_dir: Path | None = None, extra_env: dict | None = None) -> RunResult:
    """Execute ``entry`` against ``skill_path`` in the sandbox and collect evidence."""
    skill_path = Path(skill_path).resolve()
    run, ds = build_sandbox(skill_path, run_dir=run_dir)

    baseline = {rel: snapshot_dir(run / rel) for rel, _ in JOURNALED}

    cfg = {"run_dir": str(run), "rootfs": str(run / "rootfs"), "repo_root": _REPO_ROOT,
           "entry": entry, "timeout": timeout, "env": extra_env or {}}
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
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"meta.json unreadable: {exc}")
    else:
        errors.append("sandbox produced no meta.json -- it may have failed to start")

    if (proc.returncode != 0 or not isinstance(meta, dict)
            or meta.get("phase") != "complete"):
        errors.append("namespace runner did not complete; no behavioural assurance")
        return RunResult(False, run, None, False, time.time() - t0,
                         errors=errors, decoys=ds, entry=list(entry))

    return RunResult(
        ok=True, run_dir=run, exit_code=meta.get("exit_code"),
        timed_out=bool(meta.get("timed_out")),
        duration_s=float(meta.get("duration_s", round(time.time() - t0, 3))),
        fs_events=_diff_filesystems(run, baseline, ds),
        net_events=_read_capture(run / "capture.jsonl"),
        processes=meta.get("processes", []),
        stdout=_read_text(run / "stdout.txt")[0],
        stderr=_read_text(run / "stderr.txt")[0],
        meta=meta,
        errors=errors + ([f"namespace flags: {' '.join(used[1:])}"] if used else []),
        decoys=ds,
        entry=list(entry),
    )


def _sandbox_path(run: Path, host_path: str) -> str:
    for rel, sbx in JOURNALED:
        prefix = str(run / rel)
        if host_path == prefix:
            return sbx
        if host_path.startswith(prefix + os.sep):
            return f"{sbx.rstrip('/')}/{host_path[len(prefix) + 1:]}"
    return host_path


def _diff_filesystems(run: Path, baseline, ds: DecoySet) -> list:
    events = []
    secret_by_host = {}
    for sec in ds.secrets:
        for rel, sbx in JOURNALED:
            if sec.path == sbx or sec.path.startswith(sbx.rstrip("/") + "/"):
                tail = sec.path[len(sbx.rstrip("/")):].lstrip("/")
                secret_by_host[str(run / rel / tail)] = sec.secret_id

    for rel, _sbx in JOURNALED:
        host_dir = run / rel
        after = snapshot_dir(host_dir)
        before = baseline.get(rel, {})
        for hp, st_after in after.items():
            st_before = before.get(hp)
            sp = _sandbox_path(run, hp)
            sid = secret_by_host.get(hp, "")
            if st_before is None:
                content, trunc = _read_text(Path(hp))
                events.append(FsEvent(sp, "created", hp, st_after.size, content, trunc, sid))
            elif (st_before.size != st_after.size
                  or st_before.mtime_ns != st_after.mtime_ns):
                content, trunc = _read_text(Path(hp))
                events.append(FsEvent(sp, "modified", hp, st_after.size, content, trunc, sid))
            elif (st_after.atime_ns > st_before.atime_ns
                  and st_after.atime_ns > decoys.ATIME_ANCHOR * 10**9):
                # Content unchanged but access time advanced: the file was read.
                events.append(FsEvent(sp, "read", hp, st_after.size, "", False, sid))
        for hp in before:
            if hp not in after:
                events.append(FsEvent(_sandbox_path(run, hp), "deleted", hp, 0, "", False,
                                      secret_by_host.get(hp, "")))
    return events


def _read_capture(path: Path) -> list:
    events = []
    if not path.exists():
        return events
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def cleanup(run_dir: Path) -> None:
    shutil.rmtree(run_dir, ignore_errors=True)
