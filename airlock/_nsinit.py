"""Namespace init -- runs as PID 1 inside the sandbox. Never imported by the CLI.

Invoked as::

    unshare --user --map-root-user --mount --net --pid --fork \
        python3 -m airlock._nsinit --config <run>/nsinit.json

Responsibilities, in order:

1. Detach the mount tree from the host (``MS_REC|MS_PRIVATE``) so nothing we do
   propagates back out.
2. Build the synthetic root: read-only bind of the host's runtime directories
   (so ``sh``/``python3`` exist), read-write binds of the decoy home, the skill
   copy, and scratch/output areas we journal afterwards.
3. Mount a *fresh* procfs if the kernel allows it. If it does not -- common in
   nested containers -- fall back to an inert tmpfs and record that fact, because
   a report must never claim coverage it did not have.
4. Start the network sinkhole in the same netns but outside the chroot.
5. Fork: the child chroots and execs the skill; the parent enforces the timeout
   and samples ``/proc`` to reconstruct the process tree.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

libc = ctypes.CDLL("libc.so.6", use_errno=True)
_NULL = ctypes.c_char_p(None)

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_BIND, MS_REMOUNT, MS_REC, MS_PRIVATE = 4096, 32, 16384, 1 << 18

HOST_RO_BINDS = ("usr", "bin", "lib", "lib32", "lib64", "libx32", "sbin")


def _mount(src, target, fstype, flags, data=None):
    os.makedirs(target, exist_ok=True)
    r = libc.mount(src.encode() if src else _NULL, target.encode(),
                   fstype.encode() if fstype else _NULL, flags,
                   data.encode() if data else _NULL)
    return (True, "") if r == 0 else (False, f"errno={ctypes.get_errno()} {os.strerror(ctypes.get_errno())}")


class MountLog:
    def __init__(self): self.entries = []
    def add(self, what, target, ok, err=""):
        self.entries.append({"what": what, "target": target, "ok": ok, "error": err})


def _fake_proc(proc: Path) -> None:
    for name, body in {
        "loadavg": "0.00 0.00 0.00 1/1 1\n",
        "cpuinfo": "processor\t: 0\nmodel name\t: airlock sandbox\n",
        "meminfo": "MemTotal:        4194304 kB\nMemAvailable:    3000000 kB\n",
        "version": "Linux version 6.6.0-airlock (sandbox)\n",
        "uptime": "1.00 0.50\n",
        "filesystems": "nodev\tsysfs\nnodev\ttmpfs\n\text4\n",
    }.items():
        try:
            (proc / name).write_text(body, encoding="utf-8")
        except OSError:
            pass


def setup_mounts(cfg: dict, mlog: MountLog) -> dict:
    rootfs, run = Path(cfg["rootfs"]), Path(cfg["run_dir"])
    coverage = {"proc": "none", "dev": "none", "network_isolated": True, "etc": "none"}

    ok, err = _mount(None, "/", None, MS_REC | MS_PRIVATE)
    mlog.add("make-rprivate /", "/", ok, err)
    coverage["mount_isolation"] = ok

    for d in HOST_RO_BINDS:
        if not os.path.isdir("/" + d):
            continue
        tgt = rootfs / d
        ok, err = _mount("/" + d, str(tgt), None, MS_BIND | MS_REC | MS_RDONLY)
        mlog.add(f"bind /{d}", str(tgt), ok, err)
        if ok:
            # Bind mounts stay writable until remounted read-only.
            _mount(None, str(tgt), None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID)

    for host_rel, sandbox_rel in (("decoy/home", "home"), ("work", "work"),
                                  ("scratch", "tmp"), ("out", "output")):
        src, tgt = run / host_rel, rootfs / sandbox_rel
        src.mkdir(parents=True, exist_ok=True)
        ok, err = _mount(str(src), str(tgt), None, MS_BIND | MS_REC)
        mlog.add(f"bind {host_rel}/ -> /{sandbox_rel}", str(tgt), ok, err)

    ok, err = _mount("/dev", str(rootfs / "dev"), None, MS_BIND | MS_REC | MS_NOSUID)
    mlog.add("bind /dev", str(rootfs / "dev"), ok, err)
    coverage["dev"] = "host-bind" if ok else "none"

    ok, err = _mount("proc", str(rootfs / "proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    if ok:
        coverage["proc"] = "fresh-procfs"
    else:
        mlog.add("fresh procfs (blocked by kernel)", str(rootfs / "proc"), False, err)
        ok2, err2 = _mount("tmpfs", str(rootfs / "proc"), "tmpfs",
                           MS_NOSUID | MS_NODEV | MS_NOEXEC)
        if ok2:
            coverage["proc"] = "inert-tmpfs"
            _fake_proc(rootfs / "proc")
        else:
            mlog.add("tmpfs /proc", str(rootfs / "proc"), False, err2)
    mlog.add(f"/proc mode: {coverage['proc']}", str(rootfs / "proc"), True)

    # /etc: seeded from the decoy tree, but backed by a host directory and
    # bind-mounted rather than a tmpfs, so writes to /etc/cron.d or similar are
    # journaled like everything else. Never the host's real /etc.
    etcroot = run / "etcroot"
    etcroot.mkdir(parents=True, exist_ok=True)
    src_etc = run / "decoy" / "etc"
    if src_etc.is_dir() and not any(etcroot.iterdir()):
        for f in src_etc.iterdir():
            try:
                (etcroot / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
                os.chmod(etcroot / f.name, 0o644)
            except OSError:
                pass
    ok, err = _mount(str(etcroot), str(rootfs / "etc"), None, MS_BIND | MS_REC)
    mlog.add("bind etcroot/ -> /etc", str(rootfs / "etc"), ok, err)
    coverage["etc"] = "synthetic" if ok else "none"

    # (e) inert /sys so interface enumeration and tools probing it do not crash.
    ok, err = _mount("tmpfs", str(rootfs / "sys"), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    mlog.add("tmpfs /sys", str(rootfs / "sys"), ok, err)
    return coverage


def sample_proc(rootfs: Path, seen: dict, stop: dict) -> None:
    """Poll the sandbox's own /proc to reconstruct the process tree."""
    proc = rootfs / "proc"
    while not stop["done"]:
        try:
            entries = list(proc.iterdir())
        except OSError:
            time.sleep(0.05); continue
        for e in entries:
            if not e.name.isdigit():
                continue
            pid = int(e.name)
            if pid in seen:
                continue
            try:
                cmdline = (e / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            except OSError:
                continue
            if not cmdline:
                continue
            ppid = 0
            try:
                stat = (e / "stat").read_text(encoding="utf-8", errors="replace")
                ppid = int(stat.rsplit(")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                pass
            seen[pid] = {"pid": pid, "ppid": ppid, "cmdline": cmdline,
                         "first_seen": round(time.time(), 4)}
        time.sleep(0.04)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    cfg = json.loads(Path(ap.parse_args().config).read_text(encoding="utf-8"))

    run, rootfs = Path(cfg["run_dir"]), Path(cfg["rootfs"])
    timeout = float(cfg.get("timeout", 60))
    mlog = MountLog()
    started = time.time()
    coverage = setup_mounts(cfg, mlog)
    meta = {"phase": "mounts_done", "pid_in_ns": os.getpid(), "coverage": coverage,
            "mounts": mlog.entries, "started_at": started}

    env = dict(os.environ)
    env["PYTHONPATH"] = cfg.get("repo_root", "") + os.pathsep + env.get("PYTHONPATH", "")
    capture = str(run / "capture.jsonl")
    sink_proc = None
    try:
        sink_proc = subprocess.Popen(
            [sys.executable, "-m", "airlock.sinkhole", "--out", capture,
             "--duration", str(timeout + 10)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        meta["sinkhole_pid"] = sink_proc.pid
    except OSError as exc:
        meta["sinkhole_error"] = str(exc)

    time.sleep(0.6)  # let listeners bind before the skill starts

    procs, stop = {}, {"done": False}
    sampler = None
    if coverage.get("proc") == "fresh-procfs":
        sampler = threading.Thread(target=sample_proc, args=(rootfs, procs, stop), daemon=True)
        sampler.start()
    coverage["process_tree"] = sampler is not None

    out_fh = open(run / "stdout.txt", "wb")
    err_fh = open(run / "stderr.txt", "wb")

    child = os.fork()
    if child == 0:
        try:
            os.setsid()
        except OSError:
            pass
        if libc.chroot(str(rootfs).encode()) != 0:
            os.write(2, b"airlock: chroot failed\n"); os._exit(127)
        os.chdir("/work")
        child_env = {
            "HOME": "/home", "USER": "user", "LOGNAME": "user", "SHELL": "/bin/sh",
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "PWD": "/work",
            "TMPDIR": "/tmp", "LANG": "C.UTF-8", "HOSTNAME": "dev-box",
            "HTTP_PROXY": "http://127.0.0.1:3128", "HTTPS_PROXY": "http://127.0.0.1:3128",
            "http_proxy": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128",
            "NO_PROXY": "", "PYTHONPATH": "/work", "AIRLOCK_SANDBOX": "1",
        }
        child_env.update(cfg.get("env", {}))
        os.dup2(out_fh.fileno(), 1); os.dup2(err_fh.fileno(), 2)
        try:
            os.dup2(os.open("/dev/null", os.O_RDWR), 0)
        except OSError:
            pass
        entry = cfg["entry"]
        try:
            os.execve(entry[0], entry, child_env)
        except OSError as exc:
            os.write(2, f"airlock: exec {entry[0]} failed: {exc}\n".encode()); os._exit(127)

    exit_code, timed_out, deadline = None, False, time.time() + timeout
    while True:
        try:
            pid, status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == child:
            if os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
            elif os.WIFSIGNALED(status):
                exit_code = -os.WTERMSIG(status)
            else:
                exit_code = status >> 8
            break
        if time.time() > deadline:
            timed_out = True
            for sig in (signal.SIGKILL,):
                try:
                    os.killpg(child, sig)
                except (OSError, ProcessLookupError):
                    try:
                        os.kill(child, sig)
                    except (OSError, ProcessLookupError):
                        pass
            try:
                os.waitpid(child, 0); exit_code = -9
            except ChildProcessError:
                pass
            break
        time.sleep(0.02)

    stop["done"] = True
    if sampler is not None:
        sampler.join(timeout=0.5)
    out_fh.close(); err_fh.close()

    if sink_proc is not None:
        try:
            sink_proc.send_signal(signal.SIGTERM); sink_proc.wait(timeout=3)
        except Exception:
            try:
                sink_proc.kill()
            except Exception:
                pass

    try:  # reap orphans inside this PID namespace
        while True:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
    except ChildProcessError:
        pass

    meta.update({"phase": "complete", "exit_code": exit_code, "timed_out": timed_out,
                 "duration_s": round(time.time() - started, 3),
                 "processes": list(procs.values())})
    (run / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        try:
            sys.stderr.write(f"airlock._nsinit fatal: {exc!r}\n")
            Path(os.environ.get("AIRLOCK_RUN_DIR", ".")).joinpath("meta.json").write_text(
                json.dumps({"phase": "fatal", "error": repr(exc)}), encoding="utf-8")
        except Exception:
            pass
        raise SystemExit(1)
