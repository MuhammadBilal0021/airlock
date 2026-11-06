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
import math
import os
import resource
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


DEFAULT_ADDRESS_SPACE = 512 * 1024 * 1024


def specimen_limits(timeout):
    """Per-process limits for the specimen.

    The address-space cap is a containment control: 512 MiB keeps a runaway
    allocation from hurting the host. Some legitimate runtimes need more just to
    start -- Node's V8 reserves address space up front and dies with SIGTRAP
    under the default (corpus-004 measured 4 packages doing exactly that), so
    the cap is overridable. Any override is reported verbatim in
    ``coverage.resource_limits.address_space_bytes``; a result can never claim a
    limit it did not apply.
    """
    address_space = DEFAULT_ADDRESS_SPACE
    override = os.environ.get("AIRLOCK_ADDRESS_SPACE_BYTES")
    if override:
        try:
            address_space = max(64 * 1024 * 1024, int(override))
        except ValueError:
            address_space = DEFAULT_ADDRESS_SPACE
    return {"address_space_bytes": address_space,
            "file_size_bytes": 8 * 1024 * 1024, "open_files": 128,
            "cpu_seconds": max(1, math.ceil(timeout)), "core_bytes": 0}


def apply_specimen_limits(limits):
    for key, kind in (("address_space_bytes", resource.RLIMIT_AS),
                      ("file_size_bytes", resource.RLIMIT_FSIZE),
                      ("open_files", resource.RLIMIT_NOFILE),
                      ("cpu_seconds", resource.RLIMIT_CPU),
                      ("core_bytes", resource.RLIMIT_CORE)):
        resource.setrlimit(kind, (limits[key], limits[key]))


def restrict_specimen():
    """Prevent namespace-root privileges from surviving or returning at exec."""
    # NOROOT and NOROOT_LOCKED disable UID 0's special capability treatment.
    for option, value in ((28, 3), (38, 1)):
        if libc.prctl(option, value, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'cannot restrict specimen privileges')
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Caps(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    empty = (Caps * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(empty)) != 0:
        raise OSError(ctypes.get_errno(), 'cannot clear specimen capabilities')


def protect_supervisor():
    # Same-UID /proc fd/memory access must not expose the outside-chroot helpers.
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE=0
        raise OSError(ctypes.get_errno(), 'cannot protect supervisor process')


def _mount(src, target, fstype, flags, data=None):
    # Individual device binds use a pre-created regular-file mountpoint.
    if not os.path.exists(target):
        os.makedirs(target, exist_ok=True)
    r = libc.mount(src.encode() if src else _NULL, target.encode(),
                   fstype.encode() if fstype else _NULL, flags,
                   data.encode() if data else _NULL)
    return (True, "") if r == 0 else (False, f"errno={ctypes.get_errno()} {os.strerror(ctypes.get_errno())}")


def _required_mount(src, target, fstype, flags, data=None):
    ok, error = _mount(src, target, fstype, flags, data)
    if not ok:
        raise RuntimeError(f"required mount failed at {target}: {error}")
    return ok, error


class MountLog:
    def __init__(self): self.entries = []
    def add(self, what, target, ok, err=""):
        self.entries.append({"what": what, "target": target, "ok": ok, "error": err})


def bind_runtime(source, target):
    # WSL locks some inherited submounts, so a nonrecursive bind can fail.
    # Apply read-only/nosuid recursively to the cloned mount tree instead.
    _required_mount(source, str(target), None, MS_BIND | MS_REC)
    _required_mount(None, str(target), None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID)
    class MountAttr(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ('attr_set', 'attr_clr', 'propagation', 'userns_fd')]
    attr = MountAttr(3, 0, 0, 0)  # MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID
    import platform
    if platform.machine() not in ('x86_64', 'aarch64', 'riscv64'):
        raise RuntimeError('recursive mount attributes unsupported on this architecture')
    if libc.syscall(ctypes.c_long(442), ctypes.c_int(-100),
                    ctypes.c_char_p(os.fsencode(target)), ctypes.c_uint(0x8000),
                    ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr))) != 0:
        raise OSError(ctypes.get_errno(), 'recursive read-only mount failed')
    if not os.statvfs(target).f_flag & os.ST_RDONLY:
        raise RuntimeError('runtime bind is not read-only')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mounted = line.split()[4]
        if mounted == str(target) or mounted.startswith(str(target).rstrip('/') + '/'):
            if not {'ro', 'nosuid'} <= set(line.split()[5].split(',')):
                raise RuntimeError('runtime submount is not read-only/nosuid')


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
    coverage = {"proc": "none", "dev": "none", "network_isolated": False, "etc": "none"}

    ok, err = _required_mount(None, "/", None, MS_REC | MS_PRIVATE)
    mlog.add("make-rprivate /", "/", ok, err)
    coverage["mount_isolation"] = ok

    for d in HOST_RO_BINDS:
        if not os.path.isdir("/" + d):
            continue
        tgt = rootfs / d
        bind_runtime('/' + d, tgt)
        mlog.add(f"recursively read-only bind /{d}", str(tgt), True)
    coverage['runtime_mounts'] = 'recursively read-only and nosuid; verified'

    # Optional hermetic runtime overlay, mounted read-only over /usr/local.
    # The host filesystem decides what a skill can run; corpus-003 measured that
    # cost (`node` absent -> exit 127 before any real work). An overlay lets a
    # pinned runtime set be supplied without root and without trusting whatever
    # the host image happens to carry.
    overlay = cfg.get("runtime_overlay")
    if overlay:
        overlay_path = Path(overlay)
        if not overlay_path.is_dir():
            raise RuntimeError(f"runtime overlay is not a directory: {overlay_path}")
        target = rootfs / "usr" / "local"
        if not target.is_dir():
            coverage['runtime_overlay'] = 'unavailable: /usr/local missing'
            mlog.add("runtime overlay requested but /usr/local is missing",
                     str(target), False)
        else:
            bind_runtime(str(overlay_path), target)
            mlog.add("recursively read-only bind runtime overlay -> /usr/local",
                     str(target), True)
            coverage['runtime_overlay'] = 'mounted read-only at /usr/local'
    else:
        coverage['runtime_overlay'] = 'none'

    for host_rel, sandbox_rel in (("decoy/home", "home"), ("work", "work"),
                                  ("scratch", "tmp"), ("out", "output")):
        src, tgt = run / host_rel, rootfs / sandbox_rel
        src.mkdir(parents=True, exist_ok=True)
        ok, err = _required_mount(str(src), str(tgt), None, MS_BIND | MS_REC)
        mlog.add(f"bind {host_rel}/ -> /{sandbox_rel}", str(tgt), ok, err)

    dev = rootfs / "dev"
    _required_mount("tmpfs", str(dev), "tmpfs", MS_NOSUID | MS_NOEXEC,
                    "size=1m,mode=755")
    # Bind only basic character devices. Never expose host disks, terminals,
    # /dev/shm, or host-specific interfaces through a recursive /dev bind.
    for name in ("null", "zero", "random", "urandom"):
        target = dev / name
        target.touch()
        _required_mount("/dev/" + name, str(target), None, MS_BIND)
        _required_mount(None, str(target), None, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NOEXEC)
    for name, target in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                         ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        (dev / name).symlink_to(target)
    _required_mount(None, str(dev), None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOEXEC)
    mlog.add("minimal /dev", str(dev), True)
    coverage["dev"] = "minimal"

    ok, err = _mount("proc", str(rootfs / "proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    if ok:
        coverage["proc"] = "fresh-procfs"
    else:
        mlog.add("fresh procfs (blocked by kernel)", str(rootfs / "proc"), False, err)
        ok2, err2 = _mount("tmpfs", str(rootfs / "proc"), "tmpfs",
                           MS_NOSUID | MS_NODEV | MS_NOEXEC, 'size=1m,nr_inodes=128')
        if ok2:
            coverage["proc"] = "inert-tmpfs"
            _fake_proc(rootfs / "proc")
            _required_mount(None, str(rootfs / 'proc'), None,
                            MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
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
    ok, err = _required_mount(str(etcroot), str(rootfs / "etc"), None, MS_BIND | MS_REC)
    mlog.add("bind etcroot/ -> /etc", str(rootfs / "etc"), ok, err)
    coverage["etc"] = "synthetic" if ok else "none"

    # (e) inert /sys so interface enumeration and tools probing it do not crash.
    ok, err = _required_mount("tmpfs", str(rootfs / "sys"), "tmpfs",
                              MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                              'size=1m,nr_inodes=128')
    mlog.add("tmpfs /sys", str(rootfs / "sys"), ok, err)
    return coverage


def sample_proc(rootfs: Path, seen: dict, stop: dict, excluded=()) -> None:
    """Poll the sandbox's own /proc to reconstruct the process tree."""
    proc = rootfs / "proc"
    # A forked child briefly inherits init's argv before exec. Do not cache that
    # transitional state as specimen activity or suppress its later real argv.
    init_argv = (proc / str(os.getpid()) / "cmdline").read_bytes()
    while not stop["done"]:
        try:
            entries = list(proc.iterdir())
        except OSError:
            time.sleep(0.05); continue
        for e in entries:
            if not e.name.isdigit():
                continue
            pid = int(e.name)
            if pid in seen or pid in excluded:
                continue
            try:
                raw = (e / "cmdline").read_bytes()
                if raw == init_argv:
                    continue
                cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
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


def verify_network_interfaces():
    """Verify loopback-only topology separately from observer readiness."""
    import socket
    names = sorted(name for _, name in socket.if_nameindex())
    if names != ['lo']:
        raise RuntimeError('network namespace is not loopback-only: ' + repr(names))
    return 'kernel interface inventory: lo only; mandatory new network namespace'


def start_observer(command, env, ready_timeout=10):
    """Wait for the private readiness pipe, never a fixed startup delay."""
    import select
    read_fd, write_fd = os.pipe()
    proc = None
    try:
        proc = subprocess.Popen(command + ['--ready-fd', str(write_fd)],
                                env=env, pass_fds=(write_fd,),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(write_fd)
        write_fd = None
        available, _, _ = select.select([read_fd], [], [], ready_timeout)
        if not available or os.read(read_fd, 1) != b'R' or proc.poll() is not None:
            raise RuntimeError('network observer did not become ready; refusing specimen launch')
        return proc
    except BaseException:
        if proc is not None:
            proc.kill()
            proc.wait()
        raise
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    cfg = json.loads(Path(ap.parse_args().config).read_text(encoding="utf-8"))

    run, rootfs = Path(cfg["run_dir"]), Path(cfg["rootfs"])
    timeout = float(cfg.get("timeout", 60))
    mlog = MountLog()
    started = time.time()
    coverage = setup_mounts(cfg, mlog)
    if os.environ.get('AIRLOCK_STORAGE_ROOT'):
        from .storage import verify_storage
        storage_root = Path(os.environ['AIRLOCK_STORAGE_ROOT']).resolve()
        if storage_root not in run.resolve().parents:
            raise RuntimeError('run directory lies outside bounded storage')
        coverage['storage_limits'] = verify_storage(storage_root)
    else:
        coverage['storage_limits'] = {'verified': False}
    limits = specimen_limits(timeout)
    coverage["resource_limits"] = {"scope": "per-process", **limits,
                                   "aggregate_limits": False}
    from .bounded import verify_limits, DEFAULTS
    try:
        coverage['aggregate_resources'] = verify_limits(DEFAULTS)
        coverage['resource_limits']['aggregate_limits'] = True
    except (OSError, ValueError, RuntimeError, StopIteration):
        coverage['aggregate_resources'] = {'verified': False}
    meta = {"phase": "mounts_done", "pid_in_ns": os.getpid(), "coverage": coverage,
            "mounts": mlog.entries, "started_at": started}

    env = dict(os.environ)
    env["PYTHONPATH"] = cfg.get("repo_root", "") + os.pathsep + env.get("PYTHONPATH", "")
    capture = str(run / "capture.jsonl")
    sink_proc = start_observer(
        [sys.executable, "-m", "airlock.sinkhole", "--out", capture,
         "--duration", str(timeout + 20)], env)
    meta["sinkhole_pid"] = sink_proc.pid
    coverage['network_observer_ready'] = True
    coverage['network_isolation_basis'] = verify_network_interfaces()
    coverage['network_isolated'] = True
    protect_supervisor()
    coverage['supervisor_access'] = 'nondumpable helpers; observer liveness checked'

    procs, stop = {}, {"done": False}
    sampler = None
    if coverage.get("proc") == "fresh-procfs":
        # These are scanner infrastructure, not behaviour of the specimen.
        excluded = {os.getpid(), meta.get("sinkhole_pid")}
        sampler = threading.Thread(target=sample_proc,
                                   args=(rootfs, procs, stop, excluded), daemon=True)
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
        try:
            apply_specimen_limits(limits)
            restrict_specimen()
        except (OSError, ValueError) as exc:
            os.write(2, f"airlock: specimen restriction failed: {exc}\n".encode())
            os._exit(127)
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

    exit_code, timed_out, deadline = None, False, time.monotonic() + timeout
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
        if time.monotonic() > deadline:
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
        if sink_proc.poll() is not None:
            raise RuntimeError('network observer exited during run; evidence incomplete')
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
