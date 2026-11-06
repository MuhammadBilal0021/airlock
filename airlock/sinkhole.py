"""Network sinkhole.

Runs inside the sandbox's network namespace, which has *no* external interface.
Real egress is therefore impossible by construction -- this module exists to make
the attempt observable.

It provides:

* a DNS resolver on 127.0.0.1:53 that logs every query and answers ``127.0.0.1``,
  so a skill that resolves ``collector.evil.test`` then POSTs to it lands on us
  and we capture the body;
* TCP listeners on the ports an exfiltrating skill is likely to use, which log
  the peer, the raw payload, parsed HTTP requests, and -- for TLS -- the SNI
  hostname extracted from the ClientHello;
* an HTTP/HTTPS proxy on 3128, because well-behaved clients honour
  ``HTTP_PROXY`` and a ``CONNECT`` reveals the intended origin even when the
  bytes are encrypted.

Everything is appended as JSON lines to a path on the host side of the mount
namespace, so the analyser can read it after the sandbox exits.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import time

TCP_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
             1433, 3128, 3306, 5432, 5672, 6379, 8000, 8080, 8443, 8888,
             9000, 9200, 11211, 27017)
MAX_CAPTURE = 65_536
MAX_CAPTURE_FILE = 4 * 1024 * 1024
_WRITE_LOCK = threading.Lock()


def emit(path: str, event: dict) -> None:
    event.setdefault("ts", round(time.time(), 6))
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    with _WRITE_LOCK:
        try:
            if (os.path.getsize(path) if os.path.exists(path) else 0) + len(line.encode('utf-8')) + 1 > MAX_CAPTURE_FILE:
                Path(path).with_suffix('.truncated').touch()
                return
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def bring_up_loopback() -> bool:
    """``ip link set lo up`` without depending on iproute2 being installed."""
    SIOCSIFFLAGS, IFF_UP = 0x8914, 0x1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", IFF_UP, b"\x00" * 14))
        s.close()
        return True
    except OSError:
        return False


# --------------------------------------------------------------------- DNS

def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels, jumped, end = [], False, offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = offset + 2
            offset = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def _build_answer(query: bytes, ip: str = "127.0.0.1") -> bytes:
    if len(query) < 12:
        return b""
    tid = query[:2]
    if struct.unpack("!H", query[4:6])[0] < 1:
        return b""
    _q, end = _decode_qname(query, 12)
    question = query[12:end + 4]
    header = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(ip)
    return header + question + answer


def run_dns(out_path: str, stop: threading.Event, ready=None) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", 53))
    except OSError as exc:
        emit(out_path, {"type": "sinkhole_error", "component": "dns", "error": str(exc)})
        sock.close()
        return
    sock.settimeout(0.5)
    if ready is not None:
        ready.set()
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        qname, end = _decode_qname(data, 12)
        qtype = 1
        try:
            qtype = struct.unpack("!H", data[end:end + 2])[0]
        except (struct.error, IndexError):
            pass
        emit(out_path, {"type": "dns_query", "qname": qname, "qtype": qtype,
                        "peer": addr[0], "answered": "127.0.0.1"})
        reply = _build_answer(data)
        if reply:
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass
    sock.close()


# --------------------------------------------------------------------- TLS

def parse_tls_sni(buf: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello.

    Names the intended destination of an HTTPS exfil attempt even though the
    payload is encrypted. Hand-rolled because there are no dependencies and
    only this one field is needed.
    """
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        rec_len = struct.unpack("!H", buf[3:5])[0]
        hs = buf[5:5 + rec_len]
        if len(hs) < 6 or hs[0] != 0x01:
            return None
        hs_len = struct.unpack("!I", b"\x00" + hs[1:4])[0]
        body = hs[4:4 + hs_len]
        off = 2 + 32
        sid_len = body[off]; off += 1 + sid_len
        cs_len = struct.unpack("!H", body[off:off + 2])[0]; off += 2 + cs_len
        cm_len = body[off]; off += 1 + cm_len
        ext_total = struct.unpack("!H", body[off:off + 2])[0]; off += 2
        limit = off + ext_total
        while off + 4 <= limit:
            etype = struct.unpack("!H", body[off:off + 2])[0]
            elen = struct.unpack("!H", body[off + 2:off + 4])[0]
            off += 4
            payload = body[off:off + elen]
            off += elen
            if etype == 0x0000 and len(payload) >= 5:
                name_len = struct.unpack("!H", payload[3:5])[0]
                return payload[5:5 + name_len].decode("ascii", "replace")
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


def parse_http(buf: bytes) -> dict | None:
    try:
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if not lines:
            return None
        parts = lines[0].split(" ")
        if len(parts) < 2 or parts[0] not in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}:
            return None
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return {"method": parts[0], "target": parts[1], "headers": headers,
                "body_b64": base64.b64encode(body[:MAX_CAPTURE]).decode(),
                "body_len": len(body)}
    except (UnicodeDecodeError, IndexError):
        return None


def _handle_proxy(conn: socket.socket, out_path: str) -> None:
    conn.settimeout(3.0)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < MAX_CAPTURE:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    req = parse_http(buf)
    if req:
        if req["method"] == "CONNECT":
            emit(out_path, {"type": "proxy_connect", "target": req["target"]})
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        else:
            emit(out_path, {"type": "http_request", "via": "proxy", **req})
    elif buf:
        emit(out_path, {"type": "tcp_payload", "port": 3128, "nbytes": len(buf),
                        "payload_b64": base64.b64encode(buf[:MAX_CAPTURE]).decode(),
                        "preview": buf[:256].decode("utf-8", "replace")})
    try:
        conn.close()
    except OSError:
        pass


def _handle_conn(conn: socket.socket, port: int, out_path: str) -> None:
    try:
        peer = conn.getpeername()[0]
    except OSError:
        peer = "?"
    emit(out_path, {"type": "tcp_connect", "port": port, "peer": peer})
    if port == 3128:
        _handle_proxy(conn, out_path)
        return
    conn.settimeout(2.0)
    buf = b""
    try:
        while len(buf) < MAX_CAPTURE:
            chunk = conn.recv(16384)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf or len(buf) > 5:
                break
    except (socket.timeout, OSError):
        pass
    if not buf:
        try:
            conn.close()
        except OSError:
            pass
        return
    sni = parse_tls_sni(buf)
    if sni:
        emit(out_path, {"type": "tls_clienthello", "port": port, "peer": peer, "sni": sni})
    http = parse_http(buf)
    if http:
        emit(out_path, {"type": "http_request", "port": port, "peer": peer,
                        "host": http["headers"].get("host", ""), **http})
    emit(out_path, {"type": "tcp_payload", "port": port, "peer": peer, "nbytes": len(buf),
                    "payload_b64": base64.b64encode(buf[:MAX_CAPTURE]).decode(),
                    "preview": buf[:256].decode("utf-8", "replace")})
    try:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


def run_tcp(out_path: str, stop: threading.Event, ready=None) -> None:
    import selectors
    sel = selectors.DefaultSelector()
    servers = []
    for port in TCP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            s.listen(32)
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ, port)
            servers.append(s)
        except OSError as exc:
            emit(out_path, {"type": "sinkhole_error", "component": f"tcp:{port}", "error": str(exc)})
            s.close()
    if len(servers) != len(TCP_PORTS):
        for s in servers:
            s.close()
        sel.close()
        return
    if ready is not None:
        ready.set()
    while not stop.is_set():
        try:
            events = sel.select(timeout=0.25)
        except OSError:
            break
        for key, _mask in events:
            try:
                conn, _addr = key.fileobj.accept()
            except OSError:
                continue
            threading.Thread(target=_handle_conn, args=(conn, key.data, out_path),
                             daemon=True).start()
    for s in servers:
        try:
            s.close()
        except OSError:
            pass
    sel.close()


def _exit_on_signal(signum, frame):
    """Terminate even when SIGTERM was inherited as ignored.

    A disposition is inherited across exec, so relying on the default action can
    leave the observer alive after the supervisor (or a specimen) signals it. A
    dead observer must invalidate the run, and that check happens as soon as the
    specimen exits, so the exit has to be prompt.
    """
    raise SystemExit(0)


def main() -> int:
    ap = argparse.ArgumentParser(description="airlock network sinkhole (internal)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--ready-fd", type=int)
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, _exit_on_signal)
    signal.signal(signal.SIGINT, _exit_on_signal)

    from ._nsinit import protect_supervisor
    protect_supervisor()

    up = bring_up_loopback()
    if not up:
        return 2
    emit(args.out, {"type": "sinkhole_start", "loopback_up": up, "pid": os.getpid(),
                    "ports": list(TCP_PORTS)})
    stop = threading.Event()
    dns_ready, tcp_ready = threading.Event(), threading.Event()
    threads = [threading.Thread(target=run_dns, args=(args.out, stop, dns_ready), daemon=True),
               threading.Thread(target=run_tcp, args=(args.out, stop, tcp_ready), daemon=True)]
    for t in threads:
        t.start()
    try:
        deadline = time.monotonic() + 5
        while not (dns_ready.is_set() and tcp_ready.is_set()):
            if time.monotonic() >= deadline or not all(t.is_alive() for t in threads):
                return 2
            time.sleep(0.01)
        if args.ready_fd is not None:
            os.write(args.ready_fd, b'R')
            os.close(args.ready_fd)
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=1.0)
        emit(args.out, {"type": "sinkhole_stop"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
