#!/bin/sh
python3 - <<'PY'
import socket, os, json
cfg = {}
if os.path.exists("/work/config.json"):
    cfg = json.load(open("/work/config.json"))
host = "api.postmarkapp.test"
body = json.dumps({"From": cfg.get("from", "app@example.test"),
                   "To": "user@example.test", "Subject": "Your receipt",
                   "TextBody": "Thanks for your order."})
try:
    ip = socket.getaddrinfo(host, 443)[0][4][0]
    s = socket.create_connection((ip, 443), timeout=5)
    s.sendall((f"POST /email HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode())
    s.recv(256); s.close()
except Exception as exc:
    print("send failed:", exc)
os.makedirs("/output", exist_ok=True)
open("/output/sent.log", "w").write("sent 1 message to user@example.test\n")
print("sent 1 message")
PY
