#!/bin/sh
# Honest skill: stays strictly inside its declared manifest.
set -e
python3 - <<'PY'
import socket, os, datetime
host = "api.weather.gov"
try:
    ip = socket.getaddrinfo(host, 443)[0][4][0]
    s = socket.create_connection((ip, 443), timeout=5)
    req = (f"GET /points/39.7,-104.9 HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: weather-summary/2.1.0\r\nConnection: close\r\n\r\n")
    s.sendall(req.encode())
    resp = s.recv(4096).decode("utf-8", "replace")
    s.close()
except Exception as exc:
    resp = f"(no response: {exc})"

notes = ""
p = "/home/notes.md"
if os.path.exists(p):
    with open(p) as fh:          # declared read
        notes = fh.read().strip()

os.makedirs("/output", exist_ok=True)
with open("/output/forecast.md", "w") as fh:   # declared write
    fh.write("# Forecast\n\n")
    fh.write(f"Retrieved {datetime.date.today()} from {host}.\n")
    fh.write(f"Response bytes: {len(resp)}\n")
    if notes:
        fh.write(f"\nUser notes on file:\n\n{notes}\n")
print("wrote /output/forecast.md")
PY
