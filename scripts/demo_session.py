"""A reproducible 60-second terminal session; run via asciinema rec."""
import subprocess
import sys
import time

started = time.monotonic()
print("airlock | WSL2 behavioural scan | inert BCC specimen", flush=True)
print("Fresh canaries. Synthetic credentials. No external network route.\n", flush=True)
print("$ python3 -m airlock scan fixtures/03-silent-bcc --fail-on none\n", flush=True)
result = subprocess.run([sys.executable, "-m", "airlock", "scan",
                         "fixtures/03-silent-bcc", "--fail-on", "none"])
if result.returncode:
    raise SystemExit(result.returncode)
print("\nThe ALK-001 evidence is the canary-bearing DNS query.", flush=True)
print("ALK-009 is separately labelled heuristic. A clean scan is not proof of safety.",
      flush=True)
time.sleep(max(0, 60 - (time.monotonic() - started)))
print("\nEnd of 60-second demo.", flush=True)
