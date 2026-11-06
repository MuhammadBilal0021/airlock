# Two-minute demo script

Record this once, keep it under two minutes, and put it at the top of the README
and every application. Deterministic: no network, no API keys, same output every
time.

## Before recording

```sh
# WSL2 Ubuntu or any Linux with util-linux
cd airlock
python3 -m airlock --version      # airlock 0.1.0
stty cols 100 rows 30             # keep lines from wrapping
```

Terminal: dark background, 16–18 pt, no prompt clutter.

## Shot list

### 0:00–0:15 — the claim

> "Every agent skill claims to be harmless. This one says it reads nothing and
> makes no network calls. Let's put it in the airlock and watch what it does."

```sh
python3 -m airlock scan fixtures/03-silent-bcc
```

Highlight on screen:

```
OBSERVED  read  /home/.aws/credentials
          dns   alck-awssecret-6fdxmujnaxmn.exfil.attacker.test
VERDICT   CRITICAL
```

> "That hostname contains the AWS secret it just read. The canary was generated
> when the sandbox was built, exists nowhere else, and appeared in a DNS query.
> That's not a heuristic. That's proof."

### 0:15–0:50 — the boring case, and why that matters

```sh
python3 -m airlock scan fixtures/01-benign-weather
```

> "A benign skill gets a clean verdict, and the report shows what the sandbox did
> and did not cover. No false alarms on the everyday case."

### 0:50–1:20 — drift: the same skill, one version later

```sh
python3 -m airlock scan fixtures/04-drift-v1.0.16   # LOW
python3 -m airlock scan fixtures/05-drift-v1.0.17   # CRITICAL
```

> "Same name, same description. The update added one behaviour, and the sandbox
> caught it. This is the rug-pull case that text scanners are blind to."

### 1:20–1:50 — the number that matters

Switch to `docs/MEASUREMENTS.md`.

> "We ran 245 real public skills and 100 adversarial packages, pre-registered,
> failures published. Text analysis caught zero of sixty code-level attacks.
> The sandbox caught fifty-five. Both numbers are in the repo, with the ones that
> make us look bad."

### 1:50–2:00 — close

> "Apache-2.0, zero runtime dependencies, runs in your own CI. The link is below."

## Recording notes

- Do not speed up the terminal; the scans are under a second each.
- Cut any sentence you stumble on rather than re-recording the whole thing.
- Burn in captions; most people watch muted.
- Export at 1080p, under 20 MB, and commit it to `docs/demo/demo.mp4`.

## Alternate 20-second clip (for social)

Just the malicious scan and one sentence: *"The skill said it reads nothing. It
read AWS credentials and exfiltrated them through DNS."*
