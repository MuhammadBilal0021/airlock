# Pre-registration — corpus-001 detection measurement

**Status: FROZEN before first scan.** Written 2026-11-07, before any corpus sample
was scanned. Any change to the prediction rule, thresholds, or metric definitions
below after scanning begins invalidates this round and requires a new
pre-registered round with a new id.

Airlock revision under test: branch `research/corpus-measurement-001`, based on
`codex/release-candidate` @ `50aea9b`.

## 1. Question

What are airlock's measured false-positive rate on real, public agent skills and
its measured recall on explicitly labelled malicious skill packages — reported
with confidence intervals, separate denominators, and the failures published?

This is a **detection-performance measurement**, not a prevalence study of any
registry, not a certification, and not evidence that unobserved behaviour is
absent.

## 2. Corpora

### B0 — benign real (target n = 200)

Public skill packages, acquired at pinned immutable revisions, selected
deterministically as the first N paths ordered by `sha256(relative path)` within
each source (the selection rule already used by `research/PILOT.md`).

| Source | Role |
|---|---|
| `openclaw/openclaw` | agent skill bundle |
| `anthropics/skills` | vendor skill bundle |
| `wshobson/agents` | community skill bundle |
| `obra/superpowers` | community skill bundle |
| `modelcontextprotocol/servers` | MCP server repo with bundled skills |

**Inclusion:** directory contains at least one `SKILL.md`; no symlinks; only text
artefacts are acquired (`.md .py .sh .js .ts .json .yaml .yml .txt .toml`); no
single file over 256 KiB; no package over 1 MiB of text.

**Label:** `benign` — meaning *the upstream project publishes it as an ordinary
skill*. This is **not** a claim that the package contains no risk.

**Known contamination:** these bundles are also where `fixtures/` ideas and the
`research/heldout-*` cases came from. Benign membership is therefore partially
in-distribution for the scanner's false-positive behaviour. Disclosed, not fixed.

### A0 — adversarial authored (target n = 100)

Packages authored for this round **before** scanning, each malicious by
construction, with a technique family recorded per sample. 20 technique families
× 5 lexical variants, generated deterministically from a fixed seed so the corpus
is reproducible without network access.

Two levels:

- **I (instruction-level, n = 40):** malice expressed in text the model reads
  (description, body, appended notes). No hostile code.
- **B (behaviour-level, n = 60):** malice expressed in executable code —
  credential reads, egress to non-declared hosts, persistence, remote fetch.

**All A0 content is synthetic:** canary credentials only, e.g.
`/home/.aws/credentials` populated with `AKIA-EXAMPLE-CANARY`, and hosts under
`*.example.test` / `attacker.test`. No real credential, host, or payload is used.

**Label:** `malicious`. The label is by construction: the authoring family is the
ground-truth intent.

**Known contamination (important):** A0 was authored by an agent that had read
airlock's published rule descriptions in `airlock/sarif.py`. Recall on A0 is
therefore an **optimistic upper bound**, not an estimate of real-world recall.
This is stated here before measurement, not discovered afterwards.

### Excluded stratum — real malicious skills

Not acquired and not measured. Rationale recorded before measurement:

1. No public, licence-clean, machine-readable corpus of real malicious agent
   skills exists at n ≥ 100 that can be verified as malicious rather than merely
   suspicious.
2. Executing samples that are *actually* malicious on any machine is not
   appropriate merely to produce a number.

Consequence: **this round cannot report real-world recall.** It reports recall on
authored adversarial samples and false positives on real benign samples. Stated
as a headline limitation, not a footnote.

## 3. Prediction rules (frozen)

A **positive** prediction is any finding whose `severity` is `critical`, `high`,
or `medium`, **excluding** coverage-disclosure rules `ALK-090`, `ALK-091`,
`ALK-092`, `ALK-093` — those describe analysis coverage, not detected malice.
`ALK-006` (declared read) and `ALK-011` (unused declaration) are `info` and are
excluded by the severity rule.

- **Static path:** applied to the declaration-only verdict produced by
  `_static_only_verdict`. Under this rule the only reachable positive is
  `ALK-009`; that is a property of the implementation and is reported as such.
- **Behavioural path:** applied to the full verdict from `airlock scan`. Only
  A0 family **B** samples are executed, and only inside the airlock namespace
  sandbox with no network route and synthetic canaries.

Thresholds are fixed at the values above. No threshold sweep, no post-hoc
selection of the best operating point.

## 4. Metrics (frozen)

Separate denominators; no pooling of static and behavioural results.

1. **False-positive rate** on B0 = positives / B0 scanned, with 95% Wilson
   score interval.
2. **Recall** on A0 = positives / A0 scanned, overall and per family, with 95%
   Wilson score interval.
3. **Precision** is prevalence-dependent and is therefore reported at prevalence
   levels 1 %, 5 %, 10 %, 50 % using the measured FPR and recall — never as a
   single unqualified number.
4. **Rule-level false positives:** count of B0 samples firing each rule.
5. **Coverage and failure accounting:** every sample's status
   (`static_only`, `completed`, `failed`, `timed_out`) is reported. Failures are
   **not** counted as clean and **not** silently dropped; they are excluded from
   the rate denominators and reported alongside them.

## 5. Reporting commitments

- Publish the unfavourable result. If recall is low or FPR is high, that is the
  finding.
- Publish per-sample outcomes, so any reader can recompute every number.
- Publish the frozen manifests with per-file SHA-256 and the scanner revision.
- Do not describe this round as validating resistance to sandbox escape.
- Do not describe `benign` as `safe`, or `malicious` as `detected` unless the
  prediction rule fired.

## 6. Reproduction

```
python scripts/acquire_corpus.py    # B0, network, pinned revisions
python scripts/generate_adversarial_corpus.py   # A0, offline, fixed seed
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-001/results/benign --static-only
python scripts/scan_dataset.py research/corpus-001/adversarial/manifest.json \
    --output research/corpus-001/results/adversarial --static-only
python scripts/measure.py research/corpus-001
```

## 7. Threats to validity (declared up front)

1. A0 recall is optimistic (rule-aware authorship).
2. B0 real skills cannot be executed by airlock: `detect_entry()` accepts only
   root-level `run.sh`/`main.py`-style artefacts, and real skills keep code in
   `scripts/`. Behavioural false-positive rate on real skills is therefore
   **unmeasured this round**.
3. Convenience samples, not prevalence samples.
4. Text-only acquisition caps what the static path can see for large packages.
5. Packages with more than one `SKILL.md` inherit the first declaration found.
