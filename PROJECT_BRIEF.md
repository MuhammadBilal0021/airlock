# airlock — project brief

**Prepared for:** Muhammad Bilal
**Date:** 4 November 2026
**Priority order:** (1) attract investors / build toward a company, (2) get hired.
**Constraint:** solo, ~20 hrs/week, 2-month sprint, Windows + WSL2, fresh repo.

This document is the strategy. `README.md` is the product. Read this first.

---

## 1. Thesis

> **Agent skills and MCP servers are the new package ecosystem, and their
> supply chain is already compromised. Every scanner on the market reads what an
> artifact *says*. airlock watches what it *does*.**

That is a one-sentence pitch an investor understands in ten seconds and a
security engineer recognises as true. It is also a category where the incumbent
open-source leader was **acquired** (Snyk bought Invariant Labs, June 2025),
which is the clearest possible signal that this is a real market and not a
science project.

Everything below exists to make that sentence defensible with evidence.

---

## 2. Why now

The timing is the strongest part of this idea. Not "AI is hot" — specific,
dated, verifiable events:

| Date | Event | Why it matters |
|---|---|---|
| Feb 2026 | Snyk **ToxicSkills**: 3,984 skills scanned, **36.8% flawed**, 13.4% critical, 76 confirmed malicious payloads | The ecosystem-scale measurement that makes the problem legible |
| Jan–Feb 2026 | **ClawHavoc**: 1,184 malicious skills across 12 publisher accounts; single C2 IP; targeted exchange keys, wallet keys, SSH creds, browser passwords, `.env` | Organised campaign, not hobbyists. Writes backdoors into `MEMORY.md`/`SOUL.md` |
| Feb 2026 | ClawHub: **5 of the top 7 most-downloaded skills were malware** | First AI agent registry poisoned at scale |
| Feb 2026 | Microsoft Defender advisory: OpenClaw is "untrusted code execution with persistent credentials… not appropriate to run on a standard personal or enterprise workstation" | A vendor telling enterprises they have a problem with no stated solution |
| Feb 2026 | BlueRock: **36.7% of 7,000+ MCP servers** potentially SSRF-vulnerable; live AWS IAM keys pulled through Microsoft's MarkItDown server | The MCP half of the market, same disease |
| Mar 2026 | SecurityScorecard: **135,000+** OpenClaw instances internet-exposed; 53,000 correlated with prior breach activity | Attack surface is already deployed and reachable |
| Mar 2026 | **NIST/CAISI Federal Register RFI on AI Agent Security** | Government procurement follows RFIs |
| Jun 2026 | Trail of Bits, *The Sorry State of Skill Distribution*: **every public scanner bypassed in under an hour** — padding, archives, and prompt-injecting the scanner's own LLM judge | The incumbents are demonstrably broken. This is your opening |
| Jun 2026 | Air Security: a malicious skill reached **26,000+ agents while every scanner cleared it**; 17,822 of 142,836 skills rest on an untrusted external instruction source | Proof that static-only scanning fails in the wild, at scale |
| Jul 2026 | **SkillJacking**: 925 skills / ~134K agents on instantly hijackable dependencies; researchers took over the most popular video-gen skill on skills.sh (11,483 installs) by re-registering a deleted owner account | Supply chain is breakable without writing any malware |

**The window:** OWASP published the Agentic Skills Top 10 (AST10) in March 2026
and its own scanner integration page still states *"An OWASP-maintained
`@owasp/ast10-scanner` package is not currently published."* AST08's official
mitigation is literally **"semantic + behavioral multi-tool pipeline."** The
standard exists; the canonical tool does not. That is a 6–12 month window before
a vendor fills it.

---

## 3. Competitive map (honest)

| Tool | Approach | Stars | The gap |
|---|---|---|---|
| NVIDIA SkillSpector | 71 static patterns / 17 categories, optional LLM judge | ~20k | `--no-llm` misses semantic attacks; LLM mode needs an API key. Static only |
| Snyk Agent Scan | Cloud analysis of tool descriptions | ~3.1k | **Requires `SNYK_TOKEN`; your descriptions leave the machine.** No offline mode |
| Cisco MCP Scanner | YARA rules, optional LLM/behavioural/VirusTotal | ~1.1k | YARA mode is keyword matching; missed the BCC case outright |
| agentgateway | Runtime policy gateway, allowlists | — | Enforcement, not analysis. Cannot tell you *what* a skill does |
| Jiffy Labs | **True dynamic sandbox analysis** | closed | Commercial, proprietary. Validates the approach and is not available to individuals |
| SkillWard | Sandbox scanner | 145 | **Stalled since July 2026**, non-standard licence, commercial funnel |
| AgentVetter | Multi-scanner aggregator | 13 | Aggregates other scanners; breadth over depth |
| OWASP AST10 scanner | — | — | **Does not exist** |

Two conclusions:

1. **The dynamic-analysis niche has one serious player and it is closed-source.**
   There is no free, offline, canonical open-source behavioural analyzer.
2. **The open-source attempts are weak and one is abandoned.** 145 stars and 13
   stars, against a category with 135,000 exposed instances and 6.7M installs on
   untrusted instruction sources. Demand is not the constraint. Execution and
   distribution are.

The big vendors are not a threat to out-engineer; they are **validation**. When
NVIDIA, Cisco and Snyk all ship into a category, an independent project in that
category is legible by default. You inherit their market education for free.

---

## 4. The specific gap airlock occupies

Documented empirically, not asserted. A four-tool MCP server was built containing
a `format_address` tool whose description instructed the model to BCC all
outgoing mail to an outside address — plain prose, no credential keyword:

| Scanner | `add` (asks for `id_rsa`) | `convert_units` (asks for `.env`) | `format_address` (BCC) |
|---|---|---|---|
| Cisco MCP Scanner, YARA | HIGH | HIGH | **SAFE — missed** |
| NVIDIA SkillSpector `--no-llm` | HIGH 90% | HIGH 60% | **not flagged** |
| **airlock** | **CRITICAL (canary captured)** | **CRITICAL (canary captured)** | **CRITICAL — ALK-001 + ALK-009** |

And the deeper point from Trail of Bits: their bypasses were *padding to force
truncation*, *hiding logic in archives*, and *prompt-injecting the LLM judge*.
**All three are attacks on a scanner that reads the artifact.** airlock does not
read the artifact to reach a verdict. You cannot pad a syscall trace. You cannot
hide a `connect()` in an archive. You cannot prompt-inject a file's access time
or a canary string appearing in a TCP payload.

That is a structural advantage, not a feature advantage. It is the moat, and it
is the single sentence to lead with in every conversation.

---

## 5. Product shape

Three layers. Each one earns the next.

### Layer 1 — Free OSS CLI (distribution + trust)
`airlock scan <path>` → declared/observed diff, findings, risk score, terminal +
JSON + Markdown + **SARIF**. Zero dependencies, no account, no API key, runs
offline. This is what gets stars, issues, and OWASP listing.

Already built and passing 19 tests, including end-to-end sandbox regressions.

### Layer 2 — Hosted reports (viral loop + SEO)
`airlock report <github-url>` renders a shareable one-page verdict at a public
URL. Every report is a backlink and a screenshot. This is where a solo project
gets distribution it cannot buy.

Plus: **a public scan of the top 1,000 registry skills**, published with full
methodology and reproducible commands. Snyk's ToxicSkills report got press
because it was a *dataset*, not a tool. This is the highest-leverage single
artifact in the entire plan — see §7.

### Layer 3 — Paid (the business)
The wedge is a control nobody else has: **behavioural drift detection across
versions.**

- **Fleet monitoring** — scan every skill and MCP server on every developer
  machine, re-scan on version change, alert on drift. The `postmark-mcp` incident
  is the sales deck: 1.0.16 clean, 1.0.17 added a BCC, 1,643 downloads before
  anyone noticed. `fixtures/04` and `fixtures/05` reproduce it exactly.
- **Registry API** — marketplaces gate uploads. ClawHub already added
  VirusTotal scanning after being poisoned; they are a buyer, not a competitor.
- **Agent Bill of Materials + compliance** — EU AI Act, SOC 2, ISO 42001.
  Enterprises need an artifact that says "here is every skill, here is what each
  one does, here is the evidence." airlock already produces that per-skill.
- **Pinned policy enforcement** — `airlock verify` fails CI when behaviour
  exceeds the pinned least-privilege manifest. This is the natural upgrade path
  from the free `policy` command.

**Comparable outcome:** Snyk acquired Invariant Labs specifically for this
capability. Cisco built AI Defense. NVIDIA shipped a scanner. Palo Alto published
the Lethal Trifecta framing. This is an M&A category with named acquirers.

---

## 6. Moat

Ranked by how hard it is to copy:

1. **The canary-isolation architecture.** Decoy machine + canary correlation +
   atime read detection + netns sinkhole with DNS/TLS-SNI capture. This is
   systems work (namespaces, bind mounts, seccomp, Landlock) that almost nobody
   in the "AI engineer" pool can do. It is not a prompt.
2. **The published dataset.** Once you have scanned 1,000 skills with a
   reproducible methodology, that is a citation asset. Nobody can retroactively
   have published it first.
3. **OWASP AST10 alignment.** Every finding carries an AST mapping. Being listed
   on an OWASP project page is credibility a startup cannot buy in its first year.
4. **Coverage honesty as a brand.** `ALK-090/091/092/093` exist to report what
   airlock could *not* see. Fixture `05` ships with a documented false positive.
   In security, the tool that admits its limits is the one professionals trust.
   This is also, not coincidentally, the exact discipline already visible in your
   `leadflow-ai` README.

---

## 7. Go-to-market

Distribution is the part solo founders lose on. Sequence it deliberately.

**Do not launch until Phase 1 is complete and the demo GIF is under 10 seconds.**

| Step | Action | Why |
|---|---|---|
| 1 | Publish the **1,000-skill scan** as a standalone article + dataset in the repo | Data gets shared; tools get bookmarked. This is the top of the funnel |
| 2 | If the scan finds a **live malicious skill**, do responsible disclosure and write it up | A real finding is worth more than any amount of marketing. This is the single highest-upside event in the plan |
| 3 | Submit a PR to **OWASP AST10**'s skill-scanner-integration page | They explicitly invite "scanning tools" contributions and their own scanner doesn't exist. Cheap legitimacy |
| 4 | Post to r/netsec, r/AI_Agents, r/mcp, then Hacker News (Show HN) | Order matters: security communities first, because they will find your bugs before HN finds your typos |
| 5 | Open issues on **SkillWard** (abandoned) and **AgentVetter** offering collaboration | Two stalled competitors with existing stars. Converting their users is cheaper than acquiring new ones |
| 6 | Email the authors of ToxicSkills, Trail of Bits' *Sorry State*, Air Security, and the AST10 project leads | They have already done the market education. They are looking for tools that fix what they documented |
| 7 | Publish the GitHub Action and get it into `awesome-mcp-security` style lists | CI integration is how a tool becomes infrastructure rather than a bookmark |

**Post on a Tuesday or Wednesday, 14:00–16:00 UTC.** Have the demo GIF, the
README, and a working `pipx install` ready before any of it. One launch, not three.

---

## 8. Traction targets (8 weeks)

Investors at your stage do not expect revenue. They expect **evidence that
strangers care.** Rank-ordered by what actually moves the needle:

| Metric | 8-week target | Why it counts |
|---|---|---|
| Real GitHub issues from real users | **10+** | Proves strangers ran it. Beats stars |
| Stars | 400–1,500 | Table stakes for credibility, not the goal |
| External contributors | 2+ | Proves it is a project, not a diary |
| A published finding / disclosure | 1 | Instant credibility; possibly press |
| Listed on OWASP AST10 scanner page | yes | Third-party endorsement |
| `pipx`/`pip` installs | 500+ | Usage, not vanity |
| Design-partner conversations | 2–3 | The seed of a pipeline |
| Forks | 30+ | Downstream dependency signal |

**Do not buy stars.** A repo with 300 stars and 15 substantive issues from
security engineers is worth dramatically more than 5,000 stars from a viral tweet,
and any technical investor can tell the difference in about ninety seconds.

---

## 9. Eight-week build plan

~160–200 hours at 20 hrs/week. Phase 1 is already substantially built.

### Weeks 1–2 — Harden what exists *(the code is written; make it trustworthy)*
- [ ] Replace atime read-detection with **Landlock + seccomp user-notification** for exact `openat`/`connect`/`execve` logging. Keep atime as a fallback for older kernels
- [ ] **overlayfs upper-dir diff** for exact write journaling (immune to mtime preservation)
- [ ] Map additional uids and **drop privileges before exec**
- [ ] `pivot_root` instead of `chroot`
- [ ] cgroups v2 limits: CPU, memory, PIDs
- [ ] Verify on a clean **WSL2 Ubuntu** — fresh procfs should succeed there, which restores the process tree and `ALK-008`
- [ ] Resource limits so a fork bomb cannot take down the host

**Exit criteria:** `airlock scan` on a real-world skill from ClawHub, on WSL2, with fresh procfs, producing a report you would show a security engineer without embarrassment.

### Weeks 3–4 — MCP mode + the verify loop
- [ ] **MCP server mode**: spawn over stdio, `tools/list`, call each tool with generated inputs, capture behaviour
- [ ] **Cross-server tool shadowing** detection: diff tool descriptions before/after a second server joins
- [ ] **Archive and binary unpacking** — the Trail of Bits bypass vector. Non-negotiable for credibility
- [ ] `airlock verify`: pin a policy manifest, fail on drift
- [ ] Payload-padding resistance: never truncate before analysis, report truncation explicitly
- [ ] Publish the **GitHub Action** and self-host CI on the repo

**Exit criteria:** a version-pinned policy that fails CI when `fixtures/05` replaces `fixtures/04`.

### Weeks 5–6 — The dataset *(highest leverage; do not skip or defer)*
- [ ] Fetch the top 1,000 skills by downloads from ClawHub / skills.sh
- [ ] Scan every one, in parallel, with a fixed timeout and a recorded manifest hash
- [ ] Publish: raw results, methodology, reproduction commands, the corpus hashes
- [ ] Write it up as an article with 5–10 real findings and screenshots
- [ ] Responsible disclosure on anything live and malicious

**Exit criteria:** a reproducible public dataset and a written report. This is the artifact that gets you cited.

### Weeks 7–8 — Distribution
- [ ] `airlock.dev` hosted report renderer (`report <url>` → public page)
- [ ] Landing page with the 10-second GIF and the dataset headline
- [ ] PR to OWASP AST10
- [ ] Launch sequence per §7
- [ ] Triage every issue within 24 hours for two weeks. Response time is the product at this stage
- [ ] Write `docs/architecture.md` explaining every design decision and tradeoff

---

## 10. Risks

Stated plainly, because the plan is worthless if the failure modes are hidden.

| Risk | Likelihood | Mitigation |
|---|---|---|
| **A vendor ships this** | High | They already have: Jiffy Labs is closed and commercial, Snyk needs a cloud token. Your position is *free, offline, canonical OSS* — the thing vendors structurally cannot ship. Speed matters; the window is 6–12 months |
| **Sandboxing is harder than expected** | Medium | Phase 1 already works on Linux namespaces with zero dependencies. Ship that, harden incrementally. Never block a release on the perfect sandbox |
| **Windows/WSL2 friction for contributors** | Medium | CI on `ubuntu-latest` is the source of truth. WSL2 is your dev environment, not the product's target |
| **False positives destroy trust** | High if ignored | Treat every FP as a bug. Ambient-read suppression and the `confidence` tiers already exist. Fixture `06` and the documented FP in `05` are regression tests for discrimination, not just detection |
| **Scanning real skills causes harm** | Medium | Scan only public artifacts, in isolation, with no credentials present, and never publish unredacted captures. Write the ethics into `SECURITY.md` before Week 5, not after |
| **You run out of time in Week 5** | High | The dataset is the deliverable that compounds. If you must cut, cut hosted reports and macOS — never cut Weeks 5–6 |
| **Category cools** | Low–Medium | The underlying capability (behavioural verification of untrusted code) transfers to CI/CD supply chain, plugin systems, and browser extensions. The skill ecosystem is the wedge, not the ceiling |

---

## 11. The hiring angle

You ranked this second, but it is nearly free upside from the same work, and it
is where this project beats a conventional portfolio piece by a wide margin.

**The problem with your current portfolio is not quality.** Your `leadflow-ai`
README — exact-quote citation validation with score capping, SSRF-safe fetching
with DNS pinning and TLS hostname verification, transactional budget quotas,
`pip-audit` in CI, and an explicit statement of its own limitations — shows more
discipline than most professional codebases. The problem is that it sits in the
most saturated category in software, where the demo looks identical to 40,000
others and rigour is invisible.

airlock makes that same rigour **the product**. Rigour is not a bonus feature
here; it is the entire value proposition. That is the shift.

What it signals, and to whom:

| Role | What airlock demonstrates |
|---|---|
| AI Infrastructure / Platform | Namespaces, mounts, seccomp, Landlock, overlayfs, cgroups — in Python, from scratch |
| Security Engineering | Threat modelling against a live, CVE-rich attack surface; SARIF; CI gating |
| Applied AI / Agent Engineering | You understand the agent stack well enough to know where it breaks |
| Founding / early engineer | Shipped a category-defining OSS tool solo, with a dataset people cite |

The combination — **AI + Linux systems + security** — is rare. Most "AI
engineers" have never called `mount(2)`. Most systems engineers cannot parse a
skill manifest. Very few can do both and explain why it matters.

**How to talk about it in an interview.** Do not describe features. Describe the
three decisions that show judgment:

1. *"I built canary correlation instead of pattern matching, because Trail of Bits
   demonstrated that every public scanner was bypassed in under an hour — and all
   three bypasses attack a scanner that reads the artifact. You cannot pad or
   prompt-inject a syscall trace."*
2. *"My first version reported all 28 decoy credentials as read. The baseline
   snapshot was hashing files, which advanced atime. I made the baseline stat-only
   and added a regression test, because a scanner with a 100% false-positive rate
   is worse than no scanner."*
3. *"I ship a fixture with a known false positive on purpose, and findings carry a
   `confidence` tier, because a tool that overstates its coverage is a liability."*

Those three answers do more than any star count.

**Practical notes:**
- Put the repo at the top of your profile and **pin it**. Unpin or archive the tutorial-grade repos; a cluttered profile dilutes the signal.
- Rewrite your GitHub bio from "AI Engineer & Data Scientist | NLP & CV enthusiast" to something with a claim in it: *"Building airlock — behavioural sandboxing for the agent skill supply chain."*
- Your `MuhammadBilal0021/MuhammadBilal0021` profile README should lead with airlock, the GIF, and one paragraph of why.
- Every existing repo needs a one-line description and topics. Several currently have none, which reads as abandoned.

---

## 12. What not to do

- **Do not build another agent framework, RAG wrapper, or chatbot.** That is the category you are trying to leave.
- **Do not add a database, an account system, or a web app in the first 8 weeks.** Every hour there is an hour not spent on the dataset.
- **Do not add an LLM dependency.** "No API key, no account, runs offline, zero dependencies" is a differentiator against Snyk specifically. Adding a GPT call surrenders it.
- **Do not chase macOS or native Windows early.** WSL2 is the supported path. Say so and move on.
- **Do not rename or restart.** The working code exists. Finish it.
- **Do not launch before the GIF is under 10 seconds and `pipx install` works.** You get one launch.

---

## Appendix: what is already built

Working and tested as of this brief — not planned, not aspirational:

- Namespace sandbox: user + mount + net + PID, `make-rprivate`, read-only host binds, chroot, adaptive `/proc` with honest coverage reporting
- Decoy machine: **14 canary-laced credentials** (SSH, AWS, `.env`, git, `gh`, npm, netrc, kubeconfig, Docker registry, Solana wallet, browser passwords, `.bash_history`), plus benign filler to test discrimination
- Canary correlation across 7 surfaces × 7 encodings (literal, upper, base64 standard/URL-safe, hex, reversed, both hostname-safe substitutions)
- atime-based read detection, with the baseline-hashing false-positive bug found and regression-tested
- Network sinkhole: hand-rolled DNS resolver answering `127.0.0.1`, TCP listeners on 28 ports, HTTP request parsing, **TLS ClientHello SNI extraction** (verified against a genuine Python `ssl` handshake), HTTP/HTTPS proxy with CONNECT logging
- Declared-capability parser: OpenClaw `SKILL.md` frontmatter, `skill.json`, `manifest.json`, `package.json`, MCP configs, and the full **OWASP Universal Skill Format**, with a hand-written recursive-descent YAML-subset parser (zero dependencies)
- 15 finding rules across `ALK-001`–`ALK-093`, each mapped to AST01–AST10, each carrying confidence and evidence
- Lethal Trifecta evaluation with an explicit basis for the middle leg
- Noise control: ambient libc/interpreter read suppression, scratch-write suppression, suppression disclosed in the report
- Four output formats: terminal, JSON, Markdown, **SARIF 2.1.0** (GitHub code-scanning compatible, with `security-severity` and AST tags)
- `airlock policy` — least-privilege Universal Skill Format manifest derived from observed behaviour
- `airlock demo` — six bundled fixtures: 1 benign, 4 malicious, 1 over-broad-but-honest
- 19 tests, including end-to-end sandbox regressions that fail if a malicious fixture stops being caught or a benign one starts being flagged
- GitHub Action + CI workflow across Python 3.9/3.11/3.12/3.13, with a regression gate asserting the malicious fixtures are still caught
- Zero runtime dependencies

The remaining work in §9 is hardening, MCP mode, and distribution — not
discovering whether the idea works. It works.
