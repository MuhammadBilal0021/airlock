# I ran 245 real agent skills in a sandbox. 91% of them were just text.

*Or: why scanning agent skills with a text scanner is theatre.*

Agent skills are the new npm, and the poisoning has already happened. Snyk's
audit of 3,984 skills found 1,467 with security flaws and 76+ confirmed malicious
payloads. ClawHub went from registry to malware distribution in weeks. Microsoft
Defender's advice on OpenClaw is blunt: treat it as untrusted code execution with
persistent credentials.

So the market filled with scanners. Almost all of them read the text of
`SKILL.md` and pattern-match. I wanted to know how well that actually works, so I
built a behavioural sandbox and measured both approaches on the same samples.

## What I built

`airlock` runs an untrusted skill inside a Linux namespace with no network route,
against a synthetic home directory seeded with canary credentials. Then it diffs
what the skill **declared** against what it **did**: files read, hosts contacted,
processes spawned, persistence locations written, evidence deleted.

The verdict is deterministic and reproducible. No model decides anything.

## Round 1 — 245 real skills, 100 attacks

I pinned 245 real packages from five public repositories by commit SHA and
per-file hash, then authored 100 adversarial packages across 20 technique
families. Everything was frozen before the first scan: metrics, thresholds,
confidence intervals, and a commitment to publish failures.

| What I measured | Result |
|---|---|
| False positives on the 245 real skills | **2.45%** (6/245) |
| Recall, instruction-level attacks (text) | **55%** (22/40) |
| Recall, code-level attacks — **text analysis** | **0%** (0/60) |
| Recall, code-level attacks — **behavioural** | **83.3%** (50/60) |

That zero is the whole argument. Text scanners cannot see what a shell script
does. On the same 60 samples, watching the code run caught 55 of them.

The six false positives were all the same failure mode: documentation. A heading
that said "System Prompt Design", an example CI workflow containing
`AWS_SECRET_ACCESS_KEY`, a password-hygiene tip that said "never ask the user to
send passwords" — all read as attacks.

## Round 2 — fixing precision for free

I changed the rules to require an action, not a noun phrase: mask fenced code
blocks and headings, require a verb for system-prompt references, widen the
negation window. Then I re-ran the same frozen corpus.

| | Before | After |
|---|---|---|
| False positives | 2.45% | **0%** |
| Static recall | 22% | **22%** (unchanged) |
| Behavioural recall | 83.3% | **91.7%** |

Zero false positives, no recall lost. That's rarer than it sounds; precision and
recall usually trade.

## Round 3 — the uncomfortable correction

My first coverage headline was "5 of 245 skills executed = 2% coverage". That was
wrong, and the correction matters for the whole market:

- **224 of 245 real skills (91.4%) contain no executable code at all.** They are
  prose instructions.
- **21 (8.6%) ship code.**

You cannot behaviourally analyse a package that contains nothing to run. The real
question is coverage *of the skills that can be run*, and after building a
deterministic harness rule I got **21/21 = 100%** of them to start.

But only **4/21 (19%)** ran to a clean exit.

## Round 4 — the wall behind the wall

I built a root-free runtime overlay (Node, pip, document libraries) mounted
read-only into the sandbox. The `command not found` class disappeared, and clean
start still didn't move — because the failures changed shape: Node now aborted
under a 512 MiB address-space cap, and Python scripts died on missing inputs.

Then I instrumented the harness to capture each specimen's stderr. Every failure
got a name: missing runtime, resource limit, an ignored shebang (my bug), missing
dependency, missing external service, missing input file, ES-module semantics.
After fixing what was fixable: clean start **4/21 → 8/21 (38%)**, every remaining
failure attributed.

And the first behavioural false positive appeared: a benign Anthropic scaffolding
script that installs packages — which means reading credential config and
contacting a registry. Behaviourally, that is what a supply-chain attack looks
like. Intent and behaviour diverge, and that gap is the actual hard problem in
this category.

## What this means

1. **Text-only scanning is not security.** It is 0% effective against code-level
   attacks, and its false positives land on documentation, which is what
   legitimate skills are made of.
2. **Behavioural analysis works, but coverage is the product.** The engineering
   problem is not "detect", it is "start safely and correctly".
3. **91% of the registry is prose that no sandbox can run.** Which means the next
   real advance is not a better scanner — it is an agent-in-the-loop harness that
   executes instructions against a mocked environment and observes which tool
   calls the skill induces.

## What I'm not claiming

The adversarial corpus was authored by me, with knowledge of the rule set, so its
recall is a ceiling. Real-world malicious-skill recall is unmeasured. The
behavioural false-positive rate has too few executed samples to be a rate. No
independent containment audit has been done. All of this is in the repo,
including the rounds that make the project look worse.

Apache-2.0, zero dependencies, runs in your CI. If you deploy agent skills or MCP
servers and want an independent way to say what they actually did, I'd like to
talk.

— [GitHub: MuhammadBilal0021/airlock](https://github.com/MuhammadBilal0021/airlock)
