# Measurements

Every number here comes from a frozen pre-registration, is reproducible from a
pinned corpus, and includes its failures. Rounds are never edited after the fact;
a correction or a new fix gets a new round.

## The rounds

| Round | Question | Headline result | Report |
|---|---|---|---|
| **corpus-001** | Does it detect at registry scale? | FPR **2.45%** on 245 real skills; static recall **22%** overall, **55%** on text attacks, **0%** on code attacks; behavioural recall **83.3%** | [REPORT](../research/corpus-001/REPORT.md) |
| **corpus-002** | Did fixing the 6 false positives cost anything? | FPR **2.45% → 0%** with **zero recall lost**; behavioural recall **83.3% → 91.7%** after adding anti-forensics | [REPORT](../research/corpus-002/REPORT.md) |
| **corpus-003** | How much of the registry can actually be run? | **91.4%** of real skills are pure text; addressable set is **21/245**; harness synthesis reaches **100% coverage** of it, clean start **4/21 = 19%** | [REPORT](../research/corpus-003/REPORT.md) |
| **corpus-004** | Does supplying runtimes help? | Root-free runtime overlay eliminates every `command not found`; clean start still **19%** — the next wall is resources and inputs | [REPORT](../research/corpus-004/REPORT.md) |
| **corpus-004 diagnosis** | Why exactly do executable skills fail? | stderr instrumentation names every cause; clean start **4/21 → 8/21 = 38%**; first behavioural false positive documented | [DIAGNOSIS](../research/corpus-004/DIAGNOSIS.md) |

## What the rounds together establish

1. **Text analysis is not a malware detector.** 0 of 60 code-level attacks are
   visible to the declaration-only path; 55% of text-embedded attacks and none of
   the obfuscated variants are caught.
2. **Behavioural observation works when it can run.** 92% of code-level attacks
   were caught with reproducible evidence (undeclared reads, egress, persistence,
   evidence destruction).
3. **Coverage was never 2%.** 91% of real skills contain no executable code at
   all; of the 21 that do, every one can now be started (100%), and 38% run to a
   clean exit after runtime and harness fixes.
4. **Precision can be fixed without losing recall.** Six false positives on real
   documentation were removed with a net recall gain, because the same round also
   fixed a detection gap.
5. **Benign tooling looks like an attack.** The first behavioural false positive
   is documented: a scaffolding script that installs packages behaves like a
   supply-chain attack. Intent and behaviour diverge, and that is the hard
   product problem.

## What is not measured (stated plainly)

- **Real-world malicious skill recall.** No ethically obtainable, verifiable
  corpus of real malicious skills exists at scale. The 100 adversarial packages
  were authored with knowledge of the rule set, so their recall is a ceiling.
- **Behavioural false-positive rate at a usable sample size.** 8 real packages
  executed at a clean start; 1 was flagged. That is a case, not a rate.
- **MCP servers.** The corpus is skills. MCP is in the architecture but not in
  these measurements.
- **Sandbox escape resistance.** The sandbox is built to be tested for it; no
  independent audit has been performed.

## Method

Each round lives in `research/corpus-00N/PREREGISTRATION.md` and is frozen before
the first scan. Corpora are pinned by commit SHA and per-file SHA-256; the
adversarial set is generated from a fixed seed. Metrics use Wilson 95% intervals,
separate denominators, and report failed runs rather than dropping them.

Reproduce the whole thing:

```sh
python scripts/acquire_corpus.py --output research/corpus-001/benign
python scripts/generate_adversarial_corpus.py --output research/corpus-001/adversarial
python scripts/scan_dataset.py research/corpus-001/benign/manifest.json \
    --output research/corpus-001/results/benign --static-only
python scripts/measure.py research/corpus-001
```
