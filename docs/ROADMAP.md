# Roadmap

Ordered by what would change a conclusion, not by what is interesting to build.

## Now — finish v0.1 (packaging, not engineering)

- [ ] Tag `v0.1.0` with the measurement rounds included
- [ ] Two-minute demo recording (see [DEMO.md](DEMO.md))
- [ ] Publish the measurement write-up
- [ ] Consolidate the corpus rounds into one reproducible page (done:
      [MEASUREMENTS.md](MEASUREMENTS.md))

## Next — the one capability that changes the product

### Instruction-execution harness (text-only skills)

91% of real skills are prose. Today they are only inspectable with text
heuristics (55% recall, 0% on obfuscation). The reframe: a text skill is executed
by the **agent**, so behavioural analysis means running an agent with the skill
installed, mocked tools, decoy credentials and no network, then observing which
tool calls it is induced to make.

Design constraints, decided up front:

- the verdict comes from the **observed tool call**, not from a model's opinion;
- the agent has no shell, no network, no way to alter the harness;
- N runs per sample, pre-registered protocol, distribution reported rather than a
  single sample;
- evaluated on the 224 real text skills (false positives) and the 40 authored
  instruction attacks (recall).

Success metric: instruction-attack recall above 80% at a false-positive rate
below 3%, published with intervals.

### Input materialisation

Three executable packages fail solely because a script needs a real document.
Generate one fixture per family (docx, pdf, xlsx, chart spec) so `--help` becomes
an invocation. Turns usage errors into observations.

## Later — what makes it a standard rather than a tool

- **Signed receipts.** A portable attestation: what ran, on which runtime, with
  what coverage, reproducible from a digest. Independent evidence is what
  enterprises procure.
- **Harness library at scale.** Coverage is the moat: the deterministic rules
  that let any published skill be started correctly.
- **Real-world labelled corpus.** Red-team submissions, published incidents,
  registry partnerships. This is the only way to measure real-world recall.
- **MCP servers.** Extend the same declared-vs-observed model to MCP tool
  surfaces; measure before claiming.
- **Independent containment audit.** The sandbox's escape resistance is untested
  by a third party. Until it is, the claim stays "isolated by design", not
  "verified isolated".

## What is explicitly not planned

- **An LLM as the verdict.** Non-deterministic, injectable, unauditable. Models
  may move code into the box or explain a finding; they do not decide.
- **A claim that clean means safe.** The honest claim is: no violation observed,
  under this coverage, on this runtime.
- **Chasing 100% recall on the authored corpus.** It is circular and would be
  optimising against the test set.
