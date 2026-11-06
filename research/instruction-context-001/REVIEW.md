# ALK-009 context calibration

The earlier frozen evaluation exposed three false positives and four false
negatives. This change uses those cases as development regressions. Original
`heldout-001` and `heldout-002` artifacts remain unchanged.

Changes in `airlock/declared.py`:

- BCC and authority language require nearby action wording rather than isolated
  vocabulary. Existing finding reason names remain compatible.
- Sensitive-data transfer actions cover additional vocabulary and word order.
  The spaced-adverb case is detected through its intact transfer action and
  sensitive target, not through general deobfuscation.
- Explicitly rejected quoted examples and locally negated actions are discounted.
  Quotes alone do not exempt instructions. Later active directives still match,
  with offsets and excerpts retained from the original text.
- Implicit statements that prior constraints are obsolete are detected.

The reproducible `scripts/evaluate_instruction_context.py` report records the
new scanner hash and old plan hash. On these consumed cases, benign false
positives changed from 3/8 to 0/8 and adversarial misses from 4/8 to 0/8.
See [results](results.json). This is a calibration result, not a new holdout or
a general accuracy claim.

Four new test methods cover the consumed labels, ordinary documentation,
negation, quoted examples, later active instructions, original offsets and
action-backed authority/BCC directives. The full Linux validation log is
[tests.log](tests.log), including live containment and malicious fixtures.

Final validation: 66/67 passed with zero skips in 186.449 seconds. The benign
weather fixture lacked its expected `api.weather.gov` observation; the suite
was substantially slower than the preceding run. That test passed twice on
unchanged code in 2.178 seconds in [weather-recheck.log](weather-recheck.log).
This supports an intermittent execution/observation issue, but does not prove
its cause. It is not a clean full-suite pass. All instruction-context tests,
malicious behavior fixtures and containment tests passed in the final suite.
Investigate the weather observation under load as a separate reliability task;
do not remove the assertion or weaken containment to make it pass.

Remaining limitations: bounded lexical windows do not establish grammatical
intent, broad quotation/negation understanding, or arbitrary obfuscation recall.
Documentation containing action examples may still flag; novel attacks may
still evade. The next evaluation should freeze these rules against fresh labels
before examining results. No additional real-package execution is claimed for
this calibration; the prior helper executions remain historical evidence.
