"""Re-score consumed text cases; this is calibration, not a fresh holdout."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from airlock.declared import CapabilityDeclaration, find_embedded_instructions


def main():
    baseline = ROOT / 'research/heldout-002'
    output = ROOT / 'research/instruction-context-001/results.json'
    if output.exists():
        raise SystemExit('Refusing to overwrite an existing calibration result')
    plan = json.loads((baseline / 'plan.json').read_text())
    previous = json.loads((baseline / 'text-results.json').read_text())
    counts, cases = Counter(), []
    for case in plan['text_cases']:
        hits = find_embedded_instructions(CapabilityDeclaration(
            instruction_surface=[('synthetic:body', case['text'])]))
        label = ('true_positive' if hits else 'false_negative') if case['expected_instruction'] else (
            'false_positive' if hits else 'true_negative')
        counts[label] += 1
        cases.append({**case, 'classification': label, 'hits': hits})
    digest = hashlib.sha256()
    for path in sorted((ROOT / 'airlock').glob('*.py')):
        digest.update(path.name.encode() + b'\0' + path.read_bytes())
    result = {'method': 'Consumed holdout regression; not independent validation',
              'rules_sha256': digest.hexdigest(),
              'baseline_plan_sha256': hashlib.sha256((baseline / 'plan.json').read_bytes()).hexdigest(),
              'before': previous['counts'], 'after': dict(counts), 'cases': cases}
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'before': result['before'], 'after': result['after']}, indent=2))


if __name__ == '__main__':
    main()
