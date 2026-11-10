"""Compute the pre-registered corpus-001 metrics from frozen scan results.

Implements research/corpus-001/PREREGISTRATION.md section 4 exactly:

* positive prediction = any finding with severity critical/high/medium, excluding
  the coverage-disclosure rules ALK-090/091/092/093;
* false-positive rate on B0 and recall on A0, each with a 95 % Wilson score
  interval and separate denominators;
* precision at 1 %, 5 %, 10 % and 50 % prevalence, never as one bare number;
* per-rule false-positive counts on B0;
* coverage and failure accounting, with failures excluded from denominators and
  reported next to them.

    python scripts/measure.py research/corpus-001
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

DISCLOSURE_RULES = {'ALK-090', 'ALK-091', 'ALK-092', 'ALK-093'}
POSITIVE_SEVERITIES = {'critical', 'high', 'medium'}
PREVALENCES = (0.01, 0.05, 0.10, 0.50)
Z = 1.959963984540054


def wilson(successes: int, total: int):
    """95 % Wilson score interval for a binomial proportion."""
    if total == 0:
        return None
    p = successes / total
    denominator = 1 + Z * Z / total
    centre = (p + Z * Z / (2 * total)) / denominator
    margin = Z * math.sqrt(p * (1 - p) / total + Z * Z / (4 * total * total)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def load_outcomes(results: Path):
    """Map sample id -> (status, positive, rule ids that fired)."""
    index = json.loads((results / 'index.json').read_text(encoding='utf-8'))
    outcomes = {}
    for record in index:
        report = json.loads((results / record['report']).read_text(encoding='utf-8'))
        airlock = report.get('airlock_report') or {}
        fired = [f for f in airlock.get('findings', [])
                 if f.get('severity') in POSITIVE_SEVERITIES
                 and f.get('rule_id') not in DISCLOSURE_RULES]
        outcomes[record['id']] = {
            'status': record.get('status', 'failed'),
            'positive': bool(fired),
            'rules': sorted({f['rule_id'] for f in fired}),
            'labels': sorted({f.get('severity') for f in fired}),
        }
    return outcomes


def rate(k, n):
    if n == 0:
        return None
    return {'k': k, 'n': n, 'value': k / n, 'ci95': wilson(k, n)}


def precision_at(prevalence: float, recall: float, fpr: float):
    denominator = prevalence * recall + (1 - prevalence) * fpr
    if denominator == 0:
        return None
    return prevalence * recall / denominator


def pct(value):
    return 'n/a' if value is None else f'{value * 100:.1f} %'


def ci_text(interval):
    if not interval:
        return 'n/a'
    return f'[{interval[0] * 100:.1f}, {interval[1] * 100:.1f}]'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', help='corpus root containing benign/ and adversarial/')
    parser.add_argument('--results', default=None,
                        help='results root (default: <corpus>/results)')
    parser.add_argument('--out', default=None,
                        help='report output directory (default: corpus root)')
    parser.add_argument('--benign-manifest', default=None,
                        help='manifest for B0 (default: <corpus>/benign/manifest.json)')
    parser.add_argument('--adversarial-manifest', default=None,
                        help='manifest for A0 (default: <corpus>/adversarial/manifest.json)')
    args = parser.parse_args()
    root = Path(args.corpus).resolve()
    results_root = (Path(args.results).resolve() if args.results
                    else root / 'results')
    out = Path(args.out).resolve() if args.out else root

    benign_manifest_path = (Path(args.benign_manifest).resolve()
                            if args.benign_manifest
                            else root / 'benign' / 'manifest.json')
    adversarial_manifest_path = (Path(args.adversarial_manifest).resolve()
                                 if args.adversarial_manifest
                                 else root / 'adversarial' / 'manifest.json')
    benign_manifest = json.loads(benign_manifest_path.read_text(encoding='utf-8'))
    adversarial_manifest = json.loads(
        adversarial_manifest_path.read_text(encoding='utf-8'))
    labels = json.loads(
        (adversarial_manifest_path.parent / 'labels.json').read_text(encoding='utf-8'))

    benign = load_outcomes(results_root / 'benign')
    adversarial = load_outcomes(results_root / 'adversarial')
    adversarial_behavioural_path = results_root / 'adversarial-behavioural'
    behavioural = (load_outcomes(adversarial_behavioural_path)
                   if adversarial_behavioural_path.exists() else {})
    benign_behavioural_path = results_root / 'benign-behavioural'
    benign_behavioural = (load_outcomes(benign_behavioural_path)
                          if benign_behavioural_path.exists() else {})

    report = {'preregistration': 'research/corpus-001/PREREGISTRATION.md',
              'corpora': {'benign_n': len(benign_manifest['skills']),
                          'adversarial_n': len(adversarial_manifest['skills'])},
              'statuses': {},
              'benign': {},
              'adversarial': {},
              'precision_at_prevalence': {},
              'rule_false_positives': {},
              'failures': {}}

    # --- coverage / failure accounting -------------------------------------
    for name, outcomes in (('benign', benign), ('adversarial', adversarial),
                           ('adversarial-behavioural', behavioural),
                           ('benign-behavioural', benign_behavioural)):
        report['statuses'][name] = dict(Counter(o['status'] for o in outcomes.values()))

    # --- B0 false positives -------------------------------------------------
    benign_scanned = {k: v for k, v in benign.items() if v['status'] != 'failed'}
    benign_positives = sum(1 for v in benign_scanned.values() if v['positive'])
    report['benign']['false_positive_rate'] = rate(benign_positives, len(benign_scanned))
    report['benign']['excluded_failed'] = len(benign) - len(benign_scanned)

    rule_fp = Counter()
    for value in benign_scanned.values():
        rule_fp.update(value['rules'])
    report['rule_false_positives']['benign'] = dict(rule_fp)

    # --- B0 behavioural false positives (only when that pass was run) -------
    if benign_behavioural:
        executed = {k: v for k, v in benign_behavioural.items()
                    if v['status'] == 'completed'}
        executed_positives = sum(1 for v in executed.values() if v['positive'])
        report['benign']['behavioural'] = {
            'executed_n': len(executed),
            'static_only_n': sum(1 for v in benign_behavioural.values()
                                 if v['status'] == 'static_only'),
            'failed_n': sum(1 for v in benign_behavioural.values()
                            if v['status'] == 'failed'),
            'false_positive_rate': rate(executed_positives, len(executed)),
            'by_status': dict(Counter(o['status'] for o in benign_behavioural.values())),
            'rules': dict(Counter(rule for v in executed.values() for rule in v['rules'])),
        }
        report['rule_false_positives']['benign_behavioural'] = report[
            'benign']['behavioural']['rules']

    # --- A0 recall ----------------------------------------------------------
    adversarial_scanned = {k: v for k, v in adversarial.items() if v['status'] != 'failed'}
    positives = sum(1 for v in adversarial_scanned.values() if v['positive'])
    report['adversarial']['recall'] = rate(positives, len(adversarial_scanned))
    report['adversarial']['excluded_failed'] = len(adversarial) - len(adversarial_scanned)

    family_rows = {}
    for sample_id, value in adversarial_scanned.items():
        meta = labels.get(sample_id, {})
        for key in (meta.get('level', '?'), meta.get('family', '?')):
            bucket = family_rows.setdefault(key, {'k': 0, 'n': 0})
            bucket['n'] += 1
            bucket['k'] += 1 if value['positive'] else 0
    report['adversarial']['by_group'] = {
        key: {'k': v['k'], 'n': v['n'], 'recall': v['k'] / v['n'] if v['n'] else None,
              'ci95': wilson(v['k'], v['n'])}
        for key, v in sorted(family_rows.items())}

    report['rule_false_positives']['adversarial_detected'] = dict(Counter(
        rule for v in adversarial_scanned.values() for rule in v['rules']))

    # --- A0 behavioural recall (only when that pass was run) ----------------
    if behavioural:
        b_ids = {sid for sid, meta in labels.items() if meta.get('level') == 'B'}
        b_scanned = {k: v for k, v in behavioural.items()
                     if k in b_ids and v['status'] != 'failed'}
        b_positives = sum(1 for v in b_scanned.values() if v['positive'])
        b_families = {}
        for sample_id, value in b_scanned.items():
            bucket = b_families.setdefault(labels[sample_id]['family'],
                                           {'k': 0, 'n': 0})
            bucket['n'] += 1
            bucket['k'] += 1 if value['positive'] else 0
        report['adversarial']['behavioural'] = {
            'target_n': len(b_ids),
            'scanned_n': len(b_scanned),
            'excluded_failed': len(b_ids) - len(b_scanned),
            'recall': rate(b_positives, len(b_scanned)),
            'by_family': {key: {'k': value['k'], 'n': value['n'],
                                'recall': value['k'] / value['n'] if value['n'] else None,
                                'ci95': wilson(value['k'], value['n'])}
                          for key, value in sorted(b_families.items())},
            'rules_detected': dict(Counter(rule for value in b_scanned.values()
                                           for rule in value['rules'])),
        }

    # --- prevalence-adjusted precision --------------------------------------
    recall = report['adversarial']['recall']
    fpr = report['benign']['false_positive_rate']
    if recall and fpr:
        for prevalence in PREVALENCES:
            report['precision_at_prevalence'][f'{prevalence:.0%}'] = {
                'value': precision_at(prevalence, recall['value'], fpr['value']),
                'inputs': {'recall': recall['value'], 'fpr': fpr['value']}}

    report['failures']['benign'] = [
        {'id': k, 'status': v['status']} for k, v in benign.items()
        if v['status'] == 'failed']
    report['failures']['adversarial'] = [
        {'id': k, 'status': v['status']} for k, v in adversarial.items()
        if v['status'] == 'failed']

    (out / 'measurement.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

    # --- markdown -----------------------------------------------------------
    lines = ['# corpus-001 measurement', '',
             'Generated by `scripts/measure.py` from the frozen pre-registration. '
             'Static (declaration-only) results cover every sample; the behavioural '
             'section covers only samples that ship an executable entrypoint.', '',
             '## Coverage', '',
             '| Corpus | n | statuses | excluded from denominators |',
             '|---|---|---|---|']
    for name in ('benign', 'adversarial'):
        lines.append(f'| {name} | {report["corpora"][name + "_n"]} | '
                     f'`{json.dumps(report["statuses"][name])}` | '
                     f'{report[name]["excluded_failed"]} failed |')

    result_rows = [
        f'| False-positive rate (B0, benign) | '
        f'{pct(report["benign"]["false_positive_rate"]["value"])} '
        f'({benign_positives}/{len(benign_scanned)}) | '
        f'{ci_text(report["benign"]["false_positive_rate"]["ci95"])} |',
        f'| Recall (A0, adversarial) | '
        f'{pct(report["adversarial"]["recall"]["value"])} '
        f'({positives}/{len(adversarial_scanned)}) | '
        f'{ci_text(report["adversarial"]["recall"]["ci95"])} |']
    if 'behavioural' in report['adversarial']:
        result_rows.append(
            f'| Recall, behavioural path (A0 level B) | '
            f'{pct(report["adversarial"]["behavioural"]["recall"]["value"])} '
            f'({report["adversarial"]["behavioural"]["recall"]["k"]}/'
            f'{report["adversarial"]["behavioural"]["recall"]["n"]}) | '
            f'{ci_text(report["adversarial"]["behavioural"]["recall"]["ci95"])} |')
    lines += ['', '## Results', '',
              '| Metric | Value | 95 % Wilson CI |', '|---|---|---|',
              *result_rows, '']

    real_behaviour = report['benign'].get('behavioural')
    if real_behaviour:
        lines.insert(len(lines) - 1,
                     f'| False-positive rate, behavioural path (B0) | '
                     f'{pct(real_behaviour["false_positive_rate"]["value"])} '
                     f'({real_behaviour["false_positive_rate"]["k"]}/'
                     f'{real_behaviour["false_positive_rate"]["n"]}) | '
                     f'{ci_text(real_behaviour["false_positive_rate"]["ci95"])} |')

    lines += ['## Recall by attack level and family (static path)', '',
              '| Group | Sensitive (k/n) | Recall | 95 % CI |', '|---|---|---|---|']
    for key, value in report['adversarial']['by_group'].items():
        lines.append(f'| {key} | {value["k"]}/{value["n"]} | {pct(value["recall"])} | '
                     f'{ci_text(value["ci95"])} |')

    beh = report['adversarial'].get('behavioural')
    if beh:
        lines += ['', '## Behavioural path (samples executed in the sandbox)', '',
                  f'Behaviour-level samples executed: {beh["scanned_n"]}/{beh["target_n"]} '
                  f'({beh["excluded_failed"]} failed and excluded from the denominator). '
                  'Instruction-level samples have no entrypoint, so they cannot be '
                  'executed by design and remain declaration-only.', '',
                  '| Family | Sensitive (k/n) | Recall | 95 % CI |', '|---|---|---|---|']
        for key, value in beh['by_family'].items():
            lines.append(f'| {key} | {value["k"]}/{value["n"]} | {pct(value["recall"])} | '
                         f'{ci_text(value["ci95"])} |')
        lines += ['', '| Rule | Behavioural detections |', '|---|---|']
        for rule, count in sorted(beh['rules_detected'].items()):
            lines.append(f'| {rule} | {count} |')

    if real_behaviour:
        lines += ['', '## Behavioural path on real skills', '',
                  f'{real_behaviour["executed_n"]} of {report["corpora"]["benign_n"]} '
                  f'real packages executed; {real_behaviour["static_only_n"]} stayed '
                  'declaration-only (no entrypoint discovered) and '
                  f'{real_behaviour["failed_n"]} failed. Rate denominators use only '
                  'executed packages.', '',
                  '| Status | Count |', '|---|---|']
        for status, count in sorted(real_behaviour['by_status'].items()):
            lines.append(f'| {status} | {count} |')
        lines += ['', '| Rule | False positives on real skills |', '|---|---|']
        for rule, count in sorted(real_behaviour['rules'].items()):
            lines.append(f'| {rule} | {count} |')

    lines += ['', '## Precision at assumed prevalence', '',
              '| Prevalence | Precision |', '|---|---|']
    for prevalence, value in report['precision_at_prevalence'].items():
        lines.append(f'| {prevalence} | {pct(value["value"])} |')

    lines += ['', '## Rules firing on benign samples', '',
              '| Rule | Benign samples |', '|---|---|']
    for rule, count in sorted(rule_fp.items()):
        lines.append(f'| {rule} | {count} |')

    (out / 'MEASUREMENT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')

    print(json.dumps({
        'benign_fpr': report['benign']['false_positive_rate'],
        'adversarial_recall': report['adversarial']['recall'],
        'behavioural_recall': report['adversarial'].get(
            'behavioural', {}).get('recall'),
        'by_group': report['adversarial']['by_group'],
        'statuses': report['statuses'],
    }, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
