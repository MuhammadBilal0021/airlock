"""Compare preserved before/after runs; require identical pinned inputs."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    rows = []
    for original in sorted(args.before.glob('*-run*.json')):
        old = json.loads(original.read_text())
        new = json.loads((args.after / original.name).read_text())
        assert old['provenance'] == new['provenance'], original.name
        assert old['case_file_sha256'] == new['case_file_sha256'], original.name
        assert old['entry'] == new['entry'], original.name
        assert new['status'] == 'completed' and new['expected_output_confirmed']
        before, after = old['airlock_report'], new['airlock_report']
        rows.append({'package': new['provenance']['id'], 'repetition': new['repetition'],
                     'before': before['verdict'], 'after': after['verdict'],
                     'score_before': before['risk_score'], 'score_after': after['risk_score'],
                     'findings_after': [{'rule': f['rule_id'], 'severity': f['severity'],
                                         'evidence_count': len(f['evidence'])} for f in after['findings']],
                     'write_policy': after['coverage'].get('write_policy'),
                     'files_written_before': before['observed']['files_written'],
                     'files_written_after': after['observed']['files_written']})
    assert len(rows) == 20
    (args.after / 'calibration-comparison.json').write_text(json.dumps({
        'same_pinned_inputs': True, 'same_entrypoints': True, 'runs': rows}, indent=2))
    for row in rows:
        if row['repetition'] == 1:
            print(row['package'], row['before'], '->', row['after'], row['findings_after'])


if __name__ == '__main__':
    main()
