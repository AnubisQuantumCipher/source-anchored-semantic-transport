"""Local finite literal integrity/path-validity audit, not an impact evaluator."""
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-impact-controls-20261029')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def path_valid(claim_id, path, dependencies):
    current = claim_id
    final = None
    for dependency_id in path['dependency_ids']:
        record = dependencies[dependency_id]
        if record['dependent'] != {'claim_id': current, 'revision': 'V1'}:
            return False
        target = record['requires']
        if target['kind'] == 'CLAIM':
            current = target['claim']['claim_id']
        else:
            if dependency_id != path['dependency_ids'][-1]:
                return False
            final = target['source']
    return final == path['seed']


frozen = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
rows = []
for case in frozen['cases']:
    path = Path(case['body_raw']['path'])
    raw = path.read_bytes()
    body = json.loads(raw)
    original_ok = all(len(bytes.fromhex(item['immutable_bytes_hex'])) == item['key']['bytes']
        and hashlib.sha256(bytes.fromhex(item['immutable_bytes_hex'])).hexdigest() == item['key']['sha256']
        for item in case['originals_exact_tuple_recipe'])
    expected = case['handwritten_expected_complete_result']
    result_bytes = len(encoded(expected)) + 1
    dependencies = {item['id']: item for item in body['dependencies']}
    paths_ok = True
    path_lengths = {}
    if expected['status'] == 'ok':
        for item in expected['claims']:
            paths_ok = paths_ok and all(path_valid(item['claim']['claim_id'], record, dependencies) for record in item['paths'])
            path_lengths[item['claim']['claim_id']] = len(item['paths'])
    rows.append({'id': case['id'], 'body_pin_matches': pin(path) == case['body_raw'],
        'body_canonical_bytes_match': encoded(body) == raw,
        'source_identity_construction_consistent': original_ok,
        'expected_labeled_paths_follow_declared_edges_to_seed': paths_ok,
        'positive_expected_output_bytes_including_LF': result_bytes if expected['status'] == 'ok' else None,
        'positive_expected_output_within_cap': result_bytes <= 32768,
        'positive_path_counts_observed': path_lengths,
        'body_bytes_observed': len(raw)})
failures = [row for row in rows if not all(row[key] for key in ['body_pin_matches',
    'body_canonical_bytes_match', 'source_identity_construction_consistent',
    'expected_labeled_paths_follow_declared_edges_to_seed', 'positive_expected_output_within_cap'])]
result = {'classification': 'OBSERVED_FROZEN_LITERAL_INTEGRITY_AND_PATH_VALIDITY_ONLY',
    'no_future_impact_checker_imported_or_executed': True,
    'source': pin(OUT / 'audit-literals.py'),
    'expectations': pin(OUT / 'handwritten-expectations.json'), 'cases': rows, 'failures': failures,
    'qualification': 'Does not enumerate paths or infer triggers/conflicts/history/refusal outcomes. Expected paths and classifications remain handwritten. This audit checks only byte construction, positive result sizes and validity of supplied expected labeled paths; it does not prove completeness or product behavior.'}
path = OUT / 'literal-audit-first-run.json'
with path.open('xb') as stream:
    stream.write(encoded(result))
print(json.dumps({'audit': pin(path), 'cases': len(rows), 'failures': [row['id'] for row in failures]}))
