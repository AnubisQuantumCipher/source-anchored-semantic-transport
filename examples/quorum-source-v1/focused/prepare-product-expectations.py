"""Freeze full named errors and source-success projection before product run."""
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


original = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
amended = json.loads((OUT / 'handwritten-amendments.json').read_bytes())
cases = []
for row in original['cases'] + amended['cases']:
    path = Path(row['body_raw']['path'])
    if pin(path) != row['body_raw']:
        raise ValueError('frozen source candidate changed')
    body = json.loads(path.read_bytes())
    expected = copy.deepcopy(row['expected'])
    if expected['status'] == 'ok':
        statuses = expected.pop('selector_statuses')
        expected.update(body_pin={key: row['body_raw'][key] for key in ['bytes', 'sha256']},
            source_index=[{'id': source['id'], 'key': source['key']} for source in sorted(body['sources'], key=lambda part: part['id'])],
            blob_index=[{key: blob[key] for key in ['id', 'kind', 'encoding', 'bytes', 'sha256']} for blob in sorted(body['blobs'], key=lambda part: part['id'])],
            selectors=[{'id': selector['id'], 'status': status} for selector, status in zip(sorted(body['selectors'], key=lambda part: part['id']), statuses)],
            source_authentication='UNVERIFIED', current_authority='NONE', freshness='UNKNOWN')
    cases.append({'id': row['id'], 'raw': row['body_raw'],
        'originals_exact_tuple_recipe': row['originals_exact_tuple_recipe'],
        'expected_complete_result': expected, 'manual_rationale': row['manual_rationale']})
result = {'scope': 'PRE_PRODUCT_FROZEN_EXPECTATIONS_NO_PRODUCT_IMPORT',
    'derivation': 'Named error envelopes preserved exactly. Complete success projection derives only from pre-oracle handwritten selector statuses, exact frozen Body bytes and declared contract result shape; no runtime behavior used.',
    'source_pins': [pin(OUT / name) for name in ['handwritten-expectations.json',
        'handwritten-amendments.json', 'amended-contract-frozen.json',
        'prepare-product-expectations.py']], 'cases': cases}
path = OUT / 'product-differential-expectations.json'
with path.open('xb') as stream:
    stream.write(encoded(result))
print(json.dumps({'cases': len(cases), 'expectations': pin(path)}))
