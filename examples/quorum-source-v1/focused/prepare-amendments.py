"""Additive post-contract-amendment judgments; original46 remains untouched."""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')
CONTRACT = Path('/dev/shm/semantic-transport-source-membership-20261029/contract.json')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


original = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
base = original['cases'][0]
cases = []
for name, description in [
    ('A00_EMPTY_SOURCE_NONEMPTY_QUOTE', 'Empty original[0,0) but nonempty correctly bound quote differs; emptiness cannot override comparison.'),
    ('A01_JSON_21_DIGITS', 'Canonical-looking JSON integer token exceeds explicit20-digit parser budget, mapped to named resource refusal.'),
    ('A02_RESERVED_Q_RECORDS_ALIAS', 'Q_RECORDS is reserved metadata identity and cannot be an ordinary original alias.')]:
    row = copy.deepcopy(base)
    row['id'] = name
    row['manual_rationale'] = description
    body = json.loads(Path(base['body_raw']['path']).read_bytes())
    if name == 'A00_EMPTY_SOURCE_NONEMPTY_QUOTE':
        key = dict(body['sources'][0]['key'], bytes=0, sha256=sha(b''))
        body['sources'][0]['key'] = key
        body['selectors'][0].update(source=key, begin=0, end=0,
            quote_base64='YQ==', quote_bytes=1, quote_sha256=sha(b'a'))
        row.update(source_declared_hex='', source_actual_hex='', quote_hex='61', begin=0, end=0)
        row['originals_exact_tuple_recipe'][0].update(key=key, immutable_bytes_hex='')
        row['expected']['selector_statuses'] = ['DIFFERS']
    elif name == 'A01_JSON_21_DIGITS':
        raw = b'100000000000000000000'
        blob = {'id': 'BLOB', 'kind': 'PROVENANCE_EVIDENCE', 'encoding': 'CANONICAL_JSON',
            'base64': base64.b64encode(raw).decode('ascii'), 'bytes': len(raw), 'sha256': sha(raw)}
        body['blobs'] = [blob]
        row['blob_hex'] = raw.hex()
        row['expected'] = {'status': 'error', 'stage': 'BLOB_ENCODING', 'error': 'BLOB_JSON_RESOURCE'}
    else:
        body['sources'][0]['id'] = 'Q_RECORDS'
        row['originals_exact_tuple_recipe'][0]['alias'] = 'Q_RECORDS'
        row['expected'] = {'status': 'error', 'stage': 'SOURCE_SET', 'error': 'SOURCE_RESERVED_Q_RECORDS'}
    row['actual_blob_record'] = body['blobs'][0] if body['blobs'] else None
    row['actual_selector_record'] = body['selectors'][0]
    path = OUT / 'raw' / (name + '.body.json')
    path.write_bytes(encoded(body))
    row['body_raw'] = pin(path)
    cases.append(row)

amendment = {'scope': 'ADDITIVE_PRE_ORACLE_HANDWRITTEN_EXPECTATIONS',
    'implementation_inspected': False, 'oracle_execution': 'NOT_YET_RUN',
    'original_freeze': pin(OUT / 'pre-oracle-freeze.json'),
    'original_contract_retained': pin(OUT / 'original-contract-draft01.json'),
    'amended_contract': pin(CONTRACT), 'cases': cases}
(OUT / 'handwritten-amendments.json').write_bytes(encoded(amendment))
freeze = {'phase': 'AMENDMENTS_PRE_ORACLE_FROZEN',
    'amendments': pin(OUT / 'handwritten-amendments.json'),
    'source': pin(OUT / 'prepare-amendments.py'),
    'candidates': [row['body_raw'] for row in cases]}
(OUT / 'pre-oracle-amendments-freeze.json').write_bytes(encoded(freeze))
print(json.dumps({'cases': len(cases), 'freeze': pin(OUT / 'pre-oracle-amendments-freeze.json')}))
