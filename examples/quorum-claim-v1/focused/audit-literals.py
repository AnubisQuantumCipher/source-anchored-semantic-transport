"""Finite byte-construction audit only; no new claim evaluator/product import."""
import base64
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-claim-structure-controls-20261029')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def identity(raw, size, digest):
    return len(raw) == size and hashlib.sha256(raw).hexdigest() == digest


frozen = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
rows = []
for case in frozen['cases']:
    path = Path(case['body_raw']['path'])
    raw = path.read_bytes()
    body = json.loads(raw)
    originals = case['originals_exact_tuple_recipe']
    source_map = {item['alias']: bytes.fromhex(item['immutable_bytes_hex']) for item in originals}
    source_identity_ok = all(identity(source_map[item['id']], item['key']['bytes'], item['key']['sha256']) for item in body['sources'])
    quote_identity_ok = True
    for selector in body['selectors']:
        quote = base64.b64decode(selector['quote_base64'], validate=True)
        quote_identity_ok = quote_identity_ok and identity(quote, selector['quote_bytes'], selector['quote_sha256'])
        quote_identity_ok = quote_identity_ok and base64.b64encode(quote).decode('ascii') == selector['quote_base64']
    equality = encoded(case['source_statement']) == encoded(case['claim_statement'])
    asserted_match = case['manual_interpretation'] == 'MATCHED_DECLARATION_STRUCTURE_ONLY'
    asserted_diff = case['manual_interpretation'] == 'DIFFERS_DECLARATION_STRUCTURE_ONLY'
    expected_equality_ok = equality if asserted_match else not equality if asserted_diff else True
    rows.append({'id': case['id'], 'body_pin_matches': pin(path) == case['body_raw'],
        'body_canonical_bytes_match': encoded(body) == raw,
        'source_identity_construction_consistent': source_identity_ok,
        'quote_identity_construction_consistent': quote_identity_ok,
        'template_statement_exact_bytes_equal': equality,
        'manual_MATCH_or_DIFFERS_agrees_with_template_equality': expected_equality_ok,
        'body_bytes_observed': len(raw),
        'source_bytes_observed': [len(data) for data in source_map.values()]})
failures = [row for row in rows if not all(row[key] for key in ['body_pin_matches',
    'body_canonical_bytes_match', 'source_identity_construction_consistent',
    'quote_identity_construction_consistent',
    'manual_MATCH_or_DIFFERS_agrees_with_template_equality'])]
result = {'classification': 'OBSERVED_LITERAL_CONSTRUCTION_INTEGRITY_ONLY',
    'no_product_implementation_imported_or_executed': True,
    'no_new_claim_evaluator_or_Boolean_interpreter': True,
    'source': pin(OUT / 'audit-literals.py'),
    'expectations': pin(OUT / 'handwritten-expectations.json'),
    'cases': rows, 'failures': failures,
    'qualification': 'Checks byte construction, source/quote self-identities and exact source/Claim template equality for handwritten MATCH/DIFFERS pairs only. Does not independently establish final stage/refusal judgments, schema validity, guard/dependency correctness or component correctness. Source_statement template is not a parse of source_raw_hex overrides.'}
path = OUT / 'literal-audit-first-run.json'
with path.open('xb') as stream:
    stream.write(encoded(result))
print(json.dumps({'audit': pin(path), 'cases': len(rows),
                  'failures': [row['id'] for row in failures]}))
