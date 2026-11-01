"""Focused handwritten source/blob/selector literals, prior to product inspection.

TEST-ONLY: at most64 cases; at most32768 bytes per candidate. No product import.
Hash/base64 construction binds exact literal bytes; expected outcomes are manual.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')
CONTRACT = Path('/dev/shm/semantic-transport-source-membership-20261029/contract.json')
MINIMAL = Path('/dev/shm/semantic-transport-wire-input-20261029/minimal-body.json')
BASE = json.loads(MINIMAL.read_bytes())
CASES = []


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def refusal(stage, code):
    return {'status': 'error', 'stage': stage, 'error': code}


def success(selector='MATCH'):
    return {'status': 'ok', 'stage': 'SOURCE_BLOB_SELECTOR_ONLY',
            'selector_statuses': [selector]}


def case(name, expected, rationale, **fields):
    if len(CASES) >= 64:
        raise ValueError('case budget exceeded')
    row = {'id': name, 'source_declared_hex': '616263',
        'source_actual_hex': '616263', 'quote_hex': '616263',
        'begin': 0, 'end': 3, 'blob_hex': None,
        'expected': expected, 'manual_rationale': rationale}
    row.update(fields)
    CASES.append(row)


case('S00_BASE', success(), 'Exact original and exact full-source quote.')
case('S01_CHANGED_BYTE', refusal('SOURCE_INTEGRITY', 'SOURCE_HASH_MISMATCH'),
     'Same actual length with changed byte must fail source digest.', source_actual_hex='616264')
case('S02_TRUNCATED', refusal('SOURCE_INTEGRITY', 'SOURCE_BYTES_MISMATCH'),
     'Actual length differs before digest check.', source_actual_hex='6162')
case('S03_APPENDED', refusal('SOURCE_INTEGRITY', 'SOURCE_BYTES_MISMATCH'),
     'Extra actual byte must fail declared length.', source_actual_hex='61626364')
case('S04_DECLARED_LENGTH', refusal('SOURCE_INTEGRITY', 'SOURCE_BYTES_MISMATCH'),
     'Wrong self-declared source length with original unchanged.', source_length_override=4)
case('S05_DECLARED_HASH', refusal('SOURCE_INTEGRITY', 'SOURCE_HASH_MISMATCH'),
     'Wrong self-declared digest with original unchanged.', source_hash_override='0' * 64)
case('S06_OPAQUE_INVALID_UTF8', success(),
     'Ordinary originals remain opaque bytes; invalid UTF8 is allowed here.',
     source_declared_hex='ff', source_actual_hex='ff', quote_hex='ff', end=1)
case('S07_ID_FINAL_LF', success(),
     'Pinned Id pattern-search admits final LF; no stronger fullmatch rule is invented.',
     source_alias='SOURCE\n', logical_source_id='ORIGINAL\n')

case('B00_EMPTY', success(), 'Empty canonical base64 and exact empty-byte identity.', blob_hex='')
case('B01_PAD_TWO', success(), 'Canonical two-padding encoding of one zero byte.', blob_hex='00')
case('B02_NONZERO_PAD_BITS_TWO', refusal('BLOB_INTEGRITY', 'BLOB_BASE64'),
     'AB== decodes to00 but reencoding is AA==; zero unused pad bits required.', blob_hex='00', blob_base64='AB==')
case('B03_NONZERO_PAD_BITS_ONE', refusal('BLOB_INTEGRITY', 'BLOB_BASE64'),
     'AAB= decodes to0000 but reencoding is AAA=; zero unused pad bits required.', blob_hex='0000', blob_base64='AAB=')
case('B04_FINAL_LF', refusal('BLOB_INTEGRITY', 'BLOB_BASE64'),
     'AAAA\\n passes pinned pattern search but canonical base64 rejects whitespace.', blob_hex='000000', blob_base64='AAAA\n')
case('B05_LENGTH', refusal('BLOB_INTEGRITY', 'BLOB_LENGTH_MISMATCH'),
     'Canonical decoded bytes must equal declared length.', blob_hex='00', blob_length_override=0)
case('B06_HASH', refusal('BLOB_INTEGRITY', 'BLOB_HASH_MISMATCH'),
     'Canonical decoded bytes must equal declared digest.', blob_hex='00', blob_hash_override='0' * 64)

for name, raw_hex, accepted, rationale in [
    ('U00_VALID_SCALAR', 'f09f9880', True, 'Valid supplementary scalar UTF8.'),
    ('U01_INVALID_BYTE', 'ff', False, 'Invalid UTF8 leading byte.'),
    ('U02_ENCODED_SURROGATE', 'eda080', False, 'UTF8 encoding of surrogate U+D800 is not scalar UTF8.'),
    ('U03_OVERLONG_NUL', 'c080', False, 'Overlong UTF8 form must be rejected.'),
    ('U04_TRUNCATED', 'e282', False, 'Truncated multibyte UTF8 sequence.'),
    ('U05_LITERAL_NUL', '00', True, 'NUL is a scalar; STRICT_UTF8 alone does not ban it.'),
    ('U06_REPLACEMENT_SCALAR', 'efbfbd', True, 'Literal replacement character is valid; no lossy repair or normalization.')]:
    expected = success() if accepted else refusal('BLOB_ENCODING', 'BLOB_UTF8')
    case(name, expected, rationale, blob_hex=raw_hex, blob_encoding='STRICT_UTF8')

for name, raw_hex, accepted, rationale in [
    ('J00_CANONICAL_OBJECT', '7b2261223a307d', True, 'Exact canonical object.'),
    ('J01_NEGATIVE_ZERO', '7b2261223a2d307d', False, 'Canonical JSON rejects lexical -0 before any numeric normalization.'),
    ('J02_DUPLICATE_KEYS', '7b2261223a302c2261223a317d', False, 'Duplicate decoded object key cannot silently overwrite earlier value.'),
    ('J03_FINAL_LF', '7b2261223a307d0a', False, 'Canonical JSON has no final LF.'),
    ('J04_SPACE', '7b202261223a307d', False, 'Insignificant whitespace is noncanonical.'),
    ('J05_ESCAPED_SURROGATE', '7b2273223a225c7564383030227d', False, 'Escaped surrogate is not a Unicode scalar.'),
    ('J06_LITERAL_UNICODE', '7b2273223a22c3a9227d', True, 'Canonical scalar UTF8 literal is preserved.'),
    ('J07_UNSORTED_KEYS', '7b2262223a302c2261223a307d', False, 'Object keys must have canonical scalar ordering.'),
    ('J08_FLOAT_ZERO', '7b2261223a302e307d', False, 'Integral floating token remains forbidden.'),
    ('J09_SCALAR_ROOT', '6e756c6c', True, 'Contract admits any canonical JSON value root, including null.'),
    ('J10_BOM', 'efbbbf7b2261223a307d', False, 'BOM is forbidden by W01.'),
    ('J11_UTF8_INVALID', '7b2273223a22ff227d', False, 'No replacement decoding for invalid UTF8 in JSON metadata.'),
    ('J12_DUPLICATE_DECODED_KEY', '7b2261223a302c225c7530303631223a317d', False, 'Literal a and escaped a are the same decoded key; duplicate rejection precedes canonical equivalence.')]:
    expected = success() if accepted else refusal('BLOB_ENCODING', 'BLOB_CANONICAL_JSON')
    case(name, expected, rationale, blob_hex=raw_hex, blob_encoding='CANONICAL_JSON')

case('Q00_DIFFERENT_BOUND_QUOTE', success('DIFFERS'),
     'Quote abd has correct own length/hash, differs from source abc; DIFFERS is an observation.', quote_hex='616264')
case('Q01_QUOTE_HASH', refusal('QUOTE_INTEGRITY', 'QUOTE_HASH_MISMATCH'),
     'Quote content differs from its own asserted digest.', quote_hex='616264', quote_hash_override=sha(b'abc'))
case('Q02_QUOTE_LENGTH', refusal('QUOTE_INTEGRITY', 'QUOTE_LENGTH_MISMATCH'),
     'Quote decoded length differs from quote_bytes.', quote_length_override=2)
case('Q03_SUBSLICE', success(), 'Half-open byte slice [0,2) equals ab.', quote_hex='6162', end=2)
case('Q04_NONEMPTY_SOURCE_EMPTY_00', refusal('SELECTOR_RANGE', 'SELECTOR_RANGE'),
     'Empty slice[0,0) on nonempty original is prohibited.', quote_hex='', begin=0, end=0)
case('Q05_NONEMPTY_SOURCE_EMPTY_11', refusal('SELECTOR_RANGE', 'SELECTOR_RANGE'),
     'Empty interior slice also prohibited.', quote_hex='', begin=1, end=1)
case('Q06_EMPTY_SOURCE_00', success('EMPTY_SOURCE_MATCH_NONPROBATIVE'),
     'Only empty original admits[0,0), explicitly nonprobative.',
     source_declared_hex='', source_actual_hex='', quote_hex='', begin=0, end=0)
case('Q07_REVERSED', refusal('SELECTOR_RANGE', 'SELECTOR_RANGE'),
     'begin must not exceed end.', begin=2, end=1)
case('Q08_PAST_SOURCE', refusal('SELECTOR_RANGE', 'SELECTOR_RANGE'),
     'end must not exceed actual verified source length.', end=4)
case('Q09_NONZERO_PAD_BITS', refusal('QUOTE_INTEGRITY', 'QUOTE_BASE64'),
     'Quote base64 has zero-pad-bit obligation independently of source membership.', quote_hex='00', quote_base64='AB==')
case('Q10_HASH_BEFORE_RANGE', refusal('QUOTE_INTEGRITY', 'QUOTE_HASH_MISMATCH'),
     'All quote integrity checks precede range refusals.', begin=2, end=1,
     quote_hash_override='0' * 64)

for row in CASES:
    body = copy.deepcopy(BASE)
    original_declared = bytes.fromhex(row['source_declared_hex'])
    original_actual = bytes.fromhex(row['source_actual_hex'])
    source_alias = row.get('source_alias', 'SOURCE')
    key = {'logical_source_id': row.get('logical_source_id', 'ORIGINAL'),
        'sha256': row.get('source_hash_override', sha(original_declared)),
        'bytes': row.get('source_length_override', len(original_declared))}
    body['sources'] = [{'id': source_alias, 'key': key, 'media_type': 'text/plain',
        'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'issuer_claim_id': None,
        'authentication': 'UNVERIFIED'}]
    quote = bytes.fromhex(row['quote_hex'])
    body['selectors'] = [{'id': 'SELECTOR', 'kind': 'BYTE_SPAN_V1', 'source': key,
        'begin': row['begin'], 'end': row['end'],
        'quote_base64': row.get('quote_base64', base64.b64encode(quote).decode('ascii')),
        'quote_bytes': row.get('quote_length_override', len(quote)),
        'quote_sha256': row.get('quote_hash_override', sha(quote))}]
    if row['blob_hex'] is not None:
        blob = bytes.fromhex(row['blob_hex'])
        body['blobs'] = [{'id': 'BLOB', 'kind': 'PROVENANCE_EVIDENCE',
            'encoding': row.get('blob_encoding', 'OPAQUE_BYTES'),
            'base64': row.get('blob_base64', base64.b64encode(blob).decode('ascii')),
            'bytes': row.get('blob_length_override', len(blob)),
            'sha256': row.get('blob_hash_override', sha(blob))}]
    raw = encoded(body)
    if len(raw) > 32768:
        raise ValueError('candidate byte budget exceeded')
    path = OUT / 'raw' / (row['id'] + '.body.json')
    path.write_bytes(raw)
    row['body_raw'] = pin(path)
    row['originals_exact_tuple_recipe'] = [{'alias': source_alias, 'key': key,
                                         'immutable_bytes_hex': original_actual.hex()}]
    row['actual_blob_record'] = body['blobs'][0] if body['blobs'] else None
    row['actual_selector_record'] = body['selectors'][0]

expectations = {'schema': 'quorum/focused-source-control-literals/1',
    'scope': 'HANDWRITTEN_PRE_IMPLEMENTATION_INSPECTION_TEST_CONTROLS',
    'product_implementation_inspected': False, 'oracle_execution': 'NOT_YET_RUN',
    'tuple_recipe': 'Construct exact builtin tuple of exact3tuples(alias, dict(key), bytes.fromhex(immutable_bytes_hex)); no path provider or body-source authority inference.',
    'qualification': 'Success here is only source/blob/selector byte observation, never replay or semantic acceptance. No claim/manifest/graph closure expected from this minimal Body. Id finalLF behavior preserved.',
    'source_pins': [pin(CONTRACT), pin(MINIMAL), pin(OUT / 'prepare.py')],
    'cases': CASES}
(OUT / 'handwritten-expectations.json').write_bytes(encoded(expectations))
freeze = {'phase': 'PRE_ORACLE_FROZEN',
    'expectations': pin(OUT / 'handwritten-expectations.json'),
    'sources': expectations['source_pins'], 'raw_candidates': [row['body_raw'] for row in CASES]}
(OUT / 'pre-oracle-freeze.json').write_bytes(encoded(freeze))
print(json.dumps({'cases': len(CASES), 'freeze': pin(OUT / 'pre-oracle-freeze.json')}))
