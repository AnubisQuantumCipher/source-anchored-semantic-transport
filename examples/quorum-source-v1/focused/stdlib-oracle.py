"""Focused stdlib-only observable oracles. No product implementation import.

This is not a general replay verifier. Inputs are the previously frozen finite
well-shaped fixture family. Exact source/hash/base64/UTF8/JSON/byte-slice facts
are measured independently; outcome ordering follows the pinned draft contract.
"""
import base64
import binascii
import hashlib
import json
import platform
import sys
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def verify_pin(item):
    if pin(Path(item['path'])) != item:
        raise ValueError('frozen input pin mismatch: ' + item['path'])


def failure(stage, code):
    return {'status': 'error', 'stage': stage, 'error': code}


def base64_observation(text):
    result = {'text': text}
    try:
        raw = base64.b64decode(text.encode('ascii'), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        result.update(decoder_accepted=False, canonical=False,
                      refusal_type=type(error).__name__, refusal_reason=str(error))
        return result, None
    reencoded = base64.b64encode(raw).decode('ascii')
    result.update(decoder_accepted=True, decoded_hex=raw.hex(), bytes=len(raw),
        sha256=sha(raw), reencoded=reencoded, canonical=reencoded == text)
    return result, raw


class JsonRefusal(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def integer_token(text):
    if text.startswith('-'):
        raise JsonRefusal('INTEGER_TOKEN')
    if len(text) > 20:
        raise JsonRefusal('INTEGER_BOUND_RESOURCE')
    return int(text)


def floating_token(_text):
    raise JsonRefusal('INTEGER_TOKEN')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JsonRefusal('DUPLICATE_DECODED_KEY')
        result[key] = value
    return result


def scalar_depth(value):
    pending, maximum = [(value, 0)], 0
    for _ in range(16384):
        if not pending:
            return maximum
        item, depth = pending.pop()
        if type(item) is str:
            item.encode('utf-8')
        elif type(item) is dict:
            depth += 1
            maximum = max(maximum, depth)
            pending.extend((part, depth) for pair in item.items() for part in pair)
        elif type(item) is list:
            depth += 1
            maximum = max(maximum, depth)
            pending.extend((part, depth) for part in item)
        if maximum > 12:
            raise JsonRefusal('DEPTH_RESOURCE')
    raise JsonRefusal('WORK_RESOURCE')


def json_observation(raw):
    result = {'raw_hex': raw.hex()}
    try:
        if raw.startswith(b'\xef\xbb\xbf'):
            raise JsonRefusal('BOM')
        text = raw.decode('utf-8', errors='strict')
        value = json.loads(text, parse_int=integer_token,
            parse_float=floating_token, parse_constant=floating_token,
            object_pairs_hook=unique_object)
        depth = scalar_depth(value)
        canonical = encoded(value)
        if canonical != raw:
            raise JsonRefusal('NONCANONICAL_BYTES')
        result.update(accepted=True, maximum_container_depth=depth,
                      canonical_hex=canonical.hex())
    except UnicodeError as error:
        result.update(accepted=False, reason='SCALAR_UTF8',
                      exception_type=type(error).__name__)
    except JsonRefusal as error:
        result.update(accepted=False, reason=error.reason)
    except (ValueError, TypeError) as error:
        result.update(accepted=False, reason='JSON_SYNTAX',
                      exception_type=type(error).__name__, message=str(error))
    return result


def byte_integrity(raw, length, digest):
    return {'actual_bytes': len(raw), 'actual_sha256': sha(raw),
        'declared_bytes': length, 'declared_sha256': digest,
        'length_matches': len(raw) == length, 'sha256_matches': sha(raw) == digest}


def encode_observation(blob, raw):
    if blob['encoding'] == 'CANONICAL_JSON':
        return json_observation(raw)
    if blob['encoding'] == 'STRICT_UTF8':
        try:
            text = raw.decode('utf-8', errors='strict')
            text.encode('utf-8', errors='strict')
            return {'accepted': True, 'decoded_scalar_text': text}
        except UnicodeError as error:
            return {'accepted': False, 'reason': 'SCALAR_UTF8',
                    'exception_type': type(error).__name__}
    return {'accepted': True, 'reason': 'OPAQUE_NO_PARSE'}


def outcome(body, original, observations):
    source = body['sources'][0]
    key = source['key']
    raw = bytes.fromhex(original['immutable_bytes_hex'])
    if source['id'] == 'Q_RECORDS' or key['logical_source_id'] == 'Q_RECORDS':
        return failure('SOURCE_SET', 'SOURCE_RESERVED_Q_RECORDS')
    integrity = observations['source_integrity']
    if not integrity['length_matches']:
        return failure('SOURCE_INTEGRITY', 'SOURCE_BYTES_MISMATCH')
    if not integrity['sha256_matches']:
        return failure('SOURCE_INTEGRITY', 'SOURCE_HASH_MISMATCH')
    for blob in body['blobs']:
        check = observations['blob']
        if not check['base64']['canonical']:
            return failure('BLOB_INTEGRITY', 'BLOB_BASE64')
        if not check['integrity']['length_matches']:
            return failure('BLOB_INTEGRITY', 'BLOB_LENGTH_MISMATCH')
        if not check['integrity']['sha256_matches']:
            return failure('BLOB_INTEGRITY', 'BLOB_HASH_MISMATCH')
        if not check['encoding']['accepted']:
            if blob['encoding'] == 'STRICT_UTF8':
                return failure('BLOB_ENCODING', 'BLOB_UTF8')
            resource = check['encoding']['reason'].endswith('_RESOURCE')
            return failure('BLOB_ENCODING', 'BLOB_JSON_RESOURCE' if resource else 'BLOB_CANONICAL_JSON')
    selector = body['selectors'][0]
    check = observations['quote']
    if not check['base64']['canonical']:
        return failure('QUOTE_INTEGRITY', 'QUOTE_BASE64')
    if not check['integrity']['length_matches']:
        return failure('QUOTE_INTEGRITY', 'QUOTE_LENGTH_MISMATCH')
    if not check['integrity']['sha256_matches']:
        return failure('QUOTE_INTEGRITY', 'QUOTE_HASH_MISMATCH')
    begin, end = selector['begin'], selector['end']
    if not 0 <= begin <= end <= len(raw) or (begin == end and len(raw) != 0):
        return failure('SELECTOR_RANGE', 'SELECTOR_RANGE')
    if not check['slice_equals_quote']:
        status = 'DIFFERS'
    else:
        status = 'EMPTY_SOURCE_MATCH_NONPROBATIVE' if not raw else 'MATCH'
    return {'status': 'ok', 'stage': 'SOURCE_BLOB_SELECTOR_ONLY', 'selector_statuses': [status]}


original = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
amendment = json.loads((OUT / 'handwritten-amendments.json').read_bytes())
freeze = json.loads((OUT / 'pre-oracle-freeze.json').read_bytes())
extra_freeze = json.loads((OUT / 'pre-oracle-amendments-freeze.json').read_bytes())
verify_pin(freeze['expectations'])
verify_pin(extra_freeze['amendments'])
for item in freeze['raw_candidates'] + extra_freeze['candidates']:
    verify_pin(item)
old_pin = original['source_pins'][0]
old_preserved = pin(OUT / 'original-contract-draft01.json')
if (old_pin['bytes'], old_pin['sha256']) != (old_preserved['bytes'], old_preserved['sha256']):
    raise ValueError('original amended contract bytes not preserved')
rows = []
for row in original['cases'] + amendment['cases']:
    body = json.loads(Path(row['body_raw']['path']).read_bytes())
    supplied = row['originals_exact_tuple_recipe'][0]
    actual = bytes.fromhex(supplied['immutable_bytes_hex'])
    key = body['sources'][0]['key']
    observations = {'source_integrity': byte_integrity(actual, key['bytes'], key['sha256'])}
    if body['blobs']:
        blob = body['blobs'][0]
        b64, decoded = base64_observation(blob['base64'])
        observations['blob'] = {'base64': b64}
        if decoded is not None:
            observations['blob']['integrity'] = byte_integrity(decoded, blob['bytes'], blob['sha256'])
            observations['blob']['encoding'] = encode_observation(blob, decoded)
    selector = body['selectors'][0]
    b64, quote = base64_observation(selector['quote_base64'])
    observations['quote'] = {'base64': b64}
    if quote is not None:
        observations['quote'].update(integrity=byte_integrity(quote, selector['quote_bytes'], selector['quote_sha256']),
            slice_hex=actual[selector['begin']:selector['end']].hex(),
            slice_equals_quote=actual[selector['begin']:selector['end']] == quote)
    observed = outcome(body, supplied, observations)
    rows.append({'id': row['id'], 'raw': row['body_raw'], 'handwritten_expected': row['expected'],
        'observed_ordered_contract_outcome': observed, 'independent_stdlib_observations': observations,
        'matches_handwritten': observed == row['expected']})
modules = [Path(module.__file__) for module in [base64, json, hashlib]]
report = {'classification': 'TESTED_STDLIB_ONLY_FOCUSED_LITERALS',
    'implementation_inspected_or_executed': False,
    'original_freeze': pin(OUT / 'pre-oracle-freeze.json'),
    'amendments_freeze': pin(OUT / 'pre-oracle-amendments-freeze.json'),
    'original_contract_retained': old_preserved, 'amended_contract': amendment['amended_contract'],
    'python_version': platform.python_version(), 'python_executable': pin(Path(sys.executable)),
    'stdlib_sources': [pin(path) for path in modules], 'oracle_source': pin(OUT / 'stdlib-oracle.py'),
    'case_count_observed': len(rows), 'cases': rows,
    'discrepancies': [row for row in rows if not row['matches_handwritten']],
    'qualification': 'Finite fixed well-shaped controls only. Hash/base64/scalar decoding/canonical JSON and exact slice facts are observed through stdlib; stage mapping follows the pinned draft contract. No product run, formal proof, general input correctness, authentication, semantic or replay acceptance claim.'}
(OUT / 'stdlib-oracle-first-run.json').write_bytes(encoded(report))
print(json.dumps({'cases': len(rows), 'discrepancies': [row['id'] for row in report['discrepancies']],
                  'report': pin(OUT / 'stdlib-oracle-first-run.json')}))
