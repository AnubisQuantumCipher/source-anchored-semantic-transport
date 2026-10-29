"""Bounded internal source/blob/selector bytes; no full replay or authority."""

import base64
import binascii
import hashlib
import re

import transport_quorum_input as metadata
from transport_schema import canonical

__all__ = ('check_source_membership',)

MAX_BYTES = 65536
MAX_SOURCES = 15
MAX_BINARY = 4096
MAX_OUTPUT = 32768
KEY_FIELDS = ('logical_source_id', 'sha256', 'bytes')
ID_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,31}$')
HEX = '0123456789abcdef'
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
JSON_RESOURCE = frozenset(('INPUT_INTEGER_BOUND', 'INPUT_DEPTH',
                          'INPUT_WORK_BOUND', 'INPUT_BYTE_BOUND'))


def _fail(code: str, stage: str) -> None:
    raise metadata.InputError(code, stage)


def _identifier(value: object) -> bool:
    # Preserve the frozen schema's pattern-search final-LF behavior.
    return (type(value) is str and len(value) <= 32 and value.isascii()
            and ID_PATTERN.search(value) is not None)


def _key(value: object) -> tuple[str, str, int]:
    stage = 'SOURCE_ARGUMENTS'
    if type(value) is not dict or len(value) != 3:
        _fail('SOURCE_KEY_SHAPE', stage)
    for name in value:
        if type(name) is not str or name not in KEY_FIELDS:
            _fail('SOURCE_KEY_SHAPE', stage)
    logical, digest, size = (value[name] for name in KEY_FIELDS)
    if not _identifier(logical):
        _fail('SOURCE_KEY_SHAPE', stage)
    if type(digest) is not str or len(digest) != 64:
        _fail('SOURCE_KEY_SHAPE', stage)
    if any(character not in HEX for character in digest):
        _fail('SOURCE_KEY_SHAPE', stage)
    if type(size) is not int or not 0 <= size <= MAX_BYTES:
        _fail('SOURCE_KEY_SHAPE', stage)
    return logical, digest, size


def _arguments(body: dict, originals: object) -> list[tuple]:
    stage = 'SOURCE_ARGUMENTS'
    if type(originals) is not tuple:
        _fail('SOURCE_INPUT_TYPE', stage)
    if max(len(body['sources']), len(originals)) > MAX_SOURCES:
        _fail('SOURCE_COUNT_BOUND', stage)
    result = []
    for item in originals:
        if type(item) is not tuple or len(item) != 3:
            _fail('SOURCE_INPUT_TYPE', stage)
        alias, supplied_key, data = item
        if type(data) is not bytes:
            _fail('SOURCE_INPUT_TYPE', stage)
        if not _identifier(alias):
            _fail('SOURCE_KEY_SHAPE', stage)
        result.append((alias, _key(supplied_key), data))
    return result


def _source_bounds(raw: bytes, originals: list[tuple]) -> None:
    total = len(raw)  # Exactly one Q_RECORDS source; no metadata double charge.
    for _, _, data in originals:
        total += len(data)
        if len(data) > MAX_BYTES or total > MAX_BYTES:
            _fail('SOURCE_BYTE_BOUND', 'SOURCE_BOUNDS')


def _unique_ids(names: list[str], code: str, stage: str) -> None:
    seen = set()
    for name in names:
        if name in seen:
            _fail(code, stage)
        seen.add(name)


def _body_key(key: dict) -> tuple[str, str, int]:
    # Only private fully shape-checked Body keys reach this helper.
    return key['logical_source_id'], key['sha256'], key['bytes']


def _source_set(records: list[dict], originals: list[tuple]) -> list[tuple]:
    stage = 'SOURCE_SET'
    _unique_ids([r['id'] for r in records], 'SOURCE_DECLARATION_DUPLICATE', stage)
    _unique_ids([r[0] for r in originals], 'SOURCE_DUPLICATE_ID', stage)
    for record in records:
        if record['id'] == 'Q_RECORDS' or record['key']['logical_source_id'] == 'Q_RECORDS':
            _fail('SOURCE_RESERVED_Q_RECORDS', stage)
    for alias, key, _ in originals:
        if alias == 'Q_RECORDS' or key[0] == 'Q_RECORDS':
            _fail('SOURCE_RESERVED_Q_RECORDS', stage)
    supplied = {alias: (key, data) for alias, key, data in originals}
    if set(supplied) != {record['id'] for record in records}:
        _fail('SOURCE_SET_MISMATCH', stage)
    ordered = []
    for record in sorted(records, key=lambda r: r['id']):
        key, data = supplied[record['id']]
        if key != _body_key(record['key']):
            _fail('SOURCE_KEY_MISMATCH', stage)
        ordered.append((record['id'], key, data))
    same_key = {}
    for _, key, data in ordered:
        if key in same_key and data != same_key[key]:
            _fail('SOURCE_ALIAS_BYTES_CONFLICT', stage)
        same_key[key] = data  # Equality lookup only; every copy remains charged.
    return ordered


def _source_integrity(ordered: list[tuple]) -> None:
    for _, key, data in ordered:
        if len(data) != key[2]:
            _fail('SOURCE_BYTES_MISMATCH', 'SOURCE_INTEGRITY')
        if hashlib.sha256(data).hexdigest() != key[1]:
            _fail('SOURCE_HASH_MISMATCH', 'SOURCE_INTEGRITY')


def _decoded_size(text: str, prefix: str, stage: str) -> int:
    size = len(text)
    if size % 4:
        _fail(prefix + '_BASE64', stage)
    if size == 0:
        return 0
    padding = 2 if text.endswith('==') else int(text.endswith('='))
    for index, character in enumerate(text):
        if index < size - padding:
            if character not in ALPHABET:
                _fail(prefix + '_BASE64', stage)
        elif character != '=':
            _fail(prefix + '_BASE64', stage)
    if padding == 2 and ALPHABET.index(text[-3]) & 15:
        _fail(prefix + '_BASE64', stage)
    if padding == 1 and ALPHABET.index(text[-2]) & 3:
        _fail(prefix + '_BASE64', stage)
    return (size // 4) * 3 - padding


def _binary(text: str, size: int, digest: str, prefix: str,
            stage: str, used: int) -> tuple[bytes, int]:
    decoded = _decoded_size(text, prefix, stage)
    if used + decoded > MAX_BYTES:
        _fail('DECODED_BYTE_BOUND', stage)
    if decoded > MAX_BINARY or decoded != size:
        _fail(prefix + '_LENGTH_MISMATCH', stage)
    # Text syntax, pad bits and exact allocation size have already been checked.
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise metadata.InputError(prefix + '_BASE64', stage) from error
    if len(data) != decoded or base64.b64encode(data).decode('ascii') != text:
        _fail(prefix + '_BASE64', stage)
    if hashlib.sha256(data).hexdigest() != digest:
        _fail(prefix + '_HASH_MISMATCH', stage)
    return data, used + decoded


def _blob_encoding(record: dict, data: bytes) -> None:
    if record['encoding'] == 'STRICT_UTF8':
        try:
            data.decode('utf-8')
        except UnicodeError as error:
            raise metadata.InputError('BLOB_UTF8', 'BLOB_ENCODING') from error
    elif record['encoding'] == 'CANONICAL_JSON':
        result = metadata.check_canonical_value(data)
        if result['status'] == 'error':
            code = 'BLOB_JSON_RESOURCE' if result['error'] in JSON_RESOURCE else 'BLOB_CANONICAL_JSON'
            _fail(code, 'BLOB_ENCODING')


def _blobs(records: list[dict]) -> tuple[list[dict], int]:
    _unique_ids([r['id'] for r in records], 'BLOB_DUPLICATE_ID', 'BLOB_INTEGRITY')
    index, used = [], 0
    for record in sorted(records, key=lambda r: r['id']):
        data, used = _binary(record['base64'], record['bytes'], record['sha256'],
                             'BLOB', 'BLOB_INTEGRITY', used)
        _blob_encoding(record, data)
        index.append({field: record[field] for field in
                      ('id', 'kind', 'encoding', 'bytes', 'sha256')})
    return index, used


def _quotes(records: list[dict], used: int) -> list[tuple]:
    _unique_ids([r['id'] for r in records], 'SELECTOR_DUPLICATE_ID', 'QUOTE_INTEGRITY')
    result = []
    for record in sorted(records, key=lambda r: r['id']):
        data, used = _binary(record['quote_base64'], record['quote_bytes'],
                             record['quote_sha256'], 'QUOTE', 'QUOTE_INTEGRITY', used)
        result.append((record, data))
    return result


def _selector_sources(quotes: list[tuple], sources: list[tuple]) -> list[tuple]:
    result = []
    for selector, quote in quotes:
        target, selected = _body_key(selector['source']), None
        for _, key, data in sources:
            if key == target:
                selected = data
                break  # Every matching alias was checked byte-equal beforehand.
        if selected is None:
            _fail('SELECTOR_SOURCE_MISSING', 'SELECTOR_REFERENCE')
        result.append((selector, quote, selected))
    return result


def _selector_ranges(resolved: list[tuple]) -> None:
    for selector, _, source in resolved:
        begin, end = selector['begin'], selector['end']
        if not 0 <= begin <= end <= len(source):
            _fail('SELECTOR_RANGE', 'SELECTOR_RANGE')
        if begin == end and source:
            _fail('SELECTOR_RANGE', 'SELECTOR_RANGE')


def _memberships(resolved: list[tuple]) -> list[dict]:
    result = []
    for selector, quote, source in resolved:
        begin, end = selector['begin'], selector['end']
        # Never allocate a possible65536-byte source slice for a<=4096-byte quote.
        if end - begin != len(quote) or source[begin:end] != quote:
            status = 'DIFFERS'
        else:
            status = 'MATCH' if source else 'EMPTY_SOURCE_MATCH_NONPROBATIVE'
        result.append(dict(id=selector['id'], status=status))
    return result


def _result(raw: bytes, sources: list[tuple], blobs: list[dict],
            selectors: list[dict]) -> dict:
    index = []
    for alias, key, _ in sources:
        index.append(dict(id=alias, key=dict(logical_source_id=key[0],
                                            sha256=key[1], bytes=key[2])))
    result = dict(status='ok', stage='SOURCE_BLOB_SELECTOR_ONLY',
                  body_pin=dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
                  source_index=index, blob_index=blobs, selectors=selectors,
                  source_authentication='UNVERIFIED', current_authority='NONE',
                  freshness='UNKNOWN')
    if len(canonical(result)) + 1 > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    return result


def _validated_sources(body_raw: object, originals: object) -> tuple:
    """Private owned bundle only after the entire unchanged public source gate."""
    body, schema = metadata._validated_body_with_schema(body_raw)
    supplied = _arguments(body, originals)
    _source_bounds(body_raw, supplied)
    sources = _source_set(body['sources'], supplied)
    _source_integrity(sources)
    blobs, used = _blobs(body['blobs'])
    quotes = _quotes(body['selectors'], used)
    resolved = _selector_sources(quotes, sources)
    _selector_ranges(resolved)
    result = _result(body_raw, sources, blobs, _memberships(resolved))
    return body, sources, resolved, result, schema


def check_source_membership(body_raw: object, originals: object) -> dict:
    """Pure bounded bytes stage; caller must not concurrently mutate key dicts."""
    try:
        _, _, _, result, _ = _validated_sources(body_raw, originals)
        return result
    except metadata.InputError as error:
        return metadata._error(error)
