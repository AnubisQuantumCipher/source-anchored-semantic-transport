"""Readable-language capsules, using the existing native source comparator.

The formula is a proposed reading. Source equality is decided by the native
core; this Python bridge grants no semantic, authenticity, or release verdict.
"""

import hashlib
import json
import tempfile
from pathlib import Path

from transport_formula import selected_definitions
from transport_lexicon import MAX_PLAN, Plan, bind_source, parse_plan
from transport_source_map import check_document
from transport_wire import MAX_WIRE, TransportError, encode, run_core, unpack, write_new

SCHEMA = 'transport/readable/1'
FIELDS = frozenset(('schema', 'plan', 'operator_definitions', 'source_sha256', 'frame_hex'))


def compare_source(frame: bytes, expected: bytes) -> None:
    if not isinstance(frame, bytes) or not isinstance(expected, bytes):
        raise TransportError('source comparison requires immutable byte snapshots')
    with tempfile.TemporaryDirectory(prefix='transport-readable-') as scratch:
        wire = Path(scratch) / 'frame'
        source = Path(scratch) / 'canonical-source'
        if write_new(wire, frame) or write_new(source, expected):
            raise TransportError('private readable comparison staging cleanup failed')
        run_core('check', wire, source)


def codebook_frame(plan: Plan, source: bytes) -> bytes:
    bind_source(plan, source)
    return encode(source, [phrase.encode('utf-8') for _, phrase in plan.symbols])


def seal(source: bytes, plan_data: bytes, document: bytes | None = None) -> bytes:
    plan = parse_plan(plan_data)
    frame = codebook_frame(plan, source)
    if document is not None:
        check_document(plan.origin, source, document)
    compare_source(frame, source)
    capsule = {'schema': SCHEMA, 'plan': plan_data.decode('utf-8'),
               'operator_definitions': selected_definitions(dict(plan.senses)),
               'source_sha256': hashlib.sha256(source).hexdigest(),
               'frame_hex': frame.hex()}
    result = (json.dumps(capsule, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(result) > MAX_WIRE:
        raise TransportError('readable capsule byte budget exceeded')
    return result


def bounded_json(data: bytes) -> None:
    if not data or len(data) > MAX_WIRE:
        raise TransportError('empty or oversized readable capsule')
    quoted, escaped, depth = False, False, 0
    for character in data:
        if quoted:
            if escaped:
                escaped = False
            elif character == 92:
                escaped = True
            elif character == 34:
                quoted = False
        elif character == 34:
            quoted = True
        elif character in (91, 123):
            depth += 1
            if depth > 2:
                raise TransportError('capsule nesting budget exceeded')
        elif character in (93, 125):
            depth -= 1
            if depth < 0:
                raise TransportError('malformed capsule nesting')
    if quoted or depth != 0:
        raise TransportError('incomplete capsule')


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    if len(pairs) > 8 or len({key for key, _ in pairs}) != len(pairs):
        raise TransportError('duplicate or excessive readable capsule fields')
    return dict(pairs)


def capsule_fields(data: bytes) -> dict:
    bounded_json(data)
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) != FIELDS or value['schema'] != SCHEMA:
            raise TransportError('unknown readable capsule version or fields')
        for key in ('plan', 'source_sha256', 'frame_hex'):
            if not isinstance(value[key], str):
                raise TransportError('capsule field must be text: ' + key)
            value[key].encode('utf-8')
        if len(value['plan'].encode('utf-8')) > MAX_PLAN:
            raise TransportError('capsule codebook budget exceeded')
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise TransportError('malformed readable capsule: ' + str(error)[:160]) from error


def open_capsule(data: bytes, canonical: bytes | None = None,
                 document: bytes | None = None) -> tuple[Plan, bytes]:
    item = capsule_fields(data)
    plan = parse_plan(item['plan'].encode('utf-8'))
    if item['operator_definitions'] != selected_definitions(dict(plan.senses)):
        raise TransportError('operator definition changed or missing')
    try:
        frame = bytes.fromhex(item['frame_hex'])
    except ValueError as error:
        raise TransportError('invalid source frame spelling') from error
    if frame.hex() != item['frame_hex'] or len(frame) > MAX_WIRE:
        raise TransportError('noncanonical or oversized source frame')
    source = unpack(frame)
    if hashlib.sha256(source).hexdigest() != item['source_sha256']:
        raise TransportError('retained source identity mismatch; figures may have changed')
    if codebook_frame(plan, source) != frame:
        raise TransportError('source frame and readable lexicon do not correspond')
    if canonical is not None:
        compare_source(frame, canonical)
    if document is not None:
        check_document(plan.origin, source, document)
        compare_source(frame, document[plan.origin.begin:plan.origin.end])
    return plan, source
