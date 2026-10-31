#!/usr/bin/env python3
"""Conditional exact comparison to an explicitly pinned held reference, not OCR proof."""
import argparse
import codecs
import hashlib
import json
from pathlib import Path
import resource
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_document_io import (DocumentError, FRAME_SOURCE, MAX_META, canonical,
    fields, identity, integer, loads, need, open_regular, read_file, sha)
import transport_document_reading as reading_module

CLAIM = 'EXACT_ORDERED_READING_TEXT_TO_HELD_REFERENCE_ONLY'
SCHEMA = 'transport/document-reference/1'
MAX_OUTPUT = 1_048_576
MAX_DETAILS = 64


def checked_claim(requested):
    need(requested in (CLAIM, 'EXACT_REFERENCE_TEXT'),
         'UNSUPPORTED_CLAIM: OCR accuracy and semantic completeness are not established by reference equality')


def no_links(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'UNSAFE_PATH: parent traversal')
    for item in (path, *path.parents):
        need(not item.is_symlink(), 'UNSAFE_PATH: symlink refused')
    return path


def outcome(status):
    return {'status': status, 'claim': CLAIM, 'reference_authentication': 'UNAUTHENTICATED',
            'reference_fidelity': 'UNPROVEN', 'OCR_accuracy': 'UNPROVEN',
            'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
            'execution_authority': 'NONE', 'mismatch_units': 0, 'mismatches': []}


def reference_inputs(manifest_path, text_path, expected_sha):
    supplied = (manifest_path is not None, text_path is not None, expected_sha is not None)
    if not any(supplied):
        return None
    need(all(supplied), 'PARTIAL_REFERENCE: all three held reference inputs are required')
    sha(expected_sha)
    manifest_path, text_path = no_links(manifest_path), no_links(text_path)
    need(manifest_path.exists() and text_path.exists(), 'REFERENCE_FILE_MISSING')
    raw = read_file(manifest_path, MAX_META)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'REFERENCE_PIN_MISMATCH')
    return loads(raw), text_path


def reference_checked(reference, record):
    fields(reference, ('schema', 'source_sha256', 'format', 'text_sha256', 'text_bytes', 'segments'))
    need(reference['schema'] == SCHEMA, 'REFERENCE_SCHEMA: unsupported version')
    sha(reference['source_sha256']); sha(reference['text_sha256'])
    need(reference['source_sha256'] == record['source_sha256'] and reference['format'] == record['format'],
         'REFERENCE_SOURCE_MISMATCH')
    integer(reference['text_bytes'], 0, reading_module.MAX_READING)
    units = reference['segments']
    need(type(units) is list and len(units) <= reading_module.MAX_SEGMENTS and
         len(units) == len(record['segments']), 'REFERENCE_UNIT_COUNT')
    previous, names = 0, set()
    for unit, actual in zip(units, record['segments']):
        fields(unit, ('id', 'kind', 'source_locator', 'start', 'end'))
        need(type(unit['id']) is str and 0 < len(unit['id'].encode('utf8')) <= 64 and
             unit['id'] not in names, 'REFERENCE_UNIT_ID')
        names.add(unit['id'])
        integer(unit['start'], 0, reference['text_bytes'])
        integer(unit['end'], unit['start'], reference['text_bytes'])
        need(unit['start'] == previous, 'REFERENCE_PARTITION_GAP_OR_OVERLAP')
        previous = unit['end']
        need(unit['id'] == actual['id'] and unit['kind'] == actual['kind'] and
             canonical(unit['source_locator']) == canonical(actual['source_locator']), 'REFERENCE_UNIT_ALIGNMENT')
    need(previous == reference['text_bytes'], 'REFERENCE_PARTITION_INCOMPLETE')
    return reference


def block_difference(left, right):
    common = min(len(left), len(right))
    for index in range(common):
        if left[index] != right[index]:
            return index
    return common if len(left) != len(right) else None


def compare_unit(left, right, actual, expected, left_hash, right_hash):
    remaining = [actual['end'] - actual['start'], expected['end'] - expected['start']]
    decoders = [codecs.getincrementaldecoder('utf8')('strict') for _ in range(2)]
    consumed, first = [0, 0], None
    try:
        for _ in range(reading_module.MAX_READING_FRAMES + 1):
            if remaining == [0, 0]:
                break
            blocks = [left.read(min(remaining[0], FRAME_SOURCE)), right.read(min(remaining[1], FRAME_SOURCE))]
            difference = block_difference(*blocks)
            if first is None and difference is not None:
                first = min(consumed) + difference
            for index, block in enumerate(blocks):
                need(bool(block) or remaining[index] == 0, 'REFERENCE_TEXT_TRUNCATED')
                decoders[index].decode(block, final=False)
                remaining[index] -= len(block)
                consumed[index] += len(block)
            left_hash.update(blocks[0]); right_hash.update(blocks[1])
        need(remaining == [0, 0], 'REFERENCE_UNIT_TRAVERSAL_LIMIT')
        for decoder in decoders:
            decoder.decode(b'', final=True)
    except UnicodeError as error:
        raise DocumentError('INVALID_UTF8_BOUNDARY: unit text must be complete strict UTF-8') from error
    return first


def compare_streams(reading_path, reference_path, record, reference):
    result = outcome('CONDITIONAL_EXACT_REFERENCE_MATCH')
    left_hash, right_hash = hashlib.sha256(), hashlib.sha256()
    with open_regular(no_links(reading_path), reading_module.MAX_READING) as left:
        with open_regular(reference_path, reading_module.MAX_READING) as right:
            before = identity(left), identity(right)
            need(before[0][2] == record['text_bytes'] and before[1][2] == reference['text_bytes'],
                 'REFERENCE_TEXT_SIZE_MISMATCH')
            for actual, expected in zip(record['segments'], reference['segments']):
                first = compare_unit(left, right, actual, expected, left_hash, right_hash)
                if first is not None:
                    result['mismatch_units'] += 1
                    if len(result['mismatches']) < MAX_DETAILS:
                        result['mismatches'].append({'unit_id': actual['id'], 'first_mismatch_offset': first})
            need(left.read(1) == b'' and right.read(1) == b'', 'REFERENCE_PARTITION_TRAILING_BYTES')
            need(before == (identity(left), identity(right)), 'REFERENCE_INPUT_CHANGED')
    need(left_hash.hexdigest() == record['text_sha256'], 'READING_TEXT_HASH_MISMATCH')
    need(right_hash.hexdigest() == reference['text_sha256'], 'REFERENCE_TEXT_HASH_MISMATCH')
    if result['mismatch_units']:
        result['status'] = 'MISMATCH'
    result.update(source_sha256=record['source_sha256'], reading_text_sha256=left_hash.hexdigest(),
                  reference_text_sha256=right_hash.hexdigest(), compared_units=len(record['segments']))
    return result


def compare_reference(reading_text_path, reading_record, reference_manifest_path, reference_text_path,
                      expected_manifest_sha, requested_claim=CLAIM):
    checked_claim(requested_claim)
    try:
        need(type(reading_record) is dict and 'source_sha256' in reading_record, 'READING_RECORD_REQUIRED')
        need(len(canonical(reading_record)) <= MAX_META, 'READING_RECORD_METADATA_BOUND')
        record = reading_module.record_checked(reading_record, reading_record['source_sha256'])
        supplied = reference_inputs(reference_manifest_path, reference_text_path, expected_manifest_sha)
        if supplied is None:
            return outcome('REFERENCE_MISSING')
        reference, reference_path = supplied
        reference_checked(reference, record)
        result = compare_streams(reading_text_path, reference_path, record, reference)
        result['expected_manifest_sha256'] = expected_manifest_sha
        need(len(canonical(result)) <= MAX_OUTPUT, 'REFERENCE_OUTPUT_BOUND')
        return result
    except (OSError, TypeError, KeyError, RecursionError) as error:
        raise DocumentError('REFERENCE_EVIDENCE_REFUSED: ' + type(error).__name__) from error



def package_reading_record(recovered, body):
    raw = read_file(no_links(recovered.parent / 'reading.json'), MAX_META)
    observed = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    need(observed == body['entries']['reading.json'], 'PACKAGE_READING_METADATA_MISMATCH')
    record = loads(raw)
    need(type(record) is dict and record.get('source_sha256') == body['source']['sha256'],
         'PACKAGE_READING_SOURCE_MISMATCH')
    need((record.get('text_sha256'), record.get('text_bytes')) ==
         (body['reading']['sha256'], body['reading']['bytes']), 'PACKAGE_READING_TEXT_MISMATCH')
    return record


def verify_package_reference(archive, share, reference_manifest, reference_text, expected_manifest_sha,
                             native=None, requested_claim='EXACT_REFERENCE_TEXT'):
    checked_claim(requested_claim)
    from transport_document import validated
    with validated(archive, share, native) as (recovered, body, package_id, _sections):
        need(body['reading'] is not None, 'READING_RECORD_REQUIRED: package has no reading view')
        record = package_reading_record(recovered, body)
        result = compare_reference(recovered.parent / 'reading.txt', record, reference_manifest,
                                   reference_text, expected_manifest_sha, requested_claim)
        result.update(package_id=package_id, package_source_sha256=body['source']['sha256'],
                      package_validation='FULL_PAIRED_ARCHIVE_SOURCE_AND_READING_CHECKED')
        need(len(canonical(result)) <= MAX_OUTPUT, 'REFERENCE_OUTPUT_BOUND')
        return result


def timeout_handler(_number, _frame):
    raise DocumentError('REFERENCE_COMMAND_TIMEOUT')


def cli_limits():
    for kind, requested in ((resource.RLIMIT_AS, 1_073_741_824), (resource.RLIMIT_FSIZE, 2_147_483_648),
                            (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64)):
        soft, hard = resource.getrlimit(kind)
        bound = min([requested] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (bound, bound))
    signal.signal(signal.SIGALRM, timeout_handler)
    inherited = signal.getitimer(signal.ITIMER_REAL)[0]
    signal.setitimer(signal.ITIMER_REAL, min(450, inherited) if inherited > 0 else 450)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'share'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('reference-manifest', 'reference-text', 'native'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--expected-manifest-sha')
    parser.add_argument('--requested-claim', default='EXACT_REFERENCE_TEXT')
    args = parser.parse_args()
    try:
        cli_limits()
        result = verify_package_reference(args.archive, args.share, args.reference_manifest,
            args.reference_text, args.expected_manifest_sha, args.native, args.requested_claim)
        raw = canonical(result)
        need(len(raw) + 1 <= MAX_OUTPUT, 'REFERENCE_OUTPUT_BOUND')
        print(raw.decode('ascii'))
        return 0 if result['status'] == 'CONDITIONAL_EXACT_REFERENCE_MATCH' else 1
    except (DocumentError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print('REFERENCE_REFUSED: ' + str(error)[:512], file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
