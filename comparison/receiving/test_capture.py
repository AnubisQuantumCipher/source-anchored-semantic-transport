#!/usr/bin/env python3
"""Deterministic frozen-oracle collector controls; synthetic journals only.

No source data, tool strings or journal content is executed. API path seams are
explicit test bindings to a new tmpfs tree, never forged real session journals.
"""

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import trace_support as support
import capture_trace as capture

ORACLE_SHA = '63e56f759adc3ef76ea6bfa3ced6c048456103d15e180713dde093c782920934'
SUPPORT_SHA = '73279dcbb03c769e334063204d6e945c8e5f90023f55f5fcec44672024fb292f'
LIFECYCLE_ORACLE_SHA = '8d37b74e09582502401719edb39ecf5d801c1d04373951b56a42dfe531627834'
CAP, TOTAL = 4194304, 50331648
THREAD = '00000000-0000-0000-0000-000000000001'
PARENT = '00000000-0000-0000-0000-000000000002'
AGENT = '/root/synthetic_receiver'


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def read(path, cap=CAP):
    need(path.is_file() and not path.is_symlink(), 'regular nonsymlink test source')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'test read bound')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = value if type(value) is bytes else encoded(value)
    need(len(raw) <= CAP, 'test file bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short test write')
    need(read(path) == raw, 'test readback mismatch')
    return dict(bytes=len(raw), sha256=sha(raw))


def attempt(function, *args):
    try:
        return dict(status='RETURN', value=function(*args))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, MemoryError,
            OverflowError, RecursionError) as error:
        return dict(status='REFUSED', reason=str(error)[:256])


def result(results, name, observed, expected, passed):
    need(len(results) < 256, 'control result count bound')
    results.append(dict(name=name, passed=bool(passed), expected=expected, observed=observed))


def literal_projection(results, cases, function, prefix):
    for case in cases:
        expected = case['expected']
        actual = attempt(function, case['input'])
        if expected['disposition'] == 'REFUSE':
            passed = actual['status'] == 'REFUSED' and bool(actual.get('reason'))
        else:
            passed = actual == dict(status='RETURN', value=expected['projection'])
        result(results, prefix + case['id'], actual, expected, passed)


def literal_sequences(results, cases):
    for case in cases:
        actual = attempt(lambda rows: [support.whitelisted_metadata(row) for row in rows],
                         case['input_records'])
        expected = dict(status='RETURN', value=case['expected_projections_literal'])
        result(results, 'sequence-' + case['id'], actual, expected, actual == expected)


def base_args(root, name, oracle, rows=(), raw_tail=b'', candidate=b'{}'):
    directory = root / 'cases' / name
    directory.mkdir(mode=0o700)
    journals = root / 'synthetic-journals'
    rollout = journals / (name + '-' + THREAD + '.jsonl')
    initial = oracle['protocol_fixture_specification']['matching_lineage_first_record']
    raw = encoded(initial) + b'\n' + b''.join(encoded(row) + b'\n' for row in rows) + raw_tail
    save(rollout, raw)
    for filename, value in (('interface', b'Synthetic interface data'), ('launch', b'{}')):
        save(directory / filename, value)
    if candidate is not None:
        save(directory / 'candidate', candidate)
    return SimpleNamespace(rollout=rollout, output=directory / 'capture',
        candidate=directory / 'candidate', interface=directory / 'interface', launch=directory / 'launch',
        expected_thread=THREAD, expected_parent=PARENT, expected_agent_path=AGENT)


def captured(results, args, name, expected_status='RETURN', state=None):
    actual = attempt(capture.capture, args)
    passed = actual['status'] == expected_status
    summary = dict(status=actual['status'])
    if actual['status'] == 'RETURN':
        report = actual['value']
        summary.update(metadata=len(report['metadata']), tools=len(report['events']),
            finals=len(report['final_responses']), final_capture_state=report['final_capture_state'],
            saved_candidate_used_as_final=report['saved_candidate_used_as_final'])
        passed = passed and report['saved_candidate_used_as_final'] is False
        if state is not None:
            passed = passed and report['final_capture_state'] == state
    else:
        summary['reason'] = actual['reason']
        passed = passed and not (args.output / 'report.json').exists()
    result(results, name, summary, dict(status=expected_status, final_state=state), passed)
    return actual


def metadata_limit_cases(results, oracle):
    selected = ('model_string_at_limit', 'model_string_over_limit', 'timestamp_at_limit',
                'timestamp_over_limit', 'cli_string_over_limit')
    cases = {case['id']: case for case in oracle['limit_case_specification']['cases']}
    for name in selected:
        case = cases[name]
        value = json.loads(encoded(case['construction']['template']))
        replacement = case['construction']['replace_data_string']
        keys = replacement['field'].split('.')
        need(len(keys) == 2, 'literal string construction path')
        value[keys[0]][keys[1]] = replacement['codepoint'] * replacement['count']
        actual = attempt(support.whitelisted_metadata, value)
        expected = case['expected']
        passed = actual['status'] == ('REFUSED' if expected['disposition'] == 'REFUSE' else 'RETURN')
        if actual['status'] == 'RETURN':
            projection = actual['value']
            passed = passed and projection['kind'] == expected['kind']
            passed = passed and projection['fields'][expected['field']] == replacement['codepoint'] * expected['unchanged_count']
        result(results, name, actual, expected, passed)


def primitive_limits(root, results):
    cases = [('depth-at', b'[' * 64 + b'0' + b']' * 64, 'RETURN'),
             ('depth-over', b'[' * 65 + b'0' + b']' * 65, 'REFUSED'),
             ('fields-at', encoded({'k%04d' % i: 0 for i in range(1024)}), 'RETURN'),
             ('fields-over', encoded({'k%04d' % i: 0 for i in range(1025)}), 'REFUSED')]
    for name, raw, expected in cases:
        actual = attempt(support.parse, raw)
        result(results, name, dict(status=actual['status'], reason=actual.get('reason')),
               expected, actual['status'] == expected)
    for name, size, expected in (('output-at', 4194304, 'RETURN'), ('output-over', 4194305, 'REFUSED')):
        actual = attempt(support.write, root / name, b'x' * size)
        result(results, name, actual, expected, actual['status'] == expected)
    constants = (support.MAX_FILE, support.MAX_LINE, support.MAX_LINES,
                 support.MAX_TOOLS + support.MAX_OUTPUTS)
    result(results, 'frozen-resource-constants', list(constants),
           [33554432, 1048576, 32768, 768], constants == (33554432, 1048576, 32768, 768))


def capture_limits(root, oracle, results):
    turn = {'type': 'turn_context', 'payload': {'model': 'gpt-6.1-sol'}}
    tool = {'type': 'response_item', 'payload': {'type': 'function_call', 'name': 'synthetic_data_only',
            'call_id': 'literal-repeated-id', 'arguments': '{}'}}
    final = {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
             'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': '{}'}]}}
    ignored = {'type': 'ignored', 'payload': {}}
    cases = [('metadata-at', turn, 255, 'RETURN', 'metadata', 256),
             ('metadata-over', turn, 256, 'REFUSED', None, None),
             ('tools-at', tool, 768, 'RETURN', 'events', 768),
             ('tools-over', tool, 769, 'REFUSED', None, None),
             ('finals-at', final, 8, 'RETURN', 'final_responses', 8),
             ('finals-over', final, 9, 'REFUSED', None, None),
             ('lines-at', ignored, 32767, 'RETURN', None, None),
             ('lines-over', ignored, 32768, 'REFUSED', None, None)]
    for name, row, count, expected, field, expected_count in cases:
        args = base_args(root, name, oracle, [row] * count)
        actual = captured(results, args, name, expected)
        if field is not None and actual['status'] == 'RETURN':
            result(results, name + '-exact-count', len(actual['value'][field]), expected_count,
                   len(actual['value'][field]) == expected_count)


def line_limits(root, oracle, results):
    prefix, suffix = b'{"type":"ignored","payload":"', b'"}\n'
    for name, count, expected in (('line-at', 1048576, 'RETURN'), ('line-over', 1048577, 'REFUSED')):
        raw = prefix + b'a' * (count - len(prefix) - len(suffix)) + suffix
        args = base_args(root, name, oracle, raw_tail=raw)
        captured(results, args, name, expected)
    for name, count, expected in (('file-seam-at', 4096, 'RETURN'), ('file-seam-over', 4097, 'REFUSED')):
        args = base_args(root, name, oracle)
        initial = read(args.rollout)
        tail = prefix + b'a' * (count - len(initial) - len(prefix) - len(suffix)) + suffix
        with args.rollout.open('ab') as stream:
            need(stream.write(tail) == len(tail), 'short seam fixture append')
        with patch.object(support, 'MAX_FILE', 4096):
            captured(results, args, name, expected)


def shared_limits(root, oracle, results, directory):
    manifest = read(directory / 'receipt.json')
    need(sha(manifest) == 'e0cc665b888bfa126af71f5171d93f6c3a8f16d767043283ba5c900c84a41e34',
         'held shared-fixture receipt changed')
    records = [('max', 33554432, '1fbb318918483dc668d701f678423bade427d72052bd1878a3012fed92d09271', 'RETURN'),
               ('over', 33554433, '65349ca252c9570f28f53db61203f50f9047cc4929f9e755674396cd70f67a31', 'REFUSED')]
    pins = {}
    for name, count, held, expected in records:
        path = directory / (name + '-' + THREAD + '.jsonl')
        raw = support.read(path, 33554433)
        need(len(raw) == count and sha(raw) == held, 'shared fixture identity')
        del raw
        pins[str(path)] = dict(bytes=count, sha256=held)
        args = base_args(root, 'full-file-' + name, oracle)
        args.rollout = path
        with patch.object(support, 'SESSION_ROOT', directory):
            captured(results, args, 'full-file-' + name, expected)
        after = support.read(path, 33554433)
        need(len(after) == count and sha(after) == held, 'shared fixture changed during capture')
    save(root / 'shared-fixture-pins.json', pins)


def framing_and_lineage(root, oracle, results):
    cases = oracle['protocol_fixture_specification']['capture_cases']
    for case in cases:
        if 'input_raw_utf8' not in case:
            continue
        args = base_args(root, case['id'], oracle, raw_tail=case['input_raw_utf8'].encode('utf-8'))
        captured(results, args, case['id'], 'REFUSED')
    variants = [('wrong-thread', 'expected_thread', '00000000-0000-0000-0000-000000000003'),
                ('wrong-parent', 'expected_parent', '00000000-0000-0000-0000-000000000003'),
                ('wrong-agent', 'expected_agent_path', '/root/other_receiver')]
    for name, field, replacement in variants:
        args = base_args(root, name, oracle)
        setattr(args, field, replacement)
        first = oracle['protocol_fixture_specification']['matching_lineage_first_record']
        direct = attempt(support.lineage, encoded(first), args)
        result(results, 'direct-lineage-' + name, direct, 'REFUSED', direct['status'] == 'REFUSED')
        captured(results, args, name, 'REFUSED')
    for name, row in (('missing-subagent', {'type': 'session_meta', 'payload': {'id': THREAD}}),
                      ('wrong-first-type', {'type': 'turn_context', 'payload': {'model': 'gpt-6.1-sol'}})):
        args = base_args(root, name, oracle)
        with args.rollout.open('wb') as stream:
            need(stream.write(encoded(row) + b'\n') == len(encoded(row)) + 1, 'fixture replacement')
        captured(results, args, name, 'REFUSED')


def final_capture_cases(root, oracle, results):
    rows = oracle['protocol_fixture_specification']['final_projection_cases']
    by_id = {row['id']: row['input'] for row in rows}
    literal_text = {encoded(row['input']): row['expected']['projection']['text']
                    for row in rows if row['expected']['disposition'] == 'PROJECT'}
    fixtures = [('no-observed-final', [], 'NO_OBSERVED_FINAL'),
        ('one-final', [by_id['current_phase_final']], 'SINGLE_COMPLETE_PLAINTEXT_FINAL'),
        ('incomplete-final', [by_id['partial_plaintext_final_preserved_incomplete']], 'SINGLE_INCOMPLETE_PLAINTEXT_FINAL'),
        ('empty-final', [by_id['empty_final_never_replaced_by_candidate']], 'SINGLE_INCOMPLETE_PLAINTEXT_FINAL'),
        ('identical-finals', [by_id['current_phase_final']] * 2, 'MULTIPLE_OBSERVED_FINALS_NO_SELECTION'),
        ('distinct-finals', [by_id['current_phase_final'], by_id['legacy_channel_final']], 'MULTIPLE_OBSERVED_FINALS_NO_SELECTION')]
    for name, records, expected in fixtures:
        args = base_args(root, name, oracle, records)
        actual = captured(results, args, name, state=expected)
        if actual['status'] == 'RETURN' and records:
            expected_text = [literal_text[encoded(row)] for row in records]
            actual_text = [read(args.output / item['text_file']['path']).decode('utf-8')
                           for item in actual['value']['final_responses']]
            result(results, name + '-exact-retained-bytes', actual_text, expected_text, actual_text == expected_text)
    args = base_args(root, 'different-candidate-final', oracle, [by_id['current_phase_final']], candidate=b'{"saved":1}')
    actual = captured(results, args, 'different-candidate-final', state='SINGLE_COMPLETE_PLAINTEXT_FINAL')
    if actual['status'] == 'RETURN':
        item = actual['value']['final_responses'][0]
        actual_final = read(args.output / item['text_file']['path'])
        result(results, 'different-candidate-no-substitution', dict(final=actual_final.decode(), candidate=read(args.candidate).decode()),
               dict(final='{}', candidate='{"saved":1}'), actual_final == b'{}' and read(args.candidate) == b'{"saved":1}')


def exact_tool_cases(root, oracle, results):
    specs = oracle['protocol_fixture_specification']['capture_cases']
    ids = ('exact_tool_source_no_execution', 'current_tool_output_blocks_retained',
           'truncation_warning_is_retained_not_success')
    records = [item['input'] for item in specs if item['id'] in ids]
    args = base_args(root, 'exact-tools', oracle, records)
    actual = captured(results, args, 'exact-tools')
    if actual['status'] != 'RETURN':
        return
    events = actual['value']['events']
    passed = len(events) == 3
    for event, expected in zip(events, records, strict=True):
        raw = read(args.output / event['path'])
        passed = passed and raw == encoded(expected) + b'\n'
        if event['kind'] == 'custom_tool_call':
            passed = passed and read(args.output / event['source']['path']) == expected['payload']['input'].encode()
    result(results, 'exact-tool-bytes-and-truncation-preserved', {'events': len(events)},
           {'events': 3, 'no_execution': True, 'no_truncation_promotion': True}, passed)


def mutate_byte(path):
    raw = read(path)
    offset = raw.index(b'"x":0') + 4
    with path.open('r+b') as stream:
        stream.seek(offset)
        need(stream.write(b'1') == 1, 'short mutation write')


def mutation_cases(root, oracle, results):
    tool = {'type': 'response_item', 'payload': {'type': 'function_call', 'name': 'data', 'call_id': 'x', 'arguments': '{}'}}
    args = base_args(root, 'grow-during-scan', oracle, [tool])
    original, count = support.save_tool, [0]
    def growing(*values):
        saved = original(*values)
        if count[0] == 0:
            with args.rollout.open('ab') as stream:
                raw = b'{"type":"ignored","payload":{}}\n'
                need(stream.write(raw) == len(raw), 'short growth write')
        count[0] += 1
        return saved
    with patch.object(support, 'save_tool', growing):
        captured(results, args, 'grow-during-scan', 'REFUSED')
    args = base_args(root, 'mutate-after-scan', oracle, [{'type': 'ignored', 'payload': {'x': 0}}])
    original_read, count = support.read, [0]
    def changed_read(path, cap):
        if path == args.rollout and count[0] == 0:
            mutate_byte(path)
            count[0] += 1
        return original_read(path, cap)
    with patch.object(support, 'read', changed_read):
        captured(results, args, 'mutate-after-scan', 'REFUSED')
    for field in ('candidate', 'interface', 'launch'):
        args = base_args(root, 'mutate-input-' + field, oracle)
        original_scan = support.scan
        def changed_scan(*values):
            scanned = original_scan(*values)
            with getattr(args, field).open('ab') as stream:
                need(stream.write(b' ') == 1, 'short input mutation')
            return scanned
        with patch.object(support, 'scan', changed_scan):
            captured(results, args, 'mutate-input-' + field, 'REFUSED')


def path_cases(root, oracle, results):
    for name in ('existing-output', 'symlink-output', 'symlink-source', 'directory-source', 'fifo-source'):
        args = base_args(root, name, oracle)
        if name == 'existing-output':
            args.output.mkdir()
        elif name == 'symlink-output':
            args.output.symlink_to(args.interface)
        elif name == 'symlink-source':
            alias = args.rollout.with_suffix('.alias-' + THREAD + '.jsonl')
            alias.symlink_to(args.rollout)
            args.rollout = alias
        elif name == 'directory-source':
            directory = args.rollout.with_suffix('.directory-' + THREAD + '.jsonl')
            directory.mkdir()
            args.rollout = directory
        else:
            fifo = args.rollout.with_suffix('.fifo-' + THREAD + '.jsonl')
            os.mkfifo(fifo, 0o600)
            args.rollout = fifo
        captured(results, args, name, 'REFUSED')


def candidate_failure_cases(root, oracle, results):
    final = {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
             'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': '{}'}]}}
    for name, raw, expected in (('missing-candidate', None, 'MISSING'),
        ('malformed-candidate', b'{bad', 'INVALID_JSON_OBJECT'),
        ('nonobject-candidate', b'[]', 'INVALID_JSON_OBJECT'),
        ('empty-candidate', b'', 'INVALID_JSON_OBJECT'),
        ('nonutf8-candidate', b'\xff', 'INVALID_JSON_OBJECT')):
        tool = {'type': 'response_item', 'payload': {'type': 'function_call',
                'name': 'inert', 'call_id': 'inert', 'arguments': '{}'}}
        terminal = {'type': 'event_msg', 'payload': {'type': 'task_complete', 'duration_ms': 0}}
        args = base_args(root, name, oracle, [tool, terminal, final], candidate=raw)
        actual = captured(results, args, name, state='SINGLE_COMPLETE_PLAINTEXT_FINAL')
        if actual['status'] == 'RETURN':
            report = actual['value']
            snapshot = report['inputs']['candidate']
            passed = snapshot['status'] == expected and len(report['events']) == 1 and len(report['metadata']) == 2
            if raw is None:
                passed = passed and snapshot == dict(status='MISSING', bytes=None, sha256=None, base64=None)
            else:
                passed = passed and snapshot['bytes'] == len(raw) and snapshot['sha256'] == sha(raw)
                passed = passed and base64.b64decode(snapshot['base64'], validate=True) == raw
            result(results, name + '-status-and-exact-retention', snapshot, expected, passed)
    args = base_args(root, 'over-cap-candidate', oracle, [final], candidate=b'x' * 32769)
    before = sha(read(args.rollout))
    captured(results, args, 'over-cap-candidate', 'REFUSED')
    result(results, 'over-cap-journal-preserved', sha(read(args.rollout)), before, sha(read(args.rollout)) == before)


def unsafe_candidate_cases(root, oracle, results):
    for name in ('symlink', 'directory', 'fifo'):
        args = base_args(root, 'unsafe-candidate-' + name, oracle, candidate=None)
        if name == 'symlink':
            args.candidate.symlink_to(args.interface)
        elif name == 'directory':
            args.candidate.mkdir()
        else:
            os.mkfifo(args.candidate, 0o600)
        before = sha(read(args.rollout))
        captured(results, args, 'unsafe-candidate-' + name, 'REFUSED')
        result(results, 'unsafe-candidate-' + name + '-journal-preserved', sha(read(args.rollout)),
               before, sha(read(args.rollout)) == before)
    terminal = {'type': 'event_msg', 'payload': {'type': 'task_complete', 'duration_ms': None}}
    args = base_args(root, 'missing-candidate-and-final', oracle, [terminal], candidate=None)
    actual = captured(results, args, 'missing-candidate-and-final', state='NO_OBSERVED_FINAL')
    if actual['status'] == 'RETURN':
        snapshot = actual['value']['inputs']['candidate']
        result(results, 'missing-candidate-and-final-status', snapshot['status'], 'MISSING',
               snapshot['status'] == 'MISSING' and actual['value']['saved_candidate_used_as_final'] is False)


def static_controls():
    results = {}
    for path in (Path(__file__).resolve(), HERE / 'trace_support.py', HERE / 'capture_trace.py'):
        tree = ast.parse(read(path))
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        lengths = {n.name: n.end_lineno - n.lineno + 1 for n in functions}
        need(all(value <= 60 for value in lengths.values()), 'function size bound: ' + path.name)
        need(not any(isinstance(n, (ast.While, ast.AsyncFor, ast.Assert)) for n in ast.walk(tree)),
             'while/async-for/assert enforcement prohibited')
        results[path.name] = lengths
    return results


def freeze(root, args):
    pins = {}
    for index, name in enumerate(('trace_support.py', 'capture_trace.py', 'test_capture.py',
        'trace-oracle.json', 'contract.json', 'contract-addendum.json', 'dispatch-addendum.json',
        'capture-retention-addendum.json', 'trace-lifecycle-integer-oracle.json')):
        raw = read(HERE / name)
        pins[name] = save(root / ('source-%02d.bin' % index), raw)
    need(pins['trace_support.py']['sha256'] == SUPPORT_SHA, 'held support mismatch')
    need(pins['capture_trace.py']['sha256'] == args.expect_capture_sha256, 'held capture mismatch')
    need(pins['trace-oracle.json']['sha256'] == ORACLE_SHA, 'held trace oracle mismatch')
    need(pins['trace-lifecycle-integer-oracle.json']['sha256'] == LIFECYCLE_ORACLE_SHA,
         'held supplemental lifecycle oracle mismatch')
    need(pins['capture-retention-addendum.json']['sha256'] == '0e0dd1f051e0d2586a60634a9a661a733a257b4c9f894bcebae98b428a2a05bf',
         'held capture retention clarification mismatch')
    save(root / 'source-pins.json', pins)
    return pins, json.loads(read(HERE / 'trace-oracle.json'))


def verify_pins(pins):
    for name, pin in pins.items():
        raw = read(HERE / name)
        need(dict(bytes=len(raw), sha256=sha(raw)) == pin, 'code/input changed during controls: ' + name)


def run(args):
    root = args.evidence
    need(root.is_absolute() and root.parent.is_dir() and not root.exists(), 'new tmpfs evidence directory')
    root.mkdir(mode=0o700)
    for name in ('cases', 'synthetic-journals'):
        (root / name).mkdir(mode=0o700)
    pins, oracle = freeze(root, args)
    save(root / 'static-controls.json', static_controls())
    results = []
    literal_projection(results, oracle['metadata_cases'], support.whitelisted_metadata, 'metadata-')
    literal_sequences(results, oracle['sequence_cases'])
    lifecycle = json.loads(read(HERE / 'trace-lifecycle-integer-oracle.json'))
    literal_projection(results, lifecycle['observed_literal_cases'], support.whitelisted_metadata, 'observed-lifecycle-')
    literal_projection(results, lifecycle['boundary_cases'], support.whitelisted_metadata, 'boundary-lifecycle-')
    literal_projection(results, oracle['protocol_fixture_specification']['final_projection_cases'], capture.selected, 'final-')
    metadata_limit_cases(results, oracle)
    primitive_limits(root, results)
    with patch.object(support, 'SESSION_ROOT', root / 'synthetic-journals'):
        capture_limits(root, oracle, results)
        line_limits(root, oracle, results)
        framing_and_lineage(root, oracle, results)
        final_capture_cases(root, oracle, results)
        exact_tool_cases(root, oracle, results)
        mutation_cases(root, oracle, results)
        path_cases(root, oracle, results)
        candidate_failure_cases(root, oracle, results)
        unsafe_candidate_cases(root, oracle, results)
    shared_limits(root, oracle, results, args.shared_fixtures)
    verify_pins(pins)
    save(root / 'results.json', results)
    files = list(root.rglob('*'))
    need(len(files) <= 8192, 'fixture member bound')
    total = sum(p.stat().st_size for p in files if p.is_file() and not p.is_symlink())
    need(total <= TOTAL, 'per-mode evidence aggregate bound')
    failed = [item['name'] for item in results if not item['passed']]
    receipt = dict(schema='transport/receiving-capture-controls/1', optimized=bool(sys.flags.optimize),
        status='PASS' if not failed else 'FAILED',
        controls=len(results), literal_metadata_cases=42, literal_sequence_cases=1, literal_final_cases=9,
        observed_lifecycle_cases=len(lifecycle['observed_literal_cases']), lifecycle_boundary_cases=len(lifecycle['boundary_cases']),
        failed_cases=failed, unperformed=[],
        terminal_state_gate='OWNER_ENFORCED_NOT_COLLECTOR_ATTESTED; synthetic fixtures only',
        code_pins=pins, actual_fixture_bytes_before_receipt=total, synthetic_session_root=str(root / 'synthetic-journals'),
        actual_session_access='NONE', model_calls='UNRUN', authority='NONE', interpretation='NOT_ASSESSED')
    save(root / 'receipt.json', receipt)
    print(encoded(receipt).decode('ascii'))
    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--expect-capture-sha256', required=True)
    parser.add_argument('--shared-fixtures', type=Path, required=True)
    args = parser.parse_args()
    for kind, bound in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_FSIZE, CAP), (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(kind, (bound, bound))
    return run(args)


if __name__ == '__main__':
    sys.exit(main())
