"""Source-bound projection into the fixed native finite-Q gate, never English truth."""
from pathlib import Path
import json
import math
import struct
import time

from . import challenges, refinement, native_build
from .bindings import bind_graph, graph_from_registry
from .common import (CLAIMS, PROBES, ROUNDS, SentinelError, canonical, digest, fields, hash_checked,
                     depth_checked, held_record, identity, integer, label, no_number, parse,
                     registry_snapshot, require, unique_pairs)
from .locators import resolve_locator

PROFILE = 'SINGLE_DERIVED_UTF8_EXACT_ANSWER_DIGEST'
DOCUMENTARY = ('SUPPORTED', 'REFUTED', 'BOTH', 'NEITHER')
BLOCKERS = ('NO_BLOCKER', 'REQUIRED_UNRESOLVED', 'REQUIRED_CONFLICT', 'OPEN_CHALLENGE')
SENTINEL_MODULES = ('__init__', 'analysis', 'assessments', 'bindings', 'bundle', 'census',
    'challenges', 'cli', 'common', 'comparison', 'graph', 'jobs', 'locators', 'native',
    'native_build', 'native_runtime', 'refinement')
DOCUMENT_MODULES = ('transport_document', 'transport_document_archive', 'transport_document_io',
                    'transport_document_reading', 'transport_document_context')
BUILD_MODULES = ('__init__', 'capture', 'common', 'identity', 'launcher', 'namespace',
                 'process', 'proof', 'worker')
SOURCE_FILES = tuple('tools/sentinel_v1/' + name + '.py' for name in SENTINEL_MODULES) + tuple(
    'tools/' + name + '.py' for name in DOCUMENT_MODULES) + tuple(
    'tools/document_build/' + name + '.py' for name in BUILD_MODULES)
REQUEST_FIELDS = ('schema', 'profile', 'history_sha256', 'gate_admission_sha256',
    'source_locator_sha256', 'registry_sha256', 'locator_registry_sha256',
    'revision_registry_sha256')
GATE_FIELDS = ('schema', 'profile', 'source_set_sha256', 'test_contract_sha256',
    'source_locator_sha256', 'mandatory_claim_ids', 'mandatory_probe_ids', 'rounds',
    'versioned_manifest_sha256', 'native_binary_pin', 'pure_receipt_pin', 'wire_receipt_pin',
    'evaluator_manifest_pin', 'oracle_set_sha256', 'reference_set_sha256', 'provenance_pin')


def _closed(value, names):
    require(type(value) is dict and len(value) == len(names), 'bounded closed record')
    return fields(value, names)


def _artifact(key, snapshot):
    hash_checked(key)
    require(key in snapshot, 'required native evidence absent')
    return snapshot[key]


def _pinned(value, snapshot):
    native_build.checked_pin_record(value)
    raw = _artifact(value['sha256'], snapshot)
    require(identity(raw) == value, 'native artifact pin mismatch')
    return raw


def evaluator_sources(root=None):
    """Fixed local code identities, not a hostile-loader or host attestation."""
    root = Path(__file__).resolve().parents[2] if root is None else root
    root = native_build.root_checked(root)
    result, total = {}, 0
    for name in SOURCE_FILES:
        raw = native_build.read_regular(root, name, native_build.SOURCE_CAP)
        total += len(raw)
        require(total <= native_build.SECTION_CAP, 'evaluator source byte bound')
        result[name] = identity(raw)
    return {'schema': 'sentinel/native-evaluator-sources/1', 'files': result}


def _labels(value, cap):
    require(type(value) is list and 1 <= len(value) <= cap, 'mandatory roster bound')
    result = [label(name) for name in value]
    require(len(set(result)) == len(result), 'duplicate mandatory identity')
    return result


def _request(request_raw, held, snapshot, registry_root, locators_root, revisions_root):
    value = _closed(held_record(request_raw, held), REQUEST_FIELDS)
    require(value['schema'] == 'sentinel/native-request/1' and value['profile'] == PROFILE,
            'native request version/profile')
    require((value['registry_sha256'], value['locator_registry_sha256'],
             value['revision_registry_sha256']) == (registry_root, locators_root, revisions_root),
            'native request registry roots')
    gate = _closed(parse(_artifact(value['gate_admission_sha256'], snapshot)), GATE_FIELDS)
    require(gate['schema'] == 'sentinel/native-gate-admission/1'
            and gate['profile'] == PROFILE, 'native gate version/profile')
    require(gate['source_locator_sha256'] == value['source_locator_sha256'], 'gate source locator')
    _pinned(gate['provenance_pin'], snapshot)
    _labels(gate['mandatory_claim_ids'], CLAIMS)
    _labels(gate['mandatory_probe_ids'], PROBES)
    native_build.checked_pin_record(gate['native_binary_pin'])
    return value, gate


def _history(key, gate, snapshot, registry_root):
    raw = _artifact(key, snapshot)
    value = refinement.history_checked(raw, key)
    require(value['source_set_sha256'] == gate['source_set_sha256'] and
            value['test_contract_sha256'] == gate['test_contract_sha256'], 'held history contract')
    require(type(gate['rounds']) is list and len(gate['rounds']) == len(value['rounds']),
            'complete admitted history rounds')
    current = value
    for _ in range(ROUNDS):
        previous = current['predecessor_sha256']
        if previous is None:
            require(len(current['rounds']) == 1, 'history predecessor omitted')
            break
        prior = refinement.history_checked(_artifact(previous, snapshot), previous)
        require(len(prior['rounds']) + 1 == len(current['rounds']) and
                canonical(prior['rounds']) == canonical(current['rounds'][:-1]),
                'history predecessor changed')
        current = prior
    else:
        raise ValueError('history predecessor bound')
    last = value['rounds'][-1]
    challenge = parse(_artifact(last['challenge_set_sha256'], snapshot))
    admission = _artifact(last['admission_sha256'], snapshot)
    refinement.recheck_prior(value['rounds'], challenge, admission, snapshot, registry_root)
    return value


def _qualification_evidence(gate, snapshot):
    root = Path(__file__).resolve().parents[2]
    manifest, data = native_build.checked_inputs(root, gate['versioned_manifest_sha256'])
    manifest_raw = _artifact(gate['versioned_manifest_sha256'], snapshot)
    require(canonical(manifest) == manifest_raw, 'retained version manifest differs')
    for key, name in (('pure_receipt_pin', 'pure-receipt.json'),
                      ('wire_receipt_pin', 'wire-receipt.json')):
        require(canonical(gate[key]) == canonical(manifest['evidence'][name]),
                'receipt pin differs from held version manifest')
    evidence = {}
    for name in ('pure-receipt.json', 'pure-result.json', 'pure-review.json',
                 'wire-receipt.json', 'wire-result.json', 'wire-review.json'):
        raw = _pinned(manifest['evidence'][name], snapshot)
        require(raw == data['evidence'][name], 'retained evidence differs from checked bundle')
        evidence[name] = _historical_json(raw)
    _checked_receipt(evidence, 'pure', 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED')
    _checked_receipt(evidence, 'wire', 'SENTINEL_WIRE_BUILD_AND_FROZEN_CONTROLS_CHECKED')
    pure, wire = evidence['pure-result.json']['worker'], evidence['wire-result.json']['worker']
    _proof_evidence(pure, data)
    require(wire['parser_proof'] == 'UNPROVEN', 'wire parser proof scope')
    integer(wire['controls']['literal_cases'], 51, 51)
    integer(wire['controls']['strict_prefix_cases'], 901, 901)
    binary = wire['binary']
    require(canonical(gate['native_binary_pin']) == canonical(
        {'bytes': binary['file_bytes'], 'sha256': binary['sha256']}), 'held wire ELF provenance')
    evaluator = _pinned(gate['evaluator_manifest_pin'], snapshot)
    require(canonical(evaluator_sources(root)) == evaluator, 'fixed evaluator source roster differs')
    return digest(evaluator)


def _historical_float(token):
    require(len(token) <= 64 and math.isfinite(float(token)), 'finite historical diagnostic token')
    return 'HISTORICAL_DIAGNOSTIC_FLOAT:' + token


def _historical_integer(token):
    require(len(token) <= 20, 'historical integer token bound')
    return int(token)


def _historical_json(raw):
    """Pinned old reports only; formatting/timing tokens never grant a policy result."""
    require(type(raw) is bytes and 0 < len(raw) <= 1048576, 'historical JSON byte bound')
    depth_checked(raw)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
            parse_float=_historical_float, parse_int=_historical_integer, parse_constant=no_number)
        require(type(value) is dict, 'historical report object required')
        return value
    except (UnicodeError, RecursionError) as error:
        raise SentinelError('invalid pinned historical JSON') from error


def _checked_receipt(evidence, prefix, expected_status):
    outer, result = evidence[prefix + '-receipt.json'], evidence[prefix + '-result.json']
    require(outer['status'] == result['status'] == result['worker']['status'] == expected_status,
            'retained qualification status')
    integer(outer['returncode'], 0, 0)
    require(outer['failure'] is None and outer['namespace_waited'] is True
            and result['failures'] == [] and result['readonly_qualified'] is True,
            'retained qualification incomplete')
    integer(result['cleanup']['remaining'], 0, 0)
    integer(result['terminal_cleanup']['remaining'], 0, 0)
    require(result['capture']['complete'] is True and result['capture']['readonly_qualified'] is True,
            'retained capture incomplete or writable')
    require(result['identity_before']['status'] == result['identity_after']['status'] == 'CHECKED'
            and canonical(result['identity_before']) == canonical(result['identity_after']),
            'retained runtime identity mismatch')
    for name in ('identity_before', 'identity_after'):
        integer(result[name]['files'], 1, 4096)
        hash_checked(result[name]['roster_sha256'])


def _proof_evidence(worker, data):
    proof, machine = worker['proof'], worker['machine_diagnostics']
    for key, expected in (('total', 139), ('flow', 85), ('prover', 54),
                          ('unproved', 0), ('justified', 0), ('assume', 0), ('warnings', 0)):
        integer(proof[key], expected, expected)
    for key, expected in (('entities', 46), ('flow_records', 85), ('proof_records', 54),
                          ('warn_error_records', 0)):
        integer(machine[key], expected, expected)
    roster = native_build.load_json(data['proof_roster'], 1048576)
    require(type(proof['entities']) is dict and len(proof['entities']) == 46,
            'source13 typed entity map')
    require(type(roster['entities']) is list and len(roster['entities']) == 46,
            'exact retained source-derived entity roster')
    for count in proof['entities'].values():
        integer(count, 0, 139)
    for row in roster['entities']:
        _closed(row, ('name', 'file', 'line', 'minimum_proved_checks', 'explicit_postcondition'))
        label(row['name'])
        require(row['file'] in ('sentinel_policy.ads', 'sentinel_policy.adb')
                and type(row['explicit_postcondition']) is bool, 'typed source roster row')
        integer(row['line'], 1, 131072)
        integer(row['minimum_proved_checks'], 0, 139)
        require(row['name'] in proof['entities'] and
                proof['entities'][row['name']] >= row['minimum_proved_checks'],
                'retained source-derived proof minimum not met')
    expected = {row['name'] for row in roster['entities']}
    require(set(proof['entities']) == expected, 'source13 proof entity roster differs')


def _resolution(value, gate, snapshot, archive, share, locators, locators_held,
                revisions, revisions_held, document_native):
    key = value['source_locator_sha256']
    resolution = resolve_locator(archive, share, _artifact(key, snapshot), key,
        locators, locators_held, revisions, revisions_held, document_native)
    require(resolution['status'] == 'RESOLVED_BYTES' and resolution['gaps'] == []
            and len(resolution['parts']) == 1, 'single contiguous resolved region required')
    representation = resolution['representation']
    require(representation['kind'] == 'DERIVED_UTF8', 'derived reading native profile required')
    hash_checked(representation['record_sha256'])
    part = resolution['parts'][0]
    integer(part['span'][0], 0, representation['bytes'])
    integer(part['span'][1], part['span'][0] + 1, representation['bytes'])
    require(part['span'][1] - part['span'][0] <= 65536
            and identity(part['data']) == {'bytes': part['span'][1] - part['span'][0],
                                           'sha256': part['sha256']}, 'resolved region bytes')
    return resolution


def _round_context(admitted, row, gate, snapshot):
    names = ('ordinal', 'graph_sha256', 'challenge_set_sha256', 'challenge_admission_sha256',
             'replay_sha256', 'context_admission_sha256')
    _closed(admitted, names)
    require(canonical({key: admitted[key] for key in names[:3]}) == canonical(
        {key: row[key] for key in names[:3]}) and admitted['challenge_admission_sha256'] ==
        row['admission_sha256'] and admitted['replay_sha256'] == row['replay_sha256'],
        'gate historical round differs')
    raw = _artifact(admitted['context_admission_sha256'], snapshot)
    context = _closed(parse(raw), ('schema', 'graph_sha256', 'source_set_sha256',
        'test_contract_sha256', 'source_locator_sha256', 'context_complete',
        'adjudication_complete', 'blockers', 'provenance_pin'))
    require(context['schema'] == 'sentinel/native-context-admission/1'
            and context['graph_sha256'] == row['graph_sha256'], 'held context candidate')
    require(all(context[key] == gate[key] for key in ('source_set_sha256',
        'test_contract_sha256', 'source_locator_sha256')), 'held context scope')
    require(type(context['context_complete']) is bool and
            type(context['adjudication_complete']) is bool, 'explicit typed external context flags')
    blockers = context['blockers']
    require(type(blockers) is dict and len(blockers) == len(gate['mandatory_probe_ids'])
            and set(blockers) == set(gate['mandatory_probe_ids']), 'complete external blocker roster')
    require(all(value in BLOCKERS for value in blockers.values()), 'closed external blocker')
    _pinned(context['provenance_pin'], snapshot)
    return context


def _round_checked(row, admitted, gate, snapshot, registry_root, resolution):
    context = _round_context(admitted, row, gate, snapshot)
    challenge, _snapshot, oracles = challenges.checked_set(
        _artifact(row['challenge_set_sha256'], snapshot), row['challenge_set_sha256'],
        snapshot, registry_root, _artifact(row['admission_sha256'], snapshot), row['admission_sha256'])
    graph = graph_from_registry(row['graph_sha256'], snapshot)
    require(len(graph['source_set']) == 1, 'multi-source native projection unsupported')
    bind_graph(graph, resolution)
    claims = [node for node in graph['nodes'] if node['kind'] == 'PROPOSITION']
    require([node['id'] for node in claims] == gate['mandatory_claim_ids'], 'complete mandatory claims')
    require([probe['id'] for probe in challenge['probes']] == gate['mandatory_probe_ids'],
            'complete ordered mandatory question roster')
    subjects = {probe['claim_id'] for probe in challenge['probes']}
    require(subjects == set(gate['mandatory_claim_ids']), 'every mandatory claim needs a test')
    require(refinement.test_contract(challenge, parse(_artifact(row['admission_sha256'], snapshot)))
            == gate['test_contract_sha256'], 'fixed question contract changed')
    covered = {gate['source_locator_sha256'], *resolution['dependency_locator_sha256s']}
    require([result['id'] for result in row['results']] == gate['mandatory_probe_ids'],
            'historical answer order differs')
    for probe, result in zip(challenge['probes'], row['results']):
        key = probe['target_locator_sha256']
        require(key in covered, 'probe target outside resolved closure')
        before = challenges.selected_bytes(parse(_artifact(key, snapshot)), resolution)
        require(identity(before) == probe['transformation']['before_pin'], 'probe source differs')
        require(oracles[probe['id']] is not None and result['status'] in
                ('MATCH_REFERENCE', 'MISMATCH_REFERENCE'), 'complete oracle and actual answer required')
        _pinned(result['answer_pin'], snapshot)
    return graph, claims, challenge, oracles, context


def _question_records(challenge, oracles, gate):
    questions, oracle_rows, reference_rows = [], [], []
    for ordinal, probe in enumerate(challenge['probes'], 1):
        oracle = oracles[probe['id']]
        questions.append({'ordinal': ordinal, 'claim_id': probe['claim_id'], 'probe_id': probe['id'],
            'input_sha256': probe['input_pin']['sha256'],
            'expected_answer_sha256': oracle['answer_pin']['sha256']})
        oracle_rows.append({'probe_id': probe['id'], 'oracle_pin': probe['oracle_pin']})
        reference_rows.append({'probe_id': probe['id'], 'expected_answer_pin': oracle['answer_pin']})
    oracle_set = {'schema': 'sentinel/native-oracle-set/1', 'rows': oracle_rows}
    reference = {'schema': 'sentinel/native-reference-set/1', 'rows': reference_rows}
    require(digest(canonical(oracle_set)) == gate['oracle_set_sha256'] and
            digest(canonical(reference)) == gate['reference_set_sha256'], 'held oracle/reference set')
    return {'schema': 'sentinel/native-question-roster/1', 'rows': questions}


def _answer_receipt(row, result, context_key):
    return {'schema': 'sentinel/native-answer-receipt/1', 'round': row['ordinal'],
        'graph_sha256': row['graph_sha256'], 'probe_id': result['id'],
        'answer_pin': result['answer_pin'], 'oracle_pin': result['oracle_pin'],
        'replay_sha256': row['replay_sha256'], 'context_admission_sha256': context_key}


def _events(row, context, context_key):
    events = []
    for result in row['results']:
        kinds = ['MISMATCH_REFERENCE'] if result['status'] == 'MISMATCH_REFERENCE' else []
        blocker = context['blockers'][result['id']]
        if blocker != 'NO_BLOCKER':
            kinds.append(blocker)
        for kind in kinds:
            events.append({'round': row['ordinal'], 'probe_id': result['id'], 'kind': kind,
                'replay_sha256': row['replay_sha256'], 'context_admission_sha256': context_key})
    return events


def _claim_records(claims, resolution):
    anchor = resolution['representation']['sha256']
    records = []
    for claim in claims:
        links = [{'representation': 1, 'anchor': anchor, 'first': evidence['start'],
                  'last': evidence['end']} for evidence in claim['evidence']]
        records.append({'id': claim['id'], 'documentary': claim['documentary_state'], 'links': links})
    return records


def _projection(history, gate, snapshot, registry_root, resolution, evaluator):
    rounds, questions, prior_events, parents = [], None, [], []
    for row, admitted in zip(history['rounds'], gate['rounds']):
        _graph, claims, challenge, oracles, context = _round_checked(
            row, admitted, gate, snapshot, registry_root, resolution)
        current_questions = _question_records(challenge, oracles, gate)
        require(questions is None or canonical(questions) == canonical(current_questions),
                'question roster changed between candidates')
        questions = current_questions
        repair = None
        if rounds:
            repair = {'schema': 'sentinel/native-repair/1',
                'from_graph_sha256': rounds[-1]['candidate'], 'to_graph_sha256': row['graph_sha256'],
                'history_sha256': gate['_history_sha256'], 'repair_parent_sha256s': list(parents),
                'prior_blocking_events': list(prior_events)}
        context_key = admitted['context_admission_sha256']
        answers = [{'actual': result['answer_pin']['sha256'],
            'receipt': digest(canonical(_answer_receipt(row, result, context_key))),
            'blocker': context['blockers'][result['id']]} for result in row['results']]
        rounds.append({'candidate': row['graph_sha256'], 'claims': _claim_records(claims, resolution),
            'context': context['context_complete'], 'adjudication': context['adjudication_complete'],
            'answers': answers, 'repair': repair, 'prior_events': list(prior_events)})
        prior_events.extend(_events(row, context, context_key))
        parents.extend(entry['sha256'] for entry in row['counterexamples'])
    source, reading = resolution['source'], resolution['representation']
    hashes = [source['sha256'], resolution['package_id'], reading['sha256'], reading['record_sha256'],
        gate['versioned_manifest_sha256'], digest(canonical(questions)), gate['oracle_set_sha256'],
        gate['reference_set_sha256'], evaluator]
    return {'hashes': hashes, 'source_bytes': source['bytes'], 'reading_bytes': reading['bytes'],
        'region': resolution['parts'][0]['span'], 'claim_ids': gate['mandatory_claim_ids'],
        'probe_ids': gate['mandatory_probe_ids'], 'questions': questions, 'rounds': rounds}


def _identity_wire(projection):
    hashes = projection['hashes']
    require(type(hashes) is list and len(hashes) == 9, 'nine identity hashes required')
    value = b''.join(bytes.fromhex(hash_checked(key)) for key in hashes)
    integer(projection['source_bytes'], 1, 1073741824)
    integer(projection['reading_bytes'], 1, 33554432)
    require(type(projection['region']) is list and len(projection['region']) == 2, 'one region interval')
    first, last = projection['region']
    integer(first, 0, projection['reading_bytes'])
    integer(last, first + 1, projection['reading_bytes'])
    require(last - first <= 65536, 'native region bound')
    return value + struct.pack('>IIII', projection['source_bytes'], projection['reading_bytes'], first, last)


def _mask(events, probes):
    require(type(events) is list and len(events) <= 4096, 'historical blocking event bound')
    result = bytearray(256)
    for event in events:
        integer(event['round'], 1, ROUNDS)
        require(event['probe_id'] in probes, 'historical event probe')
        slot = (event['round'] - 1) * 256 + probes.index(event['probe_id'])
        result[slot // 8] |= 1 << (7 - slot % 8)
    return bytes(result)


def _frame(opcode, payload):
    require(type(payload) is bytes and len(payload) <= 660, 'fixed frame payload bound')
    return bytes([opcode]) + struct.pack('>I', len(payload)) + payload


def _claim_wire(ordinal, claim):
    integer(ordinal, 1, CLAIMS)
    require(claim['documentary'] in DOCUMENTARY, 'documentary code')
    links = claim['links']
    require(type(links) is list and len(links) <= 16, 'complete bounded links')
    raw = struct.pack('>HBB', ordinal, DOCUMENTARY.index(claim['documentary']), len(links))
    for link in links:
        integer(link['representation'], 1, 1)
        integer(link['first'], 0, 33554432)
        integer(link['last'], link['first'] + 1, 33554432)
        raw += bytes([1]) + bytes.fromhex(hash_checked(link['anchor'])) + struct.pack(
            '>II', link['first'], link['last'])
    return _frame(3, raw)


def _encode_projection(projection):
    """Byte projection only. A caller-created projection establishes no provenance."""
    held = _identity_wire(projection)
    claims, probes, rounds = projection['claim_ids'], projection['probe_ids'], projection['rounds']
    _labels(claims, CLAIMS)
    _labels(probes, PROBES)
    require(type(rounds) is list and 1 <= len(rounds) <= ROUNDS, 'encoded round bound')
    raw = bytearray(b'STN1\x01\x00\x00\x00')
    raw.extend(_frame(1, held + struct.pack('>HH', len(claims), len(probes))
        + bytes.fromhex(hash_checked(rounds[0]['candidate']))))
    questions = projection['questions']['rows']
    require(type(questions) is list and len(questions) == len(probes), 'encoded full Q roster')
    for ordinal, question in enumerate(questions, 1):
        integer(question['ordinal'], ordinal, ordinal)
        require(question['probe_id'] == probes[ordinal - 1]
                and question['claim_id'] in claims, 'encoded Q order or subject')
        raw.extend(_frame(2, struct.pack('>HH', ordinal, claims.index(question['claim_id']) + 1)
            + bytes.fromhex(hash_checked(question['input_sha256']))
            + bytes.fromhex(hash_checked(question['expected_answer_sha256']))))
    for ordinal, row in enumerate(rounds, 1):
        candidate = bytes.fromhex(hash_checked(row['candidate']))
        if ordinal > 1:
            raw.extend(_frame(6, candidate + bytes.fromhex(digest(canonical(row['repair'])))
                              + _mask(row['prior_events'], probes)))
        require(len(row['claims']) == len(claims) and len(row['answers']) == len(probes),
                'complete round projection')
        for claim_ordinal, claim in enumerate(row['claims'], 1):
            require(claim['id'] == claims[claim_ordinal - 1], 'encoded claim order')
            raw.extend(_claim_wire(claim_ordinal, claim))
        require(type(row['context']) is bool and type(row['adjudication']) is bool,
                'encoded external context type')
        raw.extend(_frame(4, held + bytes([row['context'], row['adjudication']])))
        for answer_ordinal, answer in enumerate(row['answers'], 1):
            require(answer['blocker'] in BLOCKERS, 'encoded external blocker')
            raw.extend(_frame(5, struct.pack('>H', answer_ordinal) + candidate
                + bytes.fromhex(hash_checked(answer['actual']))
                + bytes.fromhex(hash_checked(answer['receipt'])) + bytes([BLOCKERS.index(answer['blocker'])])))
        raw.extend(_frame(7, b''))
        require(len(raw) <= 1048571, 'complete transcript byte bound')
    raw.extend(_frame(8, b''))
    return bytes(raw)


def encode_projection(projection):
    """Bounded byte primitive; it establishes no public source provenance."""
    try:
        snapshot = parse(canonical(projection))
        _closed(snapshot, ('hashes', 'source_bytes', 'reading_bytes', 'region', 'claim_ids',
                            'probe_ids', 'questions', 'rounds'))
        return _encode_projection(snapshot)
    except (MemoryError, KeyError, TypeError, IndexError, UnicodeError, struct.error) as error:
        raise SentinelError('NATIVE_PROJECTION_REFUSED:' + type(error).__name__) from error


def _prepare_request(request_raw, request_sha256, registry, registry_sha256, archive, share,
                    locator_registry, locator_registry_sha256, revision_registry,
                    revision_registry_sha256, document_native=None):
    snapshot = registry_snapshot(registry, registry_sha256)
    request, gate = _request(request_raw, request_sha256, snapshot, registry_sha256,
                            locator_registry_sha256, revision_registry_sha256)
    evaluator = _qualification_evidence(gate, snapshot)
    history = _history(request['history_sha256'], gate, snapshot, registry_sha256)
    resolution = _resolution(request, gate, snapshot, archive, share, locator_registry,
        locator_registry_sha256, revision_registry, revision_registry_sha256, document_native)
    gate = dict(gate, _history_sha256=request['history_sha256'])
    projection = _projection(history, gate, snapshot, registry_sha256, resolution, evaluator)
    wire = encode_projection(projection)
    return wire, {'schema': 'sentinel/native-preparation/1', 'status': 'PREPARED_UNQUALIFIED',
        'request_sha256': request_sha256, 'gate_sha256': request['gate_admission_sha256'],
        'history_sha256': request['history_sha256'], 'registry_sha256': registry_sha256,
        'source_evidence': {key: resolution[key] for key in ('source', 'representation', 'package_id')},
        'wire_pin': identity(wire), 'native_binary_pin': gate['native_binary_pin'],
        'evaluator_sha256': evaluator, 'projection': projection, 'execution_authority': 'NONE'}


def prepare_request(request_raw, request_sha256, registry, registry_sha256, archive, share,
                    locator_registry, locator_registry_sha256, revision_registry,
                    revision_registry_sha256, document_native=None):
    try:
        return _prepare_request(request_raw, request_sha256, registry, registry_sha256, archive,
            share, locator_registry, locator_registry_sha256, revision_registry,
            revision_registry_sha256, document_native)
    except (MemoryError, OSError, KeyError, TypeError, IndexError, UnicodeError, struct.error) as error:
        raise SentinelError('NATIVE_PREPARATION_REFUSED:' + type(error).__name__) from error


def _parse_response(raw, stderr, code, projection):
    require(type(raw) is bytes and len(raw) == 2725 and raw[:5] == b'STR1\x01', 'exact STR1 response')
    require(stderr == b'', 'native stderr refused')
    disposition, reason = raw[5], int.from_bytes(raw[6:8], 'big')
    require(disposition in (0, 1, 2) and type(code) is int and code == (3, 2, 0)[disposition],
            'native exit/disposition mismatch')
    require(raw[353] == 0 and raw[354] in (0, 1) and raw[356] == 1, 'native authority/scope/session')
    require(raw[8:312] == _identity_wire(projection), 'native identity echo mismatch')
    rounds, claims, probes = projection['rounds'], projection['claim_ids'], projection['probe_ids']
    _labels(claims, CLAIMS)
    _labels(probes, PROBES)
    require(type(rounds) is list and 1 <= len(rounds) <= ROUNDS, 'native output round bound')
    require(raw[312:344] == bytes.fromhex(rounds[-1]['candidate']) and raw[344] == len(rounds),
            'native candidate/round mismatch')
    counts = struct.unpack('>HHHH', raw[345:353])
    require(counts[:3] == (len(claims), len(probes), len(probes)) and counts[3] <= 2048,
            'native roster/count mismatch')
    documentary = bytes(DOCUMENTARY.index(claim['documentary']) for claim in rounds[-1]['claims'])
    require(raw[357:421] == documentary + bytes([3]) * (64 - len(claims)), 'native documentary mismatch')
    require(all(value <= 2 for value in raw[677:]) and raw[355] in range(7), 'closed native result/state')
    if disposition == 2:
        require(reason == 0 and raw[354:357] == bytes([1, 3, 1]), 'native qualification shape')
        status = 'NATIVE_QUALIFIED_FOR_FINITE_Q'
    elif disposition == 1:
        require(reason in (1, 2, 3) and raw[354] == 0, 'native nonqualification shape')
        status = 'NATIVE_NOT_QUALIFIED'
    else:
        require(reason in range(10, 24) and raw[354] == 0, 'native refusal shape')
        status = 'NATIVE_REFUSED'
    _response_history(raw, projection)
    return {'status': status, 'reason_code': reason, 'output_pin': identity(raw),
        'scope': 'FINITE_HELD_Q_ONLY' if disposition == 2 else 'NONE',
        'failure_mask_hex': raw[421:677].hex(), 'result_matrix_hex': raw[677:].hex(),
        'informational_failure_count': counts[3], 'execution_authority': 'NONE',
        'semantic_completeness': 'UNPROVEN', 'OCR_accuracy': 'UNPROVEN', 'world_truth': 'UNPROVEN',
        'context_adequacy': 'UNPROVEN', 'reference_authentication': 'UNPROVEN'}


def parse_response(raw, stderr, code, projection):
    try:
        snapshot = parse(canonical(projection))
        _closed(snapshot, ('hashes', 'source_bytes', 'reading_bytes', 'region', 'claim_ids',
                            'probe_ids', 'questions', 'rounds'))
        return _parse_response(raw, stderr, code, snapshot)
    except (MemoryError, KeyError, TypeError, IndexError, UnicodeError, struct.error) as error:
        raise SentinelError('NATIVE_RESPONSE_REFUSED:' + type(error).__name__) from error


def _response_history(raw, projection):
    expected_matrix, events = bytearray(2048), []
    probes = projection['probe_ids']
    require(type(projection['questions']['rows']) is list
            and len(projection['questions']['rows']) == len(probes), 'response complete Q roster')
    for round_index, row in enumerate(projection['rounds']):
        require(type(row['answers']) is list and len(row['answers']) == len(probes)
                and type(row['claims']) is list and len(row['claims']) == len(projection['claim_ids']),
                'response complete round roster')
        for index, answer in enumerate(row['answers']):
            expected = projection['questions']['rows'][index]['expected_answer_sha256']
            expected_matrix[round_index * 256 + index] = 1 if answer['actual'] == expected else 2
            if answer['actual'] != expected or answer['blocker'] != 'NO_BLOCKER':
                events.append({'round': round_index + 1, 'probe_id': projection['probe_ids'][index]})
    require(raw[677:] == bytes(expected_matrix) and raw[421:677] == _mask(events, projection['probe_ids']),
            'native historical result/mask detached from submitted artifacts')
    require(int.from_bytes(raw[351:353], 'big') == sum(value.bit_count() for value in raw[421:677]),
            'native informational count inconsistent with retained mask')


def _request_qualification(request_raw, request_sha256, registry, registry_sha256, archive, share,
        locator_registry, locator_registry_sha256, revision_registry, revision_registry_sha256,
        policy_native, policy_native_sha256, job_root, document_native=None):
    from . import native_runtime
    from .jobs import job_slot
    deadline = time.monotonic() + 450
    try:
        with job_slot(Path(job_root)):
            wire, prepared = prepare_request(request_raw, request_sha256, registry, registry_sha256,
                archive, share, locator_registry, locator_registry_sha256, revision_registry,
                revision_registry_sha256, document_native)
            require(prepared['native_binary_pin']['sha256'] == hash_checked(policy_native_sha256),
                    'explicit external wire binary differs from held admission')
            runtime = native_runtime._run(wire, policy_native, prepared['native_binary_pin'],
                                         job_root, evaluator_sources(), deadline)
    except (MemoryError, OSError, KeyError, TypeError, IndexError, UnicodeError, struct.error) as error:
        raise SentinelError('NATIVE_REQUEST_REFUSED:' + type(error).__name__) from error
    result = parse_response(runtime['stdout'], runtime['stderr'], runtime['returncode'], prepared['projection'])
    result.update({'schema': 'sentinel/native-qualification/1', 'request_sha256': request_sha256,
        'gate_sha256': prepared['gate_sha256'], 'history_sha256': prepared['history_sha256'],
        'registry_sha256': registry_sha256, 'source_evidence': prepared['source_evidence'],
        'input_pin': identity(wire), 'native_binary_pin': prepared['native_binary_pin'],
        'evaluator_sha256': prepared['evaluator_sha256'], 'runtime_receipt_pin': runtime['receipt_pin']})
    require(time.monotonic() <= deadline, 'global completion deadline')
    return canonical(result)


def request_qualification(request_raw, request_sha256, registry, registry_sha256, archive, share,
        locator_registry, locator_registry_sha256, revision_registry, revision_registry_sha256,
        policy_native, policy_native_sha256, job_root, document_native=None):
    try:
        return _request_qualification(request_raw, request_sha256, registry, registry_sha256,
            archive, share, locator_registry, locator_registry_sha256, revision_registry,
            revision_registry_sha256, policy_native, policy_native_sha256, job_root, document_native)
    except (MemoryError, OSError, KeyError, TypeError, IndexError, UnicodeError, struct.error) as error:
        raise SentinelError('NATIVE_REQUEST_REFUSED:' + type(error).__name__) from error
