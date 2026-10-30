"""Closed exact-byte SENTINEL evidence profile; no truth or qualification gate."""
import re
import sys

from transport_document_io import (DocumentError, canonical, digest, fields, integer, loads,
                                   loaded_epoch, need, sha)

PROFILE = 'sentinel/sidecar-exact/1'
CAP = 65_536
REGISTRY_CAP = 256
REGISTRY_BYTES = 8_388_608
IDENTIFIER = re.compile(r'[A-Z][A-Z0-9_]{0,47}\Z')
PIN = {'id': 'ID', 'sha256': 'SHA', 'bytes': 'SIZE'}


def array(item, low, high):
    return ('array', item, low, high)


def nullable(item):
    return ('nullable', item)


def choice(*values):
    return ('choice', values)


LOCATOR = dict(source_pin='Pin', representation_pin='Pin', unit_id='ID',
               kind=choice('SOURCE_BYTES'), selector_pin='Pin', quote_pin='Pin')
SHAPES = {
    'Pin': PIN, 'Locator': LOCATOR,
    'Claim': dict(id='ID', claim_text_pin='Pin', evidence=array('Locator', 1, 16),
                  required_context=array('Pin', 0, 16),
                  interpretation=choice('OPAQUE_PROPOSED'), formal_payload_pin='NULL',
                  interpretation_entailment=choice('UNPROVEN')),
    'Candidate': dict(id='ID', revision='REV', predecessor_pin=nullable('Pin'),
                      source_set_pin='Pin', q_set_pin='Pin', claims=array('Claim', 1, 8),
                      dependency_graph_pin='Pin', unknown_regions_pin='Pin',
                      change_reason_pin=nullable('Pin')),
    'Probe': dict(id='ID', claim_id='ID', question_pin='Pin', scenario_pin='Pin',
                  source_evidence=array('Locator', 1, 16), oracle_pin='Pin',
                  relation=choice('EXACT_ANSWER_DIGEST'), checker_pin='Pin',
                  materiality_pin='Pin'),
    'Oracle': dict(id='ID', question_pin='Pin', source_set_pin='Pin', answer_pin='Pin',
                   adjudication_pin='Pin', provenance_pin='Pin', trust_policy_pin='Pin',
                   kind=choice('MANUAL_DEVELOPMENT_FIXTURE', 'INDEPENDENT_REFERENCE',
                               'QUALIFIED_CLOSED_FRAGMENT')),
    'Result': dict(id='ID', candidate_pin='Pin', probe_pin='Pin', oracle_pin='Pin',
                   answer_pin='Pin', input_manifest_pin='Pin', evaluator_pin='Pin',
                   run_evidence_pin='Pin', comparison_receipt_pin='Pin',
                   status=choice('MATCH', 'MISMATCH', 'UNRUN', 'REFUSED')),
    'Counterexample': dict(id='ID', candidate_pin='Pin', probe_result_pin='Pin',
                           source_evidence=array('Locator', 1, 16), expected_pin='Pin',
                           actual_pin='Pin', status=choice('ALLEGED',
                               'CONFIRMED_RELATIVE_TO_ORACLE', 'DISPUTED'),
                           resolution_event_pins=array('Pin', 0, 0)),
    'History': dict(sequence='SEQ', previous_pin=nullable('Pin'),
                    kind=choice('CANDIDATE', 'RESULT', 'COUNTEREXAMPLE', 'REFINEMENT',
                                'DISPUTE', 'REPAIR_LINK', 'ORACLE_WITHDRAWAL_NOTICE',
                                'QUALIFICATION_REQUEST'), record_pin='Pin', evidence_pin='Pin'),
    'Ledger': dict(claim_id='ID', support_pins=array('Pin', 0, 16),
                   refutation_pins=array('Pin', 0, 16),
                   state=choice('SUPPORTED_ONLY', 'REFUTED_ONLY', 'BOTH', 'NEITHER'),
                   meaning=choice('DOCUMENTARY_EVIDENCE_NOT_TRUTH')),
    'Qualification': dict(candidate_pin='Pin', q_set_pin='Pin', oracle_set_pin='Pin',
                          source_set_pin='Pin', policy_pin='Pin', results_pin='Pin',
                          failure_history_pin='Pin', kernel_pin=nullable('Pin'),
                          kernel_qualification_pin=nullable('Pin'), native_decision_pin='NULL',
                          status=choice('NOT_QUALIFIED'), ceiling=choice('DEVELOPMENT_FIXTURE_ONLY',
                              'EXTERNALLY_ADJUDICATED_Q_ONLY'), semantic_completeness=choice('UNPROVEN'),
                          world_truth=choice('NOT_CERTIFIED'), execution_authority=choice('NONE')),
    'Sidecar': dict(schema=choice(PROFILE), design_source_pin='Pin', source_set_pin='Pin',
                    q_set_pin='Pin', oracle_set_pin='Pin', policy_pin='Pin',
                    previous_sidecar_pin=nullable('Pin'),
                    candidates=array('Candidate', 1, 8), probes=array('Probe', 1, 16),
                    oracles=array('Oracle', 1, 16), results=array('Result', 1, 128),
                    counterexamples=array('Counterexample', 0, 128),
                    history=array('History', 1, 256), ledger=array('Ledger', 1, 8),
                    qualification='Qualification')}


def identifier(value):
    need(type(value) is str and IDENTIFIER.fullmatch(value) is not None, 'SENTINEL ID')


def registry_snapshot(artifacts):
    need(type(artifacts) is dict, 'registry exact dict required')
    snapshot, size = {}, 0
    try:
        entries = iter(artifacts.items())
        for index in range(REGISTRY_CAP + 1):
            pair = next(entries, None)
            if pair is None:
                need(bool(snapshot), 'registry count')
                return snapshot
            need(index < REGISTRY_CAP, 'registry count')
            name, data = pair
            identifier(name)
            need(type(data) is bytes and len(data) <= CAP, 'artifact byte bound')
            size += len(data)
            need(size <= REGISTRY_BYTES, 'aggregate registry byte bound')
            snapshot[name] = data
    except RuntimeError as error:
        raise DocumentError('registry mutated during snapshot') from error
    need(False, 'registry snapshot work bound')


def registry_manifest(artifacts):
    snapshot = registry_snapshot(artifacts)
    rows = [{'id': name, 'sha256': digest(data), 'bytes': len(data)}
            for name, data in snapshot.items()]
    return canonical(sorted(rows, key=lambda row: row['id']))


def registry_context(artifacts, expected):
    sha(expected)
    snapshot = registry_snapshot(artifacts)
    need(digest(registry_manifest(snapshot)) == expected, 'registry manifest pin mismatch')
    return {'artifacts': snapshot, 'used': set(), 'parsed': {}}


def resolve(pin, context):
    fields(pin, PIN)
    identifier(pin['id'])
    sha(pin['sha256'])
    integer(pin['bytes'], 0, CAP)
    name = pin['id']
    need(name in context['artifacts'], 'unresolved PinID')
    data = context['artifacts'][name]
    need(len(data) == pin['bytes'] and digest(data) == pin['sha256'], 'artifact pin mismatch')
    context['used'].add(name)
    return data


def structured(pin, context):
    data = resolve(pin, context)
    name = pin['id']
    if name not in context['parsed']:
        context['parsed'][name] = canonical_input(data)
    return context['parsed'][name]


def canonical_input(raw):
    need(type(raw) is bytes and len(raw) <= CAP, 'SENTINEL payload bound')
    value = loads(raw)
    need(canonical(value) == raw, 'SENTINEL noncanonical JSON')
    return value


def check_primitive(value, kind):
    if kind == 'ID':
        identifier(value)
    elif kind == 'SHA':
        sha(value)
    elif kind in ('SIZE', 'REV', 'SEQ'):
        integer(value, 0, {'SIZE': CAP, 'REV': 7, 'SEQ': 255}[kind])
    else:
        need(kind == 'NULL' and value is None, 'SENTINEL null field')


def check_shape(value, kind, context):
    pending = [(value, kind)]
    for _ in range(16_384):
        if not pending:
            return
        item, spec = pending.pop()
        if type(spec) is tuple:
            check_container(item, spec, pending)
        elif spec in SHAPES:
            shape = SHAPES[spec]
            fields(item, shape)
            if spec == 'Pin':
                resolve(item, context)
            pending.extend((item[key], child) for key, child in shape.items())
        else:
            check_primitive(item, spec)
        need(len(pending) <= 16_384, 'SENTINEL shape work bound')
    need(not pending, 'SENTINEL shape work exhausted')


def check_container(value, spec, pending):
    if spec[0] == 'choice':
        need(type(value) is str and value in spec[1], 'unsupported SENTINEL value')
    elif spec[0] == 'nullable':
        if value is not None:
            pending.append((value, spec[1]))
    else:
        need(spec[0] == 'array' and type(value) is list, 'SENTINEL array')
        need(spec[2] <= len(value) <= spec[3], 'SENTINEL array count')
        pending.extend((child, spec[1]) for child in value)


def record_index(rows):
    result = {}
    for row in rows:
        name = row['id']
        need(name not in result, 'duplicate record ID')
        result[name] = row
    return result


def target(pin, rows, context):
    need(pin['id'] in rows, 'wrong-kind or missing record reference')
    row = rows[pin['id']]
    need(resolve(pin, context) == canonical(row), 'record identity mismatch')
    return row


def equals_artifact(pin, value, context):
    need(resolve(pin, context) == canonical(value), 'structured artifact mismatch')


def source_locator(locator, sources, context):
    source = locator['source_pin']
    need(source in sources, 'locator outside fixed source set')
    need(locator['representation_pin'] == source, 'unsupported representation relation')
    selector = structured(locator['selector_pin'], context)
    fields(selector, ('start', 'end'))
    data = resolve(source, context)
    integer(selector['start'], 0, len(data))
    integer(selector['end'], selector['start'] + 1, len(data))
    need(resolve(locator['quote_pin'], context) == data[selector['start']:selector['end']],
         'source quote mismatch')


def check_sources(document, context):
    sources = structured(document['source_set_pin'], context)
    check_shape(sources, array('Pin', 1, 8), context)
    need(len({row['id'] for row in sources}) == len(sources), 'duplicate source ID')
    for candidate in document['candidates']:
        for claim in candidate['claims']:
            for locator in claim['evidence']:
                source_locator(locator, sources, context)
        unknown = structured(candidate['unknown_regions_pin'], context)
        check_shape(unknown, array('Locator', 0, 64), context)
        for locator in unknown:
            source_locator(locator, sources, context)
    for collection in ('probes', 'counterexamples'):
        key = 'source_evidence'
        for row in document[collection]:
            for locator in row[key]:
                source_locator(locator, sources, context)


def dependency_graph(candidate, context):
    graph = structured(candidate['dependency_graph_pin'], context)
    fields(graph, ('nodes', 'edges'))
    check_shape(graph['nodes'], array('ID', 1, 32), context)
    need(type(graph['edges']) is list and len(graph['edges']) <= 64, 'graph edge count')
    nodes = graph['nodes']
    need(len(nodes) == len(set(nodes)) and set(nodes) ==
         {row['id'] for row in candidate['claims']}, 'graph claim nodes')
    edges = set()
    for edge in graph['edges']:
        check_shape(edge, array('ID', 2, 2), context)
        need(edge[0] in nodes and edge[1] in nodes and tuple(edge) not in edges,
             'graph dangling or duplicate edge')
        edges.add(tuple(edge))
    remaining = set(nodes)
    for _ in range(32):
        roots = {node for node in remaining if not any(
            right == node and left in remaining for left, right in edges)}
        remaining.difference_update(roots)
    need(not remaining, 'dependency cycle')


def check_candidates(document, context):
    fixed_claims = None
    previous = None
    for index, candidate in enumerate(document['candidates']):
        need(candidate['revision'] == index, 'candidate revision sequence')
        for key in ('source_set_pin', 'q_set_pin'):
            need(candidate[key] == document[key], 'candidate epoch changed')
        claims = record_index(candidate['claims'])
        if fixed_claims is None:
            fixed_claims = set(claims)
            need(candidate['predecessor_pin'] is None and candidate['change_reason_pin'] is None,
                 'candidate genesis')
        else:
            need(set(claims) == fixed_claims, 'candidate claim IDs changed')
            need(candidate['predecessor_pin'] is not None and
                 candidate['change_reason_pin'] is not None, 'candidate predecessor/reason')
            need(candidate['predecessor_pin']['id'] == previous['id'], 'predecessor record ID')
            equals_artifact(candidate['predecessor_pin'], previous, context)
        dependency_graph(candidate, context)
        previous = candidate
    return fixed_claims


def check_questions(document, context, claims):
    probes, oracles = record_index(document['probes']), record_index(document['oracles'])
    equals_artifact(document['q_set_pin'], document['probes'], context)
    equals_artifact(document['oracle_set_pin'], document['oracles'], context)
    used_oracles = set()
    for probe in probes.values():
        need(probe['claim_id'] in claims, 'probe claim reference')
        oracle = target(probe['oracle_pin'], oracles, context)
        need(oracle['question_pin'] == probe['question_pin'] and
             oracle['source_set_pin'] == document['source_set_pin'], 'oracle epoch mismatch')
        used_oracles.add(oracle['id'])
    need(used_oracles == set(oracles), 'unused oracle')
    return probes, oracles


def check_results(document, context, candidates, probes, oracles):
    pairs, failures = {}, {}
    for row in document['results']:
        candidate = target(row['candidate_pin'], candidates, context)
        probe = target(row['probe_pin'], probes, context)
        oracle = target(row['oracle_pin'], oracles, context)
        need(row['oracle_pin'] == probe['oracle_pin'], 'result oracle mismatch')
        pair = (candidate['id'], probe['id'])
        need(pair not in pairs, 'duplicate candidate/probe result')
        actual = resolve(row['answer_pin'], context)
        expected = resolve(oracle['answer_pin'], context)
        derived = 'MATCH' if actual == expected else 'MISMATCH'
        need(row['status'] in ('UNRUN', 'REFUSED', derived), 'imported comparison mismatch')
        pairs[pair] = row
        if row['status'] != 'MATCH':
            failures[row['id']] = row
    need(len(pairs) == len(candidates) * len(probes), 'incomplete result matrix')
    return failures


def check_counterexamples(document, context, candidates, results, oracles):
    failures = {row['id']: row for row in document['results'] if row['status'] != 'MATCH'}
    covered = set()
    for row in document['counterexamples']:
        result = target(row['probe_result_pin'], results, context)
        target(row['candidate_pin'], candidates, context)
        need(result['id'] in failures and row['candidate_pin'] == result['candidate_pin'],
             'counterexample failing candidate/result')
        oracle = target(result['oracle_pin'], oracles, context)
        need(row['expected_pin'] == oracle['answer_pin'] and
             row['actual_pin'] == result['answer_pin'], 'counterexample answer identity')
        if row['status'] == 'CONFIRMED_RELATIVE_TO_ORACLE':
            need(result['status'] == 'MISMATCH', 'counterexample confirmation unsupported')
        covered.add(result['id'])
    need(covered == set(failures), 'failure history omission')


def check_ledger(document, claims):
    rows = document['ledger']
    need(len(rows) == len(claims) and {row['claim_id'] for row in rows} == claims,
         'ledger claim coverage')
    for row in rows:
        support, refute = bool(row['support_pins']), bool(row['refutation_pins'])
        derived = ('BOTH' if refute else 'SUPPORTED_ONLY') if support else (
            'REFUTED_ONLY' if refute else 'NEITHER')
        need(row['state'] == derived, 'imported documentary state mismatch')
        for key in ('support_pins', 'refutation_pins'):
            ids = [pin['id'] for pin in row[key]]
            need(len(ids) == len(set(ids)), 'duplicate ledger evidence')


def annotation(row, indexes, context):
    value = structured(row['record_pin'], context)
    kind = row['kind']
    if kind == 'ORACLE_WITHDRAWAL_NOTICE':
        fields(value, ('oracle_pin', 'reason_pin'))
        check_shape(value['reason_pin'], 'Pin', context)
        check_shape(value['oracle_pin'], 'Pin', context)
        target(value['oracle_pin'], indexes['ORACLE'], context)
        return None
    names = ('candidate_pin',) if kind == 'QUALIFICATION_REQUEST' else (
        'candidate_pin', 'counterexample_pin')
    fields(value, names)
    check_shape(value['candidate_pin'], 'Pin', context)
    candidate = target(value['candidate_pin'], indexes['CANDIDATE'], context)
    if kind == 'QUALIFICATION_REQUEST':
        return None
    check_shape(value['counterexample_pin'], 'Pin', context)
    failure = target(value['counterexample_pin'], indexes['COUNTEREXAMPLE'], context)
    failed_candidate = target(failure['candidate_pin'], indexes['CANDIDATE'], context)
    if kind in ('REFINEMENT', 'REPAIR_LINK'):
        need(candidate['revision'] > failed_candidate['revision'], 'repair candidate ordering')
        return candidate['id'], failure['id']
    return None


def check_history(document, context, indexes):
    seen = {name: set() for name in ('CANDIDATE', 'RESULT', 'COUNTEREXAMPLE')}
    repairs, previous, positions = set(), None, {}
    for index, row in enumerate(document['history']):
        need(row['sequence'] == index, 'history sequence gap')
        if index == 0:
            need(row['previous_pin'] is None, 'history genesis')
        else:
            need(row['previous_pin'] is not None, 'history predecessor missing')
            equals_artifact(row['previous_pin'], previous, context)
        kind = row['kind']
        if kind in seen:
            value = target(row['record_pin'], indexes[kind], context)
            need(value['id'] not in seen[kind], 'duplicate history record')
            seen[kind].add(value['id'])
            positions[(kind, value['id'])] = index
        else:
            repair = annotation(row, indexes, context)
            check_annotation_order(row, context, seen)
            if repair is not None:
                repairs.add(repair)
        previous = row
    for kind in seen:
        need(seen[kind] == set(indexes[kind]), 'missing history record')
    check_history_order(document, indexes, positions, repairs)
    return repairs


def check_annotation_order(row, context, seen):
    value = structured(row['record_pin'], context)
    if 'candidate_pin' in value:
        need(value['candidate_pin']['id'] in seen['CANDIDATE'], 'annotation before candidate')
    if 'counterexample_pin' in value:
        need(value['counterexample_pin']['id'] in seen['COUNTEREXAMPLE'],
             'annotation before counterexample')


def check_history_order(document, indexes, positions, repairs):
    for result in document['results']:
        need(positions[('CANDIDATE', result['candidate_pin']['id'])] <
             positions[('RESULT', result['id'])], 'result before candidate')
    for failure in document['counterexamples']:
        need(positions[('RESULT', failure['probe_result_pin']['id'])] <
             positions[('COUNTEREXAMPLE', failure['id'])], 'counterexample before result')
    for candidate in document['candidates'][1:]:
        for failure in document['counterexamples']:
            old = indexes['CANDIDATE'][failure['candidate_pin']['id']]
            if old['revision'] < candidate['revision']:
                need((candidate['id'], failure['id']) in repairs, 'missing prior failure repair link')
                need(positions[('COUNTEREXAMPLE', failure['id'])] <
                     positions[('CANDIDATE', candidate['id'])], 'revision before prior failure')


def check_resolution_events(document, context):
    annotations = {row['record_pin']['id']: row for row in document['history']
                   if row['kind'] in ('DISPUTE', 'REFINEMENT', 'REPAIR_LINK')}
    for failure in document['counterexamples']:
        for pin in failure['resolution_event_pins']:
            need(pin['id'] in annotations, 'unrecorded resolution event')
            event = annotations[pin['id']]
            need(pin == event['record_pin'], 'resolution event pin mismatch')
            payload = structured(pin, context)
            need(payload['counterexample_pin']['id'] == failure['id'],
                 'resolution event wrong counterexample')


def check_qualification(document, context):
    row = document['qualification']
    for key in ('q_set_pin', 'oracle_set_pin', 'source_set_pin', 'policy_pin'):
        need(row[key] == document[key], 'qualification epoch mismatch')
    need(row['candidate_pin']['id'] == document['candidates'][-1]['id'], 'current candidate ID')
    equals_artifact(row['candidate_pin'], document['candidates'][-1], context)
    equals_artifact(row['results_pin'], document['results'], context)
    equals_artifact(row['failure_history_pin'], document['history'], context)


def check_epoch(document, context):
    check_shape(document, 'Sidecar', context)
    candidates = record_index(document['candidates'])
    results = record_index(document['results'])
    counterexamples = record_index(document['counterexamples'])
    claims = check_candidates(document, context)
    check_sources(document, context)
    probes, oracles = check_questions(document, context, claims)
    all_ids = list(candidates) + list(probes) + list(oracles) + list(results) + list(counterexamples)
    need(len(set(all_ids)) == len(all_ids), 'record IDs collide across kinds')
    check_results(document, context, candidates, probes, oracles)
    check_counterexamples(document, context, candidates, results, oracles)
    check_ledger(document, claims)
    indexes = {'CANDIDATE': candidates, 'RESULT': results,
               'COUNTEREXAMPLE': counterexamples, 'ORACLE': oracles}
    repairs = check_history(document, context, indexes)
    check_resolution_events(document, context)
    check_qualification(document, context)
    return repairs


def check_prefix(previous, current):
    for key in ('schema', 'design_source_pin', 'source_set_pin', 'q_set_pin',
                'oracle_set_pin', 'policy_pin', 'probes', 'oracles'):
        need(previous[key] == current[key], 'previous fixed epoch changed')
    for key in ('candidates', 'results', 'counterexamples', 'history'):
        old, new = previous[key], current[key]
        need(len(old) <= len(new) and new[:len(old)] == old, 'previous history rewritten')
    need(len(previous['candidates']) < len(current['candidates']) and
         len(previous['history']) < len(current['history']), 'snapshot chain does not progress')


def check_previous(previous_raw, expected_previous_sha256, current, context):
    first = current['previous_sidecar_pin']
    if first is None:
        need(previous_raw is None and expected_previous_sha256 is None,
             'genesis cannot ignore supplied previous evidence')
        return
    need(type(previous_raw) is bytes and len(previous_raw) <= CAP, 'previous payload required')
    sha(expected_previous_sha256)
    need(first['sha256'] == expected_previous_sha256 and
         digest(previous_raw) == expected_previous_sha256 and
         resolve(first, context) == previous_raw, 'previous sidecar pin mismatch')
    seen = {digest(canonical(current))}
    for _ in range(7):
        pin = current['previous_sidecar_pin']
        need(pin['sha256'] not in seen, 'snapshot cycle')
        seen.add(pin['sha256'])
        previous = structured(pin, context)
        check_epoch(previous, context)
        check_prefix(previous, current)
        if previous['previous_sidecar_pin'] is None:
            return
        current = previous
    need(False, 'snapshot depth bound')


def checked_sidecar(raw, artifacts, expected_sha256, expected_registry_sha256,
                    previous_raw=None, expected_previous_sha256=None):
    sha(expected_sha256)
    document = canonical_input(raw)
    need(digest(raw) == expected_sha256, 'sidecar pin mismatch')
    context = registry_context(artifacts, expected_registry_sha256)
    repairs = check_epoch(document, context)
    check_previous(previous_raw, expected_previous_sha256, document, context)
    need(context['used'] == set(context['artifacts']), 'unreachable current registry artifact')
    return document, context, repairs


def validate_sidecar(raw, artifacts, expected_sha256, expected_registry_sha256,
                     previous_raw=None, expected_previous_sha256=None):
    document, _, repairs = checked_sidecar(raw, artifacts, expected_sha256,
        expected_registry_sha256, previous_raw, expected_previous_sha256)
    result = {'schema': 'sentinel/structural-report/1', 'sidecar_sha256': digest(raw),
              'registry_sha256': expected_registry_sha256, 'status': 'STRUCTURE_AND_EXACT_BYTES_ONLY',
              'candidates': len(document['candidates']), 'probes': len(document['probes']),
              'retained_results': len(document['results']),
              'retained_failures': sum(row['status'] != 'MATCH' for row in document['results']),
              'repair_links': len(repairs), 'qualification': 'NOT_QUALIFIED',
              'semantic_completeness': 'UNPROVEN', 'world_truth': 'NOT_CERTIFIED',
              'execution_authority': 'NONE'}
    need(len(canonical(result)) <= CAP, 'SENTINEL report bound')
    return result


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
