"""Source-bound challenge planning and exact-reference replay, never qualification.

The generator cannot admit its oracle. A separately held admission binds exact
oracle and checker bytes. Independence and source entailment remain external
review obligations; a reference match is not truth or universal equivalence.
"""
from .common import (JOB_BYTES, PROBES, canonical, digest, fields, hash_checked, held_record,
                     identity, integer, label, parse, pin_checked, registry_snapshot,
                     require)
import sys
from transport_document_io import loaded_epoch

PROFILE = 'sentinel/challenge-set/1'


def artifact(pin, registry):
    pin_checked(pin)
    require(pin['sha256'] in registry, 'challenge dependency missing')
    raw = registry[pin['sha256']]
    require(identity(raw) == pin, 'challenge dependency pin mismatch')
    return raw


def mutate(before, start, end, replacement, category):
    require(type(before) is bytes and len(before) <= JOB_BYTES, 'mutation source bound')
    require(type(replacement) is bytes and len(replacement) <= JOB_BYTES, 'replacement bound')
    integer(start, 0, len(before))
    integer(end, start, len(before))
    require(category in ('PRESERVING_PROPOSED', 'CHANGING_PROPOSED'), 'mutation class')
    require(len(before) - (end - start) + len(replacement) <= JOB_BYTES, 'mutation result bound')
    after = before[:start] + replacement + before[end:]
    return after, {'class': category, 'before_pin': identity(before),
        'after_pin': identity(after), 'replacement_pin': identity(replacement),
        'span': [start, end], 'oracle_status': 'UNRESOLVED'}


def transformation(record, registry):
    fields(record, ('class', 'before_pin', 'after_pin', 'replacement_pin', 'span', 'oracle_status'))
    require(record['oracle_status'] == 'UNRESOLVED', 'generator cannot certify equivalence')
    require(type(record['span']) is list and len(record['span']) == 2, 'mutation span')
    before = artifact(record['before_pin'], registry)
    replacement = artifact(record['replacement_pin'], registry)
    after, expected = mutate(before, *record['span'], replacement, record['class'])
    require(expected == record and artifact(record['after_pin'], registry) == after,
            'mutation replay mismatch')
    return after


def admission_checked(raw, held, graph, source_set):
    value = held_record(raw, held)
    fields(value, ('schema', 'graph_sha256', 'source_set_sha256', 'checker_sha256', 'oracles'))
    require(value['schema'] == 'sentinel/challenge-admission/1', 'admission version')
    require(value['graph_sha256'] == graph and value['source_set_sha256'] == source_set,
            'admission source or interpretation mismatch')
    hash_checked(value['checker_sha256'])
    require(type(value['oracles']) is dict and len(value['oracles']) <= PROBES, 'oracle admission bound')
    for key, pin in value['oracles'].items():
        label(key)
        hash_checked(pin)
    return value


def oracle_checked(probe, registry, admission, source_set):
    pin = probe['oracle_pin']
    if pin is None:
        require(probe['id'] not in admission['oracles'], 'admitted oracle omitted')
        return None
    raw = artifact(pin, registry)
    require(admission['oracles'].get(probe['id']) == digest(raw), 'oracle not independently held')
    value = parse(raw)
    fields(value, ('schema', 'probe_id', 'input_sha256', 'source_set_sha256', 'answer_pin',
                   'relation', 'adjudication_pin', 'provenance_pin'))
    require(value['schema'] == 'sentinel/challenge-oracle/1' and value['probe_id'] == probe['id'],
            'oracle version or target')
    require(value['input_sha256'] == probe['input_pin']['sha256']
            and value['source_set_sha256'] == source_set, 'oracle input or source mismatch')
    wanted = {'PRESERVING_PROPOSED': 'EQUIVALENT', 'CHANGING_PROPOSED': 'MATERIAL_DIFFERENCE'}
    require(value['relation'] == wanted[probe['transformation']['class']], 'oracle relation mismatch')
    for key in ('answer_pin', 'adjudication_pin', 'provenance_pin'):
        artifact(value[key], registry)
    return value


def checked_set(raw, held, registry, registry_root, admission_raw, admission_held):
    value = held_record(raw, held)
    snapshot = registry_snapshot(registry, registry_root)
    fields(value, ('schema', 'graph_sha256', 'source_set_sha256', 'probes'))
    require(value['schema'] == PROFILE, 'challenge set version')
    hash_checked(value['graph_sha256'])
    hash_checked(value['source_set_sha256'])
    require(value['graph_sha256'] in snapshot and value['source_set_sha256'] in snapshot,
            'graph or source-set dependency missing')
    from .bindings import graph_from_registry, target_in_graph
    graph = graph_from_registry(value['graph_sha256'], snapshot)
    require(graph['source_set_sha256'] == value['source_set_sha256']
            and canonical(graph['source_set']) == snapshot[value['source_set_sha256']],
            'challenge source set differs from checked graph')
    admission = admission_checked(admission_raw, admission_held, value['graph_sha256'],
                                  value['source_set_sha256'])
    require(type(value['probes']) is list and 1 <= len(value['probes']) <= PROBES, 'probe count')
    ids, oracles = set(), {}
    for probe in value['probes']:
        fields(probe, ('id', 'claim_id', 'target_locator_sha256', 'input_pin',
                       'transformation', 'oracle_pin', 'checker_sha256'))
        label(probe['id']); label(probe['claim_id'])
        pin_checked(probe['input_pin'])
        hash_checked(probe['target_locator_sha256']); hash_checked(probe['checker_sha256'])
        require(probe['id'] not in ids, 'duplicate challenge ID')
        ids.add(probe['id'])
        locator = parse(artifact({'sha256': probe['target_locator_sha256'],
            'bytes': len(snapshot.get(probe['target_locator_sha256'], b''))}, snapshot))
        require(type(locator) is dict and locator.get('schema') == 'sentinel/evidence-locator/1',
                'challenge locator dependency')
        target_in_graph(graph, probe['claim_id'], locator)
        require(probe['checker_sha256'] == admission['checker_sha256']
                and probe['checker_sha256'] == SOURCE_EPOCH
                and probe['checker_sha256'] in snapshot, 'checker identity mismatch')
        after = transformation(probe['transformation'], snapshot)
        require(identity(after) == probe['input_pin'], 'exact challenge input mismatch')
        oracles[probe['id']] = oracle_checked(probe, snapshot, admission, value['source_set_sha256'])
    require(set(admission['oracles']) <= ids, 'unknown admitted oracle')
    return value, snapshot, oracles


def answer_snapshot(answers):
    require(type(answers) is dict and len(answers) <= PROBES, 'answer count')
    snapshot = {}
    try:
        entries = iter(answers.items())
        for index in range(PROBES + 1):
            pair = next(entries, None)
            if pair is None:
                return snapshot
            require(index < PROBES, 'answer count')
            key, value = pair
            label(key)
            require(type(value) is bytes and len(value) <= JOB_BYTES, 'immutable answer bound')
            snapshot[key] = value
    except RuntimeError as error:
        raise ValueError('answers mutated during snapshot') from error
    raise ValueError('answer count bound')


def replay(raw, held, registry, registry_root, admission_raw, admission_held, answers):
    answers = answer_snapshot(answers)
    value, snapshot, oracles = checked_set(raw, held, registry, registry_root,
                                           admission_raw, admission_held)
    require(set(answers) <= set(oracles), 'unknown submitted answer')
    rows = []
    for probe in value['probes']:
        answer, oracle = answers.get(probe['id']), oracles[probe['id']]
        require(answer is None or type(answer) is bytes and len(answer) <= JOB_BYTES,
                'immutable answer byte bound')
        status = 'UNRUN' if answer is None else 'UNRESOLVED_ORACLE' if oracle is None else (
            'MATCH_REFERENCE' if answer == artifact(oracle['answer_pin'], snapshot) else 'MISMATCH_REFERENCE')
        rows.append({'id': probe['id'], 'claim_id': probe['claim_id'], 'status': status,
                     'answer_pin': None if answer is None else identity(answer),
                     'oracle_pin': probe['oracle_pin']})
    return canonical({'schema': 'sentinel/challenge-replay/1', 'challenge_set_sha256': held,
        'admission_sha256': admission_held, 'results': rows, 'qualification': 'NOT_QUALIFIED',
        'execution_authority': 'NONE', 'semantic_completeness': 'UNPROVEN',
        'scope': 'RECORDED_ANSWER_COMPARISON_TO_HELD_REFERENCE_NOT_MODEL_EXECUTION'})


def selected_bytes(locator, resolution):
    fields(locator, ('schema', 'id', 'source', 'representation', 'selector', 'dependencies', 'revision'))
    require(locator['source'] == resolution['source']
            and locator['representation'] == resolution['representation']
            and locator['revision'] == resolution['revision'], 'resolved coordinate space mismatch')
    selector = locator['selector']
    require(selector['kind'] in ('SOURCE_BYTES', 'DERIVED_UTF8', 'CODE_BYTES', 'PAGE_TEXT'),
            'mutation requires contiguous resolved evidence')
    start, end = selector['start'], selector['end']
    integer(start, 0, 2 ** 31 - 1); integer(end, start + 1, 2 ** 31 - 1)
    for part in resolution['parts']:
        first, last = part['span']
        if first <= start < end <= last:
            raw = part['data'][start - first:end - first]
            require(digest(raw) == selector['quote_sha256'], 'resolved target quote mismatch')
            return raw
    raise ValueError('target absent from resolved evidence closure')


def replay_source_bound(raw, held, registry, registry_root, admission_raw, admission_held,
                         answers, archive, share, locator_raw, locator_held,
                         locator_registry, locator_registry_held, revision_registry,
                         revision_registry_held, native=None):
    """Resolve one complete locator closure through SAST before reference replay."""
    from .locators import resolve_locator
    value, snapshot, _oracles = checked_set(raw, held, registry, registry_root,
                                            admission_raw, admission_held)
    resolution = resolve_locator(archive, share, locator_raw, locator_held, locator_registry,
        locator_registry_held, revision_registry, revision_registry_held, native)
    require(resolution['status'] == 'RESOLVED_BYTES', 'challenge evidence unsupported')
    from .bindings import bind_graph, graph_from_registry
    binding = bind_graph(graph_from_registry(value['graph_sha256'], snapshot), resolution)
    covered = {locator_held, *resolution['dependency_locator_sha256s']}
    for probe in value['probes']:
        target = probe['target_locator_sha256']
        require(target in covered, 'unresolved challenge target')
        before = selected_bytes(parse(snapshot[target]), resolution)
        require(identity(before) == probe['transformation']['before_pin'],
                'mutation source differs from resolved evidence')
    result = parse(replay(raw, held, snapshot, registry_root, admission_raw, admission_held, answers))
    result['source_evidence'] = binding
    return canonical(result)


def import_existing_exact(raw, registry, held, registry_root, previous=None, previous_held=None):
    """Use the original exact-profile checker rather than reinterpreting its fields."""
    from transport_sentinel import checked_sidecar
    document, _context, repairs = checked_sidecar(raw, registry, held, registry_root,
                                                previous, previous_held)
    return canonical({'schema': 'sentinel/legacy-exact-import/1', 'source_sidecar_sha256': held,
        'result_ids': [row['id'] for row in document['results']],
        'counterexample_ids': [row['id'] for row in document['counterexamples']],
        'repair_links': [list(pair) for pair in sorted(repairs)],
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'})


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
