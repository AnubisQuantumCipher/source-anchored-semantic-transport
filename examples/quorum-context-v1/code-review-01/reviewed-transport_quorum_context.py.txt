"""Exact typed preassessment context. No external custody or full replay claim."""

import hashlib

import transport_quorum_impact as impact
import transport_quorum_input as metadata
import transport_quorum_source as source
from transport_schema import canonical

__all__ = ('check_context_bindings',)

MAX_SORT_BYTES = 65536
MAX_OUTPUT = 32768
RECORD_TYPES = {
    'blobs': 'Blob', 'challenges': 'Challenge', 'claims': 'Claim',
    'dependencies': 'Dependency', 'history': 'HistoryEntry',
    'input_manifests': 'InputManifest', 'provenance': 'Provenance',
    'reading_withdrawals': 'ReadingWithdrawal', 'readings': 'Reading',
    'rules': 'RuleSpec', 'run_evidence': 'RunEvidence', 'selectors': 'Selector',
    'sources': 'SourceVersion', 'tasks': 'TaskView', 'updates': 'UpdateNotice',
}


def _fail(code: str, stage: str) -> None:
    raise metadata.InputError('CONTEXT_' + code, 'CONTEXT_' + stage)


def _label(record: dict) -> tuple[str, str]:
    return record['id'], record['revision']


def _key_label(key: dict) -> tuple[str, str]:
    return key['claim_id'], key['revision']


def _sort_key(value: object, kind: str) -> tuple[bytes, ...]:
    if kind == 'record':
        return (canonical(value['id']),)
    if kind == 'claim':
        return canonical(value['id']), canonical(value['revision'])
    return (canonical(value),)


def _ordered(values: list, kind: str = 'value') -> list:
    keys, total = [], 0
    for value in values:  # Only fixed-schema bounded owned lists reach here.
        key = _sort_key(value, kind)
        total += sum(len(part) for part in key)
        if total > MAX_SORT_BYTES:
            _fail('SORT_KEY_BOUND', 'ARRAY_ORDER')
        keys.append((key, value))
    keys.sort(key=lambda pair: pair[0])
    return [value for _, value in keys]


def _pin(record: dict, name: str) -> dict:
    raw = canonical(record)
    return dict(id=name, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))


def _nonclaims(body: dict) -> list[tuple]:
    result = [('Registry', body['registry'])]
    result.extend(('Seat', seat) for seat in _ordered(body['registry']['seats'], 'record'))
    result.append(('Policy', body['policy']))
    for field in RECORD_TYPES:  # Fixed lexical field order.
        if field != 'claims':
            result.extend((RECORD_TYPES[field], r) for r in _ordered(body[field], 'record'))
    return result


def _identities(body: dict) -> tuple:
    records, seen = _nonclaims(body), set()
    for _, record in records:
        if record['id'] in seen:
            _fail('ID_DUPLICATE', 'IDENTITIES')
        seen.add(record['id'])
    ordered_claims = _ordered(body['claims'], 'claim')
    for claim in ordered_claims:
        if claim['id'] in seen:
            _fail('CLAIM_LABEL_COLLISION', 'IDENTITIES')
    derived = []
    for claim in ordered_claims:
        name = claim['id'] + ':' + claim['revision']
        if not source._identifier(name):
            _fail('CLAIM_PIN_ID_SHAPE', 'IDENTITIES')
        derived.append((name, claim))
    for name, _ in derived:
        if name in seen:
            _fail('ID_DUPLICATE', 'IDENTITIES')
        seen.add(name)
    index = {r['id']: (kind, r, _pin(r, r['id'])) for kind, r in records}
    claim_keys = {}
    for name, claim in derived:
        pin = _pin(claim, name)
        index[name] = 'Claim', claim, pin
        claim_keys[_label(claim)] = dict(claim_id=claim['id'], revision=claim['revision'],
                                        sha256=pin['sha256'], bytes=pin['bytes'])
    return index, claim_keys


def _order(values: list, kind: str = 'value') -> None:
    if values != _ordered(values, kind):
        _fail('ARRAY_ORDER', 'ARRAY_ORDER')


def _fields(records: list[dict], field: str) -> None:
    for record in records:
        _order(record[field])


def _array_order(body: dict) -> None:
    for field in RECORD_TYPES:
        _order(body[field], 'claim' if field == 'claims' else 'record')
    _order(body['registry']['seats'], 'record')
    for manifest in body['input_manifests']:
        _order(manifest['registry_snapshot']['seats'], 'record')
    _fields(body['claims'], 'dependency_ids')
    _fields(body['claims'], 'selector_ids')
    _fields(body['tasks'], 'context_dependency_ids')
    _fields(body['tasks'], 'rule_ids')
    for task in body['tasks']:
        _fields(task['claim_rosters'], 'expected_seat_ids')
    _fields(body['readings'], 'challenge_ids')
    _fields(body['claims'], 'conflict_claims')
    _fields(body['tasks'], 'selected_sources')
    _fields(body['tasks'], 'claim_rosters')
    for field in ('dependencies', 'rule_specs', 'selectors', 'source_versions'):
        _fields(body['input_manifests'], field)
    _fields(body['readings'], 'source_versions')


def _seat_evidence(body: dict, sources: list[tuple]) -> list:
    keys = {key for _, key, _ in sources}
    result = []
    for seat in body['registry']['seats']:
        if seat['origin_kind'] == 'MANUAL_DEVELOPMENT_FIXTURE':
            valid = seat['declared_model_id'] is None and seat['identity_assurance'] == 'MANUAL_FIXTURE_ONLY'
        else:
            valid = seat['identity_assurance'] == 'UNVERIFIED'
        if not valid:
            _fail('SEAT_ORIGIN', 'REGISTRY')
        evidence = seat['identity_evidence']
        key = None if evidence is None else evidence['source']
        if key is not None and source._body_key(key) not in keys:
            _fail('SEAT_EVIDENCE_SOURCE', 'REGISTRY')
        result.append(dict(seat_id=seat['id'], source=None if key is None else dict(key),
            typed_binding='ABSENT' if key is None else 'MATCH_SUPPLIED_ORIGINAL',
            temporal_origin='UNKNOWN', authentication='UNVERIFIED'))
    return result


def _rosters(task: dict, claim_keys: dict, seats: set[str]) -> None:
    labels = [_key_label(row['claim']) for row in task['claim_rosters']]
    if len(set(labels)) != len(labels):
        _fail('TASK_ROSTER_DUPLICATE', 'TASK')
    if set(labels) != set(claim_keys):
        _fail('TASK_ROSTER_SET', 'TASK')
    for row in task['claim_rosters']:  # Verified canonical complete-row order.
        if row['claim'] != claim_keys[_key_label(row['claim'])]:
            _fail('TASK_ROSTER_PIN', 'TASK')
        if not set(row['expected_seat_ids']).issubset(seats):
            _fail('TASK_ROSTER_SEAT', 'TASK')


def _task(body: dict, claim_keys: dict) -> dict:
    task = body['tasks'][0]
    if task['registry_id'] != body['registry']['id']:
        _fail('TASK_REGISTRY', 'TASK')
    if task['policy_id'] != body['policy']['id']:
        _fail('TASK_POLICY', 'TASK')
    if set(task['rule_ids']) != {r['id'] for r in body['rules']}:
        _fail('TASK_RULE_SET', 'TASK')
    for claim in body['claims']:
        if claim['task_view_id'] != task['id']:
            _fail('TASK_CLAIM_OWNER', 'TASK')
    _rosters(task, claim_keys, {s['id'] for s in body['registry']['seats']})
    if {canonical(k) for k in task['selected_sources']} != {canonical(s['key']) for s in body['sources']}:
        _fail('TASK_SOURCE_SET', 'TASK')
    if not set(task['context_dependency_ids']).issubset({d['id'] for d in body['dependencies']}):
        _fail('TASK_CONTEXT_DEPENDENCY', 'TASK')
    return task


def _claim_conflicts(body: dict, claim_keys: dict) -> None:
    for claim in body['claims']:
        for label in claim['conflict_claims']:
            if _key_label(label) not in claim_keys:
                _fail('CLAIM_CONFLICT_MISSING', 'CLAIM_CONFLICTS')


def _blob_reference(pin: dict, index: dict, kind: str, prefix: str, stage: str) -> None:
    if pin['id'] not in index:
        _fail(prefix + '_MISSING', stage)
    record_type, record, actual = index[pin['id']]
    if record_type != 'Blob':
        _fail(prefix + '_TYPE', stage)
    if pin != actual:
        _fail(prefix + '_PIN', stage)
    if record['kind'] != kind:
        _fail(prefix + '_KIND', stage)


def _pin_set(actual: list[dict], names: set[str], index: dict, code: str) -> None:
    expected = {canonical(index[name][2]) for name in names}
    if {canonical(pin) for pin in actual} != expected:
        _fail(code, 'MANIFESTS')


def _manifest_context(manifest: dict, body: dict, task: dict, index: dict,
                      claim_keys: dict, by_label: dict) -> None:
    if manifest['task'] != index[task['id']][2]:
        _fail('MANIFEST_TASK', 'MANIFESTS')
    label = _key_label(manifest['claim'])
    if label not in claim_keys or manifest['claim'] != claim_keys[label]:
        _fail('MANIFEST_CLAIM', 'MANIFESTS')
    claim = by_label[label]
    if {canonical(k) for k in manifest['source_versions']} != {canonical(k) for k in task['selected_sources']}:
        _fail('MANIFEST_SOURCE_SET', 'MANIFESTS')
    _pin_set(manifest['selectors'], set(claim['selector_ids']), index, 'MANIFEST_SELECTOR_SET')
    names = set(claim['dependency_ids']) | set(task['context_dependency_ids'])
    _pin_set(manifest['dependencies'], names, index, 'MANIFEST_DEPENDENCY_SET')
    if canonical(manifest['registry_snapshot']) != canonical(body['registry']):
        _fail('MANIFEST_REGISTRY', 'MANIFESTS')
    _pin_set(manifest['rule_specs'], {r['id'] for r in body['rules']}, index, 'MANIFEST_RULE_SET')
    if manifest['policy'] != index[body['policy']['id']][2]:
        _fail('MANIFEST_POLICY', 'MANIFESTS')
    _blob_reference(manifest['prompt'], index, 'PROMPT', 'MANIFEST_PROMPT', 'MANIFESTS')
    _blob_reference(manifest['settings'], index, 'SETTINGS', 'MANIFEST_SETTINGS', 'MANIFESTS')


def _manifests(body: dict, task: dict, index: dict, claim_keys: dict) -> list:
    by_label = {_label(c): c for c in body['claims']}
    result = []
    for manifest in body['input_manifests']:
        _manifest_context(manifest, body, task, index, claim_keys, by_label)
        result.append(dict(pin=dict(index[manifest['id']][2]), claim=dict(manifest['claim']),
                           binding='MATCH_PREASSESSMENT_TYPED_CONTEXT_ONLY'))
    return result


def _result(body: dict, impact_result: dict, index: dict, seats: list, manifests: list) -> dict:
    records = [dict(pin, record_type=kind) for kind, _, pin in index.values()]
    records = _ordered(records, 'record')
    result = dict(status='ok', stage='CONTEXT_BINDINGS_ONLY',
        body_pin=dict(impact_result['body_pin']), records=records, seat_evidence=seats,
        manifests=manifests, registry=dict(pin=dict(index[body['registry']['id']][2]),
            binding='MATCH_STATIC_DECLARATIONS_ONLY'),
        task=dict(pin=dict(index[body['tasks'][0]['id']][2]), binding='MATCH_EXACT_TASK_CONTEXT_ONLY'),
        external_record_pin_match='NOT_EVALUATED', independent_inputs='UNKNOWN',
        source_authentication='UNVERIFIED', current_authority='NONE', freshness='UNKNOWN',
        semantic_completeness='UNPROVEN', full_reference_closure='NOT_EVALUATED',
        deferred_gates=['AGGREGATION', 'BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST',
                        'CHALLENGE_WITHDRAWAL', 'READING_RUN_PROVENANCE'])
    if len(canonical(result)) + 1 > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    return result


def check_context_bindings(body_raw: object, originals: object, held_update_pins: object) -> dict:
    """Check exact context from bytes; metadata types and history grant no authority."""
    try:
        body, sources, impact_result, _ = impact._validated_impact(body_raw, originals, held_update_pins)
        index, claim_keys = _identities(body)
        _array_order(body)
        seats = _seat_evidence(body, sources)
        task = _task(body, claim_keys)
        _claim_conflicts(body, claim_keys)
        if task['task_text'] is not None:
            _blob_reference(task['task_text'], index, 'TASK_TEXT', 'TASK_TEXT', 'TASK_TEXT')
        manifests = _manifests(body, task, index, claim_keys)
        return _result(body, impact_result, index, seats, manifests)
    except metadata.InputError as error:
        return metadata._error(error)
