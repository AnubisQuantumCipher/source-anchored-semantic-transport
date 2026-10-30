"""Deterministic full replay behind the separately qualified local bootstrap.

The private entry accepts owned host observations, never a public trust flag.
No model, network, history mutation or consequential authorization occurs here.
"""

import hashlib
import re

import transport_quorum_claim as claim
import transport_quorum_context as context
import transport_quorum_graph as graph
import transport_quorum_impact as impact
import transport_quorum_input as metadata
import transport_quorum_reading as reading
import transport_quorum_shape as shape
import transport_quorum_source as source
from transport_schema import canonical

MAX_OUTPUT = 131072
MAX_TARGETS = 1024
ALIASES = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
EXCLUSIONS = [
    'Positional REF role identity does not establish semantic relevance.',
    'Recorded stances do not establish model identity or independence.',
    'Source and issuer authentication and current authority are not provided.',
    'Typed declaration identity does not establish entailment or truth.',
]
RAW_ERRORS = {
    'INPUT_ENCODING': ('REFUSED_ENCODING', 'INVALID_UTF8'),
    'INPUT_INTEGER_TOKEN': ('REFUSED_INTEGER_TOKEN', 'INTEGER_TOKEN'),
    'INPUT_INTEGER_BOUND': ('REFUSED_BYTE_BOUND', 'INTEGER_BOUND'),
    'INPUT_DEPTH': ('REFUSED_DEPTH', 'DEPTH'),
    'INPUT_RECORD_BOUND': ('REFUSED_RECORD_BOUND', 'RECORD_BOUND'),
    'INPUT_BYTE_BOUND': ('REFUSED_BYTE_BOUND', 'BYTE_BOUND'),
    'INPUT_BYTE_FIELD_BOUND': ('REFUSED_BYTE_BOUND', 'BYTE_BOUND'),
    'INPUT_WORK_BOUND': ('REFUSED_BYTE_BOUND', 'WORK_BOUND'),
    'INPUT_NONCANONICAL': ('REFUSED_NONCANONICAL', 'NONCANONICAL'),
    'INPUT_UNADMITTED': ('REFUSED_UNADMITTED_REPLAY', 'UNADMITTED_VERSION'),
}


class ReplayError(Exception):
    def __init__(self, replay: str, reason: str) -> None:
        super().__init__(reason)
        self.replay, self.reason = replay, reason
        self.missing_targets, self.missing_predecessors = [], []


class Work:
    """Conservative prepaid orchestration work; component quotas remain separate."""

    def __init__(self, raw_bytes: int) -> None:
        self.remaining = raw_bytes * (96 + 16 + 16 + 128 + 32 + 1) + 15 * 15 * 15
        # Reserve up to 128 linear passes over the bounded metadata for all
        # fixed orchestration scans and construction; detailed incidences below
        # are additionally charged, not hidden inside that reservation.
        self.charge(raw_bytes * 128)

    def charge(self, amount: int) -> None:
        if type(amount) is not int or amount < 0 or amount > self.remaining:
            _fail('REFUSED_BYTE_BOUND', 'WORK_BOUND')
        self.remaining -= amount


def _fail(replay: str, reason: str) -> None:
    raise ReplayError(replay, reason)


def _record(raw: bytes) -> dict:
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _reason(code: str) -> dict:
    return dict(code=code, detail='', record_ids=[])


def _refusal(stage: str, error: ReplayError, request: dict | None) -> dict:
    return dict(schema='quorum/replay-refusal/1', accepted_result=False,
        replay=error.replay, input_request=request, failed_stage=stage,
        reasons=[_reason(error.reason)], missing_target_keys=error.missing_targets,
        missing_predecessor_ids=error.missing_predecessors,
        dimension_status='NOT_EVALUATED', diagnostic_result=None,
        diagnostic_result_accepted=False, previous_receipt=None, authority='NONE', freshness='UNKNOWN')


def _raw(raw: object) -> object:
    return metadata._read_value(raw)


def _fixed_shape(value: object, schema: dict, root: str, bounds: bool) -> None:
    budget = shape.Budget('BOUNDS' if bounds else 'SCHEMA')
    definitions = schema['$defs']
    frame = shape.Frame(definitions[root], value, definitions, budget, bounds)
    if not shape._evaluate_stack([frame], definitions, budget, bounds) and not bounds:
        _fail('REFUSED_CLOSED_SCHEMA', 'CLOSED_SCHEMA')


def _physical(body_raw: bytes, originals: object, auxiliary: object) -> list:
    if type(originals) is not tuple or len(originals) > 15:
        _fail('REFUSED_SOURCE_COUNT', 'SOURCE_COUNT')
    result, total = [], len(body_raw)
    items = originals + (() if auxiliary is None else (auxiliary[:3],))
    if len(items) + 1 > 16:
        _fail('REFUSED_SOURCE_COUNT', 'SOURCE_COUNT')
    for number, item in enumerate(items):
        if type(item) is not tuple or len(item) != 3 or type(item[2]) is not bytes:
            _fail('REFUSED_CLOSED_SCHEMA', 'SOURCE_ARGUMENTS')
        alias, key, raw = item
        if number < len(originals) and (type(alias) is not str or ALIASES.fullmatch(alias) is None):
            _fail('REFUSED_UNADMITTED_REPLAY', 'PACKAGE_ALIAS_PROFILE')
        if number == len(originals) and not source._identifier(alias):
            _fail('REFUSED_CLOSED_SCHEMA', 'AUXILIARY_ARGUMENTS')
        parsed = source._key(key)
        total += len(raw)
        if total > 65536 or len(raw) > 65536:
            _fail('REFUSED_BYTE_BOUND', 'SOURCE_BYTES')
        result.append((alias, parsed, raw))
    return result[:len(originals)]


def _admission(request: object, envelope: object, body: object) -> None:
    for value, expected in ((request, 'quorum/replay-request/1'),
                            (envelope, 'quorum/external-replay-envelope/1')):
        if type(value) is dict and type(value.get('schema')) is str and value['schema'] != expected:
            _fail('REFUSED_UNADMITTED_REPLAY', 'UNADMITTED_VERSION')
    shape._admission(body)


def _identities(body: dict) -> tuple:
    for record in context._ordered(body['claims'], 'claim'):
        if not source._identifier(record['id'] + ':' + record['revision']):
            _fail('REFUSED_DUPLICATE_RECORD_ID', 'RECORD_IDENTITY')
    names = [u['id'] for u in body['updates']]
    if len(set(names)) != len(names):
        _fail('REFUSED_DUPLICATE_EVENT_ID', 'DUPLICATE_EVENT_ID')
    try:
        return context._identities(body)
    except metadata.InputError as error:
        raise ReplayError('REFUSED_DUPLICATE_RECORD_ID', 'RECORD_IDENTITY') from error


def _missing_target(target: dict) -> None:
    error = ReplayError('REFUSED_MISSING_DEPENDENCY', 'MISSING_TARGET')
    error.missing_targets = [target]
    raise error


def _pin_target(pin: dict, index: dict, snapshot: bool = False) -> tuple:
    if pin['id'] not in index:
        _fail('REFUSED_MISSING_DEPENDENCY', 'MISSING_TARGET')
    actual = index[pin['id']]
    if pin != actual[2]:
        _fail('REFUSED_SNAPSHOT_PIN' if snapshot else 'REFUSED_INPUT_INTEGRITY',
              'STATIC_RECORD_PIN' if snapshot else 'TYPED_TARGET_PIN')
    return actual


def _request_pins(request: dict, index: dict) -> None:
    supplied = request['record_pins']
    expected = context._ordered([item[2] for item in index.values()])
    if context._ordered(supplied) != expected:
        _fail('REFUSED_INPUT_INTEGRITY', 'RECORD_PIN')
    for name in ('task', 'registry', 'policy'):
        _pin_target(request[name], index, True)
    for pin in request['rules'] + request['input_manifest_pins']:
        _pin_target(pin, index, True)


def _source_keys(request: dict, body: dict, supplied: list) -> list:
    try:
        sources = source._source_set(body['sources'], supplied)
        source._source_integrity(sources)
    except metadata.InputError as error:
        raise ReplayError('REFUSED_SOURCE_BYTES', 'SOURCE_PIN') from error
    expected = context._ordered(list({canonical(r['key']): r['key'] for r in body['sources']}.values()))
    if context._ordered(request['external_source_pins']) != expected:
        _fail('REFUSED_SOURCE_BYTES', 'SOURCE_PIN')
    return sources


def _auxiliary(body_raw: bytes, originals: tuple, envelope: dict, auxiliary: object) -> None:
    receipt = envelope['untrusted_receipt']
    if (receipt is None) != (auxiliary is None):
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')
    if auxiliary is None:
        return
    if type(auxiliary) is not tuple or len(auxiliary) != 4:
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')
    alias, key, raw, held = auxiliary
    source._key(held)
    if key != held or dict(key, **_record(raw)) != key:
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')
    if alias == 'Q_RECORDS' or alias in {row[0] for row in originals}:
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')
    if any(raw == other for other in (body_raw, *(row[2] for row in originals))):
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')
    if (receipt['received_result_source'] != key or receipt['received_result_sha256'] != key['sha256']
            or receipt['received_result_bytes'] != key['bytes']):
        _fail('REFUSED_INPUT_INTEGRITY', 'AUXILIARY_SOURCE_IDENTITY')


def _target_rows(body: dict) -> list:
    rows = []
    fields = (('blobs', 'Blob'), ('selectors', 'Selector'), ('sources', 'SourceVersion'),
        ('claims', 'Claim'), ('seats', 'Seat'), ('dependencies', 'Dependency'),
        ('tasks', 'TaskView'), ('input_manifests', 'InputManifest'), ('provenance', 'Provenance'),
        ('run_evidence', 'RunEvidence'), ('readings', 'Reading'), ('challenges', 'Challenge'),
        ('reading_withdrawals', 'ReadingWithdrawal'), ('updates', 'UpdateNotice'), ('history', 'HistoryEntry'))
    for field, kind in fields:
        records = body['registry']['seats'] if field == 'seats' else body[field]
        for record in context._ordered(records, 'claim' if kind == 'Claim' else 'record'):
            _record_targets(rows, kind, record)
    return rows


def _add_target(rows: list, kind: str, expected: str, value: dict | None) -> None:
    if value is not None:
        if len(rows) >= MAX_TARGETS:
            _fail('REFUSED_BYTE_BOUND', 'TARGET_WORK_BOUND')
        rows.append((kind, expected, value))


def _guard_targets(rows: list, kind: str, statement: dict) -> None:
    for position in ('condition', 'exception'):
        for node in statement[position]['nodes']:
            if node['op'] == 'REF':
                _add_target(rows, kind, 'Source', node['target'])


def _record_targets(rows: list, kind: str, r: dict) -> None:
    if kind in ('TaskView', 'InputManifest'):
        _context_targets(rows, kind, r)
        return
    scalar = {
        'SourceVersion': (('key', 'Source'),), 'Selector': (('source', 'Source'),),
        'Provenance': (('evidence', 'Blob'),), 'HistoryEntry': (('artifact', 'Source'),),
        'TaskView': (('task_text', 'Blob'),),
        'InputManifest': (('task', 'TaskView'), ('claim', 'Claim'), ('policy', 'Policy'),
                          ('prompt', 'Blob'), ('settings', 'Blob')),
        'RunEvidence': (('input_manifest', 'InputManifest'), ('prompt', 'Blob'), ('settings', 'Blob'),
                        ('response', 'Blob'), ('raw_run_evidence', 'Blob'),
                        ('externally_pinned_eligibility_policy', 'Source')),
        'Reading': (('claim', 'Claim'), ('input_manifest', 'InputManifest'), ('prompt', 'Blob'),
                    ('settings', 'Blob'), ('response', 'Blob'), ('provenance', 'Provenance')),
        'Challenge': (('claim', 'Claim'), ('provenance', 'Provenance'), ('evidence', 'Blob')),
        'ReadingWithdrawal': (('provenance', 'Provenance'), ('evidence', 'Blob')),
        'UpdateNotice': (('old_version', 'Source'), ('new_version', 'Source'),
                         ('provenance', 'Provenance'), ('evidence', 'Blob')),
    }
    for field, expected in scalar.get(kind, ()):
        _add_target(rows, kind, expected, r[field])
    _nested_targets(rows, kind, r)


def _context_targets(rows: list, kind: str, r: dict) -> None:
    if kind == 'TaskView':
        for item in r['claim_rosters']:
            _add_target(rows, kind, 'Claim', item['claim'])
        _add_target(rows, kind, 'Blob', r['task_text'])
        for value in r['selected_sources']:
            _add_target(rows, kind, 'Source', value)
        return
    for field, expected in (('task', 'TaskView'), ('claim', 'Claim')):
        _add_target(rows, kind, expected, r[field])
    for field, expected in (('selectors', 'Selector'), ('dependencies', 'Dependency'), ('rule_specs', 'RuleSpec')):
        for value in r[field]:
            _add_target(rows, kind, expected, value)
    for field, expected in (('policy', 'Policy'), ('prompt', 'Blob'), ('settings', 'Blob')):
        _add_target(rows, kind, expected, r[field])
    for value in r['source_versions']:
        _add_target(rows, kind, 'Source', value)
    for seat in r['registry_snapshot']['seats']:
        if seat['identity_evidence'] is not None:
            _add_target(rows, 'Seat', 'Source', seat['identity_evidence']['source'])


def _nested_targets(rows: list, kind: str, r: dict) -> None:
    if kind == 'Seat' and r['identity_evidence'] is not None:
        _add_target(rows, kind, 'Source', r['identity_evidence']['source'])
    if kind == 'Claim' and r['payload']['profile'] == claim.STRUCTURAL:
        _guard_targets(rows, kind, r['payload']['statement'])
    if kind == 'Dependency':
        target = r['requires']
        _add_target(rows, kind, 'Source' if target['kind'] == 'SOURCE' else 'Claim',
                    target['source'] if target['kind'] == 'SOURCE' else target['claim'])
    if kind == 'Reading':
        for value in r['source_versions']:
            _add_target(rows, kind, 'Source', value)


def _target_identity(rows: list, index: dict, keys: dict, source_keys: set, work: Work) -> list:
    actual_kinds = []
    for origin, expected, value in rows:
        work.charge(1 + len(index) + len(keys) + len(source_keys))
        if expected == 'Source':
            if source._body_key(value) not in source_keys:
                _missing_target(dict(kind='SOURCE', source=dict(value)))
            actual = 'Source'
        elif expected == 'Claim':
            label = context._key_label(value)
            if label not in keys:
                _missing_target(dict(kind='CLAIM', claim=dict(value)))
            if keys[label] != value:
                _fail('REFUSED_INPUT_INTEGRITY', 'TYPED_TARGET_PIN')
            actual = 'Claim'
        else:
            actual = _pin_target(value, index)[0]
        actual_kinds.append((origin, expected, actual))
    return actual_kinds


def _read_ahead(s: dict, memberships: list) -> tuple:
    body, resolved, schema, sources = s['body'], s['resolved'], s['schema'], s['sources']
    by_id = {r[0]['id']: r for r in resolved}
    matched = {r['id']: r['status'] for r in memberships}
    cached, selected_claims, source_keys = {}, set(), {key for _, key, _ in sources}
    for c in context._ordered(body['claims'], 'claim'):
        if c['payload']['profile'] != claim.STRUCTURAL or len(c['selector_ids']) != 1:
            continue
        name = c['selector_ids'][0]
        if name not in by_id:
            continue
        selector, _, raw = by_id[name]
        if not raw or selector['begin'] != 0 or selector['end'] != len(raw) or matched[name] != 'MATCH':
            continue
        key = source._body_key(selector['source'])
        selected_claims.add(claim._label(c))
        if key not in cached:
            s['work'].charge(len(raw))
            cached[key] = _declaration(raw, schema)
            rows = []
            _guard_targets(rows, 'Source', cached[key])
            _target_identity(rows, {}, {}, source_keys, s['work'])
    return cached, selected_claims


def _declaration(raw: bytes, schema: dict) -> dict:
    if len(raw) > claim.MAX_DECLARATION:
        _fail('REFUSED_BYTE_BOUND', 'DECLARATION_RESOURCE')
    try:
        value = metadata._read_value(raw)
        metadata._canonical_bytes(value, raw)
        shape._declaration_shape(value, schema)
    except metadata.InputError as error:
        if error.code in RAW_ERRORS:
            raise ReplayError(*RAW_ERRORS[error.code]) from error
        raise ReplayError('REFUSED_CLOSED_SCHEMA', 'DECLARATION_SOURCE_CLOSED_SCHEMA') from error
    return value['statement']


def _static_request(request: dict, body: dict, index: dict) -> None:
    for field, record in (('task', body['tasks'][0]), ('registry', body['registry']), ('policy', body['policy'])):
        if request[field] != index[record['id']][2]:
            _fail('REFUSED_REFERENCE_INCONSISTENCY', 'STATIC_CONTEXT_REFERENCE')
    for field, records in (('rules', body['rules']), ('input_manifest_pins', body['input_manifests'])):
        if context._ordered(request[field]) != context._ordered([index[r['id']][2] for r in records]):
            _fail('REFUSED_REFERENCE_INCONSISTENCY', 'STATIC_CONTEXT_REFERENCE')


def _positional(statement: dict, dependencies: list, work: Work) -> None:
    for position, role in (('condition', 'TASK_CONDITION'), ('exception', 'EXCEPTION')):
        for node in statement[position]['nodes']:
            work.charge(1 + len(dependencies))
            if node['op'] == 'REF' and not any(d['role'] == role and d['requires']['kind'] == 'SOURCE'
                    and d['requires']['source'] == node['target'] for d in dependencies):
                _fail('REFUSED_REFERENCE_INCONSISTENCY', 'REF_POSITIONAL_ROLE')


def _roles(contexts: list, cached: dict, selected_claims: set, work: Work) -> list:
    pairs = set()
    for c, selectors, dependencies in contexts:
        if c['payload']['profile'] != claim.STRUCTURAL:
            continue
        if len(selectors) != 1:
            _fail('REFUSED_REFERENCE_INCONSISTENCY', 'DEPENDENCY_REFERENCE')
        _positional(c['payload']['statement'], dependencies, work)
        key = source._body_key(selectors[0]['source'])
        if claim._label(c) in selected_claims:
            _positional(cached[key], dependencies, work)
            for position in ('condition', 'exception'):
                for node in cached[key][position]['nodes']:
                    if node['op'] == 'REF':
                        pairs.add((key, source._body_key(node['target'])))
                        if len(pairs) > 64:
                            _fail('REFUSED_BYTE_BOUND', 'SOURCE_GRAPH_BOUND')
    return sorted(pairs)


def _predecessor_references(body: dict, field: str, parent: str, domain: str) -> None:
    records = {r['id']: r for r in body[field]}
    for record in context._ordered(body[field], 'record'):
        name = record[parent]
        if name is not None:
            if name not in records:
                error = ReplayError('REFUSED_MISSING_DEPENDENCY', 'MISSING_PREDECESSOR')
                error.missing_predecessors = [name]
                raise error
            if records[name][domain] != record[domain]:
                _fail('REFUSED_REFERENCE_INCONSISTENCY', 'PREDECESSOR_CONTEXT')


def _context_references(s: dict) -> None:
    body, index, keys = s['body'], s['index'], s['keys']
    _static_request(s['request'], body, index)
    s['seats'] = context._seat_evidence(body, s['sources'])
    task = context._task(body, keys)
    if task['task_text'] is not None:
        context._blob_reference(task['task_text'], index, 'TASK_TEXT', 'TASK_TEXT', 'TASK_TEXT')
    s['manifests'] = context._manifests(body, task, index, keys)


def _dependency_references(s: dict) -> None:
    body, keys = s['body'], s['keys']
    context._claim_conflicts(body, keys)
    s['contexts'] = sorted(claim._contexts(body),
        key=lambda row: (canonical(row[0]['id']), canonical(row[0]['revision'])))
    identity_claims = dict(claims=[dict(claim=keys[claim._label(c)]) for c in body['claims']])
    s['indices'], s['labels'], s['source_keys'] = impact._nodes(body, identity_claims)
    s['edges'] = impact._dependencies(body, s['indices'], s['labels'], s['source_keys'])


def _reading_references(s: dict) -> None:
    body, index, keys = s['body'], s['index'], s['keys']
    reading._provenance(body, index)
    reading._runs(body, s['sources'], index)
    reading._readings(body, index, keys)
    reading._challenges(body, index, keys)
    s['withdrawals'] = reading._withdrawals(body, index)
    _predecessor_references(body, 'reading_withdrawals', 'predecessor_withdrawal_id', 'reading_id')


def _references(s: dict) -> None:
    body, index = s['body'], s['index']
    reason = 'CANONICAL_ARRAY_ORDER'
    try:
        if any(expected != actual for _, expected, actual in s['target_kinds']):
            _fail('REFUSED_REFERENCE_INCONSISTENCY', 'TYPED_TARGET_KIND')
        context._array_order(body)
        for field in ('record_pins', 'input_manifest_pins', 'external_source_pins', 'rules'):
            context._order(s['request'][field])
        reason = 'STATIC_CONTEXT_REFERENCE'
        _context_references(s)
        reason = 'DEPENDENCY_REFERENCE'
        _dependency_references(s)
        reason = 'REF_POSITIONAL_ROLE'
        s['source_pairs'] = _roles(s['contexts'], s['cached'], s['selected_claims'], s['work'])
        reason = 'READING_REFERENCE'
        _reading_references(s)
        reason = 'UPDATE_REFERENCE'
        impact._update_records(body, body['updates'], s['source_keys'])
        _predecessor_references(body, 'updates', 'predecessor_event_id', 'logical_source_id')
        reason = 'HISTORY_RELATED_ID'
        for record in body['history']:
            for name in record['related_record_ids']:
                if name not in index:
                    _fail('REFUSED_REFERENCE_INCONSISTENCY', reason)
        encoded = {u['id']: canonical(u) for u in body['updates']}
        s['history'], s['recorded'] = impact._history(body, s['sources'], encoded)
    except metadata.InputError as error:
        if error.code in RAW_ERRORS or 'BOUND' in error.code or 'RESOURCE' in error.code:
            raise
        if error.code == 'CONTEXT_TASK_REGISTRY':
            reason = 'TASK_REGISTRY'
        raise ReplayError('REFUSED_REFERENCE_INCONSISTENCY', reason) from error


def _source_graph(s: dict) -> None:
    keys = sorted({key for _, key, _ in s['sources']})
    if len(keys) > 15 or len(s['source_pairs']) > 64:
        _fail('REFUSED_BYTE_BOUND', 'SOURCE_GRAPH_BOUND')
    indices = {key: number for number, key in enumerate(keys)}
    matrix, ranks, resolved = bytearray(15 * 15), [0] * 15, [False] * 15
    for left, right in s['source_pairs']:
        s['work'].charge(1)
        matrix[15 * indices[left] + indices[right]] = 1
    for _ in range(15):
        for vertex in range(len(keys)):
            s['work'].charge(len(keys))
            if resolved[vertex]:
                continue
            ready, maximum = True, -1
            for target in range(len(keys)):
                if matrix[15 * vertex + target]:
                    ready = ready and resolved[target]
                    maximum = max(maximum, ranks[target])
            if ready:
                ranks[vertex] = max(1 if keys[vertex] in s['cached'] else 0, 1 + maximum)
                resolved[vertex] = True
        s['work'].charge(len(keys))
        if all(resolved[:len(keys)]):
            s['source_ranks'] = {key: ranks[indices[key]] for key in keys}
            return
    _fail('REFUSED_DEPENDENCY_CYCLE', 'SOURCE_DIGEST_CYCLE')


def _ranks(s: dict) -> None:
    base = len({key for _, key, _ in s['sources']}) + 2
    if any(rank >= base for rank in s['source_ranks'].values()):
        _fail('REFUSED_DEPENDENCY_CYCLE', 'CONTENT_DIGEST_CYCLE')
    ranks = dict(Source=base - 1, Blob=1, RuleSpec=0, Policy=0, Provenance=2,
        Seat=base, Registry=base + 1, Claim=base, Selector=base, SourceVersion=base,
        Dependency=base + 1, TaskView=base + 1, InputManifest=base + 2,
        RunEvidence=base + 3, Reading=base + 3, Challenge=base + 1,
        ReadingWithdrawal=base + 1, UpdateNotice=base + 1, HistoryEntry=base)
    for origin, _, target in s['target_kinds']:
        if ranks[origin] <= ranks[target]:
            _fail('REFUSED_DEPENDENCY_CYCLE', 'CONTENT_DIGEST_CYCLE')


def _graphs(s: dict) -> None:
    for c in context._ordered(s['body']['claims'], 'claim'):
        if c['payload']['profile'] == claim.STRUCTURAL:
            claim._guards(c['payload']['statement'], 'CLAIM')
    for key in sorted(s['cached'], key=lambda k: canonical(dict(zip(source.KEY_FIELDS, k, strict=True)))):
        claim._guards(s['cached'][key], 'DECLARATION')
    impact._reach(len(s['indices']), s['edges'], [], 'DEPENDENCY_DAG')
    impact._predecessors(s['body']['updates'])
    reading._predecessors(s['body'])
    _source_graph(s)
    _ranks(s)


def _claim_results(s: dict) -> dict:
    by_selector = {selector['id']: raw for selector, _, raw in s['resolved']}
    memberships = {row['id']: row['status'] for row in s['source_result']['selectors']}
    entries = []
    for c, selectors, _ in s['contexts']:
        disposition, selected, membership, _ = claim._scope(c, selectors, by_selector, memberships)
        if disposition is None:
            actual = s['cached'][source._body_key(selected['source'])]
            disposition = ('MATCHED_DECLARATION_STRUCTURE_ONLY' if actual == c['payload']['statement']
                           else 'DIFFERS_DECLARATION_STRUCTURE_ONLY')
        entries.append(claim._entry(c, selected, membership, disposition))
    return claim._result(s['source_result'], entries)


def _impact_result(s: dict, claims: dict) -> dict:
    updates, indices, edges = s['body']['updates'], s['indices'], s['edges']
    conflicts = impact._conflicts(updates)
    affected = {u['id']: impact._reach(len(indices), edges,
        [indices[canonical(u['old_version'])]], 'REACHABILITY') for u in updates}
    entries = impact._claim_entries(claims, indices, affected, conflicts)
    result, size = impact._skeleton(claims, entries, updates, s['history'], s['recorded'], conflicts)
    impact._paths(result, indices, edges, affected, updates, size)
    return result


def _result(s: dict, request_pin: dict) -> dict:
    s['source_result'] = source._result(s['body_raw'], s['sources'], s['blobs'], s['memberships'])
    claims = _claim_results(s)
    changed = _impact_result(s, claims)
    ctx = context._result(s['body'], changed, s['index'], s['seats'], s['manifests'])
    counted = reading._result(s['body'], claims, ctx, s['withdrawals'])
    result = dict(schema='quorum/replay-result/1', accepted_result=True,
        replay='RECOMPUTED_INFORMATIONAL', request=request_pin, claims=[],
        quarantined_update_ids=context._ordered([u['id'] for u in s['body']['updates']]),
        conflicting_update_ids=context._ordered(changed['conflicting_update_ids']),
        already_recorded_update_ids=context._ordered(changed['already_recorded_update_ids']),
        retained_history_ids=context._ordered([h['id'] for h in s['history']]),
        reasons=[], exclusions=list(EXCLUSIONS), source_authentication='UNVERIFIED',
        current_authority='NONE', freshness='UNKNOWN', semantic_completeness='UNPROVEN')
    size = len(canonical(result)) + 1
    for comparison, altered, counts in zip(claims['claims'], changed['claims'], counted['claims'], strict=True):
        entry = _full_claim(s, comparison, altered, counts)
        size += len(canonical(entry)) + (1 if result['claims'] else 0)
        if size > MAX_OUTPUT:
            _fail('REFUSED_COMPLETE_OUTPUT_BOUND', 'COMPLETE_OUTPUT_BOUND')
        result['claims'].append(entry)
    if len(canonical(result)) + 1 != size:
        _fail('REFUSED_COMPLETE_OUTPUT_BOUND', 'OUTPUT_ACCOUNTING')
    return result


def _full_claim(s: dict, comparison: dict, changed: dict, counts: dict) -> dict:
    key = comparison['claim']
    if changed['claim'] != key or counts['claim'] != key:
        _fail('REFUSED_INPUT_INTEGRITY', 'DERIVED_CLAIM_IDENTITY')
    original = s['index'][key['claim_id'] + ':' + key['revision']][1]
    selected = set(original['selector_ids'])
    memberships = [dict(selector_id=row['id'], status=row['status'], reason_codes=[])
                   for row in s['source_result']['selectors'] if row['id'] in selected]
    return dict(claim=key, source_membership=memberships, interpretation=comparison['interpretation'],
        declared_preconditions=changed['declared_preconditions'], change_impact=changed['change_impact'],
        trigger_update_ids=context._ordered(changed['trigger_update_ids']),
        impact_paths=[dict(path, affected_claim=dict(key)) for path in changed['paths']],
        aggregation=counts['aggregation'], reason_codes=[], semantic_completeness='UNPROVEN',
        claim_truth='NOT_ASSESSED', freshness='UNKNOWN', current_authority='NONE')


def _import_result(s: dict, result: dict, auxiliary: object) -> dict:
    receipt = s['envelope']['untrusted_receipt']
    if receipt is None or not receipt['validate_import']:
        return result
    raw = auxiliary[2]
    try:
        imported = metadata._read_value(raw)
        metadata._canonical_bytes(imported, raw)
        _fixed_shape(imported, s['schema'], 'ReplayResult', True)
        _fixed_shape(imported, s['schema'], 'ReplayResult', False)
        matched = raw == canonical(result)
    except (metadata.InputError, ReplayError):
        matched = False
    if matched:
        return result
    failure = _refusal('IMPORT_COMPARISON', ReplayError('REFUSED_IMPORTED_RECEIPT', 'IMPORTED_RESULT'),
                       result['request'])
    failure['diagnostic_result'] = dict(accepted_result=False,
        purpose='NONACCEPTED_IMPORTED_RECEIPT_MISMATCH_DIAGNOSTICS', claims=result['claims'], reasons=[])
    return failure


def _identity(s: dict, raw: tuple, originals: tuple, package: bytes, held: dict,
              qualified: dict, auxiliary: object) -> dict:
    metadata._canonical_bytes(s['request'], raw[0])
    if type(held) is not dict or held != _record(raw[0]):
        _fail('REFUSED_INPUT_INTEGRITY', 'REQUEST_PIN')
    s['request_pin'] = dict(id='REPLAY_REQUEST', **_record(raw[0]))
    request = s['request']
    if request['package'] != _record(package):
        _fail('REFUSED_PACKAGE_PIN', 'PACKAGE_PIN')
    metadata._canonical_bytes(s['body'], raw[2])
    metadata._canonical_bytes(s['envelope'], raw[1])
    if request['quorum_body'] != _record(raw[2]) or s['envelope']['request'] != request:
        _fail('REFUSED_INPUT_INTEGRITY', 'QUORUM_BODY_PIN')
    if any(request[name] != qualified[name] for name in ('wire_schema', 'protocol_rules', 'checker')):
        _fail('REFUSED_BOUND_COMPONENT_PIN', 'CHECKER_CLOSURE')
    s['index'], s['keys'] = _identities(s['body'])
    _request_pins(request, s['index'])
    s['sources'] = _source_keys(request, s['body'], s['supplied'])
    _auxiliary(raw[2], originals, s['envelope'], auxiliary)
    blobs, used = source._blobs(s['body']['blobs'])
    quotes = source._quotes(s['body']['selectors'], used)
    s['target_kinds'] = _target_identity(_target_rows(s['body']), s['index'], s['keys'],
                                        {key for _, key, _ in s['sources']}, s['work'])
    s['resolved'] = source._selector_sources(quotes, s['sources'])
    try:
        source._selector_ranges(s['resolved'])
    except metadata.InputError as error:
        raise ReplayError('REFUSED_SELECTOR', 'SELECTOR_RANGE') from error
    memberships = source._memberships(s['resolved'])
    s['blobs'], s['memberships'], s['body_raw'] = blobs, memberships, raw[2]
    s['cached'], s['selected_claims'] = _read_ahead(s, memberships)
    return s


def _mapped(error: metadata.InputError, stage: str) -> ReplayError:
    if error.code in RAW_ERRORS:
        return ReplayError(*RAW_ERRORS[error.code])
    if stage == 'GRAPHS':
        if error.code == 'IMPACT_DEPENDENCY_CYCLE':
            return ReplayError('REFUSED_DEPENDENCY_CYCLE', 'DEPENDENCY_CYCLE')
        if error.code == 'IMPACT_PREDECESSOR_CYCLE':
            return ReplayError('REFUSED_UPDATE_PREDECESSOR_CYCLE', 'UPDATE_CYCLE')
        reason = 'WITHDRAWAL_CYCLE' if error.code == 'READING_WITHDRAWAL_PREDECESSOR_CYCLE' else 'GUARD_GRAPH'
        return ReplayError('REFUSED_REFERENCE_INCONSISTENCY', reason)
    if stage == 'REFERENCES':
        reason = 'TASK_REGISTRY' if error.code == 'CONTEXT_TASK_REGISTRY' else 'REFERENCE_INCONSISTENCY'
        return ReplayError('REFUSED_REFERENCE_INCONSISTENCY', reason)
    if 'OUTPUT' in error.code or error.code in ('IMPACT_PATH_WORK_BOUND', 'IMPACT_PATH_LIMIT', 'IMPACT_PATH_DEPTH'):
        return ReplayError('REFUSED_COMPLETE_OUTPUT_BOUND', 'COMPLETE_OUTPUT_BOUND')
    if 'BOUND' in error.code or 'RESOURCE' in error.code:
        return ReplayError('REFUSED_BYTE_BOUND', 'BYTE_BOUND')
    if stage in ('PREPARSE', 'SCHEMA'):
        return ReplayError('REFUSED_CLOSED_SCHEMA', 'CLOSED_SCHEMA')
    return ReplayError('REFUSED_INPUT_INTEGRITY', 'INPUT_INTEGRITY')


def _replay(request_raw: object, envelope_raw: object, body_raw: object, originals: object,
            package_raw: object, held_request: object, qualified_keys: dict,
            auxiliary: object = None) -> dict:
    """Internal entry: only the qualified bootstrap supplies external root facts."""
    stage, s = 'PREPARSE', {}
    try:
        s = dict(request=_raw(request_raw), envelope=_raw(envelope_raw), body=_raw(body_raw))
        s['schema'] = shape.load_schema()
        stage = 'BOUNDS'
        if type(package_raw) is not bytes or len(package_raw) > 131072:
            _fail('REFUSED_BYTE_BOUND', 'PACKAGE_BYTES')
        if auxiliary is not None and (type(auxiliary) is not tuple or len(auxiliary) != 4):
            _fail('REFUSED_CLOSED_SCHEMA', 'AUXILIARY_ARGUMENTS')
        s['supplied'] = _physical(body_raw, originals, auxiliary)
        for field, root in (('request', 'ReplayRequest'), ('envelope', 'ReplayEnvelope'), ('body', 'ReplayBody')):
            _fixed_shape(s[field], s['schema'], root, True)
        shape._record_count(s['body'])
        stage = 'SCHEMA'
        _admission(s['request'], s['envelope'], s['body'])
        for field, root in (('request', 'ReplayRequest'), ('envelope', 'ReplayEnvelope'), ('body', 'ReplayBody')):
            _fixed_shape(s[field], s['schema'], root, False)
        s['work'] = Work(len(request_raw) + len(envelope_raw) + len(body_raw))
        stage = 'IDENTITY'
        _identity(s, (request_raw, envelope_raw, body_raw), originals, package_raw,
                  held_request, qualified_keys, auxiliary)
        stage = 'REFERENCES'
        _references(s)
        stage = 'GRAPHS'
        _graphs(s)
        stage = 'RECOMPUTATION'
        result = _result(s, s['request_pin'])
        stage = 'IMPORT_COMPARISON'
        result = _import_result(s, result, auxiliary)
        stage = 'OUTPUT_BOUND'
        if len(canonical(result)) + 1 > MAX_OUTPUT:
            _fail('REFUSED_COMPLETE_OUTPUT_BOUND', 'COMPLETE_OUTPUT_BOUND')
        metadata._lexical(canonical(result))
        _fixed_shape(result, s['schema'], 'ReplayResult' if result['accepted_result'] else 'Refusal', False)
        return result
    except metadata.InputError as error:
        return _refusal(stage, _mapped(error, stage), s.get('request_pin'))
    except ReplayError as error:
        return _refusal(stage, error, s.get('request_pin'))
