"""Bounded declared change impact. Informational records never grant authority."""

import hashlib

import transport_quorum_claim as claims
import transport_quorum_graph as graph
import transport_quorum_input as metadata
import transport_quorum_source as source
from transport_schema import canonical

__all__ = ('check_declared_impact',)

MAX_UPDATES = 8
MAX_OUTPUT = 32768
MAX_PATHS = 64
MAX_PATH_DEPTH = 32
MAX_PATH_WORK = 8192
MAX_PATH_BYTES = 4096


def _fail(code: str, stage: str) -> None:
    raise metadata.InputError('IMPACT_' + code, 'IMPACT_' + stage)


def _unique(records: list[dict], code: str, stage: str) -> None:
    source._unique_ids([r['id'] for r in records], 'IMPACT_' + code,
                       'IMPACT_' + stage)


def _pin(record: dict) -> dict:
    raw = canonical(record)
    return dict(id=record['id'], sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))


def _held_arguments(value: object) -> list[tuple]:
    stage = 'PIN_ARGUMENTS'
    if type(value) is not tuple:
        _fail('PIN_TYPE', stage)
    if len(value) > MAX_UPDATES:
        _fail('PIN_COUNT', stage)
    result = []
    for item in value:
        if type(item) is not tuple or len(item) != 3:
            _fail('PIN_TYPE', stage)
        name, digest, size = item
        if type(name) is not str or type(digest) is not str or type(size) is not int:
            _fail('PIN_TYPE', stage)
        if (not source._identifier(name) or len(digest) != 64
                or any(c not in source.HEX for c in digest) or not 0 <= size <= 65536):
            _fail('PIN_SHAPE', stage)
        result.append((name, digest, size))
    return result


def _event_pins(body: dict, held: list[tuple]) -> tuple:
    stage = 'EVENT_PINS'
    updates = sorted(body['updates'], key=lambda r: r['id'])
    _unique(updates, 'UPDATE_DUPLICATE', stage)
    source._unique_ids([p[0] for p in held], 'IMPACT_PIN_DUPLICATE', 'IMPACT_' + stage)
    if {p[0] for p in held} != {r['id'] for r in updates}:
        _fail('PIN_SET', stage)
    held_by_id = {p[0]: p[1:] for p in held}
    encoded = {}
    for update in updates:
        raw = canonical(update)
        if held_by_id[update['id']] != (hashlib.sha256(raw).hexdigest(), len(raw)):
            _fail('UPDATE_PIN', stage)
        encoded[update['id']] = raw
    return updates, encoded


def _nodes(body: dict, claim_result: dict) -> tuple:
    source_keys = {canonical(r['key']): r['key'] for r in body['sources']}
    claim_keys = {canonical(r['claim']): r['claim'] for r in claim_result['claims']}
    keys = sorted(source_keys) + sorted(claim_keys)
    indices = {key: index for index, key in enumerate(keys)}
    labels = {(key['claim_id'], key['revision']): key for key in claim_keys.values()}
    return indices, labels, source_keys


def _target(required: dict, labels: dict, source_keys: dict) -> dict:
    stage = 'DEPENDENCIES'
    if required['kind'] == 'SOURCE':
        key = required['source']
        if canonical(key) not in source_keys:
            _fail('SOURCE_TARGET_MISSING', stage)
        return key
    key = required['claim']
    label = key['claim_id'], key['revision']
    if label not in labels:
        _fail('CLAIM_TARGET_MISSING', stage)
    if key != labels[label]:
        _fail('CLAIM_TARGET_PIN', stage)
    return key


def _dependencies(body: dict, indices: dict, labels: dict, source_keys: dict) -> list:
    owners = {claims._label(c): c for c in body['claims']}
    edges = []
    for dependency in sorted(body['dependencies'], key=lambda r: r['id']):
        label = dependency['dependent']['claim_id'], dependency['dependent']['revision']
        if label not in owners:
            _fail('DEPENDENT_MISSING', 'DEPENDENCIES')
        if owners[label]['dependency_ids'].count(dependency['id']) != 1:
            _fail('DEPENDENCY_UNOWNED', 'DEPENDENCIES')
        target = _target(dependency['requires'], labels, source_keys)
        edges.append((indices[canonical(labels[label])], indices[canonical(target)], dependency['id']))
    return edges


def _reach(count: int, edges: list, seeds: list[int], stage: str) -> set[int]:
    if count > graph.MAX_NODES or len(edges) > graph.MAX_EDGES:
        _fail('GRAPH_BOUND', stage)
    # Projection only: labeled parallel records remain in edges and path evidence.
    pairs = sorted({(dependent, target) for dependent, target, _ in edges})
    result = graph.reverse_reachable(dict(schema=graph.GRAPH_SCHEMA, node_count=count,
        edges=[list(pair) for pair in pairs], changed_nodes=seeds))
    if result['status'] != 'ok':
        code = 'DEPENDENCY_CYCLE' if result['error'] == 'G_CYCLE' else 'GRAPH_REJECTED'
        _fail(code, stage)
    return set(result['nodes'])


def _update_fields(update: dict, source_keys: dict) -> None:
    stage = 'UPDATE_RECORDS'
    old, new = update['old_version'], update['new_version']
    if old['logical_source_id'] != update['logical_source_id']:
        _fail('UPDATE_LOGICAL', stage)
    if canonical(old) not in source_keys:
        _fail('UPDATE_SOURCE_MISSING', stage)
    kind, correction = update['kind'], update['correction_text']
    valid = ((kind == 'REPLACEMENT' and new is not None and new != old and correction is None)
        or (kind == 'WITHDRAWAL' and new is None and correction is None)
        or (kind == 'ATTRIBUTED_CORRECTION' and correction is not None and new != old))
    if not valid:
        _fail('UPDATE_KIND', stage)
    if new is not None:
        if new['logical_source_id'] != update['logical_source_id']:
            _fail('UPDATE_LOGICAL', stage)
        if canonical(new) not in source_keys:
            _fail('UPDATE_SOURCE_MISSING', stage)


def _record_reference(pin: dict, records: dict, prefix: str) -> dict:
    if pin['id'] not in records:
        _fail(prefix + '_MISSING', 'UPDATE_RECORDS')
    record = records[pin['id']]
    if pin != _pin(record):
        _fail(prefix + '_PIN', 'UPDATE_RECORDS')
    return record


def _update_records(body: dict, updates: list[dict], source_keys: dict) -> None:
    for update in updates:
        _update_fields(update, source_keys)
    _unique(body['provenance'], 'PROVENANCE_DUPLICATE', 'UPDATE_RECORDS')
    provenance = {p['id']: p for p in body['provenance']}
    blobs = {b['id']: b for b in body['blobs']}
    for update in updates:
        _record_reference(update['provenance'], provenance, 'UPDATE_PROVENANCE')
        if update['evidence'] is not None:
            blob = _record_reference(update['evidence'], blobs, 'UPDATE_EVIDENCE')
            if blob['kind'] != 'UPDATE_EVIDENCE':
                _fail('UPDATE_EVIDENCE_KIND', 'UPDATE_RECORDS')


def _predecessors(updates: list[dict]) -> None:
    by_id = {update['id']: i for i, update in enumerate(updates)}
    predecessors = []
    for update in updates:
        name = update['predecessor_event_id']
        if name is not None:
            if name not in by_id:
                _fail('PREDECESSOR_MISSING', 'PREDECESSORS')
            if updates[by_id[name]]['logical_source_id'] != update['logical_source_id']:
                _fail('PREDECESSOR_LOGICAL', 'PREDECESSORS')
        predecessors.append(None if name is None else by_id[name])
    result = graph.predecessor_order(predecessors)
    if result['status'] != 'ok':
        code = 'PREDECESSOR_CYCLE' if result['error'] == 'P_CYCLE' else 'PREDECESSOR_REJECTED'
        _fail(code, 'PREDECESSORS')


def _history(body: dict, sources: list[tuple], encoded: dict) -> tuple:
    _unique(body['history'], 'HISTORY_DUPLICATE', 'HISTORY')
    originals = {key: data for _, key, data in sources}
    result, recorded = [], set()
    for record in sorted(body['history'], key=lambda r: r['id']):
        key = source._body_key(record['artifact'])
        if key not in originals:
            _fail('HISTORY_SOURCE_MISSING', 'HISTORY')
        matched = None
        if record['kind'] == 'PRIOR_COMMITTED_UPDATE':
            for name, data in encoded.items():
                if originals[key] == data:
                    matched = name
                    break
            if matched is None:
                _fail('HISTORY_EVENT_MISMATCH', 'HISTORY')
            recorded.add(matched)
        result.append(dict(id=record['id'], pin=_pin(record), kind=record['kind'],
            artifact=dict(record['artifact']), classification=record['classification'],
            related_record_ids=list(record['related_record_ids']), matched_update_id=matched))
    return result, sorted(recorded)


def _conflicts(updates: list[dict]) -> set[str]:
    result = set()
    for i, left in enumerate(updates):
        effect = left['kind'], left['new_version'], left['correction_text']
        for right in updates[i + 1:]:
            other = right['kind'], right['new_version'], right['correction_text']
            same_old = left['old_version'] == right['old_version']
            same_parent = (left['predecessor_event_id'] is not None
                and left['predecessor_event_id'] == right['predecessor_event_id']
                and left['logical_source_id'] == right['logical_source_id'])
            if effect != other and (same_old or same_parent):
                result.update((left['id'], right['id']))
    return result


def _claim_entries(claim_result: dict, indices: dict, affected: dict, conflicts: set) -> list:
    result = []
    for record in claim_result['claims']:
        node = indices[canonical(record['claim'])]
        triggers = sorted(name for name, nodes in affected.items() if node in nodes)
        result.append(dict(claim=dict(record['claim']),
            declared_preconditions='CONFLICT' if conflicts.intersection(triggers) else 'MATCH',
            change_impact='NEEDS_REVALIDATION' if triggers else 'UNCHANGED_DECLARED_CLOSURE',
            trigger_update_ids=triggers, paths=[]))
    return result


def _skeleton(claim_result: dict, entries: list, updates: list, history: list,
              recorded: list, conflicts: set) -> tuple:
    result = dict(status='ok', stage='DECLARED_IMPACT_ONLY',
        body_pin=dict(claim_result['body_pin']), claims=entries, history=history,
        already_recorded_update_ids=recorded, conflicting_update_ids=sorted(conflicts),
        updates=[dict(id=u['id'], pin=_pin(u), old_version=dict(u['old_version']),
                      status=u['status']) for u in updates],
        held_update_pin_match='MATCH', independent_custody='UNKNOWN',
        source_authentication='UNVERIFIED', update_authentication='UNVERIFIED',
        current_authority='NONE', freshness='UNKNOWN', semantic_completeness='UNPROVEN',
        full_reference_closure='NOT_EVALUATED')
    size = len(canonical(result)) + 1
    if size > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    return result, [size]


def _charge(work: list[int], amount: int = 1) -> None:
    if work[0] + amount > MAX_PATH_WORK:
        _fail('PATH_WORK_BOUND', 'PATHS')
    work[0] += amount


def _pruned(count: int, edges: list, reached: set, work: list[int]) -> list:
    _charge(work)  # Trigger setup, before allocating bounded adjacency.
    adjacency = [[] for _ in range(count)]
    for dependent, required, name in edges:
        _charge(work)  # Every candidate, including discarded dead ends.
        if dependent in reached and required in reached:
            adjacency[dependent].append((required, name))
    return adjacency


def _append_path(entry: dict, update: dict, path: list[str], size: list[int]) -> None:
    if len(entry['paths']) >= MAX_PATHS:
        _fail('PATH_LIMIT', 'PATHS')
    record = dict(trigger_update_id=update['id'], seed=dict(update['old_version']),
                  dependency_ids=list(path))
    raw = canonical(record)
    addition = len(raw) + (1 if entry['paths'] else 0)
    if len(raw) > MAX_PATH_BYTES or size[0] + addition > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    size[0] += addition
    entry['paths'].append(record)


def _walk(entry: dict, update: dict, start: int, seed: int, adjacency: list,
          work: list[int], size: list[int]) -> None:
    _charge(work)  # Initial checked frame push.
    stack, path = [(start, 0)], []
    for _ in range(MAX_PATH_WORK):  # Work counter also spans all triggers.
        if not stack:
            return
        node, cursor = stack[-1]
        if node == seed:
            _charge(work)  # Completion; a Claim is never a source node.
            if not path:
                _fail('PATH_INCONSISTENCY', 'PATHS')
            _append_path(entry, update, path, size)
        elif cursor < len(adjacency[node]):
            _charge(work, 2)  # Candidate inspection and frame advance.
            target, name = adjacency[node][cursor]
            stack[-1] = node, cursor + 1
            if len(path) >= MAX_PATH_DEPTH:
                _fail('PATH_DEPTH', 'PATHS')
            _charge(work, 2)  # Path extension and checked frame push.
            path.append(name)
            stack.append((target, 0))
            continue
        _charge(work)  # Frame pop, even after scanning an empty adjacency.
        stack.pop()
        if path:
            _charge(work)  # Backtrack current path.
            path.pop()
    _fail('PATH_WORK_BOUND', 'PATHS')


def _verify_paths(entry: dict, start: int, indices: dict, edges: list) -> None:
    by_id = {name: (dependent, target) for dependent, target, name in edges}
    for path in entry['paths']:
        node = start
        for name in path['dependency_ids']:
            if name not in by_id or by_id[name][0] != node:
                _fail('PATH_INCONSISTENCY', 'PATHS')
            node = by_id[name][1]
        if node != indices[canonical(path['seed'])]:
            _fail('PATH_INCONSISTENCY', 'PATHS')
    if {p['trigger_update_id'] for p in entry['paths']} != set(entry['trigger_update_ids']):
        _fail('PATH_INCONSISTENCY', 'PATHS')


def _paths(result: dict, indices: dict, edges: list, affected: dict,
           updates: list, size: list[int]) -> None:
    by_id = {u['id']: u for u in updates}
    for entry in result['claims']:
        work, start = [0], indices[canonical(entry['claim'])]
        for name in entry['trigger_update_ids']:
            update = by_id[name]
            seed = indices[canonical(update['old_version'])]
            adjacency = _pruned(len(indices), edges, affected[name], work)
            _walk(entry, update, start, seed, adjacency, work, size)
        _verify_paths(entry, start, indices, edges)
        entry['paths'].sort(key=lambda p: (p['dependency_ids'], p['trigger_update_id']))
    actual = len(canonical(result)) + 1
    if actual > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    if actual != size[0]:
        _fail('OUTPUT_ACCOUNTING', 'OUTPUT_BOUNDS')


def _validated_impact_details(body_raw: object, originals: object, held_update_pins: object) -> tuple:
    """Private owned bundle exposed only after the complete inherited result gate."""
    body, sources, claim_result, schema = claims._validated_claims(body_raw, originals)
    held = _held_arguments(held_update_pins)
    updates, encoded = _event_pins(body, held)
    indices, labels, source_keys = _nodes(body, claim_result)
    edges = _dependencies(body, indices, labels, source_keys)
    _reach(len(indices), edges, [], 'DEPENDENCY_DAG')
    _update_records(body, updates, source_keys)
    _predecessors(updates)
    history, recorded = _history(body, sources, encoded)
    conflicts = _conflicts(updates)
    affected = {u['id']: _reach(len(indices), edges,
        [indices[canonical(u['old_version'])]], 'REACHABILITY') for u in updates}
    entries = _claim_entries(claim_result, indices, affected, conflicts)
    result, size = _skeleton(claim_result, entries, updates, history, recorded, conflicts)
    _paths(result, indices, edges, affected, updates, size)
    return body, sources, claim_result, result, schema


def _validated_impact(body_raw: object, originals: object, held_update_pins: object) -> tuple:
    """Preserve the established private tuple and every inherited refusal."""
    body, sources, _, result, schema = _validated_impact_details(body_raw, originals, held_update_pins)
    return body, sources, result, schema


def check_declared_impact(body_raw: object, originals: object, held_update_pins: object) -> dict:
    """Verify declared impact from bytes and explicit held pins; never apply updates."""
    try:
        _, _, result, _ = _validated_impact(body_raw, originals, held_update_pins)
        return result
    except metadata.InputError as error:
        return metadata._error(error)
