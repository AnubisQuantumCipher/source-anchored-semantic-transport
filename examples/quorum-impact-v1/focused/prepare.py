"""Bounded hand-derived impact fixtures; no future checker import/execution.

At most40 cases,16 Claims,64 Dependency records,8 valid notices. One host-argument
count probe intentionally supplies9 held entries. Expected paths/triggers/conflicts
are authored from explicit tiny labeled graphs, never from a product algorithm.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-impact-controls-20261029')
AUTHOR = Path('/dev/shm/semantic-transport-impact-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
MINIMAL = Path('/dev/shm/semantic-transport-wire-input-20261029/minimal-body.json')
CASES = []


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def record_pin(value, id_field='id'):
    raw = encoded(value)
    return {'id': value[id_field], 'bytes': len(raw), 'sha256': sha(raw)}


def source_key(logical, raw):
    return {'logical_source_id': logical, 'sha256': sha(raw), 'bytes': len(raw)}


SOURCES = {'O': ('OLD', 'SECTION', b'old'), 'N': ('NEW', 'SECTION', b'new'),
           'X': ('OTHER', 'OTHER', b'unrelated')}
KEYS = {name: source_key(logical, raw) for name, (_, logical, raw) in SOURCES.items()}
BASE_EDGES = [('A', 'D_A_OLD', 'SOURCE', 'O'), ('B', 'D_B_A', 'CLAIM', 'A'),
              ('C', 'D_C_OTHER', 'SOURCE', 'X')]
BASE_PATHS = {'A': [['D_A_OLD']], 'B': [['D_B_A', 'D_A_OLD']], 'C': []}
PROVENANCE = {'id': 'PROV', 'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE',
    'author_claim': 'Manual control', 'method': 'MANUALLY_AUTHORED_ILLUSTRATION',
    'run_evidence_id': None, 'evidence': None, 'limitations': 'Unverified illustration',
    'authentication': 'UNVERIFIED'}


def event(name='U1', kind='REPLACEMENT', old='O', new='N', predecessor=None,
          correction=None):
    return {'id': name, 'kind': kind, 'logical_source_id': KEYS[old]['logical_source_id'],
        'old_version': KEYS[old], 'new_version': KEYS[new] if new else None,
        'predecessor_event_id': predecessor, 'issuer_claim_id': 'ISSUER',
        'provenance': record_pin(PROVENANCE), 'evidence': None,
        'correction_text': correction, 'status': 'INFORMATIONAL_QUARANTINED'}


def add(name, rationale, error=None, stage=None, **spec):
    if len(CASES) >= 40:
        raise ValueError('case budget exceeded')
    CASES.append({'id': name, 'manual_rationale': rationale, 'manual_error': error,
                  'manual_stage': stage, 'specification': spec})


add('I00_NO_NOTICES', 'No declared update seeds: every complete declared closure unchanged.', events=[], triggers=[])
add('I01_CHAIN', 'Old-source replacement reaches A directly and B through labeled Claim dependency; C stays unchanged.')
add('I02_WITHDRAWAL', 'Withdrawal remains an informational old-version seed, not source deletion or truth negation.', events=[event(kind='WITHDRAWAL', new=None)])
add('I03_IDENTICAL_EFFECT_IDS', 'Identical effects with distinct event IDs do not conflict or disappear; each ID retains a labeled path.', events=[event('U1'), event('U2')], triggers=['U1', 'U2'])
add('I04_CONFLICT', 'Replacement and withdrawal of identical old key conflict; affected Claims require revalidation with CONFLICT.', events=[event('U1'), event('U2', kind='WITHDRAWAL', new=None)], triggers=['U1', 'U2'], conflicts=['U1', 'U2'])
add('I05_SAME_OLD_DIFFERENT_PREDECESSORS', 'Different predecessors do not suppress conflict for identical old key and different effect. Identical root withdrawals retain their own IDs but do not reach old-source Claims.', events=[event('R1', kind='WITHDRAWAL', old='N', new=None), event('R2', kind='WITHDRAWAL', old='N', new=None), event('U1', predecessor='R1'), event('U2', kind='WITHDRAWAL', new=None, predecessor='R2')], triggers=['U1', 'U2'], conflicts=['U1', 'U2'])
parallel = [('A', 'D_A_OLD_X', 'SOURCE', 'O'), ('A', 'D_A_OLD_Y', 'SOURCE', 'O'), ('B', 'D_B_A', 'CLAIM', 'A'), ('C', 'D_C_OTHER', 'SOURCE', 'X')]
parallel_paths = {'A': [['D_A_OLD_X'], ['D_A_OLD_Y']], 'B': [['D_B_A', 'D_A_OLD_X'], ['D_B_A', 'D_A_OLD_Y']], 'C': []}
add('I06_PARALLEL_LABELS', 'Parallel endpoint edges retain distinct Dependency-ID path evidence.', edges=parallel, paths=parallel_paths)
add('I07_PHYSICAL_SOURCE_ALIAS', 'Equal physical source copies count separately at source boundary but produce one complete-key graph node, no duplicate path.', source_alias_copy=True)
add('H00_PRIOR_EVENT', 'Exact prior-event bytes identify already-recorded ID while that event remains a normal impact seed.', history_mode='prior')
add('H01_REPEATED_PRIOR', 'Two distinct history records preserve both IDs; already-recorded event ID set remains unique.', history_mode='twice')
add('H02_OPAQUE_HISTORY_ORDER', 'Non-event history artifact stays opaque; classification and related_record_ids original order are preserved.', history_mode='opaque')
add('H03_HISTORY_SOURCE_MISSING', 'A history SourceKey cannot be resolved from a label alone.', error='IMPACT_HISTORY_SOURCE_MISSING', stage='IMPACT_HISTORY', history_mode='missing')
add('H04_HISTORY_EVENT_MISMATCH', 'Correctly self-bound artifact bytes unequal to canonical supplied events cannot claim prior update identity.', error='IMPACT_HISTORY_EVENT_MISMATCH', stage='IMPACT_HISTORY', history_mode='mismatch')
add('P00_PIN_SET_MISSING', 'Separately supplied event pin set may not be filled from candidate UpdateNotice.', error='IMPACT_PIN_SET', stage='IMPACT_EVENT_PINS', held_mode='missing')
add('P01_PIN_DIGEST', 'Every complete canonical event byte string must match its separately frozen held pin.', error='IMPACT_UPDATE_PIN', stage='IMPACT_EVENT_PINS', held_mode='digest')
add('P02_PIN_BOOL_LENGTH', 'Bool is not a builtin integer byte_length.', error='IMPACT_PIN_TYPE', stage='IMPACT_PIN_ARGUMENTS', held_mode='bool')
add('P03_PIN_COUNT_BEFORE_ITEMS', 'Held count above8 refuses before examining malformed items.', error='IMPACT_PIN_COUNT', stage='IMPACT_PIN_ARGUMENTS', held_mode='count')
add('P04_FINAL_LF_EVENT_ID', 'Candidate and separately held event ID preserve pinned finalLF pattern-search semantics; no stronger fullmatch.', events=[event('U1\n')], triggers=['U1\n'])
add('P05_PIN_LENGTH_BOUND', 'Builtin integer above held byte_length cap is a shape/range refusal before event-pin matching.', error='IMPACT_PIN_SHAPE', stage='IMPACT_PIN_ARGUMENTS', held_mode='length_over')
add('D00_DEPENDENCY_CYCLE', 'Every graph component is checked, with no seed-dependent cycle bypass.', error='IMPACT_DEPENDENCY_CYCLE', stage='IMPACT_DEPENDENCY_DAG', edges=[('A', 'D_A_B', 'CLAIM', 'B'), ('B', 'D_B_A', 'CLAIM', 'A'), ('C', 'D_C_OTHER', 'SOURCE', 'X')])
add('D01_CLAIM_TARGET_MISSING', 'CLAIM target needs an actual id/revision, not only a well-shaped ClaimKey.', error='IMPACT_CLAIM_TARGET_MISSING', stage='IMPACT_DEPENDENCIES', missing_claim_target=True)
add('D02_CLAIM_TARGET_PIN', 'A supplied label with wrong complete canonical Claim digest is refused.', error='IMPACT_CLAIM_TARGET_PIN', stage='IMPACT_DEPENDENCIES', wrong_claim_pin=True)
add('D03_SOURCE_TARGET_MISSING', 'Unused source-target dependency cannot be silently ignored.', error='IMPACT_SOURCE_TARGET_MISSING', stage='IMPACT_DEPENDENCIES', missing_source_target=True)
add('U00_PREDECESSOR_MISSING', 'Missing predecessor must not become a root.', error='IMPACT_PREDECESSOR_MISSING', stage='IMPACT_PREDECESSORS', events=[event(predecessor='MISSING')])
add('U01_SELF_PREDECESSOR', 'Symbolic self predecessor is a real finite canonical fixture and must refuse cycle.', error='IMPACT_PREDECESSOR_CYCLE', stage='IMPACT_PREDECESSORS', events=[event(predecessor='U1')])
bad_logical = event()
bad_logical['logical_source_id'] = 'OTHER'
add('U02_OLD_LOGICAL', 'Old SourceKey logical identity must equal notice logical_source_id.', error='IMPACT_UPDATE_LOGICAL', stage='IMPACT_UPDATE_RECORDS', events=[bad_logical])
add('E00_COMPLETE_BLOB_PIN', 'Evidence pin binds complete canonical UPDATE_EVIDENCE Blob record, not decoded payload.', evidence_mode='valid')
add('E01_STALE_KIND_PIN', 'Changing Blob kind with same valid payload invalidates its held record pin before kind classification.', error='IMPACT_UPDATE_EVIDENCE_PIN', stage='IMPACT_UPDATE_RECORDS', evidence_mode='stale_kind')
add('E02_STALE_ENCODING_PIN', 'Changing Blob encoding with same valid payload invalidates complete record pin.', error='IMPACT_UPDATE_EVIDENCE_PIN', stage='IMPACT_UPDATE_RECORDS', evidence_mode='stale_encoding')
add('E03_WRONG_KIND_FRESH_PIN', 'Even a correct complete record pin cannot make PROMPT an UPDATE_EVIDENCE record.', error='IMPACT_UPDATE_EVIDENCE_KIND', stage='IMPACT_UPDATE_RECORDS', evidence_mode='wrong_kind')
wide_edges = [('A', 'D_A_OLD_' + str(i), 'SOURCE', 'O') for i in range(8)]
wide_edges += [('B', 'D_B_A_' + str(i), 'CLAIM', 'A') for i in range(8)]
wide_edges += [('C', 'D_C_OTHER', 'SOURCE', 'X')]
wide_paths = {'A': [['D_A_OLD_' + str(i)] for i in range(8)],
    'B': [['D_B_A_' + str(i), 'D_A_OLD_' + str(j)] for i in range(8) for j in range(8)], 'C': []}
add('B00_PATH_LIMIT_INCLUSIVE', 'Explicit bounded labeled path table at inclusive per-Claim cap remains complete.', edges=wide_edges, paths=wide_paths)
add('B01_PATH_LIMIT_ALL_TRIGGERS', 'Repeated identical-effect notices retain trigger identity; discovery beyond per-Claim path cap across both triggers refuses without prefix.', error='IMPACT_PATH_LIMIT', stage='IMPACT_PATHS', edges=wide_edges, paths=wide_paths, events=[event('U1'), event('U2')], triggers=['U1', 'U2'])


def create_claims(edges):
    claims = []
    for name in ['A', 'B', 'C']:
        claims.append({'id': name, 'revision': 'V1', 'task_view_id': 'TASK',
            'payload': {'profile': 'OPAQUE_PROSE_V1', 'text': 'Manual ' + name,
                        'uncertainty': '', 'omitted_scope': ''},
            'selector_ids': [], 'dependency_ids': [edge[1] for edge in edges if edge[0] == name],
            'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'attribution': '', 'conflict_claims': []})
    keys = {claim['id']: {'claim_id': claim['id'], 'revision': 'V1',
        'sha256': sha(encoded(claim)), 'bytes': len(encoded(claim))} for claim in claims}
    return claims, keys


def create_dependencies(spec, edges, claim_keys):
    records = []
    for owner, name, kind, target in edges:
        requirement = {'kind': kind, 'source' if kind == 'SOURCE' else 'claim':
                       KEYS[target] if kind == 'SOURCE' else claim_keys[target]}
        records.append({'id': name, 'dependent': {'claim_id': owner, 'revision': 'V1'},
            'requires': copy.deepcopy(requirement), 'role': 'CONTEXT',
            'meaning': 'DECLARED_REVALIDATION_DEPENDENCY_ONLY'})
    by_id = {item['id']: item for item in records}
    if spec.get('missing_claim_target'):
        by_id['D_B_A']['requires']['claim'].update(claim_id='ABSENT', sha256='0' * 64, bytes=0)
    if spec.get('wrong_claim_pin'):
        by_id['D_B_A']['requires']['claim']['sha256'] = '0' * 64
    if spec.get('missing_source_target'):
        by_id['D_C_OTHER']['requires']['source'] = {'logical_source_id': 'ABSENT', 'sha256': '0' * 64, 'bytes': 0}
    return records


def create_events(spec):
    events = copy.deepcopy(spec.get('events', [event()]))
    blobs = []
    mode = spec.get('evidence_mode')
    if mode:
        data = b'evidence'
        blob = {'id': 'EVIDENCE', 'kind': 'UPDATE_EVIDENCE', 'encoding': 'OPAQUE_BYTES',
            'base64': base64.b64encode(data).decode('ascii'), 'bytes': len(data), 'sha256': sha(data)}
        evidence_pin = record_pin(blob)
        if mode in ('stale_kind', 'wrong_kind'):
            blob['kind'] = 'PROMPT'
        if mode == 'stale_encoding':
            blob['encoding'] = 'STRICT_UTF8'
        if mode == 'wrong_kind':
            evidence_pin = record_pin(blob)
        blobs = [blob]
        events[0]['evidence'] = evidence_pin
    return events, blobs


def create_history(spec, events, originals):
    mode = spec.get('history_mode')
    if not mode:
        return []
    data = encoded(events[0]) if mode in ('prior', 'twice') else b'opaque retained first output'
    artifact = source_key('HISTORY_ARTIFACT', data)
    if mode != 'missing':
        originals.append(('HISTORY_SOURCE', artifact, data))
    prior = mode in ('prior', 'twice', 'mismatch')
    entry = {'id': 'HISTORY_1', 'kind': 'PRIOR_COMMITTED_UPDATE' if prior else 'RETAINED_RAW_FIRST_OUTPUT',
        'artifact': artifact, 'related_record_ids': ['Z_RELATED', 'A_RELATED'],
        'classification': 'FAILED', 'note': 'Preserve exact non-authoritative history.'}
    return [entry, dict(entry, id='HISTORY_2')] if mode == 'twice' else [entry]


def held_recipe(spec, events):
    items = [{'event_id': item['id'], 'sha256': sha(encoded(item)), 'byte_length': len(encoded(item))} for item in events]
    mode = spec.get('held_mode')
    if mode == 'missing':
        items = []
    elif mode == 'digest':
        items[0]['sha256'] = '0' * 64
    elif mode == 'bool':
        items[0]['byte_length'] = True
    elif mode == 'length_over':
        items[0]['byte_length'] = 65537
    elif mode == 'count':
        return {'outer': 'exact_tuple', 'items': [None] * 9}
    return {'outer': 'exact_tuple', 'items': items}


def expected_success(spec, body, raw, keys):
    events = {item['id']: item for item in body['updates']}
    triggers = spec.get('triggers', ['U1'])
    conflicts = spec.get('conflicts', [])
    paths = spec.get('paths', BASE_PATHS)
    claims = []
    for name in ['A', 'B', 'C']:
        fired = sorted(triggers) if name in ('A', 'B') else []
        records = [{'trigger_update_id': trigger, 'seed': events[trigger]['old_version'],
            'dependency_ids': vector} for trigger in fired for vector in paths[name]]
        records.sort(key=lambda item: (item['dependency_ids'], item['trigger_update_id']))
        claims.append({'claim': keys[name],
            'declared_preconditions': 'CONFLICT' if any(item in conflicts for item in fired) else 'MATCH',
            'change_impact': 'NEEDS_REVALIDATION' if fired else 'UNCHANGED_DECLARED_CLOSURE',
            'trigger_update_ids': fired, 'paths': records})
    histories = []
    recorded = []
    for item in sorted(body['history'], key=lambda entry: entry['id']):
        matched = body['updates'][0]['id'] if item['kind'] == 'PRIOR_COMMITTED_UPDATE' else None
        if matched is not None:
            recorded.append(matched)
        histories.append({key: item[key] for key in ['id', 'kind', 'artifact', 'classification', 'related_record_ids']})
        histories[-1].update(pin=record_pin(item), matched_update_id=matched)
    return {'status': 'ok', 'stage': 'DECLARED_IMPACT_ONLY', 'body_pin': {'bytes': len(raw), 'sha256': sha(raw)},
        'claims': claims, 'updates': [{'id': item['id'], 'pin': record_pin(item),
            'old_version': item['old_version'], 'status': 'INFORMATIONAL_QUARANTINED'} for item in sorted(body['updates'], key=lambda entry: entry['id'])],
        'conflicting_update_ids': sorted(conflicts), 'already_recorded_update_ids': sorted(set(recorded)),
        'history': histories, 'held_update_pin_match': 'MATCH', 'independent_custody': 'UNKNOWN',
        'update_authentication': 'UNVERIFIED', 'source_authentication': 'UNVERIFIED',
        'current_authority': 'NONE', 'freshness': 'UNKNOWN', 'semantic_completeness': 'UNPROVEN',
        'full_reference_closure': 'NOT_EVALUATED'}


for row in CASES:
    spec = row['specification']
    edges = spec.get('edges', BASE_EDGES)
    claims, claim_keys = create_claims(edges)
    dependencies = create_dependencies(spec, edges, claim_keys)
    events, blobs = create_events(spec)
    originals = [(alias, KEYS[name], data) for name, (alias, _, data) in SOURCES.items()]
    if spec.get('source_alias_copy'):
        originals.append(('OLD_COPY', KEYS['O'], SOURCES['O'][2]))
    history = create_history(spec, events, originals)
    body = json.loads(MINIMAL.read_bytes())
    body.update(claims=claims, dependencies=dependencies, updates=events, history=history,
        provenance=[copy.deepcopy(PROVENANCE)], blobs=blobs,
        sources=[{'id': alias, 'key': key, 'media_type': 'application/octet-stream',
            'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'issuer_claim_id': None,
            'authentication': 'UNVERIFIED'} for alias, key, _ in originals])
    body['tasks'][0]['selected_sources'] = list({encoded(key): key for _, key, _ in originals}.values())
    body['tasks'][0]['claim_rosters'] = [{'claim': claim_keys[name], 'expected_seat_ids': []} for name in ['A', 'B', 'C']]
    raw = encoded(body)
    if len(raw) > 32768 or len(dependencies) > 64 or len(claims) > 16:
        raise ValueError('fixture budget exceeded')
    path = OUT / 'raw' / (row['id'] + '.body.json')
    with path.open('xb') as stream:
        stream.write(raw)
    row['body_raw'] = pin(path)
    row['originals_exact_tuple_recipe'] = [{'alias': alias, 'key': key, 'immutable_bytes_hex': data.hex()} for alias, key, data in originals]
    row['held_update_pins_exact_tuple_recipe'] = held_recipe(spec, events)
    row['handwritten_expected_complete_result'] = ({'status': 'error', 'stage': row['manual_stage'], 'error': row['manual_error']}
        if row['manual_error'] else expected_success(spec, body, raw, claim_keys))

source_paths = [AUTHOR / 'contract.json', MINIMAL, OUT / 'prepare.py']
source_paths += [ROOT / 'tools' / name for name in ['transport_quorum_source.py', 'transport_quorum_claim.py',
    'transport_quorum_input.py', 'transport_quorum_shape.py', 'transport_quorum_graph.py', 'transport_quorum_body.schema.json']]
result = {'schema': 'quorum/handwritten-declared-impact-controls/1',
    'classification': 'PRE_PRODUCT_PRE_ORACLE_MANUAL_EXPECTATIONS',
    'future_impact_implementation_inspected_or_executed': False,
    'source_pins': [pin(path) for path in source_paths], 'cases': CASES,
    'custody_qualification': 'Pins are authored developmental fixtures, frozen separately before product execution; matching cannot establish independent custody. Missing-pin controls are never filled from candidate at runtime.',
    'bound_qualification': 'Publicly unreachable32-node/32-edge-path boundaries are not falsely tested via malformed larger Bodies. Explicit path vectors and trigger assignments are handwritten from finite labeled graphs; no future checker output used.'}
path = OUT / 'handwritten-expectations.json'
with path.open('xb') as stream:
    stream.write(encoded(result))
freeze = {'phase': 'PRE_PRODUCT_PRE_ORACLE_FROZEN', 'expectations': pin(path),
    'source_pins': result['source_pins'], 'candidates': [row['body_raw'] for row in CASES]}
path = OUT / 'pre-oracle-freeze.json'
with path.open('xb') as stream:
    stream.write(encoded(freeze))
print(json.dumps({'cases': len(CASES), 'freeze': pin(path)}))
