"""Finite hand-derived context fixtures, no future context checker imports.

Exactly bounded developmental data: <=64 cases, <=2 Claims/Manifests, <=3 physical
originals and <=32768 Body bytes each. Canonical byte construction is not a verifier.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-context-controls-20261029')
AUTHOR = Path('/dev/shm/semantic-transport-context-bindings-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
MINIMAL = Path('/dev/shm/semantic-transport-wire-input-20261029/minimal-body.json')
CASES = []


def C(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin_file(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def pin_record(record, address=None):
    raw = C(record)
    return {'id': record['id'] if address is None else address,
            'bytes': len(raw), 'sha256': sha(raw)}


def claim_key(claim):
    raw = C(claim)
    return {'claim_id': claim['id'], 'revision': claim['revision'],
            'bytes': len(raw), 'sha256': sha(raw)}


def source_key(logical, data):
    return {'logical_source_id': logical, 'bytes': len(data), 'sha256': sha(data)}


def blob(name, kind, data, encoding='OPAQUE_BYTES'):
    return {'id': name, 'kind': kind, 'encoding': encoding, 'bytes': len(data),
            'sha256': sha(data), 'base64': base64.b64encode(data).decode('ascii')}


def add(name, rationale, error=None, stage=None, **spec):
    if len(CASES) >= 64:
        raise ValueError('fixture case budget exceeded')
    CASES.append({'id': name, 'manual_rationale': rationale, 'manual_error': error,
                  'manual_stage': stage, 'specification': spec})


add('P00_FULL_CONTEXT', 'Complete source-bound Task, Registry/Seats and unused Manifest; canonicalLF seat ordering, opaque decoded settings-array order and unsorted history-related IDs remain preserved.')
add('P01_NO_MANIFEST', 'No Manifest/Reading coverage requirement is invented.', no_manifest=True)
add('P02_SHARED_RAW_CLAIM_ID', 'Distinct revisions may share raw Claim.id and have distinct derived addresses.', claim_a=('A', 'R1'), claim_b=('A', 'R2'))
add('P03_RAW_LABEL_MATCHES_DERIVED', 'Raw Claim label may equal another Claim-derived address; it is not a generic Pin alias.', claim_b=('A:V1', 'V2'))
add('P04_PHYSICAL_KEY_ALIAS', 'Physical source aliases remain separately charged/indexed; exact Task source set collapses identical complete keys.', source_alias=True)
add('P05_SELF_CONFLICT_LABEL', 'Exact self conflict label is accepted data, no invented self prohibition.', conflict='self')
add('P06_ASYMMETRIC_CONFLICT', 'Existing target label closes without a semantic contradiction or symmetry rule.', conflict='other')
add('P07_DEFERRED_READING', 'Dangling dynamic Reading targets can be indexed but remain explicitly deferred, not qualified by index membership.', post='reading')
add('P08_OPAQUE_LATER_LOOKING_SOURCE', 'Seat evidence can bind actual opaque original bytes resembling later records; temporal origin remains UNKNOWN.', later_looking_original=True)

add('N00_CROSS_ROLE_DUPLICATE', 'Blob/Registry cross-role name collision refuses before reference use.', 'CONTEXT_ID_DUPLICATE', 'CONTEXT_IDENTITIES', prompt_id='REGISTRY')
add('N01_RAW_LABEL_COLLISION', 'Raw Claim label reserves its name against nonClaim Blob IDs.', 'CONTEXT_CLAIM_LABEL_COLLISION', 'CONTEXT_IDENTITIES', claim_a=('PROMPT', 'V1'))
add('N02_DERIVED_NONCLAIM_COLLISION', 'Derived Claim Pin address must be disjoint nonClaim addressable IDs.', 'CONTEXT_ID_DUPLICATE', 'CONTEXT_IDENTITIES', prompt_id='A:V1')
add('N03_COLON_COLLISION', 'Literal colon concatenation collision is refused, never escaped or normalized.', 'CONTEXT_ID_DUPLICATE', 'CONTEXT_IDENTITIES', claim_a=('A:B', 'C'), claim_b=('A', 'B:C'))
add('N04_DERIVED_LENGTH', 'Shape-admitted raw label can produce an overlong derived address and must refuse.', 'CONTEXT_CLAIM_PIN_ID_SHAPE', 'CONTEXT_IDENTITIES', claim_b=('B' * 32, 'V1'))
add('N05_DERIVED_EMBEDDED_LF', 'FinalLF raw Claim label is admitted upstream, but its derived address has embeddedLF and fails the original predicate.', 'CONTEXT_CLAIM_PIN_ID_SHAPE', 'CONTEXT_IDENTITIES', claim_a=('A\n', 'V1'))

add('O00_SOURCE_RECORD_ORDER', 'Source record arrays use C(id), not original caller order.', 'CONTEXT_ARRAY_ORDER', 'CONTEXT_ARRAY_ORDER', wrong_order='sources')
add('O01_FINAL_LF_RAW_ORDER', 'Raw Unicode Seat order differs from canonical JSON-byte order; only canonical C(id) is admitted.', 'CONTEXT_ARRAY_ORDER', 'CONTEXT_ARRAY_ORDER', wrong_order='seats')
add('O02_ROSTER_LABEL_ORDER', 'Roster is sorted by complete C(row), not Claim-label order.', 'CONTEXT_ARRAY_ORDER', 'CONTEXT_ARRAY_ORDER', wrong_order='rosters')
add('O03_RULE_ID_ORDER', 'Task rule-ID set still must satisfy canonical scalar-array order.', 'CONTEXT_ARRAY_ORDER', 'CONTEXT_ARRAY_ORDER', wrong_order='rule_ids')
add('O04_DEPENDENCY_ID_ORDER', 'Claim dependency IDs have explicit set-array canonical order.', 'CONTEXT_ARRAY_ORDER', 'CONTEXT_ARRAY_ORDER', wrong_order='dependency_ids')

add('S00_MANUAL_MODEL', 'Manual Seat requires null model ID; declared text does not grant recorded-model identity.', 'CONTEXT_SEAT_ORIGIN', 'CONTEXT_REGISTRY', seat_fault='manual_model')
add('S01_EXTERNAL_ASSURANCE', 'Recorded external Seat must remain UNVERIFIED.', 'CONTEXT_SEAT_ORIGIN', 'CONTEXT_REGISTRY', seat_fault='external_assurance')
add('S02_SEAT_EVIDENCE_SOURCE', 'Equal inline Registry copy cannot validate a stale body Seat evidence SourceKey.', 'CONTEXT_SEAT_EVIDENCE_SOURCE', 'CONTEXT_REGISTRY', seat_fault='source')

for suffix, mode, code in [
    ('REGISTRY', 'registry', 'REGISTRY'), ('POLICY', 'policy', 'POLICY'),
    ('RULE_SET', 'rules', 'RULE_SET'), ('CLAIM_OWNER', 'claim_owner', 'CLAIM_OWNER'),
    ('ROSTER_DUPLICATE', 'roster_duplicate', 'ROSTER_DUPLICATE'),
    ('ROSTER_MISSING', 'roster_missing', 'ROSTER_SET'),
    ('ROSTER_PIN', 'roster_pin', 'ROSTER_PIN'), ('ROSTER_SEAT', 'roster_seat', 'ROSTER_SEAT'),
    ('SOURCE_SET', 'sources', 'SOURCE_SET'), ('CONTEXT_DEPENDENCY', 'context', 'CONTEXT_DEPENDENCY')]:
    add('T_' + suffix, 'Exact sole Task binding failure; other static pins are freshly authored to the candidate Task.', 'CONTEXT_TASK_' + code, 'CONTEXT_TASK', task_fault=mode)
add('C00_CONFLICT_TARGET_MISSING', 'A conflict label must name an actual supplied exact revision.', 'CONTEXT_CLAIM_CONFLICT_MISSING', 'CONTEXT_CLAIM_CONFLICTS', conflict='missing')
for suffix, mode, code in [('MISSING', 'missing', 'MISSING'), ('TYPE', 'type', 'TYPE'),
                           ('PIN', 'pin', 'PIN'), ('KIND', 'kind', 'KIND')]:
    add('X_TASK_TEXT_' + suffix, 'Optional nonnull Task text checks missing/type/fullrecordpin/kind in fixed order.', 'CONTEXT_TASK_TEXT_' + code, 'CONTEXT_TASK_TEXT', text_fault=mode)

for suffix, mode, code in [
    ('TASK', 'task', 'TASK'), ('CLAIM', 'claim', 'CLAIM'), ('SOURCES', 'sources', 'SOURCE_SET'),
    ('SELECTOR', 'selector', 'SELECTOR_SET'), ('DEPENDENCY_CONTEXT', 'dependency', 'DEPENDENCY_SET'),
    ('REGISTRY', 'registry', 'REGISTRY'), ('RULES', 'rules', 'RULE_SET'), ('POLICY', 'policy', 'POLICY'),
    ('PROMPT_MISSING', 'prompt_missing', 'PROMPT_MISSING'),
    ('PROMPT_READING_TYPE', 'prompt_reading', 'PROMPT_TYPE'),
    ('PROMPT_STALE_ENCODING', 'prompt_encoding', 'PROMPT_PIN'),
    ('PROMPT_KIND', 'prompt_kind', 'PROMPT_KIND'),
    ('SETTINGS_MISSING', 'settings_missing', 'SETTINGS_MISSING'),
    ('SETTINGS_RUN_TYPE', 'settings_run', 'SETTINGS_TYPE'),
    ('SETTINGS_PAYLOAD_PIN', 'settings_payload', 'SETTINGS_PIN'),
    ('SETTINGS_KIND', 'settings_kind', 'SETTINGS_KIND'),
    ('UNUSED_SECOND_SETTINGS', 'second_settings', 'SETTINGS_MISSING')]:
    add('M_' + suffix, 'Every supplied Manifest closes this exact typed binding even with no Reading consumer; no postassessment substitution.', 'CONTEXT_MANIFEST_' + code, 'CONTEXT_MANIFESTS', manifest_fault=mode)


def make_claims(spec):
    a_id, a_rev = spec.get('claim_a', ('A', 'V1'))
    b_id, b_rev = spec.get('claim_b', ('B', 'V1'))
    claims = {}
    for alias, name, revision, text, deps in [
        ('A', a_id, a_rev, 'A substantially longer manually supplied opaque claim.', ['DEP_A_PRIMARY']),
        ('B', b_id, b_rev, 'B', ['DEP_B_PRIMARY', 'DEP_CONTEXT'])]:
        claims[alias] = {'id': name, 'revision': revision, 'task_view_id': 'TASK',
            'payload': {'profile': 'OPAQUE_PROSE_V1', 'text': text, 'uncertainty': '', 'omitted_scope': ''},
            'selector_ids': ['SELECTOR'], 'dependency_ids': deps,
            'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'attribution': '', 'conflict_claims': []}
    target = spec.get('conflict')
    if target:
        selected = claims['A'] if target == 'self' else claims['B']
        label = {'claim_id': selected['id'], 'revision': selected['revision']}
        if target == 'missing':
            label['revision'] = 'ABSENT_REVISION'
        claims['A']['conflict_claims'] = [label]
    if spec.get('task_fault') == 'claim_owner':
        claims['A']['task_view_id'] = 'OTHER_TASK'
    return claims


def make_sources(spec):
    main = b'Original source'
    definition = (b'{"id":"LATER_READING","record_type":"Reading","response":"later"}'
                  if spec.get('later_looking_original') else b'definition')
    originals = [('SOURCE_MAIN', source_key('MAIN', main), main),
                 ('SOURCE_DEF', source_key('DEFINITION', definition), definition)]
    if spec.get('source_alias'):
        originals.append(('SOURCE_MAIN_COPY', originals[0][1], main))
    records = [{'id': alias, 'key': key, 'media_type': 'application/octet-stream',
        'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'issuer_claim_id': None,
        'authentication': 'UNVERIFIED'} for alias, key, _ in originals]
    return originals, records


def make_seats(spec, definition_key):
    first = {'id': 'SEAT:', 'declared_label': 'Manual seat colon',
        'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'declared_model_id': None,
        'declared_family_id': 'FAMILY', 'identity_assurance': 'MANUAL_FIXTURE_ONLY',
        'identity_evidence': {'source': copy.deepcopy(definition_key), 'assertion': 'Declared illustration only'}}
    second = dict(first, id='SEAT\n', declared_label='Manual seat LF', identity_evidence=None)
    fault = spec.get('seat_fault')
    if fault == 'manual_model':
        first['declared_model_id'] = 'Claimed model'
    elif fault == 'external_assurance':
        first['origin_kind'] = 'RECORDED_EXTERNAL_ASSESSOR'
    elif fault == 'source':
        first['identity_evidence']['source']['sha256'] = '0' * 64
    return [first, second]


def make_posts(spec, claims, main_key):
    need_reading = spec.get('post') == 'reading' or spec.get('manifest_fault') == 'prompt_reading'
    need_run = spec.get('manifest_fault') == 'settings_run'
    dummy = {'id': 'DEFERRED', 'sha256': '0' * 64, 'bytes': 0}
    provenance = {'id': 'PROV', 'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE',
        'author_claim': 'Manual record', 'method': 'MANUALLY_AUTHORED_ILLUSTRATION',
        'run_evidence_id': None, 'evidence': None, 'limitations': 'UNVERIFIED', 'authentication': 'UNVERIFIED'}
    readings, runs = [], []
    if need_reading:
        readings = [{'id': 'READING', 'seat_id': 'SEAT:', 'claim': claim_key(claims['A']),
            'task_view_id': 'TASK', 'source_versions': [main_key], 'input_manifest': dummy,
            'prompt': dummy, 'settings': dummy, 'response': dummy, 'provenance': dummy,
            'stance': 'SUPPORT', 'challenge_ids': [], 'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE'}]
    if need_run:
        runs = [{'id': 'RUN', 'seat_id': 'SEAT:', 'input_manifest': dummy,
            'provider_claim': '', 'model_id_claim': '', 'family_id_claim': 'FAMILY',
            'provider_run_id_claim': None, 'prompt': dummy, 'settings': dummy, 'response': dummy,
            'raw_run_evidence': None, 'externally_pinned_eligibility_policy': None,
            'asserted_utc': None, 'verification': 'UNVERIFIED', 'independent_inputs': 'UNKNOWN'}]
    return provenance, readings, runs


def make_task(body, claims, spec, task_text):
    task = body['tasks'][0]
    task['task_text'] = pin_record(task_text)
    task['selected_sources'] = sorted({C(item['key']): item['key'] for item in body['sources']}.values(), key=C)
    task['context_dependency_ids'] = ['DEP_CONTEXT']
    seats = sorted([item['id'] for item in body['registry']['seats']], key=C)
    task['claim_rosters'] = [{'claim': claim_key(claim), 'expected_seat_ids': list(seats)} for claim in claims.values()]
    fault = spec.get('task_fault')
    if fault in ('registry', 'policy'):
        task[fault + '_id'] = 'MISSING'
    elif fault == 'rules':
        task['rule_ids'][0] = 'UNKNOWN_RULE'
    elif fault == 'roster_duplicate':
        duplicate = copy.deepcopy(task['claim_rosters'][0]); duplicate['claim']['sha256'] = '0' * 64
        task['claim_rosters'] = [task['claim_rosters'][0], duplicate]
    elif fault == 'roster_missing':
        task['claim_rosters'].pop()
    elif fault == 'roster_pin':
        task['claim_rosters'][0]['claim']['sha256'] = '0' * 64
    elif fault == 'roster_seat':
        task['claim_rosters'][0]['expected_seat_ids'] = ['MISSING_SEAT']
    elif fault == 'sources':
        task['selected_sources'].pop()
    elif fault == 'context':
        task['context_dependency_ids'] = ['MISSING_DEPENDENCY']
    text_fault = spec.get('text_fault')
    if text_fault == 'missing':
        task['task_text'] = {'id': 'MISSING_TEXT', 'sha256': '0' * 64, 'bytes': 0}
    elif text_fault == 'type':
        task['task_text'] = pin_record(body['provenance'][0])
    elif text_fault == 'pin':
        task['task_text']['sha256'] = '0' * 64
    elif text_fault == 'kind':
        task_text['kind'] = 'PROMPT'; task['task_text'] = pin_record(task_text)


def make_manifest(body, claim, name, prompt, settings):
    dependencies = {item['id']: item for item in body['dependencies']}
    selectors = {item['id']: item for item in body['selectors']}
    task = body['tasks'][0]
    return {'id': name, 'schema': 'quorum/preassessment-input/1', 'task': pin_record(task),
        'claim': claim_key(claim), 'source_versions': copy.deepcopy(task['selected_sources']),
        'selectors': [pin_record(selectors[key]) for key in claim['selector_ids']],
        'dependencies': [pin_record(dependencies[key]) for key in sorted(set(claim['dependency_ids'] + task['context_dependency_ids']), key=C) if key in dependencies],
        'registry_snapshot': copy.deepcopy(body['registry']),
        'rule_specs': [pin_record(item) for item in body['rules']], 'policy': pin_record(body['policy']),
        'prompt': pin_record(prompt), 'settings': pin_record(settings)}


def mutate_manifest(body, manifest, spec, prompt, settings):
    fault = spec.get('manifest_fault')
    if fault in ('task', 'claim', 'policy'):
        manifest[fault]['sha256'] = '0' * 64
    elif fault == 'sources':
        manifest['source_versions'].pop()
    elif fault == 'selector':
        manifest['selectors'] = [pin_record(body['provenance'][0])]
    elif fault == 'dependency':
        manifest['dependencies'] = [item for item in manifest['dependencies'] if item['id'] != 'DEP_CONTEXT']
    elif fault == 'registry':
        manifest['registry_snapshot']['seats'][0]['declared_label'] = 'Changed inline declaration'
    elif fault == 'rules':
        manifest['rule_specs'][0]['sha256'] = '0' * 64
    elif fault in ('prompt_missing', 'settings_missing', 'second_settings'):
        field = 'prompt' if fault == 'prompt_missing' else 'settings'
        manifest[field] = {'id': 'MISSING_BLOB', 'sha256': '0' * 64, 'bytes': 0}
    elif fault == 'prompt_reading':
        manifest['prompt'] = pin_record(body['readings'][0])
    elif fault == 'settings_run':
        manifest['settings'] = pin_record(body['run_evidence'][0])
    elif fault == 'prompt_encoding':
        prompt['encoding'] = 'STRICT_UTF8'
    elif fault == 'prompt_kind':
        prompt['kind'] = 'RAW_RESPONSE'; manifest['prompt'] = pin_record(prompt)
    elif fault == 'settings_payload':
        manifest['settings'] = {'id': settings['id'], 'sha256': settings['sha256'], 'bytes': settings['bytes']}
    elif fault == 'settings_kind':
        settings['kind'] = 'RAW_RESPONSE'; manifest['settings'] = pin_record(settings)


RECORD_FIELDS = {'blobs': 'Blob', 'challenges': 'Challenge', 'claims': 'Claim',
    'dependencies': 'Dependency', 'history': 'HistoryEntry', 'input_manifests': 'InputManifest',
    'provenance': 'Provenance', 'reading_withdrawals': 'ReadingWithdrawal', 'readings': 'Reading',
    'rules': 'RuleSpec', 'run_evidence': 'RunEvidence', 'selectors': 'Selector',
    'sources': 'SourceVersion', 'tasks': 'TaskView', 'updates': 'UpdateNotice'}


def sort_metadata(body):
    for field in RECORD_FIELDS:
        key = (lambda item: (C(item['id']), C(item['revision']))) if field == 'claims' else (lambda item: C(item['id']))
        body[field].sort(key=key)
    body['registry']['seats'].sort(key=lambda item: C(item['id']))
    for claim in body['claims']:
        for field in ['dependency_ids', 'selector_ids', 'conflict_claims']:
            claim[field].sort(key=C)
    for task in body['tasks']:
        for row in task['claim_rosters']:
            row['expected_seat_ids'].sort(key=C)
        for field in ['context_dependency_ids', 'rule_ids', 'selected_sources', 'claim_rosters']:
            task[field].sort(key=C)
    for manifest in body['input_manifests']:
        manifest['registry_snapshot']['seats'].sort(key=lambda item: C(item['id']))
        for field in ['dependencies', 'rule_specs', 'selectors', 'source_versions']:
            manifest[field].sort(key=C)
    for reading in body['readings']:
        for field in ['challenge_ids', 'source_versions']:
            reading[field].sort(key=C)


def assemble(spec):
    body = json.loads(MINIMAL.read_bytes())
    claims = make_claims(spec)
    originals, body['sources'] = make_sources(spec)
    main_key, def_key = originals[0][1], originals[1][1]
    body['registry']['seats'] = make_seats(spec, def_key)
    body['claims'] = list(claims.values())
    body['dependencies'] = [{'id': name, 'dependent': {'claim_id': claims[owner]['id'], 'revision': claims[owner]['revision']},
        'requires': {'kind': 'SOURCE', 'source': target}, 'role': role,
        'meaning': 'DECLARED_REVALIDATION_DEPENDENCY_ONLY'} for name, owner, target, role in [
            ('DEP_A_PRIMARY', 'A', main_key, 'SOURCE'), ('DEP_B_PRIMARY', 'B', main_key, 'SOURCE'),
            ('DEP_CONTEXT', 'B', def_key, 'CONTEXT')]]
    data = originals[0][2]
    body['selectors'] = [{'id': 'SELECTOR', 'kind': 'BYTE_SPAN_V1', 'source': main_key,
        'begin': 0, 'end': len(data), 'quote_bytes': len(data), 'quote_sha256': sha(data),
        'quote_base64': base64.b64encode(data).decode('ascii')}]
    prompt = blob(spec.get('prompt_id', 'PROMPT'), 'PROMPT', b'opaque prompt')
    settings = blob('SETTINGS', 'SETTINGS', b'["Z","A"]', 'CANONICAL_JSON')
    task_text = blob('TASK_TEXT', 'TASK_TEXT', b'Task narrative.', 'STRICT_UTF8')
    body['blobs'] = [prompt, settings, task_text]
    provenance, body['readings'], body['run_evidence'] = make_posts(spec, claims, main_key)
    body['provenance'] = [provenance]
    body['history'] = [{'id': 'HISTORY', 'kind': 'RETAINED_RAW_FIRST_OUTPUT', 'artifact': def_key,
        'related_record_ids': ['Z_RELATED', 'A_RELATED'], 'classification': 'FAILED', 'note': 'Retain original order.'}]
    make_task(body, claims, spec, task_text)
    sort_metadata(body)  # Exact Task Pin must bind already ordered complete Task.
    if not spec.get('no_manifest'):
        first = make_manifest(body, claims['A'], 'MANIFEST_A', prompt, settings)
        body['input_manifests'] = [first]
        if spec.get('manifest_fault') == 'second_settings':
            second = make_manifest(body, claims['B'], 'MANIFEST_Z', prompt, settings)
            body['input_manifests'].append(second); mutate_manifest(body, second, spec, prompt, settings)
        else:
            mutate_manifest(body, first, spec, prompt, settings)
    sort_metadata(body)
    return body, originals


def disorder(body, mode):
    if mode == 'sources':
        body['sources'].reverse()
    elif mode == 'seats':
        body['registry']['seats'].sort(key=lambda item: item['id'])
    elif mode == 'rosters':
        rows = body['tasks'][0]['claim_rosters']
        original = C(rows)
        rows.sort(key=lambda row: (C(row['claim']['claim_id']), C(row['claim']['revision'])))
        if C(rows) == original:
            raise ValueError('roster minimal pair failed to distinguish sort keys')
    elif mode == 'rule_ids':
        body['tasks'][0]['rule_ids'].reverse()
    elif mode == 'dependency_ids':
        next(item for item in body['claims'] if len(item['dependency_ids']) > 1)['dependency_ids'].reverse()


def expected_success(body, raw):
    records = []
    for record, kind in [(body['registry'], 'Registry'), (body['policy'], 'Policy')]:
        records.append(dict(pin_record(record), record_type=kind))
    records += [dict(pin_record(record), record_type='Seat') for record in body['registry']['seats']]
    for field, kind in RECORD_FIELDS.items():
        for record in body[field]:
            address = record['id'] + ':' + record['revision'] if kind == 'Claim' else record['id']
            records.append(dict(pin_record(record, address), record_type=kind))
    records.sort(key=lambda item: C(item['id']))
    seats = [{'seat_id': item['id'], 'source': None if item['identity_evidence'] is None else item['identity_evidence']['source'],
        'typed_binding': 'ABSENT' if item['identity_evidence'] is None else 'MATCH_SUPPLIED_ORIGINAL',
        'temporal_origin': 'UNKNOWN', 'authentication': 'UNVERIFIED'} for item in body['registry']['seats']]
    return {'status': 'ok', 'stage': 'CONTEXT_BINDINGS_ONLY', 'body_pin': {'bytes': len(raw), 'sha256': sha(raw)},
        'records': records, 'registry': {'pin': pin_record(body['registry']), 'binding': 'MATCH_STATIC_DECLARATIONS_ONLY'},
        'task': {'pin': pin_record(body['tasks'][0]), 'binding': 'MATCH_EXACT_TASK_CONTEXT_ONLY'}, 'seat_evidence': seats,
        'manifests': [{'pin': pin_record(item), 'claim': item['claim'], 'binding': 'MATCH_PREASSESSMENT_TYPED_CONTEXT_ONLY'} for item in body['input_manifests']],
        'source_authentication': 'UNVERIFIED', 'current_authority': 'NONE', 'freshness': 'UNKNOWN',
        'independent_inputs': 'UNKNOWN', 'semantic_completeness': 'UNPROVEN',
        'external_record_pin_match': 'NOT_EVALUATED', 'full_reference_closure': 'NOT_EVALUATED',
        'deferred_gates': ['AGGREGATION', 'BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST', 'CHALLENGE_WITHDRAWAL', 'READING_RUN_PROVENANCE']}


for case in CASES:
    body, originals = assemble(case['specification'])
    disorder(body, case['specification'].get('wrong_order'))
    raw = C(body)
    if len(raw) > 32768 or len(originals) > 3 or len(body['claims']) > 2 or len(body['input_manifests']) > 2:
        raise ValueError('candidate fixture budget exceeded')
    path = OUT / 'raw' / (case['id'] + '.body.json')
    with path.open('xb') as stream:
        stream.write(raw)
    case['body_raw'] = pin_file(path)
    case['originals_exact_tuple_recipe'] = [{'alias': alias, 'key': key, 'immutable_bytes_hex': data.hex()} for alias, key, data in originals]
    case['held_update_pins_exact_tuple_recipe'] = {'outer': 'exact_tuple', 'items': []}
    case['handwritten_expected_complete_result'] = ({'status': 'error', 'stage': case['manual_stage'], 'error': case['manual_error']}
        if case['manual_error'] else expected_success(body, raw))

source_paths = [AUTHOR / 'contract.json', AUTHOR / 'design-addendum.json', MINIMAL, OUT / 'prepare.py']
source_paths += [ROOT / 'tools' / name for name in ['transport_quorum_input.py', 'transport_quorum_shape.py',
    'transport_quorum_source.py', 'transport_quorum_claim.py', 'transport_quorum_impact.py', 'transport_quorum_body.schema.json']]
result = {'classification': 'PRE_PRODUCT_PRE_ORACLE_HANDWRITTEN_CONTEXT_EXPECTATIONS',
    'future_context_checker_inspected_or_executed': False, 'source_pins': [pin_file(path) for path in source_paths],
    'cases': CASES, 'qualification': 'Internal exact typed context only. Full success projections derive from authored complete records/pins, not future checker outputs. Dynamic/postassessment fields remain deferred; opaque contents cannot prove temporal origin, authentication, independence, truth, completeness or full replay acceptance.'}
path = OUT / 'handwritten-expectations.json'
with path.open('xb') as stream:
    stream.write(C(result))
freeze = {'phase': 'PRE_PRODUCT_PRE_ORACLE_FROZEN', 'expectations': pin_file(path),
    'source_pins': result['source_pins'], 'candidates': [case['body_raw'] for case in CASES]}
path = OUT / 'pre-oracle-freeze.json'
with path.open('xb') as stream:
    stream.write(C(freeze))
print(json.dumps({'cases': len(CASES), 'freeze': pin_file(path)}))
