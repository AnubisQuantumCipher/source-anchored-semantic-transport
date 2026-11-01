"""Finite handwritten claim-structure pairs, before new implementation inspection.

TEST-ONLY fixture construction, not a claim checker. At most64 cases, one Claim
each, at most3 source/selector/dependency entries, at most32768 raw Body bytes.
All semantic/error expectations are authored below before any oracle run.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-claim-structure-controls-20261029')
AUTHOR = Path('/dev/shm/semantic-transport-claim-structure-20261029')
WIRE = Path('/dev/shm/semantic-transport-wire-20261029/revision-02')
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


def guard(nodes, root=None):
    return {'nodes': nodes, 'root': len(nodes) - 1 if root is None else root}


TRUE = guard([{'op': 'TRUE'}])
FALSE = guard([{'op': 'FALSE'}])
BASE_STATEMENT = {'subject': 'TENANT', 'action': 'DISCLOSE_INFORMATION',
    'modality': 'MUST_NOT', 'condition': TRUE, 'exception': FALSE}
TARGET_RAW = b'bounded definition fixture'
TARGET_KEY = {'logical_source_id': 'DEFINITION', 'sha256': sha(TARGET_RAW),
              'bytes': len(TARGET_RAW)}
REF = guard([{'op': 'REF', 'target': TARGET_KEY}])
ROOT_BAD = guard([{'op': 'TRUE'}, {'op': 'FALSE'}], 0)
ORDER_BAD = guard([{'op': 'NOT', 'operand': 0}])
UNREACHABLE = guard([{'op': 'TRUE'}, {'op': 'FALSE'}])


def statement(**changes):
    result = copy.deepcopy(BASE_STATEMENT)
    result.update(copy.deepcopy(changes))
    return result


def add(name, interpretation, rationale, error=None, stage=None, **spec):
    if len(CASES) >= 64:
        raise ValueError('case budget exceeded')
    CASES.append({'id': name, 'manual_interpretation': interpretation,
        'manual_rationale': rationale, 'manual_error': error, 'manual_stage': stage,
        'specification': spec})


MATCH = 'MATCHED_DECLARATION_STRUCTURE_ONLY'
DIFFERS = 'DIFFERS_DECLARATION_STRUCTURE_ONLY'
SCOPE = 'UNRESOLVED_INSUFFICIENT_SCOPE'
MISSING = 'NOT_CHECKED_MISSING_EVIDENCE'
OPAQUE = 'UNRESOLVED_UNSUPPORTED_PROFILE'

add('E00_EXACT', MATCH, 'All five complete statement fields match exactly.')
add('E01_ACTOR_CHANGED', DIFFERS, 'Subject actor is changed without source change.', claim_statement=statement(subject='LANDLORD'))
add('E02_ACTION_CHANGED', DIFFERS, 'Action changes without source change.', claim_statement=statement(action='SHARE_INFORMATION'))
add('E03_MODALITY_MAY', DIFFERS, 'MUST_NOT and MAY are distinct declared modalities.', claim_statement=statement(modality='MAY'))
add('E04_NEGATION_REMOVED', DIFFERS, 'Removing NOT from modality cannot preserve exact statement structure.', claim_statement=statement(modality='MUST'))
add('E05_EXCEPTION_CHANGED', DIFFERS, 'Exception graph is a required compared field, never dropped.', claim_statement=statement(exception=TRUE))
add('E06_NOT_NODE', DIFFERS, 'Replacing leaf TRUE with NOT(FALSE) changes syntax; no Boolean evaluation is used.', claim_statement=statement(condition=guard([{'op': 'FALSE'}, {'op': 'NOT', 'operand': 0}])))
ordered = guard([{'op': 'TRUE'}, {'op': 'FALSE'}, {'op': 'AND', 'left': 0, 'right': 1}])
reversed_operands = guard([{'op': 'TRUE'}, {'op': 'FALSE'}, {'op': 'AND', 'left': 1, 'right': 0}])
add('E07_OPERAND_ORDER', DIFFERS, 'Operand order is exact data; no commutative rewrite.', source_statement=statement(condition=ordered), claim_statement=statement(condition=reversed_operands))
shared = guard([{'op': 'TRUE'}, {'op': 'AND', 'left': 0, 'right': 0}])
copied = guard([{'op': 'TRUE'}, {'op': 'TRUE'}, {'op': 'AND', 'left': 0, 'right': 1}])
add('E08_REPETITION', DIFFERS, 'Repeated operands and duplicated leaf nodes remain distinct complete graph structures.', source_statement=statement(condition=shared), claim_statement=statement(condition=copied))
add('E09_CLAIM_EXCEPTION_ABSENT', None, 'Missing Claim exception is inherited closed-Body shape refusal.', error='INPUT_CLOSED_SCHEMA', stage='SCHEMA', claim_remove_exception=True)
add('E10_SOURCE_EXCEPTION_ABSENT', None, 'Missing source exception refuses DeclarationSource shape; no default FALSE.', error='DECLARATION_SCHEMA', stage='DECLARATION_INPUT', source_remove_exception=True)
add('E11_SOURCE_EXTRA_FIELD', None, 'Additional Statement member is rejected by closed source schema.', error='DECLARATION_SCHEMA', stage='DECLARATION_INPUT', source_extra_field=True)
add('E12_FINAL_LF_ID', MATCH, 'Pinned identifier pattern-search admits final LF in equal source and Claim subject; no stronger fullmatch invented.', source_statement=statement(subject='TENANT\n'), claim_statement=statement(subject='TENANT\n'))
add('E13_ACTOR_ACTION_SWAPPED', DIFFERS, 'Subject and action positions remain distinct despite both being identifiers.', claim_statement=statement(subject='DISCLOSE_INFORMATION', action='TENANT'))

for suffix, bad_guard, code in [('ROOT', ROOT_BAD, 'ROOT'), ('ORDER', ORDER_BAD, 'ORDER'), ('UNREACHABLE', UNREACHABLE, 'UNREACHABLE')]:
    add('G_CLAIM_' + suffix, None, 'Claim guard law failure precedes comparison.', error='CLAIM_GUARD_' + code, stage='CLAIM_GUARDS', claim_statement=statement(condition=bad_guard))
    add('G_SOURCE_' + suffix, None, 'Source guard law failure remains mandatory even when subject already differs.', error='DECLARATION_GUARD_' + code, stage='DECLARATION_GUARDS', source_statement=statement(condition=bad_guard), claim_statement=statement(subject='LANDLORD'))

add('O00_IDENTICAL_TEXT', OPAQUE, 'Opaque text exactly reproduces source JSON bytes but is never a structural profile.', opaque=True, opaque_exact_source_text=True)
add('O01_INVALID_SOURCE_OPAQUE', OPAQUE, 'Opaque original invalidUTF8 stays uninterpreted under opaque Claim profile.', opaque=True, source_raw_hex='ff')

add('S00_NO_SELECTOR', None, 'Owner correction preserves pinned exactly-one selector gate: zero refuses.', error='CLAIM_SELECTOR_CARDINALITY', stage='CLAIM_SCOPE', selector_mode='none')
add('S01_PARTIAL_MATCH', SCOPE, 'One partial matching selector is insufficient full-source scope.', selector_mode='partial')
add('S02_PARTIAL_DIFFERS', SCOPE, 'Partial scope is classified before quote DIFFERS.', selector_mode='partial_differs')
add('S03_FULL_DIFFERS', MISSING, 'Full nonempty scope with correctly self-bound unequal quote supplies no matching evidence.', selector_mode='differs')
add('S04_TWO_SELECTORS', None, 'Two full selectors must refuse cardinality; never select one.', error='CLAIM_SELECTOR_CARDINALITY', stage='CLAIM_SCOPE', selector_mode='two')
add('S05_EMPTY_SOURCE', SCOPE, 'Empty-source nonprobative match cannot qualify a structural declaration.', source_raw_hex='')
add('S06_EMPTY_SOURCE_DIFFERS', SCOPE, 'Empty source plus self-bound nonempty quote remains insufficient scope before DIFFERS gate.', source_raw_hex='', selector_mode='empty_differs')
add('S07_MALFORMED_SOURCE', None, 'Full matching declared structural original cannot fall back to opaque after parse failure.', error='DECLARATION_CANONICAL_JSON', stage='DECLARATION_INPUT', source_raw_hex='6e6f74204a534f4e')
add('S08_SOURCE_FINAL_LF', None, 'Full matching original with noncanonical finalLF refuses canonical declaration input.', error='DECLARATION_CANONICAL_JSON', stage='DECLARATION_INPUT', source_append_lf=True)
add('S09_SOURCE_SCALAR_ROOT', None, 'Canonical JSON null is not the closed DeclarationSource object.', error='DECLARATION_SCHEMA', stage='DECLARATION_INPUT', source_raw_hex='6e756c6c')

for role in ['SOURCE', 'DEFINITION', 'EXCEPTION', 'CONTEXT', 'TASK_CONDITION']:
    add('R_ROLE_' + role, MATCH, 'Any schema role binds exact REF identity only; semantic role relevance remains UNPROVEN.', claim_ref=True, source_ref=True, ref_dependency=True, target_supplied=True, ref_role=role)
add('R05_CLAIM_EDGE_MISSING', None, 'Claim REF needs its own explicit exact SOURCE-target edge even if statements differ.', error='CLAIM_REF_DEPENDENCY_MISSING', stage='CLAIM_REF_DEPENDENCIES', claim_ref=True, target_supplied=True)
add('R06_SOURCE_EDGE_MISSING', None, 'Parsed source REF closure cannot be bypassed by earlier structural difference.', error='DECLARATION_REF_DEPENDENCY_MISSING', stage='DECLARATION_REF_DEPENDENCIES', source_ref=True, target_supplied=True)
add('R07_CLAIM_TARGET_MISSING', None, 'Declared Claim REF edge without verified target source refuses separately.', error='CLAIM_REF_SOURCE_MISSING', stage='CLAIM_REF_DEPENDENCIES', claim_ref=True, source_ref=True, ref_dependency=True)
add('R08_SOURCE_TARGET_MISSING', None, 'Declared source REF edge without supplied target refuses after parsing.', error='DECLARATION_REF_SOURCE_MISSING', stage='DECLARATION_REF_DEPENDENCIES', source_ref=True, ref_dependency=True)
add('R09_REF_BEFORE_SCOPE', None, 'Missing Claim REF edge refuses before partial-scope disposition.', error='CLAIM_REF_DEPENDENCY_MISSING', stage='CLAIM_REF_DEPENDENCIES', claim_ref=True, target_supplied=True, selector_mode='partial')
add('R10_EXACT_KEY_REQUIRED', None, 'Same logical source ID with wrong digest does not satisfy exact REF dependency.', error='CLAIM_REF_DEPENDENCY_MISSING', stage='CLAIM_REF_DEPENDENCIES', claim_ref=True, ref_dependency=True, target_supplied=True, wrong_ref_dependency_key=True)
add('R11_PRIMARY_ROLE_REQUIRED', None, 'Primary-selector anchoring specifically requires SOURCE role.', error='CLAIM_PRIMARY_DEPENDENCY_MISSING', stage='CLAIM_REFERENCES', primary_role='CONTEXT')
add('M00_BOTH_GUARDS_BEFORE_REF', None, 'Invalid exception guard refuses before missing condition REF dependency; both guards are validated first.', error='CLAIM_GUARD_ROOT', stage='CLAIM_GUARDS', claim_statement=statement(exception=ROOT_BAD), claim_ref=True, target_supplied=True)


def create_statements(spec):
    source = copy.deepcopy(spec.get('source_statement', BASE_STATEMENT))
    claim = copy.deepcopy(spec.get('claim_statement', BASE_STATEMENT))
    if spec.get('claim_ref'):
        claim['condition'] = copy.deepcopy(REF)
    if spec.get('source_ref'):
        source['condition'] = copy.deepcopy(REF)
    if spec.get('claim_remove_exception'):
        del claim['exception']
    if spec.get('source_remove_exception'):
        del source['exception']
    if spec.get('source_extra_field'):
        source['unexpected'] = 'NO_DEFAULT_OR_EXTENSION'
    return source, claim


def create_sources(spec, source_statement):
    raw = encoded({'schema': 'quorum/declaration-source/1', 'statement': source_statement})
    if 'source_raw_hex' in spec:
        raw = bytes.fromhex(spec['source_raw_hex'])
    if spec.get('source_append_lf'):
        raw += b'\n'
    key = {'logical_source_id': 'DECLARATION', 'sha256': sha(raw), 'bytes': len(raw)}
    supplied = [('DECL_SOURCE', key, raw)]
    if spec.get('target_supplied'):
        supplied.append(('DEF_SOURCE', copy.deepcopy(TARGET_KEY), TARGET_RAW))
    records = [{'id': alias, 'key': source_key, 'media_type': 'application/json',
        'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'issuer_claim_id': None,
        'authentication': 'UNVERIFIED'} for alias, source_key, _ in supplied]
    return raw, key, supplied, records


def create_selectors(spec, raw, key):
    mode = spec.get('selector_mode', 'full')
    if mode == 'none':
        return [], 'NOT_SELECTED'
    end, quote, membership = len(raw), raw, 'MATCH' if raw else 'EMPTY_SOURCE_MATCH_NONPROBATIVE'
    if mode == 'partial':
        end, quote = len(raw) - 1, raw[:-1]
    elif mode == 'partial_differs':
        end, quote, membership = 1, b'x', 'DIFFERS'
    elif mode == 'differs':
        quote, membership = b'X' + raw[1:], 'DIFFERS'
    elif mode == 'empty_differs':
        quote, membership = b'x', 'DIFFERS'
    selectors = [{'id': 'SELECTOR', 'kind': 'BYTE_SPAN_V1', 'source': key,
        'begin': 0, 'end': end, 'quote_bytes': len(quote), 'quote_sha256': sha(quote),
        'quote_base64': base64.b64encode(quote).decode('ascii')}]
    if mode == 'two':
        selectors.append(dict(selectors[0], id='SELECTOR_2'))
    return selectors, membership


def create_dependencies(spec, key):
    label = {'claim_id': 'CLAIM', 'revision': 'V1'}
    records = [{'id': 'DEP_PRIMARY', 'dependent': label,
        'requires': {'kind': 'SOURCE', 'source': key},
        'role': spec.get('primary_role', 'SOURCE'),
        'meaning': 'DECLARED_REVALIDATION_DEPENDENCY_ONLY'}]
    if spec.get('ref_dependency'):
        target = copy.deepcopy(TARGET_KEY)
        if spec.get('wrong_ref_dependency_key'):
            target['sha256'] = '0' * 64
        records.append({'id': 'DEP_REF', 'dependent': label,
            'requires': {'kind': 'SOURCE', 'source': target},
            'role': spec.get('ref_role', 'DEFINITION'),
            'meaning': 'DECLARED_REVALIDATION_DEPENDENCY_ONLY'})
    return records


def create_claim(spec, claim_statement, source_raw, selectors, dependencies):
    payload = {'profile': 'Q_DECLARATION_IDENTITY_V1', 'statement': claim_statement,
               'uncertainty': '', 'omitted_scope': ''}
    if spec.get('opaque'):
        text = source_raw.decode('utf-8') if spec.get('opaque_exact_source_text') else 'Opaque fixture.'
        payload = {'profile': 'OPAQUE_PROSE_V1', 'text': text,
                   'uncertainty': '', 'omitted_scope': ''}
    return {'id': 'CLAIM', 'revision': 'V1', 'task_view_id': 'TASK', 'payload': payload,
        'selector_ids': [item['id'] for item in selectors],
        'dependency_ids': [item['id'] for item in dependencies],
        'origin_kind': 'MANUAL_DEVELOPMENT_FIXTURE', 'attribution': '', 'conflict_claims': []}


def claim_key(claim):
    raw = encoded(claim)
    return {'claim_id': claim['id'], 'revision': claim['revision'],
            'sha256': sha(raw), 'bytes': len(raw)}


def expected_result(row, body, body_raw, key, membership):
    if row['manual_error']:
        return {'status': 'error', 'stage': row['manual_stage'], 'error': row['manual_error']}
    claim = body['claims'][0]
    selected = claim['payload']['profile'] != 'OPAQUE_PROSE_V1' and bool(body['selectors'])
    entry = {'claim': claim_key(claim), 'profile': claim['payload']['profile'],
        'selector_id': 'SELECTOR' if selected else None, 'source': key if selected else None,
        'source_membership': membership if selected else 'NOT_SELECTED',
        'interpretation': row['manual_interpretation'], 'semantic_role_relevance': 'UNPROVEN'}
    return {'status': 'ok', 'stage': 'CLAIM_STRUCTURE_ONLY',
        'body_pin': {'bytes': len(body_raw), 'sha256': sha(body_raw)}, 'claims': [entry],
        'source_authentication': 'UNVERIFIED', 'current_authority': 'NONE',
        'freshness': 'UNKNOWN', 'semantic_completeness': 'UNPROVEN',
        'full_reference_closure': 'NOT_EVALUATED'}


for row in CASES:
    spec = row['specification']
    source_statement, claim_statement = create_statements(spec)
    source_raw, key, originals, sources = create_sources(spec, source_statement)
    selectors, membership = create_selectors(spec, source_raw, key)
    dependencies = create_dependencies(spec, key)
    claim = create_claim(spec, claim_statement, source_raw, selectors, dependencies)
    body = json.loads(MINIMAL.read_bytes())
    body.update(sources=sources, selectors=selectors, dependencies=dependencies, claims=[claim])
    body['tasks'][0]['selected_sources'] = [item['key'] for item in sources]
    body['tasks'][0]['claim_rosters'] = [{'claim': claim_key(claim), 'expected_seat_ids': []}]
    raw = encoded(body)
    if len(raw) > 32768 or max(len(sources), len(selectors), len(dependencies)) > 3:
        raise ValueError('fixture byte/collection budget exceeded')
    path = OUT / 'raw' / (row['id'] + '.body.json')
    with path.open('xb') as stream:
        stream.write(raw)
    row['body_raw'] = pin(path)
    row['originals_exact_tuple_recipe'] = [{'alias': alias, 'key': source_key,
        'immutable_bytes_hex': data.hex()} for alias, source_key, data in originals]
    row['source_statement'] = source_statement
    row['claim_statement'] = claim_statement
    row['manual_source_membership'] = membership
    row['handwritten_expected_complete_result'] = expected_result(row, body, raw, key, membership)

sources = [AUTHOR / 'contract.json', AUTHOR / 'owner-design-addendum.json',
    AUTHOR / 'correction-01.json', WIRE / 'protocol-rules.json',
    WIRE / 'quorum-body.schema.json', MINIMAL, OUT / 'prepare.py',
    OUT / 'initial-disagreement.json', OUT / 'retention-clarification.json']
expectations = {'schema': 'quorum/manual-claim-structure-minimal-pairs/1',
    'status': 'PRE_IMPLEMENTATION_PRE_ORACLE_HANDWRITTEN_EXPECTATIONS',
    'implementation_inspected_or_executed': False, 'oracle_execution': 'NOT_YET_RUN',
    'source_pins': [pin(path) for path in sources], 'cases': CASES,
    'qualification': 'Internal exact syntax/dependency-identity observations only. No Boolean evaluation, semantic role relevance, entailment, complete dependency/Task/Manifest/Reading closure, truth, authority, whole replay or product acceptance. Original draft zero-selector disagreement is retained separately.'}
path = OUT / 'handwritten-expectations.json'
with path.open('xb') as stream:
    stream.write(encoded(expectations))
freeze = {'phase': 'PRE_IMPLEMENTATION_PRE_ORACLE_FROZEN', 'expectations': pin(path),
    'source_pins': expectations['source_pins'], 'candidates': [row['body_raw'] for row in CASES]}
path = OUT / 'pre-oracle-freeze.json'
with path.open('xb') as stream:
    stream.write(encoded(freeze))
print(json.dumps({'cases': len(CASES), 'freeze': pin(path)}))
