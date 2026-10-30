"""Internal exact declaration structures; no meaning, authority or full replay."""

import hashlib

import transport_quorum_input as metadata
import transport_quorum_shape as shape
import transport_quorum_source as source
from transport_schema import canonical

__all__ = ('check_claim_structure',)

MAX_DECLARATION = 4096
MAX_OUTPUT = 32768
STRUCTURAL = 'Q_DECLARATION_IDENTITY_V1'
JSON_RESOURCE = frozenset(('INPUT_INTEGER_BOUND', 'INPUT_DEPTH',
                          'INPUT_WORK_BOUND', 'INPUT_BYTE_BOUND'))


def _fail(code: str, stage: str) -> None:
    raise metadata.InputError(code, stage)


def _label(claim: dict) -> tuple[str, str]:
    return claim['id'], claim['revision']


def _unique(values: list, code: str) -> None:
    seen = set()
    for value in values:
        if value in seen:
            _fail(code, 'CLAIM_REFERENCES')
        seen.add(value)


def _resolve(names: list[str], records: dict, code: str) -> list[dict]:
    result = []
    for name in sorted(names):
        if name not in records:
            _fail(code, 'CLAIM_REFERENCES')
        result.append(records[name])
    return result


def _primary_anchors(selectors: list[dict], dependencies: list[dict]) -> None:
    for selector in selectors:
        found = False
        for dependency in dependencies:
            target = dependency['requires']
            if (dependency['role'] == 'SOURCE' and target['kind'] == 'SOURCE'
                    and target['source'] == selector['source']):
                found = True
                break
        if not found:
            _fail('CLAIM_PRIMARY_DEPENDENCY_MISSING', 'CLAIM_REFERENCES')


def _contexts(body: dict) -> list[tuple]:
    claims = sorted(body['claims'], key=_label)
    _unique([_label(c) for c in claims], 'CLAIM_REVISION_DUPLICATE')
    _unique([d['id'] for d in body['dependencies']], 'DEPENDENCY_ID_DUPLICATE')
    selectors = {s['id']: s for s in body['selectors']}
    dependencies = {d['id']: d for d in body['dependencies']}
    result, owned = [], set()
    for claim in claims:
        chosen = _resolve(claim['selector_ids'], selectors, 'CLAIM_SELECTOR_MISSING')
        required = _resolve(claim['dependency_ids'], dependencies, 'CLAIM_DEPENDENCY_MISSING')
        for dependency in required:
            owner = dependency['dependent']
            if (owner['claim_id'], owner['revision']) != _label(claim):
                _fail('CLAIM_DEPENDENCY_OWNER', 'CLAIM_REFERENCES')
        _primary_anchors(chosen, required)
        owned.update(s['id'] for s in chosen)
        result.append((claim, chosen, required))
    if any(selector['id'] not in owned for selector in body['selectors']):
        _fail('CLAIM_SELECTOR_UNOWNED', 'CLAIM_REFERENCES')
    return result


def _operands(node: dict) -> tuple[int, ...]:
    if node['op'] == 'NOT':
        return (node['operand'],)
    if node['op'] in ('AND', 'OR'):
        return node['left'], node['right']
    return ()  # TRUE/FALSE/REF are leaves under the closed pinned schema.


def _guard(guard: dict, prefix: str) -> None:
    nodes, stage = guard['nodes'], prefix + '_GUARDS'
    if guard['root'] != len(nodes) - 1:
        _fail(prefix + '_GUARD_ROOT', stage)
    for index, node in enumerate(nodes):
        if any(not 0 <= operand < index for operand in _operands(node)):
            _fail(prefix + '_GUARD_ORDER', stage)
    visited = [False] * len(nodes)  # Pinned schema bounds this to32 flags.
    visited[-1] = True
    for index in range(len(nodes) - 1, -1, -1):
        if visited[index]:
            for operand in _operands(nodes[index]):
                visited[operand] = True
    if not all(visited):
        _fail(prefix + '_GUARD_UNREACHABLE', stage)


def _guards(statement: dict, prefix: str) -> None:
    for name in ('condition', 'exception'):
        _guard(statement[name], prefix)


def _ref_dependencies(statement: dict, dependencies: list[dict],
                      sources: list[tuple], prefix: str) -> None:
    stage = prefix + '_REF_DEPENDENCIES'
    for name in ('condition', 'exception'):
        for node in statement[name]['nodes']:
            if node['op'] != 'REF':
                continue
            target, found = node['target'], False
            for dependency in dependencies:
                required = dependency['requires']
                if required['kind'] == 'SOURCE' and required['source'] == target:
                    found = True  # All five roles preserve identity only.
                    break
            if not found:
                _fail(prefix + '_REF_DEPENDENCY_MISSING', stage)
            if not any(key == source._body_key(target) for _, key, _ in sources):
                _fail(prefix + '_REF_SOURCE_MISSING', stage)


def _claim_prechecks(contexts: list[tuple], sources: list[tuple]) -> None:
    for claim, _, dependencies in contexts:
        if claim['payload']['profile'] == STRUCTURAL:
            statement = claim['payload']['statement']
            _guards(statement, 'CLAIM')
            _ref_dependencies(statement, dependencies, sources, 'CLAIM')


def _scope(claim: dict, selectors: list[dict], resolved: dict,
           memberships: dict) -> tuple:
    if claim['payload']['profile'] != STRUCTURAL:
        return 'UNRESOLVED_UNSUPPORTED_PROFILE', None, 'NOT_SELECTED', None
    if len(selectors) != 1:
        _fail('CLAIM_SELECTOR_CARDINALITY', 'CLAIM_SCOPE')
    selector = selectors[0]
    data, membership = resolved[selector['id']], memberships[selector['id']]
    if selector['begin'] != 0 or selector['end'] != len(data) or not data:
        return 'UNRESOLVED_INSUFFICIENT_SCOPE', selector, membership, data
    if membership != 'MATCH':
        return 'NOT_CHECKED_MISSING_EVIDENCE', selector, membership, data
    return None, selector, membership, data


def _declaration(data: bytes, schema: dict) -> dict:
    stage = 'DECLARATION_INPUT'
    if len(data) > MAX_DECLARATION:
        _fail('DECLARATION_RESOURCE', stage)
    try:
        value = metadata._read_value(data)
        metadata._canonical_bytes(value, data)
    except metadata.InputError as error:
        code = 'DECLARATION_RESOURCE' if error.code in JSON_RESOURCE else 'DECLARATION_CANONICAL_JSON'
        raise metadata.InputError(code, stage) from error
    try:
        shape._declaration_shape(value, schema)
    except metadata.InputError as error:
        code = 'DECLARATION_RESOURCE' if error.code == 'INPUT_WORK_BOUND' else 'DECLARATION_SCHEMA'
        raise metadata.InputError(code, stage) from error
    return value['statement']


def _entry(claim: dict, selector: dict | None, membership: str,
           interpretation: str) -> dict:
    raw = canonical(claim)
    key = dict(claim_id=claim['id'], revision=claim['revision'],
               sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
    return dict(claim=key, profile=claim['payload']['profile'],
                selector_id=None if selector is None else selector['id'],
                source=None if selector is None else dict(selector['source']),
                source_membership=membership, interpretation=interpretation,
                semantic_role_relevance='UNPROVEN')


def _comparisons(contexts: list[tuple], resolved: list[tuple],
                 source_result: dict, sources: list[tuple], schema: dict) -> list[dict]:
    by_selector = {selector['id']: data for selector, _, data in resolved}
    memberships = {r['id']: r['status'] for r in source_result['selectors']}
    result = []
    for claim, selectors, dependencies in contexts:
        disposition, selected, membership, data = _scope(claim, selectors,
                                                       by_selector, memberships)
        if disposition is None:
            statement = _declaration(data, schema)  # Once per Claim, no eligibility cache.
            _guards(statement, 'DECLARATION')
            _ref_dependencies(statement, dependencies, sources, 'DECLARATION')
            if statement == claim['payload']['statement']:
                disposition = 'MATCHED_DECLARATION_STRUCTURE_ONLY'
            else:
                disposition = 'DIFFERS_DECLARATION_STRUCTURE_ONLY'
        result.append(_entry(claim, selected, membership, disposition))
    return result


def _result(source_result: dict, claims: list[dict]) -> dict:
    result = dict(status='ok', stage='CLAIM_STRUCTURE_ONLY',
                  body_pin=dict(source_result['body_pin']), claims=claims,
                  source_authentication='UNVERIFIED', current_authority='NONE',
                  freshness='UNKNOWN', semantic_completeness='UNPROVEN',
                  full_reference_closure='NOT_EVALUATED')
    if len(canonical(result)) + 1 > MAX_OUTPUT:
        _fail('CLAIM_OUTPUT_BYTE_BOUND', 'CLAIM_OUTPUT_BOUNDS')
    return result


def _validated_claims(body_raw: object, originals: object) -> tuple:
    """Private owned bundle, available only after every inherited output gate."""
    body, sources, resolved, source_result, schema = source._validated_sources(body_raw, originals)
    contexts = _contexts(body)
    _claim_prechecks(contexts, sources)
    claims = _comparisons(contexts, resolved, source_result, sources, schema)
    result = _result(source_result, claims)
    return body, sources, result, schema


def check_claim_structure(body_raw: object, originals: object) -> dict:
    """Complete internal structure stage; never accepts a caller-validated bundle."""
    try:
        _, _, result, _ = _validated_claims(body_raw, originals)
        return result
    except metadata.InputError as error:
        return metadata._error(error)
