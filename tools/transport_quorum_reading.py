"""Bounded reading closure and recorded stance counts; no decision authority."""

import transport_quorum_context as context
import transport_quorum_input as metadata
import transport_quorum_source as source
from transport_schema import canonical

__all__ = ('check_reading_aggregation',)

MAX_WITHDRAWALS = 32
MAX_OUTPUT = 32768
MAX_ENTRY = 65536
MANUAL = 'MANUAL_DEVELOPMENT_FIXTURE'
EXTERNAL = 'RECORDED_EXTERNAL_ASSESSOR'
ELIGIBLE = 'ELIGIBLE_MANUAL_FIXTURE_ONLY'
QUALIFIED = 'QUALIFIED_STRUCTURE_ONLY'
STANCES = ('ABSTAIN', 'DISPUTE', 'OPPOSE', 'SUPPORT')
QUALIFICATIONS = {
    'MATCHED_DECLARATION_STRUCTURE_ONLY': QUALIFIED,
    'DIFFERS_DECLARATION_STRUCTURE_ONLY': 'UNQUALIFIED_MISMATCH',
    'UNRESOLVED_UNSUPPORTED_PROFILE': 'UNQUALIFIED_UNSUPPORTED',
    'UNRESOLVED_INSUFFICIENT_SCOPE': 'UNQUALIFIED_INSUFFICIENT_SCOPE',
    'NOT_CHECKED_MISSING_EVIDENCE': 'NOT_EVALUATED',
}


def _fail(code: str, stage: str) -> None:
    raise metadata.InputError('READING_' + code, 'READING_' + stage)


def _held_arguments(value: object) -> list[tuple]:
    stage = 'WITHDRAWAL_PIN_ARGUMENTS'
    if type(value) is not tuple:
        _fail('PIN_TYPE', stage)
    if len(value) > MAX_WITHDRAWALS:
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


def _event_pins(body: dict, held: list[tuple], index: dict) -> None:
    stage = 'WITHDRAWAL_EVENT_PINS'
    names = [p[0] for p in held]
    if len(set(names)) != len(names):
        _fail('PIN_DUPLICATE', stage)
    if set(names) != {w['id'] for w in body['reading_withdrawals']}:
        _fail('PIN_SET', stage)
    by_id = {p[0]: p[1:] for p in held}
    for withdrawal in body['reading_withdrawals']:
        pin = index[withdrawal['id']][2]
        if by_id[withdrawal['id']] != (pin['sha256'], pin['bytes']):
            _fail('WITHDRAWAL_PIN', stage)


def _record(name: str, kind: str, index: dict, prefix: str, stage: str) -> dict:
    if name not in index:
        _fail(prefix + '_MISSING', stage)
    actual_kind, record, _ = index[name]
    if actual_kind != kind:
        _fail(prefix + '_TYPE', stage)
    return record


def _reference(pin: dict, kind: str, index: dict, prefix: str,
               stage: str, blob_kind: str | None = None) -> dict:
    record = _record(pin['id'], kind, index, prefix, stage)
    if pin != index[pin['id']][2]:
        _fail(prefix + '_PIN', stage)
    if blob_kind is not None and record['kind'] != blob_kind:
        _fail(prefix + '_KIND', stage)
    return record


def _optional_blob(pin: dict | None, index: dict, prefix: str, stage: str, kind: str) -> None:
    if pin is not None:
        _reference(pin, 'Blob', index, prefix, stage, kind)


def _claim(key: dict, claim_keys: dict, code: str, stage: str) -> None:
    label = context._key_label(key)
    if label not in claim_keys or claim_keys[label] != key:
        _fail(code, stage)


def _provenance(body: dict, index: dict) -> None:
    stage = 'PROVENANCE'
    for record in body['provenance']:
        if record['origin_kind'] == MANUAL:
            valid = record['method'] == 'MANUALLY_AUTHORED_ILLUSTRATION' and record['run_evidence_id'] is None
        else:
            valid = record['method'] == 'RECORDED_UNVERIFIED_EXTERNAL_RUN' and record['run_evidence_id'] is not None
        if not valid:
            _fail('PROVENANCE_ORIGIN', stage)
        if record['run_evidence_id'] is not None:
            _record(record['run_evidence_id'], 'RunEvidence', index, 'PROVENANCE_RUN', stage)
        _optional_blob(record['evidence'], index, 'PROVENANCE_EVIDENCE', stage, 'PROVENANCE_EVIDENCE')


def _runs(body: dict, sources: list[tuple], index: dict) -> None:
    stage = 'RUN_EVIDENCE'
    source_keys = {key for _, key, _ in sources}
    for run in body['run_evidence']:
        seat = _record(run['seat_id'], 'Seat', index, 'RUN_SEAT', stage)
        if seat['origin_kind'] != EXTERNAL:
            _fail('RUN_SEAT_ORIGIN', stage)
        manifest = _reference(run['input_manifest'], 'InputManifest', index, 'RUN_MANIFEST', stage)
        if run['prompt'] != manifest['prompt'] or run['settings'] != manifest['settings']:
            _fail('RUN_CONTEXT', stage)
        _reference(run['response'], 'Blob', index, 'RUN_RESPONSE', stage, 'RAW_RESPONSE')
        _optional_blob(run['raw_run_evidence'], index, 'RUN_RAW_EVIDENCE', stage, 'PROVENANCE_EVIDENCE')
        policy = run['externally_pinned_eligibility_policy']
        if policy is not None and source._body_key(policy) not in source_keys:
            _fail('RUN_POLICY_SOURCE', stage)


def _readings(body: dict, index: dict, claim_keys: dict) -> None:
    stage = 'RECORDS'
    for reading in body['readings']:
        seat = _record(reading['seat_id'], 'Seat', index, 'SEAT', stage)
        _claim(reading['claim'], claim_keys, 'CLAIM', stage)
        manifest = _reference(reading['input_manifest'], 'InputManifest', index, 'MANIFEST', stage)
        if (reading['task_view_id'] != body['tasks'][0]['id'] or reading['claim'] != manifest['claim']
                or reading['source_versions'] != manifest['source_versions']
                or reading['prompt'] != manifest['prompt'] or reading['settings'] != manifest['settings']):
            _fail('INPUT_CONTEXT', stage)
        _reference(reading['response'], 'Blob', index, 'RESPONSE', stage, 'RAW_RESPONSE')
        provenance = _reference(reading['provenance'], 'Provenance', index, 'PROVENANCE', stage)
        if reading['origin_kind'] != seat['origin_kind'] or reading['origin_kind'] != provenance['origin_kind']:
            _fail('ORIGIN', stage)
        if reading['origin_kind'] == EXTERNAL:
            run = index[provenance['run_evidence_id']][1]
            if any(run[field] != reading[field] for field in
                   ('seat_id', 'input_manifest', 'prompt', 'settings', 'response')):
                _fail('RUN_CONTEXT', stage)


def _challenges(body: dict, index: dict, claim_keys: dict) -> None:
    stage = 'CHALLENGES'
    for challenge in body['challenges']:
        _claim(challenge['claim'], claim_keys, 'CHALLENGE_CLAIM', stage)
        reading = None
        if challenge['reading_id'] is not None:
            reading = _record(challenge['reading_id'], 'Reading', index, 'CHALLENGE_READING', stage)
        if challenge['seat_id'] is not None:
            _record(challenge['seat_id'], 'Seat', index, 'CHALLENGE_SEAT', stage)
        if reading is not None and (reading['claim'] != challenge['claim']
                or challenge['seat_id'] is not None and challenge['seat_id'] != reading['seat_id']):
            _fail('CHALLENGE_CONTEXT', stage)
        _reference(challenge['provenance'], 'Provenance', index, 'CHALLENGE_PROVENANCE', stage)
        _optional_blob(challenge['evidence'], index, 'CHALLENGE_EVIDENCE', stage, 'CHALLENGE_EVIDENCE')
    for reading in body['readings']:
        for name in reading['challenge_ids']:
            challenge = _record(name, 'Challenge', index, 'CHALLENGE_REFERENCE', stage)
            if challenge['claim'] != reading['claim'] or challenge['reading_id'] not in (None, reading['id']):
                _fail('CHALLENGE_REFERENCE_CONTEXT', stage)


def _withdrawals(body: dict, index: dict) -> list[dict]:
    stage, result = 'WITHDRAWALS', []
    for withdrawal in body['reading_withdrawals']:
        reading = _record(withdrawal['reading_id'], 'Reading', index, 'WITHDRAWAL_READING', stage)
        provenance = _reference(withdrawal['provenance'], 'Provenance', index, 'WITHDRAWAL_PROVENANCE', stage)
        _optional_blob(withdrawal['evidence'], index, 'WITHDRAWAL_EVIDENCE', stage, 'WITHDRAWAL_EVIDENCE')
        target = index[reading['provenance']['id']][1]
        excludes = (reading['origin_kind'] == MANUAL and target['origin_kind'] == MANUAL
                    and provenance['origin_kind'] == MANUAL and target['author_claim'] == provenance['author_claim'])
        result.append(dict(pin=dict(index[withdrawal['id']][2]), reading_id=reading['id'],
            manual_count_effect='EXCLUDES_MANUAL_FIXTURE' if excludes else 'NO_COUNT_EFFECT'))
    return result


def _predecessors(body: dict) -> None:
    stage = 'WITHDRAWAL_PREDECESSORS'
    records = body['reading_withdrawals']
    by_id = {record['id']: record for record in records}
    for record in records:
        parent = record['predecessor_withdrawal_id']
        if parent is not None:
            if parent not in by_id:
                _fail('WITHDRAWAL_PREDECESSOR_MISSING', stage)
            if by_id[parent]['reading_id'] != record['reading_id']:
                _fail('WITHDRAWAL_PREDECESSOR_CONTEXT', stage)
    resolved = set()
    for _ in range(MAX_WITHDRAWALS):  # At most 32 rounds of 32 records.
        for record in records:
            if record['predecessor_withdrawal_id'] is None or record['predecessor_withdrawal_id'] in resolved:
                resolved.add(record['id'])
        if len(resolved) == len(records):
            return
    _fail('WITHDRAWAL_PREDECESSOR_CYCLE', stage)


def _disposition(reading: dict, group: list[dict], expected: list[str],
                 withdrawals: list[dict], qualification: str) -> dict:
    target = [w for w in withdrawals if w['reading_id'] == reading['id']]
    reasons = []
    if sum(r['seat_id'] == reading['seat_id'] for r in group) > 1:
        reasons.append('INELIGIBLE_DUPLICATE_SEAT')
    if reading['seat_id'] not in expected:
        reasons.append('INELIGIBLE_NOT_EXPECTED_SEAT')
    if any(w['manual_count_effect'] == 'EXCLUDES_MANUAL_FIXTURE' for w in target):
        reasons.append('INELIGIBLE_WITHDRAWN')
    if reading['origin_kind'] == EXTERNAL:
        reasons.append('INELIGIBLE_UNVERIFIED')
    eligibility = reasons[0] if reasons else ELIGIBLE
    return dict(reading_id=reading['id'], seat_id=reading['seat_id'], raw_stance=reading['stance'],
        observation_eligibility=eligibility, claim_structural_qualification=qualification,
        reason_codes=context._ordered(reasons or [ELIGIBLE]),
        withdrawal_ids=context._ordered([w['pin']['id'] for w in target]))


def _counts(rows: list[dict]) -> dict:
    result = {stance: 0 for stance in STANCES}
    for row in rows:
        result[row['raw_stance']] += 1
    return result


def _agreement(rows: list[dict]) -> str:
    decisive = [r['raw_stance'] for r in rows if r['raw_stance'] != 'ABSTAIN']
    if not decisive:
        return 'NO_DECISIVE_READINGS'
    if len(decisive) == 1:
        return 'SINGLE_DECISIVE_READING'
    return 'RECORDED_AGREEMENT' if len(set(decisive)) == 1 else 'RECORDED_DISAGREEMENT'


def _observations(group: list[dict]) -> str:
    origins = {r['origin_kind'] for r in group}
    if not origins:
        return 'NO_RECORDED_READINGS'
    if origins == {MANUAL}:
        return 'MANUAL_FIXTURES_ONLY'
    if origins == {EXTERNAL}:
        return 'UNVERIFIED_EXTERNAL_RECORDS_ONLY'
    return 'MIXED_MANUAL_AND_UNVERIFIED'


def _ids(rows: list[dict]) -> list[str]:
    return context._ordered([row['reading_id'] for row in rows])


def _aggregate(key: dict, qualification: str, body: dict, withdrawals: list[dict]) -> dict:
    group = [r for r in body['readings'] if r['claim'] == key]
    roster = next(row for row in body['tasks'][0]['claim_rosters'] if row['claim'] == key)
    expected = list(roster['expected_seat_ids'])
    rows = [_disposition(r, group, expected, withdrawals, qualification) for r in group]
    eligible = [r for r in rows if r['observation_eligibility'] == ELIGIBLE]
    qualified = [r for r in eligible if r['claim_structural_qualification'] == QUALIFIED]
    dissent = [r for r in rows if r['raw_stance'] in ('OPPOSE', 'DISPUTE')]
    present = {r['seat_id'] for r in group} & set(expected)
    names = {r['id'] for r in group}
    return dict(expected_seat_ids=expected, present_seat_ids=context._ordered(list(present)),
        missing_seat_ids=context._ordered(list(set(expected) - present)),
        raw_counts=_counts(rows), eligible_counts=_counts(eligible), structurally_qualified_counts=_counts(qualified),
        raw_dissent_reading_ids=_ids(dissent),
        ineligible_dissent_reading_ids=_ids([r for r in dissent if r['observation_eligibility'] != ELIGIBLE]),
        qualified_dissent_reading_ids=_ids([r for r in qualified if r['raw_stance'] in ('OPPOSE', 'DISPUTE')]),
        abstaining_reading_ids=_ids([r for r in rows if r['raw_stance'] == 'ABSTAIN']),
        conflicting_duplicate_reading_ids=_ids([r for r in rows if 'INELIGIBLE_DUPLICATE_SEAT' in r['reason_codes']]),
        withdrawal_ids=context._ordered([w['pin']['id'] for w in withdrawals if w['reading_id'] in names]),
        challenge_ids=context._ordered([c['id'] for c in body['challenges'] if c['claim'] == key]),
        readings=rows, eligible_stance_agreement=_agreement(eligible), qualified_stance_agreement=_agreement(qualified),
        threshold_verdict='NOT_DEFINED', observation_class=_observations(group))


def _skeleton(context_result: dict, withdrawals: list[dict]) -> dict:
    return dict(status='ok', stage='READING_CLOSURE_AGGREGATION_ONLY',
        body_pin=dict(context_result['body_pin']), claims=[], withdrawals=withdrawals,
        current_authority='NONE', declared_model_family_identity='NOT_VALIDATED',
        dynamic_typed_reference_closure='MATCH_READING_SCOPE_ONLY', external_record_pin_match='NOT_EVALUATED',
        freshness='UNKNOWN', full_reference_closure='NOT_EVALUATED', held_withdrawal_pin_match='MATCH',
        independent_custody='UNKNOWN', raw_first_output_provenance='UNVERIFIED',
        semantic_completeness='UNPROVEN', source_authentication='UNVERIFIED',
        deferred_gates=['BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST', 'FULL_TYPED_DIGEST_GRAPH_AND_EXTERNAL_PINS',
                        'HISTORY_RELATED_ROLE_CLOSURE', 'IMPORT_COMPARISON_FULL_REPLAY_ORDER'])


def _append(result: dict, entry: dict, size: int) -> int:
    raw = canonical(entry)
    total = size + len(raw) + (1 if result['claims'] else 0)
    if len(raw) > MAX_ENTRY or total > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    result['claims'].append(entry)
    return total


def _finish(result: dict, size: int) -> dict:
    raw = canonical(result)
    if len(raw) + 1 > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    if len(raw) + 1 != size:
        _fail('OUTPUT_ACCOUNTING', 'OUTPUT_BOUNDS')
    try:
        metadata._lexical(raw)
    except metadata.InputError as error:
        raise metadata.InputError('READING_OUTPUT_BYTE_BOUND', 'READING_OUTPUT_BOUNDS') from error
    return result


def _result(body: dict, claim_result: dict, context_result: dict, withdrawals: list[dict]) -> dict:
    result = _skeleton(context_result, withdrawals)
    size = len(canonical(result)) + 1
    if size > MAX_OUTPUT:
        _fail('OUTPUT_BYTE_BOUND', 'OUTPUT_BOUNDS')
    for comparison in claim_result['claims']:
        key = comparison['claim']
        qualification = QUALIFICATIONS[comparison['interpretation']]
        entry = dict(claim=dict(key), aggregation=_aggregate(key, qualification, body, withdrawals))
        size = _append(result, entry, size)
    result['claims'].sort(key=lambda row: (canonical(row['claim']['claim_id']), canonical(row['claim']['revision'])))
    return _finish(result, size)


def check_reading_aggregation(body_raw: object, originals: object, held_update_pins: object,
                              held_withdrawal_pins: object) -> dict:
    """Validate every declared reading link before reporting non-authoritative counts."""
    try:
        body, sources, claims, _, ctx, index, claim_keys, _ = context._validated_context(
            body_raw, originals, held_update_pins)
        held = _held_arguments(held_withdrawal_pins)
        _event_pins(body, held, index)
        _provenance(body, index)
        _runs(body, sources, index)
        _readings(body, index, claim_keys)
        _challenges(body, index, claim_keys)
        withdrawals = _withdrawals(body, index)
        _predecessors(body)
        return _result(body, claims, ctx, withdrawals)
    except metadata.InputError as error:
        return metadata._error(error)
