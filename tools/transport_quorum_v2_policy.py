"""Deterministic assessment thresholds, never source truth or execution authority."""

from collections import Counter

from transport_quorum_v2_input import (MAX_INPUT, MAX_OUTPUT, Refusal, canonical,
                                      digest, fields, need, parse, pin, sha)
from transport_quorum_v2_schema import BINDING, STANCES, validate

NAMES = ('policy', 'registry', 'admissions', 'ballot')
SCOPE = {
    'authority': 'NONE', 'source_truth': 'NOT_ASSESSED', 'interpretation': 'NOT_CHECKED',
    'provider_authentication': 'NOT_ESTABLISHED', 'error_independence': 'NOT_ESTABLISHED',
    'family_identity': 'HELD_REGISTRY_ASSIGNMENT_ONLY',
    'origin_class': 'EXTERNALLY_HELD_DECLARATIONS_ONLY',
    'prompt_settings_source_bytes': 'DIGEST_REFERENCES_ONLY_NOT_REPLAYED',
    'response_bytes': 'UTF8_TEXT_DIGEST_CHECKED',
}


def _inputs(raws, held):
    need(type(raws) is tuple and len(raws) == 4, 'INPUT_ARGUMENTS')
    need(all(type(raw) is bytes for raw in raws), 'INPUT_TYPE')
    need(sum(len(raw) for raw in raws) <= MAX_INPUT, 'AGGREGATE_INPUT_BOUND')
    fields(held, NAMES[:3])
    for name, raw in zip(NAMES[:3], raws[:3], strict=True):
        digest(held[name])
        need(sha(raw) == held[name], 'HELD_ROOT_MISMATCH')
    return dict(zip(NAMES, (parse(raw) for raw in raws), strict=True))


def _reasons(row, seats, runs, seat_counts, run_counts):
    reasons = []
    if row['seat_id'] not in seats:
        reasons.append('NOT_REQUIRED_SEAT')
    if seat_counts[row['seat_id']] > 1:
        reasons.append('DUPLICATE_SEAT')
    if run_counts[row['run_id']] > 1:
        reasons.append('DUPLICATE_RUN')
    run = runs.get(row['run_id'])
    if run is None:
        reasons.append('MISSING_ADMISSION')
    elif (any(row[key] != run[key] for key in BINDING)
          or sha(canonical(row)) != run['reading_sha256']):
        reasons.append('BINDING_MISMATCH')
    if sha(row['response_text'].encode('utf-8')) != row['raw_response_sha256']:
        reasons.append('RESPONSE_DIGEST_MISMATCH')
    if run is not None and run['state'] == 'WITHDRAWN':
        reasons.append('WITHDRAWN')
    return reasons


def _dispositions(rows, seats, runs):
    seat_counts = Counter(row['seat_id'] for row in rows)
    run_counts = Counter(row['run_id'] for row in rows)
    result = []
    for row in sorted(rows, key=lambda item: item['reading_id']):
        reasons = _reasons(row, seats, runs, seat_counts, run_counts)
        result.append({'reading_id': row['reading_id'], 'eligible': not reasons,
                       'reasons': reasons, 'reading': row})
    return result


def _counts(rows):
    return {stance: sum(row['stance'] == stance for row in rows) for stance in STANCES}


def _provenance(rows, runs):
    origins = {runs[row['run_id']]['origin'] for row in rows}
    if not origins:
        return 'NO_ELIGIBLE_READINGS'
    if len(origins) > 1:
        return 'MIXED'
    return 'OBSERVED_ONLY' if 'OBSERVED_BINDING' in origins else 'SYNTHETIC_ONLY'


def _verdict(policy, eligible):
    present = {row['seat_id'] for row in eligible}
    missing = sorted(set(policy['required_seats']) - present)
    support = [row for row in eligible if row['stance'] == 'SUPPORT']
    families = sorted({row['family_id'] for row in support})
    conditions = (
        ('MISSING_ELIGIBLE_SEATS', bool(missing)),
        ('BLOCKED_DISSENT', any(row['stance'] in ('OPPOSE', 'DISPUTE') for row in eligible)),
        ('INSUFFICIENT_SUPPORT', len(support) < policy['minimum_support']),
        ('INSUFFICIENT_FAMILY_DIVERSITY', len(families) < policy['minimum_families']),
    )
    reasons = [name for name, failed in conditions if failed]
    verdict = reasons[0] if reasons else 'RECORDED_SUPPORT_THRESHOLD_MET'
    return dict(verdict=verdict, reasons=reasons, missing_seats=missing,
                support_count=len(support), support_families=families,
                actual_support_is_cross_family=len(families) >= 2,
                policy_requires_cross_family=policy['minimum_families'] >= 2,
                cross_family_policy_satisfied=not reasons and policy['minimum_families'] >= 2)


def _result(documents, raws, seats, runs):
    rows = documents['ballot']['readings']
    dispositions = _dispositions(rows, seats, runs)
    eligible = [row['reading'] for row in dispositions if row['eligible']]
    result = dict(schema='quorum/threshold-result/2', status='EVALUATED',
                  **_verdict(documents['policy'], eligible))
    result.update(eligible_count=len(eligible), dispositions=dispositions,
                  raw_stance_counts=_counts(rows), eligible_stance_counts=_counts(eligible),
                  provenance_class=_provenance(eligible, runs), scope=dict(SCOPE),
                  policy=documents['policy'],
                  input_pins={name: pin(raw) for name, raw in zip(NAMES, raws, strict=True)})
    need(len(canonical(result)) + 1 <= MAX_OUTPUT, 'COMPLETE_OUTPUT_BOUND')
    return result


def evaluate(raws, held):
    """Pure four-document API; held roots must be chosen outside the candidate."""
    try:
        documents = _inputs(raws, held)
        seats, runs = validate(documents)
        return _result(documents, raws, seats, runs)
    except Refusal as error:
        return dict(schema='quorum/threshold-refusal/2', status='REFUSED',
                    code=str(error), authority='NONE')
