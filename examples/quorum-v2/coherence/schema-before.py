"""Strict version 2 shapes; family assignments are externally held policy data."""

from transport_quorum_v2_input import array, digest, fields, identifier, integer, need, text

STANCES = ('ABSTAIN', 'DISPUTE', 'OPPOSE', 'SUPPORT')
ORIGINS = ('OBSERVED_BINDING', 'SYNTHETIC_FIXTURE')
CONTEXT = ('claim_sha256', 'task_sha256', 'source_set_sha256')
BINDING = ('seat_id', 'run_id', 'model_id', 'family_id', 'context',
           'prompt_sha256', 'settings_sha256', 'raw_response_sha256')


def context(value):
    fields(value, CONTEXT)
    for item in value.values():
        digest(item)


def policy(value):
    fields(value, ('schema', 'context', 'required_seats', 'minimum_support',
                   'minimum_families', 'dissent_rule'))
    need(value['schema'] == 'quorum/threshold-policy/2', 'POLICY_VERSION')
    context(value['context'])
    seats = value['required_seats']
    array(seats, 1, 9)
    for seat in seats:
        identifier(seat)
    need(seats == sorted(set(seats)), 'POLICY_SEAT_ORDER')
    integer(value['minimum_support'], 1, len(seats))
    integer(value['minimum_families'], 1, value['minimum_support'])
    need(value['dissent_rule'] == 'ELIGIBLE_OPPOSE_OR_DISPUTE_BLOCKS', 'DISSENT_RULE')


def registry(value, expected):
    fields(value, ('schema', 'seats'))
    need(value['schema'] == 'quorum/held-registry/2', 'REGISTRY_VERSION')
    array(value['seats'], 1, 9)
    seen = {}
    for row in value['seats']:
        fields(row, ('seat_id', 'model_id', 'family_id'))
        identifier(row['seat_id'])
        identifier(row['model_id'], 128)
        identifier(row['family_id'])
        need(row['seat_id'] not in seen, 'DUPLICATE_REGISTRY_SEAT')
        seen[row['seat_id']] = row
    need(sorted(seen) == expected, 'REGISTRY_ROSTER')
    return seen


def binding(value):
    for name in ('seat_id', 'family_id'):
        identifier(value[name])
    for name in ('run_id', 'model_id'):
        identifier(value[name], 128)
    context(value['context'])
    for name in ('prompt_sha256', 'settings_sha256', 'raw_response_sha256'):
        digest(value[name])


def admissions(value, seats, expected_context):
    fields(value, ('schema', 'runs'))
    need(value['schema'] == 'quorum/held-admissions/2', 'ADMISSIONS_VERSION')
    array(value['runs'], 0, 32)
    seen = {}
    for row in value['runs']:
        fields(row, (*BINDING, 'reading_sha256', 'state', 'origin'))
        binding(row)
        digest(row['reading_sha256'])
        need(row['state'] in ('ACTIVE', 'WITHDRAWN'), 'ADMISSION_STATE')
        need(row['origin'] in ORIGINS, 'ADMISSION_ORIGIN')
        need(row['run_id'] not in seen, 'DUPLICATE_ADMISSION_RUN')
        need(row['seat_id'] in seats, 'ADMISSION_SEAT')
        seat = seats[row['seat_id']]
        need(all(row[name] == seat[name] for name in ('model_id', 'family_id')),
             'ADMISSION_REGISTRY_MISMATCH')
        need(row['context'] == expected_context, 'ADMISSION_CONTEXT')
        seen[row['run_id']] = row
    return seen


def ballot(value, expected_context):
    fields(value, ('schema', 'context', 'readings'))
    need(value['schema'] == 'quorum/ballot/2', 'BALLOT_VERSION')
    context(value['context'])
    need(value['context'] == expected_context, 'BALLOT_CONTEXT')
    array(value['readings'], 0, 32)
    seen = set()
    for row in value['readings']:
        fields(row, (*BINDING, 'reading_id', 'response_text', 'stance'))
        binding(row)
        identifier(row['reading_id'])
        need(row['reading_id'] not in seen, 'DUPLICATE_READING_ID')
        seen.add(row['reading_id'])
        text(row['response_text'], 4096)
        need(row['stance'] in STANCES, 'STANCE')


def validate(documents):
    policy(documents['policy'])
    p = documents['policy']
    seats = registry(documents['registry'], p['required_seats'])
    runs = admissions(documents['admissions'], seats, p['context'])
    ballot(documents['ballot'], p['context'])
    need(len(seats) + len(runs) + len(documents['ballot']['readings']) <= 96,
         'RECORD_BOUND')
    return seats, runs
