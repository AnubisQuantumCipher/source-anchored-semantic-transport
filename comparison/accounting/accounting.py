"""Check declared work-record coverage; never calculate benefit or certify work."""
import hashlib
import json
from pathlib import Path
import re
import types

CAP = 65536
OUTPUT_CAP = 131072
MAX_INT = 9223372036854775807
PHASES = ('setup', 'annotation', 'inference', 'indexing', 'fetch', 'task',
          'retry', 'correction', 'cleanup', 'maintenance')
TIME_METRICS = ('human_active_ns', 'model_elapsed_ns', 'machine_elapsed_ns',
                'owner_admin_ns')
METRICS = TIME_METRICS + ('provider_cumulative_input_tokens',
    'provider_cumulative_output_tokens', 'provider_incremental_input_tokens',
    'provider_incremental_output_tokens', 'money_minor_units')
ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,47}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
HELPER_SHA = '39a0ba765ac123ee3d69573094923d96173ebe7965a594168f74dbe7d9ccb5cf'


class Refusal(ValueError):
    """Named informational validation refusal."""


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def helper():
    path = Path(__file__).resolve().parents[2] / 'tools/transport_quorum_v2_input.py'
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    need(len(raw) <= CAP and sha(raw) == HELPER_SHA, 'PIN_MISMATCH')
    module = types.ModuleType('_accounting_checked_json')
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


_JSON = helper()


def integer_token(token):
    need(token.isascii() and token.isdigit() and len(token) <= 19, 'JSON_INVALID')
    return int(token)


def document(raw):
    need(type(raw) is bytes and 0 < len(raw) <= CAP, 'INPUT_BOUND')
    try:
        _JSON._depth(raw)
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_JSON._pairs,
            parse_int=integer_token, parse_float=_JSON._noninteger,
            parse_constant=_JSON._noninteger)
        need(canonical(value) == raw, 'JSON_INVALID')
        return value
    except (_JSON.Refusal, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal('JSON_INVALID') from error


def fields(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'SCHEMA_INVALID')


def identifier(value):
    need(type(value) is str and ID.fullmatch(value) is not None, 'SCHEMA_INVALID')
    return value


def integer(value, maximum=MAX_INT, minimum=0):
    need(type(value) is int and minimum <= value <= maximum, 'SCHEMA_INVALID')


def digest(value):
    need(type(value) is str and HEX.fullmatch(value) is not None, 'PIN_MISMATCH')


def reason(value, nonempty):
    need(type(value) is str and value.isascii() and len(value) <= 256,
         'SCHEMA_INVALID')
    need(bool(value) == nonempty, 'SCHEMA_INVALID')


def array(value, maximum, empty=True):
    need(type(value) is list, 'SCHEMA_INVALID')
    need(len(value) <= maximum, 'INPUT_BOUND')
    need(empty or bool(value), 'PLAN_INVENTORY')


def dimension(metric, currency):
    need(type(metric) is str and metric in METRICS, 'SCHEMA_INVALID')
    if metric == 'money_minor_units':
        need(type(currency) is str and re.fullmatch(r'[A-Z]{3}', currency, re.ASCII)
             is not None, 'SCHEMA_INVALID')
    else:
        need(currency is None, 'SCHEMA_INVALID')


def attempts(rows):
    array(rows, 32, False)
    result = {}
    for row in rows:
        fields(row, ('id', 'task', 'arm', 'cache', 'actor', 'role', 'outcome', 'retry_of'))
        for key in ('id', 'task', 'arm', 'actor'):
            identifier(row[key])
        need(row['id'] not in result, 'PLAN_INVENTORY')
        need(row['cache'] in ('cold', 'warm', 'uncontrolled'), 'SCHEMA_INVALID')
        need(row['role'] in ('sender', 'recipient', 'shared', 'administrative'),
             'SCHEMA_INVALID')
        need(row['outcome'] in ('succeeded', 'failed', 'unsafe', 'unrun'), 'SCHEMA_INVALID')
        parent = row['retry_of']
        if parent is not None:
            identifier(parent)
            need(parent in result, 'PLAN_INVENTORY')
            need(all(row[k] == result[parent][k] for k in ('task', 'arm', 'actor', 'role')),
                 'PLAN_INVENTORY')
        result[row['id']] = row
    return result


def slots(rows, owners):
    array(rows, 128, False)
    result, dimensions = {}, set()
    for row in rows:
        fields(row, ('id', 'attempt', 'phase', 'metric', 'currency', 'applicability', 'reason'))
        identifier(row['id'])
        identifier(row['attempt'])
        need(row['id'] not in result and row['attempt'] in owners, 'PLAN_INVENTORY')
        need(row['phase'] in PHASES, 'SCHEMA_INVALID')
        dimension(row['metric'], row['currency'])
        need(row['applicability'] in ('required', 'not_applicable'), 'SCHEMA_INVALID')
        reason(row['reason'], row['applicability'] == 'not_applicable')
        key = (row['attempt'], row['phase'], row['metric'], row['currency'])
        need(key not in dimensions, 'PLAN_INVENTORY')
        dimensions.add(key)
        result[row['id']] = row
    for owner in owners:
        human = {row['phase']: row for row in rows if row['attempt'] == owner
                 and row['metric'] == 'human_active_ns'}
        need(set(human) == set(PHASES), 'PHASE_COVERAGE')
        need(human['task']['applicability'] == 'required', 'PHASE_COVERAGE')
    return result


def plan_document(plan):
    fields(plan, ('schema', 'attempts', 'slots'))
    need(plan['schema'] == 'transport/accounting-plan/1', 'SCHEMA_INVALID')
    array(plan['attempts'], 32, False)
    array(plan['slots'], 128, False)
    owners = attempts(plan['attempts'])
    return owners, slots(plan['slots'], owners)


def artifact_roster(rows, bindings):
    array(rows, 32)
    need(type(bindings) is dict, 'BINDING_MISMATCH')
    need(len(bindings) <= 32, 'INPUT_BOUND')
    result, hashes, total = {}, set(), 0
    for row in rows:
        fields(row, ('id', 'bytes', 'sha256'))
        identifier(row['id'])
        integer(row['bytes'], CAP, 1)
        digest(row['sha256'])
        need(row['id'] not in result and row['sha256'] not in hashes,
             'BINDING_MISMATCH')
        total += row['bytes']
        need(total <= 1048576, 'INPUT_BOUND')
        result[row['id']] = row
        hashes.add(row['sha256'])
    need(set(result) == set(bindings), 'BINDING_MISMATCH')
    for name, raw in bindings.items():
        need(type(raw) is bytes and 0 < len(raw) <= CAP, 'INPUT_BOUND')
        need(len(raw) == result[name]['bytes'] and sha(raw) == result[name]['sha256'],
             'ARTIFACT_PIN')
    return result


def measurements(roster, bindings, plan_sha):
    result = {}
    for name in sorted(roster):
        value = document(bindings[name])
        fields(value, ('schema', 'plan_sha256', 'measurements'))
        need(value['schema'] == 'transport/accounting-evidence/1', 'SCHEMA_INVALID')
        need(value['plan_sha256'] == plan_sha, 'ARTIFACT_PLAN')
        array(value['measurements'], 128)
        need(bool(value['measurements']), 'SCHEMA_INVALID')
        need(len(result) + len(value['measurements']) <= 128, 'INPUT_BOUND')
        for row in value['measurements']:
            fields(row, ('id', 'slot', 'metric', 'currency', 'value', 'interval'))
            identifier(row['id'])
            identifier(row['slot'])
            need(row['id'] not in result, 'MEASUREMENT_DUPLICATE')
            result[row['id']] = (name, row)
    return result


def record_roster(rows, expected):
    array(rows, 128)
    result = {}
    for row in rows:
        fields(row, ('slot', 'status', 'measurement', 'reason'))
        identifier(row['slot'])
        need(row['slot'] not in result, 'LEDGER_COVERAGE')
        result[row['slot']] = row
    need(set(result) == set(expected), 'LEDGER_COVERAGE')
    return result


def slot_result(slot, row):
    need(row['status'] in ('RECORDED', 'UNKNOWN', 'NOT_APPLICABLE'), 'SCHEMA_INVALID')
    if slot['applicability'] == 'not_applicable':
        need(row['status'] == 'NOT_APPLICABLE', 'APPLICABILITY')
    else:
        need(row['status'] in ('RECORDED', 'UNKNOWN'), 'APPLICABILITY')
    reason(row['reason'], row['status'] == 'UNKNOWN')
    if row['status'] != 'RECORDED':
        need(row['measurement'] is None, 'SCHEMA_INVALID')
    else:
        identifier(row['measurement'])
    result = {key: slot[key] for key in ('id', 'attempt', 'phase', 'metric', 'currency')}
    result.update(status=row['status'], reason=slot['reason']
                  if row['status'] == 'NOT_APPLICABLE' else row['reason'])
    return result


def measurement_result(slot, record, claims, roster, used):
    key = record['measurement']
    need(key in claims and key not in used, 'MEASUREMENT_BINDING')
    artifact, row = claims[key]
    need(all(row[k] == slot[k] for k in ('metric', 'currency'))
         and row['slot'] == slot['id'], 'MEASUREMENT_BINDING')
    dimension(row['metric'], row['currency'])
    integer(row['value'])
    used.add(key)
    return dict(measurement=key, artifact=artifact, artifact_sha256=roster[artifact]['sha256'],
                value=row['value'], interval=row['interval'],
                aggregation='NONADDITIVE_OBSERVATION' if row['metric'].startswith(
                    'provider_cumulative_') else 'NO_AGGREGATION')


def interval_check(rows, owners):
    groups = {}
    for row in rows:
        if row['status'] != 'RECORDED':
            continue
        interval = row['interval']
        if row['metric'] not in TIME_METRICS:
            need(interval is None, 'INTERVAL_INVALID')
            continue
        fields(interval, ('clock', 'start', 'end'))
        identifier(interval['clock'])
        integer(interval['start'])
        integer(interval['end'])
        need(interval['start'] < interval['end'], 'INTERVAL_INVALID')
        key = (owners[row['attempt']]['actor'], row['metric'])
        prior = groups.setdefault(key, [])
        for other in prior:
            need(interval['clock'] == other['clock'], 'INTERVAL_UNCOMPARABLE')
            need(interval['start'] >= other['end'] or other['start'] >= interval['end'],
                 'INTERVAL_OVERLAP')
        prior.append(interval)


def report(plan, plan_sha, ledger_sha, results):
    return dict(schema='transport/accounting-completeness-report/1',
        status='INCOMPLETE' if any(row['status'] == 'UNKNOWN' for row in results)
        else 'RECORDED_COMPLETE', plan_sha256=plan_sha, ledger_sha256=ledger_sha,
        attempts=plan['attempts'], slots=results, authority='NONE',
        measurement_truth='UNPROVEN', source_authentication='UNKNOWN', clock_trust='UNKNOWN',
        coverage_scope='DECLARED_FROZEN_INVENTORY_ONLY', hidden_work_detection='NONE',
        benefit='NOT_ASSESSED', acceptance='NOT_ASSESSED', prespecification_timing='NOT_VERIFIED')


def checked(plan_raw, plan_sha, ledger_raw, ledger_sha, bindings):
    for raw, held in ((plan_raw, plan_sha), (ledger_raw, ledger_sha)):
        need(type(raw) is bytes and 0 < len(raw) <= CAP, 'INPUT_BOUND')
        digest(held)
        need(sha(raw) == held, 'PIN_MISMATCH')
    need(type(bindings) is dict, 'BINDING_MISMATCH')
    need(len(bindings) <= 32, 'INPUT_BOUND')
    total = 0
    for raw in bindings.values():
        need(type(raw) is bytes and 0 < len(raw) <= CAP, 'INPUT_BOUND')
        total += len(raw)
        need(total <= 1048576, 'INPUT_BOUND')
    plan, ledger = document(plan_raw), document(ledger_raw)
    owners, expected = plan_document(plan)
    fields(ledger, ('schema', 'plan_sha256', 'artifacts', 'records'))
    need(ledger['schema'] == 'transport/accounting-ledger/1', 'SCHEMA_INVALID')
    need(ledger['plan_sha256'] == plan_sha, 'PIN_MISMATCH')
    roster = artifact_roster(ledger['artifacts'], bindings)
    claims = measurements(roster, bindings, plan_sha)
    records = record_roster(ledger['records'], expected)
    results, used = [], set()
    for key in sorted(expected):
        result = slot_result(expected[key], records[key])
        if result['status'] == 'RECORDED':
            result.update(measurement_result(expected[key], records[key], claims, roster, used))
        results.append(result)
    need(used == set(claims), 'MEASUREMENT_UNUSED')
    interval_check(results, owners)
    return report(plan, plan_sha, ledger_sha, results)


def refusal(reason_code):
    return dict(schema='transport/accounting-completeness-refusal/1', status='REFUSED',
                reason=reason_code, authority='NONE')


def validate(plan_bytes, held_plan_sha256, ledger_bytes, held_ledger_sha256, artifact_bindings):
    try:
        result = checked(plan_bytes, held_plan_sha256, ledger_bytes,
                         held_ledger_sha256, artifact_bindings)
        need(len(canonical(result)) + 1 <= OUTPUT_CAP, 'OUTPUT_BOUND')
        return result
    except Refusal as error:
        return refusal(str(error))
