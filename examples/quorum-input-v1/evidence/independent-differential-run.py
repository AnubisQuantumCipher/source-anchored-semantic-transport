"""Independent differential harness over pre-product frozen207 inputs.

Test only. No oracle/product edits. Public and eligible private first outcomes
are retained separately, with explicit independent contract predicates.
"""
import hashlib
import json
import signal
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
OUT = Path('/dev/shm/semantic-transport-input-shape-controls-20261029/implementation-differential-01')
FROZEN = OUT.parent
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
CONTRACT = Path('/dev/shm/semantic-transport-wire-input-20261029/contract-v2.json')
sys.path.insert(0, str(ROOT / 'tools'))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def save(name, value):
    path = OUT / name
    with path.open('xb') as stream:
        stream.write(encoded(value))
    return pin(path)


def expired(_signum, _frame):
    raise TimeoutError('per-call 30-second test timeout')


def first_call(call):
    signal.alarm(30)
    start = time.monotonic_ns()
    try:
        value = {'outcome': 'returned', 'value': call()}
    except Exception as error:
        value = {'outcome': 'exception', 'type': type(error).__name__,
                 'message': str(error), 'code': getattr(error, 'code', None),
                 'stage': getattr(error, 'stage', None)}
    finally:
        signal.alarm(0)
    value['elapsed_ns_observed'] = time.monotonic_ns() - start
    return value


def tokens(raw):
    failures = []
    def integer(text):
        if text.startswith('-'):
            failures.append('INPUT_INTEGER_TOKEN')
        elif len(text) > 20:
            failures.append('INPUT_INTEGER_BOUND')
        return int(text)
    def floating(text):
        failures.append('INPUT_INTEGER_TOKEN')
        return float(text)
    value = json.loads(raw, parse_int=integer, parse_float=floating)
    return value, failures


def metadata_inspection(value):
    pending, max_depth, scalar_ok = [(value, 0)], 0, True
    for _ in range(65536):
        if not pending:
            return max_depth, scalar_ok
        item, depth = pending.pop()
        if type(item) is dict:
            depth += 1
            max_depth = max(max_depth, depth)
            pending.extend((part, depth) for pair in item.items() for part in pair)
        elif type(item) is list:
            depth += 1
            max_depth = max(max_depth, depth)
            pending.extend((part, depth) for part in item)
        elif type(item) is str:
            try:
                item.encode('utf-8')
            except UnicodeError:
                scalar_ok = False
    raise ValueError('independent metadata inspection budget exceeded')


def text_byte_cap(node):
    if node.get('pattern') == r'^[A-Za-z][A-Za-z0-9_.:-]{0,31}$':
        return 32
    if node.get('pattern', '').startswith('^(?:[A-Za-z0-9+/]'):
        return None
    if node.get('maxLength') in (64, 1024):
        return 1024
    return 4096


def local_bounds(value, schema):
    pending, violations = [(value, schema['$defs']['ReplayBody'], [])], []
    for _ in range(65536):
        if not pending:
            return violations
        item, node, path = pending.pop()
        if type(item) is list and 'maxItems' in node and len(item) > node['maxItems']:
            violations.append({'code': 'INPUT_RECORD_BOUND', 'path': path,
                               'length': len(item), 'cap': node['maxItems']})
        if type(item) is str and node.get('type') == 'string':
            cap = text_byte_cap(node)
            if cap is not None and len(item.encode('utf-8')) > cap:
                violations.append({'code': 'INPUT_BYTE_FIELD_BOUND', 'path': path,
                                   'utf8_bytes': len(item.encode('utf-8')), 'cap': cap})
        if '$ref' in node:
            pending.append((item, schema['$defs'][node['$ref'][8:]], path))
        for key in ('allOf', 'oneOf'):
            pending.extend((item, part, path) for part in node.get(key, []))
        if type(item) is dict:
            pending.extend((item[key], part, path + [key]) for key, part in node.get('properties', {}).items() if key in item)
        if type(item) is list and 'items' in node:
            pending.extend((part, node['items'], path + [index]) for index, part in enumerate(item))
    raise ValueError('independent schema-bound inspection budget exceeded')


RECORD_ARRAYS = ('sources', 'rules', 'tasks', 'claims', 'selectors', 'dependencies',
    'input_manifests', 'blobs', 'provenance', 'run_evidence', 'readings',
    'challenges', 'reading_withdrawals', 'updates', 'history')
KINDS = {'SOURCE_MEMBERSHIP_V1', 'Q_DECLARATION_IDENTITY_V1',
         'DECLARED_DEPENDENCY_IMPACT_V1', 'RECORDED_STANCE_COUNTS_V1'}


def record_total(value):
    if type(value) is not dict or type(value.get('registry')) is not dict:
        return None
    seats = value['registry'].get('seats')
    if type(seats) is not list or any(type(value.get(key)) is not list for key in RECORD_ARRAYS):
        return None
    total = 2 + len(seats) + sum(len(value[key]) for key in RECORD_ARRAYS)
    for manifest in value['input_manifests']:
        if type(manifest) is not dict or type(manifest.get('registry_snapshot')) is not dict:
            return None
        seats = manifest['registry_snapshot'].get('seats')
        if type(seats) is not list:
            return None
        total += 1 + len(seats)
    return total


def admission_predicates(value):
    records = [value.get('registry'), value.get('policy')]
    for key in ('rules', 'tasks'):
        if type(value.get(key)) is list:
            records.extend(value[key])
    if type(value.get('input_manifests')) is list:
        records.extend(item.get('registry_snapshot') for item in value['input_manifests'] if type(item) is dict)
    bad = [record['version'] for record in records if type(record) is dict
           and type(record.get('version')) is str and record['version'] != 'V1']
    if bad:
        return [{'predicate': 'non-V1 present type-str record version', 'values': bad}]
    rules = value.get('rules')
    if type(rules) is list and all(type(item) is dict and type(item.get('kind')) is str for item in rules):
        kinds = [item['kind'] for item in rules]
        if len(kinds) != 4 or set(kinds) != KINDS:
            return [{'predicate': 'missing/duplicate/unknown admitted rule-kind set', 'kinds': kinds}]
    return []


def expectation(raw, value, oracle, schema, lexical_failures, depth, scalars):
    if len(raw) > 65536 or not raw:
        return 'PREPARSE', ['INPUT_BYTE_BOUND'], [{'predicate': 'raw byte cap', 'bytes': len(raw), 'cap': 65536}]
    if lexical_failures:
        return 'PREPARSE', [lexical_failures[0]], [{'predicate': 'wire unsigned integer lexical profile'}]
    if not scalars:
        return 'PREPARSE', ['INPUT_ENCODING'], [{'predicate': 'Unicode scalar encoding'}]
    if depth > 12:
        return 'PREPARSE', ['INPUT_DEPTH'], [{'predicate': 'container depth cap', 'depth': depth, 'cap': 12}]
    violations = local_bounds(value, schema)
    count = record_total(value)
    if count is not None and count > 96:
        violations.append({'code': 'INPUT_RECORD_BOUND', 'predicate': 'aggregate record formula', 'total': count, 'cap': 96})
    if violations:
        return 'BOUNDS', sorted({item['code'] for item in violations}), violations
    admission = admission_predicates(value)
    if admission:
        return 'SCHEMA', ['INPUT_UNADMITTED'], admission
    if oracle == 'REJECT':
        return 'SCHEMA', ['INPUT_CLOSED_SCHEMA'], [{'predicate': 'frozen independent jsonschema rejection'}]
    if encoded(value) != raw:
        return 'CANONICAL_BYTES', ['INPUT_NONCANONICAL'], [{'predicate': 'exact canonical byte comparison'}]
    return 'BODY_INPUT_SHAPE_ONLY', [], [{'predicate': 'all scoped contract predicates passed; frozen oracle shape ACCEPT'}]


signal.signal(signal.SIGALRM, expired)
files = [ROOT / 'tools' / name for name in ['transport_quorum_input.py',
    'transport_quorum_shape.py', 'transport_quorum_body.schema.json',
    'transport_schema.py', 'transport_wire.py']]
files += [CONTRACT, FROZEN / 'pre-oracle-freeze.json',
          FROZEN / 'oracle-results-first-run.json', OUT / 'run.py']
before = [pin(path) for path in files]
save('source-pins-before.json', before)
import transport_quorum_input as product_input
import transport_quorum_shape as product_shape

schema_load = first_call(product_shape.load_schema)
if schema_load['outcome'] != 'returned':
    save('bootstrap-first-output.json', schema_load)
    raise RuntimeError('product bootstrap failed; retained first output')
schema = schema_load.pop('value')
save('bootstrap-first-output.json', dict(schema_load, loaded_schema_sha256=pin(product_shape.SCHEMA_PATH)['sha256']))
oracle = json.loads((FROZEN / 'oracle-results-first-run.json').read_bytes())
rows = []
for original in oracle['cases']:
    raw_path = Path(original['raw']['path'])
    if pin(raw_path) != original['raw']:
        raise ValueError('frozen raw changed: ' + original['id'])
    raw = raw_path.read_bytes()
    value, lexical_failures = tokens(raw)
    depth, scalar_ok = metadata_inspection(value)
    canonical_profile = encoded(value) == raw
    stage, codes, predicates = expectation(raw, value, original['observed_shape'], schema, lexical_failures, depth, scalar_ok)
    public = first_call(lambda: product_input.check_body_input(raw))
    public_pin = save('first-outputs/' + original['id'] + '.public.json', public)
    returned = public.get('value', {})
    public_match = public['outcome'] == 'returned' and returned.get('stage') == stage
    public_match = public_match and (returned.get('status') == 'ok' if not codes else returned.get('status') == 'error' and returned.get('error') in codes)
    eligible = len(raw) <= 65536 and not lexical_failures and depth <= 12 and scalar_ok and canonical_profile
    private = {'outcome': 'SKIPPED', 'reason': 'Outside bounded canonical integer-token scalar-compatible differential domain.'}
    private_match = None
    if eligible:
        private = first_call(lambda: product_shape._evaluate(value, schema, product_shape.Budget('SCHEMA'), False))
        private_match = private['outcome'] == 'returned' and type(private.get('value')) is bool and private['value'] == (original['observed_shape'] == 'ACCEPT')
    private_pin = save('first-outputs/' + original['id'] + '.private.json', private)
    row = {'id': original['id'], 'raw': original['raw'],
        'original_handwritten_shape': original['handwritten_shape_expected'],
        'frozen_external_oracle_shape': original['observed_shape'],
        'original_handwritten_discrepancy_retained': not original['matches_handwritten'],
        'public_first_output': public, 'public_first_output_pin': public_pin,
        'public_expected_stage': stage, 'public_expected_allowed_codes': codes,
        'independent_contract_predicates': predicates, 'public_matches_contract': public_match,
        'private_domain_eligible': eligible, 'private_first_output': private,
        'private_first_output_pin': private_pin, 'private_matches_external_oracle': private_match}
    rows.append(row)
    save('first-outputs/' + original['id'] + '.comparison.json', row)

after = [pin(path) for path in files]
save('source-pins-after.json', after)
report = {'scope': 'TEST_ONLY_FROZEN_SHAPE_DIFFERENTIAL_NO_REPLAY',
    'source_pins_unchanged_during_run': before == after,
    'case_count_observed': len(rows), 'cases': rows,
    'public_contract_discrepancies': [row for row in rows if not row['public_matches_contract']],
    'private_shape_discrepancies': [row for row in rows if row['private_matches_external_oracle'] is False],
    'private_domain_skips': [row['id'] for row in rows if not row['private_domain_eligible']],
    'retained_original_handwritten_discrepancies': [row['id'] for row in rows if row['original_handwritten_discrepancy_retained']],
    'qualification': 'Private comparison excludes oversized, noncanonical, non-scalar and non-unsigned-integer-token inputs. Private candidates remain globally raw/depth bounded; local shape violations may be compared. Public stricter refusals are compared only against explicit independent frozen-contract predicates. TESTED only; no formal proof, full replay or product acceptance.'}
result_pin = save('report.json', report)
print(json.dumps({'report': result_pin, 'cases': len(rows),
    'source_pins_unchanged': before == after,
    'public_discrepancies': [row['id'] for row in report['public_contract_discrepancies']],
    'private_discrepancies': [row['id'] for row in report['private_shape_discrepancies']],
    'private_skipped': report['private_domain_skips']}))
