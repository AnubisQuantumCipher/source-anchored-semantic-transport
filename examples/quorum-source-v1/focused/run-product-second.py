"""Create-only independent first product run; requires explicit readiness receipt."""
import hashlib
import importlib
import json
import signal
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
EXPECTED_SHA = '4f066212c3f4ded072adbd3d881ee96eb2584228265a27a7b3a9aa6db785c182'


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
    raise TimeoutError('30-second per-call timeout')


def first_call(function, raw, originals):
    signal.alarm(30)
    start = time.monotonic_ns()
    try:
        result = function(raw, originals)
        encoded(result)
        output = {'outcome': 'returned', 'value': result}
    except Exception as error:
        output = {'outcome': 'exception', 'type': type(error).__name__,
                  'message': str(error), 'code': getattr(error, 'code', None),
                  'stage': getattr(error, 'stage', None)}
    finally:
        signal.alarm(0)
    output['elapsed_ns_observed'] = time.monotonic_ns() - start
    return output


ready_path = OUT / 'repair-ready-receipt.json'
if not ready_path.is_file():
    raise RuntimeError('explicit author/owner ready receipt required before import')
ready = json.loads(ready_path.read_bytes())
if ready.get('ready') is not True or ready.get('source') not in ('/root', '/root/quorum_wire_schema'):
    raise RuntimeError('readiness receipt lacks authorized author/owner message')
component = ROOT / 'tools/transport_quorum_source.py'
if not component.is_file():
    raise RuntimeError('source component absent; no execution admitted')
expectations_path = OUT / 'product-differential-expectations.json'
if pin(expectations_path)['sha256'] != EXPECTED_SHA:
    raise ValueError('frozen product expectations changed')
expected = json.loads(expectations_path.read_bytes())
if len(expected['cases']) > 64:
    raise ValueError('case count budget exceeded')
paths = [ROOT / 'tools' / name for name in ['transport_quorum_source.py',
    'transport_quorum_input.py', 'transport_quorum_shape.py',
    'transport_quorum_body.schema.json', 'transport_schema.py', 'transport_wire.py']]
paths += [ROOT / 'install/test_quorum_input.py', expectations_path,
          OUT / 'run-product-second.py', ready_path]
before = [pin(path) for path in paths]
save('product-second-source-pins-before.json', before)
signal.signal(signal.SIGALRM, expired)
sys.path.insert(0, str(ROOT / 'tools'))
module = importlib.import_module('transport_quorum_source')
function = module.check_source_membership
rows = []
for case in expected['cases']:
    raw_path = Path(case['raw']['path'])
    if pin(raw_path) != case['raw']:
        raise ValueError('frozen source control changed: ' + case['id'])
    raw = raw_path.read_bytes()
    originals = tuple((item['alias'], dict(item['key']),
                       bytes.fromhex(item['immutable_bytes_hex']))
                      for item in case['originals_exact_tuple_recipe'])
    caller_before = encoded([{'alias': alias, 'key': key, 'hex': data.hex()}
                             for alias, key, data in originals])
    output = first_call(function, raw, originals)
    first_pin = save('product-second-outputs/' + case['id'] + '.json', output)
    caller_after = encoded([{'alias': alias, 'key': key, 'hex': data.hex()}
                            for alias, key, data in originals])
    matches = output['outcome'] == 'returned'
    matches = matches and encoded(output['value']) == encoded(case['expected_complete_result'])
    row = {'id': case['id'], 'raw': case['raw'],
        'frozen_expected_complete_result': case['expected_complete_result'],
        'first_output': output, 'first_output_pin': first_pin,
        'matches_frozen_complete_result': matches,
        'caller_inputs_unchanged': caller_before == caller_after}
    rows.append(row)
    save('product-second-outputs/' + case['id'] + '.comparison.json', row)
after = [pin(path) for path in paths]
save('product-second-source-pins-after.json', after)
report = {'classification': 'TESTED_SOURCE_COMPONENT_DIFFERENTIAL_ONLY',
    'source_pins_unchanged_during_run': before == after,
    'readiness_receipt': pin(ready_path), 'frozen_expectations': pin(expectations_path),
    'case_count_observed': len(rows), 'cases': rows,
    'mismatches': [row for row in rows if not row['matches_frozen_complete_result']],
    'caller_mutation_failures': [row for row in rows if not row['caller_inputs_unchanged']],
    'qualification': 'Exact complete error envelopes and complete declared success projection compared by canonical JSON bytes, preserving bool/integer distinction. No formal proof, general completeness, source authentication, semantic truth or full replay acceptance. Existing input suite rerun is a separate retained receipt.'}
result_pin = save('product-second-run.json', report)
print(json.dumps({'report': result_pin, 'cases': len(rows),
    'source_pins_unchanged': before == after,
    'mismatches': [row['id'] for row in report['mismatches']],
    'caller_mutations': [row['id'] for row in report['caller_mutation_failures']]}))
