"""Independent create-only45-case runner; explicit readiness required pre-import."""
import hashlib
import importlib
import json
import signal
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
OUT = Path('/dev/shm/semantic-transport-claim-structure-controls-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
FROZEN_SHA = '1c30f4bfd93f8583aa65612da2bd67fa5af6947609b6d8f62bc6f3f064b6a583'


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


def call_first(function, raw, originals):
    signal.alarm(30)
    start = time.monotonic_ns()
    try:
        value = function(raw, originals)
        encoded(value)
        result = {'outcome': 'returned', 'value': value}
    except Exception as error:
        result = {'outcome': 'exception', 'type': type(error).__name__,
                  'message': str(error), 'code': getattr(error, 'code', None),
                  'stage': getattr(error, 'stage', None)}
    finally:
        signal.alarm(0)
    result['elapsed_ns_observed'] = time.monotonic_ns() - start
    return result


def caller_snapshot(originals):
    try:
        raw = encoded([{'alias': alias, 'key': key, 'hex': data.hex()}
                       for alias, key, data in originals])
        return {'status': 'SNAPSHOT', 'sha256': hashlib.sha256(raw).hexdigest()}
    except Exception as error:
        return {'status': 'SNAPSHOT_FAILED', 'type': type(error).__name__}


ready_path = OUT / 'ready-receipt.json'
ready = json.loads(ready_path.read_bytes())
if ready.get('ready') is not True or ready.get('source') not in ('/root', '/root/quorum_wire_schema'):
    raise RuntimeError('explicit authorized readiness required')
module_name = ready.get('module')
if module_name not in ('transport_quorum_claim', 'transport_quorum_claim_structure'):
    raise RuntimeError('author-confirmed fixed component module name required')
for name, digest in ready['sourcepins_verified_before_run'].items():
    path = ROOT / 'tools' / name
    if path.parent != ROOT / 'tools' or pin(path)['sha256'] != digest:
        raise RuntimeError('readiness source hash mismatch: ' + name)
if pin(OUT / 'pre-oracle-freeze.json')['sha256'] != FROZEN_SHA:
    raise ValueError('original expectation freeze changed')
freeze = json.loads((OUT / 'pre-oracle-freeze.json').read_bytes())
expectations_path = Path(freeze['expectations']['path'])
if pin(expectations_path) != freeze['expectations']:
    raise ValueError('frozen handwritten expectations changed')
expected = json.loads(expectations_path.read_bytes())
if len(expected['cases']) > 64:
    raise ValueError('case budget exceeded')
paths = sorted((ROOT / 'tools').glob('*.py'))
if len(paths) > 256 or any(path.stat().st_size > 1048576 for path in paths):
    raise ValueError('test source inventory budget exceeded')
paths += [ROOT / 'tools/transport_quorum_body.schema.json',
          ROOT / 'install/test_quorum_input.py', ROOT / 'install/test_quorum_source.py',
          expectations_path, OUT / 'run-product-first.py', ready_path]
before = [pin(path) for path in paths]
save('product-source-pins-before.json', before)
signal.signal(signal.SIGALRM, expired)
sys.path.insert(0, str(ROOT / 'tools'))
module = importlib.import_module(module_name)
function = module.check_claim_structure
rows = []
for case in expected['cases']:
    raw_path = Path(case['body_raw']['path'])
    if pin(raw_path) != case['body_raw']:
        raise ValueError('frozen candidate changed: ' + case['id'])
    raw = raw_path.read_bytes()
    originals = tuple((item['alias'], dict(item['key']),
                       bytes.fromhex(item['immutable_bytes_hex']))
                      for item in case['originals_exact_tuple_recipe'])
    caller_before = caller_snapshot(originals)
    output = call_first(function, raw, originals)
    output_pin = save('product-first-outputs/' + case['id'] + '.json', output)
    caller_after = caller_snapshot(originals)
    matches = output['outcome'] == 'returned'
    matches = matches and encoded(output['value']) == encoded(case['handwritten_expected_complete_result'])
    row = {'id': case['id'], 'raw': case['body_raw'],
        'frozen_expected_complete_result': case['handwritten_expected_complete_result'],
        'first_output': output, 'first_output_pin': output_pin,
        'matches_frozen_complete_result': matches,
        'caller_snapshot_before': caller_before, 'caller_snapshot_after': caller_after,
        'caller_inputs_unchanged': caller_before == caller_after}
    rows.append(row)
    save('product-first-outputs/' + case['id'] + '.comparison.json', row)
after = [pin(path) for path in paths]
save('product-source-pins-after.json', after)
loaded = sorted({str(Path(item.__file__).resolve()) for item in sys.modules.values()
    if getattr(item, '__file__', None) and str(Path(item.__file__).resolve()).startswith(str(ROOT / 'tools') + '/')})
report = {'classification': 'TESTED_FROZEN_CLAIM_COMPONENT_DIFFERENTIAL_ONLY',
    'readiness': pin(ready_path), 'frozen_expectations': freeze['expectations'],
    'case_count_observed': len(rows), 'cases': rows,
    'source_pins_unchanged_during_run': before == after,
    'loaded_project_module_files': loaded,
    'mismatches': [row for row in rows if not row['matches_frozen_complete_result']],
    'caller_mutation_failures': [row for row in rows if not row['caller_inputs_unchanged']],
    'qualification': 'Full named error envelopes and complete frozen declared success outputs compared as canonical JSON bytes, preserving scalar type distinctions. Source inventory is test snapshot evidence, not a runtime installation/import-closure attestation. No formal proof, semantic relevance/completeness, full reference closure, full replay or product acceptance.'}
result_pin = save('product-first-run.json', report)
print(json.dumps({'report': result_pin, 'cases': len(rows),
    'source_pins_unchanged': before == after,
    'mismatches': [row['id'] for row in report['mismatches']],
    'caller_mutations': [row['id'] for row in report['caller_mutation_failures']]}))
raise SystemExit(1 if report['mismatches'] or report['caller_mutation_failures'] or before != after else 0)
