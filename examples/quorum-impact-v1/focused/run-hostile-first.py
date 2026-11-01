"""Frozen bounded hostile host-pin probes; no callback may reach product work."""
import hashlib
import importlib
import json
import signal
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
OUT = Path('/dev/shm/semantic-transport-impact-controls-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
HOST_SHA = '9d4b1341b49e84ba10f19247db6a24bd5ad4f703fe80d5b0f8269bc0297c1edf'
CALLBACKS = []


def trip(name):
    CALLBACKS.append(name)
    raise RuntimeError('host callback invoked: ' + name)


class EvilStr(str):
    def __hash__(self):
        return trip('str.hash')
    def __eq__(self, other):
        return trip('str.eq')
    def __lt__(self, other):
        return trip('str.lt')
    def __len__(self):
        return trip('str.len')
    def encode(self, *args, **kwargs):
        return trip('str.encode')
    def isascii(self):
        return trip('str.isascii')


class EvilTuple(tuple):
    def __iter__(self):
        return trip('tuple.iter')
    def __len__(self):
        return trip('tuple.len')
    def __getitem__(self, key):
        return trip('tuple.getitem')


class EvilInt(int):
    def __int__(self):
        return trip('int.int')
    def __index__(self):
        return trip('int.index')
    def __lt__(self, other):
        return trip('int.lt')
    def __gt__(self, other):
        return trip('int.gt')
    def __eq__(self, other):
        return trip('int.eq')
    def __hash__(self):
        return trip('int.hash')


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


def held_argument(recipe, baseline):
    event_id, digest, length = baseline[0]
    if recipe == 'outer_list':
        return list(baseline)
    if recipe == 'outer_subclass':
        return EvilTuple(baseline)
    if recipe == 'item_list':
        return ([event_id, digest, length],)
    if recipe == 'item_subclass':
        return (EvilTuple(baseline[0]),)
    if recipe == 'count_before_hostile':
        return (EvilTuple(baseline[0]),) + (None,) * 8
    replacements = {
        'event_subclass': (EvilStr(event_id), digest, length),
        'sha_subclass': (event_id, EvilStr(digest), length),
        'length_subclass': (event_id, digest, EvilInt(length)),
        'bool_length': (event_id, digest, True),
        'event_none': (None, digest, length), 'sha_none': (event_id, None, length),
        'negative_length': (event_id, digest, -1), 'invalid_id': ('_U1', digest, length),
        'upper_sha': (event_id, 'A' * 64, length), 'length_over': (event_id, digest, 65537),
        'final_lf_id': (event_id + '\n', digest, length),
        'huge_id': ('A' * 4096, digest, length), 'nonascii_id': ('é', digest, length),
        'short_sha': (event_id, 'a' * 63, length)}
    return (replacements[recipe],)


def expired(_signum, _frame):
    raise TimeoutError('30-second per-call timeout')


ready = json.loads((OUT / 'ready-receipt.json').read_bytes())
if ready.get('ready') is not True or ready.get('source') not in ('/root', '/root/quorum_wire_schema'):
    raise RuntimeError('explicit readiness required')
for name, digest in ready['sourcepins_verified_before_run'].items():
    if pin(ROOT / 'tools' / name)['sha256'] != digest:
        raise ValueError('readiness source changed')
if pin(OUT / 'hostile-pin-expectations.json')['sha256'] != HOST_SHA:
    raise ValueError('hostile expectations changed')
manual = json.loads((OUT / 'hostile-pin-expectations.json').read_bytes())
frozen = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
baseline = next(item for item in frozen['cases'] if item['id'] == 'I01_CHAIN')
if pin(Path(baseline['body_raw']['path'])) != baseline['body_raw']:
    raise ValueError('baseline raw changed')
baseline_held = tuple((item['event_id'], item['sha256'], item['byte_length'])
    for item in baseline['held_update_pins_exact_tuple_recipe']['items'])
paths = sorted((ROOT / 'tools').glob('*.py'))
paths += [ROOT / 'tools/transport_quorum_body.schema.json', OUT / 'run-hostile-first.py']
before = [pin(path) for path in paths]
signal.signal(signal.SIGALRM, expired)
sys.path.insert(0, str(ROOT / 'tools'))
product = importlib.import_module('transport_quorum_impact').check_declared_impact
rows = []
for case in manual['cases']:
    held = held_argument(case['recipe'], baseline_held)
    raw = (bytes.fromhex(case['body_raw_hex_override']) if 'body_raw_hex_override' in case
           else Path(baseline['body_raw']['path']).read_bytes())
    originals = tuple((item['alias'], dict(item['key']), bytes.fromhex(item['immutable_bytes_hex']))
        for item in baseline['originals_exact_tuple_recipe'])
    if case.get('originals_override') == 'NONE':
        originals = None
    CALLBACKS.clear()
    signal.alarm(30)
    start = time.monotonic_ns()
    try:
        value = product(raw, originals, held)
        output = {'outcome': 'returned', 'value': value}
    except Exception as error:
        output = {'outcome': 'exception', 'type': type(error).__name__, 'message': str(error)}
    finally:
        signal.alarm(0)
    output.update(elapsed_ns_observed=time.monotonic_ns() - start,
                  host_callbacks=list(CALLBACKS))
    first = save('hostile-first-outputs/' + case['id'] + '.json', output)
    matches = output['outcome'] == 'returned' and encoded(output['value']) == encoded(case['expected'])
    callback_ok = len(CALLBACKS) == case['expected_host_callbacks']
    rows.append({'id': case['id'], 'expected': case['expected'], 'first_output': output,
        'first_output_pin': first, 'matches_frozen_error': matches,
        'host_callbacks_match': callback_ok})
after = [pin(path) for path in paths]
report = {'classification': 'TESTED_FROZEN_HOSTILE_HOST_PIN_BOUNDARY_ONLY',
    'expectations': pin(OUT / 'hostile-pin-expectations.json'), 'cases': rows,
    'source_pins_before': before, 'source_pins_after': after,
    'source_pins_unchanged_during_run': before == after,
    'mismatches': [row for row in rows if not row['matches_frozen_error'] or not row['host_callbacks_match']],
    'qualification': 'Finite hostile caller types and argument priority only; does not prove general callback isolation, resource bounds or whole-component correctness.'}
result = save('hostile-first-run.json', report)
print(json.dumps({'report': result, 'cases': len(rows), 'source_pins_unchanged': before == after,
                  'mismatches': [row['id'] for row in report['mismatches']]}))
raise SystemExit(1 if report['mismatches'] or before != after else 0)
