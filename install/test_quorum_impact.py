#!/usr/bin/env python3
"""Frozen complete declared-impact cases; no update authority or currentness."""

import argparse
import base64
import copy
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_quorum_impact import check_declared_impact
import transport_quorum_impact as product
import transport_quorum_input as metadata

FIXTURES = ROOT / 'examples/quorum-impact-v1'
PINS = {
    'focused/hostile-pin-expectations.json': '9d4b1341b49e84ba10f19247db6a24bd5ad4f703fe80d5b0f8269bc0297c1edf',
    'review-01/probe-expectations.json': 'b761f6f55f1e94ccf312eb81b9fa9e1a479f227bf2ac10ca91ab856aa954388b',
    'contract.json': 'd61e10e00460aa3dcff68748f5f3e30149d92a4df8a0dd64d34f9f7acd0e718d',
    'oracle.json': 'f871cb750e770a15ea37a98f0e47eede7cdd5d98dee451f585715d4111552b8b',
    'focused/handwritten-expectations.json': 'c3eaf465ae17db703b318793f51609afef680179c5ed011155696cf435db9ab8',
}
SOURCE = ('tools/transport_quorum_impact.py', 'tools/transport_quorum_graph.py',
          'tools/transport_quorum_claim.py', 'tools/transport_quorum_source.py',
          'tools/transport_quorum_input.py', 'tools/transport_quorum_shape.py',
          'tools/transport_quorum_body.schema.json', 'tools/transport_schema.py',
          'tools/transport_wire.py', 'install/test_quorum_impact.py')
OUTCOMES = []
CALLBACKS = []


def read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError('fixture must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('fixture exceeds byte bound')
    return raw


def frozen(name: str) -> dict:
    raw = read(FIXTURES / name)
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('fixture identity mismatch')
    return json.loads(raw)


def serialize(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def held_recipe(items: list) -> tuple:
    if len(items) > 9:
        raise ValueError('fixture held recipe count exceeded')
    return tuple(None if item is None else
                 (item['event_id'], item['sha256'], item['byte_length']) for item in items)


def compact_case(case: dict) -> tuple:
    files = {}
    for name, pin in case['files'].items():
        raw = read(FIXTURES / case['id'] / name)
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('literal candidate identity mismatch')
        files[name] = raw
    recipe = json.loads(files['originals.json'])
    if recipe['outer_type'] != 'tuple' or len(recipe['items']) > 15:
        raise ValueError('unsupported literal fixture recipe')
    originals = []
    for item in recipe['items']:
        if item['item_type'] != 'tuple' or item['data_type'] != 'bytes':
            raise ValueError('unsupported literal item recipe')
        originals.append((item['alias_id'], item['key'],
                          base64.b64decode(item['base64'], validate=True)))
    held = json.loads(files['held-update-pins.json'])
    if held['outer_type'] != 'tuple':
        raise ValueError('unsupported held recipe')
    return files['body.json'], tuple(originals), held_recipe(held['items']), json.loads(files['expected.json'])


def focused_case(case: dict) -> tuple:
    raw = read(FIXTURES / 'focused/raw' / Path(case['body_raw']['path']).name)
    pin = case['body_raw']
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('focused candidate identity mismatch')
    originals = tuple((item['alias'], item['key'], bytes.fromhex(item['immutable_bytes_hex']))
                      for item in case['originals_exact_tuple_recipe'])
    held = case['held_update_pins_exact_tuple_recipe']
    if held['outer'] != 'exact_tuple':
        raise ValueError('unsupported focused held recipe')
    return raw, originals, held_recipe(held['items']), case['handwritten_expected_complete_result']


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


def review_public(name: str) -> tuple:
    bases = {'A06_PREDECESSOR_BEFORE_HISTORY': 'I23_PRIOR_ARTIFACT_MISMATCH',
             'A07_CYCLE_BEFORE_KIND': 'I12_CLAIM_CYCLE', 'A10_ARRAY_ORDER': 'I03_TRANSITIVE'}
    base = bases.get(name, 'I02_REPLACEMENT')
    case = next(c for c in frozen('oracle.json')['cases'] if c['id'] == base)
    raw, originals, _, expected = compact_case(case)
    body = json.loads(raw)
    if name == 'A03_LATER_KIND_BEFORE_EARLY_PROVENANCE':
        body['updates'][0]['provenance']['id'] = 'MISSING'
        update = copy.deepcopy(body['updates'][0])
        update.update(id='Z', kind='WITHDRAWAL')
        body['updates'].append(update)
    elif name == 'A04_OLD_BEFORE_PROVENANCE_DUPLICATE':
        body['updates'][0]['old_version']['sha256'] = '0' * 64
        body['provenance'].append(copy.deepcopy(body['provenance'][0]))
    elif name == 'A05_DUPLICATE_BEFORE_MISSING_PROVENANCE':
        body['updates'][0]['provenance']['id'] = 'MISSING'
        body['provenance'].append(copy.deepcopy(body['provenance'][0]))
    elif name == 'A06_PREDECESSOR_BEFORE_HISTORY':
        body['updates'][0]['predecessor_event_id'] = 'MISSING'
    elif name == 'A07_CYCLE_BEFORE_KIND':
        body['updates'][0]['kind'] = 'WITHDRAWAL'
    elif name in ('A08_UNOWNED_RECORD', 'A09_MISSING_DEPENDENT'):
        dependency = copy.deepcopy(body['dependencies'][0])
        dependency['id'] = 'ZZ_EXTRA'
        if name == 'A09_MISSING_DEPENDENT':
            dependency['dependent']['claim_id'] = 'MISSING'
        body['dependencies'].append(dependency)
    elif name == 'A10_ARRAY_ORDER':
        for value in body.values():
            if type(value) is list:
                value.reverse()
    held = tuple((u['id'], hashlib.sha256(serialize(u)).hexdigest(), len(serialize(u)))
                 for u in body['updates'])
    if name == 'A01_HOST_OUTER':
        held = EvilTuple(held)
    elif name == 'A02_HOST_ITEM':
        held = (EvilTuple(held[0]),)
    raw = serialize(body)
    expected['body_pin'] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return raw, originals, held, expected


def review_private(name: str) -> dict | None:
    # Synthetic helper probes do not establish public Body reachability.
    try:
        if name == 'R01_WORK_CHARGE':
            product._charge([8192])
        elif name == 'R02_DEPTH':
            product._walk({'paths': []}, {'id': 'U', 'old_version': {}}, 0, 33,
                [[(i + 1, 'D' + str(i))] for i in range(33)] + [[]], [0], [0])
        elif name == 'R03_OUTPUT_INCREMENTAL':
            product._append_path({'paths': []}, {'id': 'U', 'old_version': {}}, ['D'], [32768])
        elif name == 'R04_OUTPUT_ACCOUNTING':
            product._paths({'claims': []}, {}, [], {}, [], [0])
        elif name == 'R05_TRIGGER_COVERAGE':
            product._verify_paths({'paths': [], 'trigger_update_ids': ['U']}, 0, {}, [])
        elif name == 'R06_EXACT_TERMINAL':
            seed = dict(logical_source_id='S', sha256='0' * 64, bytes=0)
            entry = dict(paths=[dict(dependency_ids=['D'], seed=seed, trigger_update_id='U')],
                         trigger_update_ids=['U'])
            product._verify_paths(entry, 0, {serialize(seed): 2}, [(0, 1, 'D')])
        else:
            raise ValueError('unknown private probe')
    except metadata.InputError as error:
        return metadata._error(error)
    return None


class ImpactTests(unittest.TestCase):
    def compare(self, name, raw, originals, held, expected):
        results = []
        for arm in ('original_annotation', 'transport_projection'):
            result = check_declared_impact(raw, originals, held)
            OUTCOMES.append(dict(case=name, arm=arm, result=result, expected=expected))
            self.assertEqual(result, expected)
            self.assertLessEqual(len(serialize(result)) + 1, 32768)
            results.append(result)
        self.assertEqual(results[0], results[1])
        self.assertIsNot(results[0], results[1])

    def test_complete_manual_results(self):
        frozen('contract.json')
        cases = frozen('oracle.json')['cases']
        self.assertEqual(len(cases), 27)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case))

    def test_independent_minimal_pairs(self):
        cases = frozen('focused/handwritten-expectations.json')['cases']
        self.assertEqual(len(cases), 32)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *focused_case(case))

    def test_body_first_and_owned_output(self):
        self.compare('body_before_host_pins', b'{', None, None,
                     dict(status='error', stage='PREPARSE', error='INPUT_JSON'))
        raw, originals, held, expected = compact_case(frozen('oracle.json')['cases'][1])
        before = [(alias, serialize(key), data) for alias, key, data in originals]
        result = check_declared_impact(raw, originals, held)
        self.assertEqual(result, expected)
        self.assertEqual([(alias, serialize(key), data) for alias, key, data in originals], before)
        snapshot = serialize(result)
        originals[0][1]['bytes'] = 123
        self.assertEqual(serialize(result), snapshot)
        self.assertEqual(result['current_authority'], 'NONE')
        self.assertEqual(result['independent_custody'], 'UNKNOWN')
        parameters = list(inspect.signature(check_declared_impact).parameters)
        expected_parameters = ['body_raw', 'originals', 'held_update_pins']
        OUTCOMES.append(dict(case='PUBLIC_INTERFACE', result=parameters, expected=expected_parameters))
        self.assertEqual(parameters, expected_parameters)

    def test_hostile_host_pin_boundary(self):
        baseline = next(c for c in frozen('focused/handwritten-expectations.json')['cases']
                        if c['id'] == 'I01_CHAIN')
        for case in frozen('focused/hostile-pin-expectations.json')['cases']:
            with self.subTest(case=case['id']):
                raw, originals, held, _ = focused_case(baseline)
                held = held_argument(case['recipe'], held)
                if 'body_raw_hex_override' in case:
                    raw = bytes.fromhex(case['body_raw_hex_override'])
                if case.get('originals_override') == 'NONE':
                    originals = None
                CALLBACKS.clear()
                self.compare(case['id'], raw, originals, held, case['expected'])
                self.assertEqual(CALLBACKS, [])

    def test_independent_review_probes(self):
        for case in frozen('review-01/probe-expectations.json')['cases']:
            with self.subTest(case=case['id']):
                CALLBACKS.clear()
                if case['id'].startswith('A'):
                    raw, originals, held, expected = review_public(case['id'])
                    if case['id'] != 'A10_ARRAY_ORDER':
                        expected = case['expected']
                    self.compare(case['id'], raw, originals, held, expected)
                else:
                    actual = review_private(case['id'])
                    OUTCOMES.append(dict(case=case['id'], scope='PRIVATE_HELPER_ONLY',
                                         result=actual, expected=case['expected']))
                    self.assertEqual(actual, case['expected'])
                self.assertEqual(CALLBACKS, [])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ImpactTests))
    if args.evidence is not None:
        pins = {name: hashlib.sha256(read(ROOT / name)).hexdigest() for name in SOURCE}
        data = dict(schema='quorum/impact-component-results/1', passed=result.wasSuccessful(),
            test_methods=result.testsRun, source_pins=pins, fixture_pins=PINS, python=sys.version,
            outputs=OUTCOMES, full_replay='UNRUN', formal_proof='UNPROVEN',
            external_validation='EXTERNAL_VALIDATION_PENDING', benefit='NOT_MEASURED')
        raw = serialize(data)
        if len(raw) > 1048576:
            raise ValueError('test evidence bound exceeded')
        with args.evidence.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('short evidence write')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
