#!/usr/bin/env python3
"""Frozen complete declared-context cases; no update authority or currentness."""

import argparse
import base64
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_quorum_context import check_context_bindings
import transport_quorum_context as product
import transport_quorum_input as metadata

FIXTURES = ROOT / 'examples/quorum-context-v1'
PINS = {
    'contract.json': '6441d7df28267ffe148980c5b66d4b771f52290e41b1e13edec6679065ba2686',
    'design-addendum.json': '37d1f74b9fbaee8fed6e81ad57e02543ebe0fbbd8ae28aabdeea2f5dbdfc2608',
    'oracle.json': '53e5a4480cc7d72e95a0235ee523381a38d8963f2583300080cd31715d5ec2b5',
    'focused/handwritten-expectations.json': '7500bfdbe5bc9a7e05182187bf59aa6ec56c10fd40f453713afc1a032a6782cc',
    'review-01/complementary-controls/oracle.json': '50b2a656abe53b9b32276acb63fbe9d6c972df280c8696f2b634428825edbf3e',
    'code-review-01/additional-probe-expectations.json': '51b5ca1e66c81678afe9be121586a54e763d4f7b540b003567652040509cd1c6',
}
SOURCE = ('tools/transport_quorum_context.py', 'tools/transport_quorum_impact.py', 'tools/transport_quorum_graph.py',
          'tools/transport_quorum_claim.py', 'tools/transport_quorum_source.py',
          'tools/transport_quorum_input.py', 'tools/transport_quorum_shape.py',
          'tools/transport_quorum_body.schema.json', 'tools/transport_schema.py',
          'tools/transport_wire.py', 'install/test_quorum_context.py')
OUTCOMES = []
CALLBACKS = []


def trip(name):
    CALLBACKS.append(name)
    raise RuntimeError('host callback invoked: ' + name)


class HostTuple(tuple):
    def __iter__(self):
        return trip('iter')
    def __len__(self):
        return trip('len')
    def __getitem__(self, key):
        return trip('getitem')


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


def compact_case(case: dict, folder: Path = FIXTURES) -> tuple:
    files = {}
    for name, pin in case['files'].items():
        raw = read(folder / case['id'] / name)
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


def public_probe(name):
    raw, originals, held, _ = compact_case(frozen('oracle.json')['cases'][0])
    if name == 'H01_NO_PARSED_BODY_BYPASS':
        raw = json.loads(raw)
    elif name == 'H02_HELD_TUPLE_SUBCLASS':
        held = HostTuple(held)
    elif name == 'H03_ORIGINALS_TUPLE_SUBCLASS':
        originals = HostTuple(originals)
    elif name == 'H04_BAD_RAW_BEFORE_HOST':
        raw, originals, held = b'{', HostTuple(originals), HostTuple(held)
    elif name == 'H05_OWNED_OUTPUT_AND_API':
        case = frozen('focused/handwritten-expectations.json')['cases'][0]
        raw, originals, held, expected = focused_case(case)
        before = [(alias, serialize(key), data) for alias, key, data in originals]
        result = check_context_bindings(raw, originals, held)
        snapshot = serialize(result)
        unchanged = before == [(alias, serialize(key), data) for alias, key, data in originals]
        for _, key, _ in originals:
            key['bytes'] = 999
        return dict(output_matches_literal=result == expected,
            caller_unchanged_before_mutation=unchanged,
            output_unchanged_after_mutation=serialize(result) == snapshot,
            api=list(inspect.signature(check_context_bindings).parameters))
    else:
        raise ValueError('unknown public probe')
    return check_context_bindings(raw, originals, held)


def private_probe(name):
    # Synthetic helper bounds are not public Body reachability evidence.
    try:
        if name == 'R01_SORT_EXACT_AGGREGATE_BOUND':
            value = ['X' * 32766, 'Y' * 32766]
            return dict(same_order=product._ordered(value) == value)
        if name == 'R02_SORT_AGGREGATE_OVERFLOW':
            return product._ordered(['X' * 32766, 'Y' * 32766, ''])
        if name == 'R03_OUTPUT_BOUND_EXPLICIT':
            body = dict(registry=dict(id='REGISTRY'), tasks=[dict(id='TASK')])
            index = {name: (kind, {}, dict(id=name, sha256='0' * 64, bytes=0))
                     for name, kind in [('REGISTRY', 'Registry'), ('TASK', 'TaskView')]}
            return product._result(body, dict(body_pin=dict(sha256='X' * 32768, bytes=0)), index, [], [])
        if name == 'R04_CANONICAL_SCALAR_ORDER':
            return product._ordered(['S\n', 'S:'])
        if name == 'R05_CLAIM_PAIR_ORDER':
            return product._ordered([dict(id='A:B', revision='A'), dict(id='A', revision='Z')], 'claim')
        raise ValueError('unknown private probe')
    except metadata.InputError as error:
        return metadata._error(error)


class ContextTests(unittest.TestCase):
    def compare(self, name, raw, originals, held, expected):
        results = []
        for arm in ('original_annotation', 'transport_projection'):
            result = check_context_bindings(raw, originals, held)
            OUTCOMES.append(dict(case=name, arm=arm, result=result, expected=expected))
            self.assertEqual(result, expected)
            self.assertLessEqual(len(serialize(result)) + 1, 32768)
            results.append(result)
        self.assertEqual(results[0], results[1])
        self.assertIsNot(results[0], results[1])

    def test_complete_manual_results(self):
        frozen('contract.json')
        frozen('design-addendum.json')
        cases = frozen('oracle.json')['cases']
        self.assertEqual(len(cases), 31)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case))

    def test_independent_minimal_pairs(self):
        cases = frozen('focused/handwritten-expectations.json')['cases']
        self.assertEqual(len(cases), 55)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *focused_case(case))

    def test_body_first_and_owned_output(self):
        self.compare('body_before_host_pins', b'{', None, None,
                     dict(status='error', stage='PREPARSE', error='INPUT_JSON'))
        raw, originals, held, expected = compact_case(frozen('oracle.json')['cases'][1])
        before = [(alias, serialize(key), data) for alias, key, data in originals]
        result = check_context_bindings(raw, originals, held)
        self.assertEqual(result, expected)
        self.assertEqual([(alias, serialize(key), data) for alias, key, data in originals], before)
        snapshot = serialize(result)
        originals[0][1]['bytes'] = 123
        self.assertEqual(serialize(result), snapshot)
        self.assertEqual(result['current_authority'], 'NONE')
        self.assertEqual(result['independent_inputs'], 'UNKNOWN')
        parameters = list(inspect.signature(check_context_bindings).parameters)
        expected_parameters = ['body_raw', 'originals', 'held_update_pins']
        OUTCOMES.append(dict(case='PUBLIC_INTERFACE', result=parameters, expected=expected_parameters))
        self.assertEqual(parameters, expected_parameters)

    def test_independent_precedence_controls(self):
        folder = FIXTURES / 'review-01/complementary-controls'
        cases = frozen('review-01/complementary-controls/oracle.json')['cases']
        self.assertEqual(len(cases), 5)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case, folder))

    def test_independent_host_and_resource_probes(self):
        cases = frozen('code-review-01/additional-probe-expectations.json')['cases']
        self.assertEqual(len(cases), 10)
        for case in cases:
            with self.subTest(case=case['id']):
                CALLBACKS.clear()
                private = case['id'].startswith('R')
                result = private_probe(case['id']) if private else public_probe(case['id'])
                OUTCOMES.append(dict(case=case['id'], result=result, expected=case['expected'],
                    scope='PRIVATE_HELPER_ONLY' if private else 'PUBLIC_BOUNDARY'))
                self.assertEqual(result, case['expected'])
                self.assertEqual(CALLBACKS, [])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ContextTests))
    if args.evidence is not None:
        pins = {name: hashlib.sha256(read(ROOT / name)).hexdigest() for name in SOURCE}
        data = dict(schema='quorum/context-component-results/1', passed=result.wasSuccessful(),
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
