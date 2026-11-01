#!/usr/bin/env python3
"""Frozen reading closure and count fixtures; no actual model or authority claim."""

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
from transport_quorum_reading import check_reading_aggregation
import transport_quorum_reading as product
import transport_quorum_input as metadata

FIXTURES = ROOT / 'examples/quorum-reading-v1'
PINS = {
    'contract.json': 'f7303d91e238b95a794ff49477903c872981891ccc268e75c81e4d2b972d0c84',
    'design-addendum.json': '87f9f5fb6bdd1156ca73987392aa973f9cc7fa85406fcbfed39457fbc1b6a6d8',
    'output-resource-addendum.json': '96a0a7452fdb60d8baa4cc563007519046dac032170a1e8fa1a0ce9f238b8d7b',
    'oracle.json': '65e6826f5f45fc6fb5487f7195746a062e1da020c677be3adad683dc905f34b2',
    'review-01/precedence-controls/oracle.json': '71b0c69a743458b85ab9f97ce8d5bcdd7e9df93e2527bd18703791c4d58a7ac8',
    'focused/revision-02/handwritten-expectations.json': '52489a2cac40b2a3402f5e6fcb2a04cd82ba09b613fe9bf60db841265d712faf',
    'code-review-01/resource-probe-expectations.json': '46ea70f3453da4206345020ffb30ae6d7f1309394c43a09646cec06f7a2576e0',
    'review-01/precedence-controls/host-count-probe.json': '321393c8d66f7c0969d935e593d761386f73b6d7c39a3cacbab5c2dd5b5cf440',
}
SOURCE = ('tools/transport_quorum_reading.py', 'tools/transport_quorum_context.py',
          'tools/transport_quorum_impact.py', 'tools/transport_quorum_graph.py',
          'tools/transport_quorum_claim.py', 'tools/transport_quorum_source.py',
          'tools/transport_quorum_input.py', 'tools/transport_quorum_shape.py',
          'tools/transport_quorum_body.schema.json', 'tools/transport_schema.py',
          'tools/transport_wire.py', 'install/test_quorum_reading.py')
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
    if len(items) > 33:
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
        originals.append((item['alias_id'], item['key'], base64.b64decode(item['base64'], validate=True)))
    held = []
    for name in ('held-update-pins.json', 'held-withdrawal-pins.json'):
        value = json.loads(files[name])
        if value['outer_type'] != 'tuple':
            raise ValueError('unsupported held recipe')
        held.append(held_recipe(value['items']))
    return files['body.json'], tuple(originals), *held, json.loads(files['expected.json'])


def focused_case(case: dict) -> tuple:
    raw = read(FIXTURES / 'focused/revision-02/raw' / Path(case['body_raw']['path']).name)
    pin = case['body_raw']
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('focused candidate identity mismatch')
    originals = tuple((item['alias'], item['key'], bytes.fromhex(item['immutable_bytes_hex']))
                      for item in case['originals_exact_tuple_recipe'])
    held = []
    for name in ('held_update_pins_exact_tuple_recipe', 'held_withdrawal_pins_exact_tuple_recipe'):
        recipe = case[name]
        if recipe['outer'] != 'exact_tuple':
            raise ValueError('unsupported focused held recipe')
        held.append(held_recipe(recipe['items']))
    return raw, originals, *held, case['handwritten_expected_complete_result']


def private_probe(name):
    # Synthetic helper tests do not prove public Body reachability of a cap.
    try:
        if name == 'S01_APPEND_OVERFLOW_ATOMIC':
            result = dict(claims=[])
            try:
                product._append(result, dict(small='entry'), 32768)
            except metadata.InputError as error:
                return dict(error=metadata._error(error), claims_unchanged=result == dict(claims=[]))
        elif name == 'S02_FINAL_ACCOUNTING':
            return product._finish(dict(claims=[]), 0)
        elif name == 'S03_OUTPUT_DEPTH_MAPPED':
            result = 0
            for _ in range(14):
                result = dict(layer=result)
            return product._finish(result, len(serialize(result)) + 1)
        else:
            raise ValueError('unknown private resource probe')
    except metadata.InputError as error:
        return metadata._error(error)
    return None


class ReadingTests(unittest.TestCase):
    def compare(self, name, raw, originals, held_updates, held_withdrawals, expected):
        results = []
        for arm in ('original_annotation', 'transport_projection'):
            result = check_reading_aggregation(raw, originals, held_updates, held_withdrawals)
            OUTCOMES.append(dict(case=name, arm=arm, result=result, expected=expected))
            self.assertEqual(result, expected)
            self.assertLessEqual(len(serialize(result)) + 1, 32768)
            results.append(result)
        self.assertEqual(results[0], results[1])
        self.assertIsNot(results[0], results[1])

    def test_complete_manual_results(self):
        for name in ('contract.json', 'design-addendum.json', 'output-resource-addendum.json'):
            frozen(name)
        cases = frozen('oracle.json')['cases']
        self.assertEqual(len(cases), 18)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case))

    def test_independent_precedence_controls(self):
        folder = FIXTURES / 'review-01/precedence-controls'
        cases = frozen('review-01/precedence-controls/oracle.json')['cases']
        self.assertEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case, folder))

    def test_independent_minimal_pairs(self):
        cases = frozen('focused/revision-02/handwritten-expectations.json')['cases']
        self.assertEqual(len(cases), 46)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *focused_case(case))

    def test_independent_resource_controls(self):
        cases = frozen('code-review-01/resource-probe-expectations.json')['cases']
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case['id']):
                result = private_probe(case['id'])
                OUTCOMES.append(dict(case=case['id'], result=result, expected=case['expected'],
                                     scope='PRIVATE_HELPER_ONLY'))
                self.assertEqual(result, case['expected'])
        control = frozen('review-01/precedence-controls/host-count-probe.json')
        case = next(c for c in frozen('oracle.json')['cases'] if c['id'] == control['base_literal'])
        raw, originals, updates, _, _ = compact_case(case)
        self.assertEqual(dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()), control['base_body_pin'])
        CALLBACKS.clear()
        result = check_reading_aggregation(raw, originals, updates, (HostTuple(()),) + (None,) * 32)
        OUTCOMES.append(dict(case=control['id'], result=result, expected=control['expected'], scope='PUBLIC_BOUNDARY'))
        self.assertEqual(result, control['expected'])
        self.assertEqual(CALLBACKS, control['expected_host_callbacks'])

    def test_body_first_and_owned_output(self):
        self.compare('body_before_host_pins', b'{', None, None, None,
                     dict(status='error', stage='PREPARSE', error='INPUT_JSON'))
        raw, originals, updates, withdrawals, expected = compact_case(frozen('oracle.json')['cases'][1])
        before = [(alias, serialize(key), data) for alias, key, data in originals]
        result = check_reading_aggregation(raw, originals, updates, withdrawals)
        self.assertEqual(result, expected)
        self.assertEqual([(alias, serialize(key), data) for alias, key, data in originals], before)
        snapshot = serialize(result)
        originals[0][1]['bytes'] = 123
        self.assertEqual(serialize(result), snapshot)
        self.assertEqual(result['current_authority'], 'NONE')
        self.assertEqual(result['raw_first_output_provenance'], 'UNVERIFIED')
        parameters = list(inspect.signature(check_reading_aggregation).parameters)
        expected_parameters = ['body_raw', 'originals', 'held_update_pins', 'held_withdrawal_pins']
        OUTCOMES.append(dict(case='PUBLIC_INTERFACE', result=parameters, expected=expected_parameters))
        self.assertEqual(parameters, expected_parameters)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReadingTests))
    if args.evidence is not None:
        pins = {name: hashlib.sha256(read(ROOT / name)).hexdigest() for name in SOURCE}
        data = dict(schema='quorum/reading-component-results/1', passed=result.wasSuccessful(),
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
