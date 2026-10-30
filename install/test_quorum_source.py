#!/usr/bin/env python3
"""Source/blob/selector checks against frozen independent literal expectations."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_quorum_source import check_source_membership
from transport_quorum_source import _binary
from transport_quorum_input import InputError

FIXTURES = ROOT / 'examples/quorum-source-v1'
PINS = {
    'contract.json': 'c233f1a44017359e5ba57a6cceaa669945dd54e8fd287b0c10719370f4b20771',
    'oracle.json': '7a8a8b2e441278f7abf32ab7699bc0e70647f154ebd249eeecfb58985fbbcc8f',
    'focused/handwritten-expectations.json': '3ca7452a75d850ae4547359192bc304b5e0996dfc872b50687ff0d507acd412d',
    'focused/handwritten-amendments.json': '1d4147b714d9c0f7af57d3a6b106b51ff0d002f5a55eb3f083fa5e45a34c8f8b',
    'evidence/code-review-01/additional-probes.json': 'bb1427c2d541e39be76630d35fda44ed9db90086cd563eb0d855f5219078d75f',
    'evidence/code-review-01/r02-private-probes.json': 'f7ca102ac5c420e57cf67c6e78a03939488cfa6829e65bb02aa39b4cc4322746',
}
SOURCE = ('tools/transport_quorum_source.py', 'tools/transport_quorum_input.py',
          'tools/transport_quorum_shape.py', 'tools/transport_quorum_body.schema.json',
          'tools/transport_schema.py', 'tools/transport_wire.py', 'install/test_quorum_source.py')
OUTCOMES = []


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


def compact_case(case: dict) -> tuple:
    files = {}
    for name, pin in case['files'].items():
        raw = read(FIXTURES / case['id'] / name)
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('literal candidate identity mismatch')
        files[name] = raw
    recipe = json.loads(files['originals.json'])
    if recipe['outer_type'] != 'tuple' or len(recipe['items']) > 16:
        raise ValueError('unsupported literal fixture recipe')
    originals = []
    for item in recipe['items']:
        if item['item_type'] != 'tuple' or item['data_type'] != 'bytes':
            raise ValueError('unsupported literal item recipe')
        originals.append((item['alias_id'], item['key'],
                          base64.b64decode(item['base64'], validate=True)))
    return files['body.json'], tuple(originals), json.loads(files['expected.json'])


def focused_cases() -> list:
    return (frozen('focused/handwritten-expectations.json')['cases'] +
            frozen('focused/handwritten-amendments.json')['cases'])


def focused_case(case: dict) -> tuple:
    name = Path(case['body_raw']['path']).name
    raw = read(FIXTURES / 'focused/raw' / name)
    pin = case['body_raw']
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('focused candidate identity mismatch')
    originals = tuple((item['alias'], item['key'], bytes.fromhex(item['immutable_bytes_hex']))
                      for item in case['originals_exact_tuple_recipe'])
    return raw, originals, case['expected']


def refusal(code: str, stage: str = 'SOURCE_ARGUMENTS') -> dict:
    return dict(status='error', stage=stage, error=code)


def additional_case(case: dict) -> tuple:
    raw = read(FIXTURES / 'evidence/code-review-01' / case['body_file'])
    if hashlib.sha256(raw).hexdigest() != case['body_sha256']:
        raise ValueError('additional probe identity mismatch')
    originals = tuple((item['alias'], dict(item['key']), bytes.fromhex(item['hex']))
                      for item in case['originals'])
    if case['construction'] == 'sixteen_null_entries':
        originals = (None,) * 16
    elif case['construction'] == 'same_alias_twice_65536_bytes':
        alias, key, _ = originals[0]
        data = b'a' * 65536
        originals = ((alias, key, data), (alias, key, data))
    elif case['construction'] is not None:
        raise ValueError('unknown frozen construction')
    return raw, originals, case['expected']


class SourceTests(unittest.TestCase):
    def compare(self, name, raw, originals, expected, projection=False):
        results = []
        for arm in ('original_annotation', 'transport_projection'):
            result = check_source_membership(raw, originals)
            observed = result
            if projection and result['status'] == 'ok':
                observed = dict(status=result['status'], stage=result['stage'],
                    selector_statuses=[entry['status'] for entry in result['selectors']])
            OUTCOMES.append(dict(case=name, arm=arm, result=result, expected=expected,
                                 projection=projection))
            self.assertEqual(observed, expected)
            self.assertLessEqual(len(serialize(result)) + 1, 32768)
            results.append(result)
        self.assertEqual(results[0], results[1])
        self.assertIsNot(results[0], results[1])

    def test_complete_literal_results(self):
        frozen('contract.json')
        cases = frozen('oracle.json')['cases']
        self.assertEqual(len(cases), 18)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *compact_case(case))

    def test_focused_independent_controls(self):
        cases = focused_cases()
        self.assertEqual(len(cases), 49)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *focused_case(case), projection=True)

    def test_host_boundary_types(self):
        raw, original, _ = focused_case(focused_cases()[0])
        alias, key, data = original[0]
        class TupleSubclass(tuple):
            pass
        class BytesSubclass(bytes):
            pass
        class DictSubclass(dict):
            pass
        class TextSubclass(str):
            pass
        invalid = (None, [], TupleSubclass(original), ((alias, key),),
                   ((alias, key, bytearray(data)),), ((alias, key, BytesSubclass(data)),),
                   (TupleSubclass(original[0]),))
        for index, candidate in enumerate(invalid):
            self.compare('host_type_' + str(index), raw, candidate, refusal('SOURCE_INPUT_TYPE'))
        keys = (DictSubclass(key), dict(key, bytes=True), dict(key, bytes=-1),
                dict(key, bytes=65537), dict(key, sha256='A' * 64),
                dict(key, extra=None), {**key, TextSubclass('bad'): 1},
                dict(key, logical_source_id='X' * 65536))
        for index, candidate in enumerate(keys):
            self.compare('key_type_' + str(index), raw, ((alias, candidate, data),),
                         refusal('SOURCE_KEY_SHAPE'))
        for index, candidate in enumerate((None, TextSubclass(alias), 'X' * 65536, 'é')):
            self.compare('alias_type_' + str(index), raw, ((candidate, key, data),),
                         refusal('SOURCE_KEY_SHAPE'))

    def test_body_precedes_sources_and_output_is_owned(self):
        self.compare('body_before_sources', b'{', None,
                     refusal('INPUT_JSON', 'PREPARSE'))
        raw, original, _ = focused_case(focused_cases()[0])
        result = check_source_membership(raw, original)
        self.assertEqual(result['status'], 'ok')
        self.assertIsNot(result['source_index'][0]['key'], original[0][1])
        before = serialize(result)
        original[0][1]['bytes'] = 123
        self.assertEqual(serialize(result), before)
        for name in ('body', 'originals', 'quote', 'base64', 'accepted_result'):
            self.assertNotIn(name, result)

    def test_additional_frozen_review_probes(self):
        cases = frozen('evidence/code-review-01/additional-probes.json')['cases']
        self.assertEqual(len(cases), 14)
        for case in cases:
            with self.subTest(case=case['id']):
                self.compare(case['id'], *additional_case(case),
                             projection='selector_statuses' in case['expected'])

    def test_private_budget_precedence(self):
        # Helper-only quota state; not a claim of public Body reachability.
        cases = frozen('evidence/code-review-01/r02-private-probes.json')['cases']
        self.assertEqual(len(cases), 2)
        for case in cases:
            with self.subTest(case=case['id']):
                with self.assertRaises(InputError) as caught:
                    _binary(case['text'], case['size'], case['digest'], 'BLOB',
                            'BLOB_INTEGRITY', case['used'])
                actual = refusal(caught.exception.code, caught.exception.stage)
                OUTCOMES.append(dict(case=case['id'], scope='PRIVATE_HELPER_ONLY',
                                     result=actual, expected=case['expected']))
                self.assertEqual(actual, case['expected'])

    def test_host_key_callbacks_not_invoked(self):
        calls = dict(hash=0, equality=0)
        class TrapKey(str):
            def __hash__(self):
                calls['hash'] += 1
                return str.__hash__(self)

            def __eq__(self, other):
                calls['equality'] += 1
                return str.__eq__(self, other)

        raw, originals, _ = focused_case(focused_cases()[0])
        alias, key, data = originals[0]
        key = {'logical_source_id': key['logical_source_id'],
               'sha256': key['sha256'], TrapKey('bytes'): key['bytes']}
        calls.update(hash=0, equality=0)
        self.compare('host_key_callbacks', raw, ((alias, key, data),), refusal('SOURCE_KEY_SHAPE'))
        self.assertEqual(calls, dict(hash=0, equality=0))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceTests))
    if args.evidence is not None:
        pins = {name: hashlib.sha256(read(ROOT / name)).hexdigest() for name in SOURCE}
        data = dict(schema='quorum/source-component-results/1', passed=result.wasSuccessful(),
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
