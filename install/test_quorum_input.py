#!/usr/bin/env python3
"""Frozen raw controls and independent schema observations; no replay claims."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_quorum_input import InputError, _read_value, check_body_input, check_canonical_value
from transport_quorum_shape import Budget, _evaluate, load_schema
import transport_quorum_shape as shape

FIXTURES = ROOT / 'examples/quorum-input-v1'
PINS = {
    'contract-v2.json': '18d180241243baeb7dd362cf833abedfcc5e099b489034c3ead8d547054181d6',
    'raw-controls.json': 'c01ac5d93f932af82bab36246b026c0f5072fc273a995b96afdb64b0e7b8991f',
    'raw-controls-corrections-v2.json': 'ae9f844e102b15399cb6338db25548914e2203f83846277e42131e2f6e2ba843',
    'compact-matrix.json': 'e706aeb43df579edff0de1990033884f1233a594d622cd20741a22efb80e7e41',
    'public-expectations.json': 'fe938cb3e439f9a50ce4c4782afddb10b95d4451782e8baa8f4d274eb9ba2c0f',
    'admission-correction.json': '52615783aa6bfd8bd6061829491b5207c19d222486b707b2d14106d163de98c6',
}
OUTCOMES = []


def frozen(name: str) -> dict:
    raw = bounded_file(FIXTURES / name)
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('frozen fixture identity mismatch')
    return json.loads(raw)


def bounded_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError('fixture must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('test fixture bound exceeded')
    return raw


def serialized(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def raw_cases() -> list:
    original = frozen('raw-controls.json')
    changes = frozen('raw-controls-corrections-v2.json')
    overrides = {item['id']: item['expected'] for item in changes['expected_stage_overrides']}
    cases = original['controls'] + changes['additional_controls']
    for case in cases:
        case['input'] = bytes.fromhex(case['raw_hex'])
        case['expected'] = overrides.get(case['id'], case['expected'])
    recipes = dict(r_depth12=b'[' * 12 + b'0' + b']' * 12,
                   r_depth13=b'[' * 13 + b'0' + b']' * 13,
                   r_byte_overflow=b' ' * 65537, r_empty=b'', r_bytearray=bytearray(b'null'))
    for recipe in original['bounded_recipes']:
        cases.append(dict(id=recipe['id'], input=recipes[recipe['id']],
                          call_scope='PRIVATE_CANONICAL_READER',
                          expected=overrides.get(recipe['id'], recipe['expected'])))
    for suffix in (b'.0', b'e0'):
        cases.append(dict(id='I01_' + suffix.decode(), input=b'123456789012345678901' + suffix,
            call_scope='PRIVATE_CANONICAL_READER',
            expected=dict(status='error', stage='PREPARSE', error='INPUT_INTEGER_TOKEN')))
    return cases


class InputTests(unittest.TestCase):
    def compare(self, name, raw, expected, body=True):
        outputs = []
        for arm in ('original_annotation', 'transport_projection'):
            result = check_body_input(raw) if body else check_canonical_value(raw)
            OUTCOMES.append(dict(case=name, arm=arm, result=result, expected=expected))
            outputs.append(result)
            self.assertEqual(result, expected)
        self.assertEqual(outputs[0], outputs[1])
        self.assertIsNot(outputs[0], outputs[1])

    def test_frozen_raw(self):
        frozen('contract-v2.json')
        for case in raw_cases():
            with self.subTest(case=case['id']):
                self.compare(case['id'], case['input'], case['expected'],
                             case['call_scope'] == 'BODY_WRAPPER')

    def test_wrapper_constructions(self):
        base = json.loads(bounded_file(FIXTURES / 'minimal-body.json'))
        changes = frozen('raw-controls-corrections-v2.json')['wrapper_constructions']
        for case in changes:
            body = json.loads(serialized(base))
            name = case['id']
            if name == 'b_five_rules':
                body['rules'].append(dict(body['rules'][0], id='EXTRA'))
            elif name == 'b_three_rules':
                body['rules'].pop()
            elif name == 'b_unknown_rule_version':
                body['rules'][0]['version'] = 'V2'
            elif name == 'b_extra_field':
                body['extra'] = None
            elif name == 'b_missing_field':
                del body['history']
            elif name == 'b_manifest_rule_omission':
                body = json.loads(bounded_file(FIXTURES / 'raw/closure_C13_MANIFEST_RULE_OMISSION.json'))
            else:
                self.fail('unrecognized frozen construction')
            with self.subTest(case=name):
                self.compare(name, serialized(body), case['expected'])

    def test_frozen_independent_shape_observations(self):
        schema = load_schema()
        cases = frozen('compact-matrix.json')['cases']
        public_cases = frozen('public-expectations.json')['cases']
        expected_public = {item['id']: item for item in public_cases}
        override = frozen('admission-correction.json')['existing_fixture_override']
        self.assertIn(override['id'], expected_public)
        expected_public[override['id']] = override
        self.assertEqual(len(cases), 207)
        for case in cases:
            with self.subTest(case=case['id']):
                raw = bounded_file(FIXTURES / 'raw' / (case['id'] + '.json'))
                self.assertEqual(len(raw), case['raw']['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), case['raw']['sha256'])
                public = check_body_input(raw)
                selected = expected_public[case['id']]
                self.assertEqual(public['stage'], selected['stage'])
                if selected['allowed_errors']:
                    self.assertEqual(public['status'], 'error')
                    self.assertIn(public['error'], selected['allowed_errors'])
                else:
                    self.assertEqual(public, dict(status='ok', stage='BODY_INPUT_SHAPE_ONLY'))
                try:
                    value = _read_value(raw)
                except InputError as error:
                    self.assertEqual(public, dict(status='error', stage=error.stage, error=error.code))
                    OUTCOMES.append(dict(case=case['id'], scope='OUTSIDE_RAW_PROFILE', result=public))
                    continue
                expected = case['observed_shape'] == 'ACCEPT'
                result = _evaluate(value, schema, Budget('SCHEMA'), False)
                OUTCOMES.append(dict(case=case['id'], scope='SHAPE_PARITY', result=result,
                    independent_observed=expected, handwritten=case['handwritten_shape_expected'], public=public))
                self.assertEqual(result, expected)
                if not expected:
                    self.assertEqual(public['status'], 'error')
                if public['status'] == 'ok':
                    self.assertTrue(expected)
                    self.assertEqual(public, dict(status='ok', stage='BODY_INPUT_SHAPE_ONLY'))

    def test_host_type_and_unchanged_unicode(self):
        class ByteSubclass(bytes):
            pass
        for raw in ('null', None, ByteSubclass(b'null')):
            self.compare('host_type', raw, dict(status='error', stage='PREPARSE', error='INPUT_TYPE'))
        self.assertNotEqual(_read_value('"é"'.encode()), _read_value('"é"'.encode()))

    def test_explicit_work_refusal(self):
        schema = load_schema()
        value = json.loads(bounded_file(FIXTURES / 'minimal-body.json'))
        budget = Budget('SCHEMA')
        budget.steps = 0
        with self.assertRaises(InputError) as caught:
            _evaluate(value, schema, budget, False)
        self.assertEqual((caught.exception.code, caught.exception.stage), ('INPUT_WORK_BOUND', 'SCHEMA'))

    def test_review_regressions(self):
        base = json.loads(bounded_file(FIXTURES / 'minimal-body.json'))
        base['schema'] = 'quorum/replay-body/2'
        self.compare('unknown_body_version', serialized(base),
                     dict(status='error', stage='SCHEMA', error='INPUT_UNADMITTED'))
        base['schema'] = 'quorum/replay-body/1'
        base['mode'] = 'X' * 4097
        self.compare('oversized_const', serialized(base),
                     dict(status='error', stage='BOUNDS', error='INPUT_BYTE_FIELD_BOUND'))
        budget = Budget('SCHEMA')
        budget.bytes = 0
        before = budget.steps
        with self.assertRaises(InputError) as caught:
            shape._string_size('x' * 1024, budget)
        self.assertEqual(caught.exception.code, 'INPUT_WORK_BOUND')
        self.assertEqual(budget.steps, before)

    def test_bootstrap_special_files_and_tamper(self):
        with tempfile.TemporaryDirectory(prefix='quorum-schema-') as directory:
            root = Path(directory)
            fifo, bad, link = root / 'fifo', root / 'bad', root / 'link'
            os.mkfifo(fifo)
            bad.write_bytes(b'{}')
            link.symlink_to(shape.SCHEMA_PATH)
            for path in (fifo, bad, link, root / 'missing', root):
                with self.subTest(path=path.name), patch.object(shape, 'SCHEMA_PATH', path):
                    self.assertEqual(check_body_input(b'{}'), dict(status='error',
                        stage='BOOTSTRAP', error='INPUT_SCHEMA_UNSUPPORTED'))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(InputTests))
    if args.evidence is not None:
        paths = ('tools/transport_quorum_input.py', 'tools/transport_quorum_shape.py',
                 'tools/transport_quorum_body.schema.json', 'install/test_quorum_input.py')
        pins = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths}
        data = dict(schema='quorum/input-component-results/1', passed=result.wasSuccessful(),
            test_methods=result.testsRun, source_pins=pins, fixture_pins=PINS, python=sys.version,
            outputs=OUTCOMES, full_replay='UNRUN', formal_proof='UNPROVEN',
            external_validation='EXTERNAL_VALIDATION_PENDING', benefit='NOT_MEASURED')
        raw = serialized(data)
        if len(raw) > 1048576:
            raise ValueError('test evidence output bound exceeded')
        with args.evidence.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('short evidence write')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
