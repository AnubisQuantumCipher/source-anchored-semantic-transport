#!/usr/bin/env python3
"""Finite-checker controls with synthetic bindings; no decoder is executed here."""
import ast
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / 'install'))
import transport_finite_check as checker
from transport_install_support import canonical, read_regular, sha

BINDING = sha(b'synthetic-unit-test-binding-not-decoder-output')
PARAMETERS = ('requester_is_keeper', 'recipient_is_keeper', 'seal_ok',
              'repair_mode', 'ticket_ok', 'age_hours')
CORRECT = ('requester_is_keeper and 0 <= age_hours <= 12 and '
           '(seal_ok or (repair_mode and ticket_ok))')


def compiled(base):
    return dict(sources={'CODE': base}, source_pins={'CODE': sha(base)},
                bindings={0: dict(sha256=BINDING)})


def specification(base, name, parameters, domains, bits):
    return dict(schema=checker.SCHEMA, binding_sha256=BINDING,
                checker_sha256=sha(canonical(checker.checker_identity())),
                base_source_id='CODE', base_source_sha256=sha(base),
                function_name=name, parameters=list(parameters), domains=domains, expected_bits=bits)


def replacement(base, before, after):
    return dict(schema='transport/function-replacement/1', source_id='CODE',
                base_sha256=sha(base), before=before, after=after)


def tiny():
    base = b'def eligible(open_now, available):\n    return False\n'
    domains = {'open_now': {'type': 'boolean'},
               'available': {'type': 'integer', 'min': 0, 'max': 2}}
    spec = specification(base, 'eligible', ('open_now', 'available'), domains, '000011')
    return base, spec, replacement(base, 'False', 'open_now and available >= 1')


def run(base, spec, patch):
    test_raw, patch_raw = canonical(spec), canonical(patch)
    return checker.run_check(test_raw, patch_raw, compiled(base), sha(test_raw), sha(patch_raw))


def guard(state):
    if not state['requester_is_keeper']:
        return False
    if state['age_hours'] in (-1, 13):
        return False
    if state['seal_ok']:
        return True
    return state['repair_mode'] and state['ticket_ok']


def historical_fixture():
    raw = read_regular(ROOT / 'examples/checked-continuation-v1/fixture.json', 32768)
    fixture = json.loads(raw)
    base = next(item['text'].encode('utf-8') for item in fixture['sources'] if item['id'] == 'CODE')
    domains = {name: {'type': 'boolean'} for name in PARAMETERS[:-1]}
    domains['age_hours'] = dict(type='integer', min=-1, max=13)
    expected = []
    for flags in itertools.product((False, True), repeat=5):
        for age in range(-1, 14):
            state = dict(zip(PARAMETERS, (*flags, age), strict=True))
            expected.append('1' if guard(state) else '0')
    spec = specification(base, 'allow_demo_route', PARAMETERS, domains, ''.join(expected))
    before = base.decode('utf-8').split('    return ', 1)[1].rstrip('\n')
    return base, spec, replacement(base, before, CORRECT)


class FiniteChecks(unittest.TestCase):
    def test_held_out_table_order_and_no_source_mutation(self):
        base, spec, patch = tiny()
        frozen = deepcopy((base, spec, patch))
        receipt = run(base, spec, patch)
        self.assertEqual((base, spec, patch), frozen)
        self.assertEqual(receipt['actual_bits'], '000011')
        self.assertEqual(receipt['state_count'], 6)
        self.assertEqual(receipt['truth'], 'KNOWN_TRUE')
        self.assertEqual(receipt['status'], 'TESTED_FINITE_DOMAIN')
        self.assertEqual(receipt['expected_interpretation'], 'UNPROVEN')
        self.assertEqual(receipt['execution_authority'], 'NONE')

    def test_existing_fixture_against_independent_guard_oracle(self):
        base, spec, patch = historical_fixture()
        receipt = run(base, spec, patch)
        self.assertEqual(receipt['state_count'], 480)
        self.assertEqual(receipt['actual_bits'], spec['expected_bits'])
        self.assertEqual(receipt['failures'], 0)
        self.assertEqual(receipt['truth'], 'KNOWN_TRUE')

    def test_actor_off_by_one_and_overbroad_exception_are_false(self):
        base, spec, patch = historical_fixture()
        mutations = (CORRECT.replace('requester_is_keeper', 'recipient_is_keeper'),
                     CORRECT.replace('<= 12', '< 12'),
                     'requester_is_keeper and ((seal_ok and 0 <= age_hours <= 12) or '
                     '(repair_mode and ticket_ok))',
                     CORRECT.replace('repair_mode and ticket_ok', 'repair_mode or ticket_ok'))
        for expression in mutations:
            with self.subTest(expression=expression):
                receipt = run(base, spec, dict(patch, after=expression))
                self.assertEqual(receipt['truth'], 'KNOWN_FALSE')
                self.assertGreater(receipt['failures'], 0)
                self.assertLessEqual(len(receipt['first_mismatches']), 16)

    def test_mismatch_cap_and_complete_actual_table(self):
        base, spec, patch = historical_fixture()
        receipt = run(base, dict(spec, expected_bits='1' * 480), dict(patch, after='False'))
        self.assertEqual(receipt['actual_bits'], '0' * 480)
        self.assertEqual(receipt['failures'], 480)
        self.assertEqual(len(receipt['first_mismatches']), 16)
        self.assertIs(receipt['mismatches_truncated'], True)

    def test_base_revision_and_source_identity_refused(self):
        base, spec, patch = tiny()
        cases = ((base + b'\n', spec, patch), (base, dict(spec, base_source_sha256='0' * 64), patch),
                 (base, dict(spec, base_source_id='OTHER'), patch),
                 (base, spec, dict(patch, source_id='OTHER')),
                 (base, spec, dict(patch, base_sha256='0' * 64)))
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                run(*values)

    def test_missing_duplicate_and_changed_binding_refused(self):
        base, spec, patch = tiny()
        test_raw, patch_raw = canonical(spec), canonical(patch)
        for bindings in ({}, {0: {'sha256': '0' * 64}},
                         {0: {'sha256': BINDING}, 1: {'sha256': BINDING}}):
            value = dict(compiled(base), bindings=bindings)
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                checker.run_check(test_raw, patch_raw, value, sha(test_raw), sha(patch_raw))

    def test_schema_and_field_closure(self):
        base, spec, patch = tiny()
        for key, value in (('schema', 'transport/finite-predicate-test/2'), ('extra', True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                run(base, dict(spec, **{key: value}), patch)
        for key, value in (('schema', 'transport/function-replacement/2'), ('extra', True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                run(base, spec, dict(patch, **{key: value}))
        missing = dict(spec)
        del missing['domains']
        with self.assertRaises(ValueError):
            run(base, missing, patch)

    def test_wrong_external_input_pins(self):
        base, spec, patch = tiny()
        test_raw, patch_raw = canonical(spec), canonical(patch)
        for test_pin, patch_pin in (('0' * 64, sha(patch_raw)), (sha(test_raw), '0' * 64)):
            with self.subTest(test_pin=test_pin), self.assertRaises(ValueError):
                checker.run_check(test_raw, patch_raw, compiled(base), test_pin, patch_pin)

    def test_changed_checker_pin_and_midcheck_dependency(self):
        base, spec, patch = tiny()
        with self.assertRaisesRegex(ValueError, 'checker identity differs'):
            run(base, dict(spec, checker_sha256='0' * 64), patch)
        identity = checker.checker_identity()
        changed = dict(identity, profile='changed')
        with mock.patch.object(checker, 'checker_identity', side_effect=(identity, changed)):
            with self.assertRaisesRegex(ValueError, 'dependency changed'):
                run(base, spec, patch)

    def test_unsafe_expressions_are_never_executed(self):
        base, spec, patch = tiny()
        for expression in ('__import__("os").system("false")', 'open("marker", "w")',
                           'available + 1 > 0', '(lambda: True)()', 'open_now.real',
                           '[x for x in ()]', 'True\n    return False', 'unknown'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                run(base, spec, dict(patch, after=expression))

    def test_exact_header_and_parameter_order(self):
        base, spec, _ = tiny()
        for before, after in (('eligible(', 'eligible( '), ('eligible', 'other'),
                              ('open_now, available', 'available, open_now')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                run(base, spec, replacement(base, before, after))

    def test_domain_overflow_refused_before_evaluation(self):
        base, spec, patch = tiny()
        domains = deepcopy(spec['domains'])
        domains['available']['max'] = 1000000
        with mock.patch.object(checker, 'evaluate', side_effect=AssertionError('must not evaluate')):
            with self.assertRaisesRegex(ValueError, 'state bound'):
                run(base, dict(spec, domains=domains), patch)
        domains['available']['max'] = 256
        with mock.patch.object(checker, 'evaluate', side_effect=AssertionError('must not evaluate')):
            with self.assertRaisesRegex(ValueError, 'state bound'):
                run(base, dict(spec, domains=domains), patch)

    def test_exact_maximum_state_count(self):
        base, spec, patch = tiny()
        domains = deepcopy(spec['domains'])
        domains['available']['max'] = 255
        receipt = run(base, dict(spec, domains=domains, expected_bits='0' * 256 + '0' + '1' * 255), patch)
        self.assertEqual(receipt['state_count'], 512)
        self.assertEqual(receipt['truth'], 'KNOWN_TRUE')

    def test_bool_integer_type_separation(self):
        base, spec, patch = tiny()
        for expression in ('available == True', 'open_now == 1', 'available',
                           'not available', 'open_now and available'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                run(base, spec, dict(patch, after=expression))
        domains = deepcopy(spec['domains'])
        domains['available']['min'] = False
        with self.assertRaises(ValueError):
            run(base, dict(spec, domains=domains), patch)

    def test_invalid_domain_shapes_and_expected_bits(self):
        base, spec, patch = tiny()
        for domains in ({}, {'open_now': {'type': 'float'}},
                        dict(spec['domains'], open_now={'type': 'boolean', 'min': 0})):
            with self.subTest(domains=domains), self.assertRaises(ValueError):
                run(base, dict(spec, domains=domains), patch)
        for bits in ('00001', '0000110', '00001x', [0, 0, 0, 0, 1, 1], True):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                run(base, dict(spec, expected_bits=bits), patch)

    def test_zero_parameter_constant(self):
        base = b'def fixed():\n    return False\n'
        spec = specification(base, 'fixed', (), {}, '1')
        receipt = run(base, spec, replacement(base, 'False', 'True'))
        self.assertEqual(receipt['actual_bits'], '1')
        self.assertEqual(receipt['state_count'], 1)

    def test_input_bounds_and_malformed_json(self):
        base, spec, patch = tiny()
        patch_raw = canonical(patch)
        for raw in (b'{', b'\xff', b'{}' + b' ' * checker.CAP,
                    b'{"schema":"one","schema":"two"}', b'\xef\xbb\xbf{}'):
            with self.subTest(raw=raw[:32]), self.assertRaises(ValueError):
                checker.run_check(raw, patch_raw, compiled(base), sha(raw), sha(patch_raw))
        for text in ('x' * 4097, '\0', '\ud800'):
            with self.subTest(text=text[:10]), self.assertRaises((ValueError, UnicodeError)):
                run(base, spec, dict(patch, after=text))

    def test_exact_receipt_recomputation(self):
        receipt = run(*tiny())
        raw = canonical(receipt)
        result = checker.validate_receipt(raw, receipt, sha(raw))
        self.assertEqual(result['status'], 'RECOMPUTED_RECEIPT_MATCH')
        self.assertEqual(run(*tiny()), receipt)

    def test_tampered_truncated_swapped_noncanonical_receipts(self):
        receipt = run(*tiny())
        other = run(*historical_fixture())
        for raw in (canonical(dict(receipt, truth='KNOWN_FALSE')), canonical(receipt)[:-1],
                    canonical(other), canonical(receipt) + b' ', canonical(dict(receipt, extra=True))):
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                checker.validate_receipt(raw, receipt, sha(raw))
        with self.assertRaises(ValueError):
            checker.validate_receipt(canonical(receipt), receipt, '0' * 64)

    def test_identity_declares_actual_dependency_bytes(self):
        identity = checker.checker_identity()
        self.assertEqual(tuple(item['path'] for item in identity['dependencies']), checker.DEPENDENCIES)
        for item in identity['dependencies']:
            raw = read_regular(ROOT / 'install' / item['path'], 131072)
            self.assertEqual(item['sha256'], sha(raw))
            self.assertEqual(item['bytes'], len(raw))
        self.assertEqual(identity['formal_proof'], 'NOT_CLAIMED')

    def test_functions_bounded_and_direct_recursion_absent(self):
        for name in ('transport_finite_check.py', 'test_finite_check.py'):
            tree = ast.parse(read_regular(ROOT / 'install' / name, 131072))
            for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
                self.assertLessEqual(function.end_lineno - function.lineno + 1, 60)
                for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                    self.assertFalse(isinstance(call.func, ast.Name) and call.func.id == function.name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
