#!/usr/bin/env python3
"""Frozen deterministic structural-contract controls; no models or source scoring."""
import argparse
import ast
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_response_contract as validator
import transport_response_contract_model as model
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

HERE = Path(__file__).absolute().parent
CONFIG = {}


def sample():
    return dict(decoder_execution_authority='NONE', source_approval='UNKNOWN', actions=[dict(id='review', status='PENDING')],
                attempt_count=1, note='', is_draft=True, reserved=None)


def frozen(path, held):
    raw = read_regular(path)
    require(sha(raw) == held, 'held test input freeze differs')
    value = json.loads(raw)
    require(type(value['files']) is list and 0 < len(value['files']) <= 16, 'test input count bound')
    for item in value['files']:
        data = read_regular(Path(item['path']))
        require(len(data) == item['bytes'] and sha(data) == item['sha256'], 'frozen test dependency differs')
    return raw


def invoke(argv):
    number = CONFIG['processes']
    require(number < 32, 'test process count bound')
    CONFIG['processes'] += 1
    result = run_bounded(argv, CONFIG['evidence'], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=15, cap=32768)
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / ('process-%02d.%s' % (number, stream)), result[stream], 32768)
    write_new(CONFIG['evidence'] / ('process-%02d.json' % number), canonical(
        {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
        | {stream: dict(bytes=len(result[stream]), sha256=sha(result[stream])) for stream in ('stdout', 'stderr')}))
    return result


class Controls(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(read_regular(HERE / 'response_contract_example.json'))
        self.compiled = model.compile_contract(canonical(self.contract))
        self.root = CONFIG['evidence'] / self._testMethodName
        self.root.mkdir()

    def result(self, value):
        return validator.validate(canonical(value), self.compiled)

    def compile_bad(self, value):
        with self.assertRaises((ValueError, TypeError, UnicodeError)):
            model.compile_contract(canonical(value))

    def test_complete_example_and_no_semantic_certificate(self):
        value = sample()
        value['source_approval'] = 'APPROVED'
        value['actions'][0]['status'] = 'DONE'
        result = self.result(value)
        self.assertEqual(result['status'], 'STRUCTURALLY_CONFORMANT')
        self.assertEqual(result['source_approval'], 'NOT_ASSESSED')
        self.assertEqual(result['execution_authority'], 'NONE')
        self.assertEqual(result['semantics'], 'NOT_ASSESSED')
        self.assertEqual(result['task_completion'], 'NOT_ASSESSED')
        self.assertTrue(result['inspection_complete'])

    def test_closed_required_root_and_nested_keys(self):
        for kind in ('missing', 'extra', 'nested_missing', 'nested_extra'):
            value = sample()
            if kind == 'missing':
                del value['actions']
            elif kind == 'extra':
                value['new_field'] = 'ignored?'
            elif kind == 'nested_missing':
                del value['actions'][0]['status']
            else:
                value['actions'][0]['extra'] = 1
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_per_field_enums_not_generic_vocabulary(self):
        for key, token in (('source_approval', 'NONE'), ('decoder_execution_authority', 'UNKNOWN'), ('source_approval', 'PENDING')):
            value = sample()
            value[key] = token
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')
        value = sample()
        value['actions'][0]['status'] = 'APPROVED'
        self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_bool_is_not_integer_and_integer_is_not_bool(self):
        for key, item in (('attempt_count', True), ('attempt_count', False), ('is_draft', 1), ('is_draft', 0)):
            value = sample()
            value[key] = item
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_inclusive_integer_bounds(self):
        for number in (0, 64):
            value = sample()
            value['attempt_count'] = number
            self.assertEqual(self.result(value)['status'], 'STRUCTURALLY_CONFORMANT')
        for number in (-1, 65):
            value = sample()
            value['attempt_count'] = number
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_string_byte_bounds_and_empty_value(self):
        value = sample()
        value['note'] = 'λ' * 128
        self.assertEqual(self.result(value)['status'], 'STRUCTURALLY_CONFORMANT')
        value['note'] += 'λ'
        self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')
        value = sample()
        value['actions'][0]['id'] = ''
        self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_unique_ids_are_exact_not_semantic_deduplication(self):
        value = sample()
        value['actions'].append(dict(id='review', status='UNKNOWN'))
        self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')
        value['actions'][1]['id'] = 'review '
        self.assertEqual(self.result(value)['status'], 'STRUCTURALLY_CONFORMANT')
        value['actions'][1]['id'] = 1
        self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_array_type_length_and_required_minimum(self):
        for items in (None, {}, 'review', [dict(id=str(n), status='PENDING') for n in range(17)]):
            value = sample()
            value['actions'] = items
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')
        self.contract['nodes'][5]['min_items'] = 1
        compiled = model.compile_contract(canonical(self.contract))
        value = sample()
        value['actions'] = []
        self.assertEqual(validator.validate(canonical(value), compiled)['status'], 'STRUCTURAL_MISMATCH')

    def test_literal_null_not_placeholder(self):
        for item in ('UNKNOWN', False, 0, {}):
            value = sample()
            value['reserved'] = item
            self.assertEqual(self.result(value)['status'], 'STRUCTURAL_MISMATCH')

    def test_scalar_array_uniqueness_and_no_uniqueness_mode(self):
        leaf = dict(id='FLAG', type='boolean', description='boolean element')
        array = dict(id='FLAGS', type='array', description='unique booleans', items='FLAG',
                     min_items=0, max_items=4, unique=True, unique_by=None)
        root = dict(id='ROOT', type='object', description='closed flags', fields=dict(flags='FLAGS'))
        contract = dict(schema=model.SCHEMA, description='scalar uniqueness', root='ROOT', nodes=[leaf, array, root])
        compiled = model.compile_contract(canonical(contract))
        self.assertEqual(validator.validate(b'{"flags":[true,false]}', compiled)['status'], 'STRUCTURALLY_CONFORMANT')
        self.assertEqual(validator.validate(b'{"flags":[true,true]}', compiled)['status'], 'STRUCTURAL_MISMATCH')
        self.assertEqual(validator.validate(b'{"flags":[true,1]}', compiled)['status'], 'STRUCTURAL_MISMATCH')
        array['unique'] = False
        compiled = model.compile_contract(canonical(contract))
        self.assertEqual(validator.validate(b'{"flags":[true,true]}', compiled)['status'], 'STRUCTURALLY_CONFORMANT')

    def test_no_cross_field_arithmetic_or_truth_inference(self):
        value = sample()
        value['attempt_count'] = 64
        value['actions'] = []
        value['note'] = 'This structurally valid claim has no source verification.'
        self.assertEqual(self.result(value)['status'], 'STRUCTURALLY_CONFORMANT')

    def test_unsupported_keywords_versions_and_types(self):
        for key in ('pattern', '$ref', 'default', 'additionalProperties', 'code'):
            value = copy.deepcopy(self.contract)
            value['nodes'][0][key] = 'unsupported'
            self.compile_bad(value)
        value = copy.deepcopy(self.contract)
        value['schema'] = 'transport/response-contract/2'
        self.compile_bad(value)
        for kind in ('number', 'union', 'any', ['string', 'null']):
            value = copy.deepcopy(self.contract)
            value['nodes'][0]['type'] = kind
            self.compile_bad(value)

    def test_forward_unknown_and_self_references(self):
        for target in ('RESPONSE', 'MISSING', 'ACTION'):
            value = copy.deepcopy(self.contract)
            value['nodes'][4]['fields']['id'] = target
            self.compile_bad(value)

    def test_node_ids_root_and_unreachable_instructions(self):
        for bad in ('bad-id', '', 'X' * 33):
            value = copy.deepcopy(self.contract)
            value['nodes'][0]['id'] = bad
            self.compile_bad(value)
        value = copy.deepcopy(self.contract)
        value['nodes'][1]['id'] = value['nodes'][0]['id']
        self.compile_bad(value)
        value = copy.deepcopy(self.contract)
        value['root'] = 'NOTE'
        self.compile_bad(value)
        value = copy.deepcopy(self.contract)
        del value['nodes'][-1]['fields']['reserved']
        self.compile_bad(value)

    def test_descriptions_are_inert_not_supplied_code(self):
        marker = self.root / 'must-not-exist'
        self.contract['description'] = "__import__('pathlib').Path(" + repr(str(marker)) + ").touch()"
        self.assertIsInstance(model.compile_contract(canonical(self.contract)), tuple)
        self.assertFalse(marker.exists())
        for item in ('', 3, 'a' * 1025):
            value = copy.deepcopy(self.contract)
            value['description'] = item
            self.compile_bad(value)

    def test_bad_string_enum_and_range_declarations(self):
        for enumeration in ([], ['NONE', 'NONE'], [True], ['X' * 17]):
            value = copy.deepcopy(self.contract)
            value['nodes'][0]['enum'] = enumeration
            self.compile_bad(value)
        for field, item in (('min_bytes', True), ('max_bytes', 4097), ('max_bytes', 0)):
            value = copy.deepcopy(self.contract)
            value['nodes'][0][field] = item
            self.compile_bad(value)

    def test_field_array_and_integer_contract_limits(self):
        for field, item in (('min', True), ('min', -(2 ** 63) - 1), ('max', 2 ** 63), ('max', -1)):
            value = copy.deepcopy(self.contract)
            value['nodes'][6][field] = item
            self.compile_bad(value)
        for field, item in (('unique', 1), ('min_items', True), ('max_items', 65), ('max_items', -1)):
            value = copy.deepcopy(self.contract)
            value['nodes'][5][field] = item
            self.compile_bad(value)
        value = copy.deepcopy(self.contract)
        value['nodes'][-1]['fields'] = {'f' + str(i): 'NOTE' for i in range(33)}
        self.compile_bad(value)

    def test_unique_by_contract_requires_string_identity(self):
        for change in ('missing', 'integer', 'empty', 'unique_false', 'scalar'):
            value = copy.deepcopy(self.contract)
            if change == 'missing':
                value['nodes'][5]['unique_by'] = 'absent'
            elif change == 'integer':
                value['nodes'][4]['fields']['id'] = 'COUNT'
            elif change == 'empty':
                value['nodes'][2]['min_bytes'] = 0
            elif change == 'unique_false':
                value['nodes'][5]['unique'] = False
            else:
                value['nodes'][5]['items'] = 'ACTION_ID'
            self.compile_bad(value)

    def test_duplicate_json_keys_at_every_level(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"a":{"x":1,"x":2}}'):
            with self.assertRaises(ValueError):
                model.safe_json(raw, 65536, 4096)
        with self.assertRaises(ValueError):
            validator.validate(b'{"a":1,"a":2}', self.compiled)

    def test_malformed_truncated_nonutf8_and_surrogates(self):
        for raw in (b'{', b'{} trailing', b'[]', b'{"x":"\xff"}', b'{"x":"\\ud800"}'):
            with self.assertRaises((ValueError, UnicodeError)):
                validator.validate(raw, self.compiled)

    def test_nonfinite_floats_exponents_and_oversize_integers(self):
        for literal in ('NaN', 'Infinity', '-Infinity', '1.0', '1e0', str(2 ** 63), str(-(2 ** 63) - 1)):
            with self.assertRaises(ValueError):
                validator.validate(('{"x":' + literal + '}').encode(), self.compiled)

    def test_byte_depth_value_and_instruction_caps(self):
        for raw in (b' ' * 32769, b'{"x":' + b'[' * 13 + b'0' + b']' * 13 + b'}',
                    canonical(dict(x=[[None] * 128 for _ in range(9)]))):
            with self.assertRaises(ValueError):
                validator.validate(raw, self.compiled)
        value = copy.deepcopy(self.contract)
        value['nodes'] = value['nodes'] * 6
        self.compile_bad(value)
        with self.assertRaises(ValueError):
            model.compile_contract(b' ' * 65537)

    def test_contract_graph_depth_limit(self):
        nodes = [dict(id='BASE', type='null', description='literal null')]
        for index in range(8):
            nodes.append(dict(id='OBJECT' + str(index), type='object', description='nested object',
                              fields=dict(child=nodes[-1]['id'])))
        self.compile_bad(dict(schema=model.SCHEMA, description='depth control', root=nodes[-1]['id'], nodes=nodes))

    def test_integer_singleton_is_only_literal_restriction(self):
        self.contract['nodes'][6]['min'] = 1
        self.contract['nodes'][6]['max'] = 1
        compiled = model.compile_contract(canonical(self.contract))
        self.assertEqual(validator.validate(canonical(sample()), compiled)['status'], 'STRUCTURALLY_CONFORMANT')
        value = sample()
        value['attempt_count'] = 2
        self.assertEqual(validator.validate(canonical(value), compiled)['status'], 'STRUCTURAL_MISMATCH')

    def test_bounded_diagnostics_are_not_incomplete_success(self):
        leaf = dict(id='TEXT', type='string', description='one allowed token', min_bytes=1, max_bytes=4, enum=['OK'])
        root = dict(id='ROOT', type='object', description='closed test fields', fields={'f' + str(i): 'TEXT' for i in range(32)})
        compiled = model.compile_contract(canonical(dict(schema=model.SCHEMA, description='diagnostic bound', root='ROOT', nodes=[leaf, root])))
        result = validator.validate(canonical({'f' + str(i): 'BAD' for i in range(32)}), compiled)
        self.assertEqual(result['status'], 'STRUCTURAL_MISMATCH')
        self.assertEqual(len(result['errors']), 16)
        self.assertTrue(result['errors_truncated'])
        self.assertFalse(result['inspection_complete'])
        self.assertLessEqual(len(canonical(result)) + 1, validator.OUTPUT_BYTES)

    def test_cli_complete_verdicts_and_held_contract_pin(self):
        contract, candidate = self.root / 'contract.json', self.root / 'candidate.json'
        raw = canonical(self.contract)
        write_new(contract, raw)
        write_new(candidate, canonical(sample()))
        base = [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'transport_response_contract.py'),
                '--contract', str(contract), '--candidate', str(candidate), '--expect-contract-sha256']
        for held, expected in ((sha(raw), 'STRUCTURALLY_CONFORMANT'), ('0' * 64, 'REFUSED')):
            result = invoke(base + [held])
            self.assertEqual(result['stderr'], b'')
            self.assertTrue(result['stdout'].endswith(b'\n'))
            verdict = json.loads(result['stdout'])
            self.assertEqual(verdict['status'], expected)
            self.assertEqual(result['exit_code'], 0 if expected == 'STRUCTURALLY_CONFORMANT' else 2)
        candidate.write_bytes(b'{}')
        result = invoke(base + [sha(raw)])
        self.assertEqual((json.loads(result['stdout'])['status'], result['exit_code']), ('STRUCTURAL_MISMATCH', 1))
        candidate.write_bytes(b'{')
        result = invoke(base + [sha(raw)])
        self.assertEqual((json.loads(result['stdout'])['status'], result['exit_code']), ('REFUSED', 2))

    def test_cli_missing_arguments_returns_json_refusal(self):
        result = invoke([sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'transport_response_contract.py')])
        self.assertEqual(result['stderr'], b'')
        self.assertEqual((json.loads(result['stdout'])['status'], result['exit_code']), ('REFUSED', 2))

    def test_changed_file_recheck_refuses_positive_verdict(self):
        contract, candidate = self.root / 'contract.json', self.root / 'candidate.json'
        raw, data = canonical(self.contract), canonical(sample())
        counts = {}
        def changed(path, cap):
            counts[path] = counts.get(path, 0) + 1
            return raw if path == contract and counts[path] == 1 else b'{}' if path == contract else data
        output = io.BytesIO()
        argv = ['validator', '--contract', str(contract), '--candidate', str(candidate), '--expect-contract-sha256', sha(raw)]
        with patch.object(validator, 'read_regular', changed), patch.object(validator.resource, 'setrlimit'), \
             patch.object(validator.sys, 'argv', argv), patch.object(validator.sys, 'stdout', SimpleNamespace(buffer=output)):
            status = validator.main()
        self.assertEqual((json.loads(output.getvalue())['status'], status), ('REFUSED', 2))

    def test_strict_utf8_contract_and_candidate_encoding(self):
        contract = canonical(self.contract).decode()
        candidate = canonical(sample()).decode()
        for encoding in ('utf-16', 'utf-32', 'utf-16-le', 'utf-32-be'):
            with self.assertRaises((ValueError, UnicodeError)):
                model.compile_contract(contract.encode(encoding))
            with self.assertRaises((ValueError, UnicodeError)):
                validator.validate(candidate.encode(encoding), self.compiled)
        for prefix in (b'\xff', b'\xef\xbb\xbf'):
            with self.assertRaises((ValueError, UnicodeError)):
                model.compile_contract(prefix + contract.encode())
            with self.assertRaises((ValueError, UnicodeError)):
                validator.validate(prefix + candidate.encode(), self.compiled)

    def test_new_function_size_limit(self):
        for name in ('transport_response_contract.py', 'transport_response_contract_model.py', 'test_response_contract.py'):
            for node in ast.walk(ast.parse(read_regular(HERE / name))):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (name, node.name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--expect-freeze-sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    before = frozen(args.freeze, args.expect_freeze_sha256)
    require(args.evidence.is_absolute() and not args.evidence.exists(), 'new absolute evidence directory required')
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(evidence=args.evidence, processes=0)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    require(frozen(args.freeze, args.expect_freeze_sha256) == before, 'test inputs changed')
    receipt = dict(schema='transport/response-contract-controls/1', status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED',
                   tests_run=result.testsRun, processes=CONFIG['processes'], failures=[text for _, text in result.failures],
                   errors=[text for _, text in result.errors], input_freeze_sha256=args.expect_freeze_sha256,
                   model_execution='UNRUN', scope='STRUCTURAL_CONTRACT_CONTROLS_ONLY', semantics='NOT_ASSESSED', authority='NONE')
    write_new(args.evidence / 'receipt.json', canonical(receipt) + b'\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
