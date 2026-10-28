#!/usr/bin/env python3
"""Minimal independent controls; never compile or execute candidate source."""

import ast
import hashlib
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_fixture_expression as adapter


def held(raw):
    return hashlib.sha256(raw).hexdigest()


def source(expression, parameters='a, b, c'):
    return ('def decide(' + parameters + '):\n    return ' + expression + '\n').encode('utf-8')


def booleans(*names):
    return {name: {'type': 'boolean'} for name in names}


def parse(expression, names=('a', 'b', 'c'), domains=None):
    if domains is None:
        domains = booleans(*names)
    return adapter.parse_function(source(expression, ', '.join(names)), 'decide', names, domains)


class PatchControls(unittest.TestCase):
    def test_exact_patch_preserves_utf8_crlf_and_prefix_suffix(self):
        base = '# λ\r\ndef decide():\r\n    return False\r\n# tail\n'.encode('utf-8')
        expected = '# λ\r\ndef decide():\r\n    return True\r\n# tail\n'.encode('utf-8')
        result, receipt = adapter.apply_replacement(base, held(base), b'False', b'True')
        self.assertEqual(result, expected)
        self.assertEqual(receipt['base_sha256'], held(base))
        self.assertEqual(receipt['result_sha256'], held(expected))
        self.assertEqual(receipt['replacement_count'], 1)
        self.assertEqual(receipt['semantics'], 'NOT_ASSESSED')
        self.assertEqual(receipt['execution_authority'], 'NONE')

    def test_tampered_base_and_held_digest_format(self):
        for digest in ('0' * 64, held(b'base').upper(), 'x' * 64, None, b'0' * 64):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                adapter.apply_replacement(b'base', digest, b'base', b'new')

    def test_empty_absent_duplicate_and_overlapping_sites(self):
        for base, before in ((b'base', b''), (b'base', b'missing'), (b'xx', b'x'), (b'aaa', b'aa')):
            with self.subTest(base=base, before=before), self.assertRaises(ValueError):
                adapter.apply_replacement(base, held(base), before, b'new')

    def test_byte_caps_and_empty_replacement(self):
        base = b'x' + b' ' * (adapter.MAX_BYTES - 1)
        self.assertEqual(adapter.apply_replacement(base, held(base), b'x', b'y')[0], b'y' + base[1:])
        self.assertEqual(adapter.apply_replacement(b'x', held(b'x'), b'x', b'')[0], b'')
        cases = ((base, b'x', b'yy'), (base + b' ', b'x', b'y'),
                 (b'x', b'x', b'y' * (adapter.MAX_BYTES + 1)),
                 (b'x', b'x' * (adapter.MAX_BYTES + 1), b'y'))
        for original, before, after in cases:
            with self.subTest(size=len(original)), self.assertRaises(ValueError):
                adapter.apply_replacement(original, held(original), before, after)

    def test_utf8_nul_and_exact_byte_types(self):
        for original, before, after in ((b'\xff', b'x', b'y'), (b'x', b'\xff', b'y'),
                                        (b'x', b'x', b'\xff'), (b'x', b'x', b'\0'),
                                        (bytearray(b'x'), b'x', b'y')):
            with self.subTest(original=original), self.assertRaises(ValueError):
                adapter.apply_replacement(original, held(original), before, after)


class ExpressionControls(unittest.TestCase):
    def rejected(self, raw, names=('a',), domains=None):
        with self.assertRaises(ValueError):
            adapter.parse_function(raw, 'decide', names, domains if domains is not None else booleans(*names))

    def test_boolean_precedence_and_parenthesized_scope_truth_tables(self):
        states = ((False, False, False), (False, False, True), (False, True, False),
                  (False, True, True), (True, False, False), (True, False, True),
                  (True, True, False), (True, True, True))
        cases = (('a or b and c', (False, False, False, True, True, True, True, True)),
                 ('(a or b) and c', (False, False, False, True, False, True, False, True)),
                 ('not a and b or c', (False, True, True, True, False, True, False, True)))
        for expression, expected in cases:
            program = parse(expression)
            observed = tuple(adapter.evaluate(program, dict(zip(('a', 'b', 'c'), state))) for state in states)
            self.assertEqual(observed, expected, expression)

    def test_chained_comparison_inclusive_exclusive_and_not_precedence(self):
        domains = {'x': {'type': 'integer', 'min': -2, 'max': 2}}
        cases = (('-1 <= x < 1', (False, True, True, False, False)),
                 ('not x < 0', (False, False, True, True, True)),
                 ('x != 0 and x <= 1', (True, True, False, True, False)),
                 ('x > -1 and x >= 0', (False, False, True, True, True)))
        for expression, expected in cases:
            program = parse(expression, ('x',), domains)
            observed = tuple(adapter.evaluate(program, {'x': value}) for value in (-2, -1, 0, 1, 2))
            self.assertEqual(observed, expected, expression)

    def test_signed_limits_and_equivalent_integer_spellings(self):
        domains = {'x': {'type': 'integer', 'min': -1000000, 'max': 1000000}}
        program = parse('-1_000_000 <= x <= +0xf4240', ('x',), domains)
        for value in (-1000000, 0, 1000000):
            self.assertIs(adapter.evaluate(program, {'x': value}), True)
        for expression in ('x == 1000001', 'x == -1000001', 'x == +1000001'):
            self.rejected(source(expression, 'x'), ('x',), domains)

    def test_boolean_ordering_and_zero_parameter_constant(self):
        program = parse('a < b', ('a', 'b'))
        for a, b, expected in ((False, False, False), (False, True, True),
                                (True, False, False), (True, True, False)):
            self.assertIs(adapter.evaluate(program, {'a': a, 'b': b}), expected)
        self.assertIs(adapter.evaluate(parse('True', (), {}), {}), True)

    def test_unsupported_expressions_and_unsafe_constructs(self):
        expressions = ('open("marker", "w")', '__import__("os")', 'a.real', 'a[0]',
                       '1 + 1 == 2', 'a if a else False', '(x := True)', '[a for x in ()]',
                       '(lambda: True)()', '(True,)', '[True]', '{True}', '{"a": True}',
                       'a is True', 'a in (True,)', 'a & True', 'await a', 'yield a',
                       '"True"', 'None', '1.0 == 1.0', 'b"a" == b"a"', '... == ...',
                       '~1 == 1', '-True == False', '--1 == 1', '-a == 1', '+a == 1')
        for expression in expressions:
            with self.subTest(expression=expression):
                self.rejected(source(expression, 'a'))

    def test_entire_module_and_function_header_are_closed(self):
        cases = ('def decide(a):\n    "doc"\n    return a\n',
                 'def decide(a):\n    pass\n', 'def decide(a):\n    return\n',
                 'def decide(a):\n    return a\n    return a\n',
                 'def decide(a):\n    return a\ndef other():\n    return True\n',
                 'import os\ndef decide(a):\n    return a\n',
                 '@a\ndef decide(a):\n    return a\n',
                 'async def decide(a):\n    return a\n',
                 'def other(a):\n    return a\n', 'def decide(b):\n    return b\n',
                 'def decide(a=True):\n    return a\n', 'def decide(a, /):\n    return a\n',
                 'def decide(*, a):\n    return a\n', 'def decide(*a):\n    return True\n',
                 'def decide(**a):\n    return True\n', 'def decide(a: bool):\n    return a\n',
                 'def decide(a) -> bool:\n    return a\n',
                 'def decide(a): # type: (bool) -> bool\n    return a\n',
                 'def decide(a):\n    return a # type: ignore\n',
                 'def decide(a, a):\n    return a\n')
        for text in cases:
            with self.subTest(text=text):
                self.rejected(text.encode('utf-8'))

    def test_no_implicit_boolean_integer_conversions_or_undeclared_names(self):
        domains = {'a': {'type': 'boolean'}, 'x': {'type': 'integer', 'min': 0, 'max': 2}}
        for expression in ('1', 'x', 'not x', 'a and x', 'x or a', 'True == 1',
                           'a < x', '0 <= x == a', 'unknown', 'False and unknown'):
            with self.subTest(expression=expression):
                self.rejected(source(expression, 'a, x'), ('a', 'x'), domains)

    def test_exact_state_types_keys_and_domain_bounds(self):
        domains = {'a': {'type': 'boolean'}, 'x': {'type': 'integer', 'min': 0, 'max': 2}}
        program = parse('a and x == 1', ('a', 'x'), domains)
        for state in ({'a': 1, 'x': 1}, {'a': True, 'x': True}, {'a': True, 'x': 1.0},
                      {'a': True, 'x': -1}, {'a': True, 'x': 3}, {'a': True},
                      {'a': True, 'x': 1, 'extra': False}, [('a', True), ('x', 1)]):
            with self.subTest(state=state), self.assertRaises(ValueError):
                adapter.evaluate(program, state)

    def test_malformed_domain_and_parameter_specification(self):
        domains = ({'a': {'type': 'Boolean'}}, {'a': {'type': ['boolean']}},
                   {'a': {'type': 'boolean', 'extra': True}},
                   {'a': {'type': 'integer', 'min': False, 'max': 1}},
                   {'a': {'type': 'integer', 'min': 2, 'max': 1}},
                   {'a': {'type': 'integer', 'min': -1000001, 'max': 1}},
                   {'a': {'type': 'integer', 'min': 0, 'max': 1000001}},
                   {}, {'b': {'type': 'boolean'}})
        for domain in domains:
            with self.subTest(domain=domain):
                self.rejected(source('a', 'a'), ('a',), domain)
        for names in (('a', 'a'), ('a', 1), ('for',), 'a', ('x' * 65,), tuple('a' + str(i) for i in range(17))):
            with self.subTest(names=names), self.assertRaises(ValueError):
                adapter.parse_function(source('True', ''), 'decide', names, {})

    def test_unicode_identifier_normalization_refused_but_utf8_comment_allowed(self):
        self.rejected('def decide(ａ):\n    return ａ\n'.encode('utf-8'))
        self.rejected('def ｄecide(a):\n    return a\n'.encode('utf-8'))
        raw = '# λ comment\n'.encode('utf-8') + source('a', 'a')
        program = adapter.parse_function(raw, 'decide', ('a',), booleans('a'))
        self.assertIs(adapter.evaluate(program, {'a': True}), True)

    def test_source_byte_bound_before_parser_and_malformed_inputs(self):
        raw = source('a', 'a')
        at_cap = raw + b'#' + b' ' * (adapter.MAX_BYTES - len(raw) - 1)
        program = adapter.parse_function(at_cap, 'decide', ('a',), booleans('a'))
        self.assertIs(adapter.evaluate(program, {'a': False}), False)
        for bad in (at_cap + b' ', b'\xff', raw + b'\0', b'def decide(', bytearray(raw), 'return True'):
            with self.subTest(kind=type(bad).__name__):
                self.rejected(bad)

    def test_depth_and_node_limits_are_enforced(self):
        self.rejected(source('not ' * adapter.MAX_DEPTH + 'a', 'a'))
        self.rejected(source(' or '.join(['a'] * 260), 'a'))
        self.rejected(source('(' * 300 + 'a' + ')' * 300, 'a'))
        program = parse('not ' * 20 + 'a', ('a',))
        self.assertIs(adapter.evaluate(program, {'a': True}), True)

    def test_exact_ast_node_and_depth_boundaries(self):
        expression = ' or '.join(['a'] * 252)
        raw = source(expression, 'a, b')
        self.assertEqual(len(tuple(ast.walk(ast.parse(raw)))), adapter.MAX_NODES)
        program = adapter.parse_function(raw, 'decide', ('a', 'b'), booleans('a', 'b'))
        self.assertIs(adapter.evaluate(program, {'a': False, 'b': True}), False)
        over = source(expression, 'a, b, c')
        self.assertEqual(len(tuple(ast.walk(ast.parse(over)))), adapter.MAX_NODES + 1)
        self.rejected(over, ('a', 'b', 'c'))
        at_depth = parse('not ' * 43 + 'a', ('a',))
        self.assertIs(adapter.evaluate(at_depth, {'a': True}), False)
        self.rejected(source('not ' * 44 + 'a', 'a'))

    def test_ordered_parameters_duplicate_spec_and_fixed_name(self):
        self.rejected(source('a', 'b, a'), ('a', 'b'))
        for name in ('decide ', '', 'for', 'ｄecide', None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.parse_function(source('a', 'a'), name, ('a',), booleans('a'))

    def test_owned_source_functions_have_explicit_size_bound(self):
        for path in (Path(adapter.__file__), Path(__file__)):
            tree = ast.parse(path.read_bytes())
            pending = [tree]
            for _ in range(10000):
                if not pending:
                    break
                node = pending.pop()
                if type(node) in (ast.FunctionDef, ast.AsyncFunctionDef):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (path.name, node.name))
                pending.extend(ast.iter_child_nodes(node))
            self.assertFalse(pending, 'owned-source inspection step bound')


if __name__ == '__main__':
    unittest.main(verbosity=2)
