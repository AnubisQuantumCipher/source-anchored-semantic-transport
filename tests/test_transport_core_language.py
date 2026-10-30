"""Literal source-conformance controls; no English or model-truth oracle."""

import copy
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import transport_core_language as language
from transport_wire import TransportError

SOURCE = b'REQ_AUDIT: When E, A shall Q, unless X.\n'
TREE = {'schema': 'transport/meaning/3', 'nodes': [
    {'op': 'pred', 'predicate': 'EVENT', 'terms': []},
    {'op': 'pred', 'predicate': 'ACTION', 'terms': ['ACTOR']},
    {'op': 'pred', 'predicate': 'EXCEPTION', 'terms': []},
    {'op': 'not', 'args': [2]}, {'op': 'and', 'args': [0, 3]},
    {'op': 'if', 'args': [4, 1]}, {'op': 'must', 'args': [5]}], 'root': 6}
SYMBOLS = [
    {'id': 'EVENT', 'kind': 'predicate', 'arity': 0,
     'binding': {'kind': 'span', 'span': [16, 17], 'quote': 'E'}},
    {'id': 'ACTOR', 'kind': 'term',
     'binding': {'kind': 'span', 'span': [19, 20], 'quote': 'A'}},
    {'id': 'ACTION', 'kind': 'predicate', 'arity': 1,
     'binding': {'kind': 'span', 'span': [27, 28], 'quote': 'Q'}},
    {'id': 'EXCEPTION', 'kind': 'predicate', 'arity': 0,
     'binding': {'kind': 'span', 'span': [37, 38], 'quote': 'X'}}]


class CoreLanguageTests(unittest.TestCase):
    def assert_outside(self, source):
        result = language.parse_fragment(source)
        self.assertEqual(result['status'], 'NOT_IN_FRAGMENT')
        self.assertIsNone(result['tree'])
        self.assertEqual(result['symbols'], [])
        self.assertEqual(result['lexical_interpretation'], 'OPAQUE_MODEL_LABELS')
        return result

    def test_literal_complete_source_tree_and_byte_bindings(self):
        result = language.parse_fragment(SOURCE)
        self.assertEqual(result['status'], 'IN_FRAGMENT')
        self.assertEqual(result['tree'], TREE)
        self.assertEqual(result['symbols'], SYMBOLS)
        self.assertEqual(result['requirement_id'], {'value': 'REQ_AUDIT', 'span': [0, 9]})
        self.assertEqual(result['source_sha256'], hashlib.sha256(SOURCE).hexdigest())
        for symbol in result['symbols']:
            begin, end = symbol['binding']['span']
            self.assertEqual(SOURCE[begin:end].decode(), symbol['binding']['quote'])

    def test_no_exception_has_literal_conditional_norm_scope(self):
        result = language.parse_fragment(b'R: When E, A shall Q.')
        expected = {'schema': 'transport/meaning/3', 'nodes': [
            {'op': 'pred', 'predicate': 'EVENT', 'terms': []},
            {'op': 'pred', 'predicate': 'ACTION', 'terms': ['ACTOR']},
            {'op': 'if', 'args': [0, 1]}, {'op': 'must', 'args': [2]}], 'root': 3}
        self.assertEqual(result['tree'], expected)
        self.assertEqual([item['id'] for item in result['symbols']],
                         ['EVENT', 'ACTOR', 'ACTION'])
        self.assertNotIn('truth', result)
        self.assertNotIn('satisfaction', result)

    def test_multiword_labels_remain_opaque_and_anchored(self):
        source = (b'REQ-AUDIT-001: When a valid sample arrives, the controller shall '
                  b'append that sample to the audit log, unless maintenance mode is active at arrival.')
        result = language.parse_fragment(source)
        self.assertEqual(result['status'], 'IN_FRAGMENT')
        self.assertEqual(result['lexical_interpretation'], 'OPAQUE_MODEL_LABELS')
        self.assertEqual(result['symbols'][2]['binding']['quote'],
                         'append that sample to the audit log')
        source = b'R: When sample-ready, audit-controller shall log-sample.'
        self.assertEqual(language.parse_fragment(source)['status'], 'IN_FRAGMENT')

    def test_exact_translation_checks_tree_and_source_bindings(self):
        result = language.validate_translation(SOURCE, copy.deepcopy(TREE), copy.deepcopy(SYMBOLS))
        self.assertEqual(result['status'], 'CHECKED_CONTROLLED_TRANSLATION')
        self.assertEqual(result['lexical_interpretation'], 'OPAQUE_MODEL_LABELS')
        self.assertEqual(TREE['nodes'][5]['args'], [4, 1])
        for replacement in (b'B shall', b'A should', b'A shall not', b'A may'):
            source = SOURCE.replace(b'A shall', replacement)
            if replacement == b'B shall':
                with self.assertRaises(TransportError):
                    language.validate_translation(source, TREE, SYMBOLS)
            else:
                self.assertEqual(language.validate_translation(source, TREE, SYMBOLS)['status'],
                                 'NOT_IN_FRAGMENT')

    def test_actor_event_action_exception_mutations_do_not_match_old_bindings(self):
        for before, after in ((b'E,', b'F,'), (b'A shall', b'B shall'),
                              (b'Q,', b'R,'), (b'X.', b'Y.')):
            with self.subTest(before=before), self.assertRaises(TransportError):
                language.validate_translation(SOURCE.replace(before, after), TREE, SYMBOLS)
        for index in range(len(SYMBOLS)):
            symbols = copy.deepcopy(SYMBOLS)
            symbols[index]['binding']['span'][0] += 1
            with self.subTest(index=index), self.assertRaises(TransportError):
                language.validate_translation(SOURCE, TREE, symbols)

    def test_scope_operand_and_type_mutations_are_refused(self):
        mutations = []
        for position, key, value in ((5, 'args', [1, 4]), (3, 'op', 'must'),
                                     (1, 'terms', []), (0, 'predicate', 'ACTION')):
            tree = copy.deepcopy(TREE)
            tree['nodes'][position][key] = value
            mutations.append(tree)
        tree = copy.deepcopy(TREE)
        tree['nodes'][5]['args'][1] = True
        mutations.append(tree)
        tree = copy.deepcopy(TREE)
        tree['root'] = 5
        mutations.append(tree)
        for tree in mutations:
            with self.subTest(tree=tree), self.assertRaises(TransportError):
                language.validate_translation(SOURCE, tree, SYMBOLS)

    def test_removed_exception_or_event_never_silently_matches(self):
        with self.assertRaises(TransportError):
            language.validate_translation(SOURCE.replace(b', unless X', b''), TREE, SYMBOLS)
        self.assert_outside(b'R: A shall Q.')
        self.assert_outside(b'R: If E, A shall Q.')
        self.assert_outside(b'R: when E, A shall Q.')

    def test_clock_quantities_and_old_controller_stay_outside(self):
        cases = (b'R: When E, A shall Q within 100 ms.',
                 b'R: When E, A shall Q within 100 ms, unless X.',
                 b'R: When E, A shall Q 100 ms.',
                 b'R: When E, A shall Q within one hundred milliseconds.')
        for source in cases:
            with self.subTest(source=source):
                self.assert_outside(source)
        root = Path(__file__).resolve().parents[1]
        self.assert_outside((root / 'examples/authoring-v1/controller/source.txt').read_bytes())

    def test_document_padding_and_truncation_never_parse_a_prefix(self):
        cases = (b'', b'\n', b' ' + SOURCE, SOURCE + b'\n', SOURCE + b'Next.',
                 SOURCE.rstrip(b'\n') + b' Next.', SOURCE.replace(b'\n', b'\r\n'),
                 SOURCE.replace(b'E,', b'E, When F,'), SOURCE.replace(b'X.', b'X, unless Y.'),
                 SOURCE.replace(b'A shall', b'A  shall'), SOURCE[:-2], SOURCE[:-3],
                 SOURCE.replace(b'When E', b'When '), SOURCE.replace(b'A shall', b' shall'),
                 SOURCE.replace(b'shall Q', b'shall '), SOURCE.replace(b'unless X', b'unless '))
        for source in cases:
            with self.subTest(source=source):
                self.assert_outside(source)

    def test_unicode_controls_numbers_and_noncanonical_labels_stay_outside(self):
        labels = ('é', 'A\x00', 'A\tB', 'A  B', 'A--B', '-A', 'A-', 'A_B',
                  'A1', 'A.B', 'A;B', '(A)', 'A/B', 'A:B', 'A,B')
        for label in labels:
            source = SOURCE.replace(b'A shall', label.encode('utf-8') + b' shall')
            with self.subTest(label=label):
                self.assert_outside(source)

    def test_declared_reserved_markers_are_case_insensitively_rejected(self):
        for marker in sorted(language.RESERVED):
            for role in (b'E,', b'A shall', b'Q,', b'X.'):
                suffix = role[1:]
                source = SOURCE.replace(role, marker.upper().encode() + suffix)
                with self.subTest(marker=marker, role=role):
                    self.assert_outside(source)
        for marker in (b'because', b'believes', b'according', b'cause', b'not', b'every'):
            self.assert_outside(SOURCE.replace(b'Q,', b'Q ' + marker + b' R,'))

    def test_one_optional_newline_and_exact_source_hash(self):
        first = language.parse_fragment(SOURCE)
        second = language.parse_fragment(SOURCE[:-1])
        self.assertEqual(first['tree'], second['tree'])
        self.assertEqual(first['symbols'], second['symbols'])
        self.assertNotEqual(first['source_sha256'], second['source_sha256'])
        self.assertEqual(second['source_sha256'], hashlib.sha256(SOURCE[:-1]).hexdigest())

    def test_type_and_resource_limits_fail_closed(self):
        for source in (None, '', bytearray(SOURCE), memoryview(SOURCE), 1, True,
                       b'A' * (language.MAX_SOURCE_BYTES + 1)):
            with self.subTest(source_type=type(source)):
                result = self.assert_outside(source)
                self.assertIsNone(result['source_sha256'])
        self.assert_outside(b'R: When E, ' + b'A' * 256 + b' shall Q.')
        accepted = language.parse_fragment(b'R: When E, ' + b'A' * 255 + b' shall Q.')
        self.assertEqual(accepted['status'], 'IN_FRAGMENT')

    def test_untrusted_authored_objects_are_bounded_before_serialization(self):
        cyclic = {'schema': 'transport/meaning/3'}
        cyclic['nodes'] = cyclic
        bad = [None, [], {'nodes': list(range(9))}, {'x': 'A' * 2049},
               {'x': -1}, {'x': 0.1}, {'x': object()}, cyclic]
        for authored in bad:
            with self.subTest(authored_type=type(authored)), self.assertRaises(TransportError):
                language.validate_translation(SOURCE, authored, SYMBOLS)

    def test_outside_source_has_no_checked_translation_despite_valid_authored_tree(self):
        result = language.validate_translation(b'An ordinary document.', TREE, SYMBOLS)
        self.assertEqual(result['status'], 'NOT_IN_FRAGMENT')
        self.assertIsNone(result['tree'])


if __name__ == '__main__':
    unittest.main()
