"""Independent literal reference comparator controls; no native or semantic run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document_fidelity as subject

CLAIM = 'EXACT_ORDERED_READING_TEXT_TO_HELD_REFERENCE_ONLY'
REFERENCE_UNITS = ['The controller shall not permit reset.\n',
 'Transfer 100 ms after the sample arrives.\n',
 'Alice shall notify Bob.\n',
 'The controller shall append the sample unless maintenance is active.\n']
LITERAL_CASES = [{'expected': 'MATCH',
  'id': 'positive',
  'literal_expected_offsets': [],
  'mismatch_units': [],
  'reading_units': ['The controller shall not permit reset.\n',
                    'Transfer 100 ms after the sample arrives.\n',
                    'Alice shall notify Bob.\n',
                    'The controller shall append the sample unless maintenance is active.\n']},
 {'expected': 'DIFFERS',
  'id': 'dropped_negation',
  'literal_expected_offsets': [{'first_mismatch_offset': 21, 'unit_id': 'u1'}],
  'mismatch_units': ['u1'],
  'reading_units': ['The controller shall permit reset.\n',
                    'Transfer 100 ms after the sample arrives.\n',
                    'Alice shall notify Bob.\n',
                    'The controller shall append the sample unless maintenance is active.\n']},
 {'expected': 'DIFFERS',
  'id': 'changed_number',
  'literal_expected_offsets': [{'first_mismatch_offset': 12, 'unit_id': 'u2'}],
  'mismatch_units': ['u2'],
  'reading_units': ['The controller shall not permit reset.\n',
                    'Transfer 1000 ms after the sample arrives.\n',
                    'Alice shall notify Bob.\n',
                    'The controller shall append the sample unless maintenance is active.\n']},
 {'expected': 'DIFFERS',
  'id': 'changed_unit',
  'literal_expected_offsets': [{'first_mismatch_offset': 13, 'unit_id': 'u2'}],
  'mismatch_units': ['u2'],
  'reading_units': ['The controller shall not permit reset.\n',
                    'Transfer 100 s after the sample arrives.\n',
                    'Alice shall notify Bob.\n',
                    'The controller shall append the sample unless maintenance is active.\n']},
 {'expected': 'DIFFERS',
  'id': 'swapped_actors',
  'literal_expected_offsets': [{'first_mismatch_offset': 0, 'unit_id': 'u3'}],
  'mismatch_units': ['u3'],
  'reading_units': ['The controller shall not permit reset.\n',
                    'Transfer 100 ms after the sample arrives.\n',
                    'Bob shall notify Alice.\n',
                    'The controller shall append the sample unless maintenance is active.\n']},
 {'expected': 'DIFFERS',
  'id': 'lost_exception',
  'literal_expected_offsets': [{'first_mismatch_offset': 38, 'unit_id': 'u4'}],
  'mismatch_units': ['u4'],
  'reading_units': ['The controller shall not permit reset.\n',
                    'Transfer 100 ms after the sample arrives.\n',
                    'Alice shall notify Bob.\n',
                    'The controller shall append the sample.\n']}]
SOURCE_HASH = hashlib.sha256(b'Independent synthetic source; not an actual PDF.\n').hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def segments(units, labelled=False):
    rows, offset = [], 0
    for index, text in enumerate(units, 1):
        end = offset + len(text.encode('utf8'))
        row = {'id': 'u' + str(index), 'kind': 'page', 'source_locator': {'page': index},
               'start': offset, 'end': end}
        if labelled:
            row['label'] = 'Synthetic unit ' + str(index)
        rows.append(row)
        offset = end
    return rows


class LiteralReferenceControls(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.case = Path(self.folder.name)
        self.reading_path = self.case / 'reading.txt'
        self.reference_path = self.case / 'reference.txt'
        self.manifest_path = self.case / 'reference.json'
        reference = ''.join(REFERENCE_UNITS).encode('utf8')
        self.reference_path.write_bytes(reference)
        self.manifest = {'schema': 'transport/document-reference/1', 'source_sha256': SOURCE_HASH,
                         'format': 'pdf', 'text_sha256': sha(reference), 'text_bytes': len(reference),
                         'segments': segments(REFERENCE_UNITS)}
        self.write_manifest()
        self.write_reading(REFERENCE_UNITS)

    def write_manifest(self):
        raw = json.dumps(self.manifest, sort_keys=True, separators=(',', ':')).encode('utf8')
        self.manifest_path.write_bytes(raw)
        self.expected_sha = sha(raw)

    def write_reading(self, units):
        raw = ''.join(units).encode('utf8')
        self.reading_path.write_bytes(raw)
        self.reading = {'schema': 'transport/reading-view/1', 'format': 'pdf',
                        'source_sha256': SOURCE_HASH, 'text_sha256': sha(raw),
                        'text_bytes': len(raw), 'segments': segments(units, True),
                        'tool_versions': {'independent-fixture': '1'},
                        'uncertainty': ['Synthetic mechanism test, no real PDF extraction.'],
                        'coverage': {'pages': 4}, 'text_path': 'reading.txt'}

    def compare(self, **changes):
        args = {'reading_text_path': self.reading_path, 'reading_record': self.reading,
                'reference_manifest_path': self.manifest_path,
                'reference_text_path': self.reference_path,
                'expected_manifest_sha': self.expected_sha, 'requested_claim': CLAIM}
        args.update(changes)
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('pure comparator spawned process')):
            return subject.compare_reference(**args)

    def assert_boundary(self, result):
        self.assertEqual(result['claim'], CLAIM)
        self.assertEqual(result['reference_authentication'], 'UNAUTHENTICATED')
        for key in ('reference_fidelity', 'OCR_accuracy', 'semantic_completeness', 'context_adequacy'):
            self.assertEqual(result[key], 'UNPROVEN')
        self.assertEqual(result['execution_authority'], 'NONE')

    def test_literal_positive_and_all_semantic_byte_changes(self):
        for case in LITERAL_CASES:
            with self.subTest(case=case['id']):
                self.write_reading(case['reading_units'])
                result = self.compare()
                self.assert_boundary(result)
                expected = 'CONDITIONAL_EXACT_REFERENCE_MATCH' if case['expected'] == 'MATCH' else 'MISMATCH'
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['mismatch_units'], len(case['mismatch_units']))
                self.assertEqual(result['mismatches'], case['literal_expected_offsets'])

    def test_independently_held_manifest_pin_mismatch_refuses(self):
        with self.assertRaises(ValueError):
            self.compare(expected_manifest_sha='0' * 64)

    def test_wrong_reference_source_refuses_even_with_new_manifest_pin(self):
        self.manifest['source_sha256'] = sha(b'different synthetic source')
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.compare()

    def test_wrong_reference_format_refuses(self):
        self.manifest['format'] = 'epub'
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.compare()

    def test_missing_duplicate_reordered_reference_units_refuse(self):
        good = copy.deepcopy(self.manifest)
        variants = [good['segments'][:-1], good['segments'] + [good['segments'][0]],
                    list(reversed(good['segments']))]
        for rows in variants:
            with self.subTest(rows=rows):
                self.manifest = copy.deepcopy(good)
                self.manifest['segments'] = rows
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.compare()

    def test_unknown_reference_field_schema_and_version_refuse(self):
        good = copy.deepcopy(self.manifest)
        for key, value in [('trusted', True), ('schema', 'unrecognized'),
                           ('schema', 'transport/document-reference/2')]:
            with self.subTest(key=key, value=value):
                self.manifest = copy.deepcopy(good)
                self.manifest[key] = value
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.compare()

    def test_reference_gap_overlap_and_locator_substitution_refuse(self):
        good = copy.deepcopy(self.manifest)
        for delta in (-1, 1):
            self.manifest = copy.deepcopy(good)
            self.manifest['segments'][1]['start'] += delta
            self.write_manifest()
            with self.assertRaises(ValueError):
                self.compare()
        self.manifest = copy.deepcopy(good)
        self.manifest['segments'][0]['source_locator'] = {'page': 99}
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.compare()

    def test_missing_duplicate_reordered_reading_units_refuse(self):
        good = copy.deepcopy(self.reading)
        for rows in (good['segments'][:-1], good['segments'] + [good['segments'][0]],
                     list(reversed(good['segments']))):
            changed = copy.deepcopy(good)
            changed['segments'] = rows
            with self.assertRaises(ValueError):
                self.compare(reading_record=changed)

    def test_reference_truncation_or_stale_text_pin_refuses(self):
        raw = self.reference_path.read_bytes()
        for changed in (raw[:-1], raw + b'not declared'):
            self.reference_path.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.compare()

    def test_reading_truncation_or_stale_text_pin_refuses(self):
        raw = self.reading_path.read_bytes()
        for changed in (raw[:-1], raw + b'not declared'):
            self.reading_path.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.compare()

    def test_reference_invalid_utf8_refuses_even_with_correct_hashes(self):
        raw = self.reference_path.read_bytes()
        changed = b'\xff' + raw[1:]
        self.reference_path.write_bytes(changed)
        self.manifest['text_sha256'] = sha(changed)
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.compare()

    def test_reading_invalid_utf8_refuses_even_with_correct_hashes(self):
        raw = self.reading_path.read_bytes()
        changed = b'\xff' + raw[1:]
        self.reading_path.write_bytes(changed)
        self.reading['text_sha256'] = sha(changed)
        with self.assertRaises(ValueError):
            self.compare()

    def test_leaf_symlink_inputs_refuse(self):
        for key, target in [('reading_text_path', self.reading_path),
                            ('reference_manifest_path', self.manifest_path),
                            ('reference_text_path', self.reference_path)]:
            link = self.case / (key + '-link')
            link.symlink_to(target)
            with self.subTest(path=key), self.assertRaises(ValueError):
                self.compare(**{key: link})

    def test_special_directory_input_refuses(self):
        for key in ('reading_text_path', 'reference_manifest_path', 'reference_text_path'):
            with self.subTest(path=key), self.assertRaises(ValueError):
                self.compare(**{key: self.case})

    def test_missing_reference_is_explicit_and_never_verified(self):
        result = self.compare(reference_manifest_path=None, reference_text_path=None,
                              expected_manifest_sha=None)
        self.assertEqual(result['status'], 'REFERENCE_MISSING')
        self.assert_boundary(result)

    def test_partial_reference_tuple_refuses_as_malformed(self):
        variants = [{'reference_manifest_path': None}, {'reference_text_path': None},
                    {'expected_manifest_sha': None},
                    {'reference_manifest_path': None, 'reference_text_path': None},
                    {'reference_manifest_path': None, 'expected_manifest_sha': None},
                    {'reference_text_path': None, 'expected_manifest_sha': None}]
        for values in variants:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, 'PARTIAL_REFERENCE'):
                self.compare(**values)

    def test_named_missing_reference_files_refuse(self):
        for key in ('reference_manifest_path', 'reference_text_path'):
            missing = self.case / ('absent-' + key)
            self.assertFalse(missing.exists())
            with self.subTest(path=key), self.assertRaisesRegex(ValueError, 'REFERENCE_FILE_MISSING'):
                self.compare(**{key: missing})

    def test_unsupported_broad_claim_refuses_even_when_bytes_match(self):
        for claim in ('OCR_ACCURACY', 'SEMANTIC_COMPLETENESS'):
            with self.subTest(claim=claim), self.assertRaisesRegex(ValueError, 'UNSUPPORTED_CLAIM'):
                self.compare(requested_claim=claim)


if __name__ == '__main__':
    unittest.main(verbosity=2)
