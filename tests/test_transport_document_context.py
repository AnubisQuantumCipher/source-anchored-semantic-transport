"""Pure context-boundary controls; validated() is mocked, no native acceptance."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as document
import transport_document_context as subject


def section(name, start, end, dependencies=()):
    return {'id': name, 'label': 'Untrusted annotation', 'start': start,
            'end': end, 'dependencies': list(dependencies), 'sha256': '0' * 64}


def scratch_size(root):
    size, count = 0, 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        count += len(dirs) + len(files)
        if count > 8192:
            raise ValueError('context test entry bound')
        for name in files:
            size += (Path(folder) / name).lstat().st_size
    if size > 8_388_608:
        raise ValueError('context test scratch bound')
    return size


class ContextControls(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('TRANSPORT_DOCUMENT_CONTEXT_TEST_SCRATCH',
                                   tempfile.gettempdir())) / 'document-context-tests'
        base.mkdir(parents=True, exist_ok=True)
        if scratch_size(base) > 8_388_608 - 262_144:
            raise ValueError('context test fixture reserve')
        folder = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(folder.cleanup)
        self.addCleanup(lambda: scratch_size(base))
        self.root = Path(folder.name)
        self.source = self.root / 'source'
        self.payload = b'A!B'
        self.source.write_bytes(self.payload)
        self.sections = [section('A', 0, 1, ['B']), section('B', 2, 3)]
        self.package_id = hashlib.sha256(b'package').hexdigest()
        self.body = {'source': {'bytes': 3, 'sha256': hashlib.sha256(self.payload).hexdigest()}}
        self.calls = []
        self.addCleanup(patch.stopall)
        patch.object(document, 'validated', self.validated).start()
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/process forbidden')).start()

    @contextmanager
    def validated(self, archive, share, native):
        self.calls.append((archive, share, native))
        yield self.source, self.body, self.package_id, self.sections

    def context(self, selected='A'):
        return subject.read_section_context('archive', 'share', selected, 'native')

    def resize(self, payload, sections):
        self.payload, self.sections = payload, sections
        self.source.write_bytes(payload)
        self.body = {'source': {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}}

    def test_disjoint_literal_parts_keep_gap_identity_and_no_authority(self):
        value = self.context()
        self.assertEqual(value['parts'], [
            {'source_span': [0, 1], 'output_span': [0, 1], 'data': b'A'},
            {'source_span': [2, 3], 'output_span': [1, 2], 'data': b'B'}])
        self.assertEqual(value['gaps'], [[1, 2]])
        self.assertEqual(value['selected_bytes'], 2)
        self.assertEqual(value['package_id'], self.package_id)
        self.assertEqual(value['source_sha256'], self.body['source']['sha256'])
        self.assertEqual(value['source_bytes'], 3)
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertIn('UNPROVEN', value['interpretation'])
        self.assertNotIn('label', repr(value))
        self.assertEqual(self.calls, [('archive', 'share', 'native')])

    def test_legacy_raw_concatenation_remains_A_B_without_gap_byte(self):
        self.assertEqual(document.read_section('archive', 'share', 'A', 'native'), b'AB')

    def test_source_order_dependency_closure_not_declaration_order(self):
        self.sections = [section('A', 2, 3, ['B']), section('B', 0, 1)]
        self.assertEqual([part['data'] for part in self.context()['parts']], [b'A', b'B'])

    def test_overlap_and_adjacency_merge_without_invented_bytes(self):
        for rows in ([section('A', 0, 2, ['B']), section('B', 1, 3)],
                     [section('A', 0, 1, ['B']), section('B', 1, 3)]):
            self.sections = rows
            value = self.context()
            self.assertEqual(value['parts'], [
                {'source_span': [0, 3], 'output_span': [0, 3], 'data': b'A!B'}])
            self.assertEqual(value['gaps'], [])

    def test_exact_new_cap_accepts_and_overcap_refuses_before_part_read(self):
        self.resize(b'x' * 65536, [section('A', 0, 65536)])
        self.assertEqual(self.context()['selected_bytes'], 65536)
        self.resize(b'x' * 65537, [section('A', 0, 65537)])
        with patch.object(subject, 'read_parts', side_effect=AssertionError('overcap read')):
            with self.assertRaisesRegex(ValueError, '65536'):
                self.context()

    def test_aggregate_disjoint_cap_is_not_per_part(self):
        self.resize(b'x' * 65538, [section('A', 0, 32768, ['B']), section('B', 32769, 65538)])
        with self.assertRaisesRegex(ValueError, '65536'):
            self.context()

    def test_unknown_missing_and_cyclic_dependencies_refuse(self):
        with self.assertRaises(ValueError):
            self.context('UNKNOWN')
        self.sections = [section('A', 0, 1, ['MISSING'])]
        with self.assertRaises(ValueError):
            self.context()
        self.sections = [section('A', 0, 1, ['B']), section('B', 2, 3, ['A'])]
        with self.assertRaises(ValueError):
            self.context()

    def test_part_count_and_invalid_integer_bounds_refuse(self):
        self.sections = [section('A' + str(i), 0, 1) for i in range(65)]
        with self.assertRaisesRegex(ValueError, 'count'):
            self.context('A0')
        for start, end in ((False, 1), (0, True), (-1, 1), (1, 1), (0, 4)):
            self.sections = [section('A', start, end)]
            with self.assertRaises(ValueError):
                self.context()

    def test_exact_64_parts_preserve_all_gaps_and_outputs(self):
        self.resize(b'x!' * 64, [section('A' + str(i), i * 2, i * 2 + 1)
                                    for i in range(64)])
        self.sections[0]['dependencies'] = ['A' + str(i) for i in range(1, 64)]
        value = self.context('A0')
        self.assertEqual(len(value['parts']), 64)
        self.assertEqual(len(value['gaps']), 63)
        self.assertEqual(value['selected_bytes'], 64)
        self.assertEqual(value['parts'][-1],
                         {'source_span': [126, 127], 'output_span': [63, 64], 'data': b'x'})

    def test_malformed_selector_source_size_and_source_hash_refuse(self):
        for selected in (None, False, []):
            with self.assertRaises(ValueError):
                self.context(selected)
        self.body['source']['bytes'] = False
        with self.assertRaises(ValueError):
            self.context()
        self.body['source']['bytes'] = 3
        self.body['source']['sha256'] = 'invalid'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.context()

    def test_validation_refusal_precedes_part_access(self):
        @contextmanager
        def refuse(*_args):
            raise ValueError('original validation refusal')
            yield
        with patch.object(document, 'validated', refuse), \
             patch.object(subject, 'read_parts', side_effect=AssertionError('unvalidated read')):
            with self.assertRaisesRegex(ValueError, 'original validation refusal'):
                self.context()

    def test_symlink_source_and_source_size_change_refuse(self):
        actual = self.root / 'actual'
        self.source.rename(actual)
        self.source.symlink_to(actual)
        with self.assertRaises(OSError):
            self.context()
        self.source.unlink()
        actual.rename(self.source)
        self.source.write_bytes(b'AB')
        with self.assertRaisesRegex(ValueError, 'size changed'):
            self.context()

    def test_short_read_refuses_and_descriptor_change_refuses(self):
        real_identity = subject.identity
        def truncate(stream):
            before = real_identity(stream)
            self.source.write_bytes(b'A')
            return before
        with patch.object(subject, 'identity', side_effect=truncate):
            with self.assertRaisesRegex(ValueError, 'truncated'):
                self.context()
        self.source.write_bytes(b'A!B')
        before = None
        def changed(stream):
            nonlocal before
            row = real_identity(stream)
            if before is None:
                before = row
                return row
            return row[:-1] + (row[-1] + 1,)
        with patch.object(subject, 'identity', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'descriptor changed'):
                self.context()

    def test_metadata_cap_and_bad_source_package_id_refuse(self):
        with patch.object(subject, 'MAX_CONTEXT_META', 1):
            with self.assertRaisesRegex(ValueError, 'metadata bound'):
                self.context()
        self.package_id = 'invalid'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.context()


if __name__ == '__main__':
    unittest.main()
