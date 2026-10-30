"""Independent pure public-boundary controls; validated() is mocked, no recovery proof.

All text is synthetic. Native/process creation is forbidden. These controls test
ordering and bindings, not actual package/native execution or OCR/English truth.
"""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as core
import transport_document_fidelity as subject

SCRATCH = Path(os.environ.get('TRANSPORT_DOCUMENT_FIDELITY_PUBLIC_TEST_SCRATCH',
                              tempfile.gettempdir())) / 'fidelity-public'
CAP = 8_388_608


def raw_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def allocated(root):
    pending, total = [root], 0
    for _ in range(8192):
        if not pending:
            return total
        path = pending.pop()
        info = path.lstat()
        total += max(info.st_size, info.st_blocks * 512)
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
            if len(pending) > 8192:
                raise ValueError('public control entry bound')
    raise ValueError('public control traversal bound')


def units(size):
    return [{'id': 'u%03d' % i, 'label': 'Synthetic unit %d' % i,
             'kind': 'page', 'source_locator': {'page': i},
             'start': i - 1, 'end': i} for i in range(1, size + 1)]


class PublicBoundaryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)
        if allocated(SCRATCH) + 1_048_576 > CAP:
            raise ValueError('public controls initial prebudget')
        cls.arena = Path(tempfile.mkdtemp(prefix='run-', dir=SCRATCH))

    def setUp(self):
        self.assertLessEqual(allocated(SCRATCH) + 65_536, CAP)
        self.case = self.arena / self._testMethodName
        self.case.mkdir(mode=0o700)
        self.original = self.case / 'source.pdf'
        self.original.write_bytes(b'%PDF synthetic bytes; no actual extraction.\n')
        self.reading_path = self.case / 'reading.txt'
        self.record_path = self.case / 'reading.json'
        self.reference_path = self.case / 'reference.txt'
        self.manifest_path = self.case / 'reference.json'
        self.source_sha = digest(self.original.read_bytes())
        self.events = []
        self.configure(b'Synthetic reading.\n', b'Synthetic reading.\n')
        denied = patch.object(subprocess, 'Popen', side_effect=AssertionError('process creation forbidden'))
        denied.start()
        self.addCleanup(denied.stop)
        no_native = patch.object(core, 'run_native', side_effect=AssertionError('native execution forbidden'))
        no_native.start()
        self.addCleanup(no_native.stop)

    def tearDown(self):
        self.assertLessEqual(allocated(SCRATCH), CAP)

    def configure(self, reading, reference, reading_units=None, reference_units=None):
        self.reading_path.write_bytes(reading)
        self.reference_path.write_bytes(reference)
        base = [{'id': 'u001', 'label': 'Synthetic unit', 'kind': 'page',
                 'source_locator': {'page': 1}, 'start': 0, 'end': len(reading)}]
        rows = copy.deepcopy(reading_units if reading_units is not None else base)
        refs = copy.deepcopy(reference_units if reference_units is not None else rows)
        if reference_units is None:
            refs[-1]['end'] = len(reference)
        self.record = {'schema': 'transport/reading-view/1', 'format': 'pdf',
                       'source_sha256': self.source_sha, 'text_sha256': digest(reading),
                       'text_bytes': len(reading), 'segments': rows,
                       'tool_versions': {'synthetic-fixture': '1'},
                       'uncertainty': ['No source transcription or semantic claim.'],
                       'coverage': {'synthetic_units': len(rows)}, 'text_path': 'reading.txt'}
        raw = raw_json(self.record)
        self.record_path.write_bytes(raw)
        self.body = {'source': {'sha256': self.source_sha},
                     'reading': {'sha256': digest(reading), 'bytes': len(reading)},
                     'entries': {'reading.json': {'bytes': len(raw), 'sha256': digest(raw)}}}
        manifest = {'schema': 'transport/document-reference/1', 'format': 'pdf',
                    'source_sha256': self.source_sha, 'text_sha256': digest(reference),
                    'text_bytes': len(reference),
                    'segments': [{k: v for k, v in row.items() if k != 'label'} for row in refs]}
        raw = raw_json(manifest)
        self.manifest_path.write_bytes(raw)
        self.manifest_sha = digest(raw)

    @contextmanager
    def validation(self, _archive, _share, _native):
        self.events.append('validated-enter')
        try:
            yield self.original, self.body, 'f' * 64, []
        finally:
            self.events.append('validated-exit')

    def verify(self, **changes):
        args = {'archive': 'synthetic-archive.zip', 'share': 'synthetic-share.txt',
                'reference_manifest': self.manifest_path, 'reference_text': self.reference_path,
                'expected_manifest_sha': self.manifest_sha}
        args.update(changes)
        with patch.object(core, 'validated', self.validation):
            return subject.verify_package_reference(**args)

    def compare(self):
        return subject.compare_reference(self.reading_path, self.record, self.manifest_path,
                                         self.reference_path, self.manifest_sha)

    def assert_boundary(self, result):
        self.assertEqual(result['claim'], 'EXACT_ORDERED_READING_TEXT_TO_HELD_REFERENCE_ONLY')
        self.assertEqual(result['reference_authentication'], 'UNAUTHENTICATED')
        self.assertEqual(result['execution_authority'], 'NONE')
        for key in ('reference_fidelity', 'OCR_accuracy', 'semantic_completeness', 'context_adequacy'):
            self.assertEqual(result[key], 'UNPROVEN')

    def test_public_positive_binds_package_metadata_source_and_text(self):
        result = self.verify()
        self.assertEqual(result['status'], 'CONDITIONAL_EXACT_REFERENCE_MATCH')
        self.assertEqual(result['package_id'], 'f' * 64)
        self.assertEqual(result['source_sha256'], self.source_sha)
        self.assertEqual(result['package_source_sha256'], self.source_sha)
        self.assertEqual(result['expected_manifest_sha256'], self.manifest_sha)
        self.assertEqual(result['compared_units'], 1)
        self.assertEqual(self.events, ['validated-enter', 'validated-exit'])
        self.assert_boundary(result)

    def test_supported_all_none_still_enters_validation_before_comparison(self):
        original = subject.compare_reference
        def observed(*args, **kwargs):
            self.assertEqual(self.events, ['validated-enter'])
            return original(*args, **kwargs)
        with patch.object(subject, 'compare_reference', side_effect=observed) as comparison:
            result = self.verify(reference_manifest=None, reference_text=None, expected_manifest_sha=None)
        comparison.assert_called_once()
        self.assertEqual(result['status'], 'REFERENCE_MISSING')
        self.assertEqual(self.events, ['validated-enter', 'validated-exit'])
        self.assert_boundary(result)

    def test_validation_refusal_blocks_comparison_and_reference_reads(self):
        with patch.object(core, 'validated', side_effect=subject.DocumentError('VALIDATION_SENTINEL')):
            with patch.object(subject, 'compare_reference', side_effect=AssertionError('comparison reached')) as compared:
                with patch.object(subject, 'reference_inputs', side_effect=AssertionError('reference reached')) as inputs:
                    with self.assertRaisesRegex(ValueError, 'VALIDATION_SENTINEL'):
                        subject.verify_package_reference('invalid', 'invalid', None, None, None)
        compared.assert_not_called()
        inputs.assert_not_called()

    def test_strong_claims_fail_before_package_or_process_work(self):
        for claim in ('OCR_ACCURACY', 'SEMANTIC_COMPLETENESS', 'UNKNOWN_PROOF'):
            with self.subTest(claim=claim), patch.object(core, 'validated') as validation:
                with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_CLAIM'):
                    subject.verify_package_reference('invalid', 'invalid', None, None, None,
                                                     requested_claim=claim)
                validation.assert_not_called()

    def test_tampered_reading_record_locator_refuses_before_comparison(self):
        changed = copy.deepcopy(self.record)
        changed['segments'][0]['source_locator'] = {'page': 2}
        self.record_path.write_bytes(raw_json(changed))
        with patch.object(subject, 'compare_reference', side_effect=AssertionError('comparison reached')) as compare:
            with self.assertRaisesRegex(ValueError, 'PACKAGE_READING_METADATA_MISMATCH'):
                self.verify()
        compare.assert_not_called()

    def test_package_source_and_text_descriptors_are_independently_bound(self):
        good = copy.deepcopy(self.body)
        variants = [('source', 'sha256', '0' * 64, 'PACKAGE_READING_SOURCE_MISMATCH'),
                    ('reading', 'sha256', '0' * 64, 'PACKAGE_READING_TEXT_MISMATCH'),
                    ('reading', 'bytes', len(self.reading_path.read_bytes()) + 1,
                     'PACKAGE_READING_TEXT_MISMATCH')]
        for field, key, value, message in variants:
            self.body = copy.deepcopy(good)
            self.body[field][key] = value
            with self.subTest(field=field, key=key), self.assertRaisesRegex(ValueError, message):
                self.verify()

    def test_opaque_package_refuses_without_comparison(self):
        self.body['reading'] = None
        with patch.object(subject, 'compare_reference', side_effect=AssertionError('comparison reached')) as compare:
            with self.assertRaisesRegex(ValueError, 'READING_RECORD_REQUIRED'):
                self.verify()
        compare.assert_not_called()

    def test_reading_metadata_symlink_refuses(self):
        stored = self.case / 'stored-reading.json'
        self.record_path.rename(stored)
        self.record_path.symlink_to(stored)
        with self.assertRaisesRegex(ValueError, 'UNSAFE_PATH'):
            self.verify()

    def test_symlink_parent_reference_refuses(self):
        parent = self.case / 'reference-parent'
        parent.symlink_to(self.case, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'UNSAFE_PATH'):
            self.verify(reference_manifest=parent / self.manifest_path.name)

    def test_valid_utf8_text_with_split_codepoint_units_refuses(self):
        rows = units(2)
        rows[1]['end'] = 3
        self.configure(b'\xc3\xa9X', b'\xc3\xa9X', rows, rows)
        with self.assertRaisesRegex(ValueError, 'INVALID_UTF8_BOUNDARY'):
            self.compare()

    def test_empty_unit_match_remains_conditional(self):
        self.configure(b'', b'')
        result = self.verify()
        self.assertEqual(result['status'], 'CONDITIONAL_EXACT_REFERENCE_MATCH')
        self.assertEqual(result['compared_units'], 1)
        self.assert_boundary(result)

    def test_mismatch_details_bounded_but_every_unit_counted(self):
        rows = units(66)
        self.configure(b'A' * 66, b'B' * 66, rows, rows)
        result = self.verify()
        self.assertEqual(result['status'], 'MISMATCH')
        self.assertEqual(result['mismatch_units'], 66)
        self.assertEqual(len(result['mismatches']), 64)
        self.assertEqual(result['compared_units'], 66)
        self.assertEqual(result['mismatches'], [{'unit_id': 'u%03d' % i,
                         'first_mismatch_offset': 0} for i in range(1, 65)])
        self.assert_boundary(result)

    def test_in_place_reading_and_reference_mutations_refuse(self):
        original = subject.compare_unit
        for path in (self.reading_path, self.reference_path):
            self.configure(b'Synthetic reading.\n', b'Synthetic reading.\n')
            def mutate(*args, **kwargs):
                result = original(*args, **kwargs)
                info = path.stat()
                path.write_bytes(b'X' + path.read_bytes()[1:])
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                return result
            with self.subTest(path=path.name), patch.object(subject, 'compare_unit', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'REFERENCE_INPUT_CHANGED'):
                    self.compare()

    def test_stricter_resource_limits_and_inherited_timer_are_preserved(self):
        inherited = {resource.RLIMIT_AS: (67_108_864, 134_217_728),
                     resource.RLIMIT_FSIZE: (4096, 8192), resource.RLIMIT_CORE: (0, 0),
                     resource.RLIMIT_NOFILE: (16, 32)}
        with patch.object(subject.resource, 'getrlimit', side_effect=lambda key: inherited[key]):
            with patch.object(subject.resource, 'setrlimit') as limited:
                with patch.object(subject.signal, 'signal'):
                    with patch.object(subject.signal, 'getitimer', return_value=(2.5, 0)):
                        with patch.object(subject.signal, 'setitimer') as timer:
                            subject.cli_limits()
        self.assertEqual(limited.call_args_list, [unittest.mock.call(key, (value[0], value[0]))
                         for key, value in inherited.items()])
        timer.assert_called_once_with(subject.signal.ITIMER_REAL, 2.5)

    def test_cli_statuses_and_refusal_never_promote_missing_or_mismatch(self):
        for status, expected in [('CONDITIONAL_EXACT_REFERENCE_MATCH', 0),
                                 ('MISMATCH', 1), ('REFERENCE_MISSING', 1)]:
            result = subject.outcome(status)
            out, err = io.StringIO(), io.StringIO()
            with patch.object(sys, 'argv', ['fidelity', '--archive', 'unused', '--share', 'unused']):
                with patch.object(subject, 'cli_limits'), patch.object(subject.signal, 'alarm'):
                    with patch.object(subject, 'verify_package_reference', return_value=result):
                        with redirect_stdout(out), redirect_stderr(err):
                            code = subject.main()
            self.assertEqual(code, expected)
            self.assertEqual(json.loads(out.getvalue())['status'], status)
            self.assertEqual(err.getvalue(), '')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['fidelity', '--archive', 'unused', '--share', 'unused']):
            with patch.object(subject, 'cli_limits'), patch.object(subject.signal, 'alarm'):
                with patch.object(subject, 'verify_package_reference', side_effect=ValueError('FIXED_REFUSAL')):
                    with redirect_stdout(out), redirect_stderr(err):
                        code = subject.main()
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('REFERENCE_REFUSED: FIXED_REFUSAL', err.getvalue())

    def test_cli_output_bound_includes_newline(self):
        result = subject.outcome('CONDITIONAL_EXACT_REFERENCE_MATCH')
        limit = len(raw_json(result))
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['fidelity', '--archive', 'unused', '--share', 'unused']):
            with patch.object(subject, 'cli_limits'), patch.object(subject.signal, 'alarm'):
                with patch.object(subject, 'MAX_OUTPUT', limit):
                    with patch.object(subject, 'verify_package_reference', return_value=result):
                        with redirect_stdout(out), redirect_stderr(err):
                            code = subject.main()
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('REFERENCE_OUTPUT_BOUND', err.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2, failfast=True)
