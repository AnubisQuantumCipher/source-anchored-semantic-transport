"""Real graph checks through the portable exact-evidence container; no native claim."""
import ast
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
import transport_sentinel_package as subject
from transport_document_io import DocumentError, canonical, digest, read_file
import test_transport_sentinel as fixtures


class PortableEvidenceControls(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.Fixture()
        self.args = self.fixture.arguments()
        self.share, self.archive, self.report = subject.encode_evidence(*self.args)
        self.folder = tempfile.TemporaryDirectory(dir='/dev/shm', prefix='sentinel-container-')
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.blocked = patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden'))
        self.blocked.start()
        self.addCleanup(self.blocked.stop)

    def refused(self, archive=None, share=None, previous=None):
        with self.assertRaises((DocumentError, zipfile.BadZipFile)):
            subject.decode_evidence(self.archive if archive is None else archive,
                self.share if share is None else share, previous)

    def entries(self):
        with zipfile.ZipFile(io.BytesIO(self.archive)) as archive:
            return {info.filename: archive.read(info) for info in archive.infolist()}

    def altered_zip(self, entries=None, name=None, mode=None, compression=None,
                    extra=b'', comment=b'', duplicate=False, timestamp=None):
        stream = io.BytesIO()
        values = self.entries() if entries is None else entries
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.comment = comment
            for path in sorted(values):
                info = zipfile.ZipInfo(path if path != 'README.txt' or name is None else name,
                                      date_time=timestamp or (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (mode or (stat.S_IFREG | 0o600)) << 16
                info.compress_type = zipfile.ZIP_STORED if compression is None else compression
                info.extra = extra
                archive.writestr(info, values[path])
                if duplicate and path == 'README.txt':
                    with self.assertWarns(UserWarning):
                        archive.writestr(info, values[path])
        return stream.getvalue()

    def repinned_manifest(self, entries, mutate):
        manifest = subject.canonical_input(entries['manifest.json'])
        mutate(manifest)
        entries['manifest.json'] = canonical(manifest)
        share = subject.share_bytes(digest(entries['manifest.json']), 'evidence.zip', None)
        return subject.zip_bytes(entries), share

    def test_exact_deterministic_round_trip_retains_failures_and_no_qualification(self):
        share, archive, report = subject.encode_evidence(*self.args)
        self.assertEqual((share, archive, report), (self.share, self.archive, self.report))
        checked, received = subject.decode_evidence(archive, share)
        self.assertEqual(checked[:4], self.args)
        self.assertEqual(received['retained_failures'], 2)
        self.assertEqual(received['qualification'], 'NOT_QUALIFIED')
        self.assertEqual(received['execution_authority'], 'NONE')
        self.assertEqual(received['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(received['package_id'], report['package_id'])

    def test_complete_budget_at_boundary_and_one_less(self):
        exact = len(self.share)
        self.assertEqual(subject.encode_evidence(*self.args, budget=exact)[0], self.share)
        with self.assertRaisesRegex(DocumentError, 'does not fit'):
            subject.encode_evidence(*self.args, budget=exact - 1)
        for value in (True, 0, 1025):
            with self.assertRaises(DocumentError):
                subject.encode_evidence(*self.args, budget=value)

    def test_share_is_matched_and_references_are_inert(self):
        changed = self.share.replace(self.report['package_id'].encode(), b'0' * 64)
        self.refused(share=changed)
        for reference in ('', 'two words', '../local file', '\n', 'x' * 257, 'é'):
            with self.assertRaises(DocumentError):
                subject.encode_evidence(*self.args, reference=reference)
        share = subject.encode_evidence(*self.args, reference='https://example.invalid/never-fetch')[0]
        self.assertEqual(subject.decode_evidence(self.archive, share)[1]['package_id'], self.report['package_id'])
        for bad in (self.share + b'x', self.share[:-1], self.share.replace(b'PKG:', b'pkg:'), b'\xff'):
            self.refused(share=bad)

    def test_swapped_archives_refuse(self):
        other = fixtures.Fixture(1)
        _, archive, _ = subject.encode_evidence(*other.arguments())
        self.refused(archive=archive)

    def test_every_missing_entry_and_extra_entry_refuse(self):
        entries = self.entries()
        for name in entries:
            with self.subTest(missing=name):
                self.refused(archive=subject.zip_bytes({key: value for key, value in entries.items() if key != name}))
        entries['EXTRA'] = b'ignored instruction'
        self.refused(archive=subject.zip_bytes(entries))

    def test_unsafe_paths_refuse(self):
        for name in ('../escape', '/absolute', 'artifacts/../X.bin', 'artifacts/X/Y.bin',
                     'artifacts/X\\Y.bin', 'artifacts/.bin', 'README.txt/', 'C:\\X'):
            with self.subTest(path=name):
                self.refused(archive=self.altered_zip(name=name))

    def test_symlink_directory_and_device_entries_refuse(self):
        for mode in (stat.S_IFLNK | 0o600, stat.S_IFDIR | 0o600, stat.S_IFCHR | 0o600,
                     stat.S_IFREG | 0o644):
            self.refused(archive=self.altered_zip(mode=mode))

    def test_compression_extras_comments_duplicates_and_timestamp_refuse(self):
        for changed in (self.altered_zip(compression=zipfile.ZIP_DEFLATED),
                        self.altered_zip(extra=b'\x01\x00\x00\x00'),
                        self.altered_zip(comment=b'untrusted'),
                        self.altered_zip(duplicate=True),
                        self.altered_zip(timestamp=(1981, 1, 1, 0, 0, 0))):
            self.refused(archive=changed)

    def test_truncated_prefixed_trailing_and_crc_altered_zip_refuse(self):
        for changed in (self.archive[:-1], self.archive[:-22], b'prefix' + self.archive,
                        self.archive + b'trailing', self.archive[:100]):
            self.refused(archive=changed)
        changed = bytearray(self.archive)
        changed[45] ^= 1
        self.refused(archive=bytes(changed))

    def test_wrong_entry_digest_and_registry_sidecar_and_instructions_refuse(self):
        for name in ('sidecar.json', 'registry.json', 'README.txt', 'artifacts/NOTE.bin'):
            entries = self.entries()
            entries[name] += b'x'
            self.refused(archive=subject.zip_bytes(entries))

    def test_supported_manifest_types_versions_and_claims_only(self):
        for key, value in (('schema', 'sentinel/evidence-zip/2'), ('qualification', 'QUALIFIED_FOR_Q'),
                           ('execution_authority', 'EXECUTE'), ('sidecar_sha256', '0' * 64),
                           ('registry_sha256', '0' * 64), ('authentication', 'SIGNED')):
            entries = self.entries()
            archive, share = self.repinned_manifest(entries, lambda item: item.update({key: value}))
            self.refused(archive, share)
        entries = self.entries()
        archive, share = self.repinned_manifest(entries,
            lambda item: item['files'][0].update(bytes=True))
        self.refused(archive, share)

    def test_raw_sidecar_claim_or_missing_artifact_still_refuses_before_output(self):
        changed = dict(self.fixture.document)
        changed['qualification'] = dict(changed['qualification'], status='QUALIFIED_FOR_Q')
        with self.assertRaises(DocumentError):
            subject.encode_evidence(*self.fixture.arguments(changed))
        artifacts = dict(self.args[1])
        del artifacts['NOTE']
        with self.assertRaises(DocumentError):
            subject.encode_evidence(self.args[0], artifacts, *self.args[2:])

    def test_historical_continuation_requires_independently_held_root(self):
        control = fixtures.SentinelControls()
        previous, current, prior = control.extension()
        args = current.arguments()
        with self.assertRaises(DocumentError):
            subject.encode_evidence(*args)
        share, archive, report = subject.encode_evidence(*args, previous=digest(prior))
        with self.assertRaises(DocumentError):
            subject.decode_evidence(archive, share)
        with self.assertRaises(DocumentError):
            subject.decode_evidence(archive, share, '0' * 64)
        checked, value = subject.decode_evidence(archive, share, digest(prior))
        self.assertEqual(checked[4], prior)
        self.assertEqual(value['qualification'], 'NOT_QUALIFIED')
        subject.export_directory(self.root / 'extended', share, archive, report)
        self.assertEqual(read_file(self.root / 'extended' / 'evidence.zip', subject.ARCHIVE_CAP), archive)

    def test_directory_export_is_create_only_and_readback_checked(self):
        out = self.root / 'output'
        subject.export_directory(out, self.share, self.archive, self.report)
        self.assertEqual(read_file(out / 'share.txt'), self.share)
        self.assertEqual(read_file(out / 'evidence.zip', subject.ARCHIVE_CAP), self.archive)
        with self.assertRaises(FileExistsError):
            subject.export_directory(out, self.share, self.archive, self.report)

    def test_directory_input_refuses_symlinks_directories_and_unknown_names(self):
        artifacts = self.root / 'artifacts'
        artifacts.mkdir()
        for name, data in self.args[1].items():
            (artifacts / (name + '.bin')).write_bytes(data)
        self.assertEqual(subject.read_artifacts(artifacts), self.args[1])
        (artifacts / 'BAD.bin').symlink_to(artifacts / 'NOTE.bin')
        with self.assertRaises(OSError):
            subject.read_artifacts(artifacts)
        (artifacts / 'BAD.bin').unlink()
        (artifacts / 'BAD.bin').mkdir()
        with self.assertRaises(DocumentError):
            subject.read_artifacts(artifacts)
        (artifacts / 'BAD.bin').rmdir()
        (artifacts / 'bad.bin').write_bytes(b'bad')
        with self.assertRaises(DocumentError):
            subject.read_artifacts(artifacts)

    def test_staging_uses_real_validator_and_does_not_qualify(self):
        checked, _ = subject.decode_evidence(self.archive, self.share)
        exported = subject.canonical_input(subject.export_policy_inputs(*checked))
        self.assertEqual(exported['status'], 'NOT_QUALIFIED')
        self.assertEqual(exported['probes'][3]['expected_answer_sha256'], digest(b'UNKNOWN'))
        self.assertEqual(exported['probes'][4]['expected_answer_sha256'], digest(b'CONFLICT'))

    def test_parser_has_no_network_or_native_dispatch_and_functions_are_bounded(self):
        tree = ast.parse((ROOT / 'tools' / 'transport_sentinel_package.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)
        self.assertEqual(subject.parser().parse_args(['inspect', '--archive', 'a', '--share', 'b']).command,
                         'inspect')
        self.assertFalse(any(isinstance(node, ast.Import) and any(alias.name in
            ('socket', 'subprocess', 'urllib', 'requests') for alias in node.names) for node in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
