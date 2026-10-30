"""Independent synthetic-policy data controls; no executable payload runs."""
import hashlib
import os
import tempfile
import importlib.util
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / 'tools/package_document_decoder.py'
SCRATCH = Path(os.environ.get('TRANSPORT_DOCUMENT_BUNDLE_TEST_SCRATCH', '/dev/shm/transport-document-bundle-tests'))
SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
ROOT = Path(tempfile.mkdtemp(prefix='bundle-', dir=SCRATCH))
spec = importlib.util.spec_from_file_location('bundle_subject', SOURCE)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


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
                raise ValueError('control inventory bound')
    raise ValueError('control iteration bound')


def stored(path, entries):
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in entries.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100755 if name == 'document_native_decode' else 0o100644) << 16
            archive.writestr(info, raw)


class Pure(unittest.TestCase):
    def setUp(self):
        self.assertLessEqual(allocated(ROOT) + 262144, 4194304)
        self.case = ROOT / (('optimized-' if sys.flags.optimize else 'normal-') + self._testMethodName)
        self.case.mkdir(mode=0o700)
        self.inputs = self.case / 'inputs'
        (self.inputs / 'tools').mkdir(parents=True, mode=0o700)
        self.data = {name: (name + ': independently fixed synthetic bytes\n').encode()
                     for name in subject.HELD}
        self.policy = {name: digest(raw) for name, raw in self.data.items()}
        for name, raw in self.data.items():
            path = self.inputs / name if name in ('LICENSE', 'document_native_decode') else self.inputs / 'tools' / name
            path.write_bytes(raw)
        self.native = self.inputs / 'document_native_decode'
        self.archive = self.case / 'test.zip'

    def tearDown(self):
        self.assertLessEqual(allocated(ROOT), 4194304)

    def create(self):
        with patch.object(subject, 'HELD', self.policy):
            return subject.create_bundle(self.inputs, self.native, self.archive)

    def test_positive_data_roundtrip(self):
        result = self.create()
        self.assertEqual(result['archive']['sha256'], digest(self.archive.read_bytes()))
        with patch.object(subject, 'HELD', self.policy):
            _raw, data, _meta, _manifest = subject.loaded_bundle(self.archive)
            output = self.case / 'decoded-software'
            unpacked = subject.unpack_bundle(self.archive, output)
            self.assertEqual(unpacked['status'], 'CHECKED_UNPACKED_PAYLOAD_NOT_EXECUTED')
        for name, raw in data.items():
            self.assertEqual((output / name).read_bytes(), raw)
        self.assertEqual((output / 'document_native_decode').stat().st_mode & 0o777, 0o755)

    def test_missing_input_refuses_before_archive(self):
        (self.inputs / 'tools/transport_document.py').unlink()
        with self.assertRaises(OSError):
            self.create()
        self.assertFalse(self.archive.exists())

    def test_different_input_refuses_before_archive(self):
        (self.inputs / 'tools/transport_document.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'declared input pin mismatch'):
            self.create()
        self.assertFalse(self.archive.exists())

    def test_oversize_refuses_before_read(self):
        path = self.case / 'three-bytes'
        path.write_bytes(b'ABC')
        with patch.object(subject.os, 'read', side_effect=AssertionError('read reached')) as read:
            with self.assertRaisesRegex(ValueError, 'file type or byte bound'):
                subject.read_bounded(path, 2)
        read.assert_not_called()

    def test_create_only_refuses_before_collection(self):
        self.archive.write_bytes(b'KEEP')
        with patch.object(subject, 'collect', side_effect=AssertionError('collection reached')) as collect:
            with self.assertRaisesRegex(ValueError, 'destination already exists'):
                subject.create_bundle(self.inputs, self.native, self.archive)
        collect.assert_not_called()
        self.assertEqual(self.archive.read_bytes(), b'KEEP')

    def test_changed_member_refuses_before_extraction(self):
        self.create()
        with zipfile.ZipFile(self.archive) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries['transport_document.py'] = b'changed while old manifest pins remain'
        changed = self.case / 'changed.zip'
        stored(changed, entries)
        output = self.case / 'refused-output'
        with patch.object(subject, 'HELD', self.policy):
            with self.assertRaisesRegex(ValueError, 'bundle file pin mismatch'):
                subject.unpack_bundle(changed, output)
        self.assertFalse(output.exists())

    def test_missing_member_refuses_before_extraction(self):
        self.create()
        with zipfile.ZipFile(self.archive) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries.pop('transport_document_reading.py')
        missing = self.case / 'missing.zip'
        stored(missing, entries)
        output = self.case / 'refused-output'
        with patch.object(subject, 'HELD', self.policy):
            with self.assertRaisesRegex(ValueError, 'bundle directory bound'):
                subject.unpack_bundle(missing, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2, failfast=True)
