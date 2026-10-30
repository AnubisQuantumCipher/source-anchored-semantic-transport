"""Independent checkpoint path controls; own markers only, no native execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'sentinel_checkpoint_subject', ROOT / 'examples/sentinel-exact-v1/freeze_receipt.py')
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class CheckpointControls(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('SENTINEL_CHECKPOINT_TEST_SCRATCH', tempfile.gettempdir()))
        base.mkdir(parents=True, exist_ok=True)
        self.folder = tempfile.TemporaryDirectory(dir=base, prefix='checkpoint-control-')
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.base = self.root / 'declared'
        self.base.mkdir()
        self.expected, self.inventories = {}, {}
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')).start()
        for name in subject.ARTIFACTS:
            data = ('HELD:' + name).encode('ascii')
            path = self.base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.expected[name] = data
        for attempt in ('attempt01', 'attempt02', 'attempt03', 'attempt04'):
            self.make_capture(attempt)

    def make_capture(self, attempt):
        folder = self.base / 'build-runs' / attempt / 'capture'
        folder.mkdir(parents=True)
        names = ['proof.stderr', 'proof/gnatprove/gnatprove.out', 'checks.stdout', 'checks.stderr']
        if attempt == 'attempt04':
            names.append('proof/gnatprove/sentinel_policy.spark')
        rows = []
        for index, name in enumerate(names):
            data = ('MARKER:' + attempt + ':' + name).encode('ascii')
            payload = 'payload-' + str(index).zfill(4) + '.bin'
            (folder / payload).write_bytes(data)
            rows.append(dict(subject.pin(data), path=name, kind='regular', payload=payload))
            self.expected['raw/' + attempt + '/' + name] = data
        self.inventories[attempt] = rows
        self.write_inventory(attempt, rows)

    def write_inventory(self, attempt, rows):
        path = self.base / 'build-runs' / attempt / 'capture' / 'inventory.json'
        path.write_text(json.dumps({'entries': rows}))

    def test_positive_copies_every_exact_fixture_byte(self):
        self.assertEqual(subject.selected_artifacts(self.base), self.expected)

    def test_absolute_and_parent_payloads_refuse_before_outside_read(self):
        outside = self.root / 'outside-marker'
        outside.write_bytes(b'OWNED_MARKER_NOT_PRIVATE_DATA')
        original = subject.read
        def guarded(path, *args):
            self.assertTrue(Path(path).is_relative_to(self.base), 'outside read attempted')
            self.assertNotIn('..', Path(path).parts, 'parent traversal attempted')
            return original(path, *args)
        for payload in (str(outside), '../outside-marker', '../../outside-marker'):
            rows = copy.deepcopy(self.inventories['attempt01'])
            rows[0]['payload'] = payload
            self.write_inventory('attempt01', rows)
            with patch.object(subject, 'read', side_effect=guarded):
                with self.assertRaisesRegex(ValueError, 'basename'):
                    subject.selected_artifacts(self.base)

    def test_duplicate_malformed_nonregular_and_declared_bounds_refuse(self):
        changes = [('payload', 'payload-1.bin'), ('payload', 'payload-0000.bin/extra'),
                   ('payload', 'payload-0000.bin\x00'), ('kind', 'symlink'),
                   ('bytes', True), ('bytes', -1), ('bytes', 1048577)]
        for key, value in changes:
            rows = copy.deepcopy(self.inventories['attempt01'])
            rows[0][key] = value
            self.write_inventory('attempt01', rows)
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                subject.selected_artifacts(self.base)
        rows = copy.deepcopy(self.inventories['attempt01'])
        rows.append(copy.deepcopy(rows[0]))
        self.write_inventory('attempt01', rows)
        with self.assertRaisesRegex(ValueError, 'missing captured'):
            subject.selected_artifacts(self.base)

    def test_reader_rejects_symlink_fifo_directory_growth_and_overbound(self):
        regular = self.root / 'regular'
        regular.write_bytes(b'EXACT')
        self.assertEqual(subject.read(regular, 5), b'EXACT')
        with self.assertRaises(ValueError):
            subject.read(regular, 4)
        link, fifo = self.root / 'link', self.root / 'fifo'
        link.symlink_to(regular)
        os.mkfifo(fifo)
        for path in (link, fifo, self.root):
            with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                subject.read(path)
        actual = subject.os.fstat
        calls = []
        def changed(fd):
            value = actual(fd)
            calls.append(fd)
            if len(calls) == 2:
                regular.write_bytes(b'CHANGED')
                return actual(fd)
            return value
        with patch.object(subject.os, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed or truncated'):
                subject.read(regular)


if __name__ == '__main__':
    unittest.main()
