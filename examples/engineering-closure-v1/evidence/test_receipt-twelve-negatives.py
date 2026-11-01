#!/usr/bin/env python3
"""Finite mutation controls for retained engineering evidence, not proof reruns."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RELATIVE = HERE.relative_to(ROOT)
MAX_FILES = 512
MAX_BYTES = 16777216
NEGATIVE_IDS = (
    'changed_source', 'missing_log', 'changed_stream', 'incomplete_proof_units',
    'unproved_check', 'swallowed_suite_failure', 'skipped_suite',
    'changed_installation', 'source_inventory_omission',
    'changed_original_installation', 'portable_inner_failure',
    'weakened_proof_contract',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_path(root, name):
    require(type(name) is str and 0 < len(name) <= 1024, 'fixture path bound')
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and relative.as_posix() == name
            and len(relative.parts) <= 32
            and all(part not in ('', '.', '..') for part in relative.parts)
            and '\\' not in name and '\x00' not in name, 'unsafe fixture path')
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), 'fixture symlink refused')
    return current


def read(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_BYTES,
            'fixture must be a bounded regular file')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES and len(data) == metadata.st_size,
            'fixture changed size or exceeded read bound')
    return data


def tree_names():
    pending, names, visited = [HERE], [], 0
    for _ in range(MAX_FILES):
        if not pending:
            return names
        with os.scandir(pending.pop()) as entries:
            for item in entries:
                visited += 1
                require(visited <= MAX_FILES and not item.is_symlink(),
                        'fixture tree entry bound or symlink')
                path = Path(item.path)
                if item.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(item.is_file(follow_symlinks=False), 'special fixture file')
                    if path != HERE / 'receipt.json':
                        names.append(path.relative_to(ROOT).as_posix())
    raise ValueError('fixture directory traversal bound')


def fixture_names():
    source = json.loads(read(ROOT / 'install/SOURCE.json'))
    proof = json.loads(read(HERE / 'evidence/source-before.json'))
    python_sources = json.loads(read(HERE / 'evidence/python-sources.json'))
    require(type(source['files']) is list and len(source['files']) <= MAX_FILES
            and type(proof) is dict and len(proof) <= MAX_FILES
            and type(python_sources) is dict and len(python_sources) <= MAX_FILES,
            'fixture inventory shape or bound')
    names = ['install/SOURCE.json'] + [item['path'] for item in source['files']]
    names += list(proof) + list(python_sources) + tree_names()
    require(all(type(name) is str for name in names), 'fixture path type')
    result = sorted(set(names))
    require(len(result) <= MAX_FILES, 'aggregate fixture path bound')
    return result


def copy_fixture(root):
    originals, total = {}, 0
    for name in fixture_names():
        source = checked_path(ROOT, name)
        size = source.lstat().st_size
        require(0 <= size <= MAX_BYTES - total, 'aggregate fixture byte bound')
        data = read(source)
        total += len(data)
        require(total <= MAX_BYTES, 'aggregate fixture bytes changed')
        destination = checked_path(root, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            require(stream.write(data) == len(data), 'short fixture copy')
        require(read(destination) == data, 'fixture copy readback differs')
        originals[name] = hashlib.sha256(data).hexdigest()
    return originals


def load_checker():
    spec = importlib.util.spec_from_file_location('engineering_closure_checker',
                                                  HERE / 'receipt.py')
    require(spec is not None and spec.loader is not None, 'checker loader unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReceiptControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract = json.loads(read(HERE / 'contract.json'))
        require(contract['negative_controls'] == list(NEGATIVE_IDS),
                'frozen negative control identifiers differ')
        cls.checker = load_checker()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='engineering-closure-controls-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.here = self.root / RELATIVE
        self.originals = copy_fixture(self.root)
        self.addCleanup(self.originals_unchanged)
        self.baseline = self.checker.expected(self.root, self.here)
        self.assertIsInstance(self.baseline, dict)

    def originals_unchanged(self):
        for name, digest in self.originals.items():
            with self.subTest(original=name):
                self.assertEqual(hashlib.sha256(read(checked_path(ROOT, name))).hexdigest(),
                                 digest, 'original fixture changed')

    def evidence(self, name):
        return checked_path(self.here / 'evidence', name)

    def change(self, path, data):
        self.assertTrue(path.is_relative_to(self.root))
        self.assertLessEqual(len(data), MAX_BYTES)
        self.assertNotEqual(read(path), data, 'negative mutation must change bytes')
        with path.open('wb') as stream:
            self.assertEqual(stream.write(data), len(data))
        self.assertEqual(read(path), data)

    def change_json(self, path, value):
        self.change(path, (json.dumps(value, sort_keys=True, separators=(',', ':'))
                           + '\n').encode('utf-8'))

    def refused(self):
        with self.assertRaises(ValueError):
            self.checker.expected(self.root, self.here)

    def test_positive_baseline(self):
        self.assertEqual(self.checker.expected(self.root, self.here), self.baseline)

    def test_changed_source(self):
        path = self.root / 'src/transport_decoder.ads'
        self.change(path, read(path) + b'\n-- Controlled copied-source mutation.\n')
        self.refused()

    def test_missing_log(self):
        path = self.evidence('core-proof-03.stdout')
        self.assertTrue(path.is_file())
        path.unlink()
        self.assertFalse(path.exists())
        self.refused()

    def test_changed_stream(self):
        path = self.evidence('core-proof-03.stdout')
        self.change(path, read(path) + b'\nCONTROLLED_CHANGED_STREAM\n')
        self.refused()

    def test_incomplete_proof_units(self):
        path = self.evidence('proofs/core.out')
        lines = read(path).splitlines(keepends=True)
        rows = [index for index, line in enumerate(lines) if line.startswith(b'in unit ')]
        self.assertTrue(rows, 'positive fixture has no proof unit rows')
        del lines[rows[-1]]
        self.change(path, b''.join(lines))
        self.refused()

    def test_unproved_check(self):
        path = self.evidence('proofs/core.out')
        lines = read(path).splitlines(keepends=True)
        rows = [index for index, line in enumerate(lines) if line.startswith(b'Total ')]
        self.assertEqual(len(rows), 1, 'positive fixture needs exactly one Total row')
        index = rows[0]
        self.assertTrue(lines[index].rstrip().endswith(b'.'))
        position = lines[index].rfind(b'.')
        lines[index] = lines[index][:position] + b'1' + lines[index][position + 1:]
        self.change(path, b''.join(lines))
        self.refused()

    def test_swallowed_suite_failure(self):
        path = self.evidence('current-handoff/test_handoff_reader.json')
        value = json.loads(read(path))
        self.assertEqual(value['exit_code'], 0)
        value.update(exit_code=1, status='FAILURE')
        self.change_json(path, value)
        self.refused()

    def test_skipped_suite(self):
        path = self.evidence('current-handoff/test_handoff_reader/receipt.json')
        value = json.loads(read(path))
        self.assertFalse(value.get('skipped'))
        value['skipped'] = [{'test': 'controlled_skipped_test', 'reason': 'UNRUN'}]
        self.change_json(path, value)
        self.refused()

    def test_changed_installation(self):
        path = self.evidence('install-current/second-bundle-inventory.json')
        value = json.loads(read(path))
        self.assertNotEqual(value['bin/semantic-transport']['sha256'], '0' * 64)
        value['bin/semantic-transport']['sha256'] = '0' * 64
        self.change_json(path, value)
        self.refused()

    def test_source_inventory_omission(self):
        names = ('source-before.json', 'source-after.json',
                 'source-after-continuation.json', 'source-after-full-proof.json',
                 'copied-source-after.json', 'copied-source-after-full-proof.json')
        for name in names:
            path = self.evidence(name)
            value = json.loads(read(path))
            self.assertIn('src/transport_decoder.ads', value)
            del value['src/transport_decoder.ads']
            self.change_json(path, value)
        self.refused()

    def test_changed_original_installation(self):
        path = self.evidence('installed-after-full-proof.json')
        value = json.loads(read(path))
        self.assertNotEqual(value['bin/transport_native']['sha256'], '0' * 64)
        value['bin/transport_native']['sha256'] = '0' * 64
        self.change_json(path, value)
        self.refused()

    def test_portable_inner_failure(self):
        path = self.evidence('install-current/portable/receipt.json')
        value = json.loads(read(path))
        self.assertNotEqual(value['status'], 'FAILED')
        value.update(status='FAILED', failure='CONTROLLED')
        self.change_json(path, value)
        self.refused()

    def test_weakened_proof_contract(self):
        path = self.here / 'contract.json'
        value = json.loads(read(path))
        self.assertNotEqual(value['proofs'][0], value['proofs'][1])
        value['proofs'][0] = dict(value['proofs'][1])
        self.change_json(path, value)
        self.refused()


if __name__ == '__main__':
    unittest.main(verbosity=2)
