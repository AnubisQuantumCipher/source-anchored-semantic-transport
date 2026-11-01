"""Tamper checks for the transport buffer parenthesis epoch."""

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EPOCH = 'examples/semantic-core-buffer-epoch'


def load(root):
    path = root / EPOCH / 'check_epoch.py'
    spec = importlib.util.spec_from_file_location('semantic_core_buffer_epoch', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BufferEpochTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='buffer-epoch-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / EPOCH, self.root / EPOCH)
        for name in load(self.root).PATHS:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        self.receipt = json.loads((ROOT / 'examples/semantic-core-v3/receipt.json').read_bytes())

    def test_current_sources_match_epoch(self):
        result = load(self.root).verify(self.root, self.receipt)
        self.assertEqual(result['status'], 'BUFFER_EPOCH_CHECKED')

    def test_live_buffer_tamper_refused(self):
        path = self.root / 'src/transport_buffers.adb'
        path.write_bytes(path.read_bytes().replace(b'(Start + Size)', b'(Start  + Size)', 1))
        with self.assertRaises(ValueError):
            load(self.root).verify(self.root, self.receipt)

    def test_historical_buffer_tamper_refused(self):
        path = self.root / EPOCH / 'historical/src/transport_buffers.adb'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            load(self.root).verify(self.root, self.receipt)

    def test_manifest_tamper_refused(self):
        path = self.root / EPOCH / 'manifest.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            load(self.root).verify(self.root, self.receipt)

    def test_extra_epoch_file_refused(self):
        (self.root / EPOCH / 'extra.txt').write_bytes(b'x')
        with self.assertRaises(ValueError):
            load(self.root).verify(self.root, self.receipt)


if __name__ == '__main__':
    unittest.main()
