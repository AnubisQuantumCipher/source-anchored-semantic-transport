"""Independent mutation probes for the one allowed import-only repair."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('continuity', HERE / 'check_continuity.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='transport-continuity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.example = self.root / 'examples/semantic-core-v3'
        CHECK.artifact_names(ROOT / 'examples/semantic-core-v3')
        shutil.copytree(ROOT / 'examples/semantic-core-v3', self.example)
        receipt = json.loads(CHECK.read(self.example, 'receipt.json'))
        for item in receipt['source_files']:
            destination = self.root / item['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(CHECK.read(ROOT, item['path']))

    def test_exact_continuity(self):
        result = CHECK.check(self.root)
        self.assertEqual(result['status'], 'CHECKED_IMPORT_ONLY_CONTINUITY')

    def test_arbitrary_language_test_change_refused(self):
        path = self.root / CHECK.LANGUAGE
        path.write_bytes(path.read_bytes() + b'\n# arbitrary change\n')
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_missing_bootstrap_refused(self):
        path = self.root / CHECK.LANGUAGE
        path.write_bytes(CHECK.original_language(path.read_bytes()))
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_runtime_change_refused(self):
        path = self.root / 'tools/transport_core.py'
        path.write_bytes(path.read_bytes() + b'\n# runtime drift\n')
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_receipt_reseal_refused(self):
        path = self.example / 'receipt.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_added_frozen_artifact_refused(self):
        (self.example / 'unexpected').write_bytes(b'new')
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_extra_core_file_refused(self):
        (self.root / 'tools/transport_core_extra.py').write_bytes(b'def added():\n    pass\n')
        with self.assertRaises(ValueError):
            CHECK.static_core(self.root)

    def test_missing_core_file_refused(self):
        (self.root / 'tools/transport_core.py').unlink()
        with self.assertRaises(ValueError):
            CHECK.static_core(self.root)

    def test_oversized_function_refused(self):
        raw = b'def oversized():\n' + b'    pass\n' * 60
        (self.root / 'tools/transport_core.py').write_bytes(raw)
        with self.assertRaisesRegex(ValueError, '60 lines'):
            CHECK.static_core(self.root)

    def test_wrong_inventory_numeric_type_refused(self):
        rows = [{'path': 'tools/transport_core.py', 'bytes': True, 'sha256': '0' * 64}]
        with self.assertRaises(ValueError):
            CHECK.check_rows(self.root, rows)

    def test_symlink_and_traversal_refused(self):
        (self.root / 'linked').symlink_to(self.root / 'tools/transport_core.py')
        for name in ('linked', '../outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                CHECK.read(self.root, name)

    def test_oversized_input_refused(self):
        (self.root / 'oversized').write_bytes(b'x' * (CHECK.CAP + 1))
        with self.assertRaises(ValueError):
            CHECK.read(self.root, 'oversized')


if __name__ == '__main__':
    unittest.main()
