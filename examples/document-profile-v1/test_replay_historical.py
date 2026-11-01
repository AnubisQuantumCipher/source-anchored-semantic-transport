"""Pure historical/current boundary counterexamples; no product or model dispatch."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('historical_replay_tested', HERE / 'replay_historical.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class HistoricalControls(unittest.TestCase):
    def fixture(self, folder):
        root, here = Path(folder) / 'root', Path(folder) / 'epoch'
        base = here / 'historical-inputs'
        manifest = json.loads((HERE / 'historical-inputs/manifest.json').read_bytes())
        for name in CHECK.ALIASES:
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((HERE / 'historical-inputs' / name).read_bytes())
        preparer = 'examples/quorum-graph-v1/prepare_receipt.py'
        payloads = {preparer: b'pass\n', 'tools/transport_quorum_graph.py': b'CURRENT_COMPONENT\n'}
        rows = []
        for name in CHECK.ALIASES:
            rows.append({'path': name, **CHECK.pin((base / name).read_bytes())})
        for name, raw in payloads.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            rows.append({'path': name, **CHECK.pin(raw)})
        receipt_path = 'examples/quorum-graph-v1/receipt.json'
        raw = json.dumps({'files': rows}).encode()
        (root / receipt_path).write_bytes(raw)
        manifest['profiles']['graph'] = {'receipt': {'path': receipt_path, **CHECK.pin(raw)},
                                         'preparer': {'path': preparer, **CHECK.pin(payloads[preparer])}}
        (base / 'manifest.json').write_text(json.dumps(manifest))
        return root, here

    def test_fixed_two_historical_aliases_current_other_bytes_and_stage_readback(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            data, preparer = CHECK.selected(root, here, 'graph')
            self.assertEqual(len(data), 5)
            self.assertEqual(preparer, 'examples/quorum-graph-v1/prepare_receipt.py')
            staged = Path(folder) / 'staged'
            CHECK.stage(staged, data)
            self.assertEqual(CHECK.read(staged, 'tools/transport_quorum_graph.py'), b'CURRENT_COMPONENT\n')
            self.assertEqual(CHECK.read(staged, 'install/check_source.py'), CHECK.historical(here)['install/check_source.py'])

    def test_missing_historical_snapshot_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            (here / 'historical-inputs/install/check_source.py').unlink()
            with self.assertRaises(OSError):
                CHECK.selected(root, here, 'graph')

    def test_tampered_historical_snapshot_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            (here / 'historical-inputs/install/check_source.py').write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):
                CHECK.selected(root, here, 'graph')

    def test_changed_current_component_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            (root / 'tools/transport_quorum_graph.py').write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):
                CHECK.selected(root, here, 'graph')

    def test_changed_retained_receipt_refuses_with_unchanged_component(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            CHECK.selected(root, here, 'graph')
            receipt = root / 'examples/quorum-graph-v1/receipt.json'
            receipt.write_bytes(receipt.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                CHECK.selected(root, here, 'graph')

    def test_unsafe_paths_refuse_before_filesystem_access(self):
        for name in ('../escape', '/absolute', 'a/../escape', 'a//b', './x', 'a\\b', 'a\x00b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                CHECK.relative(name)

    def test_oversize_file_unknown_profile_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root, here = self.fixture(folder)
            target = root / 'tools/transport_quorum_graph.py'
            with target.open('wb') as stream:
                stream.truncate(CHECK.FILE_CAP + 1)
            with self.assertRaises(ValueError):
                CHECK.selected(root, here, 'graph')
            with self.assertRaises(ValueError):
                CHECK.selected(root, here, 'unapproved')
            target.unlink()
            target.symlink_to(here / 'historical-inputs/install/check_source.py')
            with self.assertRaises(ValueError):
                CHECK.read(root, 'tools/transport_quorum_graph.py')


if __name__ == '__main__':
    unittest.main()
