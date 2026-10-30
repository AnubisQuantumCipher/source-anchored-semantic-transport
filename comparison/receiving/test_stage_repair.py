"""Local private staging controls over the unchanged public fixture; no model calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_repair as stage
import stage_repair_support as support


class RepairStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stage-case-',
            dir=os.environ['RECEIVING_REPAIR_TEST_ROOT'])
        self.addCleanup(self.temp.cleanup)
        self.anchor = Path(self.temp.name)
        self.config = support.load(support.read(Path(os.environ['RECEIVING_REPAIR_CONFIG'])))
        self.path = self.anchor / 'config.json'
        self.path.write_bytes(support.raw_json(self.config))
        self.pin = support.digest(self.path.read_bytes())

    def prepare(self, name='run'):
        return stage.prepare(self.path, self.pin, self.anchor, name)

    def update(self):
        self.path.write_bytes(support.raw_json(self.config))
        self.pin = support.digest(self.path.read_bytes())

    def test_complete_stage_preserves_scope_and_private_modes(self):
        result = self.prepare()
        root = self.anchor / 'run'
        self.assertEqual(result['status'], 'STAGED_NOT_DISPATCHED')
        self.assertEqual(result['model_calls'], 0)
        for path in root.rglob('*'):
            expected = 0o700 if path.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, str(path))
        for name in ('task', 'annotations', 'changes'):
            suffix = '.txt' if name == 'task' else '.json'
            actual = root / 'receivers/transport/input' / (name + suffix)
            self.assertEqual(actual.read_bytes(), support.checked(self.config['inputs'][name]))
        self.assertEqual((root / 'preflight/oracle.json').read_bytes(),
                         support.checked(self.config['inputs']['oracle']))
        contents = {p.name for p in (root / 'receivers/transport/input').iterdir()}
        self.assertEqual(contents, {'content', 'manifest.json', 'annotations.json',
                                    'changes.json', 'task.txt', 'interface.txt'})
        self.assertFalse((root / 'receivers/transport/answer.json').exists())
        self.assertFalse((root / 'receivers/transport/source-workspace').exists())

    def test_existing_run_refuses_without_overwrite(self):
        self.prepare()
        path = self.anchor / 'run/preflight/staged-inputs.json'
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(path.read_bytes(), before)

    def test_nonprivate_anchor_refuses_without_chmod(self):
        self.anchor.chmod(0o755)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(stat.S_IMODE(self.anchor.stat().st_mode), 0o755)
        self.assertFalse((self.anchor / 'run').exists())

    def test_symlink_anchor_refused(self):
        target = self.anchor / 'private'
        target.mkdir(mode=0o700)
        link = self.anchor / 'linked'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            stage.prepare(self.path, self.pin, link, 'run')
        self.assertFalse((target / 'run').exists())

    def test_symlink_ancestor_of_anchor_refused(self):
        target = self.anchor / 'private'
        target.mkdir(mode=0o700)
        (target / 'nested').mkdir(mode=0o700)
        link = self.anchor / 'ancestor-link'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            stage.prepare(self.path, self.pin, link / 'nested', 'run')
        self.assertFalse((target / 'nested/run').exists())

    def test_unsafe_run_name_refused(self):
        for name in ('../escape', '/absolute', 'nested/name', '.', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare(name)

    def test_wrong_config_pin_refuses_before_run(self):
        with self.assertRaises(ValueError):
            stage.prepare(self.path, '0' * 64, self.anchor, 'run')
        self.assertFalse((self.anchor / 'run').exists())

    def test_wrong_input_pin_refuses_before_run(self):
        self.config['inputs']['task']['sha256'] = '0' * 64
        self.update()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse((self.anchor / 'run').exists())

    def test_coherent_changed_task_refuses_original_seal(self):
        target = self.anchor / 'changed-task.txt'
        raw = support.checked(self.config['inputs']['task']) + b'Changed task.'
        target.write_bytes(raw)
        self.config['inputs']['task'] = {'path': str(target), 'bytes': len(raw),
                                       'sha256': support.digest(raw)}
        self.update()
        with self.assertRaises((ValueError, KeyError)):
            self.prepare()
        self.assertFalse((self.anchor / 'run').exists())

    def test_manifest_change_beyond_relocation_refuses(self):
        config, data, unused = stage.configuration(self.path, self.pin)
        value = support.load(data['transport_original_manifest'])
        value['pair']['identity'] = 'STS1:' + '0' * 64
        data['transport_original_manifest'] = support.raw_json(value)
        with self.assertRaisesRegex(ValueError, 'MANIFEST_CHANGED'):
            stage.sealed_inputs(config, data)

    def test_missing_dependency_refuses_before_run(self):
        self.config['dependencies'][0]['path'] = str(self.anchor / 'missing')
        self.update()
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.anchor / 'run').exists())

    def test_altered_package_refuses(self):
        manifest = support.load(support.checked(self.config['inputs']['manifest']))
        folder = self.anchor / 'content'
        folder.mkdir(mode=0o700)
        for row in manifest['content']['files']:
            (folder / row['path']).write_bytes(b'tampered')
        manifest['content']['root'] = str(folder)
        with self.assertRaises(ValueError):
            stage.declared_content(manifest)

    def test_changed_parent_refuses_before_first_payload(self):
        original = stage.stage_payloads
        def interfere(config, data, content, manifest, root, records):
            (root / 'receivers/transport').chmod(0o755)
            return original(config, data, content, manifest, root, records)
        with patch.object(stage, 'stage_payloads', side_effect=interfere):
            with self.assertRaises(ValueError):
                self.prepare()
        parent = self.anchor / 'run/receivers/transport'
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        self.assertEqual(list((parent / 'input/content').iterdir()), [])

    def test_inherited_soft_and_hard_limits_never_raised(self):
        for soft, hard, ceiling, expected in ((10, 20, 30, 10), (30, 40, 20, 20),
                (resource.RLIM_INFINITY, resource.RLIM_INFINITY, 30, 30)):
            with patch.object(resource, 'getrlimit', return_value=(soft, hard)):
                with patch.object(resource, 'setrlimit') as setter:
                    support.lower_limit(resource.RLIMIT_CPU, ceiling)
                    setter.assert_called_once_with(resource.RLIMIT_CPU, (expected, expected))

    def test_duplicate_json_and_noninteger_pins_refuse(self):
        with self.assertRaises(ValueError):
            support.load(b'{"x":1,"x":2}')
        value = copy.deepcopy(self.config['inputs']['task'])
        value['bytes'] = True
        with self.assertRaises(ValueError):
            support.checked(value)

    def test_staging_budget_refuses_before_write(self):
        root = self.anchor / 'budget'
        root.mkdir(mode=0o700)
        stage.private.chain(root, 'input')
        records = [{'bytes': support.RUN_CAP}]
        with self.assertRaises(ValueError):
            support.save(root, 'input/x', b'x', records)
        self.assertFalse((root / 'input/x').exists())


if __name__ == '__main__':
    unittest.main()
