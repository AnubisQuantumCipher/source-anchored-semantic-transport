#!/usr/bin/env python3
"""Small isolated native-reuse controls; no compiler, live donor or runtime execution."""

import copy
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_repackage as reuse
from transport_install_layout import input_names
from transport_install_support import canonical, sha


class RepackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='transport-repackage-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('old', 'new', 'donor', 'provenance'):
            (self.root / name).mkdir(mode=0o700)
        self.config_path = self.root / 'config.json'
        self.config = dict(schema='transport/repackage-config/1', source_trust=reuse.TRUST,
            old_source=dict(root=str(self.root / 'old'), sha256='1' * 64),
            new_source=dict(root=str(self.root / 'new'), sha256='2' * 64),
            donor=dict(root=str(self.root / 'donor'), install_sha256='3' * 64, native_sha256='4' * 64,
                build_receipt=dict(path=str(self.root / 'provenance/receipt.json'), sha256='5' * 64),
                compile_receipt=dict(path=str(self.root / 'provenance/compile.json'), sha256='6' * 64)),
            output=dict(prefix=str(self.root / 'derived'), receipt=str(self.root / 'receipt')))
        self.make_donor()
        self.make_provenance()
        self.save_config()

    def save_config(self):
        raw = canonical(self.config)
        self.config_path.write_bytes(raw)
        return sha(raw)

    def save_record(self, name, value):
        record = self.config['donor'][name]
        raw = canonical(value)
        Path(record['path']).write_bytes(raw)
        record['sha256'] = sha(raw)

    def make_donor(self):
        donor = self.root / 'donor'
        (donor / 'bin').mkdir(mode=0o700)
        native = bytearray(64)
        native[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', native, 18, reuse.PROFILES[platform.machine()]['machine'])
        self.native = bytes(native)
        (donor / 'bin/transport_native').write_bytes(self.native)
        (donor / 'bin/semantic-transport').write_bytes(b'fictional nonexecuted launcher')
        (donor / 'RUNTIME.json').write_bytes(b'fictional old runtime')
        files = [dict(path=name, bytes=len((donor / name).read_bytes()), sha256=sha((donor / name).read_bytes()))
                 for name in ('bin/transport_native', 'RUNTIME.json')]
        raw = canonical(dict(files=files))
        (donor / 'INSTALL.json').write_bytes(raw)
        self.config['donor'].update(install_sha256=sha(raw), native_sha256=sha(self.native))

    def make_provenance(self):
        donor = self.config['donor']
        profile = reuse.PROFILES[platform.machine()]
        drivers = {name: dict(path=str(self.root / ('gpr' if name == 'gprbuild' else 'compiler') / name),
                    bytes=1, sha256='7' * 64, version='fictional test driver, not executed')
                   for name in ('gcc', 'gnatbind', 'gnatlink', 'gprbuild', 'readelf')}
        self.build = dict(schema='transport/build-receipt/1', action='build', status='INSTALLED_BUILD_SPECIFIC_BUNDLE',
            prefix=donor['root'], source_manifest_sha256=self.config['old_source']['sha256'],
            install_manifest_sha256=donor['install_sha256'], scratch=str(self.root / 'old-scratch'),
            environment=dict(architecture=platform.machine()), toolchain=dict(drivers=drivers),
            elf=dict(native_sha256=donor['native_sha256'], interpreter=profile['interpreter'],
                     search_paths='ABSENT', needed=['libc.so.6']),
            verification=dict(status='INSTALLATION_RECONSTRUCTION_CHECKED',
                source_manifest_sha256=self.config['old_source']['sha256'],
                manifest_sha256=donor['install_sha256'], native_sha256=donor['native_sha256']))
        mapped = self.build['scratch'] + '=/source/source-anchored-semantic-transport'
        self.compile = dict(status='SUCCESS', exit_code=0, argv=[drivers['gprbuild']['path'], '-q', '-p', '-R',
            '-P', 'transport.gpr', '-j1', '-cargs:Ada', '-fdebug-prefix-map=' + mapped,
            '-ffile-prefix-map=' + mapped, '-gno-record-gcc-switches'],
            environment=dict(PATH=':'.join((str(self.root / 'gpr'), str(self.root / 'compiler'), '/usr/bin', '/bin')),
                             LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1', SOURCE_DATE_EPOCH='0'))
        for stream in ('stdout', 'stderr'):
            (self.root / 'provenance' / ('compile.' + stream)).write_bytes(b'')
            self.compile[stream] = dict(path='compile.' + stream, bytes=0, sha256=sha(b''))
        self.save_record('build_receipt', self.build)
        self.save_record('compile_receipt', self.compile)

    def sources(self):
        old = {name: ('synthetic input ' + name).encode() for name in input_names()}
        old['tools/transport_plan.py'] = (b'from transport_schema import canonical\n'
            b'def check_plan():\n    return "unchanged"\n'
            b'def semantic_lines(units):\n    return ["old rendering"]\n')
        new = dict(old)
        new['tools/transport_plan.py'] = old['tools/transport_plan.py'].replace(b'old rendering', b'new rendering')
        return old, new

    def state(self):
        paths = reuse.paths_for(self.config, self.config_path)
        snapshot, native = reuse.bundle_snapshot(paths['donor'], self.config['donor']['install_sha256'],
                                                 self.config['donor']['native_sha256'])
        old, new = self.sources()
        return dict(config=self.config, config_path=self.config_path, config_sha256=self.save_config(),
            paths=paths, old=old, new=new, comparison=reuse.compare_inputs(old, new),
            donor_snapshot=snapshot, native=native, helpers=[], storage=[],
            provenance=reuse.original_provenance(self.config))

    def fake_stage(self, stage, files, native, source_sha, environment, receipt):
        (stage / 'bin').mkdir(mode=0o700)
        (stage / 'bin/transport_native').write_bytes(native)
        (stage / 'RUNTIME.json').write_bytes(b'fictional new runtime')
        (stage / 'INSTALL.json').write_bytes(b'fictional new installation')
        return sha(b'fictional new installation')

    def test_pinned_config_requires_exact_fields_trust_and_digests(self):
        self.assertEqual(reuse.load_config(self.config_path, self.save_config()), self.config)
        with self.assertRaises(ValueError):
            reuse.load_config(self.config_path, '0' * 64)
        for key, value in (('schema', 'unknown'), ('source_trust', 'assumed'), ('extra', True)):
            altered = dict(self.config, **{key: value})
            self.config_path.write_bytes(canonical(altered))
            with self.assertRaises(ValueError):
                reuse.load_config(self.config_path, sha(self.config_path.read_bytes()))

    def test_native_bootstrap_and_all_nonrenderer_changes_refuse(self):
        old, new = self.sources()
        self.assertEqual(reuse.compare_inputs(old, new)['changed'], ['tools/transport_plan.py'])
        cases = ('src/transport_native.adb', 'transport.gpr', 'install/transport_install_build.py',
                 'install/transport_install_check.py', 'tools/transport_package.py')
        for name in cases:
            altered = dict(new)
            altered[name] += b' changed'
            with self.subTest(name=name), self.assertRaises(ValueError):
                reuse.compare_inputs(old, altered)
        for altered in ({name: raw for name, raw in new.items() if name != 'src/transport_native.adb'},
                        dict(new, **{'src/extra.adb': b'new'}), dict(old)):
            with self.assertRaises(ValueError):
                reuse.compare_inputs(old, altered)
        altered = dict(new)
        altered['tools/transport_plan.py'] = altered['tools/transport_plan.py'].replace(b'unchanged', b'changed')
        with self.assertRaises(ValueError):
            reuse.compare_inputs(old, altered)
        altered['tools/transport_plan.py'] = b'def invalid('
        with self.assertRaises(ValueError):
            reuse.compare_inputs(old, altered)

    def test_executing_helper_closure_must_match_declared_bootstrap(self):
        files = {'install/' + name: (reuse.HERE / name).read_bytes()
                 for name in reuse.HELPERS if name != 'transport_repackage.py'}
        self.assertEqual(len(reuse.helper_pins(files)), len(reuse.HELPERS))
        files['install/transport_install_check.py'] += b' changed'
        with self.assertRaises(ValueError):
            reuse.helper_pins(files)

    def test_source_and_native_immutability_rechecks_refuse_changes(self):
        state = self.state()
        changed = dict(state['new'])
        changed['src/transport_native.adb'] += b' changed during derivation'
        with mock.patch('transport_install_layout.source_inputs', side_effect=[({}, state['old']), ({}, changed)]):
            with self.assertRaises(ValueError):
                reuse.unchanged(state)
        (self.root / 'donor/bin/transport_native').write_bytes(b'changed during derivation')
        with mock.patch('transport_install_layout.source_inputs', side_effect=[({}, state['old']), ({}, state['new'])]):
            with self.assertRaises(ValueError):
                reuse.unchanged(state)

    def test_original_build_compile_and_logs_are_bound(self):
        result = reuse.original_provenance(self.config)
        self.assertEqual(result['elf']['native_sha256'], self.config['donor']['native_sha256'])
        (self.root / 'provenance/compile.stderr').write_bytes(b'tamper')
        with self.assertRaises(ValueError):
            reuse.original_provenance(self.config)

    def test_coherently_repinned_false_provenance_refuses(self):
        for field, value in (('status', 'FAILED'), ('action', 'check'), ('source_manifest_sha256', '0' * 64),
                             ('install_manifest_sha256', '0' * 64), ('prefix', str(self.root / 'elsewhere'))):
            altered = dict(self.build, **{field: value})
            self.save_record('build_receipt', altered)
            with self.subTest(field=field), self.assertRaises(ValueError):
                reuse.original_provenance(self.config)
        self.save_record('build_receipt', self.build)
        for field, value in (('status', 'FAILED'), ('exit_code', True), ('argv', ['not-the-build']),
                             ('environment', {})):
            self.save_record('compile_receipt', dict(self.compile, **{field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                reuse.original_provenance(self.config)

    def test_native_elf_and_verification_provenance_refuse_mismatches(self):
        for key in ('elf', 'verification'):
            altered = copy.deepcopy(self.build)
            altered[key]['native_sha256'] = '0' * 64
            self.save_record('build_receipt', altered)
            with self.subTest(key=key), self.assertRaises(ValueError):
                reuse.original_provenance(self.config)
        self.save_record('build_receipt', self.build)
        self.config['donor']['compile_receipt']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            reuse.original_provenance(self.config)

    def test_malformed_and_tampered_held_records_refuse(self):
        path = Path(self.config['donor']['build_receipt']['path'])
        path.write_bytes(b'{')
        self.config['donor']['build_receipt']['sha256'] = sha(b'{')
        with self.assertRaises(ValueError):
            reuse.original_provenance(self.config)
        self.make_provenance()
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            reuse.original_provenance(self.config)

    def test_compile_receipt_cannot_be_swapped_from_another_directory(self):
        original = Path(self.config['donor']['compile_receipt']['path'])
        elsewhere = self.root / 'other-provenance'
        elsewhere.mkdir(mode=0o700)
        swapped = elsewhere / 'compile.json'
        swapped.write_bytes(original.read_bytes())
        self.config['donor']['compile_receipt']['path'] = str(swapped)
        with self.assertRaises(ValueError):
            reuse.original_provenance(self.config)

    def test_donor_manifest_native_and_elf_bytes_are_pinned(self):
        donor = self.root / 'donor'
        held = self.config['donor']
        snapshot, native = reuse.bundle_snapshot(donor, held['install_sha256'], held['native_sha256'])
        self.assertEqual(native, self.native)
        self.assertEqual(snapshot['install_sha256'], held['install_sha256'])
        with self.assertRaises(ValueError):
            reuse.bundle_snapshot(donor, '0' * 64, held['native_sha256'])
        (donor / 'bin/transport_native').write_bytes(b'corrupt native')
        with self.assertRaises(ValueError):
            reuse.bundle_snapshot(donor, held['install_sha256'], held['native_sha256'])
        with self.assertRaises(ValueError):
            reuse.bundle_snapshot(donor, held['install_sha256'], sha(b'corrupt native'))

    def test_output_alias_source_overlap_existing_and_symlink_refuse_before_writes(self):
        original = copy.deepcopy(self.config)
        bad = [dict(prefix=str(self.root / name / 'child'), receipt=str(self.root / 'receipt'))
               for name in ('old', 'new', 'donor')]
        bad += [dict(prefix=str(self.root / 'same'), receipt=str(self.root / 'same')),
                dict(prefix='relative', receipt=str(self.root / 'receipt'))]
        for output in bad:
            self.config['output'] = output
            with self.subTest(output=output), self.assertRaises((ValueError, OSError)):
                reuse.paths_for(self.config, self.config_path)
        self.config = original
        target = self.root / 'derived'
        target.symlink_to(self.root / 'donor', target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            reuse.paths_for(self.config, self.config_path)
        target.unlink()
        target.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            reuse.paths_for(self.config, self.config_path)
        self.assertFalse((self.root / 'receipt').exists())

    def test_private_parent_and_stage_disjointness_are_required(self):
        parent = self.root / 'public'
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        self.config['output']['prefix'] = str(parent / 'derived')
        with self.assertRaises(ValueError):
            reuse.paths_for(self.config, self.config_path)
        self.assertEqual(list(parent.iterdir()), [])
        paths = dict(prefix=self.root / 'derived', receipt=self.root / 'receipt',
                     inputs=[self.root / '.transport-repackage-fixed'])
        with mock.patch.object(reuse.secrets, 'token_hex', return_value='fixed'):
            with mock.patch.object(Path, 'mkdir', side_effect=AssertionError('premature stage creation')) as mkdir:
                with self.assertRaises(ValueError):
                    reuse.create_stage(paths)
                mkdir.assert_not_called()
        parent.chmod(0o700)

    def test_storage_reserve_full_restore_and_output_bounds(self):
        usage = SimpleNamespace(free=reuse.RESERVE + 2 * reuse.OUTPUT_BUDGET)
        with mock.patch.object(reuse.os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096)):
            with mock.patch.object(reuse.shutil, 'disk_usage', return_value=usage):
                self.assertEqual(len(reuse.storage_guard([self.root], 1000)), 1)
                usage.free -= 1
                with self.assertRaises(ValueError):
                    reuse.storage_guard([self.root], 1000)
        with mock.patch.object(reuse.shutil, 'disk_usage', side_effect=AssertionError('budget must fail first')):
            with self.assertRaises(ValueError):
                reuse.storage_guard([self.root], reuse.OUTPUT_BUDGET)
        with mock.patch.object(reuse.os, 'statvfs', return_value=SimpleNamespace(f_frsize=65537)):
            with self.assertRaises(ValueError):
                reuse.storage_guard([self.root], 1000)

    def test_physical_and_logical_output_budgets_are_independent(self):
        directory = self.root / 'outputs'
        directory.mkdir(mode=0o700)
        (directory / 'tiny').write_bytes(b'x')
        for size, blocks in ((1, reuse.OUTPUT_BUDGET // 512 + 1), (reuse.OUTPUT_BUDGET + 1, 0)):
            metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=size, st_blocks=blocks)
            with mock.patch.object(Path, 'stat', return_value=metadata):
                with self.assertRaises(ValueError):
                    reuse.output_usage([directory])

    def test_mock_derivation_uses_old_donor_and_new_stage_then_checks_publication(self):
        state = self.state()
        before = reuse.bundle_snapshot(state['paths']['donor'], self.config['donor']['install_sha256'],
                                       self.config['donor']['native_sha256'])[0]
        with mock.patch.object(reuse, 'prepare', return_value=state), mock.patch.object(reuse, 'unchanged'):
            with mock.patch.object(reuse, 'complete_stage', side_effect=self.fake_stage):
                with mock.patch.object(reuse, 'verify_install', return_value={'status': 'INSTALLATION_RECONSTRUCTION_CHECKED'}) as verify:
                    result = reuse.repackage(self.config_path, state['config_sha256'])
        self.assertEqual(result['status'], 'DERIVED_RUNTIME_NATIVE_REUSED')
        self.assertEqual(result['native_build'], 'UNPERFORMED')
        self.assertEqual(verify.call_args_list[0].args[1], state['old'])
        self.assertEqual(verify.call_args_list[1].args[1], state['new'])
        self.assertEqual(verify.call_args_list[2].args[0], state['paths']['prefix'])
        self.assertEqual((state['paths']['prefix'] / 'bin/transport_native').read_bytes(), self.native)
        self.assertEqual(reuse.bundle_snapshot(state['paths']['donor'], self.config['donor']['install_sha256'],
                         self.config['donor']['native_sha256'])[0], before)
        self.assertEqual(json.loads((state['paths']['receipt'] / 'receipt.json').read_bytes()), result)

    def test_failed_stage_retains_receipt_and_never_publishes(self):
        state = self.state()
        with mock.patch.object(reuse, 'prepare', return_value=state), mock.patch.object(reuse, 'unchanged'):
            with mock.patch.object(reuse, 'verify_install', return_value={}):
                with mock.patch.object(reuse, 'complete_stage', side_effect=ValueError('stage failure')):
                    with mock.patch.object(reuse, 'atomic_publish') as publish:
                        with self.assertRaises(ValueError):
                            reuse.repackage(self.config_path, state['config_sha256'])
                        publish.assert_not_called()
        receipt = json.loads((state['paths']['receipt'] / 'receipt.json').read_bytes())
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertEqual(receipt['artifact_reuse'], 'NOT_ESTABLISHED')
        self.assertTrue(Path(receipt['stage']).is_dir())
        self.assertFalse(state['paths']['prefix'].exists())

    def test_failed_published_readback_retains_output_and_failed_receipt(self):
        state = self.state()
        with mock.patch.object(reuse, 'prepare', return_value=state), mock.patch.object(reuse, 'unchanged'):
            with mock.patch.object(reuse, 'complete_stage', side_effect=self.fake_stage):
                with mock.patch.object(reuse, 'verify_install', side_effect=[{}, {}, ValueError('published readback')]):
                    with self.assertRaises(ValueError):
                        reuse.repackage(self.config_path, state['config_sha256'])
        receipt = json.loads((state['paths']['receipt'] / 'receipt.json').read_bytes())
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertTrue(receipt['published'])
        self.assertTrue(state['paths']['prefix'].is_dir())
        self.assertEqual(receipt['artifact_reuse'], 'NOT_ESTABLISHED')


if __name__ == '__main__':
    unittest.main()
