"""Portable source preparation controls. Compiler/native/process dispatch is forbidden."""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from sentinel_v1 import native_build as build


def denied(*_args, **_kwargs):
    raise RuntimeError('no native/compiler/process dispatch in preparation controls')


subprocess.Popen = denied
os.execv = denied


def archive(value):
    return gzip.compress(json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), mtime=0)


class NativePreparation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repository'
        self.root.mkdir(mode=0o700)
        names = set(build.OVERRIDES.get(name, name) for name in build.SOURCES)
        names.update(build.PREPARERS)
        names.update(build.VERSION + 'controller/' + name for name in build.CONTROLLERS)
        names.update(build.VERSION + name for name in
                     ('literal-fixtures.json.gz', 'evidence.json.gz', 'proof-roster.json', 'manifest.json'))
        self.held = hashlib.sha256((ROOT / build.VERSION / 'manifest.json').read_bytes()).hexdigest()
        for name in sorted(names):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.out = Path(self.temporary.name) / 'new-overlay'

    def test_positive_exact_sources_and_all62_fixtures(self):
        result = build.check_package(self.root, self.held)
        self.assertEqual(result['status'], 'PINNED_PACKAGE_CHECKED_UNQUALIFIED')
        prepared = build.prepare_overlay(self.root, self.out, self.held)
        manifest = json.loads((self.root / build.VERSION / 'manifest.json').read_bytes())
        self.assertEqual(prepared['status'], 'SOURCE_PREPARED_UNQUALIFIED')
        for name, expected in manifest['sources'].items():
            self.assertEqual(build.pin((self.out / 'source' / name).read_bytes()), expected)
        for name, expected in manifest['oracles'].items():
            self.assertEqual(build.pin((self.out / 'oracles' / name).read_bytes()), expected)
        self.assertEqual(len(manifest['oracles']), 62)
        self.assertEqual(build.pin((self.out / 'proof-roster.json').read_bytes()),
                         manifest['proof_roster'])
        self.assertEqual((self.out / 'source/sentinel_native/sentinel_policy.ads').stat().st_mode & 0o222, 0)
        self.assertEqual(prepared['execution_authority'], 'NONE')

    def test_wrong_held_hash_and_shared_source_change_refuse_before_creation(self):
        with self.assertRaises(ValueError):
            build.prepare_overlay(self.root, self.out, '0' * 64)
        self.assertFalse(self.out.exists())
        target = self.root / 'tools/document_build/capture.py'
        target.write_bytes(target.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            build.prepare_overlay(self.root, self.out, self.held)
        self.assertFalse(self.out.exists())

    def test_missing_input_and_nonregular_refuse(self):
        target = self.root / build.VERSION / 'sentinel_policy.ads'
        target.unlink()
        with self.assertRaises((ValueError, OSError)):
            build.prepare_overlay(self.root, self.out, self.held)
        target.mkdir()
        with self.assertRaises(ValueError):
            build.prepare_overlay(self.root, self.out, self.held)
        self.assertFalse(self.out.exists())

    def test_leaf_and_parent_alias_refuse(self):
        target = self.root / build.VERSION / 'sentinel_policy.ads'
        saved = self.root / 'held-original.ads'
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaises((ValueError, OSError)):
            build.prepare_overlay(self.root, self.out, self.held)
        target.unlink()
        saved.rename(target)
        parent = self.root / build.VERSION / 'controller'
        parent.rename(parent.with_name('saved-controller'))
        parent.symlink_to(parent.with_name('saved-controller'), target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            build.prepare_overlay(self.root, self.out, self.held)
        self.assertFalse(self.out.exists())

    def test_closed_manifest_missing_unknown_and_unsafe_targets_refuse(self):
        target = self.root / build.VERSION / 'manifest.json'
        original = json.loads(target.read_bytes())
        changes = [dict(original, unexpected=True)]
        for name in ('missing', '../unsafe'):
            item = json.loads(json.dumps(original))
            if name == 'missing':
                item['sources'].pop(build.SOURCES[0])
            else:
                item['sources'][name] = item['sources'][build.SOURCES[0]]
            changes.append(item)
        for item in changes:
            raw = build.json_bytes(item)
            target.write_bytes(raw)
            held = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                build.prepare_overlay(self.root, self.out, held)
            self.assertFalse(self.out.exists())

    def test_boolean_empty_pin_refuses_even_when_manifest_is_re_pinned(self):
        target = self.root / build.VERSION / 'manifest.json'
        manifest = json.loads(target.read_bytes())
        self.assertEqual(manifest['evidence']['pure-checks.stderr']['bytes'], 0)
        for value in (False, 0.0):
            manifest['evidence']['pure-checks.stderr']['bytes'] = value
            raw = build.json_bytes(manifest)
            target.write_bytes(raw)
            with self.assertRaises(ValueError):
                build.prepare_overlay(self.root, self.out, hashlib.sha256(raw).hexdigest())
            self.assertFalse(self.out.exists())

    def test_compressed_expanded_and_per_file_bounds(self):
        packed = (self.root / build.VERSION / 'literal-fixtures.json.gz').read_bytes()
        value = json.loads(gzip.decompress(packed))
        missing = dict(value, items=dict(value['items']))
        missing['items'].pop(build.ORACLES[0])
        unsafe = dict(value, items=dict(value['items']))
        unsafe['items']['../escape'] = ''
        changed = dict(value, items=dict(value['items']))
        changed['items'][build.ORACLES[0]] = base64.b64encode(b'X' * (build.ORACLE_FILE_CAP + 1)).decode()
        invalid = dict(value, items=dict(value['items']))
        invalid['items'][build.ORACLES[0]] = '#'
        for raw in (b'not gzip', archive(invalid), b'X' * (build.ARCHIVE_CAP + 1),
                    archive(missing), archive(unsafe),
                    archive(changed), gzip.compress(b' ' * (build.JSON_CAP + 1), mtime=0)):
            with self.assertRaises(ValueError):
                build.decode_oracles(raw)

    def test_aggregate_preparation_budget_refuses_bounded_individual_sources(self):
        _manifest, data = build.checked_inputs(self.root, self.held)
        bounded = b' ' * build.SOURCE_CAP
        data['sources'] = {name: bounded for name in build.SOURCES}
        with self.assertRaises(ValueError):
            build.payloads(data)
        self.assertFalse(self.out.exists())

    def test_existing_and_non_tmpfs_outputs_refuse(self):
        self.out.mkdir()
        with self.assertRaises(ValueError):
            build.prepare_overlay(self.root, self.out, self.held)
        outside = Path('/tmp') / ('sentinel-output-must-not-exist-' + self.root.parent.name)
        self.assertFalse(outside.exists())
        with self.assertRaises(ValueError):
            build.prepare_overlay(self.root, outside, self.held)
        self.assertFalse(outside.exists())

    def test_fixed_commands_and_prepared_tamper_refusal(self):
        prepared = build.prepare_overlay(self.root, self.out, self.held)
        for mode in ('policy', 'wire'):
            command = build.qualification_command(prepared, mode, self.root, self.root, self.held)
            self.assertEqual(command[:5], ['/usr/bin/python3', '-I', '-S', '-B', '-Werror'])
            self.assertIn('--source-root', command)
            self.assertIn('--toolchain-root', command)
        with self.assertRaises(ValueError):
            build.qualification_command(prepared, 'arbitrary', self.root, self.root, self.held)
        forged = json.loads(json.dumps(prepared))
        first = next(iter(forged['files'].values()))
        first['bytes'] = float(first['bytes'])
        with self.assertRaises(ValueError):
            build.qualification_command(forged, 'policy', self.root, self.root, self.held)
        target = self.out / 'source/sentinel_native/sentinel_policy.ads'
        target.chmod(0o600)
        target.write_bytes(target.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            build.qualification_command(prepared, 'policy', self.root, self.root, self.held)

    def test_jointly_forged_report_and_payload_refuse_against_held_package(self):
        prepared = build.prepare_overlay(self.root, self.out, self.held)
        target = self.out / 'source/tools/build_sentinel_policy.py'
        target.chmod(0o600)
        target.write_bytes(b'raise RuntimeError("forged builder must not execute")\n')
        prepared['files']['source/tools/build_sentinel_policy.py'] = build.pin(target.read_bytes())
        record = self.out / 'preparation.json'
        record.chmod(0o600)
        record.write_bytes(build.json_bytes(prepared))
        with self.assertRaisesRegex(ValueError, 'caller-held package'):
            build.qualification_command(prepared, 'policy', self.root, self.root, self.held)
        with self.assertRaisesRegex(ValueError, 'caller-held manifest SHA'):
            build.qualification_command(prepared, 'policy', self.root, self.root, '0' * 64)

    def test_malformed_prepared_records_refuse_before_serialization(self):
        prepared = build.prepare_overlay(self.root, self.out, self.held)
        malformed = json.loads(json.dumps(prepared))
        malformed['files'] = {str(index): {} for index in range(161)}
        invalid_pin = json.loads(json.dumps(prepared))
        first = next(iter(invalid_pin['files']))
        invalid_pin['files'][first] = {'bytes': 0, 'sha256': '0' * 64, 'extra': None}
        for value in (dict(prepared, extra=None), malformed, invalid_pin,
                      dict(prepared, out='X' * 4097)):
            with mock.patch.object(build, 'json_bytes', side_effect=RuntimeError('serializer reached')):
                with self.assertRaises(ValueError):
                    build.qualification_command(value, 'policy', self.root, self.root, self.held)

    def test_cli_check_has_no_output_or_native_dispatch(self):
        arguments = ['native_build.py', '--source-root', str(self.root),
                     '--manifest-sha256', self.held, '--mode', 'check']
        old = sys.argv
        sys.argv = arguments
        try:
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(build.main(), 0)
            self.assertIn('PINNED_PACKAGE_CHECKED_UNQUALIFIED', stdout.getvalue())
        finally:
            sys.argv = old
        self.assertFalse(self.out.exists())


    def test_cli_injected_allocation_failure_refuses_without_large_allocation(self):
        arguments = ['native_build.py', '--source-root', str(self.root),
                     '--manifest-sha256', self.held, '--mode', 'check']
        with mock.patch.object(sys, 'argv', arguments):
            with mock.patch.object(build, 'check_package', side_effect=MemoryError):
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(build.main(), 2)
        self.assertIn('SENTINEL_NATIVE_BUILD_REFUSED:', stderr.getvalue())
        self.assertLessEqual(len(stderr.getvalue()), 4096)
        self.assertFalse(self.out.exists())

    def test_cli_abbreviated_option_refuses(self):
        arguments = ['native_build.py', '--source-r', str(self.root),
                     '--manifest-sha256', self.held, '--mode', 'check']
        with mock.patch.object(sys, 'argv', arguments):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    build.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
