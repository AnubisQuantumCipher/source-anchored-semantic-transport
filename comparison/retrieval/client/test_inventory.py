"""Portable evidence-reader controls; no retrieval client or native bundle runs.

Set INVENTORY_HELD_UTILITY_SHA256 to the independently reviewed utility digest.
The loader verifies that held digest before executing prepare_receipt.py. Every
fixture and any receipt write lives inside TemporaryDirectory; ZIP members are
never extracted. These tests establish utility readback behavior only.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def held_utility():
    expected = os.environ.get('INVENTORY_HELD_UTILITY_SHA256', '')
    if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('Reviewed INVENTORY_HELD_UTILITY_SHA256 is required')
    path = HERE / 'prepare_receipt.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Held utility source pin mismatch')
    name = 'independently_pinned_inventory_utility'
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def zip_bytes(entries, mode=stat.S_IFREG | 0o444):
    if len(entries) > 2049:
        raise ValueError('Test fixture member bound')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED,
                         allowZip64=False) as archive:
        for name, raw in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = mode << 16
            archive.writestr(info, raw)
    return output.getvalue()


def origins_bytes(entries):
    members = {name: {'path': '/recorded-only/' + name, **pin(raw)}
               for name, raw in entries}
    return canonical({'schema': 'transport/adaptive-client-observation-origins/1',
                      'members': members})


def changed_flags(raw, flag):
    output = bytearray(raw)
    local = raw.find(b'PK\x03\x04')
    central = raw.find(b'PK\x01\x02')
    if local < 0 or central < 0:
        raise ValueError('Test ZIP header absent')
    output[local + 6:local + 8] = struct.pack('<H', flag)
    output[central + 8:central + 10] = struct.pack('<H', flag)
    return bytes(output)


def process_fixture():
    entries = []
    for run in ('client-02', 'client-03', 'postdispatch-01'):
        stdout, stderr = ('retained ' + run).encode('ascii'), b''
        process = {'argv': ['/recorded-only/NEVER_EXECUTED'], 'exit_code': 0,
                   'stdout': pin(stdout), 'stderr': pin(stderr)}
        entries.extend([(run + '/probe.json', canonical(process)),
                        (run + '/probe.stdout', stdout),
                        (run + '/probe.stderr', stderr)])
    return entries


class InventoryCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.utility = held_utility()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='client-inventory-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.addCleanup(setattr, self.utility, 'HERE', self.utility.HERE)
        self.utility.HERE = self.root
        (self.root / 'evidence').mkdir()

    def bundle(self, entries=None, archive=None, origins=None):
        selected = [('safe/item.bin', b'original')] if entries is None else entries
        archive_raw = zip_bytes(selected) if archive is None else archive
        origin_raw = origins_bytes(selected) if origins is None else origins
        (self.root / 'evidence' / 'observations.zip').write_bytes(archive_raw)
        (self.root / 'evidence' / 'origins.json').write_bytes(origin_raw)
        return archive_raw, origin_raw

    def reject_bundle(self, entries=None, archive=None, origins=None):
        self.bundle(entries, archive, origins)
        with self.assertRaises((ValueError, zipfile.BadZipFile,
                                NotImplementedError, RuntimeError)):
            self.utility.observations()

    def inventory_fixture(self):
        entries = process_fixture()
        checked = self.bundle(entries)
        source_raw = {}
        for name in self.utility.SOURCES:
            raw = ('fixture bytes for ' + name).encode('ascii')
            (self.root / name).write_bytes(raw)
            source_raw[name] = raw
        return entries, source_raw, checked


class ObservationTests(InventoryCase):
    def test_raw_members_origins_and_checked_inputs_agree(self):
        entries = [('safe/plain.bin', b'\x00\xff\x80'),
                   ('safe/unicode.txt', 'café 終'.encode('utf-8'))]
        archive, origins = self.bundle(entries)
        contents, total, checked = self.utility.observations()
        self.assertEqual(contents, dict(entries))
        self.assertEqual(total, sum(len(raw) for _, raw in entries))
        self.assertEqual(checked, {'evidence/observations.zip': archive,
                                  'evidence/origins.json': origins})
        self.assertFalse((self.root / 'safe').exists())

    def test_valid_crc_payload_with_stale_origin_hash_is_rejected(self):
        original = [('safe/item.bin', b'original')]
        forged = [('safe/item.bin', b'forged!!')]
        self.reject_bundle(forged, origins=origins_bytes(original))

    def test_raw_payload_corruption_is_rejected(self):
        archive = zip_bytes([('safe/item.bin', b'unique_payload')])
        self.assertEqual(archive.count(b'unique_payload'), 1)
        damaged = archive.replace(b'unique_payload', b'broken_payload')
        self.reject_bundle(archive=damaged)

    def test_origin_hash_and_length_tampering_is_rejected(self):
        entries = [('safe/item.bin', b'original')]
        for field, value in [('sha256', '0' * 64), ('bytes', 99), ('bytes', True)]:
            with self.subTest(field=field, value=value):
                origins = json.loads(origins_bytes(entries))
                origins['members']['safe/item.bin'][field] = value
                self.reject_bundle(entries, origins=canonical(origins))

    def test_origins_closed_shape_and_missing_member_are_rejected(self):
        entries = [('safe/item.bin', b'original')]
        mutations = [lambda d: d.update(extra='hidden'),
                     lambda d: d.update(schema='unsupported'),
                     lambda d: d['members']['safe/item.bin'].update(extra='hidden'),
                     lambda d: d['members'].update({'absent.bin': {
                         'path': '/not-opened', **pin(b'absent')}})]
        for change in mutations:
            with self.subTest(change=mutations.index(change)):
                origins = json.loads(origins_bytes(entries))
                change(origins)
                self.reject_bundle(entries, origins=canonical(origins))

    def test_archive_member_without_origin_is_rejected(self):
        self.reject_bundle([('safe/item.bin', b'original')], origins=canonical({
            'schema': 'transport/adaptive-client-observation-origins/1',
            'members': {'different.bin': {'path': '/data', **pin(b'original')}}}))

    def test_truncated_zip_is_rejected(self):
        archive = zip_bytes([('safe/item.bin', b'original')])
        for length in (0, 4, len(archive) - 10):
            with self.subTest(length=length):
                self.reject_bundle(archive=archive[:length])

    def test_unsafe_member_paths_are_rejected(self):
        names = ['/absolute', '../escape', 'dir/../escape', './entry',
                 'dir//entry', 'dir/./entry', 'dir\\entry', 'two words',
                 'café', 'a/b/c/d/e/f/g', 'x' * 257]
        for name in names:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.utility.member_name(name)

    def test_zip_symlink_entry_is_rejected(self):
        entries = [('safe/link', b'/outside/data')]
        self.reject_bundle(entries,
                           archive=zip_bytes(entries, stat.S_IFLNK | 0o777))

    def test_unsupported_zip_flags_are_rejected(self):
        entries = [('safe/item.bin', b'original')]
        archive = zip_bytes(entries)
        for flags in (1, 8, 32, 64, 2048):
            with self.subTest(flags=flags):
                self.reject_bundle(entries, archive=changed_flags(archive, flags))

    def test_nul_in_original_zip_name_is_not_silently_normalized(self):
        archive = zip_bytes([('abcdef', b'original')])
        self.assertEqual(archive.count(b'abcdef'), 2)
        changed = archive.replace(b'abcdef', b'abc\x00ef')
        self.reject_bundle([('abc', b'original')], archive=changed)

    def test_duplicate_archive_names_are_rejected(self):
        entries = [('first', b'x'), ('other', b'y')]
        archive = zip_bytes(entries).replace(b'other', b'first')
        self.reject_bundle([('first', b'x')], archive=archive)

    def test_member_byte_bound_is_enforced(self):
        entries = [('safe/item.bin', b'x' * 131073)]
        self.reject_bundle(entries)

    def test_archive_member_count_is_bounded(self):
        entries = [(f'm{i}', b'') for i in range(2049)]
        self.reject_bundle(entries)

    def test_symlink_evidence_file_is_not_followed(self):
        archive, _ = self.bundle()
        target = self.root / 'outside.zip'
        target.write_bytes(archive)
        path = self.root / 'evidence' / 'observations.zip'
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.utility.observations()

    def test_oversized_file_is_rejected_before_archive_parse(self):
        self.bundle()
        path = self.root / 'evidence' / 'observations.zip'
        with path.open('wb') as stream:
            stream.truncate(self.utility.MAX_FILE + 1)
        with self.assertRaises(ValueError):
            self.utility.observations()


class JsonAndReceiptTests(InventoryCase):
    def test_duplicate_json_keys_are_rejected_at_each_level(self):
        for raw in (b'{"a":1,"a":2}', b'{"outer":{"a":1,"a":2}}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    self.utility.json_value(raw)

    def test_json_depth_guard_accepts_sixteen_and_refuses_seventeen(self):
        shallow = b'[' * 16 + b'0' + b']' * 16
        deep = b'[' * 17 + b'0' + b']' * 17
        self.assertIsInstance(self.utility.json_value(shallow), list)
        with self.assertRaises(ValueError):
            self.utility.json_value(deep)

    def test_json_node_guard_refuses_excess_flat_array(self):
        raw = b'[' + b','.join([b'0'] * 65537) + b']'
        with self.assertRaises(ValueError):
            self.utility.json_value(raw)

    def test_json_braces_and_escaped_quotes_inside_strings_are_data(self):
        value = {'text': 'escaped quote " and [braces] {data} \\'}
        self.assertEqual(self.utility.json_value(canonical(value)), value)

    def test_json_framing_and_nonfinite_constants_are_rejected(self):
        for raw in (b'{', b']', b'"unterminated', b'NaN', b'Infinity'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    self.utility.json_value(raw)

    def test_process_stream_pin_tampering_is_rejected(self):
        entries = process_fixture()
        contents = dict(entries)
        self.assertEqual(self.utility.process_records(contents), {
            'client-02': 1, 'client-03': 1, 'postdispatch-01': 1})
        contents['client-02/probe.stdout'] = b'forged'
        with self.assertRaises(ValueError):
            self.utility.process_records(contents)

    def test_missing_run_or_stream_is_rejected(self):
        original = dict(process_fixture())
        variants = [{k:v for k,v in original.items()
                     if not k.startswith('postdispatch-01/')},
                    {k:v for k,v in original.items() if k != 'client-02/probe.stderr'}]
        for contents in variants:
            with self.subTest(members=len(contents)):
                with self.assertRaises(ValueError):
                    self.utility.process_records(contents)

    def test_source_inventory_is_canonical_and_reproducible(self):
        entries, source_raw, evidence = self.inventory_fixture()
        first = self.utility.derived()
        second = self.utility.derived()
        self.assertEqual(first, second)
        value = json.loads(first)
        self.assertEqual(first, canonical(value))
        expected = {name: pin(raw) for name, raw in source_raw.items()}
        expected.update({'evidence/observations.zip': pin(evidence[0]),
                         'evidence/origins.json': pin(evidence[1])})
        self.assertEqual(value['files'], expected)
        self.assertEqual(value['inventory_bytes'], sum(p['bytes'] for p in expected.values()))
        self.assertEqual(value['observation_members'], len(entries))
        self.assertEqual(value['observation_expanded_bytes'],
                         sum(len(raw) for _, raw in entries))
        self.assertEqual(value['retained_process_records'], {
            'client-02': 1, 'client-03': 1, 'postdispatch-01': 1})
        self.assertEqual(value['status'], 'TESTED_DEVELOPMENT_NOT_ACCEPTED')

    def test_inventory_uses_validated_evidence_snapshot_without_reread(self):
        _, _, evidence = self.inventory_fixture()
        original_read = self.utility.read
        counts = {'observations.zip': 0, 'origins.json': 0}

        def changed_on_second_read(path):
            if path.name in counts:
                counts[path.name] += 1
                if counts[path.name] > 1:
                    return b'changed after validated snapshot'
            return original_read(path)

        with patch.object(self.utility, 'read', side_effect=changed_on_second_read):
            value = json.loads(self.utility.derived())
        self.assertEqual(counts, {'observations.zip': 1, 'origins.json': 1})
        self.assertEqual(value['files']['evidence/observations.zip'], pin(evidence[0]))
        self.assertEqual(value['files']['evidence/origins.json'], pin(evidence[1]))

    def test_source_change_changes_inventory_identity(self):
        self.inventory_fixture()
        first = json.loads(self.utility.derived())
        (self.root / 'entry.py').write_bytes(b'changed fixture, never executed')
        second = json.loads(self.utility.derived())
        self.assertNotEqual(first['files']['entry.py'], second['files']['entry.py'])
        self.assertEqual(first['files']['evidence/observations.zip'],
                         second['files']['evidence/observations.zip'])

    def test_receipt_create_only_and_check_detects_source_change(self):
        self.inventory_fixture()
        with patch.object(sys, 'argv', ['prepare_receipt.py']):
            with contextlib.redirect_stdout(io.StringIO()):
                self.utility.main()
        raw = (self.root / 'receipt.json').read_bytes()
        self.assertEqual(raw, self.utility.derived())
        with patch.object(sys, 'argv', ['prepare_receipt.py', '--check']):
            with contextlib.redirect_stdout(io.StringIO()):
                self.utility.main()
        (self.root / 'entry.py').write_bytes(b'changed fixture, never executed')
        with patch.object(sys, 'argv', ['prepare_receipt.py', '--check']):
            with self.assertRaises(ValueError):
                self.utility.main()
        with patch.object(sys, 'argv', ['prepare_receipt.py']):
            with self.assertRaises(FileExistsError):
                self.utility.main()
        self.assertEqual((self.root / 'receipt.json').read_bytes(), raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
