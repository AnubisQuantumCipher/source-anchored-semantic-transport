#!/usr/bin/env python3
"""Bounded source-distribution controls; no builds or archived-code execution."""

import copy
import contextlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import transport_source_distribution as distribution
from transport_install_layout import input_names
from transport_install_support import canonical, read_regular, sha

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'DISTRIBUTION.json'
README = 'README-DISTRIBUTION.md'
SOURCE = 'install/SOURCE.json'
DEMO = {'examples/authoring-v1/controller/authoring.json',
        'examples/authoring-v1/controller/source.txt'}
SCRATCH_CAP = 524288


def archive_members(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if len(infos) > 128:
            raise ValueError('test fixture member bound')
        return [(copy.copy(info), archive.read(info)) for info in infos]


def rewritten(raw, updates=None, remove=(), extra=(), reverse=False, comment=b''):
    members = archive_members(raw)
    selected = []
    for info, data in members:
        if info.filename not in remove:
            selected.append((info, (updates or {}).get(info.filename, data)))
    selected.extend(extra)
    if reverse:
        selected.reverse()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for info, data in selected:
            archive.writestr(info, data)
        archive.comment = comment
    return output.getvalue()


def changed_manifest(raw, **updates):
    value = json.loads(dict((info.filename, data) for info, data in archive_members(raw))[MANIFEST])
    value.update(updates)
    return rewritten(raw, {MANIFEST: canonical(value)})


def scratch_bytes(root):
    pending, total, count = [root], 0, 0
    for _ in range(128):
        if not pending:
            return total
        for path in pending.pop().iterdir():
            count += 1
            if count > 256 or path.is_symlink():
                raise ValueError('test scratch traversal bound or link')
            if path.is_dir():
                pending.append(path)
            else:
                total += path.stat().st_size
                if total > SCRATCH_CAP:
                    raise ValueError('test scratch byte budget exceeded')
    raise ValueError('test scratch directory bound')


class SourceDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_raw = read_regular(ROOT / SOURCE, 131072)
        cls.source_pin = sha(cls.source_raw)
        cls.entries = distribution.collect(ROOT, cls.source_pin)
        cls.raw = distribution.pack(cls.entries)
        cls.archive_pin = sha(cls.raw)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='transport-distribution-test-')
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)

    def tearDown(self):
        self.assertLessEqual(scratch_bytes(self.scratch), SCRATCH_CAP)

    def refused(self, raw, source_pin=None, archive_pin=None):
        with self.assertRaises((ValueError, OSError)):
            distribution.inspect_archive(raw, archive_pin or sha(raw), source_pin or self.source_pin)

    def test_collection_is_exact_pinned_installer_source_and_demo(self):
        self.assertEqual(set(self.entries), input_names() | {SOURCE, README} | DEMO)
        self.assertEqual(self.entries[SOURCE], self.source_raw)
        for name, raw in self.entries.items():
            self.assertIs(type(raw), bytes)
            self.assertLessEqual(len(raw), 131072)
            if name != README:
                self.assertEqual(raw, read_regular(ROOT / name, 131072))
        with self.assertRaises((ValueError, OSError)):
            distribution.collect(ROOT, '0' * 64)

    def test_pack_is_deterministic_and_inspection_preserves_payload(self):
        reordered = dict(reversed(list(self.entries.items())))
        self.assertEqual(distribution.pack(reordered), self.raw)
        self.assertEqual(distribution.inspect_archive(self.raw, self.archive_pin, self.source_pin), self.entries)
        self.assertLessEqual(len(self.raw), 1048576)
        members = archive_members(self.raw)
        self.assertLessEqual(len(members), 128)
        self.assertTrue(all(info.compress_type == zipfile.ZIP_STORED for info, _ in members))
        self.assertLessEqual(sum(len(raw) for _, raw in members), 4194304)

    def test_manifest_is_non_circular_and_exact(self):
        manifest = json.loads(dict((info.filename, raw) for info, raw in archive_members(self.raw))[MANIFEST])
        self.assertEqual(set(manifest), {'schema', 'scope', 'source_manifest_sha256', 'files', 'excluded'})
        self.assertEqual(manifest['schema'], 'transport/source-distribution/1')
        self.assertEqual(manifest['scope'], 'PINNED_CODEC_INSTALLER_SOURCE_AND_CONTROLLER_DEMO')
        self.assertEqual(manifest['excluded'], [MANIFEST])
        self.assertEqual(manifest['source_manifest_sha256'], self.source_pin)
        expected = [dict(path=name, bytes=len(raw), sha256=sha(raw))
                    for name, raw in sorted(self.entries.items())]
        self.assertEqual(manifest['files'], expected)

    def test_unpack_preserves_original_source_closure_without_execution(self):
        output = self.scratch / 'unpacked'
        self.assertIs(type(distribution.unpack(self.raw, self.archive_pin, self.source_pin, output)), dict)
        expected = dict(self.entries)
        expected[MANIFEST] = dict((info.filename, raw) for info, raw in archive_members(self.raw))[MANIFEST]
        actual = {path.relative_to(output).as_posix(): read_regular(path, 131072)
                  for path in output.rglob('*') if path.is_file()}
        self.assertEqual(actual, expected)
        source = json.loads(actual[SOURCE])
        self.assertEqual(sha(actual[SOURCE]), self.source_pin)
        self.assertEqual({item['path'] for item in source['files']}, input_names())
        for item in source['files']:
            raw = actual[item['path']]
            self.assertEqual((len(raw), sha(raw)), (item['bytes'], item['sha256']))
        self.assertLessEqual(scratch_bytes(self.scratch), SCRATCH_CAP)

    def test_pack_refuses_missing_extra_and_oversize_payload(self):
        for entries in (dict(self.entries, **{'unexpected.txt': b'x'}),
                        {name: raw for name, raw in self.entries.items() if name != SOURCE},
                        dict(self.entries, **{MANIFEST: b'{}'}),
                        dict(self.entries, **{README: b'x' * 131073})):
            with self.subTest(names=set(entries) - set(self.entries)):
                with self.assertRaises((ValueError, OSError)):
                    distribution.pack(entries)

    def test_pack_checks_count_and_member_bounds_before_hashing(self):
        many = {f'member-{index}': b'x' for index in range(129)}
        cases = [many]
        for name in (README, SOURCE):
            cases.append(dict(self.entries, **{name: b'x' * (distribution.MAX_ENTRY + 1)}))
        with mock.patch.object(distribution, 'sha', side_effect=AssertionError('premature hashing')) as hashed:
            for entries in cases:
                with self.subTest(count=len(entries)):
                    with self.assertRaises(ValueError):
                        distribution.pack(entries)
            hashed.assert_not_called()

    def test_publish_checks_archive_bound_before_hashing(self):
        raw = b'x' * (distribution.MAX_ARCHIVE + 1)
        with mock.patch.object(distribution, 'sha', side_effect=AssertionError('premature hashing')) as hashed:
            with self.assertRaises(ValueError):
                distribution.publish(raw, self.scratch / 'source.zip', self.scratch / 'receipt.json', self.source_pin)
            hashed.assert_not_called()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_archive_member_count_and_member_size_bounds_refuse(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
            for index in range(129):
                archive.writestr(f'entry-{index:03d}', b'')
        self.refused(output.getvalue())
        self.refused(rewritten(self.raw, {README: b'x' * 131073}))

    def test_changed_missing_reordered_and_duplicate_members_refuse(self):
        name = sorted(self.entries)[0]
        duplicate = next((info, raw) for info, raw in archive_members(self.raw) if info.filename == name)
        with self.assertWarns(UserWarning):
            doubled = rewritten(self.raw, extra=[duplicate])
        for raw in (rewritten(self.raw, {name: self.entries[name] + b'\n'}),
                    rewritten(self.raw, remove=(name,)), rewritten(self.raw, reverse=True), doubled):
            with self.subTest(archive_pin=sha(raw)):
                self.refused(raw)

    def test_unsafe_paths_symlink_and_compression_refuse(self):
        for name in ('../escape', '/absolute', 'tools/../escape', 'tools\\escape'):
            with self.subTest(name=name):
                self.refused(rewritten(self.raw, extra=[(zipfile.ZipInfo(name), b'x')]))
        members = archive_members(self.raw)
        link = copy.copy(members[0][0])
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.refused(rewritten(self.raw, remove=(link.filename,), extra=[(link, b'target')]))
        compressed = copy.copy(members[0][0])
        compressed.compress_type = zipfile.ZIP_DEFLATED
        self.refused(rewritten(self.raw, remove=(compressed.filename,), extra=[(compressed, members[0][1])]))

    def test_version_comments_flags_truncation_and_pins_refuse(self):
        flagged = bytearray(self.raw)
        flagged[6:8] = (int.from_bytes(flagged[6:8], 'little') | 1).to_bytes(2, 'little')
        central = flagged.index(b'PK\x01\x02')
        flagged[central + 8:central + 10] = (int.from_bytes(flagged[central + 8:central + 10], 'little') | 1).to_bytes(2, 'little')
        for raw in (changed_manifest(self.raw, schema='transport/source-distribution/999'),
                    rewritten(self.raw, comment=b'not canonical'), bytes(flagged), self.raw[:-1],
                    self.raw + b'trailing', b'not a ZIP', b'x' * 1048577):
            with self.subTest(length=len(raw)):
                self.refused(raw)
        self.refused(self.raw, archive_pin='0' * 64)
        self.refused(self.raw, source_pin='0' * 64)

    def test_forged_source_manifest_cannot_replace_independently_held_pin(self):
        source = json.loads(self.source_raw)
        source['product'] = 'Forged source manifest'
        forged_source = canonical(source)
        members = dict((info.filename, raw) for info, raw in archive_members(self.raw))
        manifest = json.loads(members[MANIFEST])
        manifest['source_manifest_sha256'] = sha(forged_source)
        for item in manifest['files']:
            if item['path'] == SOURCE:
                item.update(bytes=len(forged_source), sha256=sha(forged_source))
        forged = rewritten(self.raw, {SOURCE: forged_source, MANIFEST: canonical(manifest)})
        self.refused(forged, archive_pin=sha(forged))

    def test_manifest_duplicate_fields_boolean_lengths_and_wrong_scope_refuse(self):
        members = dict((info.filename, raw) for info, raw in archive_members(self.raw))
        manifest = json.loads(members[MANIFEST])
        manifest['files'][0]['bytes'] = True
        for raw in (rewritten(self.raw, {MANIFEST: canonical(manifest)}),
                    rewritten(self.raw, {MANIFEST: b'{"schema":"x","schema":"x"}'}),
                    changed_manifest(self.raw, scope='WHOLE_REPOSITORY'),
                    changed_manifest(self.raw, excluded=[])):
            self.refused(raw)

    def test_unpack_validates_before_output_and_never_overwrites(self):
        output = self.scratch / 'output'
        with self.assertRaises((ValueError, OSError)):
            distribution.unpack(self.raw, '0' * 64, self.source_pin, output)
        self.assertFalse(output.exists())
        output.mkdir()
        marker = output / 'marker'
        marker.write_bytes(b'keep')
        with self.assertRaises((ValueError, OSError)):
            distribution.unpack(self.raw, self.archive_pin, self.source_pin, output)
        self.assertEqual(marker.read_bytes(), b'keep')
        self.assertEqual(list(output.iterdir()), [marker])

    def test_low_space_refuses_unpack_and_publish_before_outputs(self):
        output = self.scratch / 'unpacked'
        archive = self.scratch / 'source.zip'
        receipt = self.scratch / 'receipt.json'
        usage = SimpleNamespace(total=1, used=1, free=0)
        with mock.patch.object(distribution.shutil, 'disk_usage', return_value=usage):
            with self.assertRaises((ValueError, OSError)):
                distribution.unpack(self.raw, self.archive_pin, self.source_pin, output)
            with self.assertRaises((ValueError, OSError)):
                distribution.publish(self.raw, archive, receipt, self.source_pin)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_private_parent_is_required_for_each_output(self):
        public = self.scratch / 'public'
        public.mkdir(mode=0o700)
        public.chmod(0o777)
        archive, receipt = self.scratch / 'source.zip', self.scratch / 'receipt.json'
        for archive_path, receipt_path in ((public / 'source.zip', receipt),
                                           (archive, public / 'receipt.json')):
            with self.subTest(archive=str(archive_path), receipt=str(receipt_path)):
                with self.assertRaises(ValueError):
                    distribution.publish(self.raw, archive_path, receipt_path, self.source_pin)
        with self.assertRaises(ValueError):
            distribution.unpack(self.raw, self.archive_pin, self.source_pin, public / 'unpacked')
        self.assertEqual(list(public.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [public])
        public.chmod(0o700)

    def test_relative_paths_are_refused_without_outputs(self):
        with contextlib.chdir(self.scratch):
            cases = ((Path('source.zip'), self.scratch / 'receipt.json'),
                     (self.scratch / 'source.zip', Path('receipt.json')))
            for archive, receipt in cases:
                with self.subTest(archive=str(archive), receipt=str(receipt)):
                    with self.assertRaises(ValueError):
                        distribution.publish(self.raw, archive, receipt, self.source_pin)
            with self.assertRaises(ValueError):
                distribution.unpack(self.raw, self.archive_pin, self.source_pin, Path('unpacked'))
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_headroom_rounds_file_allocations_and_counts_directories(self):
        block, directories = 4096, 2
        sizes = [0, 1, block, block + 1]
        boundary = distribution.RESERVE + 2 * (block + block + 2 * block + directories * block)
        usage = SimpleNamespace(free=boundary)
        with mock.patch.object(distribution.os, 'statvfs', return_value=SimpleNamespace(f_frsize=block)):
            with mock.patch.object(distribution.shutil, 'disk_usage', return_value=usage):
                distribution._headroom(self.scratch, sizes, directories)
                usage.free = boundary - 1
                with self.assertRaises(ValueError):
                    distribution._headroom(self.scratch, sizes, directories)
                usage.free = distribution.RESERVE
                distribution._headroom(self.scratch, [0], 0)
                usage.free -= 1
                with self.assertRaises(ValueError):
                    distribution._headroom(self.scratch, [0], 0)

    def test_headroom_rejects_unbounded_sizes_directories_and_allocation_units(self):
        cases = (([], 0), ([0] * 129, 0), ((0,), 0), ([True], 0), ([-1], 0),
                 ([distribution.MAX_ARCHIVE + 1], 0), ([0], True), ([0], -1), ([0], 129))
        for sizes, directories in cases:
            with self.subTest(sizes=sizes, directories=directories):
                with self.assertRaises(ValueError):
                    distribution._headroom(self.scratch, sizes, directories)
        for block in (0, distribution.MAX_ARCHIVE + 1):
            with self.subTest(block=block):
                with mock.patch.object(distribution.os, 'statvfs', return_value=SimpleNamespace(f_frsize=block)):
                    with self.assertRaises(ValueError):
                        distribution._headroom(self.scratch, [0], 0)

    def test_publish_is_create_only_and_preserves_archive_bytes(self):
        archive = self.scratch / 'source.zip'
        receipt = self.scratch / 'receipt.json'
        self.assertIs(type(distribution.publish(self.raw, archive, receipt, self.source_pin)), dict)
        self.assertEqual(archive.read_bytes(), self.raw)
        before = receipt.read_bytes()
        json.loads(before)
        self.assertLessEqual(scratch_bytes(self.scratch), SCRATCH_CAP)
        with self.assertRaises((ValueError, OSError)):
            distribution.publish(self.raw, archive, receipt, self.source_pin)
        self.assertEqual(archive.read_bytes(), self.raw)
        self.assertEqual(receipt.read_bytes(), before)

    def test_publish_refuses_alias_existing_receipt_and_wrong_source_before_writes(self):
        archive = self.scratch / 'source.zip'
        receipt = self.scratch / 'receipt.json'
        with self.assertRaises((ValueError, OSError)):
            distribution.publish(self.raw, archive, archive, self.source_pin)
        self.assertFalse(archive.exists())
        with self.assertRaises((ValueError, OSError)):
            distribution.publish(self.raw, archive, receipt, '0' * 64)
        self.assertFalse(archive.exists())
        self.assertFalse(receipt.exists())
        receipt.write_bytes(b'keep')
        with self.assertRaises((ValueError, OSError)):
            distribution.publish(self.raw, archive, receipt, self.source_pin)
        self.assertFalse(archive.exists())
        self.assertEqual(receipt.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
