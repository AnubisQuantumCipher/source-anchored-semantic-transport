"""Indexed collection integrity controls; these are not semantic acceptance."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools')); sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import collection as c
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from test_sentinel_meaning import binding


class CollectionControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.decoder = digest(b'independently held synthetic decoder dependency')
        self.rows = []
        for kind in sorted(c.MANDATORY):
            p = self.root / kind; raw = ('inert synthetic ' + kind).encode(); p.write_bytes(raw)
            self.rows.append({'id': kind, 'kind': kind, 'path': p, 'pin': identity(raw)})
        self.binding = binding(b'synthetic source')
        self.path = self.root / 'collection.snc1'

    def packed(self):
        pin = c.pack_file(self.rows, self.binding, self.decoder, self.path)
        return pin, self.path.read_bytes()

    def mutate_header(self, raw, change):
        size = int.from_bytes(raw[4:8], 'big'); header = parse(raw[8:8 + size])
        change(header); changed = canonical(header)
        return b'SNC1' + len(changed).to_bytes(4, 'big') + changed + raw[8 + size:]

    def refused(self, raw, decoder=None):
        p = self.root / 'malformed.snc1'; p.write_bytes(raw)
        with self.assertRaises((SentinelError, ValueError)):
            with c.verified_file(p, digest(raw), decoder or self.decoder):
                self.fail('malformed collection exposed')

    def test_complete_round_trip_and_selected_export(self):
        pin, raw = self.packed()
        with c.verified_file(self.path, pin['sha256'], self.decoder) as (stream, index, body):
            self.assertEqual(index['binding'], self.binding)
            self.assertEqual(index['semantic_completeness'], 'UNPROVEN')
            self.assertEqual(index['execution_authority'], 'NONE')
            for row in self.rows:
                self.assertEqual(c.entry_bytes(stream, index, body, row['id']), row['path'].read_bytes())
            output = self.root / 'exported'
            got = c.export_entry(stream, index, body, 'BASE_ARCHIVE', output)
            expected = next(row for row in self.rows if row['id'] == 'BASE_ARCHIVE')['pin']
            self.assertEqual(got, expected); self.assertEqual(c.file_pin(output, 65536), got)
        self.assertEqual(pin, identity(raw))

    def test_header_negative_controls(self):
        _pin, raw = self.packed()
        mutations = (
            lambda h: h.update(schema='sentinel/document-evidence-collection/99'),
            lambda h: h.update(execution_authority='GRANTED'),
            lambda h: h.update(qualification='QUALIFIED'),
            lambda h: h.update(semantic_completeness='PROVEN'),
            lambda h: h['items'][0].update(offset=True),
            lambda h: h['items'][1].update(offset=0),
            lambda h: h['items'][0].update(id='../escape'),
            lambda h: h['items'][0].update(kind='EXECUTE'),
            lambda h: h['items'][1].update(id=h['items'][0]['id']),
            lambda h: h['items'][0].update(bytes=False),
            lambda h: h.update(payload_bytes=True),
            lambda h: h['items'][0].update(sha256='0' * 64))
        for change in mutations:
            with self.subTest(change=repr(change)): self.refused(self.mutate_header(raw, change))

    def test_missing_entry_truncation_trailing_wrong_decoder(self):
        _pin, raw = self.packed()
        self.refused(raw[:-1]); self.refused(raw + b'x')
        self.refused(raw[:7]); self.refused(b'BAD!' + raw[4:])
        self.refused(raw, digest(b'wrong dependency'))
        self.refused(self.mutate_header(raw, lambda h: h['items'][0].update(kind='CENSUS_BLOCK')))

    def test_payload_and_whole_file_tampering(self):
        pin, raw = self.packed()
        self.refused(raw[:-1] + bytes((raw[-1] ^ 1,)))
        with self.assertRaises(SentinelError):
            with c.verified_file(self.path, digest(b'wrong package'), self.decoder):
                self.fail('wrong whole package accepted')
        self.assertEqual(pin['sha256'], digest(raw))

    def test_authoring_duplicate_missing_changed_source_refuse_before_output(self):
        for mutation in ('duplicate', 'missing', 'pin'):
            rows = deepcopy(self.rows)
            if mutation == 'duplicate': rows.append(deepcopy(rows[0]))
            if mutation == 'missing': rows.pop()
            if mutation == 'pin': rows[0]['pin'] = identity(b'changed')
            output = self.root / mutation
            with self.subTest(mutation=mutation), self.assertRaises(SentinelError):
                c.pack_file(rows, self.binding, self.decoder, output)
            self.assertFalse(output.exists())

    def test_symlink_authoring_and_retrieval_bound(self):
        original = self.rows[0]['path']; link = self.root / 'link'; link.symlink_to(original)
        rows = deepcopy(self.rows); rows[0]['path'] = link
        with self.assertRaises(OSError): c.pack_file(rows, self.binding, self.decoder, self.path)
        pin, _raw = self.packed()
        with c.verified_file(self.path, pin['sha256'], self.decoder) as (stream, index, body):
            with self.assertRaises(SentinelError): c.entry_bytes(stream, index, body, 'BASE_SHARE', 1)
            with self.assertRaises(SentinelError): c.find_entry(index, '/arbitrary/path')
            with self.assertRaises(SentinelError): c.find_entry(index, 'MISSING')

    def test_base_archive_pin_is_not_registry_eight_mib_limit(self):
        row = deepcopy(self.rows[0]); row['kind'] = 'BASE_ARCHIVE'; row['pin']['bytes'] = 8388609
        row['pin']['sha256'] = digest(b'explicitly wrong file contents')
        with self.assertRaisesRegex(SentinelError, 'input differs'):
            c.input_rows([row])


if __name__ == '__main__':
    unittest.main()
