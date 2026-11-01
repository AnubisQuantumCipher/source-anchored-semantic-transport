"""Derived-reading transport integration, independent of extraction tooling."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('TRANSPORT_DOCUMENT_TEST_SCRATCH',
                               '/dev/shm/transport-document-tests')) / 'reading'
CLI = ROOT / 'tools/transport_document_cli.py'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as document

UNCERTAINTY = ['Supplied deterministic test reading, not an independent extraction audit.',
               'Reading order and semantic completeness remain unproved.',
               'No OCR confidence is inferred from exact transport.']


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def footprint(root):
    pending, total = [root], 0
    for _ in range(8192):
        if not pending:
            return total
        path = pending.pop()
        info = path.lstat()
        total += max(info.st_size, info.st_blocks * 512)
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as iterator:
                for entry in iterator:
                    if len(pending) >= 8192:
                        raise ValueError('reading test inventory bound')
                    pending.append(Path(entry.path))
    raise ValueError('reading test inventory iteration bound')


def authored_pdf(pages):
    kids = b' '.join(('%d 0 R' % (4 + i * 2)).encode() for i in range(len(pages)))
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [' + kids + b'] /Count ' +
               str(len(pages)).encode() + b' >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for index, text in enumerate(pages):
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
                        '/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>' %
                        (5 + index * 2)).encode())
        stream = b'BT /F1 10 Tf 20 720 Td (' + text + b') Tj ET\n'
        objects.append(b'<< /Length ' + str(len(stream)).encode() +
                       b' >>\nstream\n' + stream + b'endstream')
    result, offsets = io.BytesIO(), [0]
    result.write(b'%PDF-1.4\n% deterministic reading transport fixture\n')
    for ordinal, body in enumerate(objects, 1):
        offsets.append(result.tell())
        result.write(('%d 0 obj\n' % ordinal).encode() + body + b'\nendobj\n')
    xref = result.tell()
    result.write(('xref\n0 %d\n0000000000 65535 f \n' % len(offsets)).encode())
    for offset in offsets[1:]:
        result.write(('%010d 00000 n \n' % offset).encode())
    result.write(('trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' %
                  (len(offsets), xref)).encode())
    return result.getvalue()


def fixture():
    pages, segments, offset = [], [], 0
    for index in range(66):
        text = ('Page %03d: ' % (index + 1)).encode() + b'bounded source context ' * 64 + b'\n'
        pages.append(text)
        segments.append(dict(id='P%03d' % index, label='Supplied page %d' % (index + 1),
                             start=offset, end=offset + len(text), kind='page',
                             source_locator={'page': index + 1}))
        offset += len(text)
    source, reading = authored_pdf(pages), b''.join(pages)
    record = dict(schema='transport/reading-view/1', format='pdf',
                  tool_versions={'fixture': 'authored deterministic reading fixture v1'},
                  source_sha256=sha(source), text_sha256=sha(reading), text_bytes=len(reading),
                  segments=segments, uncertainty=list(UNCERTAINTY),
                  coverage={'authored_pages': 66, 'extraction_completeness': 'UNPROVEN'},
                  text_path='reading.txt')
    return source, reading, record


def stored_zip(path, entries):
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in entries.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)


class ReadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = Path(os.environ['TRANSPORT_DOCUMENT_NATIVE'])
        cls.native_pin = os.environ['TRANSPORT_DOCUMENT_NATIVE_SHA256']
        if sha(cls.native.read_bytes()) != cls.native_pin:
            raise ValueError('reading test native pin')
        SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
        if footprint(SCRATCH) + 8388608 > 33554432:
            raise ValueError('reading fixture prebudget')
        cls.arena = Path(tempfile.mkdtemp(prefix='run-', dir=SCRATCH))
        cls.original, cls.reading, cls.record = fixture()
        cls.source = cls.arena / 'book.pdf'
        cls.text = cls.arena / 'reading.txt'
        cls.record_path = cls.arena / 'reading.json'
        cls.source.write_bytes(cls.original)
        cls.text.write_bytes(cls.reading)
        cls.record_path.write_bytes(canonical(cls.record))
        cls.view = {'text_path': cls.text, 'reading_json_path': cls.record_path}
        cls.package = cls.arena / 'package'
        document.encode_document(cls.source, cls.package, 'Two bound views', reading=cls.view)
        with zipfile.ZipFile(cls.package / 'meaning.zip') as archive:
            cls.entries = {name: archive.read(name) for name in archive.namelist()}
        cls.share = (cls.package / 'share.txt').read_bytes()

    def setUp(self):
        self.assertLessEqual(footprint(SCRATCH) + 8388608, 33554432)
        self.assertEqual(sha(self.native.read_bytes()), self.native_pin)
        self.case = self.arena / self._testMethodName
        self.case.mkdir(mode=0o700)

    def tearDown(self):
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.text.read_bytes(), self.reading)
        self.assertEqual(self.record_path.read_bytes(), canonical(self.record))
        self.assertEqual(sha(self.native.read_bytes()), self.native_pin)
        self.assertLessEqual(footprint(SCRATCH), 33554432)

    def pair(self, mutate):
        entries = copy.deepcopy(self.entries)
        manifest = json.loads(entries['manifest.json'])
        body, record = manifest['body'], json.loads(entries['reading.json'])
        mutate(entries, body, record)
        if 'reading.json' in entries:
            entries['reading.json'] = canonical(record)
        for name in body['entries']:
            if name in entries:
                body['entries'][name] = {'bytes': len(entries[name]), 'sha256': sha(entries[name])}
        package_id = sha(canonical(body))
        manifest['package_id'] = package_id
        entries['manifest.json'] = canonical(manifest)
        lines = self.share.decode().splitlines()
        lines = [('STS1:' + package_id) if line.startswith('STS1:') else
                 ('CRED:' + sha(('STS1:' + package_id).encode()))
                 if line.startswith('CRED:') else line for line in lines]
        archive, share = self.case / 'meaning.zip', self.case / 'share.txt'
        stored_zip(archive, entries)
        share.write_bytes(('\n'.join(lines) + '\n').encode())
        return archive, share

    def refused_pair(self, mutate, message):
        archive, share = self.pair(mutate)
        before = (archive.read_bytes(), share.read_bytes())
        output = self.case / 'decoded-reading.txt'
        with self.assertRaisesRegex(ValueError, message):
            document.decode_reading(archive, share, output, self.native)
        self.assertFalse(output.exists())
        self.assertEqual((archive.read_bytes(), share.read_bytes()), before)

    def refused_record(self, mutate, message):
        record = copy.deepcopy(self.record)
        mutate(record)
        path = self.case / 'reading.json'
        path.write_bytes(canonical(record))
        with self.assertRaisesRegex(ValueError, message):
            document.encode_document(self.source, self.case / 'package', 'Bad reading',
                                     reading={'text_path': self.text, 'reading_json_path': path})
        self.assertFalse((self.case / 'package').exists())

    def test_original_and_reading_decode_independently_exactly(self):
        self.assertGreater(len(self.original), 65536)
        self.assertGreater(len(self.reading), 65536)
        original, reading = self.case / 'original.pdf', self.case / 'reading.txt'
        args = self.package / 'meaning.zip', self.package / 'share.txt'
        document.decode_document(*args, original, self.native)
        result = document.decode_reading(*args, reading, self.native)
        self.assertEqual(original.read_bytes(), self.original)
        self.assertEqual(reading.read_bytes(), self.reading)
        self.assertEqual(sha(original.read_bytes()), self.record['source_sha256'])
        self.assertEqual(sha(reading.read_bytes()), self.record['text_sha256'])
        self.assertEqual(result['reading_status'], 'DERIVED_NOT_EXACT_SOURCE')

    def alias_package(self):
        text = b'X' * 65540 + b'\n'
        source = self.case / 'exact.txt'
        source.write_bytes(text)
        record = dict(schema='transport/reading-view/1', format='text',
                      tool_versions={'fixture': 'exact authored source text'},
                      source_sha256=sha(text), text_sha256=sha(text), text_bytes=len(text),
                      segments=[dict(id='LINE', label='Exact source line', start=0, end=len(text),
                                     kind='line', source_locator=dict(line=1, source_start=0,
                                                                      source_end=len(text)))],
                      uncertainty=list(UNCERTAINTY), coverage={'source_bytes': 'ALL'},
                      text_path='reading.txt')
        record_path = self.case / 'alias-reading.json'
        record_path.write_bytes(canonical(record))
        package = self.case / 'alias-package'
        document.encode_document(source, package, 'Exact source alias', reading={
            'text_path': source, 'reading_json_path': record_path})
        return source, text, package

    def test_exact_text_alias_has_one_payload_and_one_native_decode(self):
        source, text, package = self.alias_package()
        archive, share = package / 'meaning.zip', package / 'share.txt'
        with zipfile.ZipFile(archive) as stream:
            entries = stream.namelist()
            body = json.loads(stream.read('manifest.json'))['body']
        self.assertEqual(body['reading']['mode'], 'source-alias')
        self.assertEqual(body['reading']['frames'], body['frames'])
        self.assertFalse(any(name.startswith('reading/frames/') for name in entries))
        with patch.object(document, 'run_native', wraps=document.run_native) as native:
            with document.validated(archive, share, self.native) as (original, _body, _id, _sections):
                reading = original.parent / 'reading.txt'
                self.assertEqual(original.stat().st_ino, reading.stat().st_ino)
                self.assertEqual(reading.read_bytes(), text)
        self.assertEqual(native.call_count, 1)
        output = self.case / 'decoded-alias.txt'
        document.decode_reading(archive, share, output, self.native)
        self.assertEqual(output.read_bytes(), text)
        self.assertEqual(source.read_bytes(), text)

    def test_rehashed_altered_source_alias_descriptor_refuses(self):
        _source, _text, package = self.alias_package()
        with zipfile.ZipFile(package / 'meaning.zip') as stream:
            entries = {name: stream.read(name) for name in stream.namelist()}
        with patch.object(self, 'entries', entries), \
             patch.object(self, 'share', (package / 'share.txt').read_bytes()):
            self.refused_pair(lambda _e, b, _r: b['reading'].update(bytes=b['reading']['bytes'] + 1),
                              'source-alias reading mismatch')

    def test_cross_frame_segment_keeps_locator_hashes_and_uncertainty(self):
        segment = next(s for s in self.record['segments'] if s['start'] < 65536 < s['end'])
        result = document.read_reading_segment(self.package / 'meaning.zip',
                                              self.package / 'share.txt', segment['id'], self.native)
        self.assertEqual(result['data'], self.reading[segment['start']:segment['end']])
        self.assertEqual(result['segment'], segment)
        self.assertEqual(result['source_sha256'], sha(self.original))
        self.assertEqual(result['reading_sha256'], sha(self.reading))
        self.assertEqual(result['uncertainty'], UNCERTAINTY)

    def test_paginated_index_has_complete_partition_and_honest_cursor(self):
        args = self.package / 'meaning.zip', self.package / 'share.txt'
        first = document.list_reading_segments(*args, 0, 64, self.native)
        self.assertEqual(first['segments'], self.record['segments'][:64])
        self.assertEqual((first['next'], first['total']), (64, 66))
        rest = document.list_reading_segments(*args, first['next'], 64, self.native)
        self.assertEqual(rest['segments'], self.record['segments'][64:])
        self.assertIsNone(rest['next'])
        self.assertEqual(first['uncertainty'], UNCERTAINTY)
        self.assertEqual(rest['uncertainty'], UNCERTAINTY)
        for start, count in ((0, 65), (-1, 1), (67, 1), (0, 0)):
            with self.subTest(start=start, count=count), self.assertRaises(ValueError):
                document.list_reading_segments(*args, start, count, self.native)

    def test_missing_record_refuses(self):
        with self.assertRaises((ValueError, OSError)):
            document.encode_document(self.source, self.case / 'package', 'Missing',
                                     reading={'text_path': self.text,
                                              'reading_json_path': self.case / 'missing.json'})
        self.assertFalse((self.case / 'package').exists())

    def test_wrong_source_record_refuses(self):
        self.refused_record(lambda r: r.update(source_sha256='0' * 64), 'different source')

    def test_wrong_text_record_refuses(self):
        self.refused_record(lambda r: r.update(text_sha256='0' * 64), 'reading artifact changed or digest mismatch')

    def test_boolean_source_locator_offsets_refuse_exact_integer_contract(self):
        source = self.case / 'source.txt'
        source.write_bytes(b'AB')
        segments = [dict(id='A', label='A', start=0, end=1, kind='line',
                         source_locator=dict(line=1, source_start=0, source_end=1)),
                    dict(id='B', label='B', start=1, end=2, kind='line',
                         source_locator=dict(line=2, source_start=1, source_end=2))]
        record = dict(schema='transport/reading-view/1', format='text',
                      tool_versions={'fixture': 'exact two-byte source'},
                      source_sha256=sha(b'AB'), text_sha256=sha(b'AB'), text_bytes=2,
                      segments=segments, uncertainty=list(UNCERTAINTY),
                      coverage={'source_bytes': 'ALL'}, text_path='reading.txt')
        changes = ((1, 'source_start', True), (0, 'source_end', True),
                   (0, 'source_start', False))
        for number, (index, field, value) in enumerate(changes):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(record)
                changed['segments'][index]['source_locator'][field] = value
                path = self.case / ('record-%d.json' % number)
                path.write_bytes(canonical(changed))
                package = self.case / ('package-%d' % number)
                with self.assertRaisesRegex(ValueError, 'integer outside document bounds'):
                    document.encode_document(source, package, 'Boolean is not an offset',
                                             reading={'text_path': source, 'reading_json_path': path})
                self.assertFalse(package.exists())
        self.assertEqual(source.read_bytes(), b'AB')

    def test_record_partition_gap_refuses(self):
        self.refused_record(lambda r: r['segments'][1].update(start=r['segments'][1]['start'] + 1),
                            'partition gap or overlap')

    def test_record_partition_overlap_refuses(self):
        self.refused_record(lambda r: r['segments'][1].update(start=r['segments'][1]['start'] - 1),
                            'partition gap or overlap')

    def test_duplicate_segment_id_refuses(self):
        self.refused_record(lambda r: r['segments'][1].update(id=r['segments'][0]['id']),
                            'duplicate reading segment id')

    def test_incomplete_partition_refuses(self):
        self.refused_record(lambda r: r['segments'][-1].update(end=r['segments'][-1]['end'] - 1),
                            'reading partition incomplete')

    def test_empty_uncertainty_refuses(self):
        self.refused_record(lambda r: r.update(uncertainty=[]), 'uncertainty must remain explicit')

    def utf8_refused(self, raw, segments):
        text = self.case / 'invalid-reading.txt'
        text.write_bytes(raw)
        record = copy.deepcopy(self.record)
        record.update(text_bytes=len(raw), text_sha256=sha(raw), segments=segments)
        record_path = self.case / 'reading.json'
        record_path.write_bytes(canonical(record))
        package = self.case / 'invalid-package'
        with patch.object(document, 'run_native', wraps=document.run_native) as native:
            with self.assertRaisesRegex(ValueError, 'reading UTF-8 or segment boundary is invalid'):
                document.encode_document(self.source, package, 'Invalid reading text', reading={
                    'text_path': text, 'reading_json_path': record_path})
        self.assertEqual(native.call_count, 2)
        self.assertFalse(package.exists())
        self.assertEqual(text.read_bytes(), raw)

    def test_invalid_utf8_reading_refuses_after_native_hash_checks(self):
        segments = [dict(id='INVALID', label='Invalid UTF8', start=0, end=1, kind='page',
                         source_locator={'page': 1})]
        self.utf8_refused(b'\xff', segments)

    def test_split_utf8_segment_boundary_refuses_after_native_hash_checks(self):
        segments = [dict(id='HEAD', label='First byte', start=0, end=1, kind='page',
                         source_locator={'page': 1}),
                    dict(id='TAIL', label='Second byte', start=1, end=2, kind='page',
                         source_locator={'page': 2})]
        self.utf8_refused(b'\xc3\xa9', segments)

    def test_rehashed_wrong_source_record_refuses(self):
        self.refused_pair(lambda _e, _b, r: r.update(source_sha256='0' * 64), 'different source')

    def test_rehashed_reading_whole_hash_reaches_recovery_check(self):
        def mutate(_entries, body, record):
            record['text_sha256'] = body['reading']['sha256'] = '0' * 64
        self.refused_pair(mutate, 'whole-file SHA256 or length mismatch')

    def test_rehashed_reading_frame_hash_reaches_recovery_check(self):
        self.refused_pair(lambda _e, b, _r: b['reading']['frames'][0].update(source_sha256='0' * 64),
                          'recovered frame source integrity mismatch')

    def test_rehashed_reading_gap_reaches_native_ledger(self):
        self.refused_pair(lambda _e, b, _r: b['reading']['frames'][1].update(
            offset=b['reading']['frames'][1]['offset'] + 1), 'native document refusal')

    def test_rehashed_reading_overlap_reaches_native_ledger(self):
        self.refused_pair(lambda _e, b, _r: b['reading']['frames'][1].update(
            offset=b['reading']['frames'][1]['offset'] - 1), 'native document refusal')

    def test_missing_reading_frame_refuses(self):
        self.refused_pair(lambda e, b, _r: e.pop(b['reading']['frames'][0]['entry']),
                          'missing or undeclared ZIP entries')

    def test_missing_reading_metadata_refuses(self):
        self.refused_pair(lambda e, _b, _r: e.pop('reading.json'), 'missing ZIP entry')

    def test_unsafe_reading_entry_refuses(self):
        self.refused_pair(lambda e, _b, _r: e.update({'reading/../escape': b'NO'}), 'unsafe ZIP name')

    def test_unknown_segment_and_existing_output_refuse(self):
        args = self.package / 'meaning.zip', self.package / 'share.txt'
        with self.assertRaisesRegex(ValueError, 'unknown reading segment'):
            document.read_reading_segment(*args, 'ABSENT', self.native)
        output = self.case / 'existing.txt'
        output.write_bytes(b'KEEP')
        with self.assertRaisesRegex(ValueError, 'destination already exists'):
            document.decode_reading(*args, output, self.native)
        self.assertEqual(output.read_bytes(), b'KEEP')

    def test_selected_reading_context_limit_is_enforced_after_native_checks(self):
        text = b'A' * 1048577
        path = self.case / 'large-reading.txt'
        path.write_bytes(text)
        record = copy.deepcopy(self.record)
        record.update(text_bytes=len(text), text_sha256=sha(text), segments=[dict(
            id='LARGE', label='Deliberately oversized selection', start=0, end=len(text),
            kind='page', source_locator={'page': 1})])
        rp = self.case / 'reading.json'
        rp.write_bytes(canonical(record))
        package = self.case / 'package'
        document.encode_document(self.source, package, 'Large context',
                                 reading={'text_path': path, 'reading_json_path': rp})
        with self.assertRaisesRegex(ValueError, 'reading segment exceeds context budget'):
            document.read_reading_segment(package / 'meaning.zip', package / 'share.txt',
                                          'LARGE', self.native)
        output = self.case / 'full-reading.txt'
        document.decode_reading(package / 'meaning.zip', package / 'share.txt', output, self.native)
        self.assertEqual(output.read_bytes(), text)

    def command(self, label, arguments):
        runner = ("import sys,json\nclass Deny:\n"
                  " def find_spec(self,name,path=None,target=None):\n"
                  "  if name.split('.')[0] in ('transport_document_media','pytesseract',"
                  "'ocrmypdf','PIL','pypdf','fitz'): raise RuntimeError('EXTRACTION_IMPORT:'+name)\n"
                  "sys.meta_path.insert(0,Deny())\n"
                  "sys.path.insert(0," + repr(str(ROOT / 'tools')) + ")\n"
                  "import transport_document_cli as cli\n"
                  "sys.argv=['document']+json.loads(sys.argv[1])\nraise SystemExit(cli.main())\n")
        argv = ['/usr/bin/python3', '-I', '-S', '-B', '-Werror', '-c', runner, json.dumps(arguments)]
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'TRANSPORT_DOCUMENT_SCRATCH': str(SCRATCH)}
        result = subprocess.run(argv, env=env, capture_output=True, timeout=30, check=False)
        self.assertLessEqual(len(result.stdout), 262144)
        self.assertLessEqual(len(result.stderr), 4096)
        (self.case / (label + '.stdout')).write_bytes(result.stdout)
        (self.case / (label + '.stderr')).write_bytes(result.stderr)
        (self.case / (label + '.argv.json')).write_bytes(canonical(argv))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def test_isolated_cli_uses_declared_runtime_without_media_or_ocr(self):
        common = ['--archive', str(self.package / 'meaning.zip'), '--share',
                  str(self.package / 'share.txt'), '--native', str(self.native)]
        inspected = self.command('inspect', ['inspect'] + common)
        self.assertEqual(inspected['reading']['uncertainty'], UNCERTAINTY)
        self.assertEqual(inspected['reading']['segment_count'], 66)
        self.assertEqual(inspected['reading']['segment_preview'], self.record['segments'][:8])
        self.assertNotIn('segments', inspected['reading'])
        original, reading = self.case / 'original.pdf', self.case / 'reading.txt'
        self.command('decode', ['decode'] + common + ['--out', str(original)])
        self.command('reading', ['reading'] + common + ['--out', str(reading)])
        self.assertEqual(original.read_bytes(), self.original)
        self.assertEqual(reading.read_bytes(), self.reading)
        index = self.command('index', ['reading-index'] + common + ['--start', '64', '--count', '64'])
        self.assertEqual(index['segments'], self.record['segments'][64:])
        selected = self.case / 'segment.txt'
        segment = self.command('segment', ['reading-segment'] + common +
                               ['--id', 'P000', '--out', str(selected)])
        self.assertEqual(selected.read_bytes(), self.reading[:self.record['segments'][0]['end']])
        self.assertEqual(segment['uncertainty'], UNCERTAINTY)
        self.assertEqual(segment['source_sha256'], sha(self.original))
        self.assertEqual(segment['reading_sha256'], sha(self.reading))


if __name__ == '__main__':
    unittest.main()
