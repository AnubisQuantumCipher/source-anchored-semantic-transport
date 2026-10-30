"""Independent document-profile byte/refusal controls; fixtures stay in tmpfs.

Run only after supplying a pinned TRANSPORT_DOCUMENT_NATIVE.  These are
development controls, not semantic or external-human acceptance evidence.
"""
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('TRANSPORT_DOCUMENT_TEST_SCRATCH',
                               '/dev/shm/transport-document-tests')) / 'document'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as document


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def allocated(root):
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
                        raise ValueError('test inventory bound')
                    pending.append(Path(entry.path))
    raise ValueError('test inventory iteration bound')


def valid_pdf():
    """A deterministic four-page PDF with plain text and bounded comments."""
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [4 0 R 6 0 R 8 0 R 10 0 R] /Count 4 >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for page in range(4):
        stream_id = 5 + page * 2
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
                        '/Resources << /Font << /F1 3 0 R >> >> '
                        '/Contents %d 0 R >>' % stream_id).encode())
        text = ('BT /F1 12 Tf 72 720 Td (Document page %d) Tj ET\n' %
                (page + 1)).encode() + b'% bounded fixture padding\n' * 800
        objects.append(b'<< /Length ' + str(len(text)).encode() +
                       b' >>\nstream\n' + text + b'endstream')
    output = io.BytesIO()
    output.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = [0]
    for index, body in enumerate(objects, 1):
        offsets.append(output.tell())
        output.write(('%d 0 obj\n' % index).encode() + body + b'\nendobj\n')
    xref = output.tell()
    output.write(('xref\n0 %d\n0000000000 65535 f \n' % len(offsets)).encode())
    for offset in offsets[1:]:
        output.write(('%010d 00000 n \n' % offset).encode())
    output.write(('trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' %
                  (len(offsets), xref)).encode())
    return output.getvalue()


def entries_of(path):
    if path.stat().st_size > 2097152:
        raise ValueError('test archive bound')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) > 64:
            raise ValueError('test entry bound')
        return {name: archive.read(name) for name in names}


def write_zip(path, entries, extra=None):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_STORED) as archive:
            for name, raw in entries.items():
                entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, raw)
            if extra is not None:
                entry, raw = extra
                if isinstance(entry, str):
                    entry = zipfile.ZipInfo(entry, (1980, 1, 1, 0, 0, 0))
                    entry.create_system = 3
                    entry.external_attr = 0o100644 << 16
                archive.writestr(entry, raw)


class DocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = Path(os.environ['TRANSPORT_DOCUMENT_NATIVE'])
        cls.native_pin = os.environ['TRANSPORT_DOCUMENT_NATIVE_SHA256']
        if digest(cls.native.read_bytes()) != cls.native_pin:
            raise ValueError('test native pin mismatch')
        SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
        if allocated(SCRATCH) + 8388608 > 67108864:
            raise ValueError('test initial fixture prebudget')
        cls.arena = Path(tempfile.mkdtemp(prefix='run-', dir=SCRATCH))
        cls.binary = bytes(range(256)) * 513
        cls.pdf = valid_pdf()
        cls.source = cls.arena / 'binary.bin'
        cls.source.write_bytes(cls.binary)
        cls.package = cls.arena / 'base'
        document.encode_document(cls.source, cls.package, 'Binary document')
        cls.base_entries = entries_of(cls.package / 'meaning.zip')
        cls.base_share = (cls.package / 'share.txt').read_bytes()

    def setUp(self):
        # Fixed sources are below 262144 bytes and each case creates only its
        # bounded source/package/decoded/negative copies. Reserve their full
        # temporary and retained peak before any case mutation.
        self.assertLessEqual(allocated(SCRATCH) + 8388608, 67108864)
        self.case = self.arena / self._testMethodName
        self.case.mkdir(mode=0o700)
        self.assertEqual(digest(self.native.read_bytes()), self.native_pin)

    def tearDown(self):
        self.assertEqual(digest(self.native.read_bytes()), self.native_pin)
        self.assertEqual(self.source.read_bytes(), self.binary)
        self.assertLessEqual(allocated(SCRATCH), 67108864)

    def pair(self, mutation=None, extra=None, rehash=True):
        entries = copy.deepcopy(self.base_entries)
        manifest = json.loads(entries['manifest.json'])
        if mutation is not None:
            mutation(entries, manifest['body'])
        share = self.base_share
        if rehash:
            package_id = digest(canonical(manifest['body']))
            manifest['package_id'] = package_id
            lines = share.decode().splitlines()
            lines = [('STS1:' + package_id) if line.startswith('STS1:') else
                     ('CRED:' + digest(('STS1:' + package_id).encode()))
                     if line.startswith('CRED:') else line for line in lines]
            share = ('\n'.join(lines) + '\n').encode()
        entries['manifest.json'] = canonical(manifest)
        archive, formula = self.case / 'meaning.zip', self.case / 'share.txt'
        write_zip(archive, entries, extra)
        formula.write_bytes(share)
        return archive, formula

    def refused(self, mutation=None, extra=None, rehash=True, message=None):
        archive, share = self.pair(mutation, extra, rehash)
        output = self.case / 'decoded.bin'
        before = (archive.read_bytes(), share.read_bytes())
        with self.assertRaises(ValueError) as raised:
            document.decode_document(archive, share, output, self.native)
        if message is not None:
            self.assertIn(message, str(raised.exception))
        self.assertFalse(output.exists())
        self.assertEqual((archive.read_bytes(), share.read_bytes()), before)

    def roundtrip(self, raw, name):
        source = self.case / name
        source.write_bytes(raw)
        package = self.case / 'package'
        document.encode_document(source, package, name)
        output = self.case / ('decoded-' + name)
        document.decode_document(package / 'meaning.zip', package / 'share.txt',
                                 output, self.native)
        self.assertEqual(output.read_bytes(), raw)
        self.assertEqual(digest(output.read_bytes()), digest(raw))
        return package

    def test_multiframe_binary_whole_hash_and_native_decode(self):
        package = self.roundtrip(self.binary, 'binary.bin')
        entries = entries_of(package / 'meaning.zip')
        manifest = json.loads(entries['manifest.json'])
        body = manifest['body']
        self.assertEqual(manifest['package_id'], digest(canonical(body)))
        self.assertGreater(len(body['frames']), 1)
        self.assertEqual(body['source']['sha256'], digest(self.binary))
        offset = 0
        for ordinal, frame in enumerate(body['frames']):
            self.assertEqual((frame['ordinal'], frame['offset']), (ordinal, offset))
            self.assertEqual(frame['source_sha256'], digest(
                self.binary[offset:offset + frame['source_bytes']]))
            self.assertEqual(frame['wire_sha256'], digest(entries[frame['entry']]))
            self.assertEqual(frame['wire_bytes'], len(entries[frame['entry']]))
            offset += frame['source_bytes']
        self.assertEqual(offset, len(self.binary))

    def test_empty_document(self):
        self.roundtrip(b'', 'empty.bin')

    def test_valid_multipage_pdf_exact_recovery_and_optional_extraction(self):
        self.assertGreater(len(self.pdf), 65536)
        package = self.roundtrip(self.pdf, 'book.pdf')
        tool = shutil.which('pdftotext')
        if tool is not None:
            run = subprocess.run([tool, str(self.case / 'book.pdf'), '-'],
                                 capture_output=True, timeout=15, check=False)
            (self.case / 'pdftotext.stdout').write_bytes(run.stdout)
            (self.case / 'pdftotext.stderr').write_bytes(run.stderr)
            self.assertEqual(run.returncode, 0)
            for page in range(1, 5):
                self.assertIn(('Document page %d' % page).encode(), run.stdout)
        document.inspect_document(package / 'meaning.zip', package / 'share.txt', self.native)

    def test_selective_span_crosses_frames(self):
        archive, share = self.package / 'meaning.zip', self.package / 'share.txt'
        self.assertEqual(document.read_span(archive, share, 65530, 65550, self.native),
                         self.binary[65530:65550])
        self.assertEqual(document.read_span(archive, share, 0, 0, self.native), b'')
        self.assertEqual(document.read_span(archive, share, len(self.binary) - 7,
                                           len(self.binary), self.native), self.binary[-7:])

    def test_invalid_selective_spans_refuse(self):
        for start, end in ((-1, 2), (5, 4), (0, len(self.binary) + 1)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                document.read_span(self.package / 'meaning.zip', self.package / 'share.txt',
                                   start, end, self.native)

    def test_global_sections_cross_frames_and_include_support(self):
        sections = (
            dict(id='READING', label='Cross-frame source', start=65530, end=65550,
                 dependencies=['SUPPORT']),
            dict(id='SUPPORT', label='Earlier support', start=4, end=10, dependencies=[]),
        )
        package = self.case / 'sections'
        document.encode_document(self.source, package, 'Sections', sections=sections)
        actual = document.read_section(package / 'meaning.zip', package / 'share.txt',
                                       'READING', self.native)
        self.assertEqual(actual, self.binary[4:10] + self.binary[65530:65550])

    def test_overlapping_section_support_is_merged_without_separator(self):
        sections = (dict(id='A', label='Main', start=65530, end=65550, dependencies=['B']),
                    dict(id='B', label='Support', start=65540, end=65560, dependencies=[]))
        package = self.case / 'sections'
        document.encode_document(self.source, package, 'Overlap', sections=sections)
        self.assertEqual(document.read_section(package / 'meaning.zip', package / 'share.txt',
                                               'A', self.native), self.binary[65530:65560])

    def test_cyclic_section_dependencies_refuse(self):
        sections = (dict(id='A', label='A', start=0, end=2, dependencies=['B']),
                    dict(id='B', label='B', start=2, end=4, dependencies=['A']))
        with self.assertRaises(ValueError):
            document.encode_document(self.source, self.case / 'cycle', 'Cycle', sections=sections)

    def test_decode_is_create_only(self):
        output = self.case / 'existing.bin'
        output.write_bytes(b'KEEP')
        with self.assertRaises((ValueError, FileExistsError)):
            document.decode_document(self.package / 'meaning.zip', self.package / 'share.txt',
                                     output, self.native)
        self.assertEqual(output.read_bytes(), b'KEEP')

    def test_swapped_pair_refuses(self):
        other = self.case / 'other.bin'
        other.write_bytes(b'other source')
        document.encode_document(other, self.case / 'other', 'Other')
        with self.assertRaises(ValueError):
            document.decode_document(self.package / 'meaning.zip', self.case / 'other/share.txt',
                                     self.case / 'decoded.bin', self.native)
        self.assertFalse((self.case / 'decoded.bin').exists())

    def test_wire_tamper_refuses(self):
        def mutate(entries, body):
            name = body['frames'][0]['entry']
            entries[name] = b'NOPE' + entries[name][4:]
        self.refused(mutate, message='wire integrity mismatch')

    def test_rehashed_malformed_native_wire_refuses(self):
        def mutate(entries, body):
            frame = body['frames'][0]
            entries[frame['entry']] = b'NOPE' + entries[frame['entry']][4:]
            frame['wire_sha256'] = digest(entries[frame['entry']])
        self.refused(mutate, message='native document refusal')

    def test_frame_source_hash_refuses_after_outer_rehash(self):
        self.refused(lambda _entries, body: body['frames'][0].update(source_sha256='0' * 64),
                     message='recovered frame source integrity mismatch')

    def test_whole_source_hash_refuses_after_outer_rehash(self):
        self.refused(lambda _entries, body: body['source'].update(sha256='0' * 64),
                     message='whole-file SHA256 or length mismatch')

    def test_frame_order_refuses(self):
        self.refused(lambda _entries, body: body['frames'].reverse())

    def test_duplicate_ordinal_refuses(self):
        self.refused(lambda _entries, body: body['frames'][1].update(ordinal=0),
                     message='native document refusal')

    def test_gap_refuses(self):
        self.refused(lambda _entries, body: body['frames'][1].update(offset=65537),
                     message='native document refusal')

    def test_overlap_refuses(self):
        self.refused(lambda _entries, body: body['frames'][1].update(offset=65535),
                     message='native document refusal')

    def test_frame_omission_refuses(self):
        def mutate(entries, body):
            entries.pop(body['frames'].pop()['entry'])
        self.refused(mutate, message='native document refusal')

    def test_missing_frame_entry_refuses(self):
        self.refused(lambda entries, body: entries.pop(body['frames'][0]['entry']))

    def test_unknown_version_refuses(self):
        self.refused(lambda _entries, body: body.update(format='transport/document-zip/999'))

    def test_missing_lexicon_refuses(self):
        self.refused(lambda entries, _body: entries.pop('lexicon.md'))

    def test_unknown_entry_refuses(self):
        self.refused(extra=('unrecognized.bin', b'input is never executed'))

    def test_duplicate_zip_member_refuses(self):
        self.refused(extra=('manifest.json', self.base_entries['manifest.json']))

    def test_unsafe_zip_member_refuses(self):
        self.refused(extra=('../escape', b'NO'))

    def test_symlink_zip_member_refuses(self):
        entry = zipfile.ZipInfo('foreign-link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.refused(extra=(entry, b'/etc/passwd'))

    def test_compressed_entry_refuses(self):
        entry = zipfile.ZipInfo('compressed.bin')
        entry.create_system = 3
        entry.external_attr = 0o100644 << 16
        entry.compress_type = zipfile.ZIP_DEFLATED
        self.refused(extra=(entry, b'x' * 100))

    def test_duplicate_manifest_json_key_refuses(self):
        entries = copy.deepcopy(self.base_entries)
        manifest = json.loads(entries['manifest.json'])
        body = canonical(manifest['body'])
        entries['manifest.json'] = (b'{"body":' + body + b',"body":' + body +
                                    b',"package_id":' + canonical(manifest['package_id']) + b'}')
        archive, share = self.case / 'meaning.zip', self.case / 'share.txt'
        write_zip(archive, entries)
        share.write_bytes(self.base_share)
        with self.assertRaises(ValueError):
            document.decode_document(archive, share, self.case / 'decoded.bin', self.native)
        self.assertFalse((self.case / 'decoded.bin').exists())

    def test_symlink_source_refuses(self):
        source = self.case / 'source-link'
        source.symlink_to(self.source)
        with self.assertRaises(OSError) as raised:
            document.encode_document(source, self.case / 'symlink-source', 'Unsafe')
        self.assertEqual(raised.exception.errno, errno.ELOOP)
        self.assertFalse((self.case / 'symlink-source').exists())
        self.assertEqual(self.source.read_bytes(), self.binary)

    def test_missing_native_dependency_refuses(self):
        with self.assertRaises((ValueError, OSError)):
            document.decode_document(self.package / 'meaning.zip', self.package / 'share.txt',
                                     self.case / 'decoded.bin', self.case / 'absent-native')
        self.assertFalse((self.case / 'decoded.bin').exists())

    def test_truncated_zip_refuses(self):
        archive, share = self.pair()
        archive.write_bytes(archive.read_bytes()[:-17])
        with self.assertRaises(ValueError):
            document.decode_document(archive, share, self.case / 'decoded.bin', self.native)
        self.assertFalse((self.case / 'decoded.bin').exists())

    def test_budget_refusal(self):
        with self.assertRaises(ValueError):
            document.encode_document(self.source, self.case / 'too-small', 'Binary', budget=1)


if __name__ == '__main__':
    unittest.main()
