"""Literal extraction controls; no user content and no network."""
import hashlib
import unittest
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import os
import stat
import tempfile
import sysconfig
import zipfile
from unittest.mock import patch
# Only the explicit optional XML dependency is loaded from installed purelib.
if importlib.util.find_spec('defusedxml') is None:
    sys.path.append(os.environ.get('TRANSPORT_DOCUMENT_XML_PATH',
                                   sysconfig.get_paths()['purelib']))
if importlib.util.find_spec('defusedxml') is None:
    if os.environ.get('TRANSPORT_DOCUMENT_REQUIRE_XML') == '1':
        raise RuntimeError('required defusedxml dependency unavailable')
    print('SKIP: optional defusedxml dependency unavailable', file=sys.stderr)
    raise SystemExit(77)
import defusedxml
if defusedxml.__version__ != '0.7.1':
    raise ValueError('test dependency must be defusedxml 0.7.1')
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

SOURCE = Path(__file__).resolve().parents[1] / 'tools/transport_document_media.py'
ROOT = Path(os.environ.get('TRANSPORT_DOCUMENT_TEST_SCRATCH',
                           '/dev/shm/transport-document-tests')) / 'media'



def need(test, message):
    if not test:
        raise ValueError(message)



def check_storage(root):
    pending, total = [root], 0
    for _ in range(4096):
        if not pending:
            need(total + 65536 <= 8388608, 'portable fixture storage cap')
            return
        path = pending.pop()
        info = path.lstat()
        total += max(info.st_size, info.st_blocks * 512)
        need(total + 65536 <= 8388608, 'portable fixture storage cap')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    need(len(pending) < 4096, 'portable fixture entry cap')
                    pending.append(Path(entry.path))
    raise ValueError('portable fixture inventory cap')


def load():
    pin = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('frozen_media', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, pin


def epub(entries=None, spine=None, xhtml=None):
    container = b'<container><rootfiles><rootfile full-path="OPS/book.opf"/></rootfiles></container>'
    opf = b'<package><manifest><item id="a" href="a.xhtml" media-type="application/xhtml+xml"/><item id="b" href="b.xhtml" media-type="application/xhtml+xml"/><item id="i" href="image.bin" media-type="image/png"/></manifest><spine><itemref idref="a"/><itemref idref="b"/></spine></package>'
    if spine is not None:
        opf = spine
    members = [('mimetype', b'application/epub+zip'), ('META-INF/container.xml', container),
               ('OPS/book.opf', opf), ('OPS/a.xhtml', xhtml or b'<html><head><title>HIDDEN_HEAD</title></head><body><p>alpha</p><script>HIDDEN_SCRIPT</script><p>beta</p><img src="image.bin"/></body></html>'),
               ('OPS/b.xhtml', b'<html><body><p>gamma</p></body></html>'),
               ('OPS/image.bin', b'opaque-image-bytes')]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in members + (entries or []):
            archive.writestr(name, data)
    return buffer.getvalue()


def pdf():
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for word in [b'CONTROL FIRST', b'CONTROL SECOND']:
        text = b'BT /F1 12 Tf 20 200 Td (' + word + b') Tj ET\n'
        objects.append(b'<< /Length ' + str(len(text)).encode() + b' >>\nstream\n' + text + b'endstream')
    data, offsets = bytearray(b'%PDF-1.4\n'), [0]
    for number, item in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(number).encode() + b' 0 obj\n' + item + b'\nendobj\n'
    xref = len(data)
    data += b'xref\n0 8\n0000000000 65535 f \n'
    for offset in offsets[1:]:
        data += f'{offset:010d} 00000 n \n'.encode()
    data += b'trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n' + str(xref).encode() + b'\n%%EOF\n'
    return bytes(data)


def negative_cases():
    base = epub()
    end = len(base) - 22
    count = bytearray(base)
    count[end + 8:end + 12] = struct.pack('<HH', 4097, 4097)
    cdsize = bytearray(base)
    cdsize[end + 12:end + 16] = struct.pack('<I', 1048577)
    multidisk = bytearray(base)
    multidisk[end + 4:end + 6] = b'\x01\x00'
    link = io.BytesIO(base)
    with zipfile.ZipFile(link, 'a') as archive:
        info = zipfile.ZipInfo('OPS/link')
        info.create_system, info.external_attr = 3, 0o120777 << 16
        archive.writestr(info, b'a.xhtml')
    return [('path_up', epub([('../escape', b'x')])),
            ('absolute', epub([('/escape', b'x')])),
            ('backslash', epub([('OPS\\escape', b'x')])),
            ('link', link.getvalue()), ('count', bytes(count)),
            ('cdsize', bytes(cdsize)), ('multidisk', bytes(multidisk)),
            ('trailing', base + b'x'), ('truncated', base[:-1]),
            ('entry_bound', epub([('OPS/large', b'x' * 8388609)])),
            ('missing_spine', epub(spine=b'<package><manifest/></package>')),
            ('missing_resource', epub(spine=b'<package><manifest><item id="a" href="missing.xhtml"/></manifest><spine><itemref idref="a"/></spine></package>')),
            ('external_href', epub(spine=b'<package><manifest><item id="a" href="https://example.invalid/a"/></manifest><spine><itemref idref="a"/></spine></package>')),
            ('xxe', epub(xhtml=b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><html>&x;</html>')),
            ('depth', epub(xhtml=b'<a>' * 129 + b'x' + b'</a>' * 129)),
            ('malformed_xml', epub(xhtml=b'<html><body></html>')),
            ('external_doctype', epub(xhtml=b'<!DOCTYPE html SYSTEM "https://example.invalid/dtd"><html/>')),
            ('internal_doctype', epub(xhtml=b'<!DOCTYPE html [<!ENTITY x "expanded">]><html>&x;</html>'))]


def boundary_limits(module):
    limits = []
    with patch.object(module.resource, 'getrlimit', return_value=(123, 456)):
        with patch.object(module.resource, 'setrlimit', side_effect=lambda kind, bound: limits.append(bound)):
            module.tighten_limit(module.resource.RLIMIT_AS, 1000)
    need(limits == [(123, 456)], 'tighter inherited limits preserved')
    with patch.object(module.resource, 'getrlimit', return_value=(module.resource.RLIM_INFINITY,) * 2):
        with patch.object(module.resource, 'setrlimit', side_effect=lambda kind, bound: limits.append(bound)):
            module.tighten_limit(module.resource.RLIMIT_AS, 1000)
    need(limits[-1] == (1000, 1000), 'unlimited inherited bounds tightened')
    return limits


def boundary_cleanup(module):
    actions = []
    class Child:
        pid = 12345
        def wait(self, timeout):
            actions.append('reap')
    with patch.object(module.os, 'getpgid', return_value=12345), patch.object(module.os, 'getsid', return_value=12345):
        with patch.object(module.os, 'killpg', side_effect=lambda pid, number: actions.append(number)):
            with patch.object(module.time, 'sleep'):
                module.stop_process(Child())
    need(actions == [module.signal.SIGTERM, module.signal.SIGKILL, 'reap'], 'stopped leader full group cleanup before reap')
    need(module.pdf_page_count(b'Title: control\nPages: 2\n') == 2, 'unique metadata page count')
    try:
        module.pdf_page_count(b'Pages: 1\nPages: 2\n')
    except module.ExtractionError:
        pass
    else:
        raise ValueError('ambiguous metadata page count accepted')
    closed = []
    class Pipe:
        def close(self):
            closed.append('pipe')
    class Selector:
        def close(self):
            closed.append('selector')
    class Parent:
        stderr = Pipe()
    with patch.object(module, 'stop_process', side_effect=module.ExtractionError('synthetic cleanup refusal')):
        try:
            module.close_tool(Parent(), Selector())
        except module.ExtractionError:
            pass
        else:
            raise ValueError('cleanup refusal was hidden')
    need(closed == ['selector', 'pipe'], 'descriptors close after cleanup refusal')
    return [{'name': 'preserve_tighter_limits', 'PASS': True},
            {'name': 'stopped_leader_group_cleanup_order', 'PASS': True},
            {'name': 'cleanup_failure_closes_descriptors', 'PASS': True},
            {'name': 'ambiguous_page_metadata_refusal', 'PASS': True}]



def mocked_pdf_tool(argv, folder, label, deadline, stdout_cap, source_fd=None):
    tool = Path(argv[0]).name
    need(tool in ('pdfinfo', 'pdftotext', 'qpdf'), 'unexpected pure PDF tool')
    if label.endswith('-version'):
        data = ('mocked ' + tool + ' control\n').encode()
    elif label == 'pdfinfo':
        data = b'Pages: 2\n'
    elif label == 'pdf-all-pages':
        data = b'Page 1 size: 300 x 300\nPage 2 size: 300 x 300\n'
    elif label == 'qpdf-check':
        data = b'checked synthetic boundary\n'
    elif label == 'pdf-text':
        data = b'CONTROL FIRST\n\fCONTROL SECOND\n\f'
    else:
        raise ValueError('unexpected pure PDF label')
    need(len(data) <= stdout_cap, 'mock tool output bound')
    output, errors = folder / (label + '.stdout'), folder / (label + '.stderr')
    output.write_bytes(data)
    errors.write_bytes(b'')
    return 0, output, errors


def extract_case(module, source, destination):
    if os.environ.get('TRANSPORT_DOCUMENT_TEST_PURE') != '1':
        return module.extract_reading(source, destination)
    with patch.object(module.subprocess, 'Popen', side_effect=AssertionError('pure test forbids process creation')):
        with patch.object(module, 'run_tool', side_effect=mocked_pdf_tool):
            return module.extract_reading(source, destination)


def run(mode):
    module, pin = load()
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_storage(ROOT)
    folder = Path(tempfile.mkdtemp(prefix=mode + '-', dir=ROOT))
    (folder / 'source.py.inert').write_bytes(SOURCE.read_bytes())
    boundary_limits(module)
    results = boundary_cleanup(module)
    valid = [('markdown', '.md', b'# First\nA \xc3\xa9\n## Second\n'),
             ('text', '.txt', b'A\x00B\n\xf0\x9f\x98\x80'),
             ('epub', '.epub', epub()), ('epub_doctype', '.epub', epub(xhtml=b'<?xml version="1.0"?><!DOCTYPE html><html><body>alpha beta</body></html>')), ('pdf', '.pdf', pdf())]
    for name, suffix, data in valid:
        source = folder / (name + suffix)
        source.write_bytes(data)
        report = extract_case(module, source, folder / (name + '-out'))
        text = report['text_path'].read_bytes()
        need(report['source_sha256'] == hashlib.sha256(data).hexdigest(), 'source hash')
        need(report['text_sha256'] == hashlib.sha256(text).hexdigest(), 'reading hash')
        need(report['segments'][0]['start'] == 0 and report['segments'][-1]['end'] == len(text), 'coverage extents')
        if name in ('markdown', 'text'):
            need(text == data, 'UTF8 exact text bytes')
        elif name in ('epub', 'epub_doctype'):
            need(text.index(b'alpha') < text.index(b'beta') < text.index(b'gamma'), 'spine order')
            need(b'HIDDEN' not in text and report['coverage']['all_entries_crc_read'] == 6, 'EPUB omissions/inventory')
        else:
            need(len(report['segments']) == 2 and b'CONTROL FIRST' in text and b'CONTROL SECOND' in text, 'PDF pages')
        results.append({'name': name, 'PASS': True})
    bad = [(name, '.epub', data) for name, data in negative_cases()]
    bad += [('invalid_utf8', '.md', b'bad\xff'), ('unsupported', '.bin', b'hello')]
    for name, suffix, data in bad:
        source = folder / (name + suffix)
        source.write_bytes(data)
        try:
            extract_case(module, source, folder / (name + '-out'))
        except (ValueError, zipfile.BadZipFile, KeyError, DefusedXmlException, ParseError) as error:
            results.append({'name': name, 'PASS': True, 'refusal': type(error).__name__})
        else:
            raise ValueError('negative accepted: ' + name)
    need(hashlib.sha256(SOURCE.read_bytes()).hexdigest() == pin, 'source changed')
    receipt = {'source_sha256': pin, 'mode': mode, 'results': results, 'PASS': True,
               'PDF_tool_boundary': 'mocked' if os.environ.get('TRANSPORT_DOCUMENT_TEST_PURE') == '1' else 'actual'}
    check_storage(ROOT)
    (folder / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'PASS': True, 'mode': mode, 'controls': len(results), 'source_sha256': pin}))


class MediaControls(unittest.TestCase):
    def test_controls(self):
        run('optimized' if sys.flags.optimize else 'normal')


if __name__ == '__main__':
    unittest.main()
