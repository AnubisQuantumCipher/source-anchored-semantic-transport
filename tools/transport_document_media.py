"""Bounded reading views; original bytes remain the sole exact source artifact.

Offsets are UTF-8 byte offsets into reading.txt. Extraction is not semantic proof.
No supplied instructions, scripts, external entities or archive members execute.
"""
import codecs
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import resource
import selectors
import signal
import stat
import struct
import subprocess
import time
from urllib.parse import unquote, urlsplit
import zipfile

import defusedxml
from defusedxml import ElementTree as SafeXML

MAX_SOURCE = 1073741824
MAX_TEXT = 33554432
MAX_META = 16777216
MAX_ENTRIES = 4096
MAX_ENTRY = 8388608
MAX_EXPANDED = 67108864
MAX_SEGMENTS = 65536
MAX_PAGES = 16384
CHUNK = 65536


class ExtractionError(ValueError):
    """The reading view is refused; retained partial files are not accepted."""


def need(condition, message):
    if not condition:
        raise ExtractionError(message)


def tick(deadline):
    need(time.monotonic() < deadline, 'reading extraction deadline')


def identity(stream):
    item = os.fstat(stream.fileno())
    return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def open_source(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        item = os.fstat(fd)
        need(stat.S_ISREG(item.st_mode) and 0 <= item.st_size <= MAX_SOURCE,
             'reading input must be a bounded regular file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def hash_stream(stream, deadline):
    digest, total = hashlib.sha256(), 0
    stream.seek(0)
    for _ in range(MAX_SOURCE // CHUNK + 1):
        tick(deadline)
        data = stream.read(CHUNK)
        if not data:
            stream.seek(0)
            return digest.hexdigest()
        total += len(data)
        need(total <= MAX_SOURCE, 'source growth or source byte bound')
        digest.update(data)
    raise ExtractionError('source traversal bound')


def fresh_dir(path):
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        item = parent.lstat()
        need(stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode),
             'reading output ancestor must be a directory without links')
    path.mkdir(mode=0o700)
    return path


def write_json(path, value):
    data = json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2,
                      allow_nan=False).encode('utf-8') + b'\n'
    need(len(data) <= MAX_META, 'reading metadata byte bound')
    with path.open('xb') as stream:
        need(stream.write(data) == len(data), 'metadata short write')


class Writer:
    def __init__(self, path, deadline):
        self.stream = path.open('xb')
        self.size = 0
        self.digest = hashlib.sha256()
        self.deadline = deadline

    def put(self, data):
        tick(self.deadline)
        need(type(data) is bytes and len(data) <= MAX_ENTRY,
             'reading write chunk bound')
        need(self.size + len(data) <= MAX_TEXT, 'reading text byte bound')
        need(self.stream.write(data) == len(data), 'reading text short write')
        self.digest.update(data)
        self.size += len(data)

    def text(self, text):
        for offset in range(0, len(text), CHUNK):
            self.put(text[offset:offset + CHUNK].encode('utf-8', 'strict'))

    def close(self):
        self.stream.flush()
        self.stream.close()


def tighten_limit(kind, ceiling):
    soft, hard = resource.getrlimit(kind)
    new_hard = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
    new_soft = new_hard if soft == resource.RLIM_INFINITY else min(soft, new_hard)
    resource.setrlimit(kind, (new_soft, new_hard))


def process_limits(cap):
    tighten_limit(resource.RLIMIT_AS, 1073741824)
    tighten_limit(resource.RLIMIT_FSIZE, cap)
    tighten_limit(resource.RLIMIT_CORE, 0)


def tool_finished(proc):
    # Observe without reaping: the owned session leader PID remains reserved.
    return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def stop_process(proc):
    errors = []
    for number in [signal.SIGTERM, signal.SIGKILL]:
        try:
            need(os.getpgid(proc.pid) == proc.pid and os.getsid(proc.pid) == proc.pid,
                 'PDF tool owned session UNKNOWN')
            os.killpg(proc.pid, number)
        except (OSError, ExtractionError) as error:
            errors.append(type(error).__name__ + ':' + str(error)[:128])
        if number == signal.SIGTERM:
            time.sleep(0.05)
    try:
        proc.wait(timeout=1)
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(type(error).__name__ + ':' + str(error)[:128])
    # Signals address the owned group; leader reaping is not proof of group absence.
    need(not errors, 'PDF tool cleanup failed: ' + repr(errors))


def drain_errors(proc, errors, selector, used):
    for key, _ in selector.select(timeout=0.02):
        data = os.read(key.fd, min(CHUNK, 1048576 - used + 1))
        if not data:
            selector.unregister(key.fd)
        else:
            need(used + len(data) <= 1048576, 'PDF stderr byte bound')
            need(errors.write(data) == len(data), 'PDF stderr short write')
            used += len(data)
    return used


def close_tool(proc, selector):
    try:
        stop_process(proc)
    finally:
        try:
            selector.close()
        finally:
            proc.stderr.close()


def run_tool(argv, folder, label, deadline, stdout_cap, source_fd=None):
    output, errors = folder / (label + '.stdout'), folder / (label + '.stderr')
    tick(deadline)
    with output.open('xb') as stdout, errors.open('xb') as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.PIPE, start_new_session=True,
                                pass_fds=() if source_fd is None else (source_fd,),
                                preexec_fn=lambda: process_limits(stdout_cap),
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C',
                                     'LC_ALL': 'C', 'HOME': os.environ['HOME'],
                                     'TMPDIR': str(folder)})
        selector, used = selectors.DefaultSelector(), 0
        os.set_blocking(proc.stderr.fileno(), False)
        selector.register(proc.stderr, selectors.EVENT_READ)
        try:
            for _ in range(12000):
                tick(deadline)
                used = drain_errors(proc, stderr, selector, used)
                need(output.stat().st_size <= stdout_cap, 'PDF stdout byte bound')
                if tool_finished(proc) and not selector.get_map():
                    break
            else:
                raise ExtractionError('PDF process observation bound')
        finally:
            close_tool(proc, selector)
    tick(deadline)
    need(output.stat().st_size <= stdout_cap, 'PDF final stdout byte bound')
    write_json(folder / (label + '.process.json'),
               {'argv': argv, 'returncode': proc.returncode,
                'stdout_bytes': output.stat().st_size,
                'stderr_bytes': errors.stat().st_size})
    return proc.returncode, output, errors


def pdf_versions(folder, deadline):
    versions = {}
    for tool, args in [('pdfinfo', ['-v']), ('pdftotext', ['-v']),
                       ('qpdf', ['--version'])]:
        code, out, err = run_tool(['/usr/bin/' + tool] + args, folder,
                                  tool + '-version', deadline, 8192)
        need(code == 0, 'PDF version query failed')
        lines = (out.read_bytes() + err.read_bytes()).decode('utf-8', 'strict').splitlines()
        need(bool(lines), 'PDF version missing')
        versions[tool] = lines[0][:256]
    return versions


def segment(number, label, start, end, kind, locator):
    need(0 <= start <= end <= MAX_TEXT, 'reading segment extent')
    return {'id': 's' + str(number), 'label': label, 'start': start, 'end': end,
            'kind': kind, 'source_locator': locator}


def pdf_pages(raw, writer, pages):
    segments, blank, start, page, content = [], [], 0, 1, False
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    with raw.open('rb') as stream:
        for _ in range(MAX_TEXT // CHUNK + 1):
            data = stream.read(CHUNK)
            if not data:
                break
            decoder.decode(data, final=False)
            base = writer.size
            writer.put(data)
            cursor = 0
            for index, byte in enumerate(data):
                if byte == 12:
                    content = content or bool(data[cursor:index].strip())
                    need(page <= pages, 'PDF extra page delimiter')
                    segments.append(segment(page, 'Page ' + str(page), start,
                                            base + index + 1, 'page', {'page': page}))
                    if not content:
                        blank.append(page)
                    start, page, content = base + index + 1, page + 1, False
                    cursor = index + 1
            content = content or bool(data[cursor:].strip())
    decoder.decode(b'', final=True)
    need(page == pages + 1 and start == writer.size, 'PDF page coverage mismatch')
    return segments, blank


def pdf_page_count(data):
    need(type(data) is bytes and len(data) <= MAX_ENTRY, 'PDF metadata byte bound')
    matches = re.findall(rb'^Pages:[ \t]+([0-9]{1,5})[ \t]*\r?$', data, re.MULTILINE)
    need(len(matches) == 1, 'PDF page count missing or ambiguous')
    pages = int(matches[0])
    need(1 <= pages <= MAX_PAGES, 'PDF page bound')
    return pages


def extract_pdf(source, folder, writer, deadline):
    versions = pdf_versions(folder, deadline)
    argument = '/proc/self/fd/' + str(source.fileno())
    code, info, _ = run_tool(['/usr/bin/pdfinfo', argument], folder, 'pdfinfo',
                             deadline, MAX_ENTRY, source.fileno())
    need(code == 0, 'PDF metadata inspection failed')
    pages = pdf_page_count(info.read_bytes())
    code, boxes, _ = run_tool(['/usr/bin/pdfinfo', '-box', '-f', '1', '-l', str(pages),
                              argument], folder, 'pdf-all-pages', deadline,
                             MAX_ENTRY, source.fileno())
    sizes = re.findall(rb'^Page\s+(\d+)\s+size:', boxes.read_bytes(), re.MULTILINE)
    need(code == 0 and [int(x) for x in sizes] == list(range(1, pages + 1)),
         'PDF all-page inspection coverage mismatch')
    code, _, _ = run_tool(['/usr/bin/qpdf', '--check', argument], folder,
                           'qpdf-check', deadline, MAX_ENTRY, source.fileno())
    need(code in (0, 3), 'PDF structural check failed')
    check_warning = code == 3
    code, raw, _ = run_tool(['/usr/bin/pdftotext', '-enc', 'UTF-8', '-eol', 'unix',
                            '-f', '1', '-l', str(pages), argument, '-'], folder,
                           'pdf-text', deadline, MAX_TEXT, source.fileno())
    need(code == 0, 'PDF whole-file text extraction failed')
    segments, blank = pdf_pages(raw, writer, pages)
    uncertainty = ['Text extraction is not complete semantic recovery.',
                   'Figures, images, layout, equations and reading order may be lost; no OCR performed.',
                   'Blank extracted pages may be scanned/image-only or intentionally blank.']
    if check_warning:
        uncertainty.append('qpdf reported structural warnings; raw diagnostics retained.')
    return versions, segments, uncertainty, {'pages': pages, 'page_boxes_inspected': pages,
                                            'extracted_pages': len(segments), 'blank_pages': blank}


def safe_member(name, directory=False):
    need(type(name) is str and 0 < len(name) <= 1024 and '\\' not in name and
         '\x00' not in name and not name.startswith('/'), 'unsafe EPUB path')
    clean = name[:-1] if directory and name.endswith('/') else name
    parts = clean.split('/')
    need(all(part not in ('', '.', '..') and ':' not in part for part in parts),
         'unsafe EPUB path component')
    return clean


def preflight_directory(source, offset, size, count):
    source.seek(offset)
    data = source.read(size)
    need(len(data) == size, 'EPUB central directory truncation')
    cursor, expanded = 0, 0
    for _ in range(count):
        need(cursor + 46 <= size, 'EPUB central header truncation')
        fields = struct.unpack('<4s6H3I5H2I', data[cursor:cursor + 46])
        need(fields[0] == b'PK\x01\x02' and fields[2] <= 20 and fields[13] == 0,
             'EPUB central version/disk/header unsupported')
        need(fields[9] <= MAX_ENTRY, 'EPUB central entry byte bound')
        expanded += fields[9]
        need(expanded <= MAX_EXPANDED, 'EPUB central expanded byte bound')
        cursor += 46 + fields[10] + fields[11] + fields[12]
        need(cursor <= size, 'EPUB central entry extent')
    need(cursor == size, 'EPUB central count/extent mismatch')


def preflight_epub(source):
    size = identity(source)[2]
    need(22 <= size <= MAX_SOURCE, 'EPUB ZIP size')
    source.seek(max(0, size - 65557))
    tail = source.read(65557)
    position = tail.rfind(b'PK\x05\x06')
    need(position >= 0 and position + 22 <= len(tail), 'EPUB EOCD missing')
    end = struct.unpack('<4s4H2IH', tail[position:position + 22])
    need(position + 22 + end[7] == len(tail), 'EPUB trailing or ambiguous EOCD')
    need(end[1:3] == (0, 0) and 0 < end[3] == end[4] <= MAX_ENTRIES,
         'EPUB ZIP64/multidisk/count unsupported')
    absolute = size - len(tail) + position
    need(0 < end[5] <= 1048576 and end[6] + end[5] == absolute,
         'EPUB central-directory byte bound or extent')
    preflight_directory(source, end[6], end[5], end[4])
    source.seek(0)
    need(source.read(4) == b'PK\x03\x04', 'EPUB leading data unsupported')
    source.seek(0)
    return end[4]


def epub_inventory(archive, deadline):
    infos, names, total, records = archive.infolist(), set(), 0, []
    need(len(infos) <= MAX_ENTRIES, 'EPUB entry count bound')
    for info in infos:
        tick(deadline)
        name = safe_member(info.filename, info.is_dir())
        need(name not in names and info.filename == info.orig_filename, 'duplicate EPUB path')
        names.add(name)
        mode = info.external_attr >> 16
        need(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and
             not (info.flag_bits & 1), 'EPUB link/special/encrypted entry')
        need(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
             info.extract_version <= 20 and 0 <= info.file_size <= MAX_ENTRY,
             'EPUB entry type/version/byte bound')
        total += info.file_size
        need(total <= MAX_EXPANDED, 'EPUB expanded byte bound')
        digest, used = hashlib.sha256(), 0
        with archive.open(info, 'r') as stream:
            for _ in range(MAX_ENTRY // CHUNK + 1):
                tick(deadline)
                data = stream.read(CHUNK)
                if not data:
                    break
                used += len(data)
                need(used <= info.file_size, 'EPUB entry expansion mismatch')
                digest.update(data)
        need(used == info.file_size, 'EPUB entry truncated')
        records.append({'path': info.filename, 'bytes': used, 'sha256': digest.hexdigest(),
                        'crc32': info.CRC, 'kind': 'directory' if info.is_dir() else 'resource'})
    return records


def harmless_html_doctype(data):
    match = re.search(rb'<!DOCTYPE', data, re.IGNORECASE)
    if match is None:
        return data
    need(match.start() <= 4096, 'EPUB doctype location unsupported')
    declaration = re.match(rb'<!DOCTYPE[ \t\r\n]+html[ \t\r\n]*>',
                           data[match.start():], re.IGNORECASE)
    need(declaration is not None, 'EPUB active/external DTD forbidden')
    prefix = data[:match.start()]
    prefix = re.sub(rb'^\s*<\?xml[^?]*\?>', b'', prefix, count=1)
    prefix = re.sub(rb'<!--(?:(?!-->).)*-->', b'', prefix, flags=re.DOTALL)
    need(not prefix.strip(), 'EPUB doctype outside plain prolog forbidden')
    return data[:match.start()] + data[match.start() + declaration.end():]


def xml_root(data, deadline):
    depth, nodes = 0, 0
    parser = SafeXML.iterparse(io.BytesIO(harmless_html_doctype(data)), events=('start', 'end'),
                              forbid_dtd=True, forbid_entities=True, forbid_external=True)
    for event, _ in parser:
        tick(deadline)
        if event == 'start':
            depth += 1
            nodes += 1
            need(depth <= 128 and nodes <= 65536, 'EPUB XML structure bound')
        else:
            depth -= 1
    need(depth == 0, 'EPUB XML unbalanced')
    return parser.root


def epub_read(archive, name):
    info = archive.getinfo(name)
    need(not info.is_dir() and info.file_size <= MAX_ENTRY, 'EPUB XML entry bound')
    with archive.open(info) as stream:
        data = stream.read(MAX_ENTRY + 1)
    need(len(data) == info.file_size, 'EPUB XML truncation')
    return data


def local_tag(tag):
    return tag.rsplit('}', 1)[-1] if type(tag) is str else ''


def resolve_href(base, href):
    need(type(href) is str and len(href) <= 1024, 'EPUB href bound')
    parsed = urlsplit(href)
    need(not parsed.scheme and not parsed.netloc and not parsed.query,
         'external EPUB resource unsupported')
    relative = unquote(parsed.path, errors='strict')
    need(not relative.startswith('/') and '\\' not in relative and '\x00' not in relative,
         'unsafe EPUB relative resource')
    return safe_member(posixpath.normpath(posixpath.join(base, relative)))


def epub_package(archive, deadline):
    root = xml_root(epub_read(archive, 'META-INF/container.xml'), deadline)
    roots = [node.attrib.get('full-path') for node in root.iter()
             if local_tag(node.tag) == 'rootfile']
    need(len(roots) == 1, 'EPUB requires one explicit rootfile')
    package = safe_member(roots[0])
    opf = xml_root(epub_read(archive, package), deadline)
    base, manifest, spine = posixpath.dirname(package), {}, []
    for node in opf.iter():
        tag = local_tag(node.tag)
        if tag == 'item':
            key = node.attrib.get('id', '')
            need(0 < len(key) <= 1024 and key not in manifest, 'EPUB manifest ID')
            path = resolve_href(base, node.attrib.get('href', ''))
            need(path in archive.namelist(), 'EPUB missing manifest resource')
            manifest[key] = {'path': path, 'media_type': node.attrib.get('media-type', '')}
        elif tag == 'itemref':
            spine.append(node.attrib.get('idref', ''))
    need(0 < len(spine) <= MAX_ENTRIES and all(key in manifest for key in spine),
         'EPUB missing/invalid spine')
    return package, manifest, spine


def emit_xhtml(root, writer, deadline):
    blocked = {'script', 'style', 'head', 'template', 'svg', 'math'}
    breaks = {'p', 'div', 'section', 'article', 'br', 'li', 'h1', 'h2', 'h3', 'h4', 'tr'}
    stack, visited, omitted = [(root, False)], 0, {}
    for _ in range(131073):
        tick(deadline)
        if not stack:
            return omitted
        node, tail = stack.pop()
        if tail:
            writer.text(node.tail or '')
            continue
        visited += 1
        need(visited <= 65536, 'EPUB text node bound')
        tag = local_tag(node.tag).lower()
        if tag in blocked:
            omitted[tag] = omitted.get(tag, 0) + 1
            continue
        if tag in breaks:
            writer.put(b'\n')
        if tag == 'img':
            omitted['img'] = omitted.get('img', 0) + 1
        writer.text(node.text or '')
        children = list(node)
        need(len(stack) + 2 * len(children) <= 131072, 'EPUB traversal stack bound')
        for child in reversed(children):
            stack.append((child, True))
            stack.append((child, False))
    raise ExtractionError('EPUB traversal iteration bound')


def extract_epub(source, folder, writer, deadline):
    count = preflight_epub(source)
    with zipfile.ZipFile(source, 'r', allowZip64=False) as archive:
        need(len(archive.infolist()) == count, 'EPUB directory count mismatch')
        resources = epub_inventory(archive, deadline)
        need(epub_read(archive, 'mimetype') == b'application/epub+zip', 'EPUB mimetype')
        package, manifest, spine = epub_package(archive, deadline)
        segments, omissions = [], {}
        spine_paths = set()
        for number, key in enumerate(spine, 1):
            item = manifest[key]
            need(item['media_type'] in ('application/xhtml+xml', 'text/html'),
                 'EPUB spine media type unsupported')
            tree = xml_root(epub_read(archive, item['path']), deadline)
            start = writer.size
            omitted = emit_xhtml(tree, writer, deadline)
            writer.put(b'\n')
            segments.append(segment(number, 'Spine ' + str(number), start, writer.size,
                                    'epub-spine', {'path': item['path'], 'idref': key}))
            spine_paths.add(item['path'])
            for kind, count in omitted.items():
                omissions[kind] = omissions.get(kind, 0) + count
        for item in resources:
            item['in_spine'] = item['path'] in spine_paths
        write_json(folder / 'epub-resources.json', {'package': package, 'entries': resources})
    uncertainty = ['Reading view follows every spine item, not all semantic content.',
                   'Images, SVG, math, script/style/head/template text and formatting omitted; no scripts execute.',
                   'Non-spine resources are fully hashed/CRC-read but not merged into the reading text.']
    return {'defusedxml': defusedxml.__version__}, segments, uncertainty, {
        'spine_items': len(spine), 'traversed_spine_items': len(segments),
        'all_entries_crc_read': len(resources), 'omitted_elements': omissions,
        'non_spine_entries': sum(not item['in_spine'] for item in resources)}


def extract_text(source, writer, deadline, markdown):
    segments, offset = [], 0
    source.seek(0)
    for number in range(1, MAX_SEGMENTS + 2):
        tick(deadline)
        data = source.readline(MAX_TEXT + 1)
        if not data:
            return {'python': platform.python_version()}, segments, [
                'Exact UTF-8 text bytes retained; headings/lines are syntactic, not semantic units.'], {
                    'lines': len(segments), 'all_input_bytes_traversed': offset}
        need(number <= MAX_SEGMENTS and len(data) <= MAX_TEXT, 'text line/segment bound')
        text = data.decode('utf-8', 'strict')
        start = writer.size
        for offset_in_line in range(0, len(data), CHUNK):
            writer.put(data[offset_in_line:offset_in_line + CHUNK])
        heading = bool(markdown and re.match(r'^ {0,3}#{1,6}(?:\s|$)', text))
        segments.append(segment(number, ('Heading line ' if heading else 'Line ') + str(number),
                                start, writer.size, 'heading' if heading else 'line',
                                {'line': number, 'source_start': offset, 'source_end': offset + len(data)}))
        offset += len(data)
    raise ExtractionError('text traversal bound')


def extract_reading(source: Path, out_dir: Path) -> dict:
    deadline = time.monotonic() + 120
    folder = fresh_dir(out_dir)
    writer = Writer(folder / 'reading.txt', deadline)
    report = None
    try:
        with open_source(source) as stream:
            before, source_sha = identity(stream), hash_stream(stream, deadline)
            suffix = Path(source).suffix.lower()
            if suffix == '.pdf':
                result = extract_pdf(stream, folder, writer, deadline)
                format_name = 'pdf'
            elif suffix == '.epub':
                result = extract_epub(stream, folder, writer, deadline)
                format_name = 'epub'
            elif suffix in ('.md', '.txt'):
                result = extract_text(stream, writer, deadline, suffix == '.md')
                format_name = 'markdown' if suffix == '.md' else 'text'
            else:
                raise ExtractionError('unsupported reading format')
            need(identity(stream) == before and hash_stream(stream, deadline) == source_sha,
                 'source changed during extraction')
        versions, segments, uncertainty, coverage = result
        report = {'schema': 'transport/reading-view/1', 'format': format_name,
                  'tool_versions': versions, 'source_sha256': source_sha,
                  'text_sha256': writer.digest.hexdigest(), 'text_bytes': writer.size,
                  'segments': segments, 'uncertainty': uncertainty, 'coverage': coverage,
                  'text_path': 'reading.txt'}
    finally:
        writer.close()
    tick(deadline)
    write_json(folder / 'reading.json', report)
    # Validate the completed artifact bytes independently before returning it.
    with (folder / 'reading.txt').open('rb') as reading:
        need(hash_stream(reading, deadline) == report['text_sha256'], 'reading readback hash')
    tick(deadline)
    return dict(report, text_path=folder / 'reading.txt', reading_json_path=folder / 'reading.json')
