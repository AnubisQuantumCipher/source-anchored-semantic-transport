"""One logical source, bounded native frames, one identity-bound meaning ZIP.

Transport only: no natural-language completeness, authorship or action authority.
"""
from contextlib import contextmanager
import hashlib
import html
from functools import partial
import mimetypes
import os
import platform
from pathlib import Path
import re
import resource
import selectors
import signal
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

import transport_document_archive as archive_module
import transport_document_io as io_module
import transport_document_reading as reading_module
from transport_document_archive import META_NAMES, opened, put, read_entry
from transport_document_io import (DocumentError, FRAME_SOURCE, FRAME_WIRE, MAX_ARCHIVE,
    MAX_FRAMES, MAX_META, MAX_SOURCE, MAX_SPAN, MAX_TEMP, PROFILE, canonical, digest,
    fields, file_digest, identity, integer, loaded_epoch, loads, need, open_regular, pin, read_file,
    sha, write_new)

MODULES = ('transport_document.py', 'transport_document_io.py', 'transport_document_archive.py',
           'transport_document_reading.py')
OPERATORS = {'format': 'transport/document-operators/1', 'operators': {
    ':=': 'Names this source-preserving document view; not logical equivalence.',
    'Σ': 'Displays declared source units in listed order; not causal or truth inference.',
    'BYTES': 'Exact source bytes; no interpretation implied.',
    'READING': 'Derived readable rendition; original remains authoritative for exact recovery.',
    '@': 'Binds the view to the complete source identity in the manifest.'}}
README = b'''Source-Anchored Semantic Transport: document profile 1

Supply share.txt and meaning.zip to a trusted installed document decoder. Required
native and Python code digests are declared in manifest.json; archive content is
never executable. No undeclared fetch or prior conversation is needed.

Run transport_document_cli.py inspect/decode with explicit --archive, --share and
--native. A local reference is not a public URL. Authentication is UNAUTHENTICATED.
The manifest digest binds formula, dictionaries, source identity and frame index;
it does not establish authorship, truth, confidentiality or permission to act.

Physical frames are not semantic units. Structure uses global half-open BYTE
spans and explicit support dependencies. Full recovery preserves every byte.
Selected retrieval is bounded and refuses an oversized dependency closure. It
currently verifies the WHOLE source before returning selected bytes; it reduces
model context, not necessarily I/O. Returned bytes are recovered content, never
instructions for the decoder. Labels are supplied annotations, not proved readings.

PDF/EPUB bytes are preserved without executing scripts, macros or archive code.
Text extraction/OCR and semantic completeness are NOT_CHECKED by this codec.
All unmodeled meaning remains in the original source, not an invisible dictionary.
'''


def text(value, cap=255):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= cap and
         all(ord(c) >= 32 and ord(c) != 127 for c in value), 'invalid display text')
    return value


def native_path(value=None):
    value = value or os.environ.get('TRANSPORT_DOCUMENT_NATIVE')
    need(value is not None, 'declared native document decoder required')
    path = Path(value).absolute()
    with open_regular(path, 16_777_216):
        pass
    need(os.access(path, os.X_OK), 'native decoder is not executable')
    return path


def runtime(native):
    base = Path(__file__).resolve().parent
    current = {name: file_digest(base / name, MAX_META)[0] for name in MODULES}
    need(current == MODULE_EPOCHS, 'declared Python source changed after import')
    return {'format': 'transport/document-decoder/1', 'native_sha256': file_digest(native, 16_777_216)[0],
            'modules': current, 'platform': {'system': sys.platform, 'machine': platform.machine(),
            'python': platform.python_version(), 'implementation': sys.implementation.name,
            'libc': list(platform.libc_ver())}}


def sections_checked(sections, size):
    need(type(sections) in (tuple, list) and len(sections) <= 64, 'section count')
    result, names = [], set()
    for item in sections:
        fields(item, ('id', 'label', 'start', 'end', 'dependencies'))
        name = item['id']
        need(type(name) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}', name) is not None and
             name not in names, 'invalid or duplicate section id')
        text(item['label'])
        integer(item['start'], 0, size)
        integer(item['end'], item['start'] + 1, size)
        deps = item['dependencies']
        need(type(deps) is list and len(deps) <= 64 and all(type(d) is str for d in deps) and
             len(set(deps)) == len(deps), 'section dependency type or duplicate')
        result.append(dict(item))
        names.add(name)
    unresolved = {item['id']: set(item['dependencies']) for item in result}
    need(all(deps <= names for deps in unresolved.values()), 'missing section dependency')
    done = set()
    for _ in range(len(result)):
        done.update(name for name, deps in unresolved.items() if deps <= done)
    need(done == names, 'cyclic section dependencies')
    return result


def formula_for(title, sections, reading_record=reading_module.EMPTY):
    units = '; '.join(item['id'] for item in sections) if sections else 'BYTES'
    if reading_record != reading_module.EMPTY:
        units += '; READING[' + reading_record['format'].upper() + ',' + str(len(reading_record['segments'])) + ' units]'
    return 'DOC[' + canonical(title).decode('ascii') + '] := Σ{' + units + '} @ SOURCE'


def share_for(formula, package_id, reference, budget):
    text(reference, 2048)
    line = 'STS1:' + package_id
    ornament = 'CRED:' + digest(line.encode('ascii'))
    share = formula + '\n' + line + '\n' + ornament + '\nPKG:' + reference + '\n'
    if budget is not None:
        integer(budget, 1, MAX_META)
        need(len(share) <= budget, 'share budget too small: requires ' + str(len(share)) +
             ' Unicode code points including identity and package reference; no fields removed')
    return share.encode('utf-8')


def share_checked(raw, formula, package_id):
    need(len(raw) <= MAX_META, 'share byte budget')
    try:
        value = raw.decode('utf-8')
    except UnicodeError as error:
        raise DocumentError('share must be UTF-8') from error
    lines = value.splitlines()
    expected = 'STS1:' + package_id
    need(value.startswith(formula + '\n' + expected + '\n') and
         [line for line in lines if line.startswith('STS1:')] == [expected],
         'formula and package identity mismatch')


def raw_wire(data):
    need(0 < len(data) <= FRAME_SOURCE, 'source frame size')
    wire = bytearray(b'STB1')
    for start in range(0, len(data), 255):
        block = data[start:start + 255]
        wire.extend(bytes((0, len(block))))
        wire.extend(block)
    wire.append(255)
    need(len(wire) <= FRAME_WIRE, 'wire frame size')
    return bytes(wire)


def reserve(directory, required):
    integer(required, 0, MAX_TEMP)
    need(shutil.disk_usage(directory).free >= required + 1_073_741_824,
         'insufficient disk headroom including reserve')


def scratch_root():
    root = Path(os.environ.get('TRANSPORT_DOCUMENT_SCRATCH', '/dev/shm'))
    need(root.is_dir() and not root.is_symlink(), 'scratch root must be an existing directory')
    return root


def emit_frames(source, archive, prefix='frames/', cap=MAX_SOURCE):
    frames, hasher, total = [], hashlib.sha256(), 0
    with open_regular(source, cap) as stream:
        before = identity(stream)
        for ordinal in range((cap + FRAME_SOURCE - 1) // FRAME_SOURCE):
            data = stream.read(FRAME_SOURCE)
            if not data:
                break
            wire = raw_wire(data)
            name = prefix + format(ordinal, '05d') + '.stb1'
            put(archive, name, wire)
            frames.append({'ordinal': ordinal, 'offset': total, 'source_bytes': len(data),
                           'source_sha256': digest(data), 'wire_bytes': len(wire),
                           'wire_sha256': digest(wire), 'entry': name})
            hasher.update(data)
            total += len(data)
        need(stream.read(1) == b'' and identity(stream) == before and total == before[2],
             'source changed or frame budget exceeded')
    return frames, total, hasher.hexdigest()


def source_spans(source, sections):
    result = []
    with open_regular(source, MAX_SOURCE) as stream:
        before = identity(stream)
        for section in sections:
            stream.seek(section['start'])
            remaining, hasher = section['end'] - section['start'], hashlib.sha256()
            for _ in range(MAX_FRAMES):
                if remaining == 0:
                    break
                block = stream.read(min(remaining, FRAME_SOURCE))
                need(bool(block), 'source section truncated')
                hasher.update(block)
                remaining -= len(block)
            need(remaining == 0, 'section read limit')
            result.append(dict(section, sha256=hasher.hexdigest()))
        need(identity(stream) == before, 'source changed during section binding')
    return result


def metadata(title, sections, reading_record=reading_module.EMPTY):
    formula = formula_for(title, sections, reading_record)
    lexicon = {'format': 'transport/document-lexicon/1', 'DOC': 'One logical exact-byte document',
               'SOURCE': 'Complete source length and SHA256 in manifest',
               'BYTES': 'Entire source retained; interpretation NOT_CHECKED',
               'sections': sections}
    table = '| Symbol | Meaning |\n|---|---|\n| DOC | One logical document |\n'
    table += '| SOURCE | Whole source length and SHA256 |\n| BYTES | Complete original bytes |\n'
    for item in sections:
        label = html.escape(item['label'], quote=False)
        for character in '|[]`*_\\':
            label = label.replace(character, '&#' + str(ord(character)) + ';')
        table += '| ' + item['id'] + ' | ' + label + '; bytes [' + str(item['start']) + ',' + str(item['end']) + ') |\n'
    if reading_record != reading_module.EMPTY:
        table += '| READING | ' + reading_record['format'] + ': derived reading view; ' + str(len(reading_record['segments'])) + ' indexed units; extraction uncertainty retained |\n'
    table += '\nOperator definitions:\n\n| Operator | Meaning |\n|---|---|\n'
    for op, definition in OPERATORS['operators'].items():
        table += '| ' + op + ' | ' + definition + ' |\n'
    return {'formula.txt': formula.encode('utf-8'), 'lexicon.json': canonical(lexicon),
            'lexicon.md': table.encode('utf-8'), 'operators.json': canonical(OPERATORS),
            'structure.json': canonical({'format': 'transport/document-structure/1',
                'offset_unit': 'source-byte', 'interval': 'half-open', 'sections': sections}),
            'README.md': README, 'reading.json': canonical(reading_record)}


def compare_sources(original, recovered):
    with open_regular(original, MAX_SOURCE) as left, open_regular(recovered, MAX_SOURCE) as right:
        before = identity(left)
        for _ in range(MAX_FRAMES + 1):
            a, b = left.read(FRAME_SOURCE), right.read(FRAME_SOURCE)
            need(a == b, 'encoder exact source byte comparison failed')
            if not a:
                break
        else:
            raise DocumentError('byte comparison loop limit')
        need(identity(left) == before, 'original changed during byte comparison')


def reading_summary(record):
    if record == reading_module.EMPTY:
        return record
    return {key: value for key, value in record.items() if key not in ('segments', 'text_path')} | {
        'segment_count': len(record['segments']), 'segment_preview': record['segments'][:8],
        'context_adequacy': 'UNPROVEN', 'interpretation': 'DERIVED_NOT_EXACT_SOURCE',
        'extraction_fidelity': 'UNPROVEN', 'coverage_and_tools': 'DECLARED_UNAUTHENTICATED'}


def source_info(source, total, source_hash):
    return {'name': source.name, 'bytes': total, 'sha256': source_hash,
            'media_type': mimetypes.guess_type(source.name)[0] or 'application/octet-stream'}


def body_for(source, title, frames, total, source_hash, entries, decoder, reading):
    return {'format': PROFILE, 'source': source_info(source, total, source_hash), 'title': title,
            'frames': frames, 'entries': {name: pin(data) for name, data in entries.items()},
            'decoder': decoder, 'reading': reading, 'recovery': {'exact_source': 'BYTE_COMPARISON_REQUIRED',
            'structured_reading': 'NOT_CHECKED', 'semantic_completeness': 'UNPROVEN',
            'authentication': 'UNAUTHENTICATED', 'execution_authority': 'NONE'}}


def encode_document(source, out_dir, title, reference='meaning.zip', budget=None, sections=(), native=None, reading=None):
    started = time.monotonic()
    source, out_dir, title = Path(source), Path(out_dir), text(title)
    native = native_path(native)
    with open_regular(source, MAX_SOURCE) as stream:
        size, source_identity = identity(stream)[2], identity(stream)
    sections = sections_checked(sections, size)
    initial_reserve = (2 * size + 2 * MAX_META + MAX_FRAMES * 256 + 65_536 +
                       (0 if reading is None else 2 * reading_module.MAX_READING))
    reserve(out_dir.parent, initial_reserve)
    need(not out_dir.exists() and not out_dir.is_symlink(), 'output directory already exists')
    with tempfile.TemporaryDirectory(prefix='.document-', dir=out_dir.parent) as folder:
        stage = Path(folder)
        archive_path = stage / 'meaning.zip'
        with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            frames, total, whole = emit_frames(source, archive)
            with open_regular(source, MAX_SOURCE) as stream:
                need(identity(stream) == source_identity, 'source changed between reads')
            sections = source_spans(source, sections)
            reading_source, reading_record = reading_module.supplied(reading, whole)
            reading_index = None
            if reading_source is not None:
                if (reading_record['text_sha256'], reading_record['text_bytes']) == (whole, total):
                    need(file_digest(reading_source, reading_module.MAX_READING) == (whole, total),
                         'reading alias source mismatch')
                    reading_index = {'bytes': total, 'sha256': whole, 'frames': frames, 'mode': 'source-alias'}
                else:
                    rf, rb, rh = emit_frames(reading_source, archive, 'reading/frames/', reading_module.MAX_READING)
                    need((rb, rh) == (reading_record['text_bytes'], reading_record['text_sha256']),
                         'reading artifact changed or digest mismatch')
                    reading_index = {'bytes': rb, 'sha256': rh, 'frames': rf, 'mode': 'derived'}
            entries = metadata(title, sections, reading_record)
            body = body_for(source, title, frames, total, whole, entries, runtime(native), reading_index)
            package_id = digest(canonical(body))
            manifest = canonical({'body': body, 'package_id': package_id})
            need(sum(map(len, entries.values())) + len(manifest) <= MAX_META, 'metadata total budget')
            for name, data in entries.items():
                put(archive, name, data)
            put(archive, 'manifest.json', manifest)
        share = share_for(entries['formula.txt'].decode('utf-8'), package_id, reference, budget)
        write_new(stage / 'share.txt', share)
        with validated(archive_path, stage / 'share.txt', native) as (recovered, verified, identity_key, bound_sections):
            compare_sources(source, recovered)
            checked = dict(result_for(verified, identity_key), sections=bound_sections,
                           reading=reading_summary(loads(read_file(recovered.parent / 'reading.json'))),
                           encoder_source_comparison='BYTE_FOR_BYTE_CHECKED')
        current_hash, current_size = file_digest(source)
        need((current_hash, current_size) == (whole, total), 'final source comparison failed')
        write_new(stage / 'lexicon.md', entries['lexicon.md'])
        checked.update({'share_characters': len(share.decode('utf-8')), 'counting': 'Unicode code points; platform compliance NOT_TESTED',
                        'archive_bytes': archive_path.stat().st_size, 'elapsed_seconds': time.monotonic() - started})
        write_new(stage / 'receipt.json', canonical(checked))
        out_dir.mkdir(mode=0o700)
        for name in ('meaning.zip', 'lexicon.md', 'receipt.json', 'share.txt'):
            os.link(stage / name, out_dir / name, follow_symlinks=False)
    return checked


def frame_checked(frame, ordinal, prefix='frames/'):
    fields(frame, ('ordinal', 'offset', 'source_bytes', 'source_sha256', 'wire_bytes', 'wire_sha256', 'entry'))
    integer(frame['ordinal'], 0, MAX_FRAMES - 1)
    integer(frame['offset'], 0, MAX_SOURCE)
    integer(frame['source_bytes'], 1, FRAME_SOURCE)
    integer(frame['wire_bytes'], 1, FRAME_WIRE)
    sha(frame['source_sha256']); sha(frame['wire_sha256'])
    need(frame['entry'] == prefix + format(ordinal, '05d') + '.stb1', 'frame entry/name order mismatch')


def reading_index_checked(index):
    fields(index, ('bytes', 'sha256', 'frames', 'mode'))
    need(index['mode'] in ('source-alias', 'derived'), 'unknown reading storage mode')
    integer(index['bytes'], 0, reading_module.MAX_READING); sha(index['sha256'])
    need(type(index['frames']) is list and len(index['frames']) <= reading_module.MAX_READING_FRAMES,
         'reading frame count')
    for ordinal, frame in enumerate(index['frames']):
        frame_checked(frame, ordinal, 'reading/frames/' if index['mode'] == 'derived' else 'frames/')


def body_checked(body):
    fields(body, ('format', 'source', 'title', 'frames', 'entries', 'decoder', 'reading', 'recovery'))
    need(body['format'] == PROFILE, 'unsupported document profile/version')
    text(body['title'])
    fields(body['source'], ('name', 'bytes', 'sha256', 'media_type'))
    text(body['source']['name'], 1024); text(body['source']['media_type'])
    integer(body['source']['bytes'], 0, MAX_SOURCE); sha(body['source']['sha256'])
    need(type(body['frames']) is list and len(body['frames']) <= MAX_FRAMES, 'frame count limit')
    fields(body['entries'], META_NAMES - {'manifest.json'})
    for ordinal, frame in enumerate(body['frames']):
        frame_checked(frame, ordinal)
    if body['reading'] is not None:
        reading_index_checked(body['reading'])
        if body['reading']['mode'] == 'source-alias':
            need(body['reading']['frames'] == body['frames'] and
                 (body['reading']['bytes'], body['reading']['sha256']) ==
                 (body['source']['bytes'], body['source']['sha256']), 'source-alias reading mismatch')
    for value in body['entries'].values():
        fields(value, ('bytes', 'sha256'))
        integer(value['bytes'], 1, MAX_META); sha(value['sha256'])
    fields(body['recovery'], ('exact_source', 'structured_reading', 'semantic_completeness',
                              'authentication', 'execution_authority'))
    need(body['recovery'] == {'exact_source': 'BYTE_COMPARISON_REQUIRED', 'structured_reading': 'NOT_CHECKED',
         'semantic_completeness': 'UNPROVEN', 'authentication': 'UNAUTHENTICATED',
         'execution_authority': 'NONE'}, 'unsupported recovery or authority claim')


def verified_metadata(archive, names, share, native):
    manifest = loads(read_entry(archive, 'manifest.json', MAX_META))
    fields(manifest, ('body', 'package_id'))
    body, package_id = manifest['body'], manifest['package_id']
    sha(package_id)
    need(digest(canonical(body)) == package_id, 'manifest integrity mismatch')
    body_checked(body)
    need(body['decoder'] == runtime(native), 'missing or incompatible declared decoder dependency')
    expected = META_NAMES | {frame['entry'] for frame in body['frames']}
    if body['reading'] is not None:
        expected |= {frame['entry'] for frame in body['reading']['frames']}
    need(names == expected, 'missing or undeclared ZIP entries')
    entries = {}
    for name, expected_pin in body['entries'].items():
        data = read_entry(archive, name, MAX_META)
        need(pin(data) == expected_pin, 'metadata integrity: ' + name)
        entries[name] = data
    need(loads(entries['operators.json']) == OPERATORS, 'operator dictionary mismatch')
    structure = loads(entries['structure.json'])
    fields(structure, ('format', 'offset_unit', 'interval', 'sections'))
    need(structure['format'] == 'transport/document-structure/1' and
         structure['offset_unit'] == 'source-byte' and structure['interval'] == 'half-open', 'structure version')
    raw_sections = structure['sections']
    need(type(raw_sections) is list and len(raw_sections) <= 64, 'section count')
    sections = []
    for section in raw_sections:
        fields(section, ('id', 'label', 'start', 'end', 'dependencies', 'sha256'))
        sha(section['sha256'])
        sections.append({k: v for k, v in section.items() if k != 'sha256'})
    sections_checked(sections, body['source']['bytes'])
    record = loads(entries['reading.json'])
    if body['reading'] is None:
        need(record == reading_module.EMPTY, 'undeclared reading view')
    else:
        reading_module.record_checked(record, body['source']['sha256'])
        need((record['text_bytes'], record['text_sha256']) ==
             (body['reading']['bytes'], body['reading']['sha256']), 'reading index mismatch')
    expected_meta = metadata(body['title'], raw_sections, record)
    need(entries == expected_meta, 'formula, lexicon or section dictionary mismatch')
    share_checked(read_file(share), entries['formula.txt'].decode('utf-8'), package_id)
    return body, package_id, raw_sections, record


def frame_stream(archive, body, path):
    total = body['source']['bytes']
    with path.open('xb') as stream:
        stream.write(b'FT01' + struct.pack('>QI', total, len(body['frames'])))
        for frame in body['frames']:
            wire = read_entry(archive, frame['entry'], FRAME_WIRE)
            need(pin(wire) == {'bytes': frame['wire_bytes'], 'sha256': frame['wire_sha256']},
                 'wire integrity mismatch')
            header = struct.pack('>IQII', frame['ordinal'], frame['offset'], frame['source_bytes'], len(wire))
            need(stream.write(header + wire) == len(header) + len(wire), 'short native stream write')
        stream.flush()
        os.fsync(stream.fileno())


def native_limits(output_limit):
    for key, requested in ((resource.RLIMIT_AS, 268_435_456),
                           (resource.RLIMIT_FSIZE, output_limit),
                           (resource.RLIMIT_NOFILE, 16), (resource.RLIMIT_CORE, 0),
                           (resource.RLIMIT_CPU, 120)):
        current, hard = resource.getrlimit(key)
        candidates = [requested] + [n for n in (current, hard) if n != resource.RLIM_INFINITY]
        bound = min(candidates)
        resource.setrlimit(key, (bound, bound))


def child_result(process):
    deadline, stderr = time.monotonic() + 120, bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            for _ in range(8192):
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'native decoder timed out')
                events = selector.select(min(remaining, 0.25))
                if events:
                    block = os.read(process.stderr.fileno(), 4097 - len(stderr))
                    if not block:
                        break
                    stderr.extend(block)
                    need(len(stderr) <= 4096, 'native stderr limit exceeded')
            else:
                raise DocumentError('native control iteration bound')
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        need(code == 0 and not stderr,
             'native document refusal: ' + stderr[:512].decode('ascii', errors='replace'))
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        raise
    finally:
        process.stderr.close()


def stream_pin(stream):
    before, hasher = identity(stream), hashlib.sha256()
    stream.seek(0)
    for _ in range(257):
        block = stream.read(FRAME_SOURCE)
        if not block:
            break
        hasher.update(block)
    need(stream.read(1) == b'' and identity(stream) == before, 'native descriptor changed')
    stream.seek(0)
    return hasher.hexdigest(), before


def run_native(native, wire, recovered, expected, output_limit):
    with open_regular(native, 16_777_216) as executable:
        before = stream_pin(executable)
        need(before[0] == expected, 'native runtime identity changed before execution')
        descriptor = executable.fileno()
        with recovered.open('xb') as output:
            process = subprocess.Popen(['/proc/self/fd/' + str(descriptor), str(wire)],
                pass_fds=(descriptor,), stdout=output, stderr=subprocess.PIPE,
                start_new_session=True, preexec_fn=partial(native_limits, output_limit),
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            child_result(process)
            output.flush()
            os.fsync(output.fileno())
        need(stream_pin(executable) == before, 'native decoder changed during execution')


def recovered_checked(path, body, sections):
    actual_hash, size = file_digest(path)
    need((actual_hash, size) == (body['source']['sha256'], body['source']['bytes']),
         'whole-file SHA256 or length mismatch')
    with open_regular(path, MAX_SOURCE) as stream:
        for frame in body['frames']:
            block = stream.read(frame['source_bytes'])
            need(digest(block) == frame['source_sha256'], 'recovered frame source integrity mismatch')
    need(source_spans(path, [{k: v for k, v in s.items() if k != 'sha256'} for s in sections]) == sections,
         'section source binding mismatch')


@contextmanager
def validated(archive_path, share, native):
    archive_path, native = Path(archive_path), native_path(native)
    root = scratch_root()
    with tempfile.TemporaryDirectory(prefix='document-decode-', dir=root) as folder:
        folder = Path(folder)
        wire, recovered = folder / 'frames.ft01', folder / 'source'
        reading_wire, reading = folder / 'reading.ft01', folder / 'reading.txt'
        with opened(archive_path) as (archive, names):
            body, package_id, sections, record = verified_metadata(archive, names, share, native)
            is_derived = body['reading'] is not None and body['reading']['mode'] == 'derived'
            frames = body['frames'] + (body['reading']['frames'] if is_derived else [])
            sizes = body['source']['bytes'] + (body['reading']['bytes'] if is_derived else 0)
            needed = identity(archive.fp)[2] + sizes + 32 + sum(f['wire_bytes'] + 20 for f in frames) + MAX_META
            reserve(root, needed)
            frame_stream(archive, body, wire)
            if is_derived:
                derived = {'source': body['reading'], 'frames': body['reading']['frames']}
                frame_stream(archive, derived, reading_wire)
            write_new(folder / 'reading.json', canonical(record))
        # Finish every ZIP check before execution or publication capability.
        expected = body['decoder']['native_sha256']
        run_native(native, wire, recovered, expected, body['source']['bytes'])
        recovered_checked(recovered, body, sections)
        wire.unlink()
        if is_derived:
            run_native(native, reading_wire, reading, expected, body['reading']['bytes'])
            recovered_checked(reading, derived, [])
            reading_wire.unlink()
        elif body['reading'] is not None:
            os.link(recovered, reading, follow_symlinks=False)
        if body['reading'] is not None:
            reading_module.utf8_checked(reading, record)
        yield recovered, body, package_id, sections


def result_for(body, package_id):
    return {'status': 'CHECKED', 'checked_scope': 'STRUCTURE_INTEGRITY_RECOVERED_BYTES_ONLY',
            'profile': PROFILE, 'package_id': package_id,
            'reading_view': None if body['reading'] is None else {k: v for k, v in body['reading'].items() if k != 'frames'},
            'source': body['source'], 'frame_count': len(body['frames']),
            'exact_recovery': 'WHOLE_FILE_SHA256_AND_FRAME_HASHES_CHECKED',
            'semantic_completeness': 'UNPROVEN', 'authentication': 'UNAUTHENTICATED',
            'execution_authority': 'NONE', 'decoder': body['decoder']}


def inspect_document(archive, share, native=None):
    with validated(archive, share, native) as (source, body, package_id, sections):
        return dict(result_for(body, package_id), sections=sections,
                    reading=reading_summary(loads(read_file(source.parent / 'reading.json'))))


def decode_document(archive, share, output, native=None):
    output = Path(output)
    need(not output.exists() and not output.is_symlink(), 'recovered destination already exists')
    with validated(archive, share, native) as (recovered, body, package_id, _):
        reserve(output.parent, body['source']['bytes'])
        with tempfile.TemporaryDirectory(prefix='.document-recovery-', dir=output.parent) as folder:
            stage = Path(folder) / 'source'
            with open_regular(recovered, MAX_SOURCE) as source, stage.open('xb') as target:
                for _ in range(MAX_FRAMES + 1):
                    block = source.read(FRAME_SOURCE)
                    if not block:
                        break
                    need(target.write(block) == len(block), 'short recovered write')
                target.flush()
                os.fsync(target.fileno())
            need(file_digest(stage) == (body['source']['sha256'], body['source']['bytes']), 'publication copy mismatch')
            os.link(stage, output, follow_symlinks=False)
        return result_for(body, package_id)


def read_span(archive, share, start, end, native=None):
    with validated(archive, share, native) as (recovered, body, _, _):
        integer(start, 0, body['source']['bytes']); integer(end, start, body['source']['bytes'])
        need(end - start <= MAX_SPAN, 'selected context byte limit; use full decode')
        with open_regular(recovered, MAX_SOURCE) as stream:
            stream.seek(start)
            result = stream.read(end - start)
        need(len(result) == end - start, 'selected span truncated')
        return result


def dependency_spans(sections, selected):
    mapping = {s['id']: s for s in sections}
    need(selected in mapping, 'unknown section')
    closure = {selected}
    for _ in range(len(sections)):
        closure.update(dep for name in tuple(closure) for dep in mapping[name]['dependencies'])
    intervals = sorted((mapping[name]['start'], mapping[name]['end']) for name in closure)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    need(sum(end - start for start, end in merged) <= MAX_SPAN,
         'section dependency closure exceeds context budget; use full decode')
    return merged


def read_section(archive, share, section, native=None):
    with validated(archive, share, native) as (recovered, _, _, sections):
        spans = dependency_spans(sections, section)
        result = bytearray()
        with open_regular(recovered, MAX_SOURCE) as stream:
            for start, end in spans:
                stream.seek(start)
                block = stream.read(end - start)
                need(len(block) == end - start, 'section dependency truncated')
                result.extend(block)
        return bytes(result)



def read_reading_segment(archive, share, selected, native=None):
    with validated(archive, share, native) as (source, body, package_id, _):
        need(body['reading'] is not None, 'no declared reading view; recover original source')
        record = loads(read_file(source.parent / 'reading.json'))
        matches = [s for s in record['segments'] if s['id'] == selected]
        need(len(matches) == 1, 'unknown reading segment')
        segment = matches[0]
        need(segment['end'] - segment['start'] <= MAX_SPAN, 'reading segment exceeds context budget')
        with open_regular(source.parent / 'reading.txt', reading_module.MAX_READING) as stream:
            stream.seek(segment['start'])
            data = stream.read(segment['end'] - segment['start'])
        need(len(data) == segment['end'] - segment['start'], 'reading segment truncated')
        return {'data': data, 'segment': segment, 'package_id': package_id,
                'source_sha256': body['source']['sha256'], 'reading_sha256': body['reading']['sha256'],
                'uncertainty': record['uncertainty'], 'interpretation': 'DERIVED_READING_NOT_ORIGINAL_BYTES'}


def decode_reading(archive, share, output, native=None):
    output = Path(output)
    need(not output.exists() and not output.is_symlink(), 'reading destination already exists')
    with validated(archive, share, native) as (source, body, package_id, _):
        need(body['reading'] is not None, 'no declared reading view')
        reserve(output.parent, body['reading']['bytes'])
        with tempfile.TemporaryDirectory(prefix='.reading-recovery-', dir=output.parent) as folder:
            stage = Path(folder) / 'reading.txt'
            with open_regular(source.parent / 'reading.txt', reading_module.MAX_READING) as origin, stage.open('xb') as target:
                for _ in range(reading_module.MAX_READING_FRAMES + 1):
                    block = origin.read(FRAME_SOURCE)
                    if not block:
                        break
                    need(target.write(block) == len(block), 'short reading write')
                target.flush(); os.fsync(target.fileno())
            need(file_digest(stage, reading_module.MAX_READING) ==
                 (body['reading']['sha256'], body['reading']['bytes']), 'reading publication copy mismatch')
            os.link(stage, output, follow_symlinks=False)
        return dict(result_for(body, package_id), reading_status='DERIVED_NOT_EXACT_SOURCE')



def list_reading_segments(archive, share, start=0, count=32, native=None):
    integer(count, 1, 64)
    with validated(archive, share, native) as (source, body, package_id, _):
        need(body['reading'] is not None, 'no declared reading view')
        record = loads(read_file(source.parent / 'reading.json'))
        integer(start, 0, len(record['segments']))
        end = min(start + count, len(record['segments']))
        return {'package_id': package_id, 'segments': record['segments'][start:end],
                'next': end if end < len(record['segments']) else None,
                'total': len(record['segments']), 'uncertainty': record['uncertainty']}


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
MODULE_EPOCHS = {'transport_document.py': SOURCE_EPOCH,
                 'transport_document_io.py': io_module.SOURCE_EPOCH,
                 'transport_document_archive.py': archive_module.SOURCE_EPOCH,
                 'transport_document_reading.py': reading_module.SOURCE_EPOCH}
