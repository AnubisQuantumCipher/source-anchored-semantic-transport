"""Streaming stored-ZIP profile. Never extracts or executes supplied entries."""
from contextlib import contextmanager
import struct
import sys
import zipfile

from transport_document_io import (FRAME_WIRE, MAX_ARCHIVE, MAX_FRAMES, MAX_META,
                                   DocumentError, identity, loaded_epoch, need, open_regular)

META_NAMES = frozenset(('manifest.json', 'formula.txt', 'lexicon.json', 'lexicon.md',
                        'operators.json', 'structure.json', 'README.md', 'reading.json'))


def safe_name(name):
    if name in META_NAMES:
        return True
    prefix = 'reading/frames/' if name.startswith('reading/') else 'frames/'
    number = name[len(prefix):-5]
    return (name.startswith(prefix) and name.endswith('.stb1') and len(number) == 5 and
            number.isascii() and number.isdigit())


def directory(stream):
    size = identity(stream)[2]
    need(22 <= size <= MAX_ARCHIVE, 'ZIP size or truncation')
    stream.seek(size - 22)
    end = struct.unpack('<4s4H2IH', stream.read(22))
    need(end[0] == b'PK\x05\x06' and end[1:3] == (0, 0) and end[7] == 0,
         'ZIP single disk, no comments or trailing bytes required')
    need(len(META_NAMES) <= end[3] == end[4] <= MAX_FRAMES + 512 + len(META_NAMES),
         'ZIP count or ZIP64 unsupported')
    need(end[5] <= MAX_META and end[5] + end[6] == size - 22,
         'ZIP directory byte extent or budget')
    return end[6], end[3]


def entry(stream, info, cursor):
    need(info.filename == info.orig_filename and safe_name(info.filename), 'unsafe ZIP name')
    need(info.header_offset == cursor, 'overlap, gap or reordered ZIP local headers')
    need(info.create_system == 3 and info.external_attr == 0o100644 << 16,
         'ZIP must contain regular files, no links')
    need(info.compress_type == zipfile.ZIP_STORED and info.flag_bits == 0,
         'compressed, encrypted or descriptor ZIP unsupported')
    need(info.extra == info.comment == b'' and info.internal_attr == 0 and
         info.create_version == info.extract_version == 20 and info.volume == info.reserved == 0,
         'unsupported ZIP metadata or version')
    cap = FRAME_WIRE if info.filename.endswith('.stb1') else MAX_META
    need(0 < info.file_size == info.compress_size <= cap, 'ZIP entry size or expansion limit')
    stream.seek(cursor)
    raw = stream.read(30)
    need(len(raw) == 30, 'truncated ZIP header')
    head = struct.unpack('<4s5H3I2H', raw)
    name = info.filename.encode('ascii')
    need(head[:4] == (b'PK\x03\x04', 20, 0, 0) and
         head[6:9] == (info.CRC, info.file_size, info.file_size), 'ZIP header mismatch')
    need(head[4:6] == (0, 33) and info.date_time == (1980, 1, 1, 0, 0, 0), 'ZIP timestamp')
    need(head[9:] == (len(name), 0) and stream.read(len(name)) == name, 'ZIP local name')
    return cursor + 30 + len(name) + info.file_size


def check_layout(stream, archive, start, count):
    infos, cursor, meta, names = archive.infolist(), 0, 0, set()
    need(len(infos) == count, 'ZIP directory count mismatch')
    for info in infos:
        need(info.filename not in names, 'duplicate ZIP entry')
        cursor = entry(stream, info, cursor)
        need(cursor <= start, 'ZIP entry overlaps directory')
        names.add(info.filename)
        if info.filename in META_NAMES:
            meta += info.file_size
    need(cursor == start and META_NAMES <= names and meta <= MAX_META, 'missing ZIP entry or metadata budget')
    return names


@contextmanager
def opened(path):
    try:
        with open_regular(path, MAX_ARCHIVE) as stream:
            before = identity(stream)
            start, count = directory(stream)
            with zipfile.ZipFile(stream, 'r', allowZip64=False) as archive:
                names = check_layout(stream, archive, start, count)
                yield archive, names
            need(identity(stream) == before, 'ZIP changed during reading')
    except (zipfile.BadZipFile, EOFError, NotImplementedError, RuntimeError, struct.error) as error:
        raise DocumentError('invalid document ZIP: ' + str(error)[:128]) from error


def read_entry(archive, name, cap):
    info = archive.getinfo(name)
    need(info.file_size <= cap, 'entry read budget')
    with archive.open(info) as stream:
        data = stream.read(cap + 1)
    need(len(data) == info.file_size, 'entry truncation or expansion')
    return data


def put(archive, name, data):
    need(safe_name(name), 'internal unsupported ZIP name')
    need(type(data) is bytes and 0 < len(data) <= MAX_META, 'entry write byte limit')
    need(archive.fp.tell() + len(data) + 30 + len(name) + MAX_META <= MAX_ARCHIVE,
         'ZIP write budget including directory reserve')
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
