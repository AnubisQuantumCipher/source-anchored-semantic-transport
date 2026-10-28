"""Small stored-ZIP profile: bounded reads, no extraction, no decompression or code."""

import io
import struct
import zipfile

from transport_schema import require
from transport_wire import MAX_WIRE, TransportError

NAMES = frozenset(('manifest.json', 'codec.json', 'index.json', 'formula.txt', 'README.md'))


def directory(data: bytes) -> int:
    require(type(data) is bytes and 22 <= len(data) <= MAX_WIRE, 'ZIP byte budget or truncation')
    end = struct.unpack('<4s4H2IH', data[-22:])
    require(end[0] == b'PK\x05\x06' and end[1:3] == (0, 0) and end[7] == 0,
            'ZIP requires a single disk and no trailing data or comments')
    require(end[3] == end[4] == len(NAMES), 'ZIP entry count mismatch or unsupported ZIP64')
    require(end[5] + end[6] == len(data) - 22, 'ZIP directory extent mismatch')
    require(data[end[6]:end[6] + 4] == b'PK\x01\x02', 'ZIP central directory missing')
    return end[6]


def entry(info: zipfile.ZipInfo, data: bytes, cursor: int) -> int:
    require(info.filename == info.orig_filename and info.filename in NAMES, 'unsafe or unsupported ZIP path')
    require(info.header_offset == cursor and cursor + 30 <= len(data), 'ZIP local layout mismatch')
    require(info.create_system == 3 and info.external_attr == (0o100644 << 16), 'ZIP entry must be a regular file')
    require(info.compress_type == zipfile.ZIP_STORED and info.flag_bits == 0,
            'compressed, encrypted or descriptor ZIP entries are unsupported')
    require(info.extra == info.comment == b'' and info.internal_attr == 0, 'unsupported ZIP metadata')
    require(info.create_version == info.extract_version == 20, 'unsupported ZIP entry version')
    require(info.volume == 0 and info.reserved == 0, 'unsupported ZIP central disk or reserved version field')
    require(info.file_size == info.compress_size and 0 < info.file_size <= MAX_WIRE, 'ZIP entry expansion budget exceeded')
    local = struct.unpack('<4s5H3I2H', data[cursor:cursor + 30])
    name = info.filename.encode('ascii')
    require(local[:4] == (b'PK\x03\x04', 20, 0, 0) and local[6:9] == (info.CRC, info.file_size, info.file_size),
            'ZIP local/central identity mismatch')
    require(local[4:6] == (0, 33) and info.date_time == (1980, 1, 1, 0, 0, 0), 'unsupported ZIP timestamp')
    require(local[9:] == (len(name), 0) and data[cursor + 30:cursor + 30 + len(name)] == name,
            'ZIP local name or metadata mismatch')
    return cursor + 30 + len(name) + info.file_size


def read_archive(data: bytes) -> dict[str, bytes]:
    start = directory(data)
    result, cursor, expanded = {}, 0, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r', allowZip64=False) as archive:
            infos = archive.infolist()
            require(len(infos) == len(NAMES), 'ZIP directory entry count mismatch')
            for info in infos:
                require(info.filename not in result, 'duplicate ZIP entry')
                cursor = entry(info, data, cursor)
                expanded += info.file_size
                require(expanded <= MAX_WIRE and cursor <= start, 'ZIP total expansion budget exceeded')
                with archive.open(info, 'r') as stream:
                    value = stream.read(info.file_size + 1)
                require(len(value) == info.file_size, 'truncated ZIP entry')
                result[info.filename] = value
            require(cursor == start and set(result) == NAMES, 'ZIP entries missing or overlapping')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as error:
        raise TransportError('invalid or unsupported ZIP') from error
    return result


def write_archive(entries: dict[str, bytes]) -> bytes:
    require(set(entries) == NAMES, 'ZIP requires exactly the declared profile entries')
    require(all(type(value) is bytes and value for value in entries.values()), 'ZIP entries must be nonempty immutable bytes')
    require(sum(len(value) for value in entries.values()) <= MAX_WIRE, 'ZIP total content budget exceeded')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    data = buffer.getvalue()
    require(len(data) <= MAX_WIRE, 'ZIP output budget exceeded including headers')
    require(read_archive(data) == entries, 'ZIP readback mismatch')
    return data
