#!/usr/bin/env python3
"""Create/check/unpack one declared trusted decoder bundle; never run its native.

The resulting ZIP is also a Python zipapp for bounded, data-only verification
and extraction. Trust it separately from any meaning ZIP before running it.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import zipfile

MAX_ZIP = 4194304
MAX_META = 65536
PROFILE = {'system': 'Linux', 'machine': 'aarch64', 'python': '3.14.7',
           'libc': ['glibc', '2.43']}
HELD = {
    'document_native_decode': 'f26c6a6b4a4c8afa8a886eb2cf09d465f6f7eba6b57d48ddd589e2f1b5b0a5ef',
    'transport_document.py': 'f2b86ca3b6bf984114331bd3c49dbb2256106ded5658444b7bb183794620db6a',
    'transport_document_io.py': 'f8724d0ab7213d2641cbeec2baf40f1b0d878e148f5d764c025d352f65776d3a',
    'transport_document_archive.py': 'fe83bd6efd202521c92b2e1ab17bc04cd6d676bac85f57ce227bfa18fa442058',
    'transport_document_reading.py': 'c43b6e72d973ae03cd5c99c945b74f491d3fc7a3c7bfa6b0d3b57c99b9e6852a',
    'transport_document_cli.py': 'f8adbad6b33b9737f907d51446b27492317be785b05534f6473a21fc562d2e77',
    'LICENSE': 'e1d386e60be5de89247667ce05081ffb0716b8f14fd3e34d6033c6d2c14994ad',
}
NAMES = frozenset(HELD) | {'__main__.py', 'README.md', 'bundle.json'}
TRUST = 'Separately trust decoder software; digests do not authenticate authorship.'
README = b'''Declared document decoder software bundle, version 1

This is trusted SOFTWARE, separate from share.txt and meaning.zip (DATA).
Establish trust in the decoder bundle through a trusted source and independently
supplied whole-ZIP digest BEFORE running it. Digests are not authorship proof.
Never run or import code from meaning.zip. No user book bytes are in this bundle.

Required declared recipient profile: Linux aarch64, Python 3.14.7 standard
library, glibc 2.43 and its aarch64 loader. No GNAT install, media extractor,
OCR package, network or prior chat is required to DECODE a supplied package.
No claim of universal or already-tested cross-host portability is made.

From a private directory whose parent is trusted and not group/world-writable:
  python3 -I -S -B document-decoder.zip verify
  python3 -I -S -B document-decoder.zip unpack --out /private/fresh/decoder

The zipapp only verifies/unpacks its exact bounded whitelist and prints pins.
It never executes native code. Unpack is create-only; failure leaves evidence.
Then, using the separately supplied share.txt and meaning.zip:
  python3 -I -S -B /private/fresh/decoder/transport_document_cli.py inspect \
    --archive meaning.zip --share share.txt \
    --native /private/fresh/decoder/document_native_decode
  python3 -I -S -B /private/fresh/decoder/transport_document_cli.py decode \
    --archive meaning.zip --share share.txt \
    --native /private/fresh/decoder/document_native_decode --out recovered-book
Use reading for complete derived text, reading-index --start 0 --count 32 for a
bounded index, and reading-segment --id ID --out NEW_FILE for a selected unit.
All require the same archive/share/native arguments. Decode destinations are
create-only. Reading uncertainty is retained; extraction completeness is unproved.

The native ELF declares libc.so.6 and ld-linux-aarch64.so.1. This qualified
runtime was built with gprbuild -R; observed dynamic tags contain no RPATH or
RUNPATH. Trust the system loader/libraries and private extraction parent.
Those system libraries are not bundled or transitively proved here. The native
SHA and Python module pins must match the document manifest. LICENSE is the
repository MIT license. Formal native contracts do not prove all Python/ZIP/IO.
'''


class BundleError(ValueError):
    """Explicit bounded bundle refusal."""


def need(condition, message):
    if not condition:
        raise BundleError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_bounded(path, cap=MAX_ZIP):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, 'file type or byte bound')
        raw = os.read(fd, cap + 1)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
             for k in keys), 'file changed or short read')
        return raw
    finally:
        os.close(fd)


def profile():
    current = {'system': platform.system(), 'machine': platform.machine(),
               'python': platform.python_version(), 'libc': list(platform.libc_ver())}
    need(current == PROFILE, 'recipient platform profile mismatch')
    return current


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate bundle JSON key')
        result[key] = value
    return result


def manifest_for(payload):
    return {'format': 'transport/document-decoder-bundle/1', 'required_platform': profile(),
            'observed_kernel': os.uname().release, 'trust': TRUST,
            'files': {name: pin(raw) for name, raw in payload.items()}}


def collect(source_root, native):
    root = Path(source_root)
    payload = {}
    for name, expected in HELD.items():
        path = Path(native) if name == 'document_native_decode' else (
            root / 'LICENSE' if name == 'LICENSE' else root / 'tools' / name)
        raw = read_bounded(path)
        need(pin(raw)['sha256'] == expected, 'declared input pin mismatch: ' + name)
        payload[name] = raw
    own = read_bounded(Path(__file__), 32768)
    need(compile(own, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize) ==
         MAIN_CODE, 'loaded packager source drift')
    payload.update({'__main__.py': own, 'README.md': README})
    need(sum(map(len, payload.values())) <= MAX_ZIP, 'expanded bundle bound')
    return payload


class BoundedBuffer(io.BytesIO):
    def write(self, raw):
        need(self.tell() + len(raw) <= MAX_ZIP, 'archive byte bound')
        return super().write(raw)


def assemble(payload):
    payload = dict(payload, **{'bundle.json': canonical(manifest_for(payload))})
    need(set(payload) == NAMES and sum(map(len, payload.values())) <= MAX_ZIP, 'bundle roster or bound')
    buffer = BoundedBuffer()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(payload):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            mode = 0o100755 if name == 'document_native_decode' else 0o100644
            item.external_attr = mode << 16
            archive.writestr(item, payload[name])
    return buffer.getvalue()


def zip_entry(raw, info, cursor):
    name = info.filename
    mode = 0o100755 if name == 'document_native_decode' else 0o100644
    need(name in NAMES and name == info.orig_filename, 'unsupported or unsafe bundle member')
    need(info.header_offset == cursor and info.create_system == 3 and
         info.external_attr == mode << 16, 'bundle layout or regular mode')
    need(info.compress_type == zipfile.ZIP_STORED and info.flag_bits == 0 and
         info.extra == info.comment == b'' and info.internal_attr == 0 and
         info.date_time == (1980, 1, 1, 0, 0, 0), 'bundle entry options')
    need(0 < info.file_size == info.compress_size <= MAX_ZIP, 'bundle entry byte bound')
    head = struct.unpack('<4s5H3I2H', raw[cursor:cursor + 30])
    encoded = name.encode('ascii')
    need(head[:6] == (b'PK\x03\x04', 20, 0, 0, 0, 33) and
         head[6:9] == (info.CRC, info.file_size, info.file_size) and
         head[9:] == (len(encoded), 0) and raw[cursor + 30:cursor + 30 + len(encoded)] == encoded,
         'bundle local header mismatch')
    return cursor + 30 + len(encoded) + info.file_size


def loaded_bundle(path):
    raw = read_bounded(path)
    need(len(raw) >= 22, 'truncated bundle')
    end = struct.unpack('<4s4H2IH', raw[-22:])
    need(end[:5] == (b'PK\x05\x06', 0, 0, len(NAMES), len(NAMES)) and
         end[7] == 0 and end[5] + end[6] == len(raw) - 22, 'bundle directory bound')
    payload, cursor, expanded = {}, 0, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        need(len(infos) == len(NAMES), 'bundle member count')
        for info in infos:
            need(info.filename not in payload, 'duplicate bundle member')
            cursor = zip_entry(raw, info, cursor)
            expanded += info.file_size
            need(cursor <= end[6] and expanded <= MAX_ZIP, 'bundle expanded/layout bound')
            payload[info.filename] = archive.read(info)
    need(set(payload) == NAMES and cursor == end[6], 'missing bundle member')
    metadata = payload.pop('bundle.json')
    need(len(metadata) <= MAX_META, 'bundle metadata bound')
    manifest = json.loads(metadata, object_pairs_hook=unique,
                          parse_constant=lambda _value: need(False, 'nonfinite bundle JSON'))
    need(type(manifest) is dict and set(manifest) ==
         {'format', 'required_platform', 'observed_kernel', 'trust', 'files'}, 'bundle manifest fields')
    need(manifest['format'] == 'transport/document-decoder-bundle/1' and
         manifest['required_platform'] == profile() and manifest['trust'] == TRUST,
         'bundle profile or trust mismatch')
    need(type(manifest['observed_kernel']) is str and len(manifest['observed_kernel']) <= 128,
         'kernel observation bound')
    need(type(manifest['files']) is dict and set(manifest['files']) == set(payload), 'bundle pin roster')
    for value in manifest['files'].values():
        need(type(value) is dict and set(value) == {'bytes', 'sha256'} and
             type(value['bytes']) is int and 0 < value['bytes'] <= MAX_ZIP and
             type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
             'bundle pin schema')
    need(manifest['files'] == {name: pin(data) for name, data in payload.items()}, 'bundle file pin mismatch')
    need(all(pin(payload[name])['sha256'] == value for name, value in HELD.items()),
         'decoder epoch pin mismatch')
    return raw, payload, metadata, manifest


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), 'short bundle write')
        os.fsync(fd)
    finally:
        os.close(fd)


def create_bundle(source_root, native, output):
    output = Path(output)
    need(not os.path.lexists(output), 'bundle destination already exists')
    raw = assemble(collect(source_root, native))
    need(len(raw) <= MAX_ZIP, 'archive byte bound')
    write_new(output, raw)
    checked, _payload, _metadata, _manifest = loaded_bundle(output)
    need(checked == raw, 'bundle publication readback mismatch')
    collect(source_root, native)
    return {'status': 'CHECKED_DECLARED_DECODER_BUNDLE', 'archive': pin(raw),
            'required_platform': profile(), 'native_sha256': HELD['document_native_decode']}


def unpack_bundle(archive, destination):
    raw, payload, metadata, _manifest = loaded_bundle(archive)
    destination = Path(destination).absolute()
    parent = destination.parent
    info = parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
         'trusted private extraction parent required')
    need(not os.path.lexists(destination), 'unpack destination already exists')
    destination.mkdir(mode=0o700)
    payload['bundle.json'] = metadata
    for name, data in payload.items():
        path = destination / name
        write_new(path, data)
        need(read_bounded(path) == data, 'unpack readback mismatch')
        path.chmod(0o755 if name == 'document_native_decode' else 0o644)
    current = parent.lstat()
    need(all(getattr(current, key) == getattr(info, key) for key in
             ('st_dev', 'st_ino', 'st_uid', 'st_mode')), 'extraction parent changed')
    return {'status': 'CHECKED_UNPACKED_PAYLOAD_NOT_EXECUTED', 'archive': pin(raw),
            'files': len(payload), 'destination': str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    create.add_argument('--native', type=Path, required=True)
    create.add_argument('--out', type=Path, required=True)
    for name in ('verify', 'unpack'):
        command = commands.add_parser(name)
        command.add_argument('archive', type=Path, nargs='?', default=Path(sys.argv[0]))
        if name == 'unpack':
            command.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'create':
            result = create_bundle(args.source_root, args.native, args.out)
        elif args.command == 'unpack':
            result = unpack_bundle(args.archive, args.out)
        else:
            raw, _payload, _metadata, manifest = loaded_bundle(args.archive)
            result = {'status': 'CHECKED_DECLARED_DECODER_BUNDLE', 'archive': pin(raw),
                      'required_platform': manifest['required_platform']}
        encoded = canonical(result)
        need(len(encoded) <= 8192, 'receipt bound')
        print(encoded.decode())
        return 0
    except (BundleError, OSError, ValueError, SyntaxError, RecursionError,
            zipfile.BadZipFile, struct.error) as error:
        print('BUNDLE_REFUSED: ' + str(error)[:512], file=sys.stderr)
        return 2


MAIN_CODE = sys._getframe().f_code
if __name__ == '__main__':
    sys.exit(main())
