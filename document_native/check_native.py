"""Independent literal FT01/STB1 fixtures; bounded native subprocess checks."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
import qualify_native as qualify

ROOT = qualify.ROOT
OUT = qualify.OUT
BINARY = OUT / 'attempt03/bin/document_native_decode'


def wire(data):
    if len(data) > 65536:
        raise ValueError('fixture frame bound')
    chunks = [b'STB1']
    for start in range(0, len(data), 255):
        token = data[start:start + 255]
        chunks.append(bytes([0, len(token)]) + token)
    return b''.join(chunks) + b'\xff'


def record(data, ordinal=0, offset=0, size=None, encoded=None):
    payload = wire(data) if encoded is None else encoded
    count = len(data) if size is None else size
    return struct.pack('>IQII', ordinal, offset, count, len(payload)) + payload


def header(total, count):
    return b'FT01' + struct.pack('>QI', total, count)


def framed(data):
    count = (len(data) + 65535) // 65536
    parts = [header(len(data), count)]
    for ordinal in range(count):
        offset = ordinal * 65536
        parts.append(record(data[offset:offset + 65536], ordinal, offset))
    return b''.join(parts)


def positives():
    binary = bytes(range(256)) * 512 + b'\x00\xff\r\nEND'
    return [('empty', b''), ('one', b'Z'), ('all_bytes', bytes(range(256))),
            ('exact_frame', bytes(range(256)) * 256),
            ('cross_three', binary)]


def negatives():
    full = b'A' * 65536
    first = record(full)
    last = record(b'Z', 1, 65536)
    good = header(65537, 2) + first + last
    cases = [('magic', b'NOPE' + header(0, 0)[4:]),
             ('total_bound', header(1073741825, 16384)),
             ('count_bound', header(0, 16385)),
             ('count_mismatch', header(1, 0)),
             ('empty_with_record', header(0, 0) + record(b'A')),
             ('empty_count_one', header(0, 1)),
             ('zero_source', header(1, 1) + record(b'', size=0)),
             ('short_nonfinal', header(65537, 2) + record(b'A')),
             ('long_final', header(1, 1) + record(b'AB')),
             ('initial_ordinal', header(1, 1) + record(b'A', 1)),
             ('initial_offset', header(1, 1) + record(b'A', offset=1)),
             ('gap', header(65537, 2) + first + record(b'Z', 1, 65537)),
             ('overlap', header(65537, 2) + first + record(b'Z', 1, 65535)),
             ('duplicate', header(65537, 2) + first + first),
             ('swapped', header(65537, 2) + last + first),
             ('omitted', header(65537, 2) + first),
             ('wire_zero', header(1, 1) + record(b'A', encoded=b'')),
             ('wire_bound', header(1, 1) + struct.pack('>IQII', 0, 0, 1, 131073)),
             ('size_bound', header(1, 1) + record(b'A', size=65537)),
             ('offset_bound', header(1, 1) + record(b'A', offset=1073741825)),
             ('ordinal_bound', header(1, 1) + record(b'A', 16385)),
             ('used_mismatch', header(1, 1) + record(b'AB', size=1)),
             ('decoder_header', header(1, 1) + record(b'A', encoded=b'NOPE\xff')),
             ('decoder_opcode', header(1, 1) + record(b'A', encoded=b'STB1\x03\xff')),
             ('decoder_missing_end', header(1, 1) + record(b'A', encoded=b'STB1\x00\x01A')),
             ('decoder_trailing', header(1, 1) + record(b'A', encoded=b'STB1\x00\x01A\xffZ')),
             ('trailing_ft01', good + b'Z')]
    for length in [0, 3, 4, 7, 12, 15, 16, 19, 35, 36, len(good) - 1]:
        cases.append(('truncated_' + str(length), good[:length]))
    return cases


def run_case(folder, name, payload, expected, deadline):
    source = folder / (name + '.ft01')
    source.write_bytes(payload)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('native test suite deadline')
    with (folder / (name + '.stdout')).open('xb') as stdout:
        with (folder / (name + '.stderr')).open('xb') as stderr:
            result = subprocess.run([str(BINARY), str(source)], stdout=stdout,
                                    stderr=stderr, timeout=min(3, remaining),
                                    check=False, preexec_fn=qualify.limits)
    output = (folder / (name + '.stdout')).read_bytes()
    error = (folder / (name + '.stderr')).read_bytes()
    valid = ((result.returncode == 0 and output == expected and not error)
             if expected is not None else
             (result.returncode != 0 and error == b'FT01 input refused\n'))
    entry = {'name': name, 'returncode': result.returncode, 'PASS': valid,
             'input_sha256': hashlib.sha256(payload).hexdigest(),
             'output_bytes': len(output), 'stderr_bytes': len(error)}
    (folder / (name + '.json')).write_text(json.dumps(entry) + '\n')
    if not valid:
        raise ValueError('native fixture FAILED: ' + name)
    qualify.footprint()
    return entry


def main():
    folder = OUT / 'native-controls01'
    folder.mkdir()
    mapping = qualify.sources(folder / 'sources.zip')
    binary_pin = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    results = []
    deadline = time.monotonic() + 60
    try:
        for name, data in positives():
            results.append(run_case(folder, name, framed(data), data, deadline))
        for name, payload in negatives():
            results.append(run_case(folder, name, payload, None, deadline))
    finally:
        source_after = {p: hashlib.sha256((ROOT.parent / p).read_bytes()).hexdigest()
                        for p in mapping}
        stable = mapping == source_after and binary_pin == hashlib.sha256(BINARY.read_bytes()).hexdigest()
        receipt = {'results': results, 'sources': mapping, 'identity_stable': stable,
                   'executable': str(BINARY), 'executable_sha256': binary_pin,
                   'footprint': qualify.footprint()}
        (folder / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not stable:
        raise ValueError('source/binary identity changed')
    print(json.dumps({'PASS': True, 'cases': len(results), 'executable_sha256': binary_pin}))


if __name__ == '__main__':
    main()
