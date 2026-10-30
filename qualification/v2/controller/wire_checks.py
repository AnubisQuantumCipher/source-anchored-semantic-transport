"""Closed byte-result checks against pre-existing literal oracles; no policy model."""
import hashlib
import json
from pathlib import Path
import struct
from document_build.common import bounded_names, need, read_bytes

MANIFESTS = ('literal-oracle.json', 'wire-epoch-02.json', 'wire-epoch-03.json',
             'wire-epoch-04.json', 'wire-epoch-05.json')
OUTPUT_BYTES = 2725


def oracle_files(root):
    files, cases = {}, []
    for name in MANIFESTS:
        raw = read_bytes(root / name, 131072)
        files[name] = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        need(type(data) is dict and type(data.get('cases')) is list, 'oracle manifest shape')
        cases.extend(data['cases'])
    need(len(cases) == 51, 'exact frozen51 literal cases required')
    ids = []
    for case in cases:
        need(type(case) is dict and type(case.get('input')) is str, 'literal input row')
        name = case['input']
        need(Path(name).name == name and name.endswith('.stn'), 'literal basename')
        raw = read_bytes(root / name, 1048577)
        need(len(raw) == case['bytes'] and hashlib.sha256(raw).hexdigest() == case['sha256'],
             'literal input changed')
        files[name] = case['sha256']
        ids.append(case['id'])
        expected = case['expected']
        if 'exact_output' in expected:
            output = expected['exact_output']
            need(Path(output).name == output and output.endswith('.str'), 'output basename')
            value = read_bytes(root / output, OUTPUT_BYTES)
            need(len(value) == OUTPUT_BYTES and hashlib.sha256(value).hexdigest() ==
                 expected['output_sha256'], 'literal output changed')
            files[output] = expected['output_sha256']
    need(len(set(ids)) == 51, 'duplicate literal case ID')
    return files, cases


def output_fields(raw):
    need(type(raw) is bytes and len(raw) == OUTPUT_BYTES, 'exactSTR1 output size')
    need(raw[:5] == b'STR1\x01', 'STR1 magic/version')
    disposition, reason = raw[5], int.from_bytes(raw[6:8], 'big')
    need(disposition <= 2 and reason in (0, 1, 2, 3, *range(10, 24)), 'closed result codes')
    fields = {'disposition': disposition, 'reason_code': reason, 'output_bytes': len(raw),
        'round': raw[344], 'claim_total': int.from_bytes(raw[345:347], 'big'),
        'probe_total': int.from_bytes(raw[347:349], 'big'),
        'accepted_current': int.from_bytes(raw[349:351], 'big'),
        'retained_blocking_events': int.from_bytes(raw[351:353], 'big'),
        'authority': raw[353], 'scope': raw[354], 'policy_state': raw[355],
        'has_native_session': raw[356], 'documentary_first': raw[357],
        'failure_first_byte': raw[421], 'old_result_first': raw[677],
        'current_result_first': raw[677 + (max(raw[344], 1) - 1) * 256] if raw[344] <= 8 else 0}
    need(fields['authority'] == 0 and fields['scope'] <= 1 and fields['has_native_session'] <= 1,
         'authority/scope/session field')
    need(fields['policy_state'] in (*range(7), 255), 'closed policy state')
    need(fields['round'] <= 8 and fields['claim_total'] <= 64 and fields['probe_total'] <= 256
         and fields['accepted_current'] <= fields['probe_total']
         and fields['retained_blocking_events'] <= 2048, 'counter bounds')
    need(all(value <= 3 for value in raw[357:421]) and
         all(value <= 2 for value in raw[677:2725]), 'closed documentary/result matrix')
    if not fields['has_native_session']:
        need(raw[8:353] == bytes(345) and fields['policy_state'] == 255 and
             raw[357:421] == bytes([3]) * 64 and raw[421:] == bytes(2304),
             'canonical no-session record')
    if disposition == 2:
        need(reason == 0 and fields['scope'] == 1 and fields['policy_state'] == 3 and
             fields['has_native_session'] == 1, 'qualified result shape')
    else:
        need(fields['scope'] == 0 and (reason in (1, 2, 3) if disposition == 1
             else reason in range(10, 24)), 'non-success reason/scope')
    return fields


def check_output(raw, stderr, code, expected=None):
    need(stderr == b'', 'native stderr must be empty')
    fields = output_fields(raw)
    need(code == (0 if fields['disposition'] == 2 else 2 if fields['disposition'] == 1 else 3),
         'exit/disposition disagreement')
    if expected is None:
        need(fields['disposition'] == 0 and code == 3, 'strict prefix must refuse')
    else:
        for key, value in expected.items():
            if key in ('exact_output', 'output_sha256', 'stderr_bytes', 'exit', 'operations'):
                continue
            need(key in fields and fields[key] == value, 'literal field mismatch:' + key)
        need(code == expected['exit'], 'literal exit mismatch')
        need(len(stderr) == expected['stderr_bytes'], 'literal stderr mismatch')
        if 'output_sha256' in expected:
            need(hashlib.sha256(raw).hexdigest() == expected['output_sha256'], 'literal exact output')
    return fields


def stack_inventory(folder):
    paths = bounded_names(folder, 128)
    selected = [path for path in paths if path.suffix == '.su']
    need({path.name for path in selected} == {'sentinel_policy.su', 'sentinel_wire_io.su',
         'sentinel_wire_main.su', 'b__sentinel_wire_main.su'}, 'fixed four stack reports required')
    rows = []
    for path in sorted(selected):
        text = read_bytes(path, 131072).decode('ascii')
        lines = text.splitlines()
        need(1 <= len(lines) <= 256, 'stack report line bound')
        for line in lines:
            fields = line.split('\t')
            need(len(fields) == 3 and fields[1].isdigit() and fields[2] in
                 ('static', 'dynamic,bounded'), 'unbounded/unknown stack record')
            count = int(fields[1])
            need(count <= 1048576, 'individual stack frame exceeds1MiB')
            rows.append({'location': fields[0], 'bytes': count, 'kind': fields[2]})
    need(any('sentinel_wire_io' in row['location'] for row in rows), 'wire stack report absent')
    return {'records': rows, 'scope': 'individual compiler frame reports only; aggregate call-stack UNPROVEN',
            'maximum_frame_bytes': max(row['bytes'] for row in rows)}


def elf_inventory(path):
    raw = read_bytes(path, 8388608)
    need(len(raw) >= 64 and raw[:4] == b'\x7fELF' and raw[4] == 2 and raw[5] in (1, 2), 'ELF64 required')
    order = '<' if raw[5] == 1 else '>'
    header = struct.unpack_from(order + 'HHIQQQIHHHHHH', raw, 16)
    offset, size, count = header[4], header[8], header[9]
    need(size == 56 and 1 <= count <= 128 and offset + size * count <= len(raw), 'ELF program headers')
    loads = []
    for index in range(count):
        row = struct.unpack_from(order + 'IIQQQQQQ', raw, offset + size * index)
        if row[0] == 1:
            need(row[5] <= row[6] and row[2] + row[5] <= len(raw), 'ELF load bounds')
            loads.append({'file_bytes': row[5], 'memory_bytes': row[6], 'flags': row[1]})
    need(loads and sum(row['memory_bytes'] for row in loads) <= 16777216, 'ELF mapped image bound')
    return {'file_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'loads': loads,
            'scope': 'ELF declared load segments only; runtime heap/stack not represented'}


def operation_count(raw):
    """Count only framing for an independently frozen complete maximum transcript."""
    position = 8
    for count in range(1, 2842):
        need(position + 5 <= len(raw), 'frame header missing')
        length = int.from_bytes(raw[position + 1:position + 5], 'big')
        need(length <= 660 and position + 5 + length <= len(raw), 'frame payload bound')
        position += 5 + length
        if position == len(raw):
            return count
    raise ValueError('frame operation count bound')


def completed_in_time(elapsed, observed, deadline, seconds=3):
    need(0 < seconds <= 120 and 0 <= elapsed <= seconds and observed <= deadline,
         'late phase completion refused')
