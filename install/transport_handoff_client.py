#!/usr/bin/env python3
"""One fixed receiving session, bounded JSON intake, unchanged reader semantics.

The launcher and host are trusted bootstrap code. Disk hashes do not attest
already executing code or exclude hostile processes with the same user ID.
"""

import argparse
import os
from pathlib import Path
import resource
import select
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

BINDING_CAP, STDIN_SECONDS, MAX_READS = 16384, 5, 1024


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--expect-binding-sha256', required=True)
    request = parser.add_mutually_exclusive_group(required=True)
    request.add_argument('--request-json')
    request.add_argument('--stdin', action='store_true')
    request.add_argument('--request-file', type=Path)
    parser.add_argument('--expect-request-sha256')
    return parser.parse_args()


def absolute(value):
    require(type(value) is str and 0 < len(value.encode()) < 4096, 'absolute path byte bound')
    path = Path(value)
    require(path.is_absolute() and str(path) == value and '..' not in path.parts,
            'canonical absolute path required')
    return path


def binding(path, held):
    raw = read_regular(path, BINDING_CAP)
    require(sha(raw) == inputs.digest(held), 'externally held client binding differs')
    value = inputs.json_value(raw, BINDING_CAP)
    inputs.fields(value, ('schema', 'manifest', 'session', 'reader', 'python', 'client'))
    require(value['schema'] == 'transport/handoff-client/1', 'unsupported client binding')
    for key in ('manifest', 'reader', 'python', 'client'):
        record = value[key]
        inputs.fields(record, ('path', 'bytes', 'sha256'))
        inputs.checked_file(absolute(record['path']), record)
    require(absolute(value['client']['path']) == Path(__file__).absolute(), 'client origin differs')
    require(absolute(value['python']['path']) == Path(sys.executable).resolve(), 'client Python differs')
    reader = Path(__file__).absolute().with_name('transport_handoff_reader.py')
    require(absolute(value['reader']['path']) == reader, 'reader origin differs')
    manifest = inputs.json_value(read_regular(absolute(value['manifest']['path']), inputs.REQUEST_CAP))
    require(manifest.get('python') == value['python'], 'client and reader Python pins differ')
    require(type(manifest.get('helpers')) is list and value['reader'] in manifest['helpers'],
            'reader missing from manifest helper closure')
    inputs.bootstrap(manifest)
    session = absolute(value['session'])
    content = absolute(manifest['content']['root'])
    require(not path.absolute().is_relative_to(session) and not path.absolute().is_relative_to(content),
            'binding overlaps receiving session or source content')
    return value, raw


def intake(args):
    if args.request_file is not None:
        require(args.expect_request_sha256 is not None, '--request-file requires --expect-request-sha256')
        expected = inputs.digest(args.expect_request_sha256)
        raw = read_regular(args.request_file, inputs.REQUEST_CAP)
        require(sha(raw) == expected, 'externally held request digest differs')
        return raw, len(raw), ''
    require(args.expect_request_sha256 is None, '--expect-request-sha256 requires --request-file')
    if args.request_json is not None:
        raw = args.request_json.encode('utf-8')
        return raw[:inputs.REQUEST_CAP + 1], len(raw), ''
    data, deadline = bytearray(), time.monotonic() + STDIN_SECONDS
    try:
        descriptor = sys.stdin.fileno()
        for _ in range(MAX_READS):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                return bytes(data), -1, 'stdin deadline exceeded; total length unknown'
            block = os.read(descriptor, min(8192, inputs.REQUEST_CAP + 1 - len(data)))
            if not block:
                return bytes(data), len(data), ''
            data.extend(block)
            if len(data) > inputs.REQUEST_CAP:
                return bytes(data), -1, 'stdin byte bound exceeded; total length unknown'
        return bytes(data), -1, 'stdin read-count bound exceeded; total length unknown'
    except (OSError, ValueError) as error:
        return bytes(data), -1, ('stdin refused: ' + str(error))[:256]


def refusal(reason, process=None, dispatched=False):
    result = {'reason': str(reason)[:256], 'complete_reader_response': False, 'authority': 'NONE',
              'reader_action_may_be_recorded': dispatched}
    if process is not None:
        result.update(process_status=process['status'], exit_code=process['exit_code'],
                      stdout=inputs.record(process['stdout']), stderr=inputs.record(process['stderr']))
    return canonical({'schema': 'transport/handoff-client-refusal/1', 'status': 'REFUSED',
                      'result': result}) + b'\n', 1


def invoke(value, raw, input_bytes, error):
    with tempfile.TemporaryDirectory(prefix='transport-handoff-client-') as temporary:
        root, request = Path(temporary), Path(temporary) / 'request.json'
        write_new(request, raw, inputs.REQUEST_CAP + 1)
        argv = [value['python']['path'], '-I', '-S', '-B', '-Werror', value['reader']['path'],
                '--manifest', value['manifest']['path'], '--expect-manifest-sha256', value['manifest']['sha256'],
                '--session', value['session'], '--request', str(request), '--worker',
                '--input-bytes', str(input_bytes), '--request-error', error]
        result = run_bounded(argv, root, inputs.ENV, timeout=30, cap=inputs.CAP)
    if result['status'] not in ('SUCCESS', 'EXIT_NONZERO') or result['stderr'] or not result['stdout']:
        return refusal('bounded reader process refused', result, dispatched=True)
    answer = result['stdout']
    require(answer.endswith(b'\n') and len(answer) <= inputs.CAP, 'reader response framing differs')
    parsed = inputs.json_value(answer, inputs.CAP)
    require(parsed.get('schema') == 'transport/handoff-response/1', 'reader response schema differs')
    require(parsed.get('status') in ('OK', 'REFUSED'), 'reader response status differs')
    expected = 0 if parsed['status'] == 'OK' else 1
    require(result['exit_code'] == expected, 'reader status and exit disagree')
    return answer, expected


def main():
    args = arguments()
    dispatched = False
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (inputs.CAP, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        value, held_bytes = binding(args.binding, args.expect_binding_sha256)
        raw, input_bytes, error = intake(args)
        dispatched = True
        answer, status = invoke(value, raw, input_bytes, error)
        try:
            require(binding(args.binding, args.expect_binding_sha256)[1] == held_bytes, 'binding bytes differ')
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
            raise ValueError('Post-call integrity refusal; reader action may already be recorded: '
                             + str(error)[:160]) from error
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        answer, status = refusal(error, dispatched=dispatched)
    sys.stdout.buffer.write(answer)
    return status


if __name__ == '__main__':
    sys.exit(main())
