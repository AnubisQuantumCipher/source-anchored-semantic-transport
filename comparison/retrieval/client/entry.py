#!/usr/bin/env python3
"""Adaptive data-only retrieval with externally anchored, finite call records.

One fresh bounded worker handles each request. The caller retains the newest
head independently; disk hashes do not authenticate users or attest this host.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
RETRIEVAL = HERE.parent
PROJECT = RETRIEVAL.parents[1]
ADAPTER_SHA = '83bde7b42d687877b677b1649741a7f848e9a4d65da3b76838d9a445bb6c7811'
CORE_SHA = 'd19199a73b9994b125dbdbc2cee1c6250e91832e9d33317e8f54fe390341c7e6'
SESSION_SHA = '0826ff3fda11d023c60ea12f577e97f7d79b02f4566027647b7101cdadbdfcfe'
CAP, REQUEST_CAP = 131072, 65536


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap_read(path):
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        source = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            raw = bytearray()
            for unused in range(6):
                chunk = os.read(source, min(16384, 65537 - len(raw)))
                if not chunk:
                    return bytes(raw)
                raw.extend(chunk)
                need(len(raw) <= 65536, 'ADAPTIVE_ADAPTER_BOUND')
            raise ValueError('ADAPTIVE_ADAPTER_READ')
        finally:
            os.close(source)
    finally:
        os.close(descriptor)


def bootstrap():
    path = RETRIEVAL / 'adapter.py'
    raw = bootstrap_read(path)
    need(len(raw) <= 65536 and sha(raw) == ADAPTER_SHA, 'ADAPTIVE_ADAPTER_PIN')
    module = types.ModuleType('_adaptive_retrieval_adapter')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    inputs = module.approved_helpers()
    path = PROJECT / 'install/transport_handoff_session.py'
    raw = module.bootstrap_read(path)
    need(sha(raw) == SESSION_SHA, 'ADAPTIVE_JOURNAL_PIN')
    journal = module.execute_module('_adaptive_retrieval_journal', path, raw)
    return module, inputs, journal, sys.modules['transport_install_support']


def absolute(value):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096
         and '\x00' not in value, 'ADAPTIVE_PATH')
    path = Path(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts
         and len(path.parts) <= 65, 'ADAPTIVE_PATH')
    return path


def binding(args, adapter, inputs):
    path = absolute(str(args.manifest))
    raw = adapter.bootstrap_read(path)
    need(len(raw) <= 16384 and sha(raw) == inputs.digest(args.expect_manifest_sha256),
         'ADAPTIVE_MANIFEST_PIN')
    value = inputs.json_value(raw, 16384)
    inputs.fields(value, ('schema', 'handoff_manifest', 'annotations', 'core',
                          'adapter', 'client', 'python', 'session'))
    need(canonical(value) == raw and value['schema'] == 'transport/adaptive-retrieval-client/1',
         'ADAPTIVE_MANIFEST_SCHEMA')
    fixed = {'core': RETRIEVAL / 'retrieval.py', 'adapter': RETRIEVAL / 'adapter.py',
             'client': Path(__file__).absolute(), 'python': Path(sys.executable).resolve()}
    for name in ('handoff_manifest', 'annotations', 'core', 'adapter', 'client', 'python'):
        item = value[name]
        inputs.fields(item, ('path', 'bytes', 'sha256'))
        actual = absolute(item['path'])
        if name in fixed:
            need(actual == fixed[name], 'ADAPTIVE_CODE_PATH')
        inputs.checked_file(actual, item)
    need(value['core']['sha256'] == CORE_SHA and value['adapter']['sha256'] == ADAPTER_SHA,
         'ADAPTIVE_CODE_PIN')
    absolute(value['session'])
    return value, raw


def overlap(left, right):
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def output_paths(args, value, manifest, support):
    session, receipt = absolute(value['session']), absolute(str(args.receipt))
    protected = [PROJECT, args.manifest.parent.absolute(),
                 absolute(value['handoff_manifest']['path']).parent,
                 absolute(value['annotations']['path']).parent,
                 absolute(manifest['content']['root'])]
    if manifest['arm'] == 'transport':
        protected.append(absolute(manifest['bundle']['path']))
    for root in protected:
        need(not overlap(session, root) and not overlap(receipt, root), 'ADAPTIVE_PATH_OVERLAP')
    need(not overlap(receipt, session), 'ADAPTIVE_PATH_OVERLAP')
    support.confined(session.parent, 'adaptive-parent-check')
    support.confined(receipt.parent, receipt.name)
    need(not receipt.exists() and not receipt.is_symlink(), 'ADAPTIVE_RECEIPT_EXISTS')
    if session.exists():
        need(session.is_dir() and not session.is_symlink(), 'ADAPTIVE_SESSION_PATH')
    return session, receipt


def intake(args, inputs, support):
    if args.request_json is not None:
        need(args.expect_request_sha256 is None, 'ADAPTIVE_REQUEST_ARGUMENTS')
        raw = args.request_json.encode('utf-8', errors='strict')
        return raw[:REQUEST_CAP + 1], len(raw), len(raw) <= REQUEST_CAP + 1
    need(args.expect_request_sha256 is not None, 'ADAPTIVE_REQUEST_PIN_REQUIRED')
    cap = REQUEST_CAP + 1 if args.staged_input_bytes is not None else REQUEST_CAP
    need(args.staged_input_bytes is None or args.worker, 'ADAPTIVE_REQUEST_ARGUMENTS')
    raw = support.read_regular(absolute(str(args.request_file)), cap)
    need(sha(raw) == inputs.digest(args.expect_request_sha256), 'ADAPTIVE_REQUEST_PIN')
    if args.staged_input_bytes is not None:
        need(args.staged_input_bytes >= len(raw), 'ADAPTIVE_REQUEST_LENGTH')
        return raw, args.staged_input_bytes, args.staged_input_bytes == len(raw)
    return raw, len(raw), True


def requested_action(raw, inputs):
    try:
        value = inputs.json_value(raw)
        action = value.get('action')
        if type(action) is str and 0 < len(action) <= 32:
            return action
    except (ValueError, UnicodeError, TypeError):
        pass
    return 'INVALID'


def outer(arm, action, status, result, number):
    raw = canonical({'schema': 'transport/handoff-response/1', 'arm': arm,
                     'action': action, 'status': status, 'result': result, 'call': number}) + b'\n'
    need(len(raw) <= CAP, 'REFUSED_OUTPUT_BOUND')
    return raw


def wrapped_core(corpus, raw, arm, action, number):
    response = corpus.call(raw)
    need(type(response) is bytes and response.endswith(b'\n') and len(response) <= CAP,
         'ADAPTIVE_CORE_RESPONSE')
    parsed = json.loads(response)
    need(parsed['schema'] == 'transport/matched-retrieval-response/1'
         and parsed['call'] == 1 and parsed['status'] in ('OK', 'REFUSED')
         and canonical(parsed) + b'\n' == response, 'ADAPTIVE_CORE_RESPONSE')
    result = {'schema': 'transport/adaptive-retrieval-result/1',
              'core_response_base64': base64.b64encode(response).decode('ascii'),
              'inner_counter_scope': 'ONE_FRESH_WORKER'}
    try:
        return outer(arm, action, parsed['status'], result, number)
    except ValueError:
        return outer(arm, action, 'REFUSED', {'reason': 'REFUSED_OUTPUT_BOUND'}, number)


def revalidate(args, before, adapter, inputs, value):
    need(binding(args, adapter, inputs)[1] == before, 'ADAPTIVE_BINDING_CHANGED')
    manifest_path = absolute(value['handoff_manifest']['path'])
    manifest, unused, data = inputs.frozen_manifest(manifest_path, value['handoff_manifest']['sha256'])
    if manifest['arm'] == 'transport':
        snapshot = sys.modules['test_portable_handoff'].bundle_snapshot(Path(manifest['bundle']['path']))
        need(sha(canonical(snapshot)) == manifest['bundle']['snapshot_sha256'], 'ADAPTIVE_BUNDLE_CHANGED')
    return manifest


def receipt_bytes(args, value, number, previous, next_head, raw, response, corpus):
    return canonical({'schema': 'transport/adaptive-retrieval-call-receipt/1',
        'manifest_sha256': args.expect_manifest_sha256, 'call': number,
        'previous_head_sha256': previous, 'next_head_sha256': next_head,
        'request': {'bytes': len(raw), 'sha256': sha(raw)},
        'response': {'bytes': len(response), 'sha256': sha(response)},
        'status': json.loads(response)['status'], 'authority': 'NONE', 'costs': corpus.metrics()})


def refused(reason, recorded=False):
    return outer('UNKNOWN', 'INVALID', 'REFUSED',
                 {'reason': str(reason)[:256], 'recorded_may_exist': recorded}, 0)


def process(args):
    adapter, inputs, journal, support = bootstrap()
    value, before = binding(args, adapter, inputs)
    manifest, unused, data = inputs.frozen_manifest(absolute(value['handoff_manifest']['path']),
                                                  value['handoff_manifest']['sha256'])
    session, receipt = output_paths(args, value, manifest, support)
    raw, input_bytes, complete = intake(args, inputs, support)
    held = inputs.digest(args.expect_session_head_sha256)
    expected = journal.identity(args.manifest, args.expect_manifest_sha256)
    initial = sha(canonical(expected))
    if not session.exists():
        need(held == initial, 'ADAPTIVE_SESSION_HEAD')
    allow_new = raw == b'{"action":"catalog"}' and complete
    lock = journal.open_session(session, expected, allow_new)
    corpus, committed = None, False
    try:
        number, previous, unused = journal.replay(session, args.expect_manifest_sha256)
        need(previous == held, 'ADAPTIVE_SESSION_HEAD')
        need(number != 1 or (raw == b'{\"action\":\"catalog\"}' and complete),
             'ADAPTIVE_FIRST_CATALOG')
        parent = os.open(session.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        corpus = adapter.MatchedCorpus(value['handoff_manifest']['path'], value['handoff_manifest']['sha256'],
            value['annotations']['path'], value['annotations']['sha256'], value['core']['sha256'])
        action = requested_action(raw, inputs)
        response = wrapped_core(corpus, raw, manifest['arm'], action, number)
        revalidate(args, before, adapter, inputs, value)
        committed = True  # A failed multi-file commit may leave an ambiguous prefix.
        journal.commit(session, number, previous, args.expect_manifest_sha256,
                       raw, complete, input_bytes, response, None)
        next_head = sha(support.read_regular(session / ('call-%02d.json' % number), CAP))
        revalidate(args, before, adapter, inputs, value)
        support.write_new(receipt, receipt_bytes(args, value, number, previous, next_head,
                                               raw, response, corpus), CAP)
        return response
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        return refused(error, committed)
    finally:
        if corpus is not None:
            corpus.close()
        os.close(lock)


def bounded_length(value):
    need(type(value) is str and value.isascii() and value.isdigit()
         and len(value) <= 18, 'ADAPTIVE_REQUEST_LENGTH')
    return int(value)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--expect-manifest-sha256', required=True)
    parser.add_argument('--expect-session-head-sha256', required=True)
    parser.add_argument('--receipt', required=True, type=Path)
    request = parser.add_mutually_exclusive_group(required=True)
    request.add_argument('--request-json')
    request.add_argument('--request-file', type=Path)
    parser.add_argument('--expect-request-sha256')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--staged-input-bytes', type=bounded_length, help=argparse.SUPPRESS)
    return parser.parse_args()


def worker(args):
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, 33554432))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
    try:
        return process(args)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        return refused(error)


def launch(args, inputs, support):
    dispatched = False
    try:
        with tempfile.TemporaryDirectory(prefix='adaptive-retrieval-worker-') as temporary:
            root = Path(temporary)
            argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(Path(__file__).absolute()), '--worker']
            for name in ('manifest', 'expect_manifest_sha256', 'expect_session_head_sha256', 'receipt'):
                value = getattr(args, name)
                if value is not None:
                    argv.extend(['--' + name.replace('_', '-'), str(value)])
            need(args.staged_input_bytes is None, 'ADAPTIVE_REQUEST_ARGUMENTS')
            if args.request_json is not None:
                need(args.expect_request_sha256 is None, 'ADAPTIVE_REQUEST_ARGUMENTS')
                raw = args.request_json.encode('utf-8', errors='strict')
                prefix = raw[:REQUEST_CAP + 1]
                staged = root / 'request-prefix.bin'
                support.write_new(staged, prefix, REQUEST_CAP + 1)
                argv.extend(['--request-file', str(staged), '--expect-request-sha256', sha(prefix),
                             '--staged-input-bytes', str(len(raw))])
            else:
                need(args.expect_request_sha256 is not None, 'ADAPTIVE_REQUEST_PIN_REQUIRED')
                argv.extend(['--request-file', str(args.request_file),
                             '--expect-request-sha256', args.expect_request_sha256])
            dispatched = True
            result = support.run_bounded(argv, root, inputs.ENV, timeout=30, cap=CAP)
        return result
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        return {'client_refusal': str(error)[:256], 'recorded_may_exist': dispatched}


def wrapped(args):
    adapter, inputs, unused, support = bootstrap()
    result = launch(args, inputs, support)
    if 'client_refusal' in result:
        return refused(result['client_refusal'], result['recorded_may_exist'])
    try:
        if result['status'] in ('SUCCESS', 'EXIT_NONZERO') and result['stdout'] and not result['stderr']:
            answer = result['stdout']
            parsed = inputs.json_value(answer, CAP)
            inputs.fields(parsed, ('schema', 'arm', 'action', 'status', 'result', 'call'))
            need(answer.endswith(b'\n') and canonical(parsed) + b'\n' == answer
                 and parsed['schema'] == 'transport/handoff-response/1'
                 and parsed['status'] in ('OK', 'REFUSED'), 'ADAPTIVE_WORKER_FRAMING')
            need(result['exit_code'] == (0 if parsed['status'] == 'OK' else 1),
                 'ADAPTIVE_WORKER_EXIT')
            return answer
        return refused('ADAPTIVE_WORKER_' + result['status'], True)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        return refused(error, True)


def main():
    args = arguments()
    try:
        raw = worker(args) if args.worker else wrapped(args)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        raw = refused(error)
    sys.stdout.buffer.write(raw)
    return 0 if json.loads(raw)['status'] == 'OK' else 1


if __name__ == '__main__':
    sys.exit(main())
