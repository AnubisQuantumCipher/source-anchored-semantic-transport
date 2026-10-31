#!/usr/bin/env python3
"""Pinned original/actual-transport inputs for the one shared retrieval core.

Successful stdout consists only of unedited core response bytes. Costs go to a
separate create-only file. The CLI uses an isolated bounded worker; API callers
must supply equivalent outer limits. Bootstrap, Python/stdlib and OS are trusted.
Hash checks do not supply hostile same-user isolation or semantic adequacy.
"""

import argparse
import hashlib
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
INSTALL = HERE.parents[1] / 'install'
CORE = HERE / 'retrieval.py'
MAX_FILE, MAX_REQUESTS, MAX_OUTPUT = 4194304, 32, 131072
HELPERS = {
    'transport_install_support': 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da',
    'transport_install_layout': '92bca5af352c244f0c70831a824030511b82a0017fd4834b4a8e6916a5ed422b',
    'transport_handoff_inputs': 'e8250f03719d375ce660e8f262ef009ce2ca569bae37dcfb72ed10bfb3a91cc8',
    'test_portable_handoff': 'f8146be8e0b75ae38dea727f2983f4fb2e156775db8c075f3fbbeceb9da8c5bb',
}
APPROVED_BUNDLE = {
    'path': '/dev/shm/semantic-transport-proof-closure-20261029/install-current/first-bundle',
    'install_sha256': '398d5388da9c03a6c155e5f19523dccfb7b26aecbad256a4eb301a308013e50b',
    'snapshot_sha256': 'db7b39e750de6b87986ece10e870c5ec575ec3957fed5fee0a5df014dac7277c',
}


def require(condition, reason):
    if type(condition) is not bool or not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap_read(path):
    """Read fixed bootstrap bytes without following any path component symlink."""
    path = path.absolute()
    require(len(path.parts) <= 65 and '..' not in path.parts, 'bootstrap path bound')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE,
                    'bootstrap regular file bound')
            output = bytearray()
            for _ in range(MAX_FILE // 16384 + 2):
                block = os.read(descriptor, min(16384, MAX_FILE + 1 - len(output)))
                if not block:
                    after = os.fstat(descriptor)
                    keys = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                    require(all(getattr(before, key) == getattr(after, key) for key in keys)
                            and len(output) == before.st_size,
                            'bootstrap changed during read')
                    return bytes(output)
                output.extend(block)
                require(len(output) <= MAX_FILE, 'bootstrap read bound')
            raise ValueError('bootstrap iteration bound')
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def execute_module(name, path, raw):
    require(name not in sys.modules, 'module already loaded: ' + name)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def approved_helpers():
    """The manifest can select data, never a bootstrap Python implementation."""
    raw = {name: bootstrap_read(INSTALL / (name + '.py')) for name in HELPERS}
    for name, expected in HELPERS.items():
        require(sha(raw[name]) == expected, 'approved helper hash differs: ' + name)
        loaded = sys.modules.get(name)
        if loaded is not None:
            require(getattr(loaded, '__file__', None) == str(INSTALL / (name + '.py'))
                    and getattr(loaded, '_adapter_approved_sha256', None) == expected,
                    'preloaded helper origin refused: ' + name)
    for name, expected in HELPERS.items():
        if name not in sys.modules:
            loaded = execute_module(name, INSTALL / (name + '.py'), raw[name])
            loaded._adapter_approved_sha256 = expected
    return sys.modules['transport_handoff_inputs']


def load_core(expected):
    require(type(expected) is str and len(expected) == 64
            and all(char in '0123456789abcdef' for char in expected), 'core pin syntax')
    raw = bootstrap_read(CORE)
    require(sha(raw) == expected, 'externally held core hash differs')
    return execute_module('_matched_retrieval_core', CORE, raw)


def recovered_sources(inputs, manifest, root, data):
    if manifest['arm'] == 'original':
        return inputs.original_sources(manifest, data)
    require(manifest['bundle'] == APPROVED_BUNDLE, 'decoder outside approved fixed bundle')
    require(not any(name.startswith('transport_') and name not in HELPERS
                    for name in sys.modules), 'decoder imported before verification')
    receiver = inputs.transport_receiver(manifest, root, data)
    return {item['id']: item['data'] for item in receiver.decoded['sources']}


class MatchedCorpus:
    """One admitted corpus per fresh process; annotations remain external data."""

    def __init__(self, manifest, expected_manifest_sha256, annotations,
                 expected_annotations_sha256, expected_core_sha256):
        started = time.monotonic_ns()
        inputs = approved_helpers()
        support = sys.modules['transport_install_support']
        frozen, root, data = inputs.frozen_manifest(Path(manifest), expected_manifest_sha256)
        checked = time.monotonic_ns()
        sources = recovered_sources(inputs, frozen, root, data)
        recovered = time.monotonic_ns()
        raw = support.read_regular(Path(annotations), 65536)
        require(sha(raw) == inputs.digest(expected_annotations_sha256), 'held annotation pin differs')
        core = load_core(expected_core_sha256)
        ready = time.monotonic_ns()
        self._core = core.Corpus(sources, raw, expected_annotations_sha256)
        ended = time.monotonic_ns()
        self._metrics = {
            'schema': 'transport/matched-retrieval-costs/1', 'arm': frozen['arm'],
            'manifest_sha256': expected_manifest_sha256,
            'annotations_sha256': expected_annotations_sha256, 'core_sha256': expected_core_sha256,
            'source_bytes': sum(len(value) for value in sources.values()),
            'carrier_bytes': sum(len(value) for value in data.values()), 'annotation_bytes': len(raw),
            'bootstrap_and_manifest_ns': checked - started, 'source_recovery_ns': recovered - checked,
            'annotations_and_core_load_ns': ready - recovered, 'core_setup_ns': ended - ready,
            'cache_state': 'FRESH_PROCESS_HOST_CACHE_UNCONTROLLED', 'authority': 'NONE',
            'semantic_adequacy': 'UNPROVEN',
        }

    def call(self, request):
        return self._core.call(request)

    def close(self):
        self._core.close()

    def metrics(self):
        return dict(self._metrics, core=self._core.metrics())


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--expect-manifest-sha256', required=True)
    parser.add_argument('--annotations', required=True, type=Path)
    parser.add_argument('--expect-annotations-sha256', required=True)
    parser.add_argument('--expect-core-sha256', required=True)
    parser.add_argument('--requests', required=True, type=Path,
                        help='1..32 LF-terminated request records, <=65536 aggregate bytes')
    parser.add_argument('--metrics', required=True, type=Path, help='new separate cost file')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    return parser.parse_args()


def worker(args):
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, 33554432))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
    inputs = approved_helpers()
    support = sys.modules['transport_install_support']
    raw = support.read_regular(args.requests, 65536)
    require(raw.endswith(b'\n'), 'request schedule must end with LF')
    requests = raw[:-1].split(b'\n')
    require(1 <= len(requests) <= MAX_REQUESTS and all(requests), 'request schedule count/empty bound')
    corpus = MatchedCorpus(args.manifest, args.expect_manifest_sha256, args.annotations,
                           args.expect_annotations_sha256, args.expect_core_sha256)
    try:
        responses, size = [], 0
        for request in requests:
            answer = corpus.call(request)
            require(type(answer) is bytes and answer.endswith(b'\n'), 'core response framing differs')
            size += len(answer)
            require(size <= MAX_OUTPUT, 'aggregate schedule output bound')
            responses.append(answer)
        costs = support.canonical(corpus.metrics()) + b'\n'
        support.write_new(args.metrics, costs, MAX_OUTPUT)
        return b''.join(responses)
    finally:
        corpus.close()


def refused(error):
    import json
    return json.dumps({'schema': 'transport/matched-retrieval-adapter-refusal/1',
                       'status': 'REFUSED', 'reason': str(error)[:256], 'authority': 'NONE'},
                      sort_keys=True, separators=(',', ':')).encode() + b'\n'


def wrapped(args):
    inputs = approved_helpers()
    support = sys.modules['transport_install_support']
    with tempfile.TemporaryDirectory(prefix='matched-retrieval-worker-') as temporary:
        root = Path(temporary)
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'adapter.py'), '--worker']
        for name in ('manifest', 'expect_manifest_sha256', 'annotations',
                     'expect_annotations_sha256', 'expect_core_sha256', 'requests', 'metrics'):
            value = getattr(args, name)
            argv.extend(['--' + name.replace('_', '-'), str(value.absolute() if isinstance(value, Path) else value)])
        result = support.run_bounded(argv, root, inputs.ENV, timeout=30, cap=MAX_OUTPUT)
    if result['status'] in ('SUCCESS', 'EXIT_NONZERO') and result['stdout'] and not result['stderr']:
        return result['stdout'], result['exit_code']
    return refused('bounded worker failed: ' + result['status']), 1


def main():
    args = arguments()
    try:
        raw, code = (worker(args), 0) if args.worker else wrapped(args)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        raw, code = refused(error), 1
    sys.stdout.buffer.write(raw)
    return code


if __name__ == '__main__':
    sys.exit(main())
