#!/usr/bin/env python3
"""Bounded inert ZIP reader controls."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import struct
import sys
import zipfile
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
READER = HERE / 'prepare_receipt.py'
UTILITY = ROOT / 'comparison/retrieval/client/prepare_receipt.py'
UTILITY_SHA = '37fcb93b3ed20edb98b62416d923fe4a8612496e77f218ef5367a4de7a80d983'
SUPPORT = ROOT / 'install/transport_install_support.py'
SUPPORT_SHA = 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da'
VROOT = Path('/dev/shm/semantic-transport-native-workflow-20261029')
PAYLOAD, MEMBER = b'literal archive bytes\n', 'sample/run.stdout'


def need(condition, reason):
    if type(condition) is not bool or not condition:
        raise AssertionError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def read(path, cap=1048576):
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'read cap')
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    need(len(raw) <= 1048576, 'write cap')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short write')


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def archive(entries):
    need(1 <= len(entries) <= 3, 'ZIP count')
    local, central = bytearray(), bytearray()
    date = ((2026 - 1980) << 9) | (10 << 5) | 29
    for name, raw, malformed in entries:
        need(len(name) <= 256 and len(raw) <= 262145, 'ZIP bound')
        filename, offset = name.encode('ascii'), len(local)
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        compressed = b'\x07' if malformed else compressor.compress(raw) + compressor.flush()
        crc = zlib.crc32(raw)
        local.extend(struct.pack('<I5H3I2H', 0x04034b50, 20, 0, 8, 0, date,
                                 crc, len(compressed), len(raw), len(filename), 0))
        local.extend(filename + compressed)
        central.extend(struct.pack('<I6H3I5H2I', 0x02014b50, (3 << 8) | 20, 20, 0, 8, 0, date,
            crc, len(compressed), len(raw), len(filename), 0, 0, 0, 0, (stat.S_IFREG | 0o600) << 16, offset))
        central.extend(filename)
    ending = struct.pack('<I4H2IH', 0x06054b50, 0, 0, len(entries), len(entries), len(central), len(local), 0)
    return bytes(local + central + ending)


def origins(members):
    return dict(schema='transport/native-workflow-observations/1', selection='Inert fixtures',
                members={name: dict(path='/provenance/' + name, **pin(raw)) for name, raw in members.items()})


def fixtures(root):
    valid = archive([(MEMBER, PAYLOAD, False)])
    definitions = [
        ('valid', valid, origins({MEMBER: PAYLOAD}), 'PASS'),
        ('altered-member', archive([(MEMBER, b'changed archive bytes\n', False)]), origins({MEMBER: PAYLOAD}), 'REFUSED'),
        ('altered-pin', valid, origins({MEMBER: PAYLOAD}), 'REFUSED'),
        ('missing-entry', valid, origins({MEMBER: PAYLOAD, 'sample/missing.stdout': b'missing'}), 'REFUSED'),
        ('duplicate', archive([(MEMBER, PAYLOAD, False)] * 2), origins({MEMBER: PAYLOAD}), 'REFUSED'),
        ('traversal', archive([('../escape', PAYLOAD, False)]), origins({'../escape': PAYLOAD}), 'REFUSED'),
        ('oversized-member', archive([(MEMBER, b'X' * 262145, False)]), origins({MEMBER: b'X' * 262145}), 'REFUSED'),
        ('truncated', valid[:-7], origins({MEMBER: PAYLOAD}), 'REFUSED'),
        ('malformed-deflate', archive([(MEMBER, PAYLOAD, True)]), origins({MEMBER: PAYLOAD}), 'REFUSED')]
    result = []
    for name, raw, held, expected in definitions:
        if name == 'altered-pin':
            held['members'][MEMBER]['sha256'] = '0' * 64
        directory = root / 'cases' / name
        directory.mkdir(mode=0o700)
        (directory / 'evidence').mkdir(mode=0o700)
        save(directory / 'evidence/observations.zip', raw)
        save(directory / 'evidence/origins.json', held)
        result.append(dict(name=name, directory=str(directory), archive=pin(raw), origins=pin(canonical(held)),
                           expected=expected))
    return result


def inventory(root):
    pending, result, total, count = [root], {}, 0, 0
    for unused in range(512):
        if not pending:
            need(total <= 8388608, 'aggregate cap')
            return result
        with os.scandir(pending.pop()) as entries:
            for item in entries:
                count += 1
                need(count <= 512 and not item.is_symlink(), 'file count/type')
                path = Path(item.path)
                if item.is_dir(follow_symlinks=False):
                    result[str(path.relative_to(root))] = {'directory': True}
                    pending.append(path)
                else:
                    need(item.is_file(follow_symlinks=False), 'regular files')
                    raw = read(path)
                    total += len(raw)
                    result[str(path.relative_to(root))] = pin(raw)
    raise AssertionError('traversal cap')


def api_case(value, module, checked):
    module.HERE = Path(value['directory'])
    try:
        contents, total, archive_raw, origins_raw = module.observations(checked)
        need(contents == {MEMBER: PAYLOAD} and total == len(PAYLOAD), 'API bytes/length')
        need(pin(archive_raw) == value['archive'] and pin(origins_raw) == value['origins'], 'raw inputs')
        observed = dict(status='PASS', expanded=total)
    except (ValueError, zipfile.BadZipFile, zlib.error, NotImplementedError) as error:
        observed = dict(status='REFUSED', reason=str(error))
    return observed


def capture(root, name, command, support):
    answer = support.run_bounded(command, root, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8', 'TMPDIR': str(root / 'tmp')}, timeout=10, cap=8192)
    for stream in ('stdout', 'stderr'):
        save(root / 'captures' / (name + '.' + stream), answer[stream])
    detail = {key: value for key, value in answer.items() if key not in ('stdout', 'stderr')}
    detail.update({stream: pin(answer[stream]) for stream in ('stdout', 'stderr')})
    save(root / 'captures' / (name + '.json'), detail)
    need(answer['status'] in ('SUCCESS', 'EXIT_NONZERO'), 'child process refused')
    return answer


def fake_project(root, reader_raw, fixture):
    project = root / 'fake-project/comparison'
    target = project / 'workflow/prepare_receipt.py'
    files = {target: reader_raw, project / 'retrieval/client/prepare_receipt.py': read(UTILITY)}
    for name in ('observations.zip', 'origins.json'):
        files[target.parent / 'evidence' / name] = read(Path(fixture['directory']) / 'evidence' / name)
    for path, raw in files.items():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        save(path, raw)
    return target


def freeze(root, cases, commands, profile, reader_pin):
    paths = (Path(__file__).absolute(), READER, UTILITY, SUPPORT, Path(sys.executable).resolve())
    pins = {}
    for index, path in enumerate(paths):
        raw = read(path)
        pins[str(path)] = pin(raw)
        save(root / ('frozen-source-' + str(index) + '.bin'), raw)
    save(root / 'T-profile.json', dict(schema='transport/byte-reader-test-profile/1',
         profile=profile, cases=cases, commands=commands, source_pins=pins, initial_tree=inventory(root),
         reader_pin=reader_pin, expected_cli=dict(exit_code=1, stdout='', stderr_prefix='REFUSED:', traceback=False),
         authority='NONE', semantics='NOT_ASSESSED'))
    return pins


def run(root, expected, optimized):
    need(root.is_absolute() and root.parent == VROOT and not root.exists(), 'new private V root')
    root.mkdir(mode=0o700)
    for name in ('cases', 'captures', 'tmp'):
        (root / name).mkdir(mode=0o700)
    try:
        reader_raw = read(READER)
        need(pin(reader_raw)['sha256'] == expected and pin(read(UTILITY))['sha256'] == UTILITY_SHA
             and pin(read(SUPPORT))['sha256'] == SUPPORT_SHA, 'held code pins')
        cases = fixtures(root)
        cli = fake_project(root, reader_raw, cases[-1])
        command = [sys.executable, '-I', '-S', '-B'] + (['-O'] if optimized else []) + ['-Werror', str(cli), '--check']
        profile = dict(optimized=optimized, api_calls=10, api_scope='TRUSTED_HERE_BINDING_ONE_PROCESS',
                       max_processes=1, wall_seconds_each=10, output_bytes_each=8192,
                       max_files=512, aggregate_bytes=8388608, no_extract=True, no_archive_execution=True,
                       helper=dict(cpu=120, address_bytes=1073741824, file_bytes=33554432, descriptors=128))
        missing = {'extra/a.json': canonical(dict(argv=['test'], stdout=pin(b''), stderr=pin(b''), exit_code=0)),
                   'extra/a.stderr': b''}
        profile['missing_stdout'] = {key: raw.decode() for key, raw in missing.items()}
        profile['missing_stdout_reason'] = 'process stream pin differs'
        pins = freeze(root, cases, command, profile, pin(reader_raw))
        support = load('_reader_test_bounded_support', SUPPORT)
        module = load('_reader_under_test', READER)
        checked = load('_held_recorded_byte_utility', UTILITY)
        observations = []
        for case in cases:
            need(all(pin(read(Path(path))) == held for path, held in pins.items()), 'code changed')
            before = inventory(Path(case['directory']))
            observed = api_case(case, module, checked)
            save(root / 'captures' / (case['name'] + '.api.json'), observed)
            need(observed['status'] == case['expected'] and (case['expected'] == 'PASS' or bool(observed['reason'])), 'API status')
            need(inventory(Path(case['directory'])) == before, 'API mutated fixtures')
            observations.append(dict(case=case['name'], observed=observed))
        reason = None
        try:
            module.process_counts(missing, checked)
        except ValueError as error:
            reason = str(error)
        need(reason == profile['missing_stdout_reason'], 'missing stdout branch')
        save(root / 'captures/missing-stdout.api.json', dict(status='REFUSED', reason=reason))
        before = inventory(cli.parents[2])
        answer = capture(root, 'cli-malformed-deflate', command, support)
        need(answer['exit_code'] == 1 and answer['stdout'] == b'' and answer['stderr'].startswith(b'REFUSED:')
             and b'Traceback' not in answer['stderr'], 'CLI refusal framing')
        need(inventory(cli.parents[2]) == before, 'CLI mutated fixtures')
        save(root / 'receipt.json', dict(status='PASS', profile=profile, observations=observations,
             source_pins=pins, cli=pin(answer['stderr']), authority='NONE', semantics='NOT_ASSESSED'))
    except BaseException as error:
        save(root / 'failure.json', dict(status='FAILED', type=type(error).__name__, reason=str(error)))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--expect-reader-sha256')
    parser.add_argument('--optimized', action='store_true')
    args = parser.parse_args()
    need(args.root is not None and args.expect_reader_sha256 is not None, 'root and reader pin required')
    for kind, value in ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 120),
                        (resource.RLIMIT_FSIZE, 33554432), (resource.RLIMIT_NOFILE, 128)):
        resource.setrlimit(kind, (value, value))
    run(args.root, args.expect_reader_sha256, args.optimized)
    sys.stdout.buffer.write(canonical(dict(status='PASS', root=str(args.root))) + b'\n')


if __name__ == '__main__':
    main()
