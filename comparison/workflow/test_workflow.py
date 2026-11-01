#!/usr/bin/env python3
"""Independent literal native-workspace controls; no model or benefit evaluation.

Portable original-only fixtures are authored from held public literals. Local
mode additionally uses the existing qualified transport pair. Expected files
never come from product output. Every execution uses a fresh isolated process.
"""

import argparse
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import runpy
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
INSTALL = ROOT / 'install'
PRODUCT = HERE / 'native_workspace.py'
BASE = Path('/dev/shm/semantic-transport-native-workflow-20261029')
CONTRACT_SHA = '4f341b46d3c71008bf405014191ec15a42d45f78a31024c22f06e02d2f33c2e7'
ORACLE_SHA = '780c03a429efafd4d965cdd9045e165627810e77ee6df4e2aa28b229128f8ba4'
SOURCE_ORACLE_SHA = '23525546f46513b5d1c45acfa2161d6d5266ae2446d88deff66f4aa7d5a690f3'
CORE_SHA = 'd19199a73b9994b125dbdbc2cee1c6250e91832e9d33317e8f54fe390341c7e6'
ADAPTER_SHA = '83bde7b42d687877b677b1649741a7f848e9a4d65da3b76838d9a445bb6c7811'
SUPPORT_SHA = 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da'
HELPERS = ('transport_handoff_reader.py', 'transport_handoff_inputs.py',
           'transport_handoff_session.py', 'transport_install_support.py',
           'transport_install_layout.py', 'transport_response_evidence.py')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
MAX_FILES, MAX_BYTES, MAX_EXECUTIONS = 4096, 33554432, 256


def require(condition, reason):
    if type(condition) is not bool or not condition:
        raise AssertionError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, cap=4194304):
    require(type(cap) is int and 0 <= cap <= 16777216, 'test read cap')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'test input byte bound')
    return raw


def pin(path, cap=4194304):
    raw = read(path, cap)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def record(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    require(len(raw) <= 16777216, 'test write bound')
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'short create-only test write')


def pinned_json(path, expected):
    raw = read(path)
    require(sha(raw) == expected, 'independently held JSON differs: ' + path.name)
    value = json.loads(raw)
    require(canonical(value) == raw, 'noncanonical frozen JSON')
    return value


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def support():
    path = INSTALL / 'transport_install_support.py'
    require(pin(path)['sha256'] == SUPPORT_SHA, 'fixed bounded process helper differs')
    return load_module('workflow_test_support', path)


def literal_files(case):
    result = {}
    require(len(case['expected_files']) <= 31, 'golden file count')
    for name, held in case['expected_files'].items():
        raw = base64.b64decode(held['base64'], validate=True)
        require(record(raw) == {key: held[key] for key in ('bytes', 'sha256')}, 'golden literal file differs')
        result[name] = raw
    return result


def verify_literal_sources(case, files, source_oracle):
    originals = {item['id']: item for item in source_oracle['sources']}
    require(len(case['source_ids']) <= 16 and len(case['unit_ids']) <= 16, 'literal source/unit bound')
    for name in case['source_ids']:
        raw = base64.b64decode(originals[name]['raw_base64'], validate=True)
        require(raw == files['sources/' + name + '.bin'] and sha(raw) == originals[name]['sha256'],
                'workspace literal source differs from original235 oracle')
    require(record(files['annotations.json']) == case['annotations'], 'literal annotation binding differs')


def original_manifest(directory, case, files):
    content = directory / 'content'
    content.mkdir(mode=0o700)
    annotations = json.loads(files['annotations.json'])
    rows, entries = [], []
    for item in annotations['sources']:
        name = item['id']
        path = content / (name + '.bin')
        save(path, files['sources/' + name + '.bin'])
        rows.append({'id': name, 'label': name, 'media_type': item['media_type'],
                     'provenance': 'Independently held public literal235 source bytes',
                     'bytes': item['bytes'], 'path': path.name})
        entries.append(dict(pin(path), path=path.name))
    value = {'schema': 'transport/handoff-reader/1', 'arm': 'original',
             'helpers': [pin(INSTALL / name) for name in HELPERS],
             'python': pin(Path(sys.executable).resolve()), 'sources': rows,
             'held_source_sha256': {item['id']: item['sha256'] for item in annotations['sources']},
             'content': {'root': str(content), 'files': entries}}
    path = directory / 'handoff.json'
    save(path, value)
    return path


def make_state(root, case, arm, mode, source_oracle):
    name = case['id'] + '-' + arm
    directory = root / 'inputs' / name
    directory.mkdir(mode=0o700)
    files = literal_files(case)
    verify_literal_sources(case, files, source_oracle)
    save(directory / 'annotations.json', files['annotations.json'])
    if mode == 'portable':
        manifest = original_manifest(directory, case, files)
    else:
        held = case['arms'][arm]['old_handoff_manifest']
        manifest = Path(held['path'])
        require(pin(manifest) == held, 'existing local handoff pin differs')
    expected = base64.b64decode(case['arms'][arm]['expected_workspace_manifest_base64'], validate=True)
    require(record(expected) == case['arms'][arm]['expected_workspace_manifest'], 'golden manifest literal differs')
    if mode == 'portable':
        value = json.loads(expected)
        value['inputs']['handoff_manifest'] = record(read(manifest))
        expected = canonical(value)
    save(directory / 'expected-workspace.json', expected)
    return {'name': name, 'case': case, 'arm': arm, 'files': files, 'manifest': manifest,
            'manifest_pin': pin(manifest), 'annotations_pin': pin(directory / 'annotations.json'),
            'annotations': directory / 'annotations.json', 'expected_manifest': expected,
            'workspace': root / 'outputs' / name, 'receipt': root / 'receipts' / (name + '.json')}


def tree_files(root):
    found, pending, visited = {}, [(root, 0)], 0
    for _ in range(MAX_FILES):
        if not pending:
            return found
        directory, depth = pending.pop()
        require(depth <= 4, 'test inventory depth')
        with os.scandir(directory) as children:
            for item in children:
                visited += 1
                require(visited <= MAX_FILES, 'test inventory file count')
                path = Path(item.path)
                if item.is_symlink():
                    found[str(path.relative_to(root))] = {'symlink': os.readlink(path)}
                elif item.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                else:
                    require(item.is_file(follow_symlinks=False), 'test inventory regular only')
                    found[str(path.relative_to(root))] = record(read(path))
    raise AssertionError('test inventory traversal bound')


def golden_tree(path, state):
    path.mkdir(mode=0o700)
    (path / 'sources').mkdir(mode=0o700)
    files = dict(state['files'], **{'workspace.json': state['expected_manifest']})
    for name, raw in files.items():
        save(path / name, raw)
        (path / name).chmod(0o400)
    (path / 'sources').chmod(0o500)
    path.chmod(0o500)


def tool_records():
    result = {}
    for name in ('cat', 'rg', 'diff'):
        path = Path('/usr/bin') / name
        require(path.is_file() and not path.is_symlink(), 'required native tool missing or symlinked: ' + name)
        result[name] = pin(path, 16777216)
    return result


def capture(root, label, argv, profile, allow_stderr=False):
    profile['executions'] += 1
    require(profile['executions'] <= MAX_EXECUTIONS, 'test execution count bound')
    result = support().run_bounded(argv, root, dict(ENV, TMPDIR=str(root / 'tmp')),
                                   timeout=30, cap=131072)
    for stream in ('stdout', 'stderr'):
        save(root / 'captures' / (label + '.' + stream), result[stream])
    detail = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    detail.update({stream: record(result[stream]) for stream in ('stdout', 'stderr')})
    detail['argv'] = argv
    save(root / 'captures' / (label + '.json'), detail)
    require(result['status'] in ('SUCCESS', 'EXIT_NONZERO') and (allow_stderr or not result['stderr']),
            'child failed/truncated or emitted stderr: ' + label)
    return result


def invoke(root, label, argv, profile, lf=True):
    result = capture(root, label, argv, profile)
    raw = result['stdout']
    require(raw.endswith(b'\n') if lf else not raw.endswith(b'\n'), 'API/CLI newline framing differs')
    value = json.loads(raw)
    require(raw == canonical(value) + (b'\n' if lf else b''), 'complete canonical response framing differs')
    return result, value


def product_argv(action, state, profile):
    argv = [sys.executable, '-I', '-S', '-B']
    if profile['optimized']:
        argv.append('-O')
    argv.extend(['-Werror', str(PRODUCT), action])
    if action == 'prepare':
        require(pin(state['manifest']) == state['manifest_pin'], 'held manifest changed before call')
        require(pin(state['annotations']) == state['annotations_pin'], 'held annotations changed before call')
        argv.extend(['--manifest', str(state['manifest']), '--expect-manifest-sha256', state['manifest_pin']['sha256'],
                     '--annotations', str(state['annotations']), '--expect-annotations-sha256', state['annotations_pin']['sha256'],
                     '--expect-core-sha256', CORE_SHA, '--workspace', str(state['workspace']),
                     '--receipt', str(state['receipt'])])
    else:
        argv.extend(['--workspace', str(state['workspace']), '--expect-workspace-manifest-sha256',
                     sha(state['expected_manifest'])])
    return argv


def receipt_check(value, state, contract, verification=False):
    spec = contract['verification_receipt' if verification else 'success_receipt']
    require(set(value) == set(spec['closed_keys']), 'closed receipt fields differ')
    for key in ('schema', 'status'):
        require(value[key] == spec[key], 'receipt fixed field differs: ' + key)
    require((value['authority'], value['freshness'], value['context_adequacy'], value['data_is_untrusted'])
            == ('NONE', 'UNKNOWN', 'UNPROVEN', True), 'receipt scope differs')
    expected = dict(state['files'], **{'workspace.json': state['expected_manifest']})
    require(value['workspace_manifest'] == record(state['expected_manifest']), 'receipt manifest pin differs')
    require(value['source_snapshot'] == state['case']['expected_source_snapshot'], 'receipt source snapshot differs')
    require(value['file_count'] == len(expected), 'receipt file count differs')
    require(value['workspace_bytes'] == sum(len(raw) for raw in expected.values()), 'receipt workspace bytes differ')
    require(type(value['costs']) is dict and bool(value['costs']), 'separate observed costs required')
    if not verification:
        require(value['workspace'] == str(state['workspace']) and value['arm'] == state['arm'], 'receipt path/arm differs')


def exact_workspace(state):
    path = state['workspace']
    expected = {name: record(raw) for name, raw in state['files'].items()}
    expected['workspace.json'] = record(state['expected_manifest'])
    require(tree_files(path) == expected, 'complete native workspace differs from literal oracle')
    for directory in (path, path / 'sources'):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500
                and info.st_uid == os.getuid(), 'directory owner/mode differs')
    for name in expected:
        info = (path / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid(),
                'file owner/mode/link policy differs')
    return expected


def child_argv(profile, action, config):
    argv = [sys.executable, '-I', '-S', '-B']
    if profile['optimized']:
        argv.append('-O')
    return argv + ['-Werror', str(Path(__file__).absolute()), '--child', action, '--config', str(config)]


def child_config(root, label, state, product_sha):
    value = {key: str(state[key]) for key in ('manifest', 'annotations', 'workspace', 'receipt')}
    value.update(manifest_sha256=state['manifest_pin']['sha256'],
                 annotations_sha256=state['annotations_pin']['sha256'],
                 workspace_manifest_sha256=sha(state['expected_manifest']), product_sha256=product_sha)
    path = root / 'configs' / (label + '.json')
    if path.exists():
        require(read(path) == canonical(value), 'pre-frozen child config differs')
    else:
        save(path, value)
    return path


def api_child(action, config):
    value = json.loads(read(config))
    require(pin(PRODUCT)['sha256'] == value['product_sha256'], 'child held product differs')
    module = load_module('native_workflow_under_test', PRODUCT)
    if action in ('cli-receipt-fault', 'cli-stdout-fault'):
        if action == 'cli-receipt-fault':
            install_receipt_fault(value['receipt'])
        else:
            install_stdout_fault()
        sys.argv = [str(PRODUCT), 'prepare', '--manifest', value['manifest'],
                    '--expect-manifest-sha256', value['manifest_sha256'], '--annotations', value['annotations'],
                    '--expect-annotations-sha256', value['annotations_sha256'], '--expect-core-sha256', CORE_SHA,
                    '--workspace', value['workspace'], '--receipt', value['receipt']]
        runpy.run_path(str(PRODUCT), run_name='__main__')
        return
    if action == 'verify':
        raw = module.verify_workspace(Path(value['workspace']), value['workspace_manifest_sha256'])
    else:
        if action == 'receipt-fault':
            install_receipt_fault(value['receipt'])
        raw = module.prepare_workspace(Path(value['manifest']), value['manifest_sha256'],
              Path(value['annotations']), value['annotations_sha256'], CORE_SHA,
              Path(value['workspace']), Path(value['receipt']))
    require(type(raw) is bytes and canonical(json.loads(raw)) == raw, 'API must return canonical bytes without LF')
    require(sys.stdout.buffer.write(raw) == len(raw), 'API stdout short write')


def install_receipt_fault(target):
    original = os.open
    def controlled_open(path, flags, mode=0o777, *, dir_fd=None):
        candidate = os.fspath(path)
        if flags & os.O_CREAT and (candidate == target or candidate == Path(target).name):
            raise PermissionError('independent trusted test receipt creation fault')
        return original(path, flags, mode, dir_fd=dir_fd)
    os.open = controlled_open


def install_stdout_fault():
    original, state = os.write, {'first': True}
    def controlled_write(fd, raw):
        if fd == 1:
            if state['first']:
                state['first'] = False
                return original(fd, raw[:11])
            raise OSError('independent trusted partial stdout sink fault')
        return original(fd, raw)
    os.write = controlled_write


def refusal_check(result, value, contract, published=False):
    spec = contract['refusal']
    require(result['exit_code'] == 1, 'refusal exit differs')
    require(set(value) == set(spec['closed_keys']), 'refusal closed fields differ')
    for key in ('schema', 'status', 'authority', 'freshness', 'context_adequacy', 'data_is_untrusted'):
        require(value[key] == spec[key], 'refusal fixed metadata differs')
    require(type(value['reason']) is str and bool(value['reason']), 'fixed refusal reason missing')
    require(type(value['stage_may_exist']) is bool and type(value['workspace_may_exist']) is bool,
            'refusal publication ambiguity flag differs')
    if published is not None:
        require(value['workspace_may_exist'] is published, 'refusal publication phase differs')


def positive(root, state, profile, contract):
    label = state['name']
    result, value = invoke(root, label + '-prepare', product_argv('prepare', state, profile), profile)
    require(result['exit_code'] == 0, 'prepare refused: ' + label)
    receipt_check(value, state, contract)
    require(read(state['receipt']) == canonical(value), 'external receipt/API bytes differ')
    exact_workspace(state)
    result, value = invoke(root, label + '-verify', product_argv('verify', state, profile), profile)
    require(result['exit_code'] == 0, 'verify refused: ' + label)
    receipt_check(value, state, contract, True)
    config = child_config(root, label + '-api', state, profile['product_sha256'])
    result, value = invoke(root, label + '-api', child_argv(profile, 'verify', config), profile, False)
    require(result['exit_code'] == 0, 'public API verify failed')
    receipt_check(value, state, contract, True)
    item = dict(state, workspace=root / 'outputs' / (label + '-api-prepare'),
                receipt=root / 'receipts' / (label + '-api-prepare.json'))
    config = child_config(root, label + '-api-prepare', item, profile['product_sha256'])
    result, value = invoke(root, label + '-api-prepare', child_argv(profile, 'prepare', config), profile, False)
    require(result['exit_code'] == 0 and read(item['receipt']) == canonical(value), 'API prepare framing/receipt differs')
    receipt_check(value, item, contract)
    exact_workspace(item)


def native_calls(root, state, oracle, tools, profile):
    before = exact_workspace(state)
    main = state['case']['id'] == 'NATIVE_MAIN'
    operations = oracle['native_freedom']['operations'] if main else [
        {'index': 1, 'path': 'index.txt', 'expected': record(state['files']['index.txt'])}]
    for operation in operations:
        label = state['name'] + '-cat-' + str(operation['index'])
        require(pin(Path(tools['cat']['path']), 16777216) == tools['cat'], 'held cat changed')
        result = capture(root, label, [tools['cat']['path'], '--', str(state['workspace'] / operation['path'])], profile)
        require(result['exit_code'] == 0 and record(result['stdout']) == operation['expected']
                and result['stdout'] == state['files'][operation['path']], 'native full read differs')
    pattern = 'Native source workspace v1'
    result = capture(root, state['name'] + '-rg', [tools['rg']['path'], '--no-config', '--no-heading',
        '--no-line-number', '--no-filename', '--color', 'never', '-F', '--', pattern,
        str(state['workspace'] / 'index.txt')], profile)
    require(result['exit_code'] == 0 and result['stdout'] == (pattern + '\n').encode(), 'native rg index navigation differs')
    require(exact_workspace(state) == before, 'native reads mutated workspace')


def native_original(root, state, tools, profile):
    manifest = json.loads(read(state['manifest']))
    if state['arm'] != 'original':
        return
    entries = {item['id']: item for item in manifest['sources']}
    name = state['case']['source_ids'][0]
    original = Path(manifest['content']['root']) / entries[name]['path']
    result = capture(root, state['name'] + '-original-in-place', [tools['cat']['path'], '--', str(original)], profile)
    require(result['exit_code'] == 0 and result['stdout'] == state['files']['sources/' + name + '.bin'],
            'ordinary original in-place source read differs')
    result = capture(root, state['name'] + '-diff', [tools['diff']['path'], '--brief', '--', str(original),
                     str(state['workspace'] / 'sources' / (name + '.bin'))], profile)
    require(result['exit_code'] == 0 and not result['stdout'], 'native original/workspace diff differs')


def replace_file(path, raw):
    path.chmod(0o600)
    with path.open('wb') as stream:
        require(stream.write(raw) == len(raw), 'negative fixture short write')
    path.chmod(0o400)


def mutate_tree(path, kind, state):
    path.chmod(0o700)
    source = path / 'sources' / 'S_CTRL_NEW.bin'
    if kind == 'source':
        replace_file(source, read(source).replace(b'100', b'999'))
    elif kind in ('annotations', 'index', 'versions', 'catalog'):
        name = {'annotations': 'annotations.json', 'index': 'index.txt',
                'versions': 'versions.json', 'catalog': 'catalog.json'}[kind]
        replace_file(path / name, read(path / name) + b' ')
    elif kind == 'missing':
        (path / 'index.txt').unlink()
    elif kind == 'extra':
        save(path / 'counter.json', b'0')
        (path / 'counter.json').chmod(0o400)
    elif kind == 'truncated':
        replace_file(path / 'workspace.json', read(path / 'workspace.json')[:-1])
    elif kind == 'symlink':
        (path / 'index.txt').unlink()
        (path / 'index.txt').symlink_to(state['annotations'])
    elif kind == 'hardlink':
        (path / 'extra-link').hardlink_to(source)
    elif kind == 'mode':
        (path / 'index.txt').chmod(0o444)
    elif kind == 'unknown-workspace-schema':
        value = json.loads(read(path / 'workspace.json'))
        value['schema'] = 'transport/native-source-workspace/999'
        replace_file(path / 'workspace.json', canonical(value))
    elif kind == 'workspace-bound':
        save(path / 'oversize.bin', b'x' * 1048577)
        (path / 'oversize.bin').chmod(0o400)
    else:
        raise AssertionError('unknown frozen negative tree operation')
    path.chmod(0o500)


def repinned_tree(path, kind):
    name = {'repin-old': 'index.txt', 'rehashed-index': 'index.txt',
            'rehashed-versions': 'versions.json', 'rehashed-catalog': 'catalog.json'}[kind]
    if name == 'index.txt':
        raw = read(path / name).replace(b'UNKNOWN', b'CURRENT', 1)
    else:
        value = json.loads(read(path / name))
        if name == 'versions.json':
            value['governing_version'] = 'AUTHENTICATED_CURRENT'
        else:
            value['result']['sources'] = []
        raw = canonical(value) + (b'\n' if name == 'catalog.json' else b'')
    replace_file(path / name, raw)
    manifest = json.loads(read(path / 'workspace.json'))
    manifest['files'][name] = record(raw)
    replace_file(path / 'workspace.json', canonical(manifest))
    return read(path / 'workspace.json')


def negative_trees(root, state):
    kinds = ('source', 'annotations', 'index', 'versions', 'catalog', 'missing', 'extra', 'truncated',
             'symlink', 'hardlink', 'mode', 'unknown-workspace-schema', 'workspace-bound',
             'repin-old', 'rehashed-index', 'rehashed-versions', 'rehashed-catalog')
    result = []
    for kind in kinds:
        path = root / 'negative-trees' / kind
        golden_tree(path, state)
        expected = state['expected_manifest']
        if kind.startswith('rehashed-') or kind == 'repin-old':
            updated = repinned_tree(path, kind)
            expected = expected if kind == 'repin-old' else updated
        else:
            mutate_tree(path, kind, state)
            if kind == 'unknown-workspace-schema':
                expected = read(path / 'workspace.json')
        result.append(dict(state, name=kind, workspace=path, expected_manifest=expected))
    return result


def prepare_negatives(root, state):
    result = []
    for kind in ('annotation-schema', 'annotation-bound', 'manifest-pin', 'annotation-pin',
                 'core-pin', 'existing-workspace', 'existing-receipt', 'overlap', 'unsafe-parent'):
        name = 'prepare-' + kind
        item = dict(state, name=name, workspace=root / 'outputs' / name,
                    receipt=root / 'receipts' / (name + '.json'))
        if kind.startswith('annotation-') and kind not in ('annotation-pin',):
            value = json.loads(state['files']['annotations.json'])
            value['schema'] = 'transport/retrieval-annotations/999'
            raw = canonical(value) if kind == 'annotation-schema' else b'x' * 65537
            path = root / 'inputs' / (name + '.json')
            save(path, raw)
            item.update(annotations=path, annotations_pin=pin(path))
        elif kind == 'existing-workspace':
            item['workspace'].mkdir(mode=0o700)
            save(item['workspace'] / 'sentinel', b'preserve')
        elif kind == 'existing-receipt':
            save(item['receipt'], b'preserve')
        elif kind == 'overlap':
            item['workspace'] = state['annotations'].parent / 'forbidden-output'
        elif kind == 'unsafe-parent':
            parent = root / 'unsafe-output'
            parent.mkdir(mode=0o755)
            item['workspace'] = parent / name
        result.append(item)
    return result


def run_negatives(root, trees, prepares, profile, contract):
    for state in trees:
        before = tree_files(state['workspace'])
        result, value = invoke(root, 'negative-' + state['name'], product_argv('verify', state, profile), profile)
        refusal_check(result, value, contract, None)
        require(tree_files(state['workspace']) == before, 'verification repaired negative tree')
    for state in prepares:
        argv = product_argv('prepare', state, profile)
        for kind, flag in (('manifest-pin', '--expect-manifest-sha256'),
                           ('annotation-pin', '--expect-annotations-sha256'), ('core-pin', '--expect-core-sha256')):
            if state['name'] == 'prepare-' + kind:
                argv[argv.index(flag) + 1] = '0' * 64
        before = tree_files(root / 'outputs')
        result, value = invoke(root, state['name'], argv, profile)
        refusal_check(result, value, contract)
        require(tree_files(root / 'outputs') == before, 'refused preparation changed published outputs')
        if state['name'] == 'prepare-existing-receipt':
            require(read(state['receipt']) == b'preserve', 'existing receipt overwritten')


def postpublish(root, state, profile, contract):
    item = dict(state, name='postpublish-receipt-fault', workspace=root / 'outputs' / 'postpublish-receipt-fault',
                receipt=root / 'receipts' / 'postpublish-receipt-fault.json')
    config = child_config(root, item['name'], item, profile['product_sha256'])
    result, value = invoke(root, item['name'], child_argv(profile, 'cli-receipt-fault', config), profile)
    refusal_check(result, value, contract, True)
    require(not item['receipt'].exists(), 'faulted receipt unexpectedly exists')
    exact_workspace(item)


def stdout_diagnostic(root, state, profile, contract):
    item = dict(state, name='postpublish-stdout-fault', workspace=root / 'outputs' / 'postpublish-stdout-fault',
                receipt=root / 'receipts' / 'postpublish-stdout-fault.json')
    config = child_config(root, item['name'], item, profile['product_sha256'])
    result = capture(root, item['name'], child_argv(profile, 'cli-stdout-fault', config), profile, True)
    require(result['exit_code'] == 1 and result['stdout'] == read(item['receipt'])[:11],
            'partial stdout fault did not preserve exact prefix without appended JSON')
    value = json.loads(result['stderr'])
    require(canonical(value) + b'\n' == result['stderr'], 'stderr sink refusal framing differs')
    refusal_check(result, value, contract, True)
    exact_workspace(item)


def checker_contracts(root):
    nodes = [dict(id='SOURCE', type='string', description='source identifier', min_bytes=1, max_bytes=32),
             dict(id='DIGEST', type='string', description='held SHA256', min_bytes=64, max_bytes=64),
             dict(id='OFFSET', type='integer', description='byte offset', min=0, max=65536),
             dict(id='QUOTE', type='string', description='complete literal quote', min_bytes=1, max_bytes=4096),
             dict(id='CITATION', type='object', description='closed anchored citation', fields={
                 'source_id': 'SOURCE', 'source_sha256': 'DIGEST', 'start': 'OFFSET', 'end': 'OFFSET', 'quote': 'QUOTE'}),
             dict(id='CITATIONS', type='array', description='bounded citation set', items='CITATION',
                  min_items=1, max_items=16, unique=False, unique_by=None),
             dict(id='RESPONSE', type='object', description='source spans only', fields={'citations': 'CITATIONS'})]
    structural = canonical(dict(schema='transport/response-contract/1', description='Literal source-span parity',
                                root='RESPONSE', nodes=nodes))
    evidence = canonical(dict(schema='transport/response-evidence-contract/1', description='No entailment claim',
                             response_contract_sha256=sha(structural), selectors=[['citations', '*']]))
    save(root / 'checker-structural.json', structural)
    save(root / 'checker-evidence.json', evidence)


def checker_module():
    sys.path.insert(0, str(INSTALL))
    names = ('transport_install_support', 'transport_install_layout', 'transport_handoff_inputs',
             'transport_response_contract_model', 'transport_response_contract', 'transport_response_evidence')
    modules = {name: load_module(name, INSTALL / (name + '.py')) for name in names}
    return modules['transport_response_contract_model'], modules['transport_response_contract'], modules['transport_response_evidence']


def citation_check(root, states, oracle):
    model, structural, evidence = checker_module()
    shape = model.compile_contract(read(root / 'checker-structural.json'))
    contract_raw = read(root / 'checker-evidence.json')
    observations = []
    for state in states:
        sources = {name: read(state['workspace'] / 'sources' / (name + '.bin')) for name in state['case']['source_ids']}
        held = {name: sha(state['files']['sources/' + name + '.bin']) for name in sources}
        for obligation in oracle['citation_obligations']:
            if obligation['case'] != state['case']['id']:
                continue
            citations, opaque = [], []
            for item in obligation['expected_citations']:
                quote = base64.b64decode(item['raw_quote_base64'], validate=True)
                require(sources[item['source']][slice(*item['span'])] == quote
                        and sha(quote) == item['quote_sha256'], 'full literal unit citation bytes differ')
                try:
                    text = quote.decode('utf-8', errors='strict')
                except UnicodeDecodeError:
                    opaque.append(item['unit'])
                    continue
                citations.append(dict(source_id=item['source'], source_sha256=item['source_sha256'],
                                      start=item['span'][0], end=item['span'][1], quote=text))
            checked = None
            if citations:
                candidate = canonical(dict(citations=citations))
                require(structural.validate(candidate, shape)['status'] == 'STRUCTURALLY_CONFORMANT', 'literal citation structure differs')
                checked = evidence.validate(candidate, contract_raw, sources, held)
                require(checked['status'] == 'SOURCE_SPANS_MATCH' and checked['selected_records'] == len(citations), 'checker source parity differs')
                originals = {name: state['files']['sources/' + name + '.bin'] for name in sources}
                require(evidence.validate(candidate, contract_raw, originals, held) == checked,
                        'same checker differs between original literals and native workspace')
                bad = copy.deepcopy(citations)
                bad[0]['quote'] = ('X' if bad[0]['quote'][0] != 'X' else 'Y') + bad[0]['quote'][1:]
                altered = canonical(dict(citations=bad))
                require(structural.validate(altered, shape)['status'] == 'STRUCTURALLY_CONFORMANT', 'negative quote must retain structure')
                rejected = False
                try:
                    evidence.validate(altered, contract_raw, sources, held)
                except ValueError:
                    rejected = True
                require(rejected, 'altered source quote accepted')
            observations.append(dict(case=state['name'], obligation=obligation['id'], checked=checked,
                                     opaque_byte_checked_only=opaque, semantics='NOT_ASSESSED'))
    save(root / 'citation-observations.json', observations)


def exhausted_binding(root, mode):
    if mode != 'local':
        return {'status': 'UNPERFORMED', 'scope': 'portable native reads have no client/session dependency'}
    previous = Path('/dev/shm/semantic-transport-retrieval-20261029/client-03')
    manifest = previous / 'inputs' / 'exhaust' / 'manifest.json'
    receipt = previous / 'receipts' / 'exhaust-32.json'
    session = previous / 'sessions' / 'exhaust'
    held_receipt = json.loads(read(receipt))
    require(held_receipt['call'] == 32, 'retained exhaustion receipt is not call32')
    entry = ROOT / 'comparison' / 'retrieval' / 'client' / 'entry.py'
    require(pin(entry)['sha256'] == '69c91ad134e2018fe74bb7cad9f6d5a5574d22b8feddf57d443c3a43a103dc7e', 'old client source differs')
    value = dict(status='RETAINED_CLIENT32_CONTROL', manifest=pin(manifest), receipt=pin(receipt),
                 next_head_sha256=held_receipt['next_head_sha256'], session=str(session), inventory=tree_files(session), entry=pin(entry))
    save(root / 'retained-client-binding.json', value)
    return value


def check_exhausted(root, held, when, profile):
    if held['status'] == 'UNPERFORMED':
        return
    require(pin(Path(held['manifest']['path'])) == held['manifest']
            and pin(Path(held['receipt']['path'])) == held['receipt'], 'retained external binding/head changed')
    require(tree_files(Path(held['session'])) == held['inventory'], 'retained exhausted journal changed')
    argv = [sys.executable, '-I', '-S', '-B', '-Werror', held['entry']['path'], '--manifest', held['manifest']['path'],
            '--expect-manifest-sha256', held['manifest']['sha256'], '--expect-session-head-sha256', held['next_head_sha256'],
            '--receipt', str(root / 'receipts' / ('exhausted-' + when + '.json')), '--request-json', '{"action":"catalog"}']
    result, value = invoke(root, 'exhausted-' + when, argv, profile)
    require(result['exit_code'] == 1 and value['status'] == 'REFUSED', 'exhausted client unexpectedly admitted another call')
    require(tree_files(Path(held['session'])) == held['inventory'], 'exhausted client refusal mutated journal')


def source_pins():
    paths = [PRODUCT, Path(__file__).absolute(), HERE / 'contract.json', HERE / 'oracle.json',
             ROOT / 'comparison' / 'retrieval' / 'oracle.json',
             ROOT / 'comparison' / 'retrieval' / 'retrieval.py', ROOT / 'comparison' / 'retrieval' / 'adapter.py']
    paths.extend(INSTALL / name for name in HELPERS)
    paths.extend(INSTALL / name for name in ('transport_response_contract_model.py', 'transport_response_contract.py'))
    paths.extend((HERE / 'contract-io-addendum.json', Path(sys.executable).resolve()))
    return [pin(path, 16777216) for path in paths]


def enforce_static():
    raw = read(Path(__file__).absolute())
    tree = ast.parse(raw)
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    require(all(node.end_lineno - node.lineno + 1 <= 60 for node in functions), 'test function AST line bound')
    require(not any(isinstance(node, (ast.While, ast.AsyncFor)) for node in ast.walk(tree)), 'unbounded loop syntax')
    return {'functions': len(functions), 'max_function_ast_lines': max(node.end_lineno - node.lineno + 1 for node in functions)}


def setup_root(path):
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'absolute canonical test root required')
    require(not path.exists() and path.parent.is_dir(), 'new test root with existing parent required')
    path.mkdir(mode=0o700)
    for name in ('inputs', 'outputs', 'receipts', 'captures', 'configs', 'tmp', 'negative-trees'):
        (path / name).mkdir(mode=0o700)


def freeze_run(root, states, trees, prepares, tools, profile, held, contract):
    checker_contracts(root)
    pins = source_pins()
    require(pin(HERE / 'contract-io-addendum.json')['sha256'] ==
            'f932f753d115e32642f739d97752cb35c88763ce39313bd54be7049bac8723fb', 'held I/O addendum differs')
    require(next(item for item in pins if item['path'] == str(PRODUCT))['sha256'] == profile['product_sha256'],
            'held product source differs before freeze')
    require(pin(ROOT / 'comparison' / 'retrieval' / 'retrieval.py')['sha256'] == CORE_SHA
            and pin(ROOT / 'comparison' / 'retrieval' / 'adapter.py')['sha256'] == ADAPTER_SHA, 'held old core/adapter differs')
    for name, held_tool in tools.items():
        result = capture(root, 'version-' + name, [held_tool['path'], '--version'], profile)
        require(result['exit_code'] == 0 and bool(result['stdout']), 'native tool version unavailable')
    for index, item in enumerate(pins):
        save(root / ('frozen-source-' + str(index) + '.bin'), read(Path(item['path']), 16777216))
    schedule = []
    for state in states:
        schedule.extend([{'label': state['name'] + '-prepare', 'argv': product_argv('prepare', state, profile)},
                         {'label': state['name'] + '-verify', 'argv': product_argv('verify', state, profile)}])
        config = child_config(root, state['name'] + '-api', state, profile['product_sha256'])
        schedule.append({'label': state['name'] + '-api', 'argv': child_argv(profile, 'verify', config)})
        item = dict(state, workspace=root / 'outputs' / (state['name'] + '-api-prepare'),
                    receipt=root / 'receipts' / (state['name'] + '-api-prepare.json'))
        config = child_config(root, state['name'] + '-api-prepare', item, profile['product_sha256'])
        schedule.append({'label': state['name'] + '-api-prepare', 'argv': child_argv(profile, 'prepare', config)})
    for state in trees:
        schedule.append({'label': 'negative-' + state['name'], 'argv': product_argv('verify', state, profile)})
    for state in prepares:
        schedule.append({'label': state['name'], 'argv_before_frozen_pin_control': product_argv('prepare', state, profile)})
    for label, action in (('postpublish-receipt-fault', 'cli-receipt-fault'),
                          ('postpublish-stdout-fault', 'cli-stdout-fault')):
        item = dict(states[0], workspace=root / 'outputs' / label, receipt=root / 'receipts' / (label + '.json'))
        config = child_config(root, label, item, profile['product_sha256'])
        schedule.append({'label': label, 'argv': child_argv(profile, action, config)})
    save(root / 'T-preparation.json', dict(schema='transport/independent-native-workflow-test-freeze/1',
         profile=profile, source_pins=pins, native_tools=tools, cases=[dict(name=item['name'],
         manifest=item['manifest_pin'], annotations=item['annotations_pin'], expected_workspace=record(item['expected_manifest']),
         expected_files={name: record(raw) for name, raw in item['files'].items()}) for item in states],
         schedule=schedule, held_client=held, initial_tree=tree_files(root), static=enforce_static(),
         expected_failure_kinds=[item['name'] for item in trees + prepares],
         postpublish='trusted OS open fault only at create-only receipt after real publication',
         stdout_sink_failure='trusted partial-prefix11 stdout sink fault after real publication; separate I/O diagnostic',
         interpretation='No semantic adequacy, source authority, actor, formal proof or benefit claim'))
    require(all(pin(Path(item['path']), 16777216) == item for item in pins), 'source changed during freeze')
    return pins


def run_campaign(root, mode, product_sha, optimized):
    setup_root(root)
    profile = dict(mode=mode, optimized=optimized, product_sha256=product_sha, executions=0,
         process=dict(wall_seconds=30, stdout_stderr_each_bytes=131072, fresh_flags=['-I', '-S', '-B', '-Werror'],
                      bounded_helper_as_hard_bytes=1073741824, bounded_helper_cpu_seconds=120,
                      bounded_helper_fsize_hard_bytes=33554432, bounded_helper_nofile=128),
         max_executions=MAX_EXECUTIONS, max_tree_files=MAX_FILES, scratch_limit_bytes=134217728,
         max_test_input_bytes=MAX_BYTES, portable_client_exhaustion='UNPERFORMED' if mode == 'portable' else 'RECHECK_RETAINED_32')
    try:
        contract = pinned_json(HERE / 'contract.json', CONTRACT_SHA)
        oracle = pinned_json(HERE / 'oracle.json', ORACLE_SHA)
        source_oracle = pinned_json(ROOT / 'comparison' / 'retrieval' / 'oracle.json', SOURCE_ORACLE_SHA)
        states = [make_state(root, case, arm, mode, source_oracle) for case in oracle['cases']
                  for arm in (('original', 'transport') if mode == 'local' else ('original',))]
        primary = states[0]
        trees, prepares = negative_trees(root, primary), prepare_negatives(root, primary)
        tools, held = tool_records(), exhausted_binding(root, mode)
        pins = freeze_run(root, states, trees, prepares, tools, profile, held, contract)
        check_exhausted(root, held, 'before', profile)
        for state in states:
            require(all(pin(Path(item['path']), 16777216) == item for item in pins), 'source changed after freeze')
            positive(root, state, profile, contract)
            native_calls(root, state, oracle, tools, profile)
            native_original(root, state, tools, profile)
        check_exhausted(root, held, 'after', profile)
        citation_check(root, states, oracle)
        run_negatives(root, trees, prepares, profile, contract)
        postpublish(root, primary, profile, contract)
        stdout_diagnostic(root, primary, profile, contract)
        receipt = dict(status='PASS', mode=mode, profile=profile, source_pins=pins,
                       cases=[item['name'] for item in states], native33='TESTED',
                       optional_client_exhaustion=held['status'], citation_semantics='NOT_ASSESSED',
                       stdout_sink_failure='TESTED_CONTROLLED_PREFIX11', strongest_baseline='UNQUALIFIED', authority='NONE')
        save(root / 'receipt.json', receipt)
        return receipt
    except BaseException as error:
        save(root / 'failure.json', dict(status='FAILED', type=type(error).__name__, reason=str(error), profile=profile))
        raise


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--mode', choices=('portable', 'local'), default='portable')
    parser.add_argument('--expect-product-sha256')
    parser.add_argument('--optimized', action='store_true')
    parser.add_argument('--child', choices=('verify', 'prepare', 'cli-receipt-fault', 'cli-stdout-fault'))
    parser.add_argument('--config', type=Path)
    value = parser.parse_args()
    if value.child:
        require(value.config is not None and value.root is None, 'closed child arguments')
    else:
        require(value.root is not None and value.expect_product_sha256 is not None, 'root and external product SHA required')
    return value


def main():
    args = arguments()
    if args.child:
        api_child(args.child, args.config)
        return
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (1073741824, 1073741824))
    value = run_campaign(args.root, args.mode, args.expect_product_sha256, args.optimized)
    sys.stdout.buffer.write(canonical(dict(status=value['status'], root=str(args.root))) + b'\n')


if __name__ == '__main__':
    main()
