#!/usr/bin/env python3
"""Run held literal native-tool controls against previously verified workspaces."""

import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
PROJECT = HERE.parents[1]
ORACLE = HERE / 'native-tool-oracle.json'
PRODUCT = HERE / 'native_workspace.py'
SUPPORT = PROJECT / 'install' / 'transport_install_support.py'
ORACLE_SHA = '84ae47da461caabc9956706172a04409fcf93864485e64d51af9634cb61f705e'
FIXED = {
    PRODUCT: '4679aae738dd3efb9c4840e677ec6e55e8a423dd7c8522a0addf6612a6bbfbc1',
    HERE / 'test_workflow.py': '2abaa40398c01c504b6fa8dc87fa4413ba6b527797dd80ff242df679e68cef6a',
    PROJECT / 'comparison/retrieval/retrieval.py': 'd19199a73b9994b125dbdbc2cee1c6250e91832e9d33317e8f54fe390341c7e6',
    PROJECT / 'comparison/retrieval/adapter.py': '83bde7b42d687877b677b1649741a7f848e9a4d65da3b76838d9a445bb6c7811',
    SUPPORT: 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da',
}
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TERM': 'dumb'}
MAX_BYTES, MAX_FILES, MAX_CALLS, STREAM_CAP = 8388608, 256, 32, 8192


def require(condition, reason):
    if type(condition) is not bool or not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def record(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def absolute(text):
    require(type(text) is str and 0 < len(os.fsencode(text)) < 4096, 'path byte bound')
    require('\0' not in text and os.path.isabs(text) and os.path.normpath(text) == text,
            'absolute normalized path required')
    path = Path(text)
    require(len(path.parts) <= 64 and '..' not in path.parts, 'path component bound')
    return path


def directories(path):
    require(path.is_absolute() and len(path.parts) <= 64, 'directory path bound')
    current = Path('/')
    for part in path.parts[1:]:
        current = current / part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode), 'directory or ancestor is unsafe')


def read(path, cap=4194304):
    require(type(cap) is int and 0 <= cap <= 16777216, 'read byte bound')
    directories(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe input file')
        require(before.st_size <= cap, 'input byte bound')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    identity = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, key) == getattr(after, key) for key in identity)
            and len(raw) == before.st_size and len(raw) <= cap,
            'input changed or exceeded bound')
    return raw


def pin(path, cap=16777216):
    return dict(record(read(path, cap)), path=str(path))


def held_json(path, expected=None):
    raw = read(path)
    require(expected is None or record(raw)['sha256'] == expected, 'held JSON pin differs')
    value = json.loads(raw)
    require(type(value) is dict and canonical(value) == raw, 'canonical JSON object required')
    return raw, value


def write(state, relative, value):
    raw = value if type(value) is bytes else canonical(value)
    require(len(raw) <= 4194304 and state['bytes'] + len(raw) <= MAX_BYTES, 'output byte bound')
    require(state['files'] < MAX_FILES, 'output file bound')
    require(type(relative) is str and '/' not in relative and relative not in ('', '.', '..'),
            'flat output member required')
    with (state['root'] / relative).open('xb') as stream:
        require(stream.write(raw) == len(raw), 'short create-only evidence write')
    state['bytes'] += len(raw)
    state['files'] += 1


def setup(path, campaign):
    directories(path.parent)
    require(not path.exists() and not path.is_symlink(), 'new evidence root required')
    require(not any(parent == PROJECT or parent == campaign for parent in (path, *path.parents)),
            'evidence root overlaps protected read roots')
    parent = path.parent.stat()
    require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) & 0o077 == 0,
            'privately owned output parent required')
    path.mkdir(mode=0o700)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'private evidence root mode differs')
    return {'root': path, 'bytes': 0, 'files': 0, 'calls': 0}


def source_pins(base):
    require(type(base.get('source_pins')) is list and 1 <= len(base['source_pins']) <= 32,
            'base source inventory bound')
    pins = list(base['source_pins'])
    require(len({item['path'] for item in pins}) == len(pins), 'duplicate base source pin')
    for path, expected in FIXED.items():
        require(any(item['path'] == str(path) and item['sha256'] == expected for item in pins),
                'base fixed source identity differs')
    pins.extend([pin(Path(__file__).absolute()), pin(ORACLE)])
    require(pin(ORACLE)['sha256'] == ORACLE_SHA, 'literal tool oracle changed')
    python = pin(Path(sys.executable).resolve())
    require(python in pins, 'current Python differs from base campaign')
    return pins


def validate_pins(pins):
    require(1 <= len(pins) <= 64, 'pin inventory bound')
    for item in pins:
        require(pin(absolute(item['path'])) == item, 'held source or tool changed: ' + item['path'])


def base_campaign(campaign, expected, expected_receipt):
    raw, base = held_json(campaign / 'T-preparation.json', expected)
    require(base.get('schema') == 'transport/independent-native-workflow-test-freeze/1',
            'unsupported base campaign schema')
    receipt_raw, receipt = held_json(campaign / 'receipt.json', expected_receipt)
    require(receipt.get('status') == 'PASS' and not (campaign / 'failure.json').exists(),
            'existing complete PASS campaign required')
    require(receipt.get('source_pins') == base.get('source_pins'), 'base PASS source pins differ')
    require(base.get('profile', {}).get('product_sha256') == FIXED[PRODUCT], 'base product differs')
    require(type(base.get('cases')) is list and 1 <= len(base['cases']) <= 6, 'base cases bound')
    require(receipt.get('cases') == [item['name'] for item in base['cases']]
            and receipt.get('mode') == base['profile']['mode'], 'base PASS cases or mode differ')
    before, after = base['profile'], receipt.get('profile', {})
    require(set(before) == set(after) and
            {key: value for key, value in before.items() if key != 'executions'} ==
            {key: value for key, value in after.items() if key != 'executions'},
            'base PASS execution profile differs')
    require(type(after['executions']) is int and
            before['executions'] <= after['executions'] <= before['max_executions'],
            'base PASS process count differs')
    require(receipt.get('authority') == 'NONE' and receipt.get('strongest_baseline') == 'UNQUALIFIED',
            'base PASS claim scope differs')
    selected = [item for item in base['cases'] if item['name'] in
                ('NATIVE_MAIN-original', 'NATIVE_MAIN-transport')]
    require([item['name'] for item in selected] in
            (['NATIVE_MAIN-original'], ['NATIVE_MAIN-original', 'NATIVE_MAIN-transport']),
            'MAIN original and optional transport order required')
    return raw, base, receipt_raw, selected


def held_tools(campaign, base):
    require(set(base.get('native_tools', {})) == {'cat', 'rg', 'diff'}, 'base native tools differ')
    versions, files = {}, {}
    for name in ('cat', 'rg', 'diff'):
        tool = base['native_tools'][name]
        require(tool.get('path') == '/usr/bin/' + name and pin(Path(tool['path'])) == tool,
                'current tool binary differs from base version identity')
        captures = {suffix: read(campaign / 'captures' / ('version-' + name + '.' + suffix), 131072)
                    for suffix in ('json', 'stdout', 'stderr')}
        require(all(base['initial_tree'].get('captures/version-' + name + '.' + suffix) == record(raw)
                    for suffix, raw in captures.items()), 'base version capture differs from held preparation')
        detail = json.loads(captures['json'])
        require(detail['argv'] == [tool['path'], '--version'] and detail['status'] == 'SUCCESS'
                and detail['exit_code'] == 0 and not captures['stderr'], 'base version capture failed')
        require(all(detail[key] == record(captures[key]) for key in ('stdout', 'stderr')),
                'base version raw streams differ')
        versions[name] = {'binary': tool, 'version_stdout': record(captures['stdout']),
                          'base_record': record(captures['json'])}
        files.update({'base-version-' + name + '.' + key: raw for key, raw in captures.items()})
    return versions, files


def states(campaign, cases, oracle):
    found = []
    for case in cases:
        workspace = campaign / 'outputs' / case['name']
        directories(workspace)
        require(record(read(workspace / 'workspace.json')) == case['expected_workspace'],
                'workspace differs from externally held base expectation')
        for source in oracle['source_files'].values():
            require(case['expected_files'].get(source['path']) ==
                    {'bytes': source['bytes'], 'sha256': source['sha256']},
                    'base source expectation differs from frozen literal')
        found.append({'name': case['name'], 'arm': case['name'].split('-')[-1],
                      'workspace': str(workspace), 'expected_workspace': case['expected_workspace'],
                      'expected_files': case['expected_files']})
    return found


def source_check(item, oracle):
    result = {}
    for source_id, source in oracle['source_files'].items():
        observed = record(read(Path(item['workspace']) / source['path'], 65536))
        require(observed == {'bytes': source['bytes'], 'sha256': source['sha256']},
                'held source changed: ' + source_id)
        result[source_id] = observed
    return result


def verify_argv(item, optimized):
    argv = [str(Path(sys.executable).resolve()), '-I', '-S', '-B']
    if optimized:
        argv.append('-O')
    return argv + ['-Werror', str(PRODUCT), 'verify', '--workspace', item['workspace'],
                   '--expect-workspace-manifest-sha256', item['expected_workspace']['sha256']]


def schedule(items, oracle, tools, optimized):
    operations = oracle.get('operations')
    require(type(operations) is list and len(operations) == 6, 'exact six-operation oracle required')
    result = []
    for item in items:
        result.append({'label': item['name'] + '-preverify', 'kind': 'verify', 'arm': item['arm'],
                       'argv': verify_argv(item, optimized), 'cwd': item['workspace']})
        for operation in operations:
            argv = list(operation['argv'])
            argv[0] = tools[argv[0]]['binary']['path']
            result.append({'label': item['name'] + '-' + operation['id'], 'kind': 'native',
                           'arm': item['arm'], 'oracle_id': operation['id'], 'argv': argv,
                           'cwd': item['workspace']})
        result.append({'label': item['name'] + '-postverify', 'kind': 'verify', 'arm': item['arm'],
                       'argv': verify_argv(item, optimized), 'cwd': item['workspace']})
    require(len(result) <= MAX_CALLS, 'scheduled process count bound')
    return result


def static_check():
    tree = ast.parse(read(Path(__file__).absolute()))
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    require(bool(functions) and all(node.end_lineno - node.lineno + 1 <= 60 for node in functions),
            'function AST line bound')
    require(not any(isinstance(node, (ast.While, ast.AsyncFor)) for node in ast.walk(tree)),
            'unbounded loop syntax')
    return {'functions': len(functions), 'max_function_ast_lines':
            max(node.end_lineno - node.lineno + 1 for node in functions)}


def support(raw):
    require(record(raw)['sha256'] == FIXED[SUPPORT], 'held process helper differs')
    module = types.ModuleType('native_tool_process_support')
    module.__file__ = str(SUPPORT)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(SUPPORT), 'exec'), module.__dict__)
    return module


def capture(state, entry, helper, pins):
    validate_pins(pins)
    state['calls'] += 1
    require(state['calls'] <= MAX_CALLS, 'process count bound')
    result = helper.run_bounded(entry['argv'], Path(entry['cwd']), ENV, timeout=30, cap=STREAM_CAP)
    for stream in ('stdout', 'stderr'):
        write(state, entry['label'] + '.' + stream, result[stream])
    detail = {key: value for key, value in result.items() if key not in ('stdout', 'stderr', 'elapsed_ns')}
    detail.update(entry)
    detail.update({stream: record(result[stream]) for stream in ('stdout', 'stderr')})
    detail['environment'] = ENV
    detail['costs'] = {'wall_ns': result['elapsed_ns'], 'scope': 'FRESH_PROCESS',
                       'cpu_and_peak_memory': 'UNMEASURED'}
    write(state, entry['label'] + '.json', detail)
    require(result['status'] in ('SUCCESS', 'EXIT_NONZERO'), 'failed or truncated process capture')
    require(len(result['stdout']) <= STREAM_CAP and len(result['stderr']) <= STREAM_CAP,
            'stream byte bound')
    validate_pins(pins)
    return result


def verify_result(result, item, oracle):
    require(result['exit_code'] == 0 and not result['stderr'], 'workspace verification process failed')
    raw = result['stdout']
    value = json.loads(raw)
    require(canonical(value) + b'\n' == raw, 'complete canonical verification response required')
    required = {'schema', 'status', 'workspace_manifest', 'source_snapshot', 'file_count',
                'workspace_bytes', 'authority', 'freshness', 'context_adequacy', 'data_is_untrusted', 'costs'}
    require(set(value) == required, 'verification response fields differ')
    require(value['schema'] == 'transport/native-workflow-verification/1'
            and value['status'] == 'VERIFIED_NATIVE_FILES', 'workspace not verified')
    require(value['workspace_manifest'] == item['expected_workspace']
            and value['source_snapshot'] == oracle['source_snapshot'], 'verification identity differs')
    require((value['authority'], value['freshness'], value['context_adequacy'], value['data_is_untrusted'])
            == ('NONE', 'UNKNOWN', 'UNPROVEN', True), 'verification claim scope differs')
    expected = list(item['expected_files'].values()) + [item['expected_workspace']]
    require(value['file_count'] == len(expected) and value['workspace_bytes'] == sum(x['bytes'] for x in expected),
            'verification complete tree inventory differs')
    require(type(value['costs']) is dict and bool(value['costs']), 'observed verification costs missing')


def native_result(result, operation):
    require(result['exit_code'] == operation['expected_exit'], 'literal tool exit differs')
    for stream in ('stdout', 'stderr'):
        expected = operation['expected_' + stream]
        raw = base64.b64decode(expected['base64'], validate=True)
        require(record(raw) == {'bytes': expected['bytes'], 'sha256': expected['sha256']},
                'literal tool oracle stream pin differs')
        require(result[stream] == raw, 'literal tool stream differs: ' + operation['id'] + '/' + stream)


def freeze(state, campaign, base_raw, receipt_raw, base, items, oracle, tools, files, profile):
    pins = source_pins(base) + [tools[name]['binary'] for name in ('cat', 'rg', 'diff')]
    pins.extend([dict(record(base_raw), path=str(campaign / 'T-preparation.json')),
                 dict(record(receipt_raw), path=str(campaign / 'receipt.json'))])
    validate_pins(pins)
    calls = schedule(items, oracle, tools, profile['optimized'])
    write(state, 'runner.initial.raw.py', read(Path(__file__).absolute()))
    write(state, 'oracle.initial.raw.json', read(ORACLE))
    write(state, 'base-T-preparation.raw.json', base_raw)
    write(state, 'base-receipt.raw.json', receipt_raw)
    helper_raw = read(SUPPORT)
    write(state, 'process-helper.initial.raw.py', helper_raw)
    for name, raw in files.items():
        write(state, name, raw)
    initial_sources = {item['name']: source_check(item, oracle) for item in items}
    preparation = {'schema': 'transport/native-tool-run-freeze/1', 'profile': profile,
                   'base_campaign': str(campaign), 'base_preparation': record(base_raw),
                   'base_PASS_receipt': record(receipt_raw), 'pins': pins, 'tools': tools,
                   'states': items, 'initial_source_pins': initial_sources, 'schedule': calls,
                   'environment': ENV, 'static': static_check(), 'authority': 'NONE',
                   'strongest_baseline': 'UNQUALIFIED', 'receiver_benefit': 'UNRUN'}
    write(state, 'T-preparation.json', preparation)
    validate_pins(pins)
    return pins, calls, helper_raw


def audit_output(state):
    import itertools
    entries = list(itertools.islice(state['root'].iterdir(), MAX_FILES + 1))
    require(len(entries) == state['files'] and len(entries) <= MAX_FILES, 'output file inventory differs')
    total = 0
    for path in entries:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe evidence tree member')
        total += info.st_size
    require(total == state['bytes'] and total <= MAX_BYTES, 'output aggregate byte bound')


def execute(state, items, oracle, pins, calls, helper_raw):
    helper = support(helper_raw)
    operations = {item['id']: item for item in oracle['operations']}
    observations = []
    for entry in calls:
        item = next(value for value in items if value['arm'] == entry['arm'])
        before = source_check(item, oracle)
        result = capture(state, entry, helper, pins)
        if entry['kind'] == 'verify':
            verify_result(result, item, oracle)
        else:
            native_result(result, operations[entry['oracle_id']])
        after = source_check(item, oracle)
        require(before == after, 'source changed during native/verify call')
        observations.append({'label': entry['label'], 'status': 'PASS', 'before': before, 'after': after})
    write(state, 'observations.json', observations)
    validate_pins(pins)
    audit_output(state)
    receipt = {'schema': 'transport/native-tool-run-receipt/1', 'status': 'PASS',
               'preparation': record(read(state['root'] / 'T-preparation.json')),
               'calls': state['calls'], 'native_operations_per_arm': 6,
               'arms': [item['arm'] for item in items], 'authority': 'NONE',
               'semantic_adequacy': 'UNPROVEN', 'receiver_benefit': 'UNRUN',
               'strongest_baseline': 'UNQUALIFIED'}
    write(state, 'receipt.json', receipt)
    audit_output(state)
    return receipt


def run(args):
    campaign, root = absolute(args.campaign_root), absolute(args.root)
    directories(campaign)
    state = setup(root, campaign)
    profile = {'optimized': args.optimized, 'harness_optimized': bool(sys.flags.optimize),
               'wall_seconds': 30, 'stdout_stderr_each_bytes': STREAM_CAP,
               'max_process_calls': MAX_CALLS, 'max_native_operations_per_arm': 16,
               'max_output_bytes': MAX_BYTES, 'max_output_files': MAX_FILES,
               'helper_limits': {'address_space_bytes': 1073741824, 'cpu_seconds': 120,
                                 'file_bytes': 33554432, 'open_files': 128}}
    try:
        base_raw, base, receipt_raw, cases = base_campaign(campaign, args.expect_campaign_sha256,
                                                         args.expect_campaign_receipt_sha256)
        _, oracle = held_json(ORACLE, ORACLE_SHA)
        items = states(campaign, cases, oracle)
        tools, files = held_tools(campaign, base)
        pins, calls, helper_raw = freeze(state, campaign, base_raw, receipt_raw, base, items,
                                        oracle, tools, files, profile)
        return execute(state, items, oracle, pins, calls, helper_raw)
    except BaseException as error:
        write(state, 'failure.json', {'status': 'FAILED', 'type': type(error).__name__,
                                      'reason': str(error)[:4096], 'calls': state['calls'], 'profile': profile})
        raise


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--campaign-root', required=True)
    parser.add_argument('--expect-campaign-sha256', required=True)
    parser.add_argument('--expect-campaign-receipt-sha256', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--optimized', action='store_true')
    args = parser.parse_args()
    for value in (args.expect_campaign_sha256, args.expect_campaign_receipt_sha256):
        require(len(value) == 64 and all(char in '0123456789abcdef' for char in value), 'held digest syntax')
    return args


def main():
    try:
        result = run(arguments())
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print('FAILED: ' + str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(result) + b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
