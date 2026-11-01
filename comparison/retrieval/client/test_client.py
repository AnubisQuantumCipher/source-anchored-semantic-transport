#!/usr/bin/env python3
"""Independent receiving-client integration from held contracts and raw sources.

The new client implementation is not imported or inspected. Every execution is
bounded and retained. Development source-linkage tests do not establish semantic
adequacy, hostile same-user isolation, strongest-baseline status or benefit.
"""

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
RETRIEVAL = HERE.parent
BASE = Path('/dev/shm/semantic-transport-retrieval-20261029')
FIXTURES = BASE / 'adapter-02'
INSTALL = RETRIEVAL.parents[1] / 'install'
ORACLE_SHA = '23525546f46513b5d1c45acfa2161d6d5266ae2446d88deff66f4aa7d5a690f3'
SUPPORT_SHA = 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da'
CLIENT_CONTRACT_SHA = 'd7886289c14ca67a4b6b19f041a2edfeb4c344d654aece7eba9681a56905b443'
CLIENT_ORACLE_SHA = '7d18d07f12b52b3acf58c427a9c8fea866a60131a2b61e5a5672d5664c937ef7'
LONG_ARGV_LAUNCHER = b'''import os, sys
args = sys.argv[1:]
if len(args) > 32 or args[0] != sys.executable:
    raise ValueError('fixed test Python/argv required')
index = args.index('--request-json') + 1
if args[index] != '__FROZEN_70000_X_REQUEST__':
    raise ValueError('fixed literal oversize case required')
args[index] = 'x' * 70000
os.execve(sys.executable, args, dict(os.environ))
'''


def require(condition, reason):
    if type(condition) is not bool or not condition:
        raise AssertionError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    with path.open('xb') as output:
        require(output.write(raw) == len(raw), 'short create-only write')


def pin(path):
    raw = path.read_bytes()
    require(len(raw) <= 4194304, 'test input byte bound')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def support_module():
    path = INSTALL / 'transport_install_support.py'
    require(pin(path)['sha256'] == SUPPORT_SHA, 'approved process helper differs')
    specification = importlib.util.spec_from_file_location('client_test_support', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def input_fixture(scenario):
    require(scenario in ('SC_MAIN', 'SC_NEG'), 'unknown literal fixture')
    directory = FIXTURES / scenario
    frozen = json.loads((FIXTURES / 'T-preparation.json').read_bytes())
    index = 0 if scenario == 'SC_MAIN' else 1
    held = frozen['scenarios'][index]
    for name in ('annotations.json', 'authoring.json', 'requests.jsonl', 'expected.json'):
        require(pin(directory / name) == held[name], 'original fixture freeze differs: ' + name)
    actual = [pin(path) for path in sorted((directory / 'original-content').iterdir())]
    require(actual == held['original_sources'], 'original fixture source pins differ')
    raw_oracle = (RETRIEVAL / 'oracle.json').read_bytes()
    require(sha(raw_oracle) == ORACLE_SHA, 'original public oracle differs')
    value = json.loads(raw_oracle)
    originals = {path.stem: path.read_bytes() for path in (directory / 'original-content').iterdir()}
    for item in value['sources']:
        if item['id'] in originals:
            require(originals[item['id']] == base64.b64decode(item['raw_base64'], validate=True),
                    'fixture source bytes differ from original oracle')
    return directory, json.loads((directory / 'annotations.json').read_bytes()), originals


def identity(manifest, expected):
    return {'schema': 'transport/handoff-session/1', 'manifest_path': str(manifest.absolute()),
            'manifest_sha256': expected, 'max_calls': 32, 'max_bytes': 8388608}


def session_snapshot(session):
    if not session.exists():
        return None
    require(len(list(session.iterdir())) <= 100, 'session member bound')
    return {path.name: pin(path) for path in sorted(session.iterdir())}


def execute(root, label, argv):
    if any(len(value) > 4096 for value in argv):
        require(argv[-2:] == ['--request-json', 'x' * 70000], 'unapproved long test argument')
        inner = list(argv)
        inner[-1] = '__FROZEN_70000_X_REQUEST__'
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(root / 'long_argv.py')] + inner
    result = support_module().run_bounded(argv, root,
        {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': str(root / 'tmp')},
        timeout=30, cap=131072)
    for stream in ('stdout', 'stderr'):
        save(root / (label + '.' + stream), result[stream])
    record = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    record.update({stream: {'bytes': len(result[stream]), 'sha256': sha(result[stream])}
                   for stream in ('stdout', 'stderr')})
    save(root / (label + '.json'), record)
    require(not result['stderr'], 'client emitted stderr; direct output retained')
    require(result['stdout'].endswith(b'\n') and len(result['stdout']) <= 131072, 'outer response bound')
    response = json.loads(result['stdout'])
    require(result['stdout'] == canonical(response) + b'\n', 'outer response canonical framing')
    return result, response


def expected_unit_payloads(annotations, originals, names):
    units = {item['id']: item for item in annotations['units']}
    result = []
    for name in sorted(names):
        unit = units[name]
        begin, end = unit['span']
        raw = originals[unit['source']][begin:end]
        require(sha(raw) == unit['sha256'], 'literal expected quote anchor differs')
        result.append(dict(unit, bytes_base64=base64.b64encode(raw).decode('ascii')))
    return result


def verify_catalog(inner, annotations):
    expected_sources = sorted(annotations['sources'], key=lambda item: item['id'])
    expected_units = sorted(annotations['units'], key=lambda item: item['id'])
    require(inner['status'] == 'OK' and inner['result']['sources'] == expected_sources
            and inner['result']['units'] == expected_units, 'catalog fixed original annotations differ')


def verify_units(inner, annotations, originals, names):
    require(inner['status'] == 'OK' and inner['result']['unit_ids'] == sorted(names)
            and inner['result']['units'] == expected_unit_payloads(annotations, originals, names),
            'adaptive complete source unit payload differs from literal oracle')


def verify_core_boundary(inner):
    require(inner['schema'] == 'transport/matched-retrieval-response/1' and inner['call'] == 1
            and inner['authority'] == 'NONE' and inner['freshness'] == 'UNKNOWN'
            and inner['context_adequacy'] == 'UNPROVEN' and inner['data_is_untrusted'] is True,
            'fresh-worker core boundary differs')


def verify_journal(session, number, manifest, expected, request, response, complete=True, input_bytes=None):
    previous = sha(canonical(identity(manifest, expected))) if number == 1 else sha(
        (session / ('call-%02d.json' % (number - 1))).read_bytes())
    raw = (session / ('call-%02d.json' % number)).read_bytes()
    item = json.loads(raw)
    require(raw == canonical(item) and item['index'] == number and item['previous'] == previous
            and item['manifest_sha256'] == expected, 'durable journal identity differs')
    saved_request = (session / ('request-%02d.json' % number)).read_bytes()
    saved_response = (session / ('response-%02d.json' % number)).read_bytes()
    require(saved_request == request and saved_response == response, 'durable streams differ from direct I/O')
    for key, data in (('request', saved_request), ('response', saved_response)):
        require(item[key] == {'bytes': len(data), 'sha256': sha(data)}, 'journal stream pin differs')
    require(item['request_complete'] is complete and item['input_bytes'] ==
            (len(request) if input_bytes is None else input_bytes), 'journal completeness/length differs')
    require(item['candidate'] is None, 'retrieval journal acquired candidate authority')
    return sha(raw)


def make_binding(root, name, fixture, arm, changes=None):
    directory, _, _ = input_fixture(fixture)
    parent = root / 'inputs' / name
    parent.mkdir(mode=0o700)
    value = {'schema': 'transport/adaptive-retrieval-client/1',
             'handoff_manifest': pin(directory / (arm + '-manifest.json')),
             'annotations': pin(directory / 'annotations.json'), 'core': pin(RETRIEVAL / 'retrieval.py'),
             'adapter': pin(RETRIEVAL / 'adapter.py'), 'client': pin(HERE / 'entry.py'),
             'python': pin(Path(sys.executable).resolve()), 'session': str(root / 'sessions' / name)}
    if changes is not None:
        value.update(changes)
    path = parent / 'manifest.json'
    save(path, value)
    expected = pin(path)['sha256']
    return {'manifest': path, 'expected': expected, 'session': Path(value['session']),
            'head': sha(canonical(identity(path, expected))), 'calls': 0, 'arm': arm,
            'fixture': fixture, 'binding': value}


def argv_for(root, label, state, request):
    receipt = root / 'receipts' / (label + '.json')
    argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'entry.py'),
            '--manifest', str(state['manifest']), '--expect-manifest-sha256', state['expected'],
            '--expect-session-head-sha256', state['head'], '--receipt', str(receipt),
            '--request-json', request.decode('utf-8')]
    return argv, receipt


def admitted(root, label, state, request, embedded=True, complete=True, input_bytes=None, file_input=False):
    raw = canonical(request) if type(request) is dict else request
    argv, receipt_path = argv_for(root, label, state, raw)
    if file_input:
        path = root / 'requests' / (label + '.json')
        save(path, raw)
        argv[argv.index('--request-json'):] = ['--request-file', str(path), '--expect-request-sha256', sha(raw)]
    direct, outer = execute(root, label, argv)
    number = state['calls'] + 1
    require(outer['schema'] == 'transport/handoff-response/1' and outer['call'] == number
            and outer['arm'] == state['arm'], 'durable outer envelope identity differs')
    saved = raw[:65537]
    next_head = verify_journal(state['session'], number, state['manifest'], state['expected'],
                               saved, direct['stdout'], complete, input_bytes)
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt['schema'] == 'transport/adaptive-retrieval-call-receipt/1'
            and receipt['manifest_sha256'] == state['expected'] and receipt['call'] == number
            and receipt['previous_head_sha256'] == state['head'] and receipt['next_head_sha256'] == next_head
            and receipt['response'] == {'bytes': len(direct['stdout']), 'sha256': sha(direct['stdout'])}
            and receipt['request'] == {'bytes': len(saved), 'sha256': sha(saved)}
            and receipt['status'] == outer['status'] and receipt['authority'] == 'NONE'
            and type(receipt['costs']) is dict, 'separate post-commit receipt differs')
    state.update(head=next_head, calls=number)
    if not embedded:
        require(outer['status'] == 'REFUSED', 'expected logged outer refusal')
        return outer
    result = outer['result']
    require(set(result) == {'schema', 'core_response_base64', 'inner_counter_scope'}
            and result['schema'] == 'transport/adaptive-retrieval-result/1'
            and result['inner_counter_scope'] == 'ONE_FRESH_WORKER', 'embedded core wrapper differs')
    inner_raw = base64.b64decode(result['core_response_base64'], validate=True)
    inner = json.loads(inner_raw)
    require(inner_raw == canonical(inner) + b'\n', 'core response bytes modified/framing differs')
    verify_core_boundary(inner)
    require(outer['status'] == inner['status'], 'outer status differs from core status')
    return inner


def uncounted(root, label, state, argv=None):
    before = session_snapshot(state['session'])
    if argv is None:
        argv, receipt = argv_for(root, label, state, canonical({'action': 'catalog'}))
    else:
        receipt = Path(argv[argv.index('--receipt') + 1])
    direct, outer = execute(root, label, argv)
    require(direct['exit_code'] != 0 and outer['status'] == 'REFUSED', 'preflight rejection not explicit')
    require(outer['arm'] == 'UNKNOWN' and outer['call'] == 0
            and outer['result']['recorded_may_exist'] is False, 'uncounted refusal boundary differs')
    require(session_snapshot(state['session']) == before and not receipt.exists(),
            'uncounted refusal appended journal or published success receipt')
    return outer


def adaptive(root, state, prefix):
    _, annotations, originals = input_fixture(state['fixture'])
    catalog = admitted(root, prefix + '-catalog', state, {'action': 'catalog'})
    verify_catalog(catalog, annotations)
    main = state['fixture'] == 'SC_MAIN'
    source, phrase = ('S_CTRL_NEW', '100 ms') if main else ('S_MISSING', 'amber valve')
    search = admitted(root, prefix + '-search', state,
        {'action': 'search', 'sources': [source], 'mode': 'exact_phrase', 'field': 'source',
         'query': phrase, 'offset': 0, 'limit': 16})
    observed = [item['id'] for item in search['result']['unit_matches']]
    expected_roots = ['U_CTRL_NEW'] if main else ['U_MISSING_RULE']
    require(observed == expected_roots, 'adaptive observed search roots differ from fixed oracle')
    expanded = admitted(root, prefix + '-expand', state, {'action': 'expand', 'units': observed})
    queried = admitted(root, prefix + '-query', state,
        {'action': 'query', 'sources': [source], 'mode': 'exact_phrase', 'field': 'source', 'query': phrase})
    if main:
        for result in (expanded, queried):
            verify_units(result, annotations, originals, ['U_CTRL_NEW', 'U_DEF_NEW', 'U_MAINT'])
    else:
        for result in (expanded, queried):
            require(result['status'] == 'REFUSED' and result['result'] ==
                    {'reason': 'REFUSED_MISSING_DEPENDENCY'}, 'missing dependency lost across adaptive calls')
    trace = admitted(root, prefix + '-trace', state,
                     {'action': 'trace', 'source': 'S_CTRL_NEW' if main else 'S_APPROVAL_NEW'})
    require(trace['status'] == 'OK' and trace['result']['governing_version'] == 'UNKNOWN'
            and trace['result']['version_labels'] == 'DECLARED_NOT_AUTHENTICATED', 'trace authority boundary')
    page = admitted(root, prefix + '-page', state, {'action': 'page', 'source': 'S_OPAQUE', 'offset': 0})
    require(base64.b64decode(page['result']['bytes_base64'], validate=True) == originals['S_OPAQUE']
            and page['result']['source_sha256'] == sha(originals['S_OPAQUE'])
            and page['result']['utf8'] is None, 'opaque original bytes differ')
    return [catalog, search, expanded, queried, trace, page]


def literal_adaptive(root, state, prefix, oracle):
    outputs, catalog, search, selected = [], None, None, None
    for step in oracle['adaptive_steps']:
        raw = step['request_utf8'].encode('utf-8')
        request = json.loads(raw)
        if step['id'] == 'C_SEARCH':
            request['sources'] = [item['id'] for item in catalog['result']['sources'] if item['id'] == 'S_REVIEWS']
        elif step['id'] == 'C_EXPAND':
            request['units'] = [item['id'] for item in search['result']['unit_matches']]
        elif step['id'] == 'C_QUERY':
            request['sources'] = [item['id'] for item in catalog['result']['sources'] if item['id'] == 'S_CTRL_NEW']
        elif step['id'] in ('C_TRACE', 'C_PAGE'):
            request['source'] = selected
        require(canonical(request) == raw and step['request'] == {'bytes': len(raw), 'sha256': sha(raw)},
                'adaptive observed request differs from independently frozen literal')
        result = admitted(root, prefix + '-' + step['id'], state, raw, file_input=step['id'] == 'C_PAGE')
        encoded = canonical(result) + b'\n'
        expected = base64.b64decode(step['expected_inner_response_base64'], validate=True)
        require(encoded == expected and step['expected_inner_response'] ==
                {'bytes': len(expected), 'sha256': sha(expected)}, 'exact independent inner oracle bytes differ')
        outputs.append(encoded)
        if step['id'] == 'C_CATALOG':
            catalog = result
        elif step['id'] == 'C_SEARCH':
            search = result
        elif step['id'] == 'C_QUERY':
            selected = next(unit['source'] for unit in result['result']['units']
                            if unit['id'] in result['result']['root_units'])
    return outputs


def journal_negatives(root, states):
    stale = states['stale']
    initial = stale['head']
    admitted(root, 'stale-setup', stale, {'action': 'catalog'})
    argv, _ = argv_for(root, 'stale-head', stale, canonical({'action': 'catalog'}))
    argv[argv.index('--expect-session-head-sha256') + 1] = initial
    uncounted(root, 'stale-head', stale, argv)
    for name in ('tail', 'recreated', 'partial', 'locked'):
        state = states[name]
        admitted(root, name + '-setup', state, {'action': 'catalog'})
        if name == 'tail':
            admitted(root, name + '-second', state, {'action': 'catalog'})
            for kind in ('request', 'response', 'call'):
                (state['session'] / (kind + '-02.json')).unlink()
        elif name == 'recreated':
            original = state['session'].with_name(name + '-retained-original')
            state['session'].rename(original)
            state['session'].mkdir(mode=0o700)
            for filename in ('identity.json', 'lock'):
                save(state['session'] / filename, (original / filename).read_bytes())
        elif name == 'partial':
            save(state['session'] / 'request-02.json', b'{}')
        if name == 'locked':
            with (state['session'] / 'lock').open('r+b') as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                uncounted(root, name + '-refused', state)
        else:
            uncounted(root, name + '-refused', state)


def admission_negatives(root, states):
    admitted(root, 'session-owner-catalog', states['session-owner'], {'action': 'catalog'})
    for name in ('annotation-pin', 'client-pin', 'core-pin', 'adapter-pin', 'session-swap', 'protected-session'):
        uncounted(root, name, states[name])
    state = states['oversize-file']
    path = root / 'inputs' / 'oversize-request.json'
    save(path, b'x' * 65537)
    argv, _ = argv_for(root, 'oversize-file', state, b'{}')
    offset = argv.index('--request-json')
    argv[offset:] = ['--request-file', str(path), '--expect-request-sha256', pin(path)['sha256']]
    uncounted(root, 'oversize-file', state, argv)
    state = states['bad-requests']
    admitted(root, 'bad-request-catalog', state, {'action': 'catalog'})
    for label, raw in (('bad-json', b'{'), ('unknown-action', b'{"action":"finish"}'),
                       ('unknown-fields', b'{"action":"catalog","extra":true}')):
        result = admitted(root, label, state, raw)
        require(result['status'] == 'REFUSED', 'admitted invalid request not counted/refused')
    state = states['oversize-argv']
    admitted(root, 'oversize-argv-catalog', state, {'action': 'catalog'})
    result = admitted(root, 'oversize-argv', state, b'x' * 70000,
                      complete=False, input_bytes=70000)
    require(result['status'] == 'REFUSED' and result['result'] == {'reason': 'REFUSED_BOUND'},
            'overbound argv did not preserve bounded inner refusal')


def exhaust(root, state):
    admitted(root, 'exhaust-catalog', state, {'action': 'catalog'})
    for number in range(2, 33):
        result = admitted(root, 'exhaust-%02d' % number, state, {'action': 'not_an_action'})
        require(result['status'] == 'REFUSED' and result['result'] == {'reason': 'REFUSED_SCHEMA'},
                'exhaustion setup unexpectedly accepted invalid request')
    uncounted(root, 'exhaust-33-refused', state)


def wide_fixture(root):
    directory = root / 'wide'
    directory.mkdir(mode=0o700)
    content = directory / 'content'
    content.mkdir(mode=0o700)
    raw = b'Z' * 40000
    save(content / 'source.bin', raw)
    original = json.loads((FIXTURES / 'SC_MAIN' / 'original-manifest.json').read_bytes())
    original.update(content={'root': str(content), 'files': [dict(pin(content / 'source.bin'), path='source.bin')]},
                    sources=[{'id': 'S_WIDE', 'label': 'S_WIDE', 'media_type': 'text/plain',
                              'provenance': 'Independent public output-bound fixture', 'bytes': len(raw),
                              'path': 'source.bin'}], held_source_sha256={'S_WIDE': sha(raw)})
    save(directory / 'handoff.json', original)
    source = {'id': 'S_WIDE', 'revision': 'w1', 'encoding': 'utf-8', 'media_type': 'text/plain',
              'bytes': len(raw), 'sha256': sha(raw), 'attributes': {}}
    units = [{'id': name, 'source': 'S_WIDE', 'span': [0, len(raw)], 'sha256': sha(raw),
              'whole_unit': True, 'dependencies': [], 'annotations': {}} for name in ('U_WIDE_A', 'U_WIDE_B')]
    save(directory / 'annotations.json', {'schema': 'transport/retrieval-annotations/1',
                                         'sources': [source], 'units': units})
    return {'handoff_manifest': pin(directory / 'handoff.json'), 'annotations': pin(directory / 'annotations.json')}


def prepare_states(root):
    states = {}
    for scenario in ('SC_MAIN', 'SC_NEG'):
        for arm in ('original', 'transport'):
            name = scenario + '-' + arm
            states[name] = make_binding(root, name, scenario, arm)
    for name in ('stale', 'tail', 'recreated', 'partial', 'locked', 'bad-requests', 'oversize-file', 'oversize-argv',
                 'exhaust', 'session-owner', 'request-tamper', 'response-tamper', 'identity-tamper', 'bootstrap-only'):
        states[name] = make_binding(root, name, 'SC_MAIN', 'original')
    for name, field in (('annotation-pin', 'annotations'), ('client-pin', 'client'), ('core-pin', 'core'),
                        ('adapter-pin', 'adapter')):
        value = dict(states['stale']['binding'][field], sha256='0' * 64)
        states[name] = make_binding(root, name, 'SC_MAIN', 'original', {field: value})
    states['session-swap'] = make_binding(root, 'session-swap', 'SC_MAIN', 'original',
                                         {'session': str(states['session-owner']['session'])})
    states['wide'] = make_binding(root, 'wide', 'SC_MAIN', 'original', wide_fixture(root))
    changes = {key: states['wide']['binding'][key] for key in ('handoff_manifest', 'annotations')}
    changes['session'] = str(root / 'wide' / 'forbidden-session')
    states['protected-session'] = make_binding(root, 'protected-session', 'SC_MAIN', 'original', changes)
    return states


def extra_integrity_negatives(root, states):
    for name, filename in (('request-tamper', 'request-01.json'), ('response-tamper', 'response-01.json'),
                           ('identity-tamper', 'identity.json')):
        state = states[name]
        admitted(root, name + '-setup', state, {'action': 'catalog'})
        path = state['session'] / filename
        retained = root / (name + '-original.raw')
        save(retained, path.read_bytes())
        path.write_bytes(path.read_bytes() + b' ')
        uncounted(root, name + '-refused', state)
    state = states['stale']
    argv, _ = argv_for(root, 'missing-head', state, canonical({'action': 'catalog'}))
    offset = argv.index('--expect-session-head-sha256')
    del argv[offset:offset + 2]
    before = session_snapshot(state['session'])
    result = support_module().run_bounded(argv, root, {'PATH': '/usr/bin:/bin'}, timeout=30, cap=131072)
    save(root / 'missing-head.stdout', result['stdout'])
    save(root / 'missing-head.stderr', result['stderr'])
    require(result['exit_code'] != 0 and session_snapshot(state['session']) == before,
            'missing mandatory head permitted mutation')


def bootstrap_and_output_path_negatives(root, states):
    state = states['bootstrap-only']
    state['session'].mkdir(mode=0o700)
    save(state['session'] / 'identity.json', identity(state['manifest'], state['expected']))
    save(state['session'] / 'lock', b'')
    argv, _ = argv_for(root, 'bootstrap-first-query', state,
                       canonical({'action': 'page', 'source': 'S_PERSONAL', 'offset': 0}))
    uncounted(root, 'bootstrap-first-query', state, argv)
    state = states['wide']
    argv, _ = argv_for(root, 'protected-receipt', state, canonical({'action': 'catalog'}))
    argv[argv.index('--receipt') + 1] = str(root / 'wide' / 'forbidden-receipt.json')
    uncounted(root, 'protected-receipt', state, argv)
    state = states['stale']
    argv, receipt = argv_for(root, 'existing-receipt', state, canonical({'action': 'catalog'}))
    save(receipt, b'RETAIN_EXISTING_RECEIPT')
    before = session_snapshot(state['session'])
    _, response = execute(root, 'existing-receipt', argv)
    require(response['status'] == 'REFUSED' and response['call'] == 0
            and session_snapshot(state['session']) == before
            and receipt.read_bytes() == b'RETAIN_EXISTING_RECEIPT', 'existing receipt was overwritten or journal appended')
    argv, _ = argv_for(root, 'manifest-pin', state, canonical({'action': 'catalog'}))
    argv[argv.index('--expect-manifest-sha256') + 1] = '0' * 64
    uncounted(root, 'manifest-pin', state, argv)
    path = root / 'requests' / 'wrong-pin.json'
    save(path, canonical({'action': 'catalog'}))
    argv, _ = argv_for(root, 'request-file-pin', state, b'{}')
    argv[argv.index('--request-json'):] = ['--request-file', str(path), '--expect-request-sha256', '0' * 64]
    uncounted(root, 'request-file-pin', state, argv)


def freeze(root, states, expected_entry_sha):
    require(pin(HERE / 'entry.py')['sha256'] == expected_entry_sha, 'externally held client code differs')
    require(pin(HERE / 'contract.json')['sha256'] == CLIENT_CONTRACT_SHA, 'original frozen contract differs')
    require(pin(HERE / 'oracle.json')['sha256'] == CLIENT_ORACLE_SHA, 'original frozen client oracle differs')
    literal = json.loads((HERE / 'oracle.json').read_bytes())
    require(base64.b64decode(literal['fixture']['annotations_base64'], validate=True) ==
            (FIXTURES / 'SC_MAIN' / 'annotations.json').read_bytes(), 'client literal annotation freeze differs')
    record = {'schema': 'transport/independent-client-test-freeze/1', 'status': 'FROZEN_BEFORE_CLIENT_TESTS',
              'contract': pin(HERE / 'contract.json'), 'literal_oracle': pin(HERE / 'oracle.json'),
              'original_oracle': pin(RETRIEVAL / 'oracle.json'), 'test_harness': pin(Path(__file__).absolute()),
              'client': pin(HERE / 'entry.py'), 'core': pin(RETRIEVAL / 'retrieval.py'),
              'adapter': pin(RETRIEVAL / 'adapter.py'), 'source_preparation': pin(FIXTURES / 'T-preparation.json'),
              'fixed_long_argv_test_launcher': pin(root / 'long_argv.py'),
              'receiving_manifests': [pin(state['manifest']) for state in states.values()],
              'scenarios': ['SC_MAIN literal10steps bothactualarms', 'SC_NEG adaptive6steps bothactualarms'],
              'negative_cases': ['stale', 'tail', 'recreated', 'partial', 'locked', 'bad-requests', 'oversize-file',
                                 'annotation-pin', 'client-pin', 'core-pin', 'session-swap', 'exhaust',
                                 'adapter-pin', 'request-tamper', 'response-tamper', 'identity-tamper', 'missing-head',
                                 'bootstrap-only-first-query', 'protected-session', 'protected-receipt', 'existing-receipt',
                                 'manifest-pin', 'request-file-pin', 'wide-output'],
              'wide_inputs': [pin(path) for path in sorted((root / 'wide').rglob('*')) if path.is_file()],
              'postcommit_fault_injection': 'UNRUN; no hidden failure injection or fabricated crash evidence'}
    save(root / 'T-tests.json', record)
    return literal


def run(root, expected_entry_sha):
    require(root.parent == BASE and not root.exists(), 'new bounded scratch root required')
    root.mkdir(mode=0o700)
    for name in ('tmp', 'inputs', 'sessions', 'receipts', 'requests'):
        (root / name).mkdir(mode=0o700)
    save(root / 'long_argv.py', LONG_ARGV_LAUNCHER)
    states = prepare_states(root)
    literal = freeze(root, states, expected_entry_sha)
    try:
        outputs = [literal_adaptive(root, states['SC_MAIN-' + arm], 'MAIN-' + arm, literal)
                   for arm in ('original', 'transport')]
        require(outputs[0] == outputs[1], 'actual original/transport adaptive main responses differ')
        negative_outputs = [adaptive(root, states['SC_NEG-' + arm], 'NEG-' + arm)
                            for arm in ('original', 'transport')]
        require(negative_outputs[0] == negative_outputs[1], 'actual original/transport adaptive negative responses differ')
        journal_negatives(root, states)
        admission_negatives(root, states)
        extra_integrity_negatives(root, states)
        bootstrap_and_output_path_negatives(root, states)
        exhaust(root, states['exhaust'])
        admitted(root, 'wide-catalog', states['wide'], {'action': 'catalog'})
        result = admitted(root, 'wide-output', states['wide'], literal['outer_output_cap']['request'], embedded=False)
        require(result['result'] == {'reason': 'REFUSED_OUTPUT_BOUND'}, 'outer output cap named refusal differs')
        for scenario in ('SC_MAIN', 'SC_NEG'):
            input_fixture(scenario)
        save(root / 'receipt.json', {'status': 'TESTED_PUBLIC_ADAPTIVE_CLIENT_DEVELOPMENT',
                                     'exact_literal_main_steps_per_arm': len(literal['adaptive_steps']),
                                     'actual_transport': True, 'arm_inner_responses_equal': True,
                                     'journal_negative_controls': 'TESTED', 'durable_32_call_budget': 'TESTED',
                                     'semantic_adequacy': 'UNPROVEN', 'strongest_baseline': 'UNQUALIFIED',
                                     'human_model_benefit': 'UNRUN', 'postcommit_fault_injection': 'UNRUN',
                                     'authority': 'NONE'})
    except (AssertionError, ValueError, OSError, KeyError, TypeError) as error:
        save(root / 'failure.json', {'status': 'FAILED_RETAINED', 'reason': str(error)[:256]})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-entry-sha256', required=True)
    args = parser.parse_args()
    run(args.root, args.expect_entry_sha256)


if __name__ == '__main__':
    main()
