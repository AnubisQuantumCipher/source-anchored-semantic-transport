#!/usr/bin/env python3
"""Reproducible real-codec development integration, not baseline qualification.

Prepare freezes literal expectations before invoking the existing encoder. Run
freezes final held pins before any adapter calls. All records are create-only;
failures and direct outputs remain. No network, provider, or human execution.
"""

import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = Path('/dev/shm/semantic-transport-retrieval-20261029')
ORACLE_SHA = '23525546f46513b5d1c45acfa2161d6d5266ae2446d88deff66f4aa7d5a690f3'
sys.path.insert(0, str(HERE))
import adapter


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    with path.open('xb') as output:
        require(output.write(raw) == len(raw), 'short write')


def pin(path):
    raw = path.read_bytes()
    require(len(raw) <= 4194304, 'fixture file bound')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def oracle():
    raw = (HERE / 'oracle.json').read_bytes()
    require(sha(raw) == ORACLE_SHA, 'independent oracle pin differs')
    value = json.loads(raw)
    require(canonical(value) == raw, 'noncanonical oracle')
    return value


def source_annotation(source):
    return {'id': source['id'], 'revision': source['version_id'],
            'encoding': source['encoding'], 'media_type': source['mime_type'],
            'bytes': source['byte_length'], 'sha256': source['sha256'],
            'attributes': {key: source[key] for key in
                           ('family_id', 'version_id', 'version_state', 'current_authority')}}


def unit_annotation(unit):
    return {'id': unit['id'], 'source': unit['source_id'],
            'span': [unit['source_byte_start'], unit['source_byte_end']],
            'sha256': unit['quote_sha256'], 'whole_unit': unit['whole_unit'],
            'dependencies': unit['dependencies'], 'annotations': unit['annotations']}


def expected_schedule(value, scenario):
    requests, expected = [{'action': 'catalog'}], [{'action': 'catalog'}]
    for item in value['query_invocations']:
        if item['scenario_id'] != scenario['id']:
            continue
        query = next(q for q in value['queries'] if q['id'] == item['query_id'])
        requests.append({'action': 'query', 'sources': item['effective_search_source_ids'],
                         'mode': query['match_mode'], 'field': 'source', 'query': query['query_utf8']})
        expected.append({'action': 'query', 'id': item['id'], 'outcome': item['expected_outcome'],
                         'closure': item['expected_dependency_closure'],
                         'roots': query['expected_root_units'], 'sources': item['effective_search_source_ids'],
                         'mode': query['match_mode'], 'query': query['query_utf8']})
    requests.append({'action': 'page', 'source': 'S_OPAQUE', 'offset': 0})
    expected.append({'action': 'page', 'source': 'S_OPAQUE'})
    source = 'S_CTRL_NEW' if scenario['id'] == 'SC_MAIN' else 'S_APPROVAL_NEW'
    requests.append({'action': 'trace', 'source': source})
    expected.append({'action': 'trace', 'source': source})
    require(len(requests) <= 32, 'schedule call bound')
    return requests, expected


def scenario_files(root, value, scenario):
    directory = root / scenario['id']
    directory.mkdir(mode=0o700)
    originals = directory / 'original-content'
    originals.mkdir(mode=0o700)
    records = [item for item in value['sources'] if item['id'] in scenario['source_ids']]
    require(1 <= len(records) <= 16, 'source count')
    metadata = []
    for item in records:
        raw = base64.b64decode(item['raw_base64'], validate=True)
        require(sha(raw) == item['sha256'] and len(raw) == item['byte_length'], 'oracle source pin')
        save(originals / (item['id'] + '.bin'), raw)
        metadata.append({'id': item['id'], 'label': item['id'], 'media_type': item['mime_type'],
                         'provenance': 'Public development oracle ' + ORACLE_SHA, 'sha256': item['sha256']})
    annotations = {'schema': 'transport/retrieval-annotations/1',
                   'sources': [source_annotation(item) for item in records],
                   'units': [unit_annotation(unit) for unit in value['units']
                             if unit['id'] in scenario['unit_ids']]}
    save(directory / 'annotations.json', annotations)
    # No invented semantic declarations: actual codec carries exact original bytes.
    authoring = {'schema': 'transport/authoring/1', 'sources': metadata,
                 'interpretations': [], 'uncertainties': [], 'relations': [], 'meaning_units': []}
    save(directory / 'authoring.json', authoring)
    requests, expected = expected_schedule(value, scenario)
    save(directory / 'requests.jsonl', b''.join(canonical(item) + b'\n' for item in requests))
    save(directory / 'expected.json', expected)
    return directory, metadata


def execute(root, label, argv, cap=131072):
    support = sys.modules['transport_install_support']
    env = dict(sys.modules['transport_handoff_inputs'].ENV, TMPDIR=str(root / 'tmp'))
    result = support.run_bounded(argv, root, env, timeout=30, cap=cap)
    for stream in ('stdout', 'stderr'):
        save(root / (label + '.' + stream), result[stream])
    receipt = {key: item for key, item in result.items() if key not in ('stdout', 'stderr')}
    receipt.update({stream: {'bytes': len(result[stream]), 'sha256': sha(result[stream])}
                    for stream in ('stdout', 'stderr')})
    save(root / (label + '.json'), receipt)
    return result


def encode(root, directory, metadata):
    bundle = Path(adapter.APPROVED_BUNDLE['path'])
    output = directory / 'encoded'
    argv = [str(bundle / 'bin/semantic-transport'), 'encode', str(directory / 'authoring.json'),
            str(output), '--budget', '65536']
    for item in metadata:
        argv.extend(['--source', item['id'] + '=' + str(directory / 'original-content' / (item['id'] + '.bin'))])
    result = execute(root, directory.name + '-encode', argv)
    require(result['status'] == 'SUCCESS' and not result['stderr'], 'real encoder failed; retained')
    inspect = execute(root, directory.name + '-inspect', [str(bundle / 'bin/semantic-transport'),
                      'inspect', str(output / 'share.txt'), '--archive', str(output / 'meaning.zip')])
    require(inspect['status'] == 'SUCCESS' and not inspect['stderr'], 'real inspect failed; retained')
    identity = json.loads(inspect['stdout'])['identity']
    content = directory / 'transport-content'
    content.mkdir(mode=0o700)
    for name in ('share.txt', 'meaning.zip'):
        save(content / name, (output / name).read_bytes())
    return identity


def manifest(directory, metadata, arm, identity):
    inputs = sys.modules['transport_handoff_inputs']
    content = directory / (arm + '-content')
    helper_names = inputs.BOOTSTRAP + (('test_portable_handoff.py',) if arm == 'transport' else ())
    sources = []
    for item in metadata:
        source = {key: item[key] for key in ('id', 'label', 'media_type', 'provenance')}
        source['bytes'] = (directory / 'original-content' / (item['id'] + '.bin')).stat().st_size
        if arm == 'original':
            source['path'] = item['id'] + '.bin'
        sources.append(source)
    files = [dict(pin(path), path=path.name) for path in sorted(content.iterdir())]
    value = {'schema': inputs.SCHEMA, 'arm': arm, 'sources': sources,
             'held_source_sha256': {item['id']: item['sha256'] for item in metadata},
             'helpers': [pin(adapter.INSTALL / name) for name in helper_names],
             'python': pin(Path(sys.executable).resolve()),
             'content': {'root': str(content), 'files': files}}
    if arm == 'transport':
        value.update(bundle=adapter.APPROVED_BUNDLE,
                     pair={'share': 'share.txt', 'archive': 'meaning.zip', 'identity': identity})
    save(directory / (arm + '-manifest.json'), value)


def prepare(root):
    require(root.parent == ROOT and not root.exists(), 'new pinned scratch directory required')
    root.mkdir(mode=0o700)
    (root / 'tmp').mkdir(mode=0o700)
    adapter.approved_helpers()
    snapshot = sys.modules['test_portable_handoff'].bundle_snapshot(Path(adapter.APPROVED_BUNDLE['path']))
    require(sha(canonical(snapshot)) == adapter.APPROVED_BUNDLE['snapshot_sha256']
            and snapshot['install_manifest']['sha256'] == adapter.APPROVED_BUNDLE['install_sha256'],
            'approved encoder snapshot differs before execution')
    value = oracle()
    states = [scenario_files(root, value, item) for item in value['scenarios']]
    admission = {'schema': 'transport/retrieval-adapter-preparation-admission/1',
                 'status': 'FROZEN_BEFORE_CODEC_EXECUTION', 'oracle_sha256': ORACLE_SHA,
                 'adapter': pin(HERE / 'adapter.py'), 'harness': pin(Path(__file__).absolute()),
                 'decoder': adapter.APPROVED_BUNDLE, 'scenarios': []}
    for directory, _ in states:
        entry = {name: pin(directory / name) for name in
                 ('annotations.json', 'authoring.json', 'requests.jsonl', 'expected.json')}
        entry['original_sources'] = [pin(path) for path in sorted((directory / 'original-content').iterdir())]
        admission['scenarios'].append(entry)
    save(root / 'T-preparation.json', admission)
    for directory, metadata in states:
        identity = encode(root, directory, metadata)
        for arm in ('original', 'transport'):
            manifest(directory, metadata, arm, identity)
    save(root / 'prepared.json', {'status': 'PREPARED_NOT_TESTED', 'authority': 'NONE',
                                  'semantic_adequacy': 'UNPROVEN'})


def adapter_argv(directory, arm, core_sha, metrics):
    manifest_path, annotations = directory / (arm + '-manifest.json'), directory / 'annotations.json'
    return [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'adapter.py'),
            '--manifest', str(manifest_path), '--expect-manifest-sha256', pin(manifest_path)['sha256'],
            '--annotations', str(annotations), '--expect-annotations-sha256', pin(annotations)['sha256'],
            '--expect-core-sha256', core_sha, '--requests', str(directory / 'requests.jsonl'),
            '--metrics', str(metrics)]


def expected_difference(left, right):
    common = min(len(left), len(right))
    prefix = next((index for index in range(common) if left[index] != right[index]), common)
    remaining = common - prefix
    suffix = next((index for index in range(remaining)
                   if left[len(left) - 1 - index] != right[len(right) - 1 - index]), remaining)
    return [prefix, len(left) - suffix], [prefix, len(right) - suffix]


def dependency_keys(unit, units, sources):
    result = []
    for name in sorted(unit['dependencies']):
        if name not in units:
            result.append({'unit': name, 'missing': True})
        else:
            source = sources[units[name]['source']]
            result.append({'unit': name, 'source': source['id'], 'revision': source['revision'],
                           'sha256': source['sha256']})
    return result


def expected_trace(selected, annotations, originals):
    sources = {item['id']: item for item in annotations['sources']}
    units = {item['id']: item for item in annotations['units']}
    family = sources[selected]['attributes']['family_id']
    versions = sorted((item for item in sources.values() if item['attributes']['family_id'] == family),
                      key=lambda item: item['id'])
    comparisons, bindings = [], []
    for other in versions:
        if other['id'] == selected:
            continue
        left, right = originals[selected], originals[other['id']]
        before, after = expected_difference(left, right)
        comparisons.append({'from': selected, 'to': other['id'], 'bytes_equal': left == right,
                            'from_span': before, 'to_span': after,
                            'scope': 'ONE_CONSERVATIVE_REPLACEMENT_ENCLOSURE'})
        for unit in annotations['units']:
            if unit['source'] != selected:
                continue
            for candidate in annotations['units']:
                if candidate['source'] == other['id'] and unit['sha256'] == candidate['sha256']:
                    bindings.append({'left': unit['id'], 'right': candidate['id'], 'quote_unchanged': True,
                                     'dependency_ids_changed': unit['dependencies'] != candidate['dependencies'],
                                     'dependency_source_keys_changed': dependency_keys(unit, units, sources) !=
                                     dependency_keys(candidate, units, sources)})
    return {'source': selected, 'family': family, 'versions': versions, 'comparisons': comparisons,
            'unit_bindings': sorted(bindings, key=lambda item: (item['left'], item['right'])),
            'version_labels': 'DECLARED_NOT_AUTHENTICATED', 'governing_version': 'UNKNOWN'}


def validate_nonquery(body, item, annotations, originals):
    sources = sorted(annotations['sources'], key=lambda source: source['id'])
    units = sorted(annotations['units'], key=lambda unit: unit['id'])
    if item['action'] == 'catalog':
        names = {unit['id'] for unit in units}
        unresolved = sorted({name for unit in units for name in unit['dependencies'] if name not in names})
        require(body == {'sources': sources, 'units': units, 'unresolved_dependency_ids': unresolved,
                         'interpretation_validation': 'NOT_PERFORMED', 'source_coverage': 'ALL_HELD_ORIGINAL_BYTES'},
                'catalog original metadata differs')
    elif item['action'] == 'trace':
        require(body == expected_trace(item['source'], annotations, originals), 'trace direct-source oracle differs')
    else:
        name, raw = item['source'], originals[item['source']]
        chunk = raw[:4096]
        source = next(source for source in sources if source['id'] == name)
        require(body == {'source': name, 'source_bytes': len(raw), 'source_sha256': sha(raw),
                         'span': [0, len(chunk)], 'bytes': len(chunk), 'sha256': sha(chunk),
                         'bytes_base64': base64.b64encode(chunk).decode('ascii'), 'utf8': None,
                         'end': len(chunk) == len(raw), 'units': [unit for unit in units if unit['source'] == name],
                         'annotation_scope': 'ALL_UNITS_BELONGING_TO_SOURCE', 'coverage': 'RETURNED_BYTE_SPAN_ONLY'},
                'opaque page exact raw bytes or metadata differ')
        require(source['encoding'] == 'opaque', 'opaque test selected text source')


def validate_query(body, expected, annotations, originals):
    require(body['outcome'] == expected['outcome'], 'literal oracle outcome')
    require(body['root_units'] == sorted(expected['roots']) and body['unit_ids'] == sorted(expected['closure']),
            'literal oracle roots/complete closure')
    units = {unit['id']: unit for unit in annotations['units']}
    payloads = []
    for name in sorted(expected['closure']):
        unit = units[name]
        begin, end = unit['span']
        quote = originals[unit['source']][begin:end]
        require(sha(quote) == unit['sha256'], 'original oracle anchor identity')
        payloads.append(dict(unit, bytes_base64=base64.b64encode(quote).decode('ascii')))
    require(body['units'] == payloads, 'complete original unit bytes or annotation metadata differ')
    source_metadata = {item['id']: item for item in annotations['sources']}
    require(all(item == source_metadata[item['id']] for item in body['sources']), 'returned source metadata differs')
    whole_matches, opaque = [], []
    for name in sorted(expected['sources']):
        if source_metadata[name]['encoding'] == 'opaque':
            opaque.append(name)
            continue
        query = expected['query'].encode('utf-8')
        tokens = [token for token in query.split(b' ') if token]
        matched = query in originals[name] if expected['mode'] == 'exact_phrase' else all(
            token in originals[name] for token in tokens)
        if matched:
            whole_matches.append({'source': name, 'origins': ['source']})
    require(body['whole_source_matches'] == whole_matches and body['opaque_sources'] == opaque,
            'full original source matches or opaque scope differ')
    require(body['source_scope'] == sorted(expected['sources']) and body['unit_adequacy'] == 'DECLARED_NOT_PROVEN'
            and body['dependency_closure'] == 'ALL_REACHABLE_DECLARED_EDGES', 'query scope/adequacy boundary')
    expected_sources = {units[name]['source'] for name in expected['closure']}
    expected_sources.update(item['source'] for item in body['whole_source_matches'])
    require([item['id'] for item in body['sources']] == sorted(expected_sources), 'result source closure differs')
    require(body['context_sources'] == sorted({units[name]['source'] for name in expected['closure']}
                                              - set(expected['sources'])), 'cross-source context differs')


def validate_schedule(directory, raw):
    expected = json.loads((directory / 'expected.json').read_bytes())
    annotations = json.loads((directory / 'annotations.json').read_bytes())
    originals = {path.stem: path.read_bytes() for path in (directory / 'original-content').iterdir()}
    sources = [{'id': item['id'], 'bytes': item['bytes'], 'sha256': item['sha256']}
               for item in sorted(annotations['sources'], key=lambda source: source['id'])]
    snapshot = sha(canonical({'annotation_sha256': pin(directory / 'annotations.json')['sha256'], 'sources': sources}))
    lines = raw.splitlines(keepends=True)
    require(len(lines) == len(expected), 'response schedule count')
    for number, (line, item) in enumerate(zip(lines, expected, strict=True), 1):
        result = json.loads(line)
        require(line == canonical(result) + b'\n', 'canonical response framing')
        require(result['call'] == number and result['authority'] == 'NONE'
                and result['freshness'] == 'UNKNOWN' and result['context_adequacy'] == 'UNPROVEN'
                and result['snapshot'] == snapshot and result['data_is_untrusted'] is True
                and result['schema'] == 'transport/matched-retrieval-response/1',
                'fixed envelope boundary')
        if item['action'] != 'query':
            require(result['status'] == 'OK', 'non-query refused')
            validate_nonquery(result['result'], item, annotations, originals)
            continue
        outcome = item['outcome']
        if outcome.startswith('REFUSE_'):
            require(result['status'] == 'REFUSED' and result['result']['reason'] ==
                    outcome.replace('REFUSE_', 'REFUSED_', 1), 'expected dependency refusal')
        else:
            require(result['status'] == 'OK', 'query unexpectedly refused')
            validate_query(result['result'], item, annotations, originals)


def run_scenario(root, directory, core_sha):
    outputs = []
    for arm in ('original', 'transport'):
        argv = adapter_argv(directory, arm, core_sha, root / (directory.name + '-' + arm + '-costs.json'))
        result = execute(root, directory.name + '-' + arm, argv)
        require(result['status'] == 'SUCCESS' and not result['stderr'], 'adapter invocation failed; retained')
        validate_schedule(directory, result['stdout'])
        outputs.append(result['stdout'])
    require(outputs[0] == outputs[1], 'actual original/transport canonical arm responses differ')
    return {'scenario': directory.name, 'arm_responses_byte_equal': True,
            'responses_sha256': sha(outputs[0]), 'response_bytes': len(outputs[0]),
            'response_calls': len(outputs[0].splitlines()),
            'annotation_sha256': pin(directory / 'annotations.json')['sha256']}


def negative_pin(root, directory, core_sha, label, option):
    argv = adapter_argv(directory, 'original', core_sha, root / (label + '-costs.json'))
    argv[argv.index(option) + 1] = '0' * 64
    result = execute(root, label, argv)
    require(result['exit_code'] != 0 and not result['stderr'], 'bad pin not refused')
    answer = json.loads(result['stdout'])
    require(answer['status'] == 'REFUSED' and answer['schema'] ==
            'transport/matched-retrieval-adapter-refusal/1', 'adapter refusal shape')
    require(not (root / (label + '-costs.json')).exists(), 'failed admission emitted successful cost file')
    return {'case': label, 'status': 'TESTED_REFUSED', 'reason': answer['reason']}


def executable_selection_negatives(root, directory, core_sha):
    marker = root / 'DATA_WAS_EXECUTED'
    malicious = root / 'unapproved.py'
    save(malicious, ('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n').encode())
    cases = []
    for label, arm in (('helper-code-selection', 'original'), ('bundle-code-selection', 'transport')):
        document = json.loads((directory / (arm + '-manifest.json')).read_bytes())
        if arm == 'original':
            document['helpers'][0] = pin(malicious)
        else:
            document['bundle']['path'] = str(root)
        path = root / (label + '-manifest.json')
        save(path, document)
        argv = adapter_argv(directory, arm, core_sha, root / (label + '-costs.json'))
        argv[argv.index('--manifest') + 1] = str(path)
        argv[argv.index('--expect-manifest-sha256') + 1] = pin(path)['sha256']
        result = execute(root, label, argv)
        require(result['exit_code'] != 0 and not result['stderr'], 'data-selected executable not refused')
        answer = json.loads(result['stdout'])
        require(answer['status'] == 'REFUSED' and not marker.exists(), 'unapproved data code executed')
        require(not (root / (label + '-costs.json')).exists(), 'refusal emitted successful cost file')
        cases.append({'case': label, 'status': 'TESTED_REFUSED', 'reason': answer['reason'],
                      'unapproved_code_marker_absent': True})
    return cases


def check_structure():
    tree = ast.parse((HERE / 'adapter.py').read_bytes())
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    require(all(node.end_lineno - node.lineno + 1 <= 60 for node in functions), 'function AST line bound')
    require(not any(isinstance(node, ast.While) for node in ast.walk(tree)), 'unbounded while loop')
    return {'status': 'TESTED_AST_FUNCTION_AND_LOOP_BOUNDS', 'functions': len(functions)}


def verify_preparation(root, prep):
    value = oracle()
    require(len(prep['scenarios']) == len(value['scenarios']), 'original scenario freeze count')
    for frozen, scenario in zip(prep['scenarios'], value['scenarios'], strict=True):
        directory = root / scenario['id']
        for name in ('annotations.json', 'authoring.json', 'requests.jsonl', 'expected.json'):
            require(pin(directory / name) == frozen[name], 'original preparation pin differs: ' + name)
        originals = directory / 'original-content'
        require([pin(path) for path in sorted(originals.iterdir())] == frozen['original_sources'],
                'original source file freeze differs')
        records = [source for source in value['sources'] if source['id'] in scenario['source_ids']]
        require({path.stem for path in originals.iterdir()} == {source['id'] for source in records},
                'original source closure differs')
        for source in records:
            raw = (originals / (source['id'] + '.bin')).read_bytes()
            require(raw == base64.b64decode(source['raw_base64'], validate=True)
                    and sha(raw) == source['sha256'] and len(raw) == source['byte_length'],
                    'original source bytes differ from independently pinned oracle')
        annotations = {'schema': 'transport/retrieval-annotations/1',
                       'sources': [source_annotation(source) for source in records],
                       'units': [unit_annotation(unit) for unit in value['units'] if unit['id'] in scenario['unit_ids']]}
        require((directory / 'annotations.json').read_bytes() == canonical(annotations),
                'annotations differ from independent oracle')


def run(root, core_sha, attempt):
    require(root.parent == ROOT and (root / 'prepared.json').is_file(), 'prepared scratch required')
    output = root / attempt
    output.mkdir(mode=0o700)
    (output / 'tmp').mkdir(mode=0o700)
    adapter.approved_helpers()
    require(pin(adapter.CORE)['sha256'] == core_sha, 'held core differs before test freeze')
    prep = json.loads((root / 'T-preparation.json').read_bytes())
    require(pin(HERE / 'adapter.py') == prep['adapter'] and pin(Path(__file__).absolute()) == prep['harness'],
            'adapter/harness changed since preparation; new preparation required')
    verify_preparation(root, prep)
    scenarios = [root / item['id'] for item in oracle()['scenarios']]
    held = {'schema': 'transport/retrieval-adapter-test-admission/1', 'status': 'FROZEN_BEFORE_TESTS',
            'core': pin(adapter.CORE), 'adapter': pin(HERE / 'adapter.py'),
            'harness': pin(Path(__file__).absolute()), 'preparation': pin(root / 'T-preparation.json'),
            'negative_expected': ['manifest-pin', 'annotation-pin', 'core-pin',
                                  'helper-code-selection', 'bundle-code-selection'], 'inputs': []}
    for directory in scenarios:
        held['inputs'].append({name: pin(directory / name) for name in
                               ('annotations.json', 'requests.jsonl', 'expected.json',
                                'original-manifest.json', 'transport-manifest.json')})
    save(output / 'T-heldpins.json', held)
    try:
        structure = check_structure()
        results = [run_scenario(output, directory, core_sha) for directory in scenarios]
        negatives = [negative_pin(output, scenarios[0], core_sha, label, option) for label, option in
                     (('manifest-pin', '--expect-manifest-sha256'),
                      ('annotation-pin', '--expect-annotations-sha256'), ('core-pin', '--expect-core-sha256'))]
        negatives.extend(executable_selection_negatives(output, scenarios[0], core_sha))
        require(pin(adapter.CORE) == held['core'] and pin(HERE / 'adapter.py') == held['adapter']
                and pin(Path(__file__).absolute()) == held['harness'], 'code changed during integration')
        verify_preparation(root, prep)
        save(output / 'receipt.json', {'status': 'TESTED_DEVELOPMENT_ACTUAL_CODEC_ARM_EQUALITY',
                                      'scenarios': results, 'negative_controls': negatives, 'structure': structure,
                                      'strongest_baseline': 'UNQUALIFIED', 'semantic_adequacy': 'UNPROVEN',
                                      'human_or_model_judgment': 'UNRUN', 'benefit_acceptance': 'UNRUN',
                                      'authority': 'NONE', 'created_ns': time.time_ns()})
    except (AssertionError, ValueError, OSError, KeyError, TypeError) as error:
        save(output / 'failure.json', {'status': 'FAILED_RETAINED', 'reason': str(error)[:256]})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-core-sha256')
    parser.add_argument('--attempt', default='attempt-01')
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.root)
    else:
        require(type(args.expect_core_sha256) is str, 'external core SHA required')
        require(args.attempt.startswith('attempt-') and '/' not in args.attempt, 'attempt name')
        run(args.root, args.expect_core_sha256, args.attempt)


if __name__ == '__main__':
    main()
