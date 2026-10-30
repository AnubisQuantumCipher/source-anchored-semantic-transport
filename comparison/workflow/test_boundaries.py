#!/usr/bin/env python3
"""Additive, independently frozen native-workspace boundary controls.

The existing literal harness and every original result remain unchanged. Faults
are controlled trusted test interception around real original-arm preparation;
they convey no authority, semantic judgment, or general crash-recovery proof.
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
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
VROOT = Path('/dev/shm/semantic-transport-native-workflow-20261029')
PRODUCT = HERE / 'native_workspace.py'
PRODUCT_SHA = '4679aae738dd3efb9c4840e677ec6e55e8a423dd7c8522a0addf6612a6bbfbc1'
SCAFFOLD_SHA = '2abaa40398c01c504b6fa8dc87fa4413ba6b527797dd80ff242df679e68cef6a'
MATRIX_SHA = '9fde83da39caaebc8dc94c08b39e5b05744bd7e6334f57fcc5f65bd5392880a4'
MAX_CALLS, MAX_ADDED, MAX_TOTAL = 32, 33554432, 134217728


def need(condition, reason):
    if type(condition) is not bool or not condition:
        raise AssertionError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, cap=4194304):
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'boundary input byte cap')
    return raw


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    need(len(raw) <= 16777216, 'boundary write byte cap')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'boundary short create-only write')


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def scaffold():
    path = HERE / 'test_workflow.py'
    need(digest(read(path)) == SCAFFOLD_SHA, 'independently held original scaffold differs')
    return load_module('frozen_native_literal_harness', path)


def tree_metadata(root):
    pending, result, visited = [root], {}, 0
    for unused in range(4096):
        if not pending:
            return result
        directory = pending.pop()
        info = directory.lstat()
        result[str(directory.relative_to(root))] = metadata(info)
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                need(visited <= 4096, 'boundary inventory file count')
                path = Path(entry.path)
                result[str(path.relative_to(root))] = metadata(path.lstat())
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    raise AssertionError('boundary inventory traversal bound')


def metadata(info):
    return {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
             'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def byte_budget(root, maximum):
    pending, total, visited = [root], 0, 0
    for unused in range(16384):
        if not pending:
            need(total <= maximum, 'boundary aggregate retained-byte cap')
            return total
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                visited += 1
                need(visited <= 16384, 'boundary budget file count')
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                    need(total <= maximum, 'boundary aggregate retained-byte cap')
    raise AssertionError('boundary budget traversal bound')


def input_state(root, label, base, files, annotation, helpers):
    directory = root / 'inputs' / label
    directory.mkdir(mode=0o700)
    files = dict(files, **{'annotations.json': canonical(annotation)})
    manifest = helpers.original_manifest(directory, base['case'], files)
    annotation_path = directory / 'annotations.json'
    save(annotation_path, files['annotations.json'])
    return dict(base, name=label, manifest=manifest, manifest_pin=helpers.pin(manifest),
                annotations=annotation_path, annotations_pin=helpers.pin(annotation_path),
                workspace=root / 'outputs' / label, receipt=root / 'receipts' / (label + '.json'))


def update_sources(annotation, files):
    for item in annotation['sources']:
        raw = files['sources/' + item['id'] + '.bin']
        item.update(bytes=len(raw), sha256=digest(raw))
    for unit in annotation['units']:
        raw = files['sources/' + unit['source'] + '.bin']
        unit['sha256'] = digest(raw[slice(*unit['span'])])


def bounded_input_fixtures(root, base, helpers):
    result = []
    original_annotation = json.loads(base['files']['annotations.json'])
    for label in ('sources17', 'source-aggregate65537', 'units17', 'edges65'):
        annotation, files = copy.deepcopy(original_annotation), dict(base['files'])
        if label == 'sources17':
            for index in range(17 - len(annotation['sources'])):
                item = copy.deepcopy(annotation['sources'][0])
                item.update(id='S_BOUND_' + str(index), revision='boundary-declared')
                annotation['sources'].append(item)
                files['sources/' + item['id'] + '.bin'] = b'X'
        elif label == 'source-aggregate65537':
            first = annotation['sources'][0]['id']
            other = sum(len(files['sources/' + item['id'] + '.bin']) for item in annotation['sources'][1:])
            files['sources/' + first + '.bin'] = b'X' * (65537 - other)
        elif label == 'units17':
            unit = copy.deepcopy(annotation['units'][0])
            unit.update(id='U_BOUND_EXTRA', dependencies=[])
            annotation['units'].append(unit)
        else:
            names = [unit['id'] for unit in annotation['units']]
            for index, unit in enumerate(annotation['units']):
                unit['dependencies'] = names[:] if index < 4 else (names[:1] if index == 4 else [])
        update_sources(annotation, files)
        fixture_invariants(label, annotation, files)
        result.append(input_state(root, label, base, files, annotation, helpers))
    return result


def fixture_invariants(label, annotation, files):
    lengths = [len(files['sources/' + item['id'] + '.bin']) for item in annotation['sources']]
    sources, units = len(annotation['sources']), len(annotation['units'])
    edges = sum(len(unit['dependencies']) for unit in annotation['units'])
    need(max(lengths) <= 65536 and len(canonical(annotation)) <= 65536, 'other input byte caps must remain valid')
    need(len({item['id'] for item in annotation['sources']}) == sources
         and len({unit['id'] for unit in annotation['units']}) == units, 'unique fixture identifiers')
    need(all(len(set(unit['dependencies'])) == len(unit['dependencies']) <= 16
             for unit in annotation['units']), 'per-unit dependency bound/uniqueness')
    expected = {'sources17': (17, 16, 8), 'source-aggregate65537': (12, 16, 8),
                'units17': (12, 17, 8), 'edges65': (12, 16, 65)}[label]
    need((sources, units, edges) == expected, 'independent source/unit/edge fixture counts')
    need(sum(lengths) == 65537 if label == 'source-aggregate65537' else sum(lengths) <= 65536,
         'independent aggregate source-byte condition')


def verify_fixtures(root, base, helpers):
    result = []
    for label in ('external-hardlink', 'workspace-aggregate', 'root-symlink', 'ancestor-symlink',
                  'sources-symlink', 'root-mode', 'sources-mode'):
        path = root / 'negative-trees' / label
        helpers.golden_tree(path, base)
        if label == 'external-hardlink':
            source = path / 'sources' / 'S_CTRL_NEW.bin'
            (root / 'external-hardlink').hardlink_to(source)
            need(source.stat().st_nlink == 2, 'external hardlink fixture must be nlink2')
        elif label == 'workspace-aggregate':
            for name in base['case']['source_ids']:
                helpers.replace_file(path / 'sources' / (name + '.bin'), b'X' * 90000)
            need(sum((path / 'sources' / (name + '.bin')).stat().st_size for name in base['case']['source_ids']) > 1048576,
                 'existing source paths must exceed workspace aggregate independently')
        elif label in ('root-symlink', 'ancestor-symlink'):
            path.rename(path.with_name(label + '-target'))
            if label == 'root-symlink':
                path.symlink_to(path.with_name(label + '-target'), target_is_directory=True)
            else:
                parent = path.with_name(label + '-link')
                parent.symlink_to(path.with_name(label + '-target').parent, target_is_directory=True)
                path = parent / (label + '-target')
        elif label == 'sources-symlink':
            path.chmod(0o700)
            target = root / 'external-sources-target'
            (path / 'sources').chmod(0o700)
            (path / 'sources').rename(target)
            target.chmod(0o500)
            (path / 'sources').symlink_to(target, target_is_directory=True)
            path.chmod(0o500)
        else:
            (path if label == 'root-mode' else path / 'sources').chmod(0o700)
        result.append(dict(base, name=label, workspace=path))
    return result


def unapproved_decoder(root, base, helpers):
    held = base['case']['arms']['transport']['old_handoff_manifest']
    source = Path(held['path'])
    need(helpers.pin(source) == held, 'held existing transport handoff differs')
    manifest = json.loads(read(source))
    directory = root / 'inputs' / 'unapproved-decoder'
    directory.mkdir(mode=0o700)
    target = directory / 'unapproved-empty-bundle'
    target.mkdir(mode=0o700)
    manifest['bundle']['path'] = str(target)
    path = directory / 'handoff.json'
    save(path, manifest)
    return dict(base, name='unapproved-decoder', manifest=path, manifest_pin=helpers.pin(path),
                workspace=root / 'outputs' / 'unapproved-decoder',
                receipt=root / 'receipts' / 'unapproved-decoder.json')


def config_for(root, state, operation, hook, helpers):
    value = dict(operation=operation, hook=hook, product_sha256=PRODUCT_SHA,
                 test_sha256=digest(read(Path(__file__).absolute())),
                 workspace=str(state['workspace']), receipt=str(state['receipt']),
                 manifest=str(state['manifest']), annotations=str(state['annotations']),
                 manifest_sha256=state['manifest_pin']['sha256'],
                 annotations_sha256=state['annotations_pin']['sha256'],
                 workspace_manifest_sha256=digest(state['expected_manifest']))
    path = root / 'configs' / (state['name'] + '.json')
    save(path, value)
    return path


def patch_bootstrap(module, hook, workspace, events):
    original = module.bootstrap
    def wrapped():
        loaded = original()
        if hook == 'rename-then-raise':
            atomic = loaded[2].atomic_publish
            def atomic_fault(stage, destination):
                atomic(stage, destination)
                events.append(dict(fault=hook, stage=str(stage), workspace_exists=destination.exists(), stage_exists=stage.exists()))
                raise OSError('independent boundary rename completed then failed')
            loaded[2].atomic_publish = atomic_fault
        return loaded
    module.bootstrap = wrapped
    if hook == 'final-root-chmod':
        original_mode = module.mode_directory
        def mode_fault(path, mode, support):
            if path == workspace:
                events.append(dict(fault=hook, workspace_exists=path.exists()))
                raise OSError('independent boundary final root chmod fault')
            return original_mode(path, mode, support)
        module.mode_directory = mode_fault
    elif hook == 'final-verify':
        def verify_fault(path, held, loaded):
            need(path == workspace and path.exists(), 'final verification fault must follow real publication')
            events.append(dict(fault=hook, workspace_exists=path.exists()))
            raise OSError('independent boundary final verification fault')
        module.verify_loaded = verify_fault


def no_subprocess(events):
    def forbidden(*args, **kwargs):
        events.append(dict(subprocess_attempt=True))
        raise OSError('boundary forbids invoking unapproved decoder')
    subprocess.Popen = forbidden


def api_child(path):
    value = json.loads(read(path))
    need(digest(read(PRODUCT)) == PRODUCT_SHA == value['product_sha256'], 'held child product differs')
    need(digest(read(Path(__file__).absolute())) == value['test_sha256'], 'held child test differs')
    module = load_module('native_boundary_product', PRODUCT)
    events, workspace = [], Path(value['workspace'])
    patch_bootstrap(module, value['hook'], workspace, events)
    if value['hook'] == 'unapproved-decoder':
        no_subprocess(events)
    try:
        if value['operation'] == 'verify':
            raw = module.verify_workspace(workspace, value['workspace_manifest_sha256'])
        else:
            raw = module.prepare_workspace(Path(value['manifest']), value['manifest_sha256'],
                  Path(value['annotations']), value['annotations_sha256'],
                  scaffold().CORE_SHA, workspace, Path(value['receipt']))
        need(type(raw) is bytes and canonical(json.loads(raw)) == raw, 'API success framing differs')
        result = dict(status='SUCCESS', response_base64=base64.b64encode(raw).decode('ascii'))
    except module.WorkflowError as error:
        need(isinstance(error, ValueError), 'WorkflowError must derive from ValueError')
        result = dict(status='REFUSED', reason=error.reason,
                      workspace_may_exist=error.workspace_may_exist, stage_may_exist=error.stage_may_exist)
    result.update(schema='transport/native-boundary-api-observation/1', events=events)
    raw = canonical(result) + b'\n'
    need(sys.stdout.buffer.write(raw) == len(raw), 'boundary child stdout short write')


def child_argv(config):
    return [sys.executable, '-I', '-S', '-B', '-Werror', str(Path(__file__).absolute()), '--child', str(config)]


def refusal(observed, possible):
    need(observed['schema'] == 'transport/native-boundary-api-observation/1'
         and observed['status'] == 'REFUSED', 'expected API WorkflowError refusal')
    need(type(observed['reason']) is str and 0 < len(observed['reason'].encode()) <= 4096,
         'fixed reason must be a bounded nonempty string')
    need(type(observed['workspace_may_exist']) is bool and type(observed['stage_may_exist']) is bool,
         'API WorkflowError phase flags must be booleans')
    if possible is not None:
        need(observed['workspace_may_exist'] is possible, 'publication phase flag differs')


def execute(root, label, argv, profile, helpers):
    need(profile['executions'] < MAX_CALLS, 'finite boundary call budget')
    byte_budget(root, MAX_ADDED)
    byte_budget(VROOT, MAX_TOTAL)
    result, value = helpers.invoke(root, label, argv, profile)
    byte_budget(root, MAX_ADDED)
    byte_budget(VROOT, MAX_TOTAL)
    return result, value


def exact_payload(workspace, state, helpers):
    expected = {name: helpers.record(raw) for name, raw in state['files'].items()}
    expected['workspace.json'] = helpers.record(state['expected_manifest'])
    need(helpers.tree_files(workspace) == expected, 'published payload must remain complete literal golden bytes')


def check_negative(root, state, config, operation, profile, helpers):
    before_files = helpers.tree_files(state['workspace']) if state['workspace'].exists() else None
    before_metadata = tree_metadata(state['workspace']) if state['workspace'].exists() else None
    result, value = execute(root, state['name'], child_argv(config), profile, helpers)
    need(result['exit_code'] == 0, 'API boundary observation child failed')
    refusal(value, None if operation == 'verify' else False)
    if operation == 'verify':
        need(helpers.tree_files(state['workspace']) == before_files
             and tree_metadata(state['workspace']) == before_metadata, 'verification mutated invalid tree')
    else:
        need(not state['workspace'].exists() and not state['receipt'].exists(), 'prepublication refusal created output')
        need(value['stage_may_exist'] is False, 'prepublication refusal has no stage creation')
    if state['name'] == 'unapproved-decoder':
        need(value['events'] == [], 'unapproved decoder reached subprocess invocation')
    return value


def static_check():
    tree = ast.parse(read(Path(__file__).absolute()))
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    need(all(node.end_lineno - node.lineno + 1 <= 60 for node in functions), 'boundary function length')
    need(not any(isinstance(node, ast.While) for node in ast.walk(tree)), 'boundary loop syntax')
    return dict(functions=len(functions), maximum_ast_lines=max(node.end_lineno - node.lineno + 1 for node in functions))


def setup(root):
    need(root.is_absolute() and root.parent == VROOT and not root.exists(), 'new private V child required')
    root.mkdir(mode=0o700)
    for name in ('inputs', 'outputs', 'receipts', 'captures', 'configs', 'tmp', 'negative-trees'):
        (root / name).mkdir(mode=0o700)


def prepare_profile(root, helpers):
    matrix_raw = read(HERE / 'boundary-controls.json')
    need(digest(matrix_raw) == MATRIX_SHA, 'independently frozen boundary matrix differs')
    matrix = json.loads(matrix_raw)
    save(root / 'boundary-controls.json', matrix_raw)
    profile = dict(matrix['profile'], optimized=False, executions=0, product_sha256=PRODUCT_SHA)
    oracle = helpers.pinned_json(HERE / 'oracle.json', helpers.ORACLE_SHA)
    source_oracle = helpers.pinned_json(ROOT / 'comparison/retrieval/oracle.json', helpers.SOURCE_ORACLE_SHA)
    base = helpers.make_state(root, oracle['cases'][0], 'original', 'portable', source_oracle)
    return matrix, profile, base


def build_schedule(root, base, helpers):
    schedule = []
    good = dict(base, name='valid-golden', workspace=root / 'negative-trees' / 'valid-golden')
    helpers.golden_tree(good['workspace'], good)
    for state, operation, hook in [(good, 'verify', 'NONE'), (dict(base, name='valid-prepare'), 'prepare', 'NONE')]:
        schedule.append(dict(state=state, operation=operation, hook=hook,
                             config=config_for(root, state, operation, hook, helpers), positive=True))
    for state in verify_fixtures(root, base, helpers):
        schedule.append(dict(state=state, operation='verify', hook='NONE',
                             config=config_for(root, state, 'verify', 'NONE', helpers), positive=False))
    inputs = bounded_input_fixtures(root, base, helpers) + [unapproved_decoder(root, base, helpers)]
    for state in inputs:
        hook = 'unapproved-decoder' if state['name'] == 'unapproved-decoder' else 'NONE'
        schedule.append(dict(state=state, operation='prepare', hook=hook,
                             config=config_for(root, state, 'prepare', hook, helpers), positive=False))
    for label in ('rename-then-raise', 'final-root-chmod', 'final-verify'):
        state = dict(base, name=label, workspace=root / 'outputs' / label,
                     receipt=root / 'receipts' / (label + '.json'))
        schedule.append(dict(state=state, operation='prepare', hook=label,
                             config=config_for(root, state, 'prepare', label, helpers), positive=False))
    return schedule


def freeze(root, schedule, profile, helpers):
    paths = [Path(__file__).absolute(), HERE / 'boundary-controls.json']
    pins = helpers.source_pins() + [helpers.pin(path) for path in paths]
    need(helpers.pin(PRODUCT)['sha256'] == PRODUCT_SHA, 'held parent product differs')
    for index, item in enumerate(pins):
        save(root / ('frozen-source-' + str(index) + '.bin'), read(Path(item['path']), 16777216))
    calls = [dict(id=item['state']['name'], operation=item['operation'], hook=item['hook'],
                  argv=child_argv(item['config']), config=helpers.pin(item['config']),
                  manifest=item['state']['manifest_pin'], annotations=item['state']['annotations_pin']) for item in schedule]
    calls.extend(dict(id=label, operation='CLI', argv=argv) for label, argv in cli_argv(schedule[1]['state']))
    save(root / 'T-preparation.json', dict(schema='transport/native-boundary-test-freeze/1',
         profile=profile, calls=calls, source_pins=pins, initial_tree=helpers.tree_files(root),
         initial_metadata=tree_metadata(root), static=static_check(), literal_source='unchanged oracle780/235',
         API_errors='WorkflowError primary; CLI framing only for closed flag controls',
         repeated_reason_controls=['external-hardlink', 'units17']))
    need(all(helpers.pin(Path(item['path']), 16777216) == item for item in pins), 'source changed while freezing')
    return pins


def positive(root, item, profile, helpers):
    state = item['state']
    result, value = execute(root, state['name'], child_argv(item['config']), profile, helpers)
    need(result['exit_code'] == 0 and value['status'] == 'SUCCESS' and value['events'] == [], 'positive API control refused')
    raw = base64.b64decode(value['response_base64'], validate=True)
    response = json.loads(raw)
    contract = helpers.pinned_json(HERE / 'contract.json', helpers.CONTRACT_SHA)
    helpers.receipt_check(response, state, contract, item['operation'] == 'verify')
    exact_payload(state['workspace'], state, helpers)
    if item['operation'] == 'prepare':
        need(read(state['receipt']) == raw, 'real prepare external receipt byte identity')


def fault_control(root, item, profile, helpers):
    state = item['state']
    result, value = execute(root, state['name'], child_argv(item['config']), profile, helpers)
    need(result['exit_code'] == 0, 'trusted fault API child failed')
    refusal(value, True)
    need(len(value['events']) == 1 and value['events'][0]['fault'] == item['hook']
         and value['events'][0]['workspace_exists'] is True, 'fault must follow real publication')
    need(state['workspace'].is_dir() and not state['receipt'].exists(), 'published workspace retained and receipt absent')
    exact_payload(state['workspace'], state, helpers)
    if item['hook'] == 'rename-then-raise':
        need(value['events'][0]['stage_exists'] is False, 'atomic rename actually removed stage name')
    else:
        need(value['stage_may_exist'] is False, 'successful rename cleared stage phase')
    stages = [path.name for path in (root / 'outputs').iterdir() if path.name.startswith('.native-source-')]
    need(not stages, 'completed real atomic rename leaves no stage name')
    save(root / (state['name'] + '-retained-state.json'), dict(observation=value, stages=stages,
         output_tree=helpers.tree_files(root / 'outputs'), metadata=tree_metadata(state['workspace'])))
    return value


def cli_argv(base):
    args = [sys.executable, '-I', '-S', '-B', '-Werror', str(PRODUCT)]
    return [('top-help', args + ['--help']), ('prepare-help', args + ['prepare', '--help']),
            ('verify-work-abbreviation', args + ['verify', '--work', str(base['workspace']),
             '--expect-workspace-manifest-sha256', digest(base['expected_manifest'])])]


def cli_controls(root, base, profile, helpers):
    contract = helpers.pinned_json(HERE / 'contract.json', helpers.CONTRACT_SHA)
    observed = []
    for label, argv in cli_argv(base):
        result, value = execute(root, label, argv, profile, helpers)
        helpers.refusal_check(result, value, contract, False)
        observed.append(dict(id=label, observed=value))
    return observed


def run(root):
    setup(root)
    helpers, observations = scaffold(), []
    try:
        matrix, profile, base = prepare_profile(root, helpers)
        schedule = build_schedule(root, base, helpers)
        pins = freeze(root, schedule, profile, helpers)
        for item in schedule:
            need(all(helpers.pin(Path(pin['path']), 16777216) == pin for pin in pins), 'source changed after boundary freeze')
            if item['positive']:
                positive(root, item, profile, helpers)
            elif item['hook'] in ('rename-then-raise', 'final-root-chmod', 'final-verify'):
                value = fault_control(root, item, profile, helpers)
                observations.append(dict(id=item['state']['name'], observed=value))
            else:
                value = check_negative(root, item['state'], item['config'], item['operation'], profile, helpers)
                observations.append(dict(id=item['state']['name'], observed=value))
                if item['state']['name'] in matrix['stability_repeats']:
                    result, repeated = execute(root, item['state']['name'] + '-repeat', child_argv(item['config']), profile, helpers)
                    need(result['exit_code'] == 0 and repeated == value, 'same input refusal reason/flags/events changed')
        observations.extend(cli_controls(root, base, profile, helpers))
        value = dict(status='PASS', profile=profile, observations=observations, source_pins=pins,
                     added_regular_bytes=byte_budget(root, MAX_ADDED), authority='NONE',
                     semantic_adequacy='UNPROVEN', strongest_baseline='UNQUALIFIED', models='UNPERFORMED')
        save(root / 'receipt.json', value)
        return value
    except BaseException as error:
        save(root / 'failure.json', dict(status='FAILED', type=type(error).__name__, reason=str(error), observed_so_far=observations))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--child', type=Path)
    args = parser.parse_args()
    if args.child is not None:
        need(args.root is None, 'closed child request')
        api_child(args.child)
        return
    need(args.root is not None, 'new root required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for kind, bound in ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 120),
                        (resource.RLIMIT_FSIZE, 33554432), (resource.RLIMIT_NOFILE, 128)):
        resource.setrlimit(kind, (bound, bound))
    value = run(args.root)
    sys.stdout.buffer.write(canonical(dict(status=value['status'], root=str(args.root))) + b'\n')


if __name__ == '__main__':
    main()
