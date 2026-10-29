#!/usr/bin/env python3
"""Derive a fresh runtime using a provenance-bound unchanged native artifact.

This standalone operation does not compile, prove, authenticate authors, or
change the original full-build gate. Pinned source execution, Python/OS/libraries
and the original compiler remain trusted. Space checks are observations, not
reservations. Failed outputs remain evidence and are never accepted as success.
"""

import argparse
import ast
import os
from pathlib import Path
import platform
import resource
import secrets
import shutil
import stat
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
from transport_install_check import complete_stage, verify_install
from transport_install_layout import BOOTSTRAP, DIGEST, PROFILES, checked_json, exact_tree, generated, input_names
from transport_install_support import atomic_publish, canonical, confined, read_regular, require, sha, write_new

RESERVE = 10_000_000_000
OUTPUT_BUDGET = 16_777_216
MAX_RECEIPT = 131072
MAX_NATIVE = 4_194_304
MAX_LOG = 1_048_576
HELPERS = ('transport_repackage.py', 'transport_install_check.py', 'transport_install_build.py',
           'transport_install_layout.py', 'transport_install_support.py')
TRUST = 'TRUST_PINNED_SOURCE_EXECUTION_FOR_RUNTIME_DERIVATION'
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'unexpected or missing fields')


def digest(value):
    require(type(value) is str and DIGEST.fullmatch(value) is not None, 'held SHA-256 required')
    return value


def absolute(value):
    require(type(value) is str and 0 < len(value) < 2048, 'bounded path string required')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value, 'canonical absolute path required')
    return path


def pinned(path, expected, cap=MAX_RECEIPT):
    raw = read_regular(path, cap)
    require(sha(raw) == digest(expected), 'held file identity differs: ' + str(path))
    return raw


def load_config(path, expected):
    raw = pinned(path, expected)
    value = checked_json(raw)
    fields(value, ('schema', 'source_trust', 'old_source', 'new_source', 'donor', 'output'))
    require(value['schema'] == 'transport/repackage-config/1' and value['source_trust'] == TRUST,
            'explicit pinned-source execution trust required')
    for name in ('old_source', 'new_source'):
        fields(value[name], ('root', 'sha256'))
        absolute(value[name]['root'])
        digest(value[name]['sha256'])
    donor = value['donor']
    fields(donor, ('root', 'install_sha256', 'native_sha256', 'build_receipt', 'compile_receipt'))
    absolute(donor['root'])
    digest(donor['install_sha256'])
    digest(donor['native_sha256'])
    for name in ('build_receipt', 'compile_receipt'):
        fields(donor[name], ('path', 'sha256'))
        absolute(donor[name]['path'])
        digest(donor[name]['sha256'])
    fields(value['output'], ('prefix', 'receipt'))
    for item in value['output'].values():
        absolute(item)
    return value


def disjoint(paths):
    require(type(paths) is list and len(paths) <= 16, 'path comparison bound')
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            require(not left.is_relative_to(right) and not right.is_relative_to(left), 'paths overlap')


def new_target(path):
    require(path.is_absolute(), 'absolute output path required')
    confined(path.parent, path.name)
    metadata = path.parent.stat()
    require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) & 0o022 == 0,
            'private user-owned output parent required')
    require(not path.exists() and not path.is_symlink(), 'create-only output target exists')


def paths_for(config, config_path):
    roots = [absolute(config[name]['root']) for name in ('old_source', 'new_source')]
    roots.append(absolute(config['donor']['root']))
    require(roots[0] != roots[1], 'distinct old and new source roots required')
    for root in roots:
        require(root.resolve(strict=True) == root and root.is_dir(), 'input root must be a no-link directory')
    inputs = roots + [config_path]
    inputs += [absolute(config['donor'][name]['path']) for name in ('build_receipt', 'compile_receipt')]
    outputs = [absolute(config['output'][name]) for name in ('prefix', 'receipt')]
    disjoint(outputs)
    for output in outputs:
        new_target(output)
        for source in inputs:
            disjoint([output, source])
    return dict(old=roots[0], new=roots[1], donor=roots[2], prefix=outputs[0], receipt=outputs[1], inputs=inputs)


def compare_inputs(old, new):
    require(type(old) is dict and type(new) is dict and set(old) == set(new) == input_names(),
            'source input closure differs')
    native = sorted(name for name in old if name.startswith('src/') or name == 'transport.gpr')
    require(native and len(native) <= 128, 'native input set bound')
    require(native == sorted(name for name in new if name.startswith('src/') or name == 'transport.gpr'),
            'native input path set changed')
    protected = native + ['install/' + name for name in BOOTSTRAP]
    for name in protected:
        require(type(old[name]) is bytes and old[name] == new[name], 'native input or bootstrap changed: ' + name)
    changed = sorted(name for name in old if old[name] != new[name])
    require(changed == ['tools/transport_plan.py'], 'only the readable plan renderer may differ')
    require(renderer_remainder(old['tools/transport_plan.py']) == renderer_remainder(new['tools/transport_plan.py']),
            'nonrenderer plan behavior changed')
    return dict(changed=changed, native_inputs=[dict(path=name, bytes=len(old[name]), sha256=sha(old[name]))
                for name in native], bootstrap='BYTE_IDENTICAL', renderer_scope='NON_RENDERER_AST_IDENTICAL')


def renderer_remainder(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RECEIPT, 'renderer source byte bound')
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError, Warning) as error:
        raise ValueError('renderer AST parse refused') from error
    require(len(tree.body) <= 128, 'renderer top-level statement bound')
    for count, _ in enumerate(ast.walk(tree)):
        require(count < 32768, 'renderer AST node bound')
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                'lexicon_lines', 'dictionary_registry', 'dictionary_lines', 'symbol_dictionary_lines', 'semantic_lines'):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == 'transport_schema':
            node.names = [name for name in node.names if not (name.name == 'reference' and name.asname is None)]
        selected.append(node)
    return ast.dump(ast.Module(body=selected, type_ignores=tree.type_ignores), include_attributes=False)


def helper_pins(new_files):
    result = []
    for name in HELPERS:
        raw = read_regular(HERE / name, MAX_RECEIPT)
        if name != 'transport_repackage.py':
            require(raw == new_files['install/' + name], 'executing helper differs from pinned bootstrap: ' + name)
        result.append(dict(path=str(HERE / name), bytes=len(raw), sha256=sha(raw)))
    return result


def compile_provenance(config, build, compile_record):
    require(compile_record.get('status') == 'SUCCESS' and type(compile_record.get('exit_code')) is int
            and compile_record['exit_code'] == 0, 'original compilation did not succeed')
    scratch = str(absolute(build['scratch']))
    drivers = build['toolchain']['drivers']
    require(type(drivers) is dict and set(drivers) == {'gcc', 'gnatbind', 'gnatlink', 'gprbuild', 'readelf'},
            'original toolchain driver closure differs')
    for record in drivers.values():
        fields(record, ('path', 'bytes', 'sha256', 'version'))
        absolute(record['path'])
        digest(record['sha256'])
        require(type(record['bytes']) is int and 0 < record['bytes'] <= 33_554_432
                and type(record['version']) is str and 0 < len(record['version']) <= MAX_RECEIPT,
                'original toolchain identity malformed')
    gprbuild, compiler = absolute(drivers['gprbuild']['path']), absolute(drivers['gcc']['path']).parent
    mapped = scratch + '=/source/source-anchored-semantic-transport'
    expected = [str(gprbuild), '-q', '-p', '-R', '-P', 'transport.gpr', '-j1', '-cargs:Ada',
                '-fdebug-prefix-map=' + mapped, '-ffile-prefix-map=' + mapped, '-gno-record-gcc-switches']
    require(compile_record['argv'] == expected, 'original native build command differs')
    environment = dict(PATH=':'.join((str(gprbuild.parent), str(compiler), '/usr/bin', '/bin')),
                       LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1', SOURCE_DATE_EPOCH='0')
    require(compile_record['environment'] == environment, 'original compile environment differs')
    directory = absolute(config['donor']['compile_receipt']['path']).parent
    logs = []
    for stream in ('stdout', 'stderr'):
        record = compile_record[stream]
        fields(record, ('path', 'bytes', 'sha256'))
        require(record['path'] == 'compile.' + stream and type(record['bytes']) is int
                and 0 <= record['bytes'] <= MAX_LOG, 'original compile stream metadata differs')
        raw = pinned(directory / record['path'], record['sha256'], MAX_LOG)
        require(len(raw) == record['bytes'], 'original compile log length differs')
        logs.append(dict(path=str(directory / record['path']), bytes=len(raw), sha256=sha(raw)))
    return dict(command=expected, environment=environment, logs=logs,
                cwd_inferred_from_builder_and_scratch=scratch,
                cwd_evidence='INFERRED_FROM_PINNED_BUILDER_CALL_GRAPH; NOT_DIRECTLY_RECORDED_IN_COMPILE_JSON',
                compiler_trust='ORIGINAL_HELD_TOOLCHAIN_NOT_REBUILT')


def original_provenance(config):
    donor = config['donor']
    build_path = absolute(donor['build_receipt']['path'])
    compile_path = absolute(donor['compile_receipt']['path'])
    require(build_path.name == 'receipt.json' and compile_path.name == 'compile.json'
            and build_path.parent == compile_path.parent, 'original named sibling build/compile receipts required')
    held = {}
    for name in ('build_receipt', 'compile_receipt'):
        held[name] = checked_json(pinned(absolute(donor[name]['path']), donor[name]['sha256']))
    build = held['build_receipt']
    require(build.get('schema') == 'transport/build-receipt/1' and build.get('action') == 'build'
            and build.get('status') == 'INSTALLED_BUILD_SPECIFIC_BUNDLE', 'original successful build receipt required')
    require(build['prefix'] == donor['root'] and build['source_manifest_sha256'] == config['old_source']['sha256']
            and build['install_manifest_sha256'] == donor['install_sha256'], 'original build source/install binding differs')
    verification = build['verification']
    require(verification['status'] == 'INSTALLATION_RECONSTRUCTION_CHECKED'
            and verification['source_manifest_sha256'] == config['old_source']['sha256']
            and verification['manifest_sha256'] == donor['install_sha256']
            and verification['native_sha256'] == donor['native_sha256'], 'original verification binding differs')
    architecture = platform.machine()
    require(architecture in PROFILES and build['environment']['architecture'] == architecture,
            'original architecture differs from this supported host')
    elf = build['elf']
    profile = PROFILES[architecture]
    require(elf['native_sha256'] == donor['native_sha256'] and elf['interpreter'] == profile['interpreter']
            and elf['search_paths'] == 'ABSENT', 'original native ELF provenance differs')
    allowed = {Path(name).name for name in profile['libraries']}
    require(type(elf['needed']) is list and len(elf['needed']) == len(set(elf['needed']))
            and 'libc.so.6' in elf['needed'] and set(elf['needed']) <= allowed, 'original ELF dependencies differ')
    return dict(build_receipt=donor['build_receipt'], compile_receipt=donor['compile_receipt'],
                elf=elf, original_verification=verification,
                compilation=compile_provenance(config, build, held['compile_receipt']))


def bundle_snapshot(root, expected_install, expected_native):
    raw = pinned(confined(root, 'INSTALL.json'), expected_install)
    install = checked_json(raw)
    require(type(install['files']) is list and 1 <= len(install['files']) <= 128, 'donor file count bound')
    names = [record['path'] for record in install['files']] + ['INSTALL.json', 'bin/semantic-transport']
    require(len(set(names)) == len(names), 'duplicate donor member')
    exact_tree(root, set(names))
    files, total = {}, 0
    for name in names:
        path = confined(root, name)
        content = read_regular(path)
        total += len(content)
        require(total <= 8_388_608, 'donor byte budget')
        files[name] = dict(bytes=len(content), sha256=sha(content), mode=stat.S_IMODE(path.stat().st_mode))
    native = pinned(confined(root, 'bin/transport_native'), expected_native, MAX_NATIVE)
    profile = PROFILES[platform.machine()]
    require(len(native) >= 64 and native[:6] == b'\x7fELF\x02\x01'
            and struct.unpack_from('<H', native, 18)[0] == profile['machine'], 'donor ELF machine differs')
    return dict(install_sha256=sha(raw), runtime_sha256=files['RUNTIME.json']['sha256'], files=files), native


def storage_guard(parents, initial_bytes):
    require(type(parents) is list and 1 <= len(parents) <= 2, 'storage filesystem count bound')
    require(type(initial_bytes) is int and 0 <= initial_bytes <= OUTPUT_BUDGET, 'stage input budget')
    # Four runtime commands: each has bounded stdout, stderr and a bounded command record.
    # Include RUNTIME, INSTALL, launcher, input freeze, final receipt and allocation slack.
    bound = initial_bytes + 9 * MAX_LOG + 9 * MAX_RECEIPT
    require(bound <= OUTPUT_BUDGET, 'conservative output bound exceeds reuse allowance')
    observations = []
    for parent in parents:
        block = os.statvfs(parent).f_frsize
        require(type(block) is int and 0 < block <= 65536, 'filesystem allocation unit bound')
        require(bound + 256 * block <= OUTPUT_BUDGET, 'allocation allowance exceeds output budget')
        free = shutil.disk_usage(parent).free
        require(free >= RESERVE + 2 * OUTPUT_BUDGET, 'reuse output/full-comparison allowance and reserve required')
        observations.append(dict(parent=str(parent), free_bytes=free, reserve_bytes=RESERVE,
                                 output_budget_bytes=OUTPUT_BUDGET, full_comparison_budget_bytes=OUTPUT_BUDGET,
                                 conservative_logical_bound=bound, allocation_unit=block))
    return observations


def output_usage(roots):
    require(type(roots) is list and 1 <= len(roots) <= 2, 'output root count bound')
    pending, count, logical = list(roots), 0, 0
    allocated = sum(root.stat().st_blocks * 512 for root in roots)
    require(allocated <= OUTPUT_BUDGET, 'physical output allowance exceeded')
    for _ in range(256):
        if not pending:
            return dict(entries=count, logical_bytes=logical, allocated_bytes=allocated)
        directory = pending.pop()
        for path in directory.iterdir():
            count += 1
            require(count <= 256 and not path.is_symlink(), 'output entry bound or link')
            metadata = path.stat()
            allocated += metadata.st_blocks * 512
            require(allocated <= OUTPUT_BUDGET, 'physical output allowance exceeded')
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            else:
                require(stat.S_ISREG(metadata.st_mode), 'special output refused')
                logical += metadata.st_size
                require(logical <= OUTPUT_BUDGET, 'logical output allowance exceeded')
    raise ValueError('output traversal bound exceeded')


def unchanged(state):
    from transport_install_layout import source_inputs
    config, paths = state['config'], state['paths']
    for key in ('old', 'new'):
        _, files = source_inputs(paths[key], config[key + '_source']['sha256'])
        require(files == state[key], 'source changed during derivation')
    snapshot, native = bundle_snapshot(paths['donor'], config['donor']['install_sha256'], config['donor']['native_sha256'])
    require(snapshot == state['donor_snapshot'] and native == state['native'], 'donor changed during derivation')
    require(helper_pins(state['new']) == state['helpers'], 'executing helper closure changed')
    require(original_provenance(config) == state['provenance'], 'original provenance changed')
    pinned(state['config_path'], state['config_sha256'])


def prepare(config_path, expected_config):
    from transport_install_layout import source_inputs
    require(platform.system() == 'Linux' and platform.machine() in PROFILES
            and sys.version_info[:2] == (3, 14), 'supported Linux/Python runtime required')
    config_path = absolute(str(config_path))
    config = load_config(config_path, expected_config)
    paths = paths_for(config, config_path)
    _, old = source_inputs(paths['old'], config['old_source']['sha256'])
    _, new = source_inputs(paths['new'], config['new_source']['sha256'])
    comparison = compare_inputs(old, new)
    provenance = original_provenance(config)
    snapshot, native = bundle_snapshot(paths['donor'], config['donor']['install_sha256'], config['donor']['native_sha256'])
    helpers = helper_pins(new)
    initial_bytes = sum(len(raw) for raw in generated(new, native, platform.machine()).values())
    storage = storage_guard([paths['prefix'].parent, paths['receipt'].parent], initial_bytes)
    return dict(config=config, config_path=config_path, config_sha256=expected_config, paths=paths,
                old=old, new=new, comparison=comparison, provenance=provenance, donor_snapshot=snapshot,
                native=native, helpers=helpers, storage=storage)


def create_stage(paths):
    for _ in range(32):
        stage = paths['prefix'].parent / ('.transport-repackage-' + secrets.token_hex(16))
        for source in paths['inputs'] + [paths['prefix'], paths['receipt']]:
            disjoint([stage, source])
        try:
            stage.mkdir(mode=0o700)
        except FileExistsError:
            continue
        require(stat.S_IMODE(stage.stat().st_mode) == 0o700, 'private stage required')
        return stage
    raise ValueError('private staging name attempts exhausted')


def derive_stage(state, result):
    paths, config = state['paths'], state['config']
    directories = {name: paths['receipt'] / name for name in ('donor-check', 'derive', 'published-check')}
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    result['donor_verification'] = verify_install(paths['donor'], state['old'], config['old_source']['sha256'],
                                                config['donor']['install_sha256'], ENV, directories['donor-check'])
    unchanged(state)
    stage = create_stage(paths)
    result['stage'] = str(stage)
    identity = complete_stage(stage, state['new'], state['native'], config['new_source']['sha256'], ENV, directories['derive'])
    require(read_regular(confined(stage, 'bin/transport_native')) == state['native'], 'reused native bytes changed')
    result['stage_verification'] = verify_install(stage, state['new'], config['new_source']['sha256'], identity,
                                                ENV, directories['derive'])
    runtime = sha(read_regular(confined(stage, 'RUNTIME.json')))
    require(identity != config['donor']['install_sha256'] and runtime != state['donor_snapshot']['runtime_sha256'],
            'changed renderer must derive new install and runtime identities')
    result['storage_after_stage'] = output_usage([stage, paths['receipt']])
    unchanged(state)
    atomic_publish(stage, paths['prefix'])
    result['published'] = True
    result['published_verification'] = verify_install(paths['prefix'], state['new'], config['new_source']['sha256'],
                                                    identity, ENV, directories['published-check'])
    unchanged(state)
    result.update(new_install_sha256=identity, new_runtime_sha256=runtime,
                  storage_after_publication=output_usage([paths['prefix'], paths['receipt']]))


def repackage(config_path, expected_config):
    state = prepare(config_path, expected_config)
    paths, config = state['paths'], state['config']
    unchanged(state)
    paths['receipt'].mkdir(mode=0o700)
    result = dict(schema='transport/native-reuse-receipt/1', status='FAILED', published=False,
        config_sha256=expected_config, prefix=str(paths['prefix']), source_trust=config['source_trust'],
        donor_source_sha256=config['old_source']['sha256'], new_source_sha256=config['new_source']['sha256'],
        donor_install_sha256=config['donor']['install_sha256'], donor_runtime_sha256=state['donor_snapshot']['runtime_sha256'],
        native_sha256=config['donor']['native_sha256'], native_build='UNPERFORMED', formal_proof='NOT_RUN',
        artifact_reuse='NOT_ESTABLISHED', native_input_comparison=state['comparison'],
        original_provenance=state['provenance'], helper_import_closure=state['helpers'], storage=state['storage'],
        donor_before=state['donor_snapshot'], authentication='NOT_PROVIDED', semantic_completeness='UNPROVEN',
        boundary='Pinned trusted Python source executes for runtime derivation; Python/stdlib/OS, current externals and original compiler remain trusted. No hostile same-user isolation or new source-to-binary proof.',
        failure_policy='Retain partial stage/published output and receipts; absence of successful final receipt forbids acceptance.')
    try:
        derive_stage(state, result)
        result['donor_after'] = state['donor_snapshot']
        result['artifact_reuse'] = 'VERIFIED_UNCHANGED_NATIVE_FROM_HELD_INSTALLATION'
        result['status'] = 'DERIVED_RUNTIME_NATIVE_REUSED'
    except (ValueError, OSError, KeyError, TypeError, MemoryError, RecursionError, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)[:512]
        raise
    finally:
        final_receipt(paths, result)
    return result


def final_receipt(paths, result):
    raw = canonical(result)
    require(len(raw) <= MAX_RECEIPT, 'final reuse receipt byte bound')
    roots = [paths['receipt']]
    if paths['prefix'].exists():
        roots.append(paths['prefix'])
    elif result.get('stage') is not None and Path(result['stage']).is_dir():
        roots.append(Path(result['stage']))
    usage = output_usage(roots)
    block = os.statvfs(paths['receipt']).f_frsize
    require(type(block) is int and 0 < block <= 65536, 'receipt allocation unit bound')
    allocated = ((len(raw) + block - 1) // block) * block
    require(usage['entries'] < 256 and usage['logical_bytes'] + len(raw) <= OUTPUT_BUDGET
            and usage['allocated_bytes'] + allocated <= OUTPUT_BUDGET, 'final receipt exceeds output allowance')
    write_new(paths['receipt'] / 'receipt.json', raw, MAX_RECEIPT)


def main():
    require(1 <= len(sys.argv) <= 8 and all(len(arg) <= 4096 for arg in sys.argv), 'argument bound')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--expect-config-sha256', required=True)
    args = parser.parse_args()
    return repackage(args.config, args.expect_config_sha256)


if __name__ == '__main__':
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_NATIVE, 33554432))
        print(canonical(main()).decode('utf-8'))
    except (ValueError, OSError, KeyError, TypeError, MemoryError, RecursionError, KeyboardInterrupt) as error:
        print(canonical(dict(status='REFUSED', reason=type(error).__name__ + ': ' + str(error)[:512])).decode())
        raise SystemExit(1)
