#!/usr/bin/env python3
"""Freeze two reader arms, recover all sources and check focused dependencies.

No model is dispatched and no candidate is executed. Run in a new private output
directory. The operator holds the bundle installation digest separately.
"""
import argparse
from pathlib import Path
import resource
import shutil
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'install')]
import build_plan
from test_portable_handoff import bundle_snapshot, check_typed, check_view
from transport_handoff_prepare import prepare
from transport_install_build import command
from transport_install_support import canonical, read_regular, require, sha, write_new
from transport_handoff_inputs import frozen_content, json_value, original_sources, source_metadata

ENV = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')
RESERVE, OUTPUT_BUDGET, RECOVERY_BUDGET = 10000000000, 16777216, 16777216
FROZEN_NAMES = ('fixture.json', 'criteria.json', 'plan.json', 'build_plan.py', 'prepare_case.py')


def pin(path, cap=4194304):
    raw = read_regular(path, cap)
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))


def save(path, value):
    write_new(path, canonical(value), 131072)


def inputs(bundle, held_install):
    fixture, sources = build_plan.fixture_inputs()
    plan = read_regular(HERE / 'plan.json', 65536)
    require(plan == build_plan.build(), 'plan does not reproduce')
    snapshot = bundle_snapshot(bundle)
    require(snapshot['install_manifest']['sha256'] == held_install, 'held installation digest differs')
    source_map = {item['id']: item for item in fixture['sources']}
    require(set(sources) == set(source_map), 'source identities differ')
    frozen = {name: read_regular(HERE / name, 65536) for name in FROZEN_NAMES}
    for name, expected in build_plan.PINS.items():
        require(sha(frozen[name]) == expected, 'validated input changed: ' + name)
    require(frozen['plan.json'] == plan, 'validated plan changed')
    return dict(fixture=fixture, sources=sources, plan=plan, snapshot=snapshot, frozen=frozen)


def freeze_inputs(root, state):
    for name, raw in state['frozen'].items():
        require(read_regular(HERE / name, 65536) == raw, 'freeze input changed: ' + name)
        write_new(root / name, raw, 65536)
    write_new(root / 'task.txt', state['fixture']['task'].encode('utf-8'), 32768)
    directory = root / 'sources'
    directory.mkdir(mode=0o700)
    for name, raw in state['sources'].items():
        write_new(directory / (name + '.txt'), raw, 65536)
    save(root / 'input-freeze.json', dict(schema='transport/heldout-input-freeze/1',
        fixture=pin(root / 'fixture.json'), criteria=pin(root / 'criteria.json'),
        plan=pin(root / 'plan.json'), task=pin(root / 'task.txt'), bundle=state['snapshot'],
        preparation_sources={name: pin(root / name) for name in FROZEN_NAMES},
        sources={name: pin(directory / (name + '.txt')) for name in state['sources']},
        status='FROZEN_BEFORE_MODEL_DISPATCH', model_execution='UNRUN', execution_authority='NONE'))


def encode(root, bundle, state):
    argv = [str(bundle / 'bin/semantic-transport'), 'encode-plan', str(root / 'plan.json'),
            str(root / 'encoded'), '--budget', '8192', '--reference', 'attached:meaning.zip']
    for name in state['sources']:
        argv += ['--source', name + '=' + str(root / 'sources' / (name + '.txt'))]
    command(argv, root, ENV, root / 'commands', 'encode')
    share = root / 'encoded/share.txt'
    archive = root / 'encoded/meaning.zip'
    for action in ('validate', 'inspect'):
        command([str(bundle / 'bin/semantic-transport'), action, str(share), '--archive', str(archive)],
                root, ENV, root / 'commands', action)
    view = json_value(read_regular(root / 'commands/inspect.stdout', 131072), 131072)
    check_view(view, dict(expected=json_value(state['plan']), sources=state['sources']))
    return share, archive, view


def check_recovery(root, bundle, state, share, archive):
    target = root / 'recovered'
    target.mkdir(mode=0o700)
    records = []
    for name, original in state['sources'].items():
        path = target / (name + '.txt')
        command([str(bundle / 'bin/semantic-transport'), 'recover', str(share), str(path),
                 '--archive', str(archive), '--source', name], root, ENV, root / 'commands', 'recover-' + name)
        recovered = read_regular(path, 65536)
        require(recovered == original, 'source byte comparison failed: ' + name)
        records.append(dict(source=name, bytes=len(original), sha256=sha(original), byte_equal=True))
    save(root / 'exact-recovery.json', dict(status='ALL_ORIGINAL_BYTES_EQUAL', sources=records,
        numerical_scope='Exact recovered source bytes only; narrative numbers not assessed.'))


def check_focus(root, bundle, share, archive, state):
    command([str(bundle / 'bin/semantic-transport'), 'focus', str(share), '--archive', str(archive),
             '--unit', 'MU_TESTABLE_RULE'], root, ENV, root / 'commands', 'focus')
    value = json_value(read_regular(root / 'commands/focus.stdout', 131072), 131072)
    plan = json_value(state['plan'])
    expected = {unit['id'] for unit in plan['meaning_units']} - {'MU_UNRELATED_NOTE'}
    require({unit['id'] for unit in value['meaning_units']} == expected, 'focus dependency closure differs')
    require({source['id'] for source in value['sources']} == set(state['sources']) - {'UNRELATED'},
            'focus omitted a necessary source or included unrelated material')
    check_typed(value, dict(meaning_units=[unit for unit in plan['meaning_units'] if unit['id'] in expected]))
    require(value['execution_authority'] == 'NONE' and value['context_adequacy'] == 'UNPROVEN',
            'focus assurance changed')
    require(value['selected_unit'] == 'MU_TESTABLE_RULE'
            and value['dependency_closure'] == 'ALL_DECLARED_LINKS_CHECKED', 'focus selection differs')
    names = build_plan.plans.collect_ids(plan)
    interpretations = build_plan.plans.check_interpretations(plan['interpretations'], state['sources'], False)
    wanted = {item['interpretation'] for item in plan['meaning_units'] if item['id'] in expected}
    require(value['interpretations'] == [item for item in interpretations if item['id'] in wanted],
            'focus interpretation closure differs')
    require(value['uncertainties'] == build_plan.plans.check_uncertainties(
            plan['uncertainties'], state['sources'], names, False), 'focus uncertainty closure differs')
    require(value['relations'] == build_plan.plans.check_relations(
            plan['relations'], state['sources'], names, False), 'focus relation closure differs')
    save(root / 'focus-check.json', dict(status='DECLARED_DEPENDENCY_CLOSURE_CHECKED',
        unit_ids=sorted(expected), unrelated_source_excluded=True, context_adequacy='UNPROVEN',
        response=pin(root / 'commands/focus.stdout', 131072)))


def prepare_arms(root, bundle, state, share, archive, view):
    task, python = pin(root / 'task.txt'), pin(Path(sys.executable).resolve(strict=True))
    receipts = {}
    for arm in ('original', 'transport'):
        sources = []
        for item in state['fixture']['sources']:
            source_pin = pin(root / 'sources' / (item['id'] + '.txt'))
            entry = {key: value for key, value in item.items() if key != 'text'}
            entry.update({key: source_pin[key] for key in ('bytes', 'sha256')})
            if arm == 'original':
                entry['path'] = source_pin['path']
            sources.append(entry)
        config = dict(schema='transport/handoff-preparation/1', arm=arm, task=task, python=python, sources=sources)
        if arm == 'transport':
            config['bundle'] = dict(path=str(bundle), install_sha256=state['snapshot']['install_manifest']['sha256'],
                                    snapshot_sha256=sha(canonical(state['snapshot'])))
            config['pair'] = dict(share=pin(share), archive=pin(archive), identity=view['identity'])
        config_path = root / (arm + '-config.json')
        save(config_path, config)
        receipts[arm] = prepare(config_path, sha(canonical(config)), root / ('receiver-' + arm))
    return receipts


def check_arms(root, state, share, archive):
    manifests = {}
    task = state['fixture']['task'].encode('utf-8')
    for arm in ('original', 'transport'):
        receiver = root / ('receiver-' + arm)
        manifest = json_value(read_regular(receiver / 'manifest.json', 65536))
        require(manifest['arm'] == arm, 'receiving arm differs')
        source_metadata(manifest)
        require(Path(manifest['content']['root']) == receiver / 'content', 'content root differs')
        _, data = frozen_content(manifest)
        require(read_regular(receiver / 'task.txt', 32768) == task, 'receiving live task differs')
        require(read_regular(receiver / 'interface.txt', 65536).count(task) == 1,
                'receiving interface task differs')
        require(manifest['held_source_sha256'] ==
                {name: sha(raw) for name, raw in state['sources'].items()}, 'held arm sources differ')
        if arm == 'original':
            require(original_sources(manifest, data) == state['sources'], 'original arm bytes differ')
        else:
            require(data == {'share.txt': read_regular(share), 'meaning.zip': read_regular(archive)},
                    'transport content differs or exposes additional files')
        manifests[arm] = manifest
    left = [{key: value for key, value in item.items() if key != 'path'}
            for item in manifests['original']['sources']]
    require(left == manifests['transport']['sources'], 'arm source metadata differs')
    save(root / 'arm-equality.json', dict(status='LIVE_TASK_AND_SOURCE_METADATA_EQUAL',
        task_sha256=sha(task), declared_reader_content_only=True,
        criteria_exposed_by_reader=False, operating_system_isolation='NOT_CLAIMED',
        treatment='Transport adds declared reading and focus; original retains exact sources.'))


def verify_freeze(root, state):
    for name, raw in state['frozen'].items():
        require(read_regular(HERE / name, 65536) == raw, 'live input changed: ' + name)
        require(read_regular(root / name, 65536) == raw, 'frozen input changed: ' + name)
    require(read_regular(root / 'task.txt', 32768) == state['fixture']['task'].encode('utf-8'),
            'frozen task changed')
    for name, raw in state['sources'].items():
        require(read_regular(root / 'sources' / (name + '.txt'), 65536) == raw,
                'frozen source changed: ' + name)


def output_bytes(root):
    pending, total, entries = [root], 0, 0
    for _ in range(512):
        if not pending:
            return total
        directory = pending.pop()
        for child in directory.iterdir():
            entries += 1
            require(entries <= 512 and not child.is_symlink(), 'output member bound/type')
            if child.is_dir():
                pending.append(child)
            else:
                require(child.is_file(), 'nonregular output member')
                total += child.stat().st_size
                require(total + 131072 <= OUTPUT_BUDGET, 'preparation aggregate output budget')
    raise ValueError('output traversal bound')


def run(bundle, held_install, root):
    require(bundle.is_absolute() and root.is_absolute(), 'absolute paths required')
    require(len(bundle.parts) <= 65 and len(root.parts) <= 65 and '..' not in bundle.parts
            and '..' not in root.parts and len(str(bundle).encode()) < 4096
            and len(str(root).encode()) < 4096, 'bounded canonical paths required')
    require(bundle.resolve(strict=True) == bundle, 'canonical bundle path required')
    require(not root.exists() and not root.is_symlink(), 'new output directory required')
    require(root.parent.resolve(strict=True) == root.parent, 'canonical existing output parent required')
    require(not root.is_relative_to(bundle) and not bundle.is_relative_to(root), 'output overlaps bundle')
    require(not root.is_relative_to(ROOT) and not ROOT.is_relative_to(root), 'output overlaps source tree')
    free = shutil.disk_usage(root.parent).free
    require(free >= RESERVE + OUTPUT_BUDGET + RECOVERY_BUDGET, 'insufficient campaign and recovery reserve')
    state = inputs(bundle, held_install)
    root.mkdir(mode=0o700)
    (root / 'commands').mkdir(mode=0o700)
    freeze_inputs(root, state)
    share, archive, view = encode(root, bundle, state)
    check_recovery(root, bundle, state, share, archive)
    check_focus(root, bundle, share, archive, state)
    receipts = prepare_arms(root, bundle, state, share, archive, view)
    check_arms(root, state, share, archive)
    verify_freeze(root, state)
    require(bundle_snapshot(bundle) == state['snapshot'], 'sender bundle changed')
    used = output_bytes(root)
    result = dict(schema='transport/heldout-preparation/1', status='PREPARED_NOT_DISPATCHED',
        receivers=receipts, identity=view['identity'], free_bytes_before=free,
        reserve_bytes=RESERVE, output_budget_bytes=OUTPUT_BUDGET, recovery_budget_bytes=RECOVERY_BUDGET,
        observed_bytes_before_final_receipt=used,
        source_bytes=sum(len(raw) for raw in state['sources'].values()),
        share_codepoints=len(read_regular(share).decode('utf-8')), archive=pin(archive),
        model_execution='UNRUN', semantic_completeness='UNPROVEN')
    save(root / 'preparation.json', result)
    return dict(status=result['status'], identity=view['identity'], output=str(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--expect-install-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (536870912, 1073741824))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 180))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4194304, 33554432))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
    try:
        print(canonical(run(args.bundle, args.expect_install_sha256, args.output)).decode('utf-8'))
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, MemoryError) as error:
        print(canonical(dict(status='REFUSED_PARTIAL_OUTPUT_RETAINED', reason=str(error)[:256])).decode('utf-8'))
        return 1


if __name__ == '__main__':
    sys.exit(main())
