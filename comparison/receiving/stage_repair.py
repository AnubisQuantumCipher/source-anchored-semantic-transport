"""Stage one separately admitted public transport repair verification; never dispatch."""
import argparse
import base64
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import private_staging as private
import stage_repair_support as support

INPUTS = {'manifest', 'transport_original_manifest', 'original_manifest', 'task', 'oracle',
          'annotations', 'changes', 'contract', 'contract_addendum', 'repair_contract',
          'expected_checks', 'failure', 'old_interface', 'old_seal', 'private_oracle'}
LAYOUT = ('receivers/transport/input/content', 'preflight/native', 'runs', 'evaluation', 'captures')


def configuration(path, expected):
    raw = support.read(path)
    support.need(support.digest(raw) == expected, 'CONFIG_PIN')
    config = support.load(raw)
    support.need(type(config) is dict and set(config) == {
        'schema', 'inputs', 'dependencies', 'native', 'python', 'retrieval_core',
        'old_root', 'amendment', 'budget_allocation'}, 'CONFIG_FIELDS')
    support.need(config['schema'] == 'transport/receiving-repair-config/2' and
                 type(config['inputs']) is dict and set(config['inputs']) == INPUTS,
                 'CONFIG_VERSION_INPUTS')
    support.need(type(config['dependencies']) is list and
                 1 <= len(config['dependencies']) <= 64, 'DEPENDENCY_BOUND')
    data = {name: support.checked(item) for name, item in config['inputs'].items()}
    for item in config['dependencies']:
        support.checked(item, 4194304)
    for name in ('native', 'python', 'retrieval_core'):
        support.checked(config[name], 4194304)
    support.checked(config['amendment'])
    support.checked(config['budget_allocation'])
    return config, data, raw


def sealed_inputs(config, data):
    seal = support.load(data['old_seal'])
    staged = {row['path']: row for row in seal['staged_inputs']}
    original = {name: row for name, row in seal['files'].items()}
    for name in ('manifest', 'annotations', 'changes', 'task', 'old_interface'):
        item = config['inputs'][name]
        held = staged[item['path']]
        support.need(held['sha256'] == item['sha256'] and held['bytes'] == item['bytes'],
                     'ORIGINAL_STAGED_PIN')
    for name in ('oracle', 'contract', 'contract_addendum'):
        item = config['inputs'][name]
        held = original[item['path']]
        support.need(held == {'bytes': item['bytes'], 'sha256': item['sha256']},
                     'ORIGINAL_PROTOCOL_PIN')
    manifest = support.load(data['manifest'])
    initial = support.load(data['transport_original_manifest'])
    initial['content']['root'] = manifest['content']['root']
    support.need(initial == manifest, 'ORIGINAL_TRANSPORT_MANIFEST_CHANGED')
    source_manifest = support.load(data['original_manifest'])
    support.need(source_manifest['held_source_sha256'] == manifest['held_source_sha256'],
                 'SOURCE_IDENTITY_SET')
    oracle = support.load(data['oracle'])
    source_pins = {}
    for row in oracle['sources']:
        decoded = base64.b64decode(row['raw_base64'], validate=True)
        support.need(support.digest(decoded) == row['sha256'], 'ORACLE_SOURCE_PIN')
        source_pins[row['id']] = row['sha256']
    support.need(source_pins == manifest['held_source_sha256'], 'ORACLE_SOURCE_SET')
    return manifest


def declared_content(manifest):
    content = manifest['content']
    support.need(set(content) == {'root', 'files'} and len(content['files']) == 2,
                 'CONTENT_BOUND')
    files = {}
    for row in content['files']:
        support.need(row['path'] in ('meaning.zip', 'share.txt') and
                     row['path'] not in files, 'CONTENT_NAME')
        item = dict(row, path=str(Path(content['root']) / row['path']))
        files[row['path']] = support.checked(item)
    support.need(set(files) == {'meaning.zip', 'share.txt'}, 'CONTENT_PAIR')
    return files


def declared_dependencies(config, manifest):
    pins = {item['path']: item for item in config['dependencies']}
    support.need(len(pins) == len(config['dependencies']), 'DUPLICATE_DEPENDENCY')
    support.need(config['python'] == manifest['python'], 'MANIFEST_PYTHON_PIN')
    for item in manifest['helpers']:
        support.need(pins.get(item['path']) == item, 'MANIFEST_HELPER_PIN')
    for name in ('native', 'python', 'retrieval_core'):
        item = config[name]
        support.need(pins.get(item['path']) == item, 'DIRECT_DEPENDENCY_PIN')
    install_path = str(Path(manifest['bundle']['path']) / 'INSTALL.json')
    support.need(install_path in pins and pins[install_path]['sha256'] ==
                 manifest['bundle']['install_sha256'], 'BUNDLE_INSTALL_PIN')
    installation = support.load(support.checked(pins[install_path]))
    for item in installation['files']:
        absolute = dict(item, path=str(Path(manifest['bundle']['path']) / item['path']))
        support.need(pins.get(absolute['path']) == absolute, 'BUNDLE_FILE_PIN')
    for item in installation['external']:
        absolute = {key: item[key] for key in ('path', 'bytes', 'sha256')}
        support.need(pins.get(absolute['path']) == absolute, 'BUNDLE_EXTERNAL_PIN')


def native_argv(config, manifest_pin, root, preflight):
    folder = root / 'receivers/transport/input'
    destination = root / ('preflight/native' if preflight else 'receivers/transport')
    return [config['python']['path'], '-I', '-S', '-B', '-Werror',
            config['native']['path'], 'prepare', '--manifest', str(folder / 'manifest.json'),
            '--expect-manifest-sha256', manifest_pin, '--annotations',
            str(folder / 'annotations.json'), '--expect-annotations-sha256',
            config['inputs']['annotations']['sha256'], '--expect-core-sha256',
            config['retrieval_core']['sha256'], '--workspace',
            str(destination / 'source-workspace'), '--receipt',
            str(destination / 'decode-receipt.json')]


def receiver_interface(config, data, root, manifest_pin):
    original = data['old_interface'].decode('utf-8')
    old_pin = config['inputs']['manifest']['sha256']
    support.need(original.count(old_pin) == 2 and config['old_root'] in original,
                 'ORIGINAL_INTERFACE_SHAPE')
    first = 'Fresh source-review receiver; PUBLIC DEVELOPMENT, one first attempt.\n'
    support.need(original.startswith(first), 'ORIGINAL_INTERFACE_PREFIX')
    changed = original.replace(config['old_root'], str(root)).replace(old_pin, manifest_pin)
    return changed.replace(first,
        'Fresh source-review receiver; PUBLIC DEVELOPMENT repair verification, one attempt.\n'
        'This separately charged transport-only repair run does not replace any previous result.\n'
        'No comparative benefit or semantic-completeness claim follows.\n', 1).encode('utf-8')


def stage_payloads(config, data, content, manifest, root, records):
    folder = 'receivers/transport/input'
    for name, raw in content.items():
        support.save(root, folder + '/content/' + name, raw, records)
    manifest['content']['root'] = str(root / folder / 'content')
    raw = support.raw_json(manifest)
    item = support.save(root, folder + '/manifest.json', raw, records)
    for key in ('annotations', 'changes', 'task'):
        suffix = '.txt' if key == 'task' else '.json'
        support.save(root, folder + '/' + key + suffix, data[key], records)
    text = receiver_interface(config, data, root, item['sha256'])
    support.save(root, folder + '/interface.txt', text, records)
    command = native_argv(config, item['sha256'], root, False)
    support.save(root, 'runs/receiver-native-command.json', support.raw_json(command), records)
    preflight = native_argv(config, item['sha256'], root, True)
    support.save(root, 'preflight/native-command.json', support.raw_json(preflight), records)
    return item['sha256']


def launch(root):
    folder = root / 'receivers/transport/input'
    message = ('You are a fresh receiving source reviewer for one public repair verification. '
               'Start by reading exactly these files:\n' + str(folder / 'interface.txt') +
               '\n' + str(folder / 'task.txt') + '\nCarry out that unchanged task using only '
               'its declared inputs. Return the exact saved first JSON answer as your final response.')
    return {'schema': 'transport/fresh-source-review-launch/1',
            'task_name': 'public_receiver_transport_repair_02', 'model': 'gpt-6.1-sol',
            'reasoning_effort': 'high', 'fork_turns': 'none', 'message': message}


def prepare(config_path, config_pin, anchor, run_name):
    config, data, config_raw = configuration(config_path, config_pin)
    manifest = sealed_inputs(config, data)
    declared_dependencies(config, manifest)
    content = declared_content(manifest)
    root = support.new_run(anchor, run_name)
    for directory in LAYOUT:
        private.chain(root, directory)
    records = []
    manifest_pin = stage_payloads(config, data, content, manifest, root, records)
    for name, raw in data.items():
        if name not in ('manifest', 'annotations', 'changes', 'old_interface'):
            suffix = '.txt' if name == 'task' else '.json'
            support.save(root, 'preflight/' + name + suffix, raw, records)
    support.save(root, 'preflight/config.json', config_raw, records)
    for name in ('stage_repair.py', 'stage_repair_support.py', 'private_staging.py'):
        raw = support.read(Path(__file__).resolve().parent / name)
        support.save(root, 'preflight/' + name, raw, records)
    support.save(root, 'receivers/transport/launch.json', support.raw_json(launch(root)), records)
    for directory in LAYOUT:
        private.chain(root, directory, create=False)
    summary = {'schema': 'transport/receiving-repair-staging/2',
               'status': 'STAGED_NOT_DISPATCHED', 'config_sha256': config_pin,
               'manifest_sha256': manifest_pin, 'files': list(records),
               'directory_mode': '0700', 'payload_mode': '0600',
               'source_input': 'UNCHANGED_PUBLIC_SC_MAIN', 'model_calls': 0,
               'retained_first_failure_sha256': config['inputs']['failure']['sha256'],
               'first_trial': 'RETAINED_FAILED', 'native_preflight': 'NOT_RUN',
               'independent_prelaunch_review': 'REQUIRED', 'authority': 'NONE'}
    support.save(root, 'preflight/staged-inputs.json', support.raw_json(summary), records)
    return summary


def timed_out(unused_signal, unused_frame):
    raise ValueError('STAGING_WALL_LIMIT')


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--expect-config-sha256', required=True)
    parser.add_argument('--anchor', type=Path, required=True)
    parser.add_argument('--run-name', required=True)
    args = parser.parse_args()
    try:
        import resource
        for kind, cap in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 30),
                          (resource.RLIMIT_FSIZE, 4194304)):
            support.lower_limit(kind, cap)
        signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(30)
        result = prepare(args.config, args.expect_config_sha256, args.anchor, args.run_name)
        print(support.raw_json(result).decode())
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        print(support.raw_json({'status': 'STAGING_REFUSED', 'reason': str(error)[:256],
                               'partial_private_files_may_exist': True,
                               'authority': 'NONE', 'model_calls': 0}).decode())
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
