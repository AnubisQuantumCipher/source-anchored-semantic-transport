"""Bounded data-only preparer controls; no replay/bootstrap invocation."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parent
SOURCE_SHA = '23119618174b44cf9fd411014c861751a87317d59a5bb333842b5fa7c356d830'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    require(len(raw) <= 131072, 'control file bound')
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'control write')
    return pin(raw)


def set_arg(argv, name, value):
    result = list(argv)
    result[result.index('--' + name) + 1] = str(value)
    return result


def run_case(name, argv, expected, out):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=30)
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'control subprocess output bound')
    stdout_pin = save(out / (name + '.stdout'), result.stdout)
    stderr_pin = save(out / (name + '.stderr'), result.stderr)
    actual = json.loads(result.stdout)
    row = {'id': name, 'argv': argv, 'expected_exit': 2, 'exit': result.returncode,
           'expected_stdout': {'status': 'REFUSED_PREPARATION', 'reason': expected},
           'stdout': actual, 'stdout_pin': stdout_pin, 'stderr_pin': stderr_pin,
           'matches': result.returncode == 2 and actual == {
               'status': 'REFUSED_PREPARATION', 'reason': expected} and result.stderr == b''}
    save(out / (name + '.json'), row)
    return row


def copied_fixture(base, out, loader):
    manifest_path = Path(base[base.index('--fixture-manifest') + 1])
    raw = loader(manifest_path, 65536)
    value = json.loads(raw)
    folder = out / 'copied-fixture'
    folder.mkdir()
    for name in ('body', 'originals', 'expected', 'archive', 'share'):
        item = value[name]
        target = folder / item['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        save(target, loader(manifest_path.parent / item['path'], 131072))
    path = folder / 'fixture-manifest.json'
    save(path, raw)
    return path, value


def simple_cases(base, held, out):
    rows = []
    mutations = (('U02', 'bootstrap_entry', 'PUBLIC_PIN'),
                 ('U03', 'source_manifest', 'PUBLIC_PIN'))
    for name, field, expected in mutations:
        value = copy.deepcopy(held)
        value[field]['sha256'] = '0' * 64
        path = out / (name + '-held.json')
        save(path, value)
        argv = set_arg(set_arg(base, 'held-identities', path), 'out', out / (name + '-out'))
        rows.append(run_case(name, argv, expected, out))
    value = copy.deepcopy(held)
    value['extra'] = None
    path = out / 'U07-held.json'
    save(path, value)
    rows.append(run_case('U07', set_arg(base, 'held-identities', path), 'PUBLIC_FIELDS', out))
    value = copy.deepcopy(held)
    value['bootstrap_entry']['bytes'] = 100000000000000000000
    path = out / 'U11-held.json'
    save(path, value)
    rows.append(run_case('U11', set_arg(base, 'held-identities', path), 'PUBLIC_JSON', out))
    rows.append(run_case('U06', base, 'PUBLIC_PATH', out))
    return rows


def snapshot_cases(base, held, out, loader):
    rows = []
    snapshot_path = Path(base[base.index('--snapshot-file') + 1])
    value = json.loads(loader(snapshot_path, 65536))
    value['path'] = '/INTENTIONALLY_WRONG_DECODER_ROOT'
    path = out / 'U04-snapshot.json'
    new_pin = save(path, value)
    h = copy.deepcopy(held)
    h['bundle_snapshot'] = new_pin
    held_path = out / 'U04-held.json'
    save(held_path, h)
    argv = set_arg(set_arg(base, 'snapshot-file', path), 'held-identities', held_path)
    rows.append(run_case('U04', argv, 'PUBLIC_SNAPSHOT', out))
    decoder = out / 'U12-decoder'
    decoder.mkdir()
    install = save(decoder / 'INSTALL.json', b'0')
    runtime = save(decoder / 'RUNTIME.json', b'0')
    byte_pin = save(decoder / 'x', b'x')
    mode = stat.S_IMODE((decoder / 'x').stat().st_mode)
    value = {'path': str(decoder), 'install_manifest': install, 'runtime_manifest': runtime,
             'runtime_files': {'x': byte_pin}, 'files': {'x': dict(byte_pin, bytes=True, mode=mode)}}
    path = out / 'U12-snapshot.json'
    snapshot_pin = save(path, value)
    h = copy.deepcopy(held)
    h.update(decoder_install_descriptor=install, runtime_descriptor=runtime,
             bundle_snapshot=snapshot_pin)
    held_path = out / 'U12-held.json'
    save(held_path, h)
    argv = set_arg(set_arg(set_arg(base, 'snapshot-file', path), 'held-identities', held_path),
                   'decoder-root', decoder)
    rows.append(run_case('U12', argv, 'PUBLIC_PIN', out))
    return rows


def fixture_cases(base, out, loader):
    path, value = copied_fixture(base, out, loader)
    archive = path.parent / value['archive']['path']
    raw = loader(archive, 131072)
    changed = bytes([raw[0] ^ 1]) + raw[1:]
    archive.write_bytes(changed)
    argv = set_arg(base, 'fixture-manifest', path)
    rows = [run_case('U05', argv, 'PUBLIC_PIN', out)]
    value['archive'].update(pin(changed))
    path.write_bytes(canonical(value))
    rows.append(run_case('U10', argv, 'PUBLIC_PIN', out))
    return rows


def copy_control(namespace, base, out):
    manifest_path = Path(base[base.index('--fixture-manifest') + 1])
    manifest = namespace['document'](namespace['read'](manifest_path, 65536))
    body_raw = namespace['read'](manifest_path.parent / manifest['body']['path'], 65536)
    archive = namespace['read'](manifest_path.parent / manifest['archive']['path'], 131072)
    body = namespace['document'](body_raw)
    keys = {name: {'logical_source_id': name, 'bytes': 0, 'sha256': '1' * 64}
            for name in ('wire_schema', 'protocol_rules', 'checker_descriptor',
                         'runtime_descriptor', 'decoder_install_descriptor')}
    before = canonical(keys)
    request = namespace['make_request'](body, {'body': (None, body_raw),
                                               'archive': (None, archive)}, keys)
    request['checker']['runtime_descriptor']['sha256'] = '0' * 64
    row = {'id': 'U08', 'expected': {'input_keys': 'UNCHANGED_EXACT_BYTES',
            'candidate_changed': True, 'bootstrap_executed': False},
           'actual': {'input_keys': 'UNCHANGED_EXACT_BYTES' if canonical(keys) == before else 'MUTATED',
            'candidate_changed': request['checker']['runtime_descriptor']['sha256'] == '0' * 64,
            'bootstrap_executed': False}}
    row['matches'] = row['actual'] == row['expected']
    save(out / 'U08.json', row)
    return row


def main():
    raw = (ROOT / 'prepare_public_replay.py').read_bytes()
    require(pin(raw)['sha256'] == SOURCE_SHA, 'source freeze mismatch')
    namespace = {'__name__': 'owned_preparation_control', '__file__': str(ROOT / 'prepare_public_replay.py')}
    exec(compile(raw, namespace['__file__'], 'exec'), namespace)
    base = json.loads((ROOT / 'preparation-command.json').read_bytes())['argv']
    held = json.loads((ROOT / 'held-identities.json').read_bytes())
    out = ROOT / 'preparation-controls-first-run'
    out.mkdir()
    rows = simple_cases(base, held, out)
    rows.extend(snapshot_cases(base, held, out, namespace['read']))
    rows.extend(fixture_cases(base, out, namespace['read']))
    rows.append(copy_control(namespace, base, out))
    require(len(rows) == 10, 'finite control count')
    result = {'schema': 'quorum/public-preparer-controls/1', 'source': pin(raw),
              'cases': rows, 'all_match': all(row['matches'] for row in rows),
              'bootstrap_invocation': 'NOT_RUN', 'scope': 'Data-only preparation controls.'}
    save(out / 'results.json', result)
    print(json.dumps({'path': str(out / 'results.json'), 'all_match': result['all_match']}))


if __name__ == '__main__':
    main()
