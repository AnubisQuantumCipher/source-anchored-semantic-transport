"""Prepare one frozen positive ZIP-only replay; never import or execute products."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

CAP = 65536
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
ARRAYS = ('blobs', 'challenges', 'claims', 'dependencies', 'history',
          'input_manifests', 'provenance', 'reading_withdrawals', 'readings',
          'rules', 'run_evidence', 'selectors', 'sources', 'tasks', 'updates')
CHECKER = tuple('tools/transport_quorum_' + n + '.py' for n in
                ('input', 'shape', 'source', 'claim', 'graph', 'impact',
                 'context', 'reading', 'replay')) + (
    'tools/transport_quorum_body.schema.json',
    'tools/transport_quorum_protocol-rules.json',
    'install/transport_quorum_bootstrap.py')
HELPERS = tuple('install/' + n for n in ('transport_handoff_inputs.py',
    'transport_install_layout.py', 'transport_install_support.py',
    'test_portable_handoff.py'))
HELD = ('bootstrap_entry', 'decoder_install_descriptor', 'runtime_descriptor',
        'source_manifest', 'bundle_snapshot')


class PreparationError(ValueError):
    """Named preparation failure; never a fullReplay verdict."""


def need(condition, reason):
    if not condition:
        raise PreparationError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def fields(value, names):
    need(type(value) is dict and len(value) == len(names), 'PUBLIC_FIELDS')
    need(all(name in value for name in names), 'PUBLIC_FIELDS')


def checked_pin(value):
    fields(value, ('bytes', 'sha256'))
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= 8388608,
         'PUBLIC_PIN')
    need(type(value['sha256']) is str and len(value['sha256']) == 64
         and DIGEST.fullmatch(value['sha256']) is not None, 'PUBLIC_PIN')
    return dict(value)


def absolute(value):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096,
         'PUBLIC_PATH')
    need(value.startswith('/') and os.path.normpath(value) == value
         and '\x00' not in value and len(Path(value).parts) <= 65, 'PUBLIC_PATH')
    return Path(value)


def read(path, cap):
    path = absolute(str(path))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    parts = path.parts[1:]
    need(bool(parts), 'PUBLIC_PATH')
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=directory)
            os.close(directory)
            directory = nxt
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap,
             'PUBLIC_FILE')
        raw = bytearray()
        for unused in range(cap // 16384 + 2):
            block = os.read(descriptor, min(16384, cap + 1 - len(raw)))
            if not block:
                after = os.fstat(descriptor)
                names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                need(all(getattr(before, n) == getattr(after, n) for n in names)
                     and len(raw) == after.st_size, 'PUBLIC_FILE')
                return bytes(raw)
            raw.extend(block)
            need(len(raw) <= cap, 'PUBLIC_FILE')
        raise PreparationError('PUBLIC_FILE')
    finally:
        os.close(descriptor)


def pairs(items):
    need(len(items) <= 16384, 'PUBLIC_JSON')
    result = {}
    for key, value in items:
        need(key not in result, 'PUBLIC_JSON')
        result[key] = value
    return result


def rejected(value):
    raise PreparationError('PUBLIC_JSON')


def tree_bound(value):
    pending = [(value, 0)]
    for unused in range(16384):
        if not pending:
            return
        node, depth = pending.pop()
        need(depth <= 12, 'PUBLIC_JSON')
        if type(node) is dict:
            for key, item in node.items():
                key.encode('utf-8', errors='strict')
                pending.append((item, depth + 1))
        elif type(node) is list:
            for item in node:
                pending.append((item, depth + 1))
        elif type(node) is str:
            node.encode('utf-8', errors='strict')
        else:
            need(node is None or type(node) is bool or
                 (type(node) is int and 0 <= node <= 18446744073709551615),
                 'PUBLIC_JSON')
        need(len(pending) <= 16384, 'PUBLIC_JSON')
    raise PreparationError('PUBLIC_JSON')


def document(raw):
    need(len(raw) <= CAP, 'PUBLIC_JSON')
    # Lexical depth precheck bounds the stdlib parser before allocation.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= 12, 'PUBLIC_JSON')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'PUBLIC_JSON')
    value = json.loads(raw.decode('utf-8', errors='strict'),
                       object_pairs_hook=pairs, parse_float=rejected,
                       parse_constant=rejected)
    tree_bound(value)
    need(canonical(value) == raw, 'PUBLIC_JSON')
    return value


def source_key(raw, label):
    return dict(logical_source_id=label, **pin(raw))


def observed_roots(args, held):
    paths = {'bootstrap_entry': args.checker_root / 'install/transport_quorum_bootstrap.py',
             'decoder_install_descriptor': args.decoder_root / 'INSTALL.json',
             'runtime_descriptor': args.decoder_root / 'RUNTIME.json',
             'source_manifest': args.decoder_source_root / 'install/SOURCE.json',
             'bundle_snapshot': args.snapshot_file}
    observed = {}
    for name in HELD:
        cap = 131072 if name == 'bootstrap_entry' else CAP
        raw = read(paths[name], cap)
        need(pin(raw) == checked_pin(held[name]), 'PUBLIC_PIN')
        observed[name] = raw
    return observed


def relative(root, name):
    need(type(name) is str and 0 < len(name) <= 512 and not name.startswith('/'),
         'PUBLIC_PATH')
    parts = name.split('/')
    need(len(parts) <= 16 and all(p not in ('', '.', '..') for p in parts),
         'PUBLIC_PATH')
    return root / name


def snapshot_check(args, raw):
    snapshot = document(raw)
    fields(snapshot, ('path', 'install_manifest', 'runtime_manifest',
                      'runtime_files', 'files'))
    need(snapshot['path'] == str(args.decoder_root), 'PUBLIC_SNAPSHOT')
    files = snapshot['files']
    need(type(files) is dict and 1 <= len(files) <= 130, 'PUBLIC_SNAPSHOT')
    total = 0
    for name, item in files.items():
        fields(item, ('bytes', 'sha256', 'mode'))
        data = read(relative(args.decoder_root, name), 4194304)
        total += len(data)
        need(total <= 8388608 and pin(data) == {k: item[k] for k in ('bytes', 'sha256')},
             'PUBLIC_SNAPSHOT')
        mode = stat.S_IMODE(relative(args.decoder_root, name).stat().st_mode)
        need(type(item['mode']) is int and mode == item['mode'], 'PUBLIC_SNAPSHOT')
    need(snapshot['install_manifest'] == pin(read(args.decoder_root / 'INSTALL.json', CAP))
         and snapshot['runtime_manifest'] == pin(read(args.decoder_root / 'RUNTIME.json', CAP)),
         'PUBLIC_SNAPSHOT')


def fixture(args):
    manifest = document(read(args.fixture_manifest, CAP))
    fields(manifest, ('schema', 'identity', 'body', 'originals', 'expected',
                      'archive', 'share'))
    need(manifest['schema'] == 'quorum/public-replay-fixture/1', 'PUBLIC_FIXTURE')
    identity = manifest['identity']
    need(type(identity) is str and identity.startswith('STS1:')
         and DIGEST.fullmatch(identity[5:]) is not None, 'PUBLIC_FIXTURE')
    values = {}
    for name in ('body', 'originals', 'expected', 'archive', 'share'):
        item = manifest[name]
        fields(item, ('path', 'bytes', 'sha256'))
        path = relative(args.fixture_manifest.parent, item['path'])
        raw = read(path, 131072 if name == 'archive' else CAP)
        expected = checked_pin({k: item[k] for k in ('bytes', 'sha256')})
        need(pin(raw) == expected, 'PUBLIC_PIN')
        values[name] = (path, raw)
    return manifest, values


def fixture_body(values):
    body = document(values['body'][1])
    originals = document(values['originals'][1])
    fields(originals, ('items', 'outer_type'))
    need(originals['outer_type'] == 'tuple' and type(originals['items']) is list
         and len(originals['items']) <= 15, 'PUBLIC_BODY')
    source_rows = body['sources']
    need(type(source_rows) is list and len(source_rows) <= 15, 'PUBLIC_BODY')
    declared = {row['id']: row['key'] for row in source_rows}
    supplied = {row['alias_id']: row['key'] for row in originals['items']}
    need(len(declared) == len(source_rows) and len(supplied) == len(originals['items'])
         and declared == supplied, 'PUBLIC_BODY')
    need(len(values['body'][1]) + sum(row['bytes'] for row in declared.values()) <= CAP,
         'PUBLIC_BODY')
    need(len(body['tasks']) == 1, 'PUBLIC_BODY')
    return body, supplied


def descriptor(args, observed):
    rows = []
    for prefix, names in (('checker', CHECKER), ('handoff', HELPERS)):
        for name in names:
            raw = read(args.checker_root / name, 131072)
            rows.append(dict(path=prefix + '/' + name, **pin(raw)))
    python = Path(sys.executable).resolve()
    return {'schema': 'quorum/checker-bootstrap/1', 'platform': 'LINUX_OMARCHY_ONLY',
        'checker_root': str(args.checker_root), 'handoff_root': str(args.checker_root),
        'decoder_bundle_root': str(args.decoder_root),
        'decoder_source_root': str(args.decoder_source_root),
        'decoder_source_manifest_sha256': pin(observed['source_manifest'])['sha256'],
        'python': dict(path=str(python), **pin(read(python, 4194304))),
        'files': sorted(rows, key=lambda row: canonical(row['path']))}


def record_pin(row, address=None):
    return dict(id=row['id'] if address is None else address, **pin(canonical(row)))


def record_pins(body):
    result = [record_pin(body['registry']), record_pin(body['policy'])]
    need(len(body['registry']['seats']) <= 16, 'PUBLIC_BODY')
    result.extend(record_pin(r) for r in body['registry']['seats'])
    for name in ARRAYS:
        need(type(body[name]) is list and len(body[name]) <= 64, 'PUBLIC_BODY')
        for row in body[name]:
            address = row['id'] + ':' + row['revision'] if name == 'claims' else None
            result.append(record_pin(row, address))
            need(len(result) <= 96, 'PUBLIC_BODY')
    return sorted(result, key=canonical)


def make_request(body, values, keys):
    owned = copy.deepcopy(keys)
    unique_sources = {canonical(r['key']): copy.deepcopy(r['key']) for r in body['sources']}
    return {'schema': 'quorum/replay-request/1', 'package': pin(values['archive'][1]),
        'quorum_body': pin(values['body'][1]), 'task': record_pin(body['tasks'][0]),
        'registry': record_pin(body['registry']),
        'rules': sorted([record_pin(r) for r in body['rules']], key=canonical),
        'policy': record_pin(body['policy']), 'wire_schema': owned['wire_schema'],
        'protocol_rules': owned['protocol_rules'],
        'checker': {n: owned[n] for n in ('checker_descriptor', 'runtime_descriptor',
                    'decoder_install_descriptor')} | {'supported_platform': 'LINUX_OMARCHY_ONLY'},
        'input_manifest_pins': sorted([record_pin(r) for r in body['input_manifests']], key=canonical),
        'record_pins': record_pins(body),
        'external_source_pins': sorted(unique_sources.values(), key=canonical)}


def expected_result(raw, held):
    result = copy.deepcopy(document(raw))
    pending = [result]
    for unused in range(16384):
        if not pending:
            return result
        node = pending.pop()
        if type(node) is dict:
            for name, item in node.items():
                if type(item) is dict and set(item) == {'$mechanical'}:
                    node[name] = dict(id='REPLAY_REQUEST', **held)
                elif type(item) in (dict, list):
                    pending.append(item)
        elif type(node) is list:
            for item in node:
                if type(item) in (dict, list):
                    pending.append(item)
    raise PreparationError('PUBLIC_BODY')


def output(args, name, value, tally):
    raw = value if type(value) is bytes else canonical(value)
    tally[0] += len(raw)
    need(len(raw) <= 131072 and tally[0] <= 1048576, 'PUBLIC_OUTPUT_BOUND')
    path = args.out / name
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'PUBLIC_FILE')
    return dict(path=str(path), **pin(raw))


def materialize(args, held, observed, manifest, values, body, sources):
    need(not args.out.exists(), 'PUBLIC_PATH')
    args.out.mkdir()
    tally = [0]
    desc = output(args, 'checker-descriptor.json', descriptor(args, observed), tally)
    keys = {'checker_descriptor': dict(logical_source_id='CHECKER_DESCRIPTOR',
               **{k: desc[k] for k in ('bytes', 'sha256')}),
        'wire_schema': source_key(read(args.checker_root / CHECKER[-3], CAP), 'WIRE_SCHEMA'),
        'protocol_rules': source_key(read(args.checker_root / CHECKER[-2], CAP), 'PROTOCOL_RULES'),
        'decoder_install_descriptor': source_key(observed['decoder_install_descriptor'], 'DECODER_INSTALL_DESCRIPTOR'),
        'runtime_descriptor': source_key(observed['runtime_descriptor'], 'DECODER_RUNTIME_DESCRIPTOR')}
    frozen_keys = canonical(keys)
    request = make_request(body, values, keys)
    req = output(args, 'request.json', request, tally)
    held_request = {k: req[k] for k in ('bytes', 'sha256')}
    env = output(args, 'envelope.json', {'schema': 'quorum/external-replay-envelope/1',
        'request': copy.deepcopy(request), 'untrusted_receipt': None}, tally)
    absent = args.out / 'ABSENT_EVALUATOR_SIDECARS'
    need(not absent.exists(), 'PUBLIC_PATH')
    invocation = {'schema': 'quorum/bootstrap-invocation/1', 'arm': 'transport',
        'bootstrap_entry': copy.deepcopy(held['bootstrap_entry']),
        'checker_descriptor': {'path': desc['path'], 'key': copy.deepcopy(keys['checker_descriptor'])},
        'decoder_install_descriptor': copy.deepcopy(keys['decoder_install_descriptor']),
        'runtime_descriptor': copy.deepcopy(keys['runtime_descriptor']),
        'source_manifest_pin': copy.deepcopy(held['source_manifest']),
        'bundle_snapshot_pin': copy.deepcopy(held['bundle_snapshot']),
        'wire_schema': copy.deepcopy(keys['wire_schema']), 'protocol_rules': copy.deepcopy(keys['protocol_rules']),
        'request': req, 'held_request': held_request, 'envelope': env,
        'body': dict(path=str(absent / 'body.json'), **pin(values['body'][1])),
        'package': dict(path=str(values['archive'][0]), **pin(values['archive'][1])),
        'originals': [{'alias': alias, 'key': copy.deepcopy(key),
                       'path': str(absent / ('source-' + str(i)))}
                      for i, (alias, key) in enumerate(sorted(sources.items(), key=lambda row: canonical(row[0])))],
        'share': dict(path=str(values['share'][0]), identity=manifest['identity'], **pin(values['share'][1])),
        'auxiliary': None}
    inv = output(args, 'invocation.json', invocation, tally)
    output(args, 'expected.json', expected_result(values['expected'][1], held_request), tally)
    need(canonical(keys) == frozen_keys, 'PUBLIC_HOST_MUTATED')
    return inv, tally


def finish(args, held, before, inv, tally):
    after = observed_roots(args, held)
    need(before == canonical({n: pin(r) for n, r in after.items()}), 'PUBLIC_HOST_MUTATED')
    entry = args.checker_root / 'install/transport_quorum_bootstrap.py'
    command = [str(Path(sys.executable).resolve()), '-I', '-S', str(entry), inv['path'],
               '--expect-invocation-sha256', inv['sha256'],
               '--expect-bootstrap-sha256', held['bootstrap_entry']['sha256']]
    output(args, 'result-command.json', {'argv': command, 'execution': 'NOT_RUN'}, tally)
    output(args, 'command.txt', (shlex.join(command) + '\n').encode(), tally)
    receipt = {'schema': 'quorum/public-preparation-receipt/1',
        'status': 'PREPARED_NOT_EXECUTED', 'invocation': inv,
        'independently_held_root_pins': copy.deepcopy(held),
        'host_observations': 'UNCHANGED_EXACT_PINS',
        'runtime_sidecars': 'ABSENT_TRANSPORT_PATHS_ONLY',
        'qualification': 'NOT_EVALUATED', 'acceptance': 'NOT_EVALUATED',
        'trust': 'Recipient independently verifies entry/release before execution; preparer is not authority.'}
    return output(args, 'preparation-receipt.json', receipt, tally)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('checker-root', 'decoder-root', 'decoder-source-root', 'held-identities',
                 'snapshot-file', 'fixture-manifest', 'out'):
        parser.add_argument('--' + name, type=absolute, required=True)
    args = parser.parse_args()
    held = document(read(args.held_identities, CAP))
    fields(held, ('schema',) + HELD)
    need(held['schema'] == 'quorum/public-held-identities/1', 'PUBLIC_FIELDS')
    observed = observed_roots(args, held)
    before = canonical({n: pin(r) for n, r in observed.items()})
    snapshot_check(args, observed['bundle_snapshot'])
    manifest, values = fixture(args)
    body, sources = fixture_body(values)
    inv, tally = materialize(args, held, observed, manifest, values, body, sources)
    receipt = finish(args, held, before, inv, tally)
    print(canonical(receipt).decode())


if __name__ == '__main__':
    try:
        main()
    except PreparationError as error:
        print(json.dumps({'status': 'REFUSED_PREPARATION', 'reason': str(error)}))
        raise SystemExit(2)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        print(json.dumps({'status': 'REFUSED_PREPARATION', 'reason': 'PUBLIC_JSON'}))
        raise SystemExit(2)
    except OSError:
        print(json.dumps({'status': 'REFUSED_PREPARATION', 'reason': 'PUBLIC_FILE'}))
        raise SystemExit(2)
    except (KeyError, TypeError, ValueError):
        print(json.dumps({'status': 'REFUSED_PREPARATION', 'reason': 'PUBLIC_BODY'}))
        raise SystemExit(2)
