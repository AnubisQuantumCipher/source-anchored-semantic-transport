"""Prepare bounded caller-authored QUORUM sources for paired qualified replay.

Preparation freezes inputs and executes only the pinned installed encoder. It does
not execute the replay commands or establish semantic truth or current authority.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import types

CAP = 65536
FILE_CAP = 131072
TOTAL_CAP = 1048576
HELPER_PINS = {
    'prepare_quorum_replay.py': '23119618174b44cf9fd411014c861751a87317d59a5bb333842b5fa7c356d830',
    'transport_public_share.py': 'cba055858360c177f25bd510c24ebdf31833e8ed550f362c55d946acbfc766b9'}
HELD = ('bootstrap_entry', 'decoder_install_descriptor', 'runtime_descriptor',
        'source_manifest', 'bundle_snapshot', 'encoder_launcher', 'sender_input')
IDENTIFIER = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
LOGICAL_ID = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,31}$')


class SenderError(ValueError):
    """Named refusal; never a replay verdict."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SenderError('SENDER_INPUT_FIELDS')


def need(condition, reason):
    if not condition:
        raise SenderError(reason)


def bootstrap_read(path):
    """Bounded no-symlink read before trusted helper functions are available."""
    need(path.is_absolute() and len(path.parts) <= 65, 'SENDER_HELPER')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=directory)
            os.close(directory)
            directory = nxt
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= CAP, 'SENDER_HELPER')
        result = bytearray()
        for unused in range(CAP + 1):
            block = os.read(fd, min(16384, CAP + 1 - len(result)))
            if not block:
                after = os.fstat(fd)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                need(all(getattr(before, n) == getattr(after, n) for n in fields)
                     and len(result) == after.st_size, 'SENDER_HELPER')
                return bytes(result)
            result.extend(block)
            need(len(result) <= CAP, 'SENDER_HELPER')
        raise SenderError('SENDER_HELPER')
    finally:
        os.close(fd)


def helpers():
    result, observed = [], []
    root = Path(os.path.abspath(__file__)).parent
    for name, digest in HELPER_PINS.items():
        path = root / name
        raw = bootstrap_read(path)
        need(hashlib.sha256(raw).hexdigest() == digest, 'SENDER_HELPER')
        module = types.ModuleType('_sender_' + name[:-3])
        module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        result.append(module)
        observed.append((path, raw))
    return result[0], result[1], observed


def closed(value, names, reason):
    need(type(value) is dict and set(value) == set(names), reason)


def source_key(p, value):
    closed(value, ('logical_source_id', 'bytes', 'sha256'), 'SENDER_SOURCES')
    # Preserve the pinned wire schema's maxLength and search semantics,
    # including its existing final-LF behavior; archive aliases stay narrower.
    need(type(value['logical_source_id']) is str and
         len(value['logical_source_id']) <= 32 and
         LOGICAL_ID.search(value['logical_source_id']) is not None,
         'SENDER_SOURCES')
    pin = p.checked_pin({name: value[name] for name in ('bytes', 'sha256')})
    need(pin['bytes'] <= CAP, 'SENDER_BOUND')
    return dict(logical_source_id=value['logical_source_id'], **pin)


def roots(p, args, held):
    paths = {'bootstrap_entry': args.checker_root / 'install/transport_quorum_bootstrap.py',
             'decoder_install_descriptor': args.decoder_root / 'INSTALL.json',
             'runtime_descriptor': args.decoder_root / 'RUNTIME.json',
             'source_manifest': args.decoder_source_root / 'install/SOURCE.json',
             'bundle_snapshot': args.snapshot_file,
             'encoder_launcher': args.decoder_root / 'bin/semantic-transport',
             'sender_input': args.sender_input}
    result = {}
    for name in HELD:
        raw = p.read(paths[name], FILE_CAP if name == 'bootstrap_entry' else CAP)
        need(p.pin(raw) == p.checked_pin(held[name]), 'SENDER_PIN')
        result[name] = raw
    return result


def body_preflight(p, body):
    closed(body, ('schema', 'mode', 'registry', 'policy') + p.ARRAYS, 'SENDER_BODY')
    need(body['schema'] == 'quorum/replay-body/1' and
         body['mode'] == 'PURE_INFORMATIONAL_REPLAY', 'SENDER_BODY')
    need(type(body['registry']) is dict and type(body['policy']) is dict,
         'SENDER_BODY')
    for name in p.ARRAYS:
        rows = body[name]
        need(type(rows) is list and len(rows) <= 64 and
             all(type(row) is dict for row in rows), 'SENDER_BODY')
    need(len(body['tasks']) == 1 and len(body['sources']) <= 15, 'SENDER_BODY')
    p.record_pins(body)


def sender_inputs(p, raw):
    value = p.document(raw)
    closed(value, ('schema', 'body', 'sources'), 'SENDER_INPUT_FIELDS')
    need(value['schema'] == 'quorum/sender-input/1', 'SENDER_SCHEMA')
    row = value['body']
    closed(row, ('path', 'bytes', 'sha256'), 'SENDER_BODY')
    path = p.absolute(row['path'])
    body_raw = p.read(path, CAP)
    expected = p.checked_pin({k: row[k] for k in ('bytes', 'sha256')})
    need(p.pin(body_raw) == expected, 'SENDER_PIN')
    body = p.document(body_raw)
    body_preflight(p, body)
    rows = value['sources']
    need(type(rows) is list and len(rows) <= 15, 'SENDER_SOURCES')
    observed, supplied, total = [(path, body_raw)], {}, len(body_raw)
    for item in rows:
        closed(item, ('alias', 'key', 'path'), 'SENDER_SOURCES')
        alias = item['alias']
        need(type(alias) is str and IDENTIFIER.fullmatch(alias) is not None
             and alias != 'Q_RECORDS' and alias not in supplied, 'SENDER_SOURCES')
        key, path = source_key(p, item['key']), p.absolute(item['path'])
        data = p.read(path, CAP)
        need(p.pin(data) == {k: key[k] for k in ('bytes', 'sha256')}, 'SENDER_PIN')
        total += len(data)
        need(total <= CAP, 'SENDER_BOUND')
        supplied[alias] = (key, data)
        observed.append((path, data))
    declared = {}
    for row in body['sources']:
        alias = row.get('id')
        need(type(alias) is str and IDENTIFIER.fullmatch(alias) is not None
             and alias != 'Q_RECORDS' and alias not in declared, 'SENDER_SOURCES')
        declared[alias] = source_key(p, row['key'])
    need(declared == {name: row[0] for name, row in supplied.items()}, 'SENDER_SOURCES')
    return body, body_raw, supplied, observed


def new_directory(s, path):
    parent = s._parent(path)
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
        except FileExistsError as error:
            raise SenderError('SENDER_OUTPUT_EXISTS') from error
    finally:
        os.close(parent)


def publish(p, s, args, state, name, value):
    raw = value if type(value) is bytes else p.canonical(value)
    need(len(raw) <= FILE_CAP and state['total'] + len(raw) <= TOTAL_CAP, 'SENDER_BOUND')
    path = args.out / name
    s._publish(path, raw)
    state['total'] += len(raw)
    state['files'][name] = raw
    return dict(path=str(path), **p.pin(raw))


def copy_sources(p, s, args, state, body_raw, sources):
    body_file = publish(p, s, args, state, 'body.json', body_raw)
    copied = []
    for index, alias in enumerate(sorted(sources, key=p.canonical)):
        key, raw = sources[alias]
        row = publish(p, s, args, state, 'source-%02d.bin' % index, raw)
        copied.append(dict(alias=alias, key=copy.deepcopy(key), path=row['path']))
    ids = sorted(list(sources) + ['Q_RECORDS'], key=p.canonical)
    plan = {'schema': 'transport/transport-plan/1', 'interpretations': [],
            'relations': [], 'uncertainties': [], 'sources': [
                {'id': name, 'label': 'Exact fixture ' + name,
                 'media_type': 'application/octet-stream',
                 'provenance': 'Manually supplied frozen original bytes; no semantic qualification.'}
                for name in ids]}
    plan_file = publish(p, s, args, state, 'plan.json', plan)
    return body_file, copied, plan_file


def encode(p, s, args, state, body_file, copied, plan_file):
    command = [str(args.decoder_root / 'bin/semantic-transport'), 'encode-plan',
               plan_file['path'], str(args.out / 'encoded'), '--budget', str(args.budget),
               '--reference', args.reference]
    for row in copied:
        command.extend(('--source', row['alias'] + '=' + row['path']))
    command.extend(('--source', 'Q_RECORDS=' + body_file['path']))
    s._argv_bound(command)
    execution, timed_out = s._run_encoder(command, s._limits())
    recorded = {'argv': command, 'exit_code': execution['exit_code'], 'timed_out': timed_out}
    for stream in ('stdout', 'stderr'):
        raw = base64.b64decode(execution[stream]['base64'], validate=True)
        recorded[stream] = publish(p, s, args, state, 'encoder-' + stream + '.bin', raw)
    publish(p, s, args, state, 'encoder-execution.json', recorded)
    need(not timed_out and execution['exit_code'] == 0, 'SENDER_ENCODER')
    snapshot = s._canonical_snapshot(args.out / 'encoded', 'encode-plan')
    for name, raw in snapshot.items():
        need(state['total'] + len(raw) <= TOTAL_CAP, 'SENDER_BOUND')
        state['total'] += len(raw)
        state['files']['encoded/' + name] = raw
    parts = snapshot['share.txt'].rsplit(b'\n', 2)
    need(len(parts) == 3 and s.TOKEN.fullmatch(parts[1]) is not None and
         parts[2] == args.reference.encode('ascii'), 'SENDER_ENCODER')
    return snapshot, parts[1].decode('ascii')


def descriptor_keys(p, s, args, state, observed):
    value = p.descriptor(args, observed)
    desc = publish(p, s, args, state, 'checker-descriptor.json', value)
    keys = {'checker_descriptor': dict(logical_source_id='CHECKER_DESCRIPTOR',
               **{k: desc[k] for k in ('bytes', 'sha256')}),
        'wire_schema': p.source_key(p.read(args.checker_root / p.CHECKER[-3], CAP), 'WIRE_SCHEMA'),
        'protocol_rules': p.source_key(p.read(args.checker_root / p.CHECKER[-2], CAP), 'PROTOCOL_RULES'),
        'decoder_install_descriptor': p.source_key(observed['decoder_install_descriptor'], 'DECODER_INSTALL_DESCRIPTOR'),
        'runtime_descriptor': p.source_key(observed['runtime_descriptor'], 'DECODER_RUNTIME_DESCRIPTOR')}
    return desc, keys, value


def arm_invocation(p, args, arm, held, desc, keys, body_file, copied, package, share):
    absent = args.out / 'ABSENT_EVALUATOR_SIDECARS'
    rows, body_row = copy.deepcopy(copied), copy.deepcopy(body_file)
    if arm == 'transport':
        body_row['path'] = str(absent / 'body.json')
        for index, row in enumerate(rows):
            row['path'] = str(absent / ('source-%02d.bin' % index))
    return {'schema': 'quorum/bootstrap-invocation/1', 'arm': arm,
        'bootstrap_entry': copy.deepcopy(held['bootstrap_entry']),
        'checker_descriptor': {'path': desc['path'], 'key': copy.deepcopy(keys['checker_descriptor'])},
        'decoder_install_descriptor': copy.deepcopy(keys['decoder_install_descriptor']),
        'runtime_descriptor': copy.deepcopy(keys['runtime_descriptor']),
        'source_manifest_pin': copy.deepcopy(held['source_manifest']),
        'bundle_snapshot_pin': copy.deepcopy(held['bundle_snapshot']),
        'wire_schema': copy.deepcopy(keys['wire_schema']), 'protocol_rules': copy.deepcopy(keys['protocol_rules']),
        'body': body_row, 'package': copy.deepcopy(package), 'originals': rows,
        'share': copy.deepcopy(share), 'auxiliary': None}


def replay_arm(p, s, args, state, arm, held, desc, keys, body, body_file,
               body_raw, copied, package, package_raw, share):
    values = {'archive': (Path(package['path']), package_raw),
              'body': (Path(body_file['path']), body_raw)}
    request = p.make_request(body, values, keys)
    req = publish(p, s, args, state, arm + '-request.json', request)
    env = publish(p, s, args, state, arm + '-envelope.json',
        {'schema': 'quorum/external-replay-envelope/1', 'request': copy.deepcopy(request),
         'untrusted_receipt': None})
    inv = arm_invocation(p, args, arm, held, desc, keys, body_file, copied, package, share)
    inv.update(request=req, held_request={k: req[k] for k in ('bytes', 'sha256')}, envelope=env)
    row = publish(p, s, args, state, arm + '-invocation.json', inv)
    command = [str(Path(sys.executable).resolve()), '-I', '-S',
        str(args.checker_root / 'install/transport_quorum_bootstrap.py'), row['path'],
        '--expect-invocation-sha256', row['sha256'],
        '--expect-bootstrap-sha256', held['bootstrap_entry']['sha256']]
    publish(p, s, args, state, arm + '-result-command.json',
            {'argv': command, 'execution': 'NOT_RUN'})
    publish(p, s, args, state, arm + '-command.txt', (shlex.join(command) + '\n').encode())
    return row


def replay_inputs(p, s, args, state, held, observed, body, body_raw, body_file, copied, encoded, identity):
    desc, keys, descriptor = descriptor_keys(p, s, args, state, observed)
    rows = [dict(id=row['alias'], **{k: row['key'][k] for k in ('bytes', 'sha256')}) for row in copied]
    rows.append(dict(id='Q_RECORDS', **p.pin(body_raw)))
    index_raw = p.canonical({'schema': 'quorum/original-source-envelope/1',
                            'sources': sorted(rows, key=lambda row: p.canonical(row['id']))})
    index = publish(p, s, args, state, 'original-index.json', index_raw)
    package = dict(path=str(args.out / 'encoded/meaning.zip'), **p.pin(encoded['meaning.zip']))
    share = dict(path=str(args.out / 'encoded/share.txt'), identity=identity, **p.pin(encoded['share.txt']))
    result = {}
    for arm, item, raw, text in (('original', index, index_raw, None),
                                  ('transport', package, encoded['meaning.zip'], share)):
        result[arm] = replay_arm(p, s, args, state, arm, held, desc, keys, body,
            body_file, body_raw, copied, item, raw, text)
    return result, descriptor


def finish(p, s, args, state, held, observed, inputs, helper_inputs, desc, invocations, identity):
    need(roots(p, args, held) == observed, 'SENDER_HOST_CHANGED')
    p.snapshot_check(args, observed['bundle_snapshot'])
    for path, raw in inputs + helper_inputs:
        need(p.read(path, CAP) == raw, 'SENDER_HOST_CHANGED')
    need(p.descriptor(args, observed) == desc, 'SENDER_HOST_CHANGED')
    for name, raw in state['files'].items():
        need(p.read(args.out / name, FILE_CAP) == raw, 'SENDER_HOST_CHANGED')
    need(not (args.out / 'ABSENT_EVALUATOR_SIDECARS').exists(), 'SENDER_HOST_CHANGED')
    receipt = {'schema': 'quorum/sender-preparation-receipt/1', 'status': 'PREPARED_NOT_EXECUTED',
        'identity': identity, 'invocations': invocations, 'held_identities': copy.deepcopy(held),
        'host_observations': 'UNCHANGED_EXACT_PINS', 'qualification': 'NOT_EVALUATED',
        'acceptance': 'NOT_EVALUATED', 'semantic_completeness': 'UNPROVEN',
        'current_authority': 'NONE', 'source_authentication': 'UNVERIFIED',
        'carrier_profile': 'EXISTING_EXACT_BYTES_WITH_HISTORICAL_FIXTURE_LABELS',
        'carrier_limitations': 'Historical Exact fixture metadata is required by this carrier version; it is not independent verification. Body preserves caller declarations. No arbitrary pre-existing ZIP import.',
        'files': [dict(path=name, **p.pin(raw)) for name, raw in sorted(state['files'].items())]}
    return publish(p, s, args, state, 'preparation-receipt.json', receipt)


def arguments(p, s):
    s._argv_bound(sys.argv)
    parser = Parser(description=__doc__)
    for name in ('checker-root', 'decoder-root', 'decoder-source-root', 'held-identities',
                 'snapshot-file', 'sender-input', 'out'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--budget', default='512')
    parser.add_argument('--reference', default='attached:meaning.zip')
    args = parser.parse_args()
    for name in ('checker_root', 'decoder_root', 'decoder_source_root', 'held_identities',
                 'snapshot_file', 'sender_input', 'out'):
        setattr(args, name, p.absolute(getattr(args, name)))
    args.budget = s._budget(args.budget)
    raw = args.reference.encode('ascii', errors='strict')
    need(raw == b'attached:meaning.zip' or s.REFERENCE.fullmatch(raw) is not None, 'SENDER_INPUT_FIELDS')
    return args


def main(p, s, helper_inputs):
    args = arguments(p, s)
    held_raw = p.read(args.held_identities, CAP)
    held = p.document(held_raw)
    closed(held, ('schema',) + HELD, 'SENDER_INPUT_FIELDS')
    need(held['schema'] == 'quorum/sender-held-identities/1', 'SENDER_SCHEMA')
    observed = roots(p, args, held)
    need(p.pin(observed['encoder_launcher'])['sha256'] == s.ENCODER_SHA256, 'SENDER_PIN')
    p.snapshot_check(args, observed['bundle_snapshot'])
    body, body_raw, sources, inputs = sender_inputs(p, observed['sender_input'])
    inputs.append((args.held_identities, held_raw))
    new_directory(s, args.out)
    state = {'total': 0, 'files': {}}
    body_file, copied, plan_file = copy_sources(p, s, args, state, body_raw, sources)
    encoded, identity = encode(p, s, args, state, body_file, copied, plan_file)
    invocations, desc = replay_inputs(p, s, args, state, held, observed, body,
        body_raw, body_file, copied, encoded, identity)
    return finish(p, s, args, state, held, observed, inputs, helper_inputs, desc, invocations, identity)


def entry():
    p = s = None
    try:
        p, s, observed = helpers()
        result = main(p, s, observed)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except (SenderError, ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        reason = str(error) if isinstance(error, SenderError) else 'SENDER_BODY'
        if p is not None and isinstance(error, p.PreparationError):
            reason = str(error)
        elif s is not None and isinstance(error, s.PublicShareError):
            reason = str(error)
        elif isinstance(error, (UnicodeError, json.JSONDecodeError, RecursionError)):
            reason = 'PUBLIC_JSON'
        elif isinstance(error, OSError):
            reason = 'PUBLIC_FILE'
        print(json.dumps({'status': 'REFUSED_SENDER_PREPARATION', 'reason': reason}))
        return 2


if __name__ == '__main__':
    raise SystemExit(entry())
