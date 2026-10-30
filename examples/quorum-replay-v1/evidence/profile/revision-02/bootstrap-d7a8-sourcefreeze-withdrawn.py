"""Fixed-host QUORUM CLI; external entry verification precedes execution.

Self checks are defense, not authentication. No receipt or boolean supplied by a
caller grants host qualification. Stdlib, OS and hash implementation remain trust
assumptions. Public invocation always performs actual bounded qualification.
"""

import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
CAP = 65536
FILE_CAP = 4194304
MODULE_CAP = 512
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,31}$')
CHECKER_NAMES = tuple('tools/transport_quorum_' + n + '.py' for n in
                      ('input', 'shape', 'source', 'claim', 'graph', 'impact',
                       'context', 'reading', 'replay')) + (
    'tools/transport_quorum_body.schema.json',
    'tools/transport_quorum_protocol-rules.json',
    'install/transport_quorum_bootstrap.py')
HELPER_NAMES = tuple('install/' + n for n in (
    'transport_handoff_inputs.py', 'transport_install_layout.py',
    'transport_install_support.py', 'test_portable_handoff.py'))
ROSTER = tuple('checker/' + n for n in CHECKER_NAMES) + tuple(
    'handoff/' + n for n in HELPER_NAMES)
LEGACY = {
    'transport_schema': '1c324b661314bd3a92f23b4502207f38a483baa6565d479838de450f110eeb1a',
    'transport_wire': '2a0fa77da78ae4591fc296f6ce4f62e961c68ed992479ffe59974e236b0f58c4',
    'transport_operators': 'b638b57693d26238ec2c461b810ad665008a8b59886ed0be53f0dbc71809f417'}


class HostError(ValueError):
    """Named closed outer-host refusal; never fullReplay acceptance."""


def _need(condition, reason):
    if not condition:
        raise HostError(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _fields(value, names, reason='CHECKER_DESCRIPTOR_RAW'):
    _need(type(value) is dict and len(value) == len(names), reason)
    _need(all(name in value for name in names), reason)


def _uint(value, cap, reason='CHECKER_DESCRIPTOR_RAW'):
    _need(type(value) is int and 0 <= value <= cap, reason)


def _digest(value, reason='CHECKER_DESCRIPTOR_RAW'):
    _need(type(value) is str and len(value) == 64
          and DIGEST.fullmatch(value) is not None, reason)


def _path(value):
    _need(type(value) is str and 0 < len(value) <= 4096,
          'CHECKER_DESCRIPTOR_RAW')
    _need(value.startswith('/') and os.path.normpath(value) == value
          and '..' not in value.split('/') and '\x00' not in value,
          'CHECKER_DESCRIPTOR_RAW')
    _need(len(value.encode('utf-8')) <= 4096 and len(Path(value).parts) <= 65,
          'CHECKER_DESCRIPTOR_RAW')
    return Path(value)


def _read_inner(value, cap):
    path = _path(str(value))
    parts = path.parts[1:]
    _need(bool(parts), 'CHECKER_FILE_IDENTITY')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/', flags | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, flags | os.O_DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = nxt
        nxt = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    try:
        start = os.fstat(nxt)
        _need(stat.S_ISREG(start.st_mode) and start.st_size <= cap,
              'CHECKER_FILE_IDENTITY')
        raw = bytearray()
        for unused in range(cap // 16384 + 2):
            block = os.read(nxt, min(16384, cap + 1 - len(raw)))
            if not block:
                end = os.fstat(nxt)
                _need((start.st_dev, start.st_ino, start.st_size,
                       start.st_mtime_ns, start.st_ctime_ns) ==
                      (end.st_dev, end.st_ino, end.st_size,
                       end.st_mtime_ns, end.st_ctime_ns)
                      and len(raw) == end.st_size, 'CHECKER_FILE_IDENTITY')
                return bytes(raw)
            raw.extend(block)
            _need(len(raw) <= cap, 'CHECKER_FILE_IDENTITY')
        raise HostError('CHECKER_FILE_IDENTITY')
    finally:
        os.close(nxt)



def _read(value, cap):
    try:
        return _read_inner(value, cap)
    except OSError as error:
        raise HostError('CHECKER_FILE_IDENTITY') from error


def _checked(path, cap, pin, reason):
    try:
        return _matches(_read(path, cap), pin, reason)
    except (HostError, OSError) as error:
        raise HostError(reason) from error


def _pin_shape(value, cap=FILE_CAP):
    _fields(value, ('bytes', 'sha256'))
    _uint(value['bytes'], cap)
    _digest(value['sha256'])


def _key(value):
    _fields(value, ('logical_source_id', 'bytes', 'sha256'))
    name = value['logical_source_id']
    _need(type(name) is str and 0 < len(name) <= 32 and name.isascii()
          and ID.search(name) is not None, 'CHECKER_DESCRIPTOR_RAW')
    _uint(value['bytes'], CAP)
    _digest(value['sha256'])


def _file(value, cap=131072):
    _fields(value, ('path', 'bytes', 'sha256'))
    _path(value['path'])
    _uint(value['bytes'], cap)
    _digest(value['sha256'])


def _record(raw):
    return dict(bytes=len(raw), sha256=_sha(raw))


def _matches(raw, pin, reason):
    _need(len(raw) == pin['bytes'] and _sha(raw) == pin['sha256'], reason)
    return raw


def _bounded_depth(text):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            _need(depth <= 12, 'CHECKER_DESCRIPTOR_RAW')
        elif char in ']}':
            depth -= 1
            _need(depth >= 0, 'CHECKER_DESCRIPTOR_RAW')
    _need(depth == 0 and not quoted, 'CHECKER_DESCRIPTOR_RAW')


def _integer(token):
    _need(len(token) <= 20 and token.isascii() and token.isdecimal()
          and (token == '0' or token[0] != '0'), 'CHECKER_DESCRIPTOR_RAW')
    return int(token)


def _pairs(pairs):
    _need(len(pairs) <= 128, 'CHECKER_DESCRIPTOR_RAW')
    result = {}
    for key, value in pairs:
        _need(key not in result, 'CHECKER_DESCRIPTOR_RAW')
        result[key] = value
    return result


def _no_number(value):
    raise HostError('CHECKER_DESCRIPTOR_RAW')


def _parse(raw):
    _need(type(raw) is bytes and len(raw) <= CAP, 'CHECKER_DESCRIPTOR_RAW')
    text = raw.decode('utf-8', errors='strict')
    _bounded_depth(text)
    value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                       parse_float=_no_number, parse_constant=_no_number)
    _need(_canonical(value) == raw, 'CHECKER_DESCRIPTOR_RAW')
    return value


def _source_shape(value, auxiliary=False):
    names = ('alias', 'key', 'path', 'held_key') if auxiliary else (
        'alias', 'key', 'path')
    _fields(value, names)
    alias = value['alias']
    _need(type(alias) is str and 0 < len(alias) <= 32
          and alias.isascii() and ID.search(alias) is not None,
          'CHECKER_DESCRIPTOR_RAW')
    _key(value['key'])
    _path(value['path'])
    if auxiliary:
        _key(value['held_key'])


def _invocation(value):
    names = ('schema', 'arm', 'bootstrap_entry', 'checker_descriptor',
             'decoder_install_descriptor', 'runtime_descriptor',
             'source_manifest_pin', 'bundle_snapshot_pin', 'wire_schema',
             'protocol_rules', 'request', 'envelope', 'body', 'package',
             'originals', 'share', 'auxiliary', 'held_request')
    _fields(value, names)
    _need(value['schema'] == 'quorum/bootstrap-invocation/1'
          and value['arm'] in ('original', 'transport'), 'CHECKER_DESCRIPTOR_RAW')
    for name in ('bootstrap_entry', 'source_manifest_pin', 'bundle_snapshot_pin'):
        _pin_shape(value[name])
    _pin_shape(value['held_request'], CAP)
    _fields(value['checker_descriptor'], ('path', 'key'))
    _path(value['checker_descriptor']['path'])
    _key(value['checker_descriptor']['key'])
    for name in ('decoder_install_descriptor', 'runtime_descriptor',
                 'wire_schema', 'protocol_rules'):
        _key(value[name])
    for name in ('request', 'envelope', 'body', 'package'):
        _file(value[name])
    rows = value['originals']
    _need(type(rows) is list and len(rows) <= 15, 'CHECKER_DESCRIPTOR_RAW')
    for row in rows:
        _source_shape(row)
    share = value['share']
    _need((share is None) == (value['arm'] == 'original'), 'CHECKER_DESCRIPTOR_RAW')
    if share is not None:
        _fields(share, ('path', 'bytes', 'sha256', 'identity'))
        _file({key: share[key] for key in ('path', 'bytes', 'sha256')})
        _need(type(share['identity']) is str and
              re.fullmatch(r'STS1:[0-9a-f]{64}', share['identity']) is not None,
              'CHECKER_DESCRIPTOR_RAW')
    if value['auxiliary'] is not None:
        _source_shape(value['auxiliary'], True)
    return value


def _descriptor(value):
    _fields(value, ('schema', 'platform', 'checker_root', 'handoff_root',
                    'python', 'files', 'decoder_bundle_root',
                    'decoder_source_root', 'decoder_source_manifest_sha256'))
    _need(value['schema'] == 'quorum/checker-bootstrap/1' and
          value['platform'] == 'LINUX_OMARCHY_ONLY', 'CHECKER_DESCRIPTOR_RAW')
    for name in ('checker_root', 'handoff_root', 'decoder_bundle_root',
                 'decoder_source_root'):
        _path(value[name])
    _file(value['python'], FILE_CAP)
    _digest(value['decoder_source_manifest_sha256'])
    rows = value['files']
    _need(type(rows) is list and len(rows) <= CAP, 'CHECKER_DESCRIPTOR_RAW')
    for row in rows:
        _fields(row, ('path', 'bytes', 'sha256'))
        _uint(row['bytes'], 131072)
        _digest(row['sha256'])
        _need(type(row['path']) is str, 'CHECKER_DESCRIPTOR_RAW')
    return value


def _file_set(desc):
    rows = desc['files']
    _need(len(rows) == 16, 'CHECKER_FILE_SET')
    names = [row['path'] for row in rows]
    _need(all(name in ROSTER for name in names) and len(set(names)) == 16
          and names == sorted(names, key=_canonical), 'CHECKER_FILE_SET')


def _module_budget(preloaded=False):
    _need(len(sys.modules) <= MODULE_CAP, 'MODULE_COUNT_BOUND')
    if preloaded:
        _need(not any(name.startswith('transport_') or name == 'test_portable_handoff'
                      for name in sys.modules),
              'PRELOADED_TRANSPORT_MODULE')


def _checker_files(desc):
    allowed = {}
    for row in desc['files']:
        domain, relative = row['path'].split('/', 1)
        root = desc['checker_root'] if domain == 'checker' else desc['handoff_root']
        path = _path(root) / relative
        raw = _read(path, 131072)
        _matches(raw, row, 'CHECKER_FILE_IDENTITY')
        if path.suffix == '.py':
            _need(path.stem not in allowed, 'CHECKER_FILE_SET')
            allowed[path.stem] = dict(path=str(path), **_record(raw))
    return allowed


def _audit(allowed):
    _module_budget()
    rows = []
    for name, module in tuple(sys.modules.items()):
        if not name.startswith('transport_') and name not in allowed:
            continue
        _need(name in allowed and module is not None, 'IMPORTED_MODULE_ORIGIN')
        expected = allowed[name]
        _need(getattr(module, '__file__', None) == expected['path'],
              'IMPORTED_MODULE_ORIGIN')
        raw = _read(expected['path'], FILE_CAP)
        _matches(raw, expected, 'IMPORTED_MODULE_ORIGIN')
        if name.startswith('transport_'):
            rows.append(dict(name=name, **expected))
    return sorted(rows, key=lambda row: _canonical(row['name']))


def _load(name, allowed):
    _need(name in allowed, 'IMPORTED_MODULE_ORIGIN')
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, allowed[name]['path'])
        _need(spec is not None and spec.loader is not None, 'IMPORTED_MODULE_ORIGIN')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except (ImportError, AttributeError, SyntaxError, ValueError) as error:
            raise HostError('IMPORTED_MODULE_ORIGIN') from error
    _audit(allowed)
    return sys.modules[name]


def _helpers(desc, allowed):
    directory = str(_path(desc['handoff_root']) / 'install')
    sys.path.insert(0, directory)
    for name in ('transport_install_support', 'transport_install_layout',
                 'transport_handoff_inputs', 'test_portable_handoff'):
        _load(name, allowed)
    return (sys.modules['transport_install_layout'],
            sys.modules['transport_handoff_inputs'])


def _bundle(inv, desc, layout, helpers):
    root = _path(desc['decoder_bundle_root'])
    install_raw = _checked(root / 'INSTALL.json', CAP,
                           inv['decoder_install_descriptor'], 'DECODER_INSTALL_IDENTITY')
    declared = dict(path=str(root), install_sha256=inv['decoder_install_descriptor']['sha256'],
                    snapshot_sha256=inv['bundle_snapshot_pin']['sha256'])
    try:
        actual_root, snapshot = helpers.frozen_bundle(dict(bundle=declared), root)
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise HostError('DECODER_INSTALL_IDENTITY') from error
    _matches(_canonical(snapshot), inv['bundle_snapshot_pin'], 'DECODER_INSTALL_IDENTITY')
    _checked(root / 'RUNTIME.json', CAP,
                           inv['runtime_descriptor'], 'DECODER_RUNTIME_IDENTITY')
    source_pin = inv['source_manifest_pin']
    _need(source_pin['sha256'] == desc['decoder_source_manifest_sha256'],
          'DECODER_SOURCE_IDENTITY')
    source_root = _path(desc['decoder_source_root'])
    _checked(source_root / 'install' / 'SOURCE.json', FILE_CAP,
                          source_pin, 'DECODER_SOURCE_IDENTITY')
    try:
        layout.source_inputs(source_root, source_pin['sha256'])
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise HostError('DECODER_SOURCE_IDENTITY') from error
    install = layout.checked_json(install_raw)
    _need(install['source_manifest_sha256'] == source_pin['sha256'],
          'DECODER_SOURCE_IDENTITY')
    return actual_root, snapshot


def _legacy(root, snapshot, allowed):
    for relative, pin in snapshot['files'].items():
        if relative.startswith('tools/') and relative.endswith('.py'):
            path = root / relative
            name = path.stem
            _need(name not in allowed, 'IMPORTED_MODULE_ORIGIN')
            allowed[name] = dict(path=str(path), bytes=pin['bytes'], sha256=pin['sha256'])
    for name, expected in LEGACY.items():
        _need(name in allowed and allowed[name]['sha256'] == expected,
              'LEGACY_QUALIFIED_BYTES')
    sys.path.insert(0, str(root / 'tools'))



def _runtime(inv, desc, allowed):
    module = _load('transport_package', allowed)
    try:
        actual = _canonical(module.runtime_contract())
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
        raise HostError('DECODER_RUNTIME_IDENTITY') from error
    expected = _checked(_path(desc['decoder_bundle_root']) / 'RUNTIME.json', CAP,
                        inv['runtime_descriptor'], 'DECODER_RUNTIME_IDENTITY')
    _need(actual == expected, 'DECODER_RUNTIME_IDENTITY')
    _audit(allowed)


def _qualified(inv, desc, entry, allowed):
    _checked(desc['python']['path'], FILE_CAP, desc['python'], 'PYTHON_IDENTITY')
    _need(str(Path(sys.executable).resolve()) == desc['python']['path'], 'PYTHON_IDENTITY')
    return dict(schema='quorum/bootstrap-qualified/1', status='QUALIFIED_FIXED_HOST',
                bootstrap_entry=_record(entry), checker_descriptor=inv['checker_descriptor']['key'],
                python=desc['python'], decoder_install_descriptor=inv['decoder_install_descriptor'],
                runtime_descriptor=inv['runtime_descriptor'], source_manifest=inv['source_manifest_pin'],
                modules=_audit(allowed))


def _carrier(value, cap):
    return _matches(_read(value['path'], cap), value, 'CHECKER_FILE_IDENTITY')


def _originals(inv, body):
    rows = inv['originals']
    auxiliary = inv['auxiliary']
    # Carrier slots are fixed; aggregate admission belongs after pure PREPARSE.
    result = []
    for row in rows:
        raw = _matches(_read(row['path'], CAP), row['key'], 'CHECKER_FILE_IDENTITY')
        result.append((row['alias'], dict(row['key']), raw))
    aux = None
    if auxiliary is not None:
        raw = _matches(_read(auxiliary['path'], CAP), auxiliary['key'], 'CHECKER_FILE_IDENTITY')
        aux = (auxiliary['alias'], dict(auxiliary['key']), raw, dict(auxiliary['held_key']))
    return tuple(result), aux


def _original_index(package, body, originals):
    value = _parse(package)
    _fields(value, ('schema', 'sources'))
    _need(value['schema'] == 'quorum/original-source-envelope/1', 'CHECKER_DESCRIPTOR_RAW')
    expected = [dict(id=alias, **_record(raw)) for alias, key, raw in originals]
    expected.append(dict(id='Q_RECORDS', **_record(body)))
    expected.sort(key=lambda row: _canonical(row['id']))
    _need(value['sources'] == expected, 'CHECKER_FILE_IDENTITY')


def _transport(inv, package, body, originals, allowed):
    share = _carrier(inv['share'], 131072)
    module = _load('transport_mcp', allowed)
    try:
        receiver = module.Receiver(share, package, inv['share']['identity'])
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
        raise HostError('CHECKER_FILE_IDENTITY') from error
    _audit(allowed)
    expected = {alias: raw for alias, key, raw in originals}
    _need(len(expected) == len(originals) and 'Q_RECORDS' not in expected,
          'CHECKER_FILE_IDENTITY')
    expected['Q_RECORDS'] = body
    actual = receiver.decoded['sources']
    _need(type(actual) is list and len(actual) == len(expected), 'CHECKER_FILE_IDENTITY')
    _need([item['id'] for item in actual] == sorted(expected, key=_canonical),
          'CHECKER_FILE_IDENTITY')
    _need(receiver.decoded['schema'] == 'transport/decoded/1', 'CHECKER_FILE_IDENTITY')
    for field in ('interpretations', 'uncertainties', 'relations'):
        _need(receiver.decoded[field] == [], 'CHECKER_FILE_IDENTITY')
    for row in actual:
        _need(row['label'] == 'Exact fixture ' + row['id']
              and row['media_type'] == 'application/octet-stream'
              and row['provenance'] == 'Manually supplied frozen original bytes; no semantic qualification.',
              'CHECKER_FILE_IDENTITY')
        raw = expected[row['id']]
        _need(row['bytes'] == len(raw) and row['sha256'] == _sha(raw),
              'CHECKER_FILE_IDENTITY')
    recovered = {row['id']: row['data'] for row in actual}
    _need(recovered == expected, 'CHECKER_FILE_IDENTITY')


def _arguments(argv):
    _need(len(argv) == 6 and argv[2] == '--expect-invocation-sha256'
          and argv[4] == '--expect-bootstrap-sha256', 'CHECKER_DESCRIPTOR_RAW')
    _digest(argv[3])
    _digest(argv[5])
    return _path(argv[1]), argv[3], argv[5]


def _entry_and_invocation(argv):
    path, expected_invocation, expected_entry = _arguments(argv)
    entry = _read(str(Path(__file__).absolute()), 131072)
    _need(_sha(entry) == expected_entry, 'BOOTSTRAP_ENTRY_PIN')
    _module_budget(preloaded=True)
    raw = _read(path, CAP)
    value = _invocation(_parse(raw))
    _need(_sha(raw) == expected_invocation, 'CHECKER_DESCRIPTOR_PIN')
    _matches(entry, value['bootstrap_entry'], 'BOOTSTRAP_ENTRY_PIN')
    return entry, value


def _host(inv, entry):
    item = inv['checker_descriptor']
    raw = _read(item['path'], CAP)
    desc = _descriptor(_parse(raw))
    _matches(raw, item['key'], 'CHECKER_DESCRIPTOR_PIN')
    _checked(desc['python']['path'], FILE_CAP, desc['python'], 'PYTHON_IDENTITY')
    _need(str(Path(sys.executable).resolve()) == desc['python']['path'], 'PYTHON_IDENTITY')
    _file_set(desc)
    allowed = _checker_files(desc)
    _need(allowed['transport_quorum_bootstrap']['path'] == str(Path(__file__).absolute())
          and allowed['transport_quorum_bootstrap']['sha256'] == _sha(entry),
          'BOOTSTRAP_ENTRY_PIN')
    layout, helpers = _helpers(desc, allowed)
    root, snapshot = _bundle(inv, desc, layout, helpers)
    _legacy(root, snapshot, allowed)
    _runtime(inv, desc, allowed)
    return desc, allowed


def _run(inv, entry, desc, allowed):
    request = _carrier(inv['request'], 131072)
    envelope = _carrier(inv['envelope'], 131072)
    body = _carrier(inv['body'], 131072)
    package = _carrier(inv['package'], 131072)
    originals, auxiliary = _originals(inv, body)
    if inv['arm'] == 'transport':
        _transport(inv, package, body, originals, allowed)
    else:
        _original_index(package, body, originals)
    for name in LEGACY:
        _load(name, allowed)
    sys.path.insert(0, str(_path(desc['checker_root']) / 'tools'))
    checker = _load('transport_quorum_replay', allowed)
    for field, filename in (('wire_schema', 'transport_quorum_body.schema.json'),
                            ('protocol_rules', 'transport_quorum_protocol-rules.json')):
        _matches(_read(_path(desc['checker_root']) / 'tools' / filename, CAP),
                 inv[field], 'CHECKER_FILE_IDENTITY')
    receipt = _qualified(inv, desc, entry, allowed)
    receipt_raw = _canonical(receipt) + b'\n'
    _need(len(receipt_raw) <= CAP, 'CHECKER_FILE_IDENTITY')
    keys = dict(wire_schema=dict(inv['wire_schema']), protocol_rules=dict(inv['protocol_rules']),
                checker=dict(supported_platform='LINUX_OMARCHY_ONLY',
                             checker_descriptor=dict(inv['checker_descriptor']['key']),
                             runtime_descriptor=dict(inv['runtime_descriptor']),
                             decoder_install_descriptor=dict(inv['decoder_install_descriptor'])))
    answer = checker._replay(request, envelope, body, originals, package,
                             dict(inv['held_request']), keys, auxiliary)
    _need(_audit(allowed) == receipt['modules'], 'IMPORTED_MODULE_ORIGIN')
    return receipt_raw, answer



def _output_refusal(result):
    request = result.get('request', result.get('input_request'))
    _fields(request, ('id', 'bytes', 'sha256'), 'CHECKER_FILE_IDENTITY')
    _need(request['id'] == 'REPLAY_REQUEST', 'CHECKER_FILE_IDENTITY')
    _uint(request['bytes'], CAP, 'CHECKER_FILE_IDENTITY')
    _digest(request['sha256'], 'CHECKER_FILE_IDENTITY')
    return dict(schema='quorum/replay-refusal/1', accepted_result=False,
                replay='REFUSED_COMPLETE_OUTPUT_BOUND', input_request=request,
                failed_stage='OUTPUT_BOUND',
                reasons=[dict(code='OUTPUT_BYTE_BOUND', detail='', record_ids=[])],
                missing_target_keys=[], missing_predecessor_ids=[],
                dimension_status='NOT_EVALUATED', diagnostic_result=None,
                diagnostic_result_accepted=False, previous_receipt=None,
                authority='NONE', freshness='UNKNOWN')


def _write(stream, raw):
    _need(stream.write(raw) == len(raw), 'CHECKER_FILE_IDENTITY')
    stream.flush()


def main(argv=None):
    try:
        entry, invocation = _entry_and_invocation(sys.argv if argv is None else argv)
        desc, allowed = _host(invocation, entry)
        receipt, result = _run(invocation, entry, desc, allowed)
        raw = _canonical(result) + b'\n'
        if len(raw) > 131072 or len(raw) + len(receipt) > 131072:
            result = _output_refusal(result)
            raw = _canonical(result) + b'\n'
        _need(len(raw) + len(receipt) <= 131072, 'CHECKER_FILE_IDENTITY')
        _write(sys.stderr.buffer, receipt)
        _write(sys.stdout.buffer, raw)
        return 0 if result.get('accepted_result') is True else 1
    except HostError as error:
        reason = str(error)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        reason = 'CHECKER_DESCRIPTOR_RAW'
    refusal = dict(schema='quorum/bootstrap-refusal/1', status='REFUSED_HOST_PRECONDITION',
                   authority='NONE', reason=reason)
    _write(sys.stdout.buffer, _canonical(refusal) + b'\n')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
