"""Finite create-only hash-linked call records; same-user hostile races are not isolated."""

import fcntl
import os
from pathlib import Path

from transport_install_support import canonical, confined, read_regular, require, sha, write_new
from transport_handoff_inputs import CAP, CANDIDATE_CAP, REQUEST_CAP, fields, json_value, record

MAX_CALLS, MAX_FILES, MAX_SESSION = 32, 100, 8388608


def identity(manifest_path, expected):
    return {'schema': 'transport/handoff-session/1', 'manifest_path': str(manifest_path.absolute()),
            'manifest_sha256': expected, 'max_calls': MAX_CALLS, 'max_bytes': MAX_SESSION}


def open_session(path, expected, allow_new):
    confined(path.parent, 'handoff-parent-check')
    if not path.exists():
        require(allow_new, 'new session must begin with describe')
        path.mkdir(mode=0o700)
        write_new(path / 'identity.json', canonical(expected), CAP)
        write_new(path / 'lock', b'', 0)
    descriptor = os.open(path / 'lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(read_regular(path / 'identity.json', CAP) == canonical(expected), 'session identity differs')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def members(path):
    found, size = {}, 0
    for number, item in enumerate(path.iterdir()):
        require(number < MAX_FILES and not item.is_symlink() and item.is_file(), 'unexpected session member')
        raw = read_regular(item, CAP)
        size += len(raw)
        require(size <= MAX_SESSION, 'session byte bound exceeded')
        found[item.name] = raw
    return found


def checked_log(raw, index, previous, expected):
    value = json_value(raw, CAP)
    fields(value, ('schema', 'index', 'previous', 'manifest_sha256', 'action', 'status',
                   'request', 'response', 'candidate', 'request_complete', 'input_bytes'))
    require(canonical(value) == raw and value['schema'] == 'transport/handoff-call/1', 'call record serialization mismatch')
    require(type(value['index']) is int and value['index'] == index
            and value['previous'] == previous and value['manifest_sha256'] == expected, 'call hash chain differs')
    require(value['status'] in ('OK', 'REFUSED') and type(value['request_complete']) is bool, 'call status invalid')
    require(type(value['input_bytes']) is int and (value['input_bytes'] >= 0
            or (value['input_bytes'] == -1 and not value['request_complete'])), 'call request length invalid')
    return value


def replay(path, expected):
    files = members(path)
    require('identity.json' in files and files.get('lock') == b'', 'session bootstrap missing')
    allowed, previous, finished = {'identity.json', 'lock'}, sha(files['identity.json']), False
    count, candidate = 0, None
    for index in range(1, MAX_CALLS + 1):
        name = 'call-%02d.json' % index
        if name not in files:
            break
        require(not finished, 'call after finished candidate')
        item = checked_log(files[name], index, previous, expected)
        for kind, cap in (('request', REQUEST_CAP + 1), ('response', CAP)):
            filename = '%s-%02d.json' % (kind, index)
            require(filename in files and record(files[filename]) == item[kind], 'recorded stream identity mismatch')
            require(len(files[filename]) <= cap, 'recorded stream exceeds bound')
            allowed.add(filename)
        response = files['response-%02d.json' % index]
        require(response.endswith(b'\n') and len(response) <= CAP, 'response final newline bound')
        decoded = json_value(response, CAP)
        require(decoded['call'] == index and decoded['action'] == item['action']
                and decoded['status'] == item['status'], 'response/call metadata differs')
        finished = item['action'] in ('finish', 'finish_evidence') and item['status'] == 'OK'
        require((item['candidate'] is not None) == finished, 'candidate state differs')
        if finished:
            require('candidate.json' in files and len(files['candidate.json']) <= CANDIDATE_CAP
                    and record(files['candidate.json']) == item['candidate'], 'candidate identity differs')
            json_value(files['candidate.json'], CANDIDATE_CAP)
            allowed.add('candidate.json')
            candidate = item['candidate']
        allowed.add(name)
        previous, count = sha(files[name]), index
    require(set(files) == allowed, 'unexpected file, partial call or log gap in session')
    require(count < MAX_CALLS and not finished, 'session call bound exhausted or already finished')
    return count + 1, previous, candidate


def commit(path, number, previous, expected, raw, complete, input_bytes, response, candidate):
    require(len(raw) <= REQUEST_CAP + 1 and len(response) <= CAP and response.endswith(b'\n'), 'call stream bound')
    body = json_value(response, CAP)
    fields(body, ('schema', 'arm', 'action', 'status', 'result', 'call'))
    item = {'schema': 'transport/handoff-call/1', 'index': number, 'previous': previous,
            'manifest_sha256': expected, 'action': body['action'], 'status': body['status'],
            'request': record(raw), 'response': record(response),
            'candidate': None if candidate is None else record(candidate),
            'request_complete': complete, 'input_bytes': input_bytes}
    write_new(path / ('request-%02d.json' % number), raw, REQUEST_CAP + 1)
    write_new(path / ('response-%02d.json' % number), response, CAP)
    if candidate is not None:
        write_new(path / 'candidate.json', candidate, CANDIDATE_CAP)
    write_new(path / ('call-%02d.json' % number), canonical(item), CAP)
