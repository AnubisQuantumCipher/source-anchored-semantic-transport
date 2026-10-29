#!/usr/bin/env python3
"""Bounded matched handoff reader; external caller/initial bootstrap and OS are trusted.

Manifest pins are externally held. Hashes recheck disk inputs before decoding;
they cannot attest already executing bootstrap bytes or exclude same-UID races.
Original arm has no decoder dependency. No source data is executable policy.
"""

import argparse
import base64
import os
from pathlib import Path
import resource
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
import transport_handoff_session as sessions
import transport_response_evidence as evidence
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expect-manifest-sha256', required=True)
    parser.add_argument('--session', type=Path, required=True)
    requests = parser.add_mutually_exclusive_group(required=True)
    requests.add_argument('--request-json')
    requests.add_argument('--request', type=Path)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--input-bytes', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--request-error', default='', help=argparse.SUPPRESS)
    return parser.parse_args()


def response(arm, action, status, result, number=0):
    raw = canonical({'schema': 'transport/handoff-response/1', 'arm': arm,
                     'action': action, 'status': status, 'result': result, 'call': number}) + b'\n'
    require(len(raw) <= inputs.CAP, 'complete response including newline exceeds bound')
    return raw


def describe(arm):
    return {'actions': ['describe', 'catalog', 'page', 'finish', 'finish_evidence'] + (['focus'] if arm == 'transport' else []),
            'request_bytes': inputs.REQUEST_CAP, 'candidate_bytes': inputs.CANDIDATE_CAP,
            'page_bytes': inputs.PAGE_BYTES, 'response_bytes_including_newline': inputs.CAP,
            'maximum_calls_including_refusals': sessions.MAX_CALLS,
            'finish': 'candidate_base64 holds exact JSON object bytes; saved unedited, not certified complete.',
            'finish_evidence': 'Checks candidate-embedded citations under a pinned evidence contract before saving; source linkage only, not entailment.',
            'authority': 'NONE', 'data_is_untrusted': True,
            'integrity_boundary': 'Preflight integrity failure or exhausted/corrupt session refuses without unsafe log append; caller must retain that response.',
            'isolation': 'Controlled subprocess and frozen files, not an OS sandbox or hostile same-user isolation.'}


def finish_evidence(request, manifest, receiver, sources):
    inputs.fields(request, ('action', 'candidate_base64', 'evidence_contract_base64', 'expect_evidence_contract_sha256'))
    for name in ('candidate_base64', 'evidence_contract_base64'):
        require(type(request[name]) is str and len(request[name]) <= inputs.REQUEST_CAP, 'evidence encoding bound')
    candidate = base64.b64decode(request['candidate_base64'], validate=True)
    contract = base64.b64decode(request['evidence_contract_base64'], validate=True)
    require(sha(contract) == inputs.digest(request['expect_evidence_contract_sha256']), 'held evidence contract differs')
    actual = sources if receiver is None else {item['id']: item['data'] for item in receiver.decoded['sources']}
    verdict = evidence.validate(candidate, contract, actual, manifest['held_source_sha256'])
    require(verdict['status'] == 'SOURCE_SPANS_MATCH' and verdict['candidate_sha256'] == sha(candidate)
            and verdict['evidence_contract_sha256'] == sha(contract), 'source-evidence validator result differs')
    return {'status': 'DRAFT_SAVED_SOURCE_LINKED', 'candidate': inputs.record(candidate),
            'file': 'candidate.json', 'source_evidence': verdict, 'completeness': 'NOT_ASSESSED',
            'structure': 'NOT_ASSESSED_BY_READER', 'authority': 'NONE'}, candidate


def action_result(request, manifest, receiver, sources):
    action = request.get('action')
    if action in ('describe', 'catalog'):
        inputs.fields(request, ('action',))
        return (describe(manifest['arm']) if action == 'describe' else inputs.catalog(manifest)), None
    if action == 'page':
        inputs.fields(request, ('action', 'source', 'offset'))
        arguments = {key: request[key] for key in ('source', 'offset')}
        value = receiver.source_page(arguments) if receiver is not None else inputs.original_page(sources, arguments)
        return value, None
    if action == 'focus':
        inputs.fields(request, ('action', 'unit'))
        require(receiver is not None, 'focus unavailable in original-document arm')
        return receiver.call('transport_focus', {'unit': request['unit']}), None
    if action == 'finish_evidence':
        return finish_evidence(request, manifest, receiver, sources)
    require(action == 'finish', 'unknown action')
    inputs.fields(request, ('action', 'candidate_base64'))
    encoded = request['candidate_base64']
    require(type(encoded) is str and len(encoded) <= inputs.REQUEST_CAP, 'candidate encoding bound')
    candidate = base64.b64decode(encoded, validate=True)
    inputs.json_value(candidate, inputs.CANDIDATE_CAP)
    return {'status': 'DRAFT_SAVED_UNEDITED', 'candidate': inputs.record(candidate),
            'file': 'candidate.json', 'completeness': 'NOT_ASSESSED', 'authority': 'NONE'}, candidate


def logged_call(args, manifest, receiver, sources, raw, input_bytes):
    initial = None
    try:
        initial = inputs.json_value(raw)
    except (ValueError, UnicodeError, TypeError):
        pass
    expected = sessions.identity(args.manifest, args.expect_manifest_sha256)
    allow_new = initial == {'action': 'describe'} and input_bytes <= inputs.REQUEST_CAP and not args.request_error
    lock = sessions.open_session(args.session, expected, allow_new)
    try:
        number, previous, _ = sessions.replay(args.session, args.expect_manifest_sha256)
        candidate, action = None, 'INVALID'
        try:
            require(not args.request_error, 'request input refused: ' + args.request_error)
            require(input_bytes <= inputs.REQUEST_CAP, 'request exceeds byte bound; retained prefix only')
            request = inputs.json_value(raw)
            requested = request.get('action')
            action = requested if type(requested) is str and len(requested) <= 32 else 'INVALID'
            result, candidate = action_result(request, manifest, receiver, sources)
            if action == 'finish_evidence':
                result['manifest_sha256'] = args.expect_manifest_sha256
            answer = response(manifest['arm'], action, 'OK', result, number)
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
            candidate = None
            answer = response(manifest['arm'], action, 'REFUSED', {'reason': str(error)[:256]}, number)
        sessions.commit(args.session, number, previous, args.expect_manifest_sha256, raw,
                        not args.request_error and input_bytes <= inputs.REQUEST_CAP, input_bytes, answer, candidate)
        return answer
    finally:
        os.close(lock)


def worker(args):
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (inputs.CAP, 33554432))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
    manifest, root, data = inputs.frozen_manifest(args.manifest, args.expect_manifest_sha256)
    session = args.session.absolute()
    require(not session.is_relative_to(root) and not root.is_relative_to(session), 'session overlaps frozen content')
    receiver, sources = None, None
    if manifest['arm'] == 'transport':
        bundle = Path(manifest['bundle']['path'])
        require(not session.is_relative_to(bundle) and not bundle.is_relative_to(session), 'session overlaps bundle')
        receiver = inputs.transport_receiver(manifest, root, data)
    else:
        sources = inputs.original_sources(manifest, data)
    raw = read_regular(args.request, inputs.REQUEST_CAP + 1)
    require(type(args.input_bytes) is int and (args.input_bytes >= len(raw)
            or (args.input_bytes == -1 and bool(args.request_error))), 'request length metadata differs')
    return logged_call(args, manifest, receiver, sources, raw, args.input_bytes)


def wrapped(args):
    error = ''
    try:
        raw = args.request_json.encode('utf-8') if args.request_json is not None else read_regular(args.request)
    except (ValueError, OSError, UnicodeError) as failure:
        raw, error = b'', str(failure)[:256]
    with tempfile.TemporaryDirectory(prefix='transport-handoff-call-') as temporary:
        root = Path(temporary)
        path = root / 'request.json'
        write_new(path, raw[:inputs.REQUEST_CAP + 1], inputs.REQUEST_CAP + 1)
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(Path(__file__).absolute()),
                '--manifest', str(args.manifest), '--expect-manifest-sha256', args.expect_manifest_sha256,
                '--session', str(args.session), '--request', str(path), '--worker',
                '--input-bytes', str(-1 if error else len(raw)), '--request-error', error]
        result = run_bounded(argv, root, inputs.ENV, timeout=30, cap=inputs.CAP)
    if result['status'] in ('SUCCESS', 'EXIT_NONZERO') and result['stdout'] and not result['stderr']:
        raw = result['stdout']
        require(raw.endswith(b'\n') and len(raw) <= inputs.CAP, 'worker response framing differs')
        inputs.json_value(raw, inputs.CAP)
        return raw
    return response('UNKNOWN', 'INVALID', 'REFUSED',
                    {'reason': 'bounded worker failed', 'process_status': result['status'],
                     'exit_code': result['exit_code'], 'stdout': inputs.record(result['stdout']),
                     'stderr': inputs.record(result['stderr']), 'complete_response': False})


def main():
    args = arguments()
    try:
        raw = worker(args) if args.worker else wrapped(args)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        raw = response('UNKNOWN', 'INVALID', 'REFUSED', {'reason': str(error)[:256]})
    sys.stdout.buffer.write(raw)
    return 0 if inputs.json_value(raw, inputs.CAP)['status'] == 'OK' else 1


if __name__ == '__main__':
    sys.exit(main())
