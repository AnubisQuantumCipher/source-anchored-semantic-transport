#!/usr/bin/env python3
"""Bounded local adapter for host-registered SENTINEL workflow inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_v1.common import SentinelError

MAX_INPUT = 8192
MAX_OUTPUT = 1048576
FIELDS = {
    'prepare': ('run_id', 'input_id', 'input_sha256'),
    'inspect': ('run_id', 'expected_sha256'),
    'advance': ('run_id', 'expected_sha256', 'submission_id', 'submission_sha256'),
    'receive': ('input_id', 'input_sha256'),
}
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
ENCODED_SOURCE = 'sast/encoded-source-unsigned/1'
ENCODER_ARGUMENTS = ('source', 'out', 'title', 'native', 'native_sha256')


class AdapterError(ValueError):
    """Stable public error code, never a source exception or private path."""


class SessionBoundExceeded(BaseException):
    """Terminate the session; ordinary request-error handlers must not swallow it."""


class ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise AdapterError('INVALID_COMMAND')


def refusal(reason):
    return {'status': 'REFUSED', 'reason': reason, 'qualification': 'NOT_QUALIFIED',
            'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
            'execution_authority': 'NONE'}


def checked_arguments(operation, arguments):
    if operation not in FIELDS or type(arguments) is not dict:
        raise AdapterError('INVALID_REQUEST')
    if set(arguments) != set(FIELDS[operation]):
        raise AdapterError('INVALID_REQUEST')
    for key in FIELDS[operation]:
        value = arguments[key]
        if type(value) is not str or not 1 <= len(value) <= 256:
            raise AdapterError('INVALID_REQUEST')
        if len(value.encode('utf-8')) > 256 or '\x00' in value:
            raise AdapterError('INVALID_REQUEST')
        if key.endswith('sha256') and DIGEST.fullmatch(value) is None:
            raise AdapterError('INVALID_REQUEST')
    return dict(arguments)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError('INVALID_REQUEST')
        result[key] = value
    return result


def preserve_source_call(stream):
    """Read one source and refuse signing. The workflow root is not opened."""
    from transport_workflow_capture import read_source, source_package_gate
    try:
        source = read_source(stream)
    except SentinelError as error:
        value = intake_refusal(error)
        value['signed_export'] = 'NOT_PERFORMED'
        value['production_key_admission'] = 'ABSENT'
        value['zip_written'] = False
        return value
    return source_package_gate(source)


def intake_refusal(error):
    value = refusal(str(error))
    value['graph_import'] = 'NOT_PERFORMED'
    value['registered'] = False
    value['accepted_graph'] = None
    value['truncated'] = False
    value['cap_raised'] = False
    return value



def manifest_lineage_call(stream):
    """Invoke the shipped lineage check. The workflow root is not opened."""
    from transport_workflow_capture import manifest_lineage_invocation, read_lineage_request
    try:
        return manifest_lineage_invocation(read_lineage_request(stream))
    except SentinelError as error:
        value = refusal(str(error))
        value['lineage'] = 'NOT_PERFORMED'
        value['production_key_admission'] = 'ABSENT'
        value['trust_distribution'] = 'ABSENT'
        value['current_revocation'] = 'NOT_RECHECKED'
        value['signature'] = None
        value['zip_written'] = False
        value['key_generated'] = False
        value['provider_called'] = False
        value['frozen_manifest_redefined'] = False
        return value


def read_arguments(stream, operation, endpoint=None):
    from transport_workflow_capture import read_unsplit
    try:
        raw = read_unsplit(stream).raw
    except SentinelError as error:
        if str(error) != 'host receiver requires the complete generation':
            raise
        raise AdapterError('INVALID_REQUEST') from None
    if len(raw) > MAX_INPUT:
        raise AdapterError('INVALID_REQUEST')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
        if endpoint is not None:
            from transport_workflow_endpoint import FIELDS as extra, checked_arguments as checked
            if operation in extra:
                return checked(operation, value)
        return checked_arguments(operation, value)
    except (ValueError, UnicodeError, RecursionError):
        raise AdapterError('INVALID_REQUEST') from None


def response_bytes(value):
    if type(value) is not dict:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode('ascii')
    if len(raw) + 1 > MAX_OUTPUT:
        raise AdapterError('OUTPUT_BOUND_EXCEEDED')
    return raw


def recorded_failure_view(root, arguments, view):
    """Report a recorded failure instead of offering another capture frame.

    No journal returns the workflow object unchanged. A journal is not imported,
    and the job is not marked complete.
    """
    if type(view) is not dict or view.get('status') != 'WAITING_EXTERNAL_CAPTURE':
        return view
    action = view.get('next_action')
    if type(action) is not dict or type(action.get('job_id')) is not str:
        return view
    from transport_workflow_capture import recorded_terminal
    history = recorded_terminal(root, arguments['run_id'], arguments['expected_sha256'],
                                action['job_id'])
    if history is None:
        return view
    return {'schema': view.get('schema'), 'run_id': arguments['run_id'], 'head': view.get('head'),
        'status': 'RECORDED_FAILURE_NOT_DISPATCHED', 'job_id': action['job_id'],
        'journal_head': history['journal_head'], 'attempt_count': len(history['attempts']),
        'completed_jobs': view.get('completed_jobs'), 'pending_jobs': view.get('pending_jobs'),
        'next_action': None, 'graph_import': 'NOT_PERFORMED',
        'dispatch': 'REFUSED_RECORDED_FAILURE', 'capture_offered': False,
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE'}


def invoke(workflow, operation, arguments, endpoint=None):
    try:
        if endpoint is not None and operation not in FIELDS:
            value = endpoint.call(operation, arguments)
        else:
            checked = checked_arguments(operation, arguments)
            value = workflow.call(operation, checked)
            root = getattr(workflow, 'root', None)
            if operation == 'inspect' and type(root) is type(Path('/')):
                value = recorded_failure_view(root, checked, value)
        response_bytes(value)
        return value
    except AdapterError as error:
        return refusal(str(error))
    except Exception:
        return refusal('WORKFLOW_REQUEST_REFUSED')


def timeout(_signal, _frame):
    raise SessionBoundExceeded()


def limits():
    bounds = ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 45),
              (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_FSIZE, MAX_OUTPUT),
              (resource.RLIMIT_CORE, 0))
    for key, requested in bounds:
        soft, hard = resource.getrlimit(key)
        bound = min([requested] + [item for item in (soft, hard)
                                   if item != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))
    remaining, _interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining <= 0 or remaining > 60:
        signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 60)


def workflow_for(root):
    if type(root) is not type(Path('/')) or not root.is_absolute():
        raise AdapterError('WORKFLOW_STARTUP_REFUSED')
    from sentinel_v1.workflow import Workflow
    from sentinel_v1.workflow_store import root_descriptor
    descriptor = root_descriptor(root)
    os.close(descriptor)
    return Workflow(root)


def encode_source_limits():
    """Document-encoder bounds. The JSON adapter's 1MiB file cap stays off."""
    bounds = ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_FSIZE, 2147483648),
              (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0))
    for key, requested in bounds:
        soft, hard = resource.getrlimit(key)
        bound = min([requested] + [item for item in (soft, hard)
                                    if item != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))


def sha256_file(path, reads, reason):
    hasher = hashlib.sha256()
    size = 0
    try:
        with path.open('rb') as stream:
            for _ in range(reads):
                block = stream.read(65536)
                if block == b'':
                    break
                size += len(block)
                hasher.update(block)
            else:
                if stream.read(1) != b'':
                    raise AdapterError(reason)
    except OSError:
        raise AdapterError(reason) from None
    if size == 0:
        raise AdapterError(reason)
    return hasher.hexdigest()


def encoder_arguments_present(args):
    return any(getattr(args, name) is not None for name in ENCODER_ARGUMENTS)


def unsigned_encode_fields(value, phase, zip_written):
    value['schema'] = ENCODED_SOURCE
    value['phase'] = phase
    value['production_key_admission'] = 'ABSENT'
    value['trust_distribution'] = 'ABSENT'
    value['current_revocation'] = 'NOT_RECHECKED'
    value['signature'] = None
    value['zip_written'] = zip_written
    value['key_generated'] = False
    value['provider_called'] = False
    value['signed_export'] = 'NOT_PERFORMED'
    value['qualification'] = 'NOT_QUALIFIED'
    value['semantic_completeness'] = 'UNPROVEN'
    value['context_adequacy'] = 'UNPROVEN'
    value['execution_authority'] = 'NONE'
    return value


def encoder_output_present(path):
    if not isinstance(path, Path):
        return False
    candidate = path / 'meaning.zip'
    try:
        return candidate.is_file() and not candidate.is_symlink()
    except OSError:
        return False


def encoder_refusal(reason, phase, stderr=b'', zip_written=False):
    value = unsigned_encode_fields(refusal(reason), phase, zip_written)
    text = stderr.decode('utf-8', 'replace').splitlines()
    line = text[0] if text else ''
    if line.startswith('DOCUMENT_REFUSED: ') and len(line) <= 532 and '\n' not in line:
        value['document_reason'] = line
    return value


def share_formula(path, title):
    from transport_document import formula_for
    try:
        raw = path.read_bytes()
    except OSError:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT') from None
    if len(raw) > 8192 or b'\n' not in raw:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    try:
        found = raw.split(b'\n', 1)[0].decode('utf-8')
    except UnicodeError:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT') from None
    if found != formula_for(title, ()):
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    return found


def checked_encoder_payload(payload):
    if type(payload) is not dict or payload.get('status') != 'CHECKED':
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    if payload.get('encoder_source_comparison') != 'BYTE_FOR_BYTE_CHECKED':
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    if payload.get('authentication') != 'UNAUTHENTICATED':
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    if payload.get('exact_recovery') != 'WHOLE_FILE_SHA256_AND_FRAME_HASHES_CHECKED':
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    source = payload.get('source')
    package_id = payload.get('package_id')
    if type(source) is not dict or type(package_id) is not str:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    source_bytes = source.get('bytes')
    source_sha = source.get('sha256')
    if type(source_bytes) is not int or source_bytes < 0:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    if type(source_sha) is not str or DIGEST.fullmatch(source_sha) is None:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    if DIGEST.fullmatch(package_id) is None:
        raise AdapterError('INVALID_WORKFLOW_OUTPUT')
    return source_bytes, source_sha, package_id


def encode_source_call(args):
    """Encode one host file with the pinned decoder. Do not sign it."""
    if None in (args.source, args.out, args.title, args.native, args.native_sha256):
        raise AdapterError('INVALID_COMMAND')
    if type(args.title) is not str or type(args.native_sha256) is not str:
        raise AdapterError('INVALID_COMMAND')
    if DIGEST.fullmatch(args.native_sha256) is None:
        raise AdapterError('INVALID_COMMAND')
    try:
        native_digest = sha256_file(args.native, 256, 'NATIVE_PIN_MISMATCH')
    except AdapterError as error:
        if str(error) != 'NATIVE_PIN_MISMATCH':
            raise
        return encoder_refusal('NATIVE_PIN_MISMATCH', 'SOURCE_NOT_ENCODED')
    if native_digest != args.native_sha256:
        return encoder_refusal('NATIVE_PIN_MISMATCH', 'SOURCE_NOT_ENCODED')
    script = Path(__file__).resolve().parent / 'transport_document_cli.py'
    command = [sys.executable, '-I', '-B', '-Werror', str(script), 'encode',
               str(args.source), '--out', str(args.out), '--title', args.title,
               '--opaque', '--native', str(args.native)]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=450, check=False)
    except subprocess.TimeoutExpired:
        return encoder_refusal('document encoder interrupted', 'INTERRUPTED')
    except OSError:
        return encoder_refusal('INVALID_WORKFLOW_OUTPUT', 'SOURCE_NOT_ENCODED')
    if completed.returncode != 0:
        return encoder_refusal('document encoder refused', 'SOURCE_NOT_ENCODED', completed.stderr)
    try:
        payload = json.loads(completed.stdout.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise AdapterError('INVALID_WORKFLOW_OUTPUT') from None
    source_bytes, source_sha, package_id = checked_encoder_payload(payload)
    value = {'status': 'ENCODED_NOT_SIGNED', 'source_bytes': source_bytes,
             'source_sha256': source_sha, 'package_id': package_id,
             'formula': share_formula(args.out / 'share.txt', args.title),
             'lexicon_sha256': sha256_file(args.out / 'lexicon.md', 16, 'INVALID_WORKFLOW_OUTPUT'),
             'zip_sha256': sha256_file(args.out / 'meaning.zip', 32768, 'INVALID_WORKFLOW_OUTPUT'),
             'share_sha256': sha256_file(args.out / 'share.txt', 16, 'INVALID_WORKFLOW_OUTPUT'),
             'encoder_source_comparison': 'BYTE_FOR_BYTE_CHECKED',
             'exact_recovery': 'WHOLE_FILE_SHA256_AND_FRAME_HASHES_CHECKED',
             'authentication': 'UNAUTHENTICATED', 'native_sha256': args.native_sha256}
    return unsigned_encode_fields(value, 'SOURCE_ENCODED_NOT_SIGNED', True)


def parser():
    result = ClosedArgumentParser(allow_abbrev=False, description=__doc__)
    result.add_argument('--root', type=Path, required=True,
                        help='existing private workflow root; host registration is separate')
    host_arguments(result)
    result.add_argument('operation', choices=tuple(FIELDS) + (
        'receive_verified', 'read_verified', 'preserve_source', 'manifest_lineage',
        'encode_source'))
    return result


def host_arguments(result):
    result.add_argument('--host-admission', type=Path)
    result.add_argument('--host-admission-sha256')
    result.add_argument('--source', type=Path)
    result.add_argument('--out', type=Path)
    result.add_argument('--title')
    result.add_argument('--native', type=Path)
    result.add_argument('--native-sha256', dest='native_sha256')


def endpoint_for(args):
    if args.host_admission is None and args.host_admission_sha256 is None:
        return None
    if args.host_admission is None or args.host_admission_sha256 is None:
        raise AdapterError('WORKFLOW_STARTUP_REFUSED')
    from transport_workflow_endpoint import Endpoint
    return Endpoint(args.root, args.host_admission, args.host_admission_sha256)


def main(argv=None):
    try:
        selected = sys.argv[1:] if argv is None else list(argv)
        args = parser().parse_args(selected)
        if args.operation == 'encode_source':
            encode_source_limits()
        else:
            limits()
        if args.operation != 'encode_source' and encoder_arguments_present(args):
            raise AdapterError('INVALID_COMMAND')
        if args.operation == 'encode_source':
            try:
                value = encode_source_call(args)
            except AdapterError as error:
                value = encoder_refusal(str(error), 'SOURCE_NOT_ENCODED',
                                        zip_written=encoder_output_present(args.out))
            except (OSError, ValueError):
                value = encoder_refusal('INVALID_WORKFLOW_OUTPUT', 'SOURCE_NOT_ENCODED',
                                        zip_written=encoder_output_present(args.out))
        elif args.operation == 'preserve_source':
            value = preserve_source_call(sys.stdin.buffer)
        elif args.operation == 'manifest_lineage':
            value = manifest_lineage_call(sys.stdin.buffer)
        else:
            endpoint = endpoint_for(args)
            try:
                arguments = read_arguments(sys.stdin.buffer, args.operation, endpoint)
            except SentinelError as error:
                value = intake_refusal(error)
            else:
                workflow = workflow_for(args.root)
                value = invoke(workflow, args.operation, arguments, endpoint)
    except AdapterError as error:
        value = refusal(str(error))
    except (Exception, KeyboardInterrupt, SessionBoundExceeded, BaseExceptionGroup):
        value = refusal('WORKFLOW_STARTUP_OR_SESSION_REFUSED')
    try:
        sys.stdout.buffer.write(response_bytes(value) + b'\n')
        sys.stdout.buffer.flush()
        return 2 if value.get('status') == 'REFUSED' else 0
    except (OSError, ValueError, MemoryError):
        return 2


if __name__ == '__main__':
    sys.exit(main())
