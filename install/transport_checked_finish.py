#!/usr/bin/env python3
"""Optional checked submission interface: structural validation then exact draft custody.

Direct client use remains possible. This is not OS authority enforcement, source
approval, semantic grading or a retrospective rule for any earlier campaign.
"""
import base64
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
import transport_response_contract as validator
import transport_response_contract_model as model
from transport_install_layout import exact_tree
from transport_install_support import canonical, read_regular, require, run_bounded, sha

HERE = Path(__file__).absolute().parent
MAX_TRACKED, MAX_TRACKED_BYTES, PROCESS_CAP = 48, 16777216, 8192


def absolute(value):
    require(type(value) is str and 0 < len(value.encode()) < 4096, 'absolute path byte bound')
    path = Path(value)
    require(path.is_absolute() and str(path) == value and '..' not in path.parts, 'canonical absolute path required')
    return path


def tracked(state, path, cap):
    path = absolute(str(path))
    raw = read_regular(path, cap)
    files = state['files']
    if path in files:
        require(files[path][0] == raw, 'tracked input identity differs')
    else:
        require(len(files) < MAX_TRACKED and sum(len(item[0]) for item in files.values()) + len(raw) <= MAX_TRACKED_BYTES,
                'tracked input resource bound')
        files[path] = (raw, cap)
    return raw


def recheck(state):
    require(len(state['files']) <= MAX_TRACKED, 'tracked input count bound')
    for path, (raw, cap) in state['files'].items():
        require(read_regular(path, cap) == raw, 'checked submission input changed')


def held_file(state, path, expected, cap):
    raw = tracked(state, path, cap)
    require(sha(raw) == inputs.digest(expected), 'externally held input digest differs')
    return raw


def checked_record(state, item, cap=4194304):
    inputs.fields(item, ('path', 'bytes', 'sha256'))
    require(type(item['bytes']) is int and 0 <= item['bytes'] <= cap, 'record byte declaration bound')
    raw = held_file(state, absolute(item['path']), item['sha256'], cap)
    require(len(raw) == item['bytes'], 'record file length differs')
    return raw


def binding(state, args):
    raw = held_file(state, args.binding, args.expect_binding_sha256, 16384)
    value = inputs.json_value(raw, 16384)
    inputs.fields(value, ('schema', 'manifest', 'session', 'reader', 'python', 'client'))
    require(value['schema'] == 'transport/handoff-client/1', 'client binding schema')
    files = {key: checked_record(state, value[key]) for key in ('manifest', 'reader', 'python', 'client')}
    require(absolute(value['python']['path']) == Path(sys.executable).resolve(), 'binding Python differs')
    root = absolute(value['client']['path']).parent
    require(Path(value['client']['path']).name == 'transport_handoff_client.py'
            and absolute(value['reader']['path']) == root / 'transport_handoff_reader.py', 'fixed client/reader origins required')
    require(files['client'] == tracked(state, HERE / 'transport_handoff_client.py', 4194304), 'client differs from trusted local release')
    manifest = inputs.json_value(files['manifest'])
    arm = manifest.get('arm')
    require(arm in ('original', 'transport'), 'binding arm unsupported')
    common = {'schema', 'arm', 'helpers', 'python', 'content', 'sources', 'held_source_sha256'}
    inputs.fields(manifest, common | ({'bundle', 'pair'} if arm == 'transport' else set()))
    require(manifest['schema'] == inputs.SCHEMA and manifest['python'] == value['python'], 'binding/manifest identities differ')
    names = inputs.BOOTSTRAP + (('test_portable_handoff.py',) if arm == 'transport' else ())
    helpers = manifest['helpers']
    require(type(helpers) is list and len(helpers) == len(names), 'fixed helper closure count')
    require({item['path'] for item in helpers} == {str(root / name) for name in names}, 'fixed helper origins differ')
    exact_tree(root, set(names) | {'transport_handoff_client.py'})
    for item in helpers:
        data = checked_record(state, item)
        require(data == tracked(state, HERE / Path(item['path']).name, 4194304), 'helper differs from trusted local release')
    inputs.source_metadata(manifest)
    content_root, content = inputs.frozen_content(manifest)
    for name in content:
        tracked(state, content_root / name, inputs.CAP)
    if arm == 'original':
        inputs.original_sources(manifest, content)
    session = absolute(value['session'])
    require(not session.is_symlink() and (not session.exists() or session.is_dir()), 'receiving session path differs')
    require(not absolute(str(args.contract)).is_relative_to(session) and not absolute(str(args.candidate)).is_relative_to(session),
            'contract/candidate must be outside submission session')
    return value


def captured_stream(raw, complete):
    require(type(raw) is bytes and len(raw) <= PROCESS_CAP and type(complete) is bool, 'captured stream bound/type')
    return dict(**inputs.record(raw), base64=base64.b64encode(raw).decode('ascii'),
                capture_complete=complete, extent='COMPLETE' if complete else 'PREFIX_OR_INCOMPLETE')


def client_call(state, value, request):
    require(len(state['calls']) < 2, 'checked-submit call count bound')
    raw = canonical(request)
    require(len(raw) <= inputs.REQUEST_CAP, 'client request bound')
    argv = [value['python']['path'], '-I', '-S', '-B', '-Werror', value['client']['path'], '--binding',
            str(state['args'].binding), '--expect-binding-sha256', state['args'].expect_binding_sha256, '--request-json', raw.decode()]
    recheck(state)
    state['client_dispatched'] = True
    if request['action'] == 'finish':
        state['finish_dispatched'] = True
    result = run_bounded(argv, Path(value['client']['path']).parent, inputs.ENV, timeout=35, cap=PROCESS_CAP)
    observation = {key: result[key] for key in ('status', 'exit_code', 'elapsed_ns')}
    complete = result['status'] in ('SUCCESS', 'EXIT_NONZERO')
    observation.update(action=request['action'], stdout=captured_stream(result['stdout'], complete),
                       stderr=captured_stream(result['stderr'], complete))
    state['calls'].append(observation)
    require(result['status'] in ('SUCCESS', 'EXIT_NONZERO') and not result['stderr'] and bool(result['stdout']), 'bounded client process refused')
    require(result['stdout'].endswith(b'\n'), 'client response framing differs')
    answer = inputs.json_value(result['stdout'], PROCESS_CAP)
    require(answer.get('schema') == 'transport/handoff-response/1' and answer.get('action') == request['action']
            and answer.get('status') == 'OK' and result['exit_code'] == 0, 'client refused checked submission')
    recheck(state)
    return answer


def submit(state, args):
    state['args'] = args
    for name in inputs.BOOTSTRAP + ('transport_handoff_client.py', 'transport_checked_finish.py',
                                    'transport_response_contract.py', 'transport_response_contract_model.py'):
        tracked(state, HERE / name, 4194304)
    tracked(state, Path(sys.executable).resolve(), 4194304)
    require(len({absolute(str(args.contract)), absolute(str(args.candidate)), absolute(str(args.binding))}) == 3, 'input roles must use distinct paths')
    contract = held_file(state, args.contract, args.expect_contract_sha256, model.CONTRACT_BYTES)
    candidate = tracked(state, args.candidate, model.CANDIDATE_BYTES)
    candidate.decode('utf-8', errors='strict')
    shape = validator.validate(candidate, model.compile_contract(contract))
    state['shape'] = shape
    require(shape['status'] == 'STRUCTURALLY_CONFORMANT', 'candidate does not conform; no client action attempted')
    value = binding(state, args)
    session = Path(value['session'])
    if not session.exists():
        client_call(state, value, dict(action='describe'))
    response = client_call(state, value, dict(action='finish', candidate_base64=base64.b64encode(candidate).decode('ascii')))
    require(response['result']['status'] == 'DRAFT_SAVED_UNEDITED'
            and response['result']['candidate'] == inputs.record(candidate), 'client candidate receipt differs')
    require(read_regular(session / 'candidate.json', model.CANDIDATE_BYTES) == candidate, 'saved draft bytes differ')
    recheck(state)
    return dict(status='DRAFT_SAVED_STRUCTURALLY_CHECKED', candidate=inputs.record(candidate),
                contract_sha256=sha(contract), binding_sha256=args.expect_binding_sha256, client_response=response)


def arguments():
    parser = validator.Parser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--expect-contract-sha256', required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--expect-binding-sha256', required=True)
    return parser.parse_args()


def main():
    state = dict(files={}, calls=[], shape=None, client_dispatched=False, finish_dispatched=False)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (inputs.CAP, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        result = submit(state, arguments())
        status = 0
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError, RecursionError) as error:
        mismatch = state['shape'] is not None and state['shape']['status'] == 'STRUCTURAL_MISMATCH'
        result = dict(status='STRUCTURAL_MISMATCH' if mismatch else 'REFUSED', reason=str(error)[:256])
        status = 1 if mismatch else 2
    result.update(schema='transport/checked-finish/1', structural_verdict=state['shape'], calls=state['calls'],
                  client_dispatched=state['client_dispatched'], reader_action_may_be_recorded=state['client_dispatched'],
                  draft_state='SAVED_EXACT_BYTES' if status == 0 else 'UNKNOWN_MAY_BE_SAVED' if state['finish_dispatched'] else 'NOT_SUBMITTED_BY_THIS_COMMAND',
                  scope='STRUCTURE_AND_DRAFT_CUSTODY_ONLY', semantics='NOT_ASSESSED', source_approval='NOT_ASSESSED', execution_authority='NONE')
    raw = canonical(result) + b'\n'
    require(len(raw) <= inputs.CAP, 'complete checked-finish verdict including LF exceeds bound')
    sys.stdout.buffer.write(raw)
    return status


if __name__ == '__main__':
    sys.exit(main())
