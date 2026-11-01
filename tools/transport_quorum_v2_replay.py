"""Live admitted V1 source replay plus a separate version 2 assessment policy."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'install'))
sys.path.insert(0, str(ROOT / 'tools'))

from transport_quorum_v2_input import (Refusal, array, canonical, digest, fields,
                                      identifier, integer, need, parse, pin,
                                      read_regular, sha, text)
from transport_quorum_v2_policy import NAMES, evaluate
from transport_quorum_v2_process import run_bounded

BOOTSTRAP_SHA = '03f2bf18a67b9a6d6ccf25fd506b252b38ac34c78f56153eb22b8ecfca5738ea'
ADMITTED_SHA = '3efde7878e3b61d7a8af2b2b99f27a9ef78c7fd9e421f8953fa96dd7a1238869'
CAP = 131072


def _held(path, expected, cap=65536):
    digest(expected)
    raw = read_regular(path, cap)
    need(sha(raw) == expected, 'REPLAY_HELD_PIN')
    return raw


def _admitted(invocation, descriptor):
    raw = _held(ROOT / 'docs/quorum-v2-replay-admitted.json', ADMITTED_SHA)
    expected = parse(raw)
    actual = dict(schema=expected['schema'], files=descriptor['files'],
                  decoder_source_manifest_sha256=descriptor['decoder_source_manifest_sha256'],
                  runtime_descriptor=invocation['runtime_descriptor'],
                  decoder_install_descriptor=invocation['decoder_install_descriptor'],
                  python={key: descriptor['python'][key] for key in ('bytes', 'sha256')},
                  platform=descriptor['platform'])
    need(actual == expected, 'UNADMITTED_REPLAY_CLOSURE')
    need(invocation['source_manifest_pin']['sha256'] == expected['decoder_source_manifest_sha256'],
         'UNADMITTED_SOURCE_MANIFEST')
    _closure_files(descriptor, expected)
    return expected


def _closure_files(descriptor, admitted):
    roots = {'checker': descriptor['checker_root'], 'handoff': descriptor['handoff_root']}
    for row in admitted['files']:
        prefix, suffix = row['path'].split('/', 1)
        raw = _held(Path(roots[prefix]) / suffix, row['sha256'])
        need(len(raw) == row['bytes'], 'REPLAY_CLOSURE_FILE_LENGTH')


def _setup(options, raws):
    need(options['bootstrap_sha256'] == BOOTSTRAP_SHA, 'UNADMITTED_BOOTSTRAP')
    bootstrap = _held(options['bootstrap'], BOOTSTRAP_SHA)
    invocation_raw = _held(options['invocation'], options['invocation_sha256'])
    request_raw = _held(options['request'], options['request_sha256'])
    inv, request = parse(invocation_raw), parse(request_raw)
    need(inv['schema'] == 'quorum/bootstrap-invocation/1', 'INVOCATION_SCHEMA')
    need(request['schema'] == 'quorum/replay-request/1', 'REQUEST_SCHEMA')
    need(inv['auxiliary'] is None, 'AUXILIARY_UNSUPPORTED_BY_ADAPTER')
    desc_pin = inv['checker_descriptor']['key']
    descriptor_raw = _held(inv['checker_descriptor']['path'], desc_pin['sha256'])
    need(len(descriptor_raw) == desc_pin['bytes'], 'DESCRIPTOR_LENGTH')
    descriptor = parse(descriptor_raw)
    admitted = _admitted(inv, descriptor)
    need(inv['held_request'] == pin(request_raw), 'INVOCATION_REQUEST_MISMATCH')
    need(inv['request']['sha256'] == sha(request_raw)
         and inv['request']['bytes'] == len(request_raw), 'INVOCATION_REQUEST_MISMATCH')
    account = _accounting(inv, admitted, raws, invocation_raw, request_raw, descriptor_raw)
    account.update(_runtime_accounting(inv, descriptor))
    return dict(bootstrap=bootstrap, invocation_raw=invocation_raw, request_raw=request_raw,
                descriptor_raw=descriptor_raw, invocation=inv, request=request,
                descriptor=descriptor, accounting=account)


def _accounting(inv, admitted, raws, invocation_raw, request_raw, descriptor_raw):
    array(inv['originals'], 0, 15)
    carrier = [inv[key]['bytes'] for key in ('envelope', 'package', 'body')]
    if inv['share'] is not None:
        carrier.append(inv['share']['bytes'])
    carrier += [row['key']['bytes'] for row in inv['originals']]
    for length in carrier:
        integer(length, 0, CAP)
    policy = sum(len(raw) for raw in raws)
    metadata = len(invocation_raw) + len(request_raw) + len(descriptor_raw)
    total = policy + metadata + sum(carrier)
    need(total <= 65536, 'COMBINED_MESSAGE_INPUT_BOUND')
    return dict(policy_input_bytes=policy, replay_metadata_bytes=metadata,
                declared_carrier_bytes=sum(carrier), conservative_message_total_bytes=total,
                message_budget_bytes=65536, contained_source_bytes_counted_again=True,
                shared_checker_helper_bytes=sum(row['bytes'] for row in admitted['files']),
                shared_python_executable_bytes=admitted['python']['bytes'])


def _runtime_accounting(inv, descriptor):
    raw = _held(Path(descriptor['decoder_bundle_root']) / 'INSTALL.json',
                inv['decoder_install_descriptor']['sha256'])
    install = parse(raw)
    array(install['files'], 1, 256)
    array(install['external'], 0, 64)
    for row in install['files'] + install['external']:
        integer(row['bytes'], 0, 16777216)
    return dict(decoder_bundle_declared_file_bytes=len(raw) + sum(r['bytes'] for r in install['files']),
                external_runtime_declared_bytes=sum(r['bytes'] for r in install['external']),
                setup_accounting='SEPARATE_CATEGORIES_MAY_SHARE_FILES',
                setup_not_counted='Python standard library, transitive libraries and operating system')


def _document(raw):
    need(type(raw) is bytes and raw.endswith(b'\n'), 'REPLAY_OUTPUT_FRAMING')
    value = parse(raw[:-1], CAP)
    need(canonical(value) + b'\n' == raw, 'REPLAY_OUTPUT_CANONICAL')
    return value


def _receipt(receipt, setup):
    fields(receipt, ('schema', 'status', 'bootstrap_entry', 'checker_descriptor', 'python',
                     'decoder_install_descriptor', 'runtime_descriptor', 'source_manifest', 'modules'))
    need(receipt['schema'] == 'quorum/bootstrap-qualified/1'
         and receipt['status'] == 'QUALIFIED_FIXED_HOST', 'REPLAY_QUALIFICATION')
    need(receipt['bootstrap_entry'] == pin(setup['bootstrap']), 'RECEIPT_ENTRY')
    inv, desc = setup['invocation'], setup['descriptor']
    for field in ('decoder_install_descriptor', 'runtime_descriptor'):
        need(receipt[field] == inv[field], 'RECEIPT_COMPONENT')
    need(receipt['checker_descriptor'] == inv['checker_descriptor']['key'], 'RECEIPT_DESCRIPTOR')
    need(receipt['source_manifest'] == inv['source_manifest_pin'], 'RECEIPT_SOURCE')
    need(receipt['python'] == desc['python'] and type(receipt['modules']) is list,
         'RECEIPT_MODULES')


def _selected(result, setup, claim_id, revision):
    fields(result, ('schema', 'accepted_result', 'replay', 'request', 'claims',
                    'quarantined_update_ids', 'conflicting_update_ids', 'already_recorded_update_ids',
                    'retained_history_ids', 'reasons', 'exclusions', 'source_authentication',
                    'current_authority', 'freshness', 'semantic_completeness'))
    need(result['schema'] == 'quorum/replay-result/1'
         and result['accepted_result'] is True
         and result['replay'] == 'RECOMPUTED_INFORMATIONAL', 'REPLAY_RESULT')
    expected = dict(id='REPLAY_REQUEST', **pin(setup['request_raw']))
    need(result['request'] == expected, 'REPLAY_REQUEST_MISMATCH')
    array(result['claims'], 1, 16)
    selected = []
    for row in result['claims']:
        need(type(row) is dict and type(row.get('claim')) is dict, 'REPLAY_CLAIM_SHAPE')
        claim = row['claim']
        fields(claim, ('bytes', 'claim_id', 'revision', 'sha256'))
        digest(claim['sha256'])
        integer(claim['bytes'], 1, 65536)
        identifier(claim['claim_id'])
        identifier(claim['revision'])
        if claim['claim_id'] == claim_id and claim['revision'] == revision:
            selected.append(row)
    need(len(selected) == 1, 'REPLAY_SELECTED_CLAIM')
    return selected[0]


def _context(request, selected):
    digest(request['task']['sha256'])
    array(request['external_source_pins'], 0, 16)
    for source in request['external_source_pins']:
        fields(source, ('bytes', 'logical_source_id', 'sha256'))
        integer(source['bytes'], 0, 65536)
        identifier(source['logical_source_id'])
        digest(source['sha256'])
    return dict(claim_sha256=selected['claim']['sha256'],
                task_sha256=request['task']['sha256'],
                source_set_sha256=sha(canonical(request['external_source_pins'])))


def compose(process, setup, options, threshold):
    need(process['status'] == 'SUCCESS' and type(process['exit_code']) is int
         and process['exit_code'] == 0, 'REPLAY_PROCESS')
    need(len(process['stdout']) + len(process['stderr']) <= CAP, 'REPLAY_CAPTURE_BOUND')
    result, receipt = _document(process['stdout']), _document(process['stderr'])
    _receipt(receipt, setup)
    selected = _selected(result, setup, options['claim_id'], options['revision'])
    context = _context(setup['request'], selected)
    need(context == threshold['policy']['context'], 'REPLAY_POLICY_CONTEXT')
    output = dict(schema='quorum/source-replay-threshold/2', status='EVALUATED_DIMENSIONS',
                  source_replay=result, host_qualification=receipt, threshold=threshold,
                  replay_context=context, source_replay_status='RECOMPUTED_NOW',
                  execution_authority='NONE', source_truth='NOT_ASSESSED',
                  accounting=setup['accounting'], elapsed_replay_ns=process['elapsed_ns'],
                  replay_output_pins={name: pin(process[name]) for name in ('stdout', 'stderr')})
    need(len(canonical(output)) + 1 <= CAP, 'COMPLETE_COMPOSED_OUTPUT_BOUND')
    return output


def replay(raws, held, options):
    try:
        fields(options, ('bootstrap', 'bootstrap_sha256', 'invocation', 'invocation_sha256',
                         'request', 'request_sha256', 'claim_id', 'revision'))
        for name in ('bootstrap', 'invocation', 'request'):
            text(options[name], 4096)
            need(Path(options[name]).is_absolute() and '\x00' not in options[name], 'ADAPTER_PATH')
        threshold = evaluate(raws, held)
        need(threshold['status'] == 'EVALUATED', 'THRESHOLD_INPUT_REFUSED')
        identifier(options['claim_id'])
        identifier(options['revision'])
        setup = _setup(options, raws)
        argv = [str(Path(sys.executable).resolve()), '-I', '-S', options['bootstrap'],
                options['invocation'], '--expect-invocation-sha256', options['invocation_sha256'],
                '--expect-bootstrap-sha256', BOOTSTRAP_SHA]
        process = run_bounded(argv, ROOT, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        _held(options['bootstrap'], BOOTSTRAP_SHA)
        need(_setup(options, raws) == setup, 'REPLAY_INPUTS_CHANGED')
        return compose(process, setup, options, threshold)
    except (ValueError, OSError, KeyError, TypeError) as error:
        code = str(error) if isinstance(error, Refusal) else 'ADAPTER_INPUT_SHAPE_OR_IO'
        return dict(schema='quorum/source-replay-threshold-refusal/2', status='REFUSED',
                    code=code, execution_authority='NONE')


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in NAMES:
        parser.add_argument('--' + name, required=True)
    for name in NAMES[:3]:
        parser.add_argument('--expect-' + name + '-sha256', required=True)
    for name in ('bootstrap', 'invocation', 'request', 'claim-id', 'revision'):
        parser.add_argument('--' + name, required=True)
    for name in ('bootstrap', 'invocation', 'request'):
        parser.add_argument('--expect-' + name + '-sha256', required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    try:
        raws = tuple(read_regular(getattr(args, name)) for name in NAMES)
        held = {name: getattr(args, 'expect_' + name + '_sha256') for name in NAMES[:3]}
        options = {name: getattr(args, name) for name in ('bootstrap', 'invocation', 'request',
                                                       'claim_id', 'revision')}
        options.update({name + '_sha256': getattr(args, 'expect_' + name + '_sha256')
                        for name in ('bootstrap', 'invocation', 'request')})
        result = replay(raws, held, options)
    except (ValueError, OSError):
        result = dict(schema='quorum/source-replay-threshold-refusal/2', status='REFUSED',
                      code='FILE_IO', execution_authority='NONE')
    sys.stdout.buffer.write(canonical(result) + b'\n')
    return 2 if result['status'] == 'REFUSED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
