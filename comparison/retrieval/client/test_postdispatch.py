#!/usr/bin/env python3
"""Additive trusted fault injections around real worker/commit boundaries.

These controls inject process-result corruption or a receipt-write failure in an
isolated Python process. They do not claim that the real codec produced malformed
output, and they do not model hostile same-user concurrency or a power failure.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
TEST_SHA = 'a13a10843d584d15705cd6ba8800bef68f223df8d4ca882aa573ce9a94acbbe4'
CASES = ('malformed-worker-stdout', 'truncated-worker-stdout', 'worker-exit-mismatch',
         'prelaunch-stage-failure', 'postcommit-receipt-failure')


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def harness():
    import hashlib
    path = HERE / 'test_client.py'
    if hashlib.sha256(path.read_bytes()).hexdigest() != TEST_SHA:
        raise ValueError('unchanged independent client harness required')
    return load_module('independent_client_test_helpers', path)


def child(args):
    helper = harness()
    helper.require(helper.pin(HERE / 'entry.py')['sha256'] == args.expect_entry_sha256,
                   'held client code differs before isolated injection')
    entry = load_module('client_injected_boundary', HERE / 'entry.py')
    adapter, inputs, journal, support = entry.bootstrap()
    original_run, original_write = support.run_bounded, support.write_new
    dispatched = []
    receipt_path = args.root / 'receipts' / (args.case + '.json')

    def injected_run(*values, **keywords):
        dispatched.append(True)
        result = original_run(*values, **keywords)
        helper.save(args.root / (args.case + '-actual-worker.stdout'), result['stdout'])
        helper.save(args.root / (args.case + '-actual-worker.stderr'), result['stderr'])
        helper.require(result['status'] == 'SUCCESS' and result['exit_code'] == 0,
                       'real worker failed before requested boundary injection')
        changed = dict(result)
        if args.case == 'malformed-worker-stdout':
            changed['stdout'] = b'{\n'
        elif args.case == 'truncated-worker-stdout':
            changed['stdout'] = result['stdout'][:-1]
        elif args.case == 'worker-exit-mismatch':
            changed['exit_code'] = 1
        return changed

    def injected_write(path, raw, maximum=4194304):
        if args.case == 'prelaunch-stage-failure' and path.name == 'request-prefix.bin':
            raise OSError('INJECTED_BEFORE_WORKER_DISPATCH')
        if args.case == 'postcommit-receipt-failure' and path == receipt_path:
            raise OSError('INJECTED_RECEIPT_WRITE_AFTER_CALL_COMMIT')
        return original_write(path, raw, maximum)

    support.run_bounded, support.write_new = injected_run, injected_write
    entry.bootstrap = lambda: (adapter, inputs, journal, support)
    manifest = args.root / 'inputs' / args.case / 'manifest.json'
    expected = helper.pin(manifest)['sha256']
    request = SimpleNamespace(manifest=manifest, expect_manifest_sha256=expected,
        expect_session_head_sha256=helper.sha(helper.canonical(helper.identity(manifest, expected))),
        receipt=receipt_path, request_json='{"action":"catalog"}', request_file=None,
        expect_request_sha256=None, staged_input_bytes=None, worker=args.case == 'postcommit-receipt-failure')
    entry.arguments = lambda: request
    code = entry.main()
    helper.save(args.root / (args.case + '-injection.json'),
                {'case': args.case, 'bounded_worker_dispatched': bool(dispatched),
                 'trusted_fault_injection': True, 'exit_code': code})
    return code


def check_case(helper, root, state, name, result):
    outer = json.loads(result['stdout'])
    expected_ambiguous = name != 'prelaunch-stage-failure'
    helper.require(result['exit_code'] == 1 and outer['status'] == 'REFUSED'
                   and outer['arm'] == 'UNKNOWN' and outer['call'] == 0
                   and outer['result']['recorded_may_exist'] is expected_ambiguous,
                   'injected boundary ambiguity flag differs from phase contract')
    session = state['session']
    receipt = root / 'receipts' / (name + '.json')
    if not expected_ambiguous:
        helper.require(not session.exists() and not receipt.exists(), 'prelaunch failure caused journal effects')
        return {'case': name, 'status': 'TESTED_INJECTED_PRELAUNCH_NO_COMMIT', 'recorded_may_exist': False}
    call = session / 'call-01.json'
    helper.require(call.is_file(), 'actual committed record absent behind ambiguous outcome')
    request = (session / 'request-01.json').read_bytes()
    response = (session / 'response-01.json').read_bytes()
    helper.verify_journal(session, 1, state['manifest'], state['expected'], request, response)
    helper.require(request == b'{"action":"catalog"}' and json.loads(response)['status'] == 'OK',
                   'real committed source-linked catalog differs')
    helper.require(receipt.exists() is (name != 'postcommit-receipt-failure'), 'injected receipt state differs')
    return {'case': name, 'status': 'TESTED_INJECTED_BOUNDARY_WITH_REAL_COMMIT',
            'recorded_may_exist': True, 'committed_call': helper.pin(call), 'receipt_exists': receipt.exists()}


def run(args):
    helper = harness()
    root = args.root
    helper.require(root.parent == helper.BASE and not root.exists(), 'new bounded injection root required')
    root.mkdir(mode=0o700)
    for name in ('inputs', 'sessions', 'receipts', 'requests', 'tmp'):
        (root / name).mkdir(mode=0o700)
    states = {name: helper.make_binding(root, name, 'SC_MAIN', 'original') for name in CASES}
    helper.require(helper.pin(HERE / 'entry.py')['sha256'] == args.expect_entry_sha256, 'held product pin differs')
    frozen = {'schema': 'transport/client-postdispatch-injection-freeze/1',
              'status': 'FROZEN_BEFORE_ISOLATED_IMPORT_OR_EXECUTION', 'client': helper.pin(HERE / 'entry.py'),
              'injection_test': helper.pin(Path(__file__).absolute()), 'original_test': helper.pin(HERE / 'test_client.py'),
              'contract': helper.pin(HERE / 'contract.json'), 'oracle': helper.pin(HERE / 'oracle.json'),
              'receiving_manifests': [helper.pin(state['manifest']) for state in states.values()],
              'cases': [{'case': name, 'expected_recorded_may_exist': name != 'prelaunch-stage-failure',
                         'expected_commit': name != 'prelaunch-stage-failure'} for name in CASES],
              'scope': 'TRUSTED_CONTROLLED_FAULT_INJECTION; real source-linked original worker/commit, no codec corruption claim'}
    helper.save(root / 'T-injection.json', frozen)
    results = []
    try:
        for name in CASES:
            argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(Path(__file__).absolute()),
                    '--root', str(root), '--expect-entry-sha256', args.expect_entry_sha256, '--child', '--case', name]
            result, _ = helper.execute(root, name, argv)
            results.append(check_case(helper, root, states[name], name, result))
        helper.require(helper.pin(HERE / 'entry.py') == frozen['client'], 'product source changed during injection run')
        helper.save(root / 'receipt.json', {'status': 'TESTED_CONTROLLED_POSTDISPATCH_AND_RECEIPT_FAILURES',
                                           'cases': results, 'fault_origin': 'TRUSTED_TEST_SHIM',
                                           'semantic_adequacy': 'UNPROVEN', 'authority': 'NONE',
                                           'crash_or_power_failure': 'UNRUN'})
    except (AssertionError, ValueError, OSError, KeyError, TypeError) as error:
        helper.save(root / 'failure.json', {'status': 'FAILED_RETAINED', 'reason': str(error)[:256]})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-entry-sha256', required=True)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--case', choices=CASES)
    args = parser.parse_args()
    return child(args) if args.child else run(args)


if __name__ == '__main__':
    sys.exit(main())
