#!/usr/bin/env python3
"""Recompute a finite candidate test, then evaluate its source-bound obligation.

Candidate Python is parsed as bounded data, never imported or executed. Test
tables are declared interpretations, not automatically proved source meanings.
An imported receipt is compared to a fresh computation, never trusted as truth.
"""
import argparse
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_bound_contract as contract
import transport_bound_lowering as lowering
import transport_finite_check as finite
import transport_handoff_inputs as inputs
from transport_bound_evaluate import evaluate, held
from transport_bound_inputs import prepared_manifest
from transport_install_support import canonical, read_regular, require, sha


def observation(receipt, compiled):
    matches = [node for node, value in compiled['bindings'].items()
               if value['sha256'] == receipt['binding_sha256']]
    require(len(matches) == 1, 'recomputed test binding missing or duplicated')
    require(receipt['truth'] in ('KNOWN_TRUE', 'KNOWN_FALSE'), 'finite checker result type')
    report = dict(provenance='RECOMPUTED_FINITE_CHECK', binding_sha256=receipt['binding_sha256'],
                  node=matches[0], truth=receipt['truth'], receipt_sha256=sha(canonical(receipt)),
                  test_sha256=receipt['test_sha256'], replacement_sha256=receipt['replacement_sha256'],
                  checker_sha256=receipt['checker_sha256'])
    return dict(masks={matches[0]: lowering.REPORT_BITS[receipt['truth']]}, reports=[report],
                observations_sha256=sha(canonical(dict(schema='transport/recomputed-test-input/1', report=report))))


def run(args):
    manifest, root, data = prepared_manifest(args.manifest, args.expect_manifest_sha256)
    require(manifest['arm'] == 'transport', 'source-bound test requires a decoded package')
    receiver = inputs.transport_receiver(manifest, root, data)
    raw = held(args.contract, args.expect_contract_sha256, contract.CAP)
    compiled = contract.compile_contract(raw, receiver.decoded, args.expect_contract_sha256)
    test = held(args.test, args.expect_test_sha256, finite.CAP)
    replacement = held(args.replacement, args.expect_replacement_sha256, finite.CAP)
    receipt = finite.run_check(test, replacement, compiled, args.expect_test_sha256,
                               args.expect_replacement_sha256)
    imported, checked = None, None
    if args.receipt is not None:
        imported = held(args.receipt, args.expect_receipt_sha256, finite.CAP)
        checked = finite.validate_receipt(imported, receipt, args.expect_receipt_sha256)
    observed = observation(receipt, compiled)
    evaluation, process = evaluate(compiled, observed, lowering.lower(compiled, observed),
                                   args.native, args.expect_native_sha256)
    for path, original in ((args.contract, raw), (args.test, test), (args.replacement, replacement)):
        require(read_regular(path, finite.CAP) == original, 'test inputs changed during evaluation')
    if imported is not None:
        require(read_regular(args.receipt, finite.CAP) == imported, 'imported test receipt changed')
    prepared_manifest(args.manifest, args.expect_manifest_sha256)
    inputs.frozen_bundle(manifest, root)
    return dict(schema='transport/bound-test-evaluation/1', status='CHECKED_AND_EVALUATED',
                test_receipt=receipt, imported_receipt_check=checked, evaluation=evaluation,
                process=process, execution_authority='NONE',
                scope='DECLARED_FINITE_TABLE_AND_GROUND_OBLIGATION_ONLY',
                expected_table_entailment='UNPROVEN', whole_source_completeness='UNPROVEN')


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'contract', 'test', 'replacement', 'native'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--expect-' + name + '-sha256', required=True)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--expect-receipt-sha256')
    args = parser.parse_args()
    require((args.receipt is None) == (args.expect_receipt_sha256 is None), 'receipt and pin must be supplied together')
    return args


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (inputs.CAP, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        result = run(arguments())
        raw = canonical(result)
        require(len(raw) + 1 <= inputs.CAP, 'test evaluation response byte bound')
        sys.stdout.buffer.write(raw + b'\n')
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RuntimeError, MemoryError) as error:
        sys.stdout.buffer.write(canonical(dict(status='REFUSED', reason=str(error)[:1024], execution_authority='NONE')) + b'\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
