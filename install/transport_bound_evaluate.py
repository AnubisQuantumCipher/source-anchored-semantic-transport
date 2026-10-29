#!/usr/bin/env python3
"""Evaluate a source-bound ground obligation; optionally check a submitted verdict.

Only the explicitly supplied, digest-pinned native evaluator is run. No imported
instructions, report code, network reference or candidate narrative is executed.
"""
import argparse
from pathlib import Path
import resource
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_bound_contract as contract
import transport_bound_lowering as lowering
from transport_bound_inputs import prepared_manifest
import transport_handoff_inputs as inputs
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

HERE = Path(__file__).absolute().parent


def held(path, expected, cap):
    raw = read_regular(path, cap)
    require(sha(raw) == inputs.digest(expected), 'externally held input identity differs')
    return raw


def evaluate(compiled, observed, lowered, native, expected):
    require(isinstance(native, Path) and native.is_absolute() and '..' not in native.parts,
            'native evaluator requires an explicit absolute path')
    require(expected == compiled['contract']['native_sha256'], 'native contract/held identity differs')
    image = held(native, expected, 4194304)
    with tempfile.TemporaryDirectory(prefix='transport-bound-evaluation-') as directory:
        root = Path(directory)
        frame = root / 'input.stv'
        write_new(frame, lowered['frame'], 1542)
        result = run_bounded([str(native), str(frame)], root, inputs.ENV, timeout=10, cap=16384)
        require(read_regular(frame, 1542) == lowered['frame'], 'evaluation frame changed')
    require(read_regular(native) == image, 'native evaluator changed during evaluation')
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and not result['stderr'],
            'native evaluation refused')
    computed = lowering.native_result(result['stdout'], lowered)
    value, unit = compiled['contract'], compiled['unit']
    receipt = dict(schema='transport/bound-evaluation/1', status='CONDITIONAL_EVALUATION',
                   package_identity=value['package_identity'], unit_id=unit['id'],
                   unit_sha256=value['unit_sha256'], source_sha256=value['source_sha256'],
                   contract_sha256=compiled['contract_sha256'], observations_sha256=observed['observations_sha256'],
                   native_sha256=expected, frame_sha256=sha(lowered['frame']), results=computed,
                   bindings=[dict(node=node, **item) for node, item in compiled['bindings'].items()],
                   reports=observed['reports'], outcome=computed[-1]['value'],
                   unevaluated_units=compiled['unevaluated_units'], residuals=unit['residuals'], context=compiled['context'],
                   scope='SELECTED_DECLARED_GROUND_OBLIGATION_CONDITIONAL_ON_REPORTS',
                   report_authentication='NOT_AUTHENTICATED', report_interpretation='UNPROVEN',
                   source_entailment='UNPROVEN', context_adequacy='UNPROVEN', execution_authority='NONE')
    require(len(canonical(receipt)) <= inputs.CAP, 'evaluation receipt byte bound')
    process = {key: result[key] for key in ('status', 'exit_code', 'elapsed_ns')}
    process.update(stdout=inputs.record(result['stdout']), stderr=inputs.record(result['stderr']))
    return receipt, process


def run(args):
    manifest, root, data = prepared_manifest(args.manifest, args.expect_manifest_sha256)
    require(manifest['arm'] == 'transport', 'source-bound evaluation requires a decoded package')
    receiver = inputs.transport_receiver(manifest, root, data)
    raw = held(args.contract, args.expect_contract_sha256, contract.CAP)
    compiled = contract.compile_contract(raw, receiver.decoded, args.expect_contract_sha256)
    reports = held(args.observations, args.expect_observations_sha256, contract.CAP)
    observed = lowering.observations(reports, compiled, args.expect_observations_sha256)
    lowered = lowering.lower(compiled, observed)
    evaluation, process = evaluate(compiled, observed, lowered, args.native, args.expect_native_sha256)
    conclusion = None
    if args.candidate is not None:
        conclusion = lowering.check_conclusion(read_regular(args.candidate, contract.CAP), evaluation)
    require(read_regular(args.contract, contract.CAP) == raw
            and read_regular(args.observations, contract.CAP) == reports, 'evaluation inputs changed')
    prepared_manifest(args.manifest, args.expect_manifest_sha256)
    inputs.frozen_bundle(manifest, root)
    return dict(status='EVALUATED', evaluation=evaluation, process=process, conclusion=conclusion)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'contract', 'observations', 'native'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--expect-' + name + '-sha256', required=True)
    parser.add_argument('--candidate', type=Path)
    return parser.parse_args()


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (inputs.CAP, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        result = run(arguments())
        raw = canonical(result)
        require(len(raw) + 1 <= inputs.CAP, 'complete evaluation response byte bound')
        sys.stdout.buffer.write(raw + b'\n')
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RuntimeError) as error:
        sys.stdout.buffer.write(canonical(dict(status='REFUSED', reason=str(error)[:1024], execution_authority='NONE')) + b'\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
