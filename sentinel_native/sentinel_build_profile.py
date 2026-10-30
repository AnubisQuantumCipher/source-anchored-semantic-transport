"""Fixed SENTINEL build/test/proof worker inside the qualified quota namespace."""
import json
import os
from pathlib import Path
import sys
from document_build import namespace as container
from document_build.capture import snapshot
from document_build.common import TERMINAL_RESERVE, digest, json_new, limits, need, read_bytes, usage
from document_build.identity import verify_roster
from document_build.process import admit_phase, drain_children, mount_command, phase
from document_build.worker import environment
from sentinel_qualification import diagnostics, machine_diagnostics, parse_proof, source_gate


def commands(root, tools):
    return [('build', 90, [tools['gprbuild'], '-R', '-P',
        str(root / 'sentinel_native/sentinel_policy.gpr'), '-j1', '-cargs:Ada',
        '-gnata', '-gnatwa', '-gnatwe', '-gnatVa', '-gnatf']),
        ('checks', 30, ['NATIVE_CHECKS']),
        ('proof', 180, [tools['gnatprove'], '-P',
        str(root / 'sentinel_native/sentinel_policy_proof.gpr'), '-U', '--level=2',
        '--report=all', '--warnings=error', '-j1', '--prover=z3', '--timeout=1',
        '--counterexamples=off'])]


def worker(work, config):
    root = Path(config['source_root'])
    need(source_gate(root) == config['sentinel_source_pins'], 'SENTINEL dispatch source changed')
    env = environment(work, config)
    records, report, binary_hash = [], None, None
    for label, seconds, argv in commands(root, config['tools']):
        if label == 'checks':
            argv = [str(work / 'bin/sentinel_policy_checks')]
        deadline = admit_phase(seconds, config['global_deadline'], TERMINAL_RESERVE)
        record = phase(argv, seconds, deadline, work, label, env)
        records.append(record)
        json_new(work / (label + '.json'), record)
        need(record['returncode'] == 0, label + ' failed; raw output retained')
        for stream in ('stdout', 'stderr'):
            diagnostics(read_bytes(work / (label + '.' + stream), 1048576))
        if label == 'checks':
            need(read_bytes(work / 'checks.stdout') == b'SENTINEL_POLICY_CHECKS_PASS\n' and
                 read_bytes(work / 'checks.stderr') == b'', 'exact runtime fixture success required')
    report = parse_proof(read_bytes(work / 'proof/gnatprove/gnatprove.out', 1048576),
                         config['proof_roster'])
    machine = machine_diagnostics(read_bytes(work / 'proof/gnatprove/sentinel_policy.spark',
                                             1048576), report)
    binary_hash = digest(work / 'bin/sentinel_policy_checks')
    need(source_gate(root) == config['sentinel_source_pins'], 'SENTINEL final source changed')
    result = {'status': 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED', 'runs': records,
              'proof': report, 'machine_diagnostics': machine, 'checks_binary_sha256': binary_hash,
              'scope': 'PURE_TYPED_POLICY_CONTRACTS_AND_STATIC_FIXTURES_ONLY',
              'native_wire': 'NOT_IMPLEMENTED_BY_THIS_PROFILE', 'English_semantics': 'UNPROVEN',
              'OCR_accuracy': 'UNPROVEN', 'wholebook_semantics': 'UNPROVEN',
              'execution_authority': 'NONE'}
    json_new(work / 'worker-result.json', result)
    return result


def execute(work, out, config):
    failures, result = [], None
    try:
        result = worker(work, config)
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        failures.append(type(error).__name__ + ':' + str(error)[:4096])
    cleanup = drain_children()
    identity_after = None
    try:
        identity_after = verify_roster(config)
        need(identity_after == config['identity_before'], 'tool/runtime roster changed')
        need(source_gate(Path(config['source_root'])) == config['sentinel_source_pins'],
             'SENTINEL source changed before capture')
    except (ValueError, OSError) as error:
        failures.append('IDENTITY_FAILED:' + str(error)[:4096])
    readonly = False
    try:
        mount_command(container.MOUNT + ['-t', 'tmpfs', '-o', 'remount,ro,' + container.QUOTA,
                      'document-private', str(work)], out, config['global_deadline'])
        fs = os.statvfs(work)
        need(bool(fs.f_flag & os.ST_RDONLY), 'readonly remount absent')
        need(fs.f_blocks * fs.f_frsize == 67108864 and fs.f_files == 4096,
             'readonly remount lost hard quota')
        readonly = True
    except (ValueError, OSError) as error:
        failures.append('READONLY_REMOUNT_FAILED:' + str(error)[:4096])
    captured = snapshot(work, out, readonly)
    if not captured['complete'] or not readonly:
        failures.append('INCOMPLETE_OR_UNQUALIFIED_CAPTURE')
    return {'status': 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED' if not failures else 'FAILED',
            'failures': failures, 'worker': result, 'cleanup': cleanup, 'capture': captured,
            'readonly_qualified': readonly, 'external_bytes': usage(out, work),
            'identity_before': config['identity_before'], 'identity_after': identity_after}


def namespace_main():
    limits()
    out = Path(sys.argv[3])
    config = json.loads(read_bytes(out / 'launch.json'))
    work = out / 'private'
    device, setup_complete = work.stat().st_dev, False
    record = {'status': 'FAILED', 'failure': 'namespace setup incomplete'}
    try:
        observed = container.setup(config, out, work)
        need(source_gate(Path(config['source_root'])) == config['sentinel_source_pins'],
             'SENTINEL source changed after readonly setup')
        setup_complete = True
        record = execute(work, out, config)
        record['namespaces'] = observed
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        record['failure'] = type(error).__name__ + ':' + str(error)[:4096]
        record['failure_stage'] = 'EXECUTE_OR_CAPTURE' if setup_complete else 'SETUP'
        drain_children()
        if not setup_complete and work.stat().st_dev != device:
            record['setup_failure_capture'] = container.failed_setup_capture(work, out, config)
    finally:
        record['terminal_cleanup'] = drain_children()
        try:
            json_new(out / 'namespace-result.json', record)
        except (ValueError, OSError) as error:
            record['status'] = 'FAILED'
            print('SENTINEL_TERMINAL_RECORD_LOST:' + str(error)[:4096], file=sys.stderr)
    return 0 if record['status'] == 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED' else 2


if __name__ == '__main__':
    sys.exit(namespace_main())
