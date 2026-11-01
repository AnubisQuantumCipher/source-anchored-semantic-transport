"""Prepared fixed build/wire control profile. Dispatch requires separate admission."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from document_build import namespace as container
from document_build.capture import snapshot
from document_build.common import TERMINAL_RESERVE, digest, json_new, limits, need, read_bytes, usage
from document_build.identity import verify_roster
from document_build.launcher import source_pins
from document_build.process import admit_phase, drain_children, mount_command, phase
from document_build.worker import environment
from sentinel_qualification import diagnostics, source_gate
from wire_checks import check_output, elf_inventory, oracle_files, stack_inventory, operation_count, completed_in_time

SUCCESS = 'SENTINEL_WIRE_BUILD_AND_FROZEN_CONTROLS_CHECKED'


def local_identity(config):
    root = Path(config['source_root'])
    need(source_gate(root) == config['native_pins'], 'native source changed')
    need(source_pins(root) == config['source_pins'], 'generic source changed')
    files, _cases = oracle_files(Path(config['oracle_root']))
    need(files == config['oracle_pins'], 'frozen oracle artifacts changed')
    for name, expected in config['controller_pins'].items():
        need(digest(Path(config['controller_root']) / name) == expected, 'controller source changed')


def append_progress(work, row):
    raw = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
    path = work / 'controls-progress.jsonl'
    need(len(raw) <= 8192 and path.stat().st_size + len(raw) <= 2097152, 'control progress bound')
    with path.open('ab') as stream:
        need(stream.write(raw) == len(raw), 'control progress short write')
        stream.flush()
        os.fsync(stream.fileno())


def native_phase(binary, source, work, label, env, deadline):
    started, code = time.monotonic(), None
    need(started < deadline, 'control suite deadline before dispatch')
    with source.open('rb') as stdin, (work / (label + '.stdout')).open('xb') as stdout:
        with (work / (label + '.stderr')).open('xb') as stderr:
            process = subprocess.Popen([str(binary)], cwd=work, env=env, stdin=stdin,
                                       stdout=stdout, stderr=stderr)
            for _ in range(302):
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    code = process.wait(timeout=1)
                    break
                if time.monotonic() >= min(deadline, started + 3):
                    break
                time.sleep(0.01)
    cleanup = drain_children()
    return {'returncode': code, 'elapsed_seconds': time.monotonic() - started,
            'per_case_seconds_bound': 3, 'cleanup': cleanup}


def one_case(binary, source, work, label, expected, env, deadline):
    before = digest(source)
    append_progress(work, {'event': 'START', 'label': label, 'input_sha256': before,
                           'input_bytes': source.stat().st_size})
    record = native_phase(binary, source, work, label, env, deadline)
    append_progress(work, {'event': 'EXIT_OBSERVED', 'label': label, 'record': record})
    need(record['returncode'] is not None, 'native deadline; raw output retained')
    completed_in_time(record['elapsed_seconds'], time.monotonic(), deadline)
    raw = read_bytes(work / (label + '.stdout'), 2725)
    stderr = read_bytes(work / (label + '.stderr'), 65536)
    fields = check_output(raw, stderr, record['returncode'], expected)
    if expected is not None and 'operations' in expected:
        need(operation_count(read_bytes(source, 1048577)) == expected['operations'],
             'literal frame operation count')
    need(digest(source) == before, 'input changed during native control')
    need(time.monotonic() <= deadline, 'suite deadline before CHECKED')
    append_progress(work, {'event': 'CHECKED', 'label': label,
        'output_sha256': hashlib.sha256(raw).hexdigest(), 'fields': fields})
    return record['elapsed_seconds']


def controls(work, config, env):
    oracle = Path(config['oracle_root'])
    _files, cases = oracle_files(oracle)
    deadline = min(admit_phase(180, config['global_deadline'], TERMINAL_RESERVE),
                   time.monotonic() + 180)
    binary = work / 'bin/sentinel_wire_main'
    with (work / 'controls-progress.jsonl').open('xb'):
        pass
    elapsed = 0.0
    for ordinal, case in enumerate(cases):
        elapsed += one_case(binary, oracle / case['input'], work, 'literal-%03d' % ordinal,
                            case['expected'], env, deadline)
    small = read_bytes(oracle / 'unknown-neither-match.stn', 901)
    need(len(small) == 901, 'frozen small positive length')
    prefix_path = work / 'prefix-input.stn'
    for length in range(len(small)):
        with prefix_path.open('wb') as stream:
            need(stream.write(small[:length]) == length, 'derived strict prefix write')
        elapsed += one_case(binary, prefix_path, work, 'prefix-%03d' % length,
                            None, env, deadline)
    need(time.monotonic() <= deadline, 'suite deadline after final control')
    return {'literal_cases': len(cases), 'strict_prefix_cases': len(small),
            'native_elapsed_seconds_sum': elapsed, 'suite_seconds_bound': 180,
            'derived_prefix_source_sha256': hashlib.sha256(small).hexdigest(),
            'input_retention': 'Frozen full fixture plus each prefix length/hash in append-only progress; sequential reusable prefix inode.'}


def worker(work, config):
    local_identity(config)
    root = Path(config['source_root'])
    env = environment(work, config)
    argv = [config['tools']['gprbuild'], '-R', '-P',
        str(root / 'sentinel_native/sentinel_wire.gpr'), '-j1', '-cargs:Ada',
        '-gnata', '-gnatwa', '-gnatwe', '-gnatVa', '-gnatf']
    deadline = admit_phase(120, config['global_deadline'], TERMINAL_RESERVE)
    build = phase(argv, 120, deadline, work, 'wire-build', env)
    json_new(work / 'wire-build.json', build)
    need(build['returncode'] == 0, 'wire strict build failed; raw output retained')
    completed_in_time(build['elapsed_seconds'], time.monotonic(), deadline, 120)
    for stream in ('stdout', 'stderr'):
        diagnostics(read_bytes(work / ('wire-build.' + stream), 1048576))
    binary = elf_inventory(work / 'bin/sentinel_wire_main')
    stack = stack_inventory(work / 'obj')
    json_new(work / 'wire-memory.json', {'binary': binary, 'stack': stack})
    result = {'status': SUCCESS, 'build': build, 'binary': binary,
        'stack': stack, 'controls': controls(work, config, env),
        'parser_proof': 'UNPROVEN', 'policy_proof': 'SEPARATE_SOURCE_BOUND_RECEIPT_NOT_RERUN_BY_WIRE_PROFILE',
        'semantic_truth': 'UNPROVEN', 'OCR_accuracy': 'UNPROVEN',
        'wholebook_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}
    local_identity(config)
    json_new(work / 'worker-result.json', result)
    return result


def execute(work, out, config):
    failures, result, after = [], None, None
    try:
        result = worker(work, config)
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failures.append(type(error).__name__ + ':' + str(error)[:4096])
    cleanup = drain_children()
    try:
        local_identity(config)
        after = verify_roster(config)
        need(after == config['identity_before'], 'tool/runtime before-after mismatch')
    except (ValueError, OSError, KeyError, TypeError) as error:
        failures.append('IDENTITY_FAILED:' + str(error)[:4096])
    readonly = False
    try:
        mount_command(container.MOUNT + ['-t', 'tmpfs', '-o', 'remount,ro,' + container.QUOTA,
                      'document-private', str(work)], out, config['global_deadline'])
        fs = os.statvfs(work)
        need(bool(fs.f_flag & os.ST_RDONLY) and fs.f_blocks * fs.f_frsize == 67108864
             and fs.f_files == 4096, 'readonly hard quota absent')
        readonly = True
    except (ValueError, OSError) as error:
        failures.append('READONLY_FAILED:' + str(error)[:4096])
    captured = snapshot(work, out, readonly)
    if not captured['complete'] or not readonly:
        failures.append('INCOMPLETE_OR_UNQUALIFIED_CAPTURE')
    return {'status': SUCCESS if not failures else 'FAILED', 'failures': failures,
        'worker': result, 'cleanup': cleanup, 'capture': captured,
        'readonly_qualified': readonly, 'external_bytes': usage(out, work),
        'identity_before': config['identity_before'], 'identity_after': after}


def main():
    limits()
    out = Path(sys.argv[3])
    config = json.loads(read_bytes(out / 'launch.json'))
    work = out / 'private'
    device, setup_complete = work.stat().st_dev, False
    record = {'status': 'FAILED', 'failure': 'namespace setup incomplete'}
    try:
        observed = container.setup(config, out, work)
        for path in (Path(config['controller_root']), Path(config['oracle_root'])):
            container.bind_readonly(path, work, config['global_deadline'])
        local_identity(config)
        setup_complete = True
        record = execute(work, out, config)
        record['namespaces'] = observed
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        record['failure'] = type(error).__name__ + ':' + str(error)[:4096]
        record['failure_stage'] = 'EXECUTE_OR_CAPTURE' if setup_complete else 'SETUP'
        record['capture_retry_performed'] = False
        drain_children()
        if not setup_complete and work.stat().st_dev != device:
            record['setup_failure_capture'] = container.failed_setup_capture(work, out, config)
    finally:
        record['terminal_cleanup'] = drain_children()
        try:
            json_new(out / 'namespace-result.json', record)
        except (ValueError, OSError) as error:
            record['status'] = 'FAILED'
            print('WIRE_TERMINAL_RECORD_LOST:' + str(error)[:4096], file=sys.stderr)
    return 0 if record['status'] == SUCCESS else 2


if __name__ == '__main__':
    sys.exit(main())
