"""One caller-held native wire executable in an owned bounded PID namespace.

This module returns raw execution evidence. It cannot grant finite-Q qualification.
The repository, cooperative executable, system runtime and kernel are trusted.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import sys
import time

from . import native_build
from .common import canonical, identity, require
from .jobs import job_slot
from document_build.capture import snapshot
from document_build.common import json_new, limits, read_bytes, usage
from document_build.launcher import collect, pin_executable, pin_regular, system_runtime
from document_build.namespace import MOUNT, QUOTA
from document_build.process import admit_phase, drain_children, mount_command, private_pids

SUCCESS = 'NATIVE_REQUEST_EXECUTED_AND_CAPTURED_NOT_QUALIFICATION'
BOOTSTRAP = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
             "runpy.run_module('sentinel_v1.native_runtime',run_name='__main__')")


def _binary(path, expected):
    native_build.checked_pin_record(expected)
    path = Path(path).absolute()
    require('..' not in path.parts and len(os.fsencode(path)) <= 4096, 'binary path alias/byte bound')
    native_build.root_checked(path.parent)
    raw = native_build.read_regular(path.parent, path.name, 8388608)
    require(identity(raw) == expected, 'external held wire ELF mismatch')
    require(raw[:6] == b'\x7fELF\x02\x01', 'fixed ELF64 little-endian runtime profile')
    _elf_dependencies(raw)
    return path, raw


def _elf_dependencies(raw):
    require(len(raw) >= 64, 'complete ELF64 header')
    header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    offset, width, count = header[4], header[8], header[9]
    require(width == 56 and 1 <= count <= 128 and offset + width * count <= len(raw),
            'bounded ELF program headers')
    rows = [struct.unpack_from('<IIQQQQQQ', raw, offset + width * index) for index in range(count)]
    interpreters = [row for row in rows if row[0] == 3]
    dynamic = [row for row in rows if row[0] == 2]
    require(len(interpreters) == len(dynamic) == 1, 'fixed interpreter/dynamic profile')
    interpreter = interpreters[0]
    require(interpreter[2] + interpreter[5] <= len(raw) and
            raw[interpreter[2]:interpreter[2] + interpreter[5]] == b'/lib/ld-linux-aarch64.so.1\x00',
            'unsupported ELF interpreter')
    table = dynamic[0]
    require(table[5] <= 16384 and table[5] % 16 == 0 and table[2] + table[5] <= len(raw),
            'bounded dynamic table')
    tags, needed, ended = {}, [], False
    for index in range(table[5] // 16):
        tag, value = struct.unpack_from('<QQ', raw, table[2] + index * 16)
        if tag == 0:
            ended = True
            break
        if tag == 1:
            needed.append(value)
        elif tag in (5, 10):
            require(tag not in tags, 'duplicate dynamic string table')
            tags[tag] = value
    require(ended and set(tags) == {5, 10} and 0 < tags[10] <= 131072,
            'complete bounded dynamic strings')
    mappings = [row for row in rows if row[0] == 1 and row[3] <= tags[5] < row[3] + row[5]]
    require(len(mappings) == 1 and len(needed) == 2, 'fixed dynamic dependency profile')
    mapping = mappings[0]
    base = mapping[2] + tags[5] - mapping[3]
    require(base + tags[10] <= len(raw), 'dynamic strings inside ELF')
    names = []
    for index in needed:
        require(index < tags[10], 'dependency string offset')
        end = raw.find(b'\x00', base + index, base + tags[10])
        require(end >= 0 and end - base - index <= 64, 'bounded dependency basename')
        names.append(raw[base + index:end])
    require(names == [b'libc.so.6', b'ld-linux-aarch64.so.1'], 'undeclared native library dependency')


def _runtime_roster():
    result = {name: pin_executable(Path(name)) for name in
              ('/usr/bin/python3', '/usr/bin/unshare', '/usr/bin/mount')}
    result.update(system_runtime())
    # The fixed aarch64 ELF uses this interpreter and ordinary system libraries.
    for name in ('/lib/ld-linux-aarch64.so.1', '/usr/lib/libc.so.6'):
        result[name] = pin_regular(Path(name))
    require(len(result) <= 64, 'fixed/loaded runtime file count')
    return result


def _verify_runtime(roster):
    require(type(roster) is dict and 1 <= len(roster) <= 64, 'runtime roster bound')
    for name, expected in roster.items():
        require(canonical(pin_regular(Path(name))) == canonical(expected), 'runtime identity changed')


def _source_identity(root, expected):
    from .native import evaluator_sources
    require(canonical(evaluator_sources(root)) == canonical(expected), 'evaluator source epoch changed')


def _new_output(job_root):
    job_root = native_build.root_checked(job_root)
    info = job_root.stat()
    require(job_root.is_relative_to(Path('/dev/shm')) and info.st_uid == os.getuid()
            and info.st_mode & 0o777 == 0o700, 'private owned tmpfs runtime arena required')
    require(os.statvfs(job_root).f_bavail * os.statvfs(job_root).f_frsize >= 1073741824,
            'oneGiB shared-memory free reserve required')
    out = job_root / ('native-request-' + str(os.getpid()) + '-' + str(time.monotonic_ns()))
    out.mkdir(mode=0o700)
    (out / 'private').mkdir(mode=0o700)
    return out


def _configuration(wire, binary, binary_pin, out, sources, deadline):
    require(type(wire) is bytes and 0 < len(wire) <= 1048576, 'fixed native transcript bound')
    require(time.monotonic() + 103 <= deadline, 'runtime global admission/reserve')
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'owned pidfd required')
    descriptor = os.pidfd_open(os.getpid())
    os.close(descriptor)
    root = Path(__file__).resolve().parents[2]
    require(not out.is_relative_to(root) and not root.is_relative_to(out),
            'runtime output overlaps readonly source')
    _source_identity(root, sources)
    path, _raw = _binary(binary, binary_pin)
    with (out / 'request.stn1').open('xb') as stream:
        require(stream.write(wire) == len(wire), 'runtime input short write')
    return {'source_root': str(root), 'source_manifest': sources, 'binary_path': str(path),
        'binary_pin': binary_pin, 'input_pin': identity(wire), 'global_deadline': deadline,
        'parent_namespaces': {name: os.readlink('/proc/self/ns/' + name)
                              for name in ('user', 'mnt', 'pid', 'net')},
        'runtime_roster': _runtime_roster(), 'private_cap': 67108864,
        'external_cap': 100663296, 'own_cap': 201326592,
        'assumption': 'Trusted fixed repository/native/runtime/kernel; no hostile-host attestation.'}


def _abort_owned(process, descriptor):
    try:
        if descriptor is None:
            process.kill()
        else:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
    finally:
        process.wait(timeout=5)


def _parent(out, config):
    json_new(out / 'launch.json', config)
    argv = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--fork',
        '--mount-proc', '--net', '--propagation', 'private', '--kill-child=SIGKILL',
        '/usr/bin/python3', '-I', '-S', '-B', '-c', BOOTSTRAP,
        str(Path(config['source_root']) / 'tools'), str(out)]
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(out)}
    descriptor = None
    streams, failure, code = {'stdout': bytearray(), 'stderr': bytearray()}, None, None
    process = subprocess.Popen(argv, cwd=out, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        descriptor = os.pidfd_open(process.pid)
        code = collect(process, descriptor, config['global_deadline'], streams)
    except BaseException as error:
        _abort_owned(process, descriptor)
        if not isinstance(error, (MemoryError, OSError, ValueError, subprocess.SubprocessError)):
            raise
        failure = type(error).__name__ + ':' + str(error)[:4096]
    finally:
        if descriptor is not None:
            os.close(descriptor)
        process.stdout.close()
        process.stderr.close()
        for name, raw in streams.items():
            with (out / ('parent.' + name)).open('xb') as stream:
                require(stream.write(raw) == len(raw), 'runtime parent log short write')
    require(code == 0 and failure is None and process.returncode is not None,
            'runtime namespace failed; retained at ' + str(out))
    return argv


def _captured_bytes(out, captured, name, cap):
    require(captured['inventory'] == 'capture/inventory.json', 'fixed inventory path')
    inventory = json.loads(read_bytes(out / captured['inventory'], 1048576))
    require(type(inventory) is dict and inventory['complete_quiescent_census'] is True
            and inventory['readonly_qualified'] is True and inventory['readonly_observed'] is True,
            'captured inventory must be readonly and quiescent')
    rows = inventory['entries']
    require(type(rows) is list and len(rows) <= 4096, 'captured inventory bound')
    matches = [row for row in rows if row.get('path') == name and row.get('kind') == 'regular']
    require(len(matches) == 1, 'required captured payload missing')
    row = matches[0]
    require(type(row['bytes']) is int and 0 <= row['bytes'] <= cap, 'captured payload byte bound')
    payload = row['payload']
    require(type(payload) is str and len(payload) == 16 and payload.startswith('payload-')
            and payload[8:12].isascii() and payload[8:12].isdigit()
            and payload.endswith('.bin'), 'captured fixed payload basename')
    raw = read_bytes(out / 'capture' / payload, cap)
    require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
            'captured payload readback mismatch')
    return raw


def _run(wire, binary, binary_pin, job_root, sources, deadline):
    """Internal lifecycle. The public qualification API holds the job_slot lease."""
    limits()
    out = _new_output(job_root)
    config = _configuration(wire, binary, binary_pin, out, sources, deadline)
    argv = _parent(out, config)
    child = json.loads(read_bytes(out / 'namespace-result.json'))
    require(child['status'] == SUCCESS and child['readonly_qualified'] is True
            and child['capture']['complete'] is True and child['failures'] == [],
            'runtime failed; partial evidence retained at ' + str(out))
    require(type(child['cleanup']['remaining']) is int and child['cleanup']['remaining'] == 0
            and type(child['terminal_cleanup']['remaining']) is int
            and child['terminal_cleanup']['remaining'] == 0,
            'runtime owned children remain')
    _source_identity(Path(config['source_root']), sources)
    _verify_runtime(config['runtime_roster'])
    _binary(binary, binary_pin)
    require(usage(out) <= config['external_cap'] and time.monotonic() <= deadline,
            'runtime external bytes/global deadline')
    stdout = _captured_bytes(out, child['capture'], 'native.stdout', 2725)
    stderr = _captured_bytes(out, child['capture'], 'native.stderr', 4096)
    require(_captured_bytes(out, child['capture'], 'request.stn1', 1048576) == wire,
            'captured request differs from held request')
    require(identity(_captured_bytes(out, child['capture'], 'sentinel-wire', 8388608)) == binary_pin,
            'captured binary differs from held binary')
    receipt = {'schema': 'sentinel/native-runtime/1', 'status': SUCCESS,
        'argv': argv, 'namespace_result_pin': identity(read_bytes(out / 'namespace-result.json')),
        'input_pin': identity(wire), 'binary_pin': binary_pin, 'execution_authority': 'NONE'}
    json_new(out / 'receipt.json', receipt)
    return {'stdout': stdout, 'stderr': stderr, 'returncode': child['native']['returncode'],
            'receipt_pin': identity(read_bytes(out / 'receipt.json')), 'out': str(out)}


def run(wire, binary, binary_pin, job_root, sources, deadline):
    """Raw lifecycle only. No source-relative qualification is granted here."""
    with job_slot(Path(job_root)):
        return _run(wire, binary, binary_pin, job_root, sources, deadline)


def _mount(argv, logs, deadline):
    require(time.monotonic() + 10 <= deadline, 'mount phase admission')
    started = time.monotonic()
    mount_command(argv, logs, deadline)
    require(time.monotonic() - started <= 10 and time.monotonic() <= deadline,
            'late mount completion refused')


def _bind_readonly(path, out, deadline):
    _mount(MOUNT + ['--bind', str(path), str(path)], out, deadline)
    _mount(MOUNT + ['-o', 'remount,bind,ro,nodev,nosuid', str(path), str(path)], out, deadline)
    require(bool(os.statvfs(path).f_flag & os.ST_RDONLY), 'readonly source/runtime bind unavailable')


def _setup(config, out, work):
    require(os.getpid() == 1 and not private_pids(), 'private PID1/initial quiescence required')
    observed = {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'pid', 'net')}
    require(all(observed[name] != config['parent_namespaces'][name] for name in observed),
            'namespace separation unavailable')
    deadline = config['global_deadline'] - 93
    _mount(['/usr/bin/mount', '-n', '--make-rprivate', '/'], out, deadline)
    _mount(MOUNT + ['-t', 'tmpfs', '-o', QUOTA, 'sentinel-request', str(work)], out, deadline)
    fs = os.statvfs(work)
    require(fs.f_blocks * fs.f_frsize == 67108864 and fs.f_files == 4096, 'hard tmpfs quota unavailable')
    _bind_readonly(Path(config['source_root']), out, deadline)
    _bind_readonly(Path(config['binary_path']), out, deadline)
    runtime_paths = sorted({row['path'] for row in config['runtime_roster'].values()})
    require(len(runtime_paths) <= 64, 'readonly runtime bind roster bound')
    for path in runtime_paths:
        _bind_readonly(Path(path), out, deadline)
    _source_identity(Path(config['source_root']), config['source_manifest'])
    _verify_runtime(config['runtime_roster'])
    _path, raw = _binary(config['binary_path'], config['binary_pin'])
    with (work / 'sentinel-wire').open('xb') as stream:
        require(stream.write(raw) == len(raw), 'private ELF short write')
    (work / 'sentinel-wire').chmod(0o500)
    raw = read_bytes(out / 'request.stn1', 1048576)
    require(identity(raw) == config['input_pin'], 'runtime request changed')
    with (work / 'request.stn1').open('xb') as stream:
        require(stream.write(raw) == len(raw), 'private input short write')
    (work / 'request.stn1').chmod(0o400)
    return observed


def _native_limits():
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    bound = min([65536] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY])
    resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))


def _native(work, config):
    deadline = admit_phase(3, config['global_deadline'], 90)
    started, code = time.monotonic(), None
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(work)}
    with (work / 'request.stn1').open('rb') as stdin, (work / 'native.stdout').open('xb') as stdout:
        with (work / 'native.stderr').open('xb') as stderr:
            process = subprocess.Popen([str(work / 'sentinel-wire')], cwd=work, env=env,
                stdin=stdin, stdout=stdout, stderr=stderr, preexec_fn=_native_limits)
            for _ in range(302):
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    code = process.wait(timeout=1)
                    break
                if time.monotonic() >= min(deadline, started + 3):
                    break
                time.sleep(0.01)
    cleanup = drain_children()
    elapsed = time.monotonic() - started
    require(code is not None and elapsed <= 3 and time.monotonic() <= deadline,
            'native timeout or late completion')
    require(identity(read_bytes(work / 'request.stn1', 1048576)) == config['input_pin']
            and identity(read_bytes(work / 'sentinel-wire', 8388608)) == config['binary_pin'],
            'private executable/input changed')
    return {'returncode': code, 'elapsed_seconds': elapsed, 'seconds_bound': 3, 'cleanup': cleanup}


def _freeze(work, out, config, failures):
    readonly = False
    try:
        _mount(MOUNT + ['-t', 'tmpfs', '-o', 'remount,ro,' + QUOTA,
                       'sentinel-request', str(work)], out, config['global_deadline'] - 60)
        fs = os.statvfs(work)
        require(bool(fs.f_flag & os.ST_RDONLY) and fs.f_blocks * fs.f_frsize == 67108864
                and fs.f_files == 4096, 'readonly remount/quota failed')
        readonly = True
    except (OSError, ValueError) as error:
        failures.append('READONLY_REMOUNT_FAILED:' + str(error)[:4096])
    captured = snapshot(work, out, readonly)
    if not captured['complete']:
        failures.append('CAPTURE_INCOMPLETE:' + captured.get('failure', 'unknown'))
    return readonly, captured


def _execute(work, out, config):
    failures, native = [], None
    try:
        native = _native(work, config)
    except (MemoryError, OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(type(error).__name__ + ':' + str(error)[:4096])
    cleanup = drain_children()
    try:
        _source_identity(Path(config['source_root']), config['source_manifest'])
        _verify_runtime(config['runtime_roster'])
        _binary(config['binary_path'], config['binary_pin'])
    except (MemoryError, OSError, ValueError) as error:
        failures.append('IDENTITY_AFTER_FAILED:' + str(error)[:4096])
    readonly, captured = _freeze(work, out, config, failures)
    return {'status': SUCCESS if not failures else 'FAILED', 'failures': failures,
        'native': native, 'cleanup': cleanup, 'readonly_qualified': readonly, 'capture': captured,
        'external_bytes': usage(out, work), 'execution_authority': 'NONE'}


def main():
    limits()
    require(len(sys.argv) == 3, 'fixed internal runtime argv')
    out = Path(sys.argv[2])
    config = json.loads(read_bytes(out / 'launch.json'))
    work = out / 'private'
    baseline, setup_complete = work.stat().st_dev, False
    record = {'status': 'FAILED', 'failures': ['runtime setup incomplete']}
    try:
        observed = _setup(config, out, work)
        setup_complete = True
        record = _execute(work, out, config)
        record['namespaces'] = observed
    except (MemoryError, OSError, ValueError, subprocess.SubprocessError) as error:
        record['failures'] = [type(error).__name__ + ':' + str(error)[:4096]]
        record['failure_stage'] = 'EXECUTE_OR_CAPTURE' if setup_complete else 'SETUP'
        record['capture_retry_performed'] = False
        drain_children()
        if not setup_complete and work.stat().st_dev != baseline:
            readonly, captured = _freeze(work, out, config, record['failures'])
            record.update({'readonly_qualified': readonly, 'capture': captured})
    finally:
        record['terminal_cleanup'] = drain_children()
        try:
            json_new(out / 'namespace-result.json', record)
        except (MemoryError, OSError, ValueError) as error:
            print('RUNTIME_TERMINAL_RECORD_LOST:' + str(error)[:4096], file=sys.stderr)
            record['status'] = 'FAILED'
            record['terminal_record_lost'] = True
    return 0 if record['status'] == SUCCESS else 2


if __name__ == '__main__':
    sys.exit(main())
