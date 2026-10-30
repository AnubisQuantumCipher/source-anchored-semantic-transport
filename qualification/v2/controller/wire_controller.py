"""Prepared fixed wire qualification launcher. Separate owner dispatch admission required."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

# This staged controller imports only the caller-held repository and its own pinned siblings.
CONTROLLER = Path(__file__).resolve().parent
SUCCESS = 'SENTINEL_WIRE_BUILD_AND_FROZEN_CONTROLS_CHECKED'
BOOTSTRAP = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
             "sys.path.insert(0,sys.argv[1]+'/../sentinel_native');"
             "sys.path.insert(0,sys.argv[2]);runpy.run_module('wire_worker',run_name='__main__')")


def dependencies(root):
    sys.path.insert(0, str(root / 'tools'))
    sys.path.insert(0, str(root / 'sentinel_native'))
    sys.path.insert(0, str(CONTROLLER))


def pins(path, expected):
    from document_build.common import need, read_bytes
    raw = read_bytes(path, 1048576)
    need(hashlib.sha256(raw).hexdigest() == expected, 'caller-held input roster changed')
    value = json.loads(raw)
    need(type(value) is dict and set(value) == {'schema', 'native', 'oracle', 'controller'},
         'exact qualification input roster schema')
    need(value['schema'] == 'sentinel/wire-qualification-inputs/1', 'input roster version')
    for label, cap in (('native', 11), ('oracle', 64), ('controller', 3)):
        rows = value[label]
        need(type(rows) is dict and 1 <= len(rows) <= cap, 'input roster cardinality')
        for name, digest in rows.items():
            need(type(name) is str and Path(name).name == name and type(digest) is str
                 and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
                 'input roster basename/digest')
    return value


def preflight(args):
    from document_build.common import directory, limits, need, read_bytes
    from document_build.launcher import discover_toolchain, pin_executable, source_pins
    from sentinel_qualification import source_gate
    from wire_checks import oracle_files
    root = directory(args.source_root.absolute())
    oracle = directory(args.oracle_root.absolute())
    out = args.out.absolute()
    directory(out.parent, owned=True)
    need(out.is_relative_to(Path('/dev/shm')) and out != Path('/dev/shm') and
         '..' not in out.parts and not out.exists() and not out.is_symlink(), 'private create-only tmpfs output')
    need(all(not out.is_relative_to(path) and not path.is_relative_to(out)
             for path in (root, oracle, CONTROLLER)), 'output overlaps readonly inputs')
    need(os.statvfs('/dev/shm').f_bavail * os.statvfs('/dev/shm').f_frsize >= 1073741824,
         'oneGiB shared-memory reserve required')
    held = pins(args.pins.absolute(), args.pins_sha256)
    actual_native = source_gate(root)
    for name, expected in held['native'].items():
        need(actual_native.get('sentinel_native/' + name) == expected, 'held native source mismatch')
    need(set(held['native']) == {'sentinel_policy.ads', 'sentinel_policy.adb',
        'sentinel_policy.gpr', 'sentinel_policy_proof.gpr', 'sentinel_policy_checks.adb',
        'sentinel_policy_fixtures.ads', 'sentinel_policy_fixtures.adb', 'sentinel_wire_io.ads',
        'sentinel_wire_io.adb', 'sentinel_wire_main.adb', 'sentinel_wire.gpr'}, 'fixed11 native inputs')
    files, _cases = oracle_files(oracle)
    need(files == held['oracle'], 'held oracle roster mismatch')
    need(set(held['controller']) == {'wire_checks.py', 'wire_worker.py', 'wire_controller.py'},
         'fixed controller roster')
    for name, expected in held['controller'].items():
        need(hashlib.sha256(read_bytes(CONTROLLER / name, 131072)).hexdigest() == expected, 'controller changed')
    config = discover_toolchain(args.toolchain_root)
    config.update({'source_root': str(root), 'source_pins': source_pins(root),
        'native_pins': actual_native, 'oracle_root': str(oracle), 'oracle_pins': files,
        'controller_root': str(CONTROLLER), 'controller_pins': held['controller'],
        'parent_namespaces': {name: os.readlink('/proc/self/ns/' + name)
                              for name in ('user', 'mnt', 'pid', 'net')},
        'runtime_pins': {name: pin_executable(Path(name)) for name in
                         ('/usr/bin/python3', '/usr/bin/unshare', '/usr/bin/mount')},
        'private_cap': 67108864, 'external_cap': 100663296, 'outer_seconds': 450,
        'held_input_roster_sha256': args.pins_sha256})
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd support required')
    descriptor = os.pidfd_open(os.getpid()); os.close(descriptor)
    limits()
    return root, out, config


def launch(root, out, config):
    from document_build.common import json_new, need, read_bytes, usage
    from document_build.launcher import collect, source_pins
    from sentinel_qualification import source_gate
    config['global_deadline'] = time.monotonic() + 450
    config['trust_boundary'] = 'Trusted repository/controller/toolchain/kernel; no hostile-host attestation.'
    out.mkdir(mode=0o700); (out / 'private').mkdir(mode=0o700)
    json_new(out / 'launch.json', config)
    argv = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--fork',
        '--mount-proc', '--net', '--propagation', 'private', '--kill-child=SIGKILL',
        '/usr/bin/python3', '-I', '-S', '-B', '-c', BOOTSTRAP,
        str(root / 'tools'), str(CONTROLLER), str(out)]
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(out)}
    process = subprocess.Popen(argv, cwd=out, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        descriptor = os.pidfd_open(process.pid)
    except OSError:
        process.kill(); process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()
        raise
    streams, failure, code = {'stdout': bytearray(), 'stderr': bytearray()}, None, None
    try:
        code = collect(process, descriptor, config['global_deadline'], streams)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ':' + str(error)[:4096]
    finally:
        os.close(descriptor)
        for name, raw in streams.items():
            with (out / ('parent.' + name)).open('xb') as stream:
                need(stream.write(raw) == len(raw), 'parent short write')
    result = {'status': 'FAILED', 'returncode': code, 'failure': failure,
        'namespace_waited': process.returncode is not None, 'external_bytes': usage(out), 'argv': argv}
    try:
        child = json.loads(read_bytes(out / 'namespace-result.json'))
        need(code == 0 and failure is None and child['status'] == SUCCESS and
             child['readonly_qualified'] and child['capture']['complete'], 'terminal qualification refused')
        need(source_gate(root) == config['native_pins'] and
             source_pins(root) == config['source_pins'], 'final source changed')
        result['status'] = SUCCESS
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        result['failure'] = type(error).__name__ + ':' + str(error)[:4096]
    json_new(out / 'receipt.json', result)
    need(result['status'] == SUCCESS, 'wire qualification failed; all available evidence retained')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'source-root', 'oracle-root', 'toolchain-root', 'pins'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--pins-sha256', required=True)
    args = parser.parse_args()
    dependencies(args.source_root.absolute())
    try:
        root, out, config = preflight(args)
        print(json.dumps(launch(root, out, config), sort_keys=True))
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('WIRE_QUALIFICATION_REFUSED:' + str(error)[:4096], file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
