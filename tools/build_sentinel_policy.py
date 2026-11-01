"""Fixed local policy qualification; supplied documents never select executables."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sentinel_native'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from document_build.common import (OUTER_SECONDS, directory, json_new, limits,
                                   need, read_bytes, usage)
from document_build.launcher import (collect, discover_toolchain, pin_executable,
                                    pin_regular, source_pins)
from sentinel_qualification import checked_roster, source_gate

SUCCESS = 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED'
BOOTSTRAP = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
             "sys.path.insert(0,sys.argv[2]);runpy.run_module('sentinel_build_profile',run_name='__main__')")


def preflight(args):
    root = directory(args.source_root.absolute())
    out = args.out.absolute()
    directory(out.parent, owned=True)
    need(out.is_relative_to(Path('/dev/shm')) and out != Path('/dev/shm') and
         '..' not in out.parts and not out.exists() and not out.is_symlink(), 'private create-only tmpfs output')
    need(os.statvfs('/dev/shm').f_bavail * os.statvfs('/dev/shm').f_frsize >= 1073741824,
         'one GiB shared-memory reserve required')
    roster_path = args.roster.absolute()
    directory(roster_path.parent)
    roster = checked_roster(root, roster_path, args.roster_sha256)
    config = discover_toolchain(args.toolchain_root)
    config.update({'source_root': str(root), 'source_pins': source_pins(root),
        'sentinel_source_pins': source_gate(root), 'proof_roster': roster,
        'parent_namespaces': {name: os.readlink('/proc/self/ns/' + name)
                              for name in ('user', 'mnt', 'pid', 'net')},
        'runtime_pins': {name: pin_executable(Path(name)) for name in
                         ('/usr/bin/python3', '/usr/bin/unshare', '/usr/bin/mount')},
        'private_cap': 67108864, 'external_cap': 100663296, 'outer_seconds': OUTER_SECONDS})
    config['runtime_pins']['caller-held-proof-roster'] = pin_regular(roster_path)
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd support required')
    descriptor = os.pidfd_open(os.getpid()); os.close(descriptor)
    return root, out, config


def launch(root, out, config):
    config['global_deadline'] = time.monotonic() + OUTER_SECONDS
    config['trust_boundary'] = 'Trusted repository, tools, kernel and cooperative GNAT; no hostile-host attestation.'
    out.mkdir(mode=0o700); (out / 'private').mkdir(mode=0o700)
    json_new(out / 'launch.json', config)
    argv = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--fork',
            '--mount-proc', '--net', '--propagation', 'private', '--kill-child=SIGKILL',
            '/usr/bin/python3', '-I', '-S', '-B', '-c', BOOTSTRAP,
            str(root / 'tools'), str(root / 'sentinel_native'), str(out)]
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(out), 'TMPDIR': str(out)}
    limits()
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
                need(stream.write(raw) == len(raw), 'parent output short write')
    result = {'status': 'FAILED', 'returncode': code, 'failure': failure, 'argv': argv,
              'namespace_waited': process.returncode is not None, 'external_bytes': usage(out)}
    terminal = out / 'namespace-result.json'
    try:
        need(code == 0 and failure is None and terminal.is_file(), 'missing successful terminal')
        child = json.loads(read_bytes(terminal))
        need(child['status'] == SUCCESS and child['readonly_qualified'] and child['capture']['complete'],
             'terminal qualification refused')
        need(source_gate(root) == config['sentinel_source_pins'] and
             source_pins(root) == config['source_pins'], 'source epoch changed')
        result['status'] = SUCCESS
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        result['failure'] = type(error).__name__ + ':' + str(error)[:4096]
    json_new(out / 'receipt.json', result)
    need(result['status'] == SUCCESS, 'SENTINEL build refused; retained at ' + str(out))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--roster', type=Path, required=True)
    parser.add_argument('--roster-sha256', required=True)
    parser.add_argument('--toolchain-root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        root, out, config = preflight(args)
        print(json.dumps(launch(root, out, config), sort_keys=True))
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        print('SENTINEL_BUILD_REFUSED:' + str(error)[:4096], file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
