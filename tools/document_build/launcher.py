"""Create-only developer interface; unavailable isolation is a terminal refusal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from .common import EXTERNAL_CAP, META_CAP, OUTER_SECONDS, PRIVATE_CAP
from .common import bounded_names, digest, directory, json_new, limits, need, read_bytes, usage
from .proof import source_gate

BOOTSTRAP = "import runpy,sys;sys.path.insert(0,sys.argv[1]);runpy.run_module('document_build.namespace',run_name='__main__')"


def pin_regular(path):
    path = path.resolve(strict=True)
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= 268_435_456, 'executable size/type bound')
    hashed = hashlib.sha256()
    with path.open('rb') as stream:
        for _ in range(4097):
            block = stream.read(65536)
            if not block:
                break
            hashed.update(block)
        need(stream.read(1) == b'', 'executable read bound')
    after = path.stat()
    need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'executable changed')
    return {'path': str(path), 'sha256': hashed.hexdigest(), 'bytes': info.st_size}



def pin_executable(path):
    need(os.access(path, os.X_OK), 'executable permission required')
    return pin_regular(path)


def compiler_runtime(tools):
    compiler_root = Path(tools['gcc']).parent.parent
    result = {}
    for branch in ('libexec/gcc', 'lib/gcc'):
        targets = bounded_names(compiler_root / branch, 8)
        need(len(targets) == 1, 'one declared compiler target required')
        versions = bounded_names(targets[0], 8)
        need(len(versions) == 1, 'one declared compiler runtime version required')
        version = versions[0]
        if branch == 'libexec/gcc':
            path = version / 'gnat1'
            result[str(path.relative_to(compiler_root))] = pin_executable(path)
        else:
            for name in ('adalib', 'adainclude'):
                files = bounded_names(version / name, 2048)
                for path in files:
                    need(path.resolve(strict=True).is_relative_to(compiler_root), 'runtime symlink escape')
                    if path.is_file():
                        result[str(path.relative_to(compiler_root))] = pin_regular(path)
    return result


def system_runtime():
    with open('/proc/self/maps', 'rb') as stream:
        maps = stream.read(1_048_577)
    need(len(maps) <= 1_048_576, 'system mapping read bound')
    paths = set()
    for line in maps.decode('utf8').splitlines():
        columns = line.split()
        if len(columns) == 6 and columns[5].startswith(('/usr/lib/', '/lib/')):
            paths.add(columns[5])
    need(len(paths) <= 64, 'loaded system-library bound')
    return {name: pin_regular(Path(name)) for name in sorted(paths)}

def discover_toolchain(root):
    if root is None:
        paths = [shutil.which(name) for name in ('gprbuild', 'gnatprove', 'gcc')]
        need(all(paths), 'existing gprbuild, gnatprove and GCC required; use --toolchain-root')
        root = Path(os.path.commonpath([str(Path(path).resolve().parent.parent) for path in paths]))
        need(root != Path('/'), 'unbounded toolchain root refused; provide one existing GNAT root')
    root = directory(root.absolute())
    children = bounded_names(root, 32)
    need(len(children) <= 32, 'toolchain top-level entry bound')
    bins = [path / 'bin' for path in children if path.is_dir() and not path.is_symlink() and (path / 'bin').is_dir()]
    if (root / 'bin').is_dir():
        bins.append(root / 'bin')
    need(len(bins) <= 16, 'toolchain bin bound')
    tools, pins = {}, {}
    for name in ('gprbuild', 'gnatprove', 'gcc'):
        found = [path / name for path in bins if (path / name).is_file()]
        need(len(found) == 1, 'unique existing tool required: ' + name)
        real = found[0].resolve(strict=True)
        need(real.is_relative_to(root), 'tool outside supplied toolchain refused')
        tools[name], pins[name] = str(real), pin_executable(real)
    prover_root = Path(tools['gnatprove']).parent.parent
    z3 = prover_root / 'libexec/spark/bin/z3'
    need(z3.resolve(strict=True).is_relative_to(root), 'prover outside supplied root')
    tools['z3'], pins['z3'] = str(z3), pin_executable(z3)
    gpr = prover_root / 'lib/gnat'
    need(gpr.is_dir(), 'existing SPARK project directory required')
    return {'toolchain_root': str(root), 'bins': [str(path) for path in sorted(bins)],
            'tools': tools, 'tool_pins': pins, 'compiler_runtime_pins': compiler_runtime(tools),
            'system_runtime_pins': system_runtime(), 'gpr_path': str(gpr)}


def source_pins(root):
    result = {}
    for folder in ('src', 'document_native', 'tools/document_build'):
        names = bounded_names(root / folder, 128)
        need(len(names) <= 128, 'source entry bound')
        for path in sorted(names):
            if path.suffix in ('.ads', '.adb', '.gpr', '.py'):
                need(path.is_file() and not path.is_symlink(), 'source symlink/special refused')
                result[str(path.relative_to(root))] = digest(path)
    result['tools/build_document_decoder.py'] = digest(root / 'tools/build_document_decoder.py')
    source_gate(root)
    return result


def preflight(args):
    root = directory(args.source_root.absolute())
    need((root / 'document_native/document_native.gpr').is_file(), 'fixed document GPR required')
    out = args.out.absolute()
    directory(out.parent)
    need('..' not in out.parts and out.is_relative_to(Path('/dev/shm')) and out != Path('/dev/shm'), 'all output must be in /dev/shm')
    need(not out.exists() and not out.is_symlink(), 'create-only output directory required')
    need(os.statvfs('/dev/shm').f_bavail * os.statvfs('/dev/shm').f_frsize >= 1_073_741_824,
         'shared-memory one-GiB free reserve required')
    need(PRIVATE_CAP + EXTERNAL_CAP <= 201_326_592, 'private plus external exceeds own 192MiB budget')
    need(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd support required')
    descriptor = os.pidfd_open(os.getpid())
    os.close(descriptor)
    config = discover_toolchain(args.toolchain_root)
    config.update({'source_root': str(root), 'source_pins': source_pins(root),
                   'parent_namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'pid', 'net')},
                   'runtime_pins': {name: pin_executable(Path(name)) for name in
                                    ('/usr/bin/python3', '/usr/bin/unshare', '/usr/bin/mount')},
                   'private_cap': PRIVATE_CAP, 'external_cap': EXTERNAL_CAP, 'outer_seconds': OUTER_SECONDS})
    return root, out, config


def collect(proc, descriptor, deadline, data):
    try:
        with selectors.DefaultSelector() as selector:
            for name in data:
                stream = getattr(proc, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            for _ in range(OUTER_SECONDS * 20 + 2):
                if not selector.get_map():
                    break
                need(time.monotonic() < deadline, 'outer wall deadline')
                for key, _mask in selector.select(0.05):
                    block = os.read(key.fd, min(65536, 1_048_577 - len(data[key.data])))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        data[key.data].extend(block)
                        need(len(data[key.data]) <= 1_048_576, 'parent stream bound')
            else:
                raise ValueError('outer observation iteration bound')
        return proc.wait(timeout=max(0.001, deadline - time.monotonic()))
    except BaseException:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()


def launch(root, out, config):
    config['global_deadline'] = time.monotonic() + OUTER_SECONDS
    config['trust_boundary'] = 'TRUSTED repository, toolchain, kernel and cooperative GNAT tools; no hostile-child capability/storage sandbox claim'
    out.mkdir(mode=0o700)
    (out / 'private').mkdir(mode=0o700)
    json_new(out / 'launch.json', config)
    argv = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--fork',
            '--mount-proc', '--net', '--propagation', 'private', '--kill-child=SIGKILL',
            '/usr/bin/python3', '-I', '-S', '-B', '-c', BOOTSTRAP, str(root / 'tools'), str(out)]
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(out), 'TMPDIR': str(out)}
    data, failure, code = {'stdout': bytearray(), 'stderr': bytearray()}, None, None
    limits()
    proc = subprocess.Popen(argv, cwd=out, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        descriptor = os.pidfd_open(proc.pid)
    except OSError:
        proc.kill()  # Unreaped direct child: owned PID cannot have been reused.
        proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()
        raise
    try:
        code = collect(proc, descriptor, config['global_deadline'], data)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ':' + str(error)[:4096]
    finally:
        os.close(descriptor)
        for name, raw in data.items():
            with (out / ('parent.' + name)).open('xb') as stream:
                need(stream.write(raw) == len(raw), 'parent output short write')
    result = {'status': 'FAILED', 'returncode': code, 'failure': failure, 'argv': argv,
              'namespace_waited': proc.returncode is not None, 'external_bytes': usage(out)}
    terminal = out / 'namespace-result.json'
    if code == 0 and failure is None and terminal.is_file():
        namespace = json.loads(read_bytes(terminal))
        need(namespace['status'] == 'BUILT_AND_LEDGER_PROOF_CHECKED' and namespace['readonly_qualified'],
             'terminal namespace qualification refused')
        need(source_pins(root) == config['source_pins'], 'source epoch changed')
        result['status'] = 'BUILT_AND_LEDGER_PROOF_CHECKED'
    json_new(out / 'receipt.json', result)
    need(result['status'] == 'BUILT_AND_LEDGER_PROOF_CHECKED', 'build refused/failed; exact evidence retained at ' + str(out))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--toolchain-root', type=Path)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root, out, config = preflight(args)
    result = launch(root, out, config)
    print(json.dumps(result, sort_keys=True))
