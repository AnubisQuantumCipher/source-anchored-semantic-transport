"""Versioned PID-namespace lifecycle adapter; shares the existing decoder core.

The atomic pidfd bridge controls only the fixed namespace monitor. This does
not prove host scheduling, arbitrary-code sandboxing, or semantic fidelity.
"""
import ctypes
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import sys
import time

NAMESPACES = ('pid', 'user', 'mnt', 'net')
UNSHARE = ('/usr/bin/unshare', '42578868785842e688633143b40a95f79a490aeab4af018571d359f8fe132009')
PYTHON = ('/usr/bin/python3.14', 'c6bc1ef497b896b7575c546b13f9bafe52e2066f184fdd3fec6af4b5b6349947')
BRIDGE_SHA = 'fccd913d85185ffbad34148c5c001bc580410208a42811926696946ea6aa1aeb'
BRIDGE_CAP = 262144
BRIDGE_SOURCE_SHA = '5250fd6d40dd9402768f73ea9b1b508631c55a1fe4049f0e40ea8d9b0b19375d'
HOST_LIBRARIES = (
    ('/usr/lib/libc.so.6', '6ab264fb4e8df9942b0fb75b48fcd5c30b2f081d8dfaa6c25d7be1d3fce5b2ab'),
    ('/usr/lib/ld-linux-aarch64.so.1', 'b1f2738bdb51e6419d7062f96c8a44bd68853698dc5ac624fa6ca9f9b03d456d'),
    ('/usr/lib/libpython3.14.so.1.0', '7e88cb35da4d8fc0fd4c3f595483f98765ee59e23ef43d9eb3ebd1e1c5432c65'),
    ('/usr/lib/libm.so.6', '71ed8de709c40acd4fd0177258fc71251a5acdb1d075122409ad42529d6c7a4e'))


def runtime_dependencies():
    """Exact declared files plus explicit trusted-host boundary; never fetch."""
    owned, host = [], {}
    base = Path(__file__).resolve().parent
    try:
        for path, expected in (UNSHARE, PYTHON, *HOST_LIBRARIES):
            held_file(path, expected, core.NATIVE_CAP, owned)
            host[path] = expected
        held_file(base / 'transport_document_pidfd.so', BRIDGE_SHA, BRIDGE_CAP, owned)
        held_file(base / 'transport_document_pidfd.c', BRIDGE_SOURCE_SHA, 32768, owned)
        return {'profile': 'transport/document-containment/1', 'host_files': host,
                'bundle_files': {'transport_document_pidfd.so': BRIDGE_SHA,
                                 'transport_document_pidfd.c': BRIDGE_SOURCE_SHA},
                'assumptions': ['trusted Linux kernel with user/PID/mount/network namespaces and pidfds',
                                'trusted declared Python standard library and extension dependencies',
                                'no hostile mutation of the embedding process or its descriptors'],
                'transitive_host_attestation': 'NOT_PROVIDED'}
    finally:
        close_phase(owned, tuple(owned))


def load_core():
    if __name__ != '__main__':
        import transport_document_supervisor
        return transport_document_supervisor
    spec = importlib.util.spec_from_loader('transport_document_supervisor', loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = '/proc/self/fd/3'
    raw = os.pread(3, 65537, 0)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != sys.argv[3]:
        raise ValueError('contained core source identity')
    sys.modules[spec.name] = module
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


core = load_core()
SupervisorError = core.SupervisorError


def held_file(path, expected, cap, owned):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    owned.append(fd)
    core.need(core.descriptor_hash(fd, cap)[0] == expected, 'contained dependency identity')
    return fd


def bridge(owned, launch):
    path = Path(__file__).with_name('transport_document_pidfd.so')
    fd = held_file(path, BRIDGE_SHA, BRIDGE_CAP, owned)
    launch['dependencies'].append((fd, BRIDGE_CAP, core.descriptor_hash(fd, BRIDGE_CAP)))
    library = ctypes.CDLL('/proc/self/fd/' + str(fd), use_errno=True)
    call = library.sast_pidfd_spawn
    call.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                     ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t)
    call.restype = ctypes.c_int
    return library, call


def arguments(own, expected, size, deadline, parent):
    args = ['/proc/self/fd/8', '--user', '--map-root-user', '--mount', '--pid',
            '--fork', '--mount-proc', '--net', '--propagation', 'private',
            '--kill-child=SIGKILL', '/proc/self/fd/9', '-I', '-S', '-B']
    if sys.flags.optimize:
        args.append('-O')
    args += ['/proc/self/fd/10', '--contained-decoder-v1', SOURCE_EPOCH, own,
             expected, str(size), str(deadline)]
    args += [parent[name] for name in NAMESPACES]
    encoded = [arg.encode('ascii') for arg in args]
    core.need(len(encoded) <= 48 and sum(map(len, encoded)) <= 8192 and
              all(len(arg) <= 512 and b'\0' not in arg for arg in encoded), 'spawn argv bounds')
    return encoded


def channels(owned, launch):
    for key in ('cancel', 'result', 'error'):
        read, write = os.pipe2(os.O_CLOEXEC)
        owned.extend((read, write))
        launch[key] = write if key == 'cancel' else read
        launch[key + '_child'] = read if key == 'cancel' else write


def close_phase(owned, selected):
    failure = sys.exception()
    try:
        core.close_batch(owned, selected)
    except OSError as error:
        if failure is None:
            raise
        failure.add_note('contained launch descriptor cleanup failed: ' + str(error))


def launch_atomic(sources, args, owned, launch):
    library, call = bridge(owned, launch)
    owner = (ctypes.c_int * 1)(-1)
    # Registered BEFORE libc creates the process, including exception handoff.
    launch['pid'] = owner
    launch['library'] = library
    duplicates = []
    try:
        for fd in sources:
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 32)
            owned.append(duplicate); duplicates.append(duplicate)
        fds = (ctypes.c_int * 11)(*duplicates)
        argv = (ctypes.c_char_p * (len(args) + 1))(*args, None)
        old = signal.pthread_sigmask(signal.SIG_BLOCK, (*core.TERMINATION, signal.SIGALRM))
        try:
            code = call(owner, fds, argv, len(args))
            if code != 0:
                raise OSError(code, 'atomic monitor spawn refused')
            core.need(owner[0] >= 0, 'spawn returned no stable handle')
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
    finally:
        close_phase(owned, duplicates)


def spawn_owner(native_fd, wire_fd, output_fd, expected, size, deadline, owned, launch):
    module = held_file(core.__file__, core.SOURCE_EPOCH, core.SOURCE_CAP, owned)
    own = held_file(__file__, SOURCE_EPOCH, core.SOURCE_CAP, owned)
    unshare = held_file(UNSHARE[0], UNSHARE[1], 1048576, owned)
    python = held_file(PYTHON[0], PYTHON[1], core.NATIVE_CAP, owned)
    launch.update(module=module, held=core.descriptor_hash(module, core.SOURCE_CAP))
    launch['dependencies'] = [(fd, cap, core.descriptor_hash(fd, cap)) for fd, cap in
                              ((own, core.SOURCE_CAP), (unshare, 1048576), (python, core.NATIVE_CAP))]
    channels(owned, launch)
    null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    owned.append(null)
    sources = (null, launch['result_child'], launch['error_child'], module,
               native_fd, wire_fd, output_fd, launch['cancel_child'], unshare, python, own)
    parent = {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES}
    args = arguments(core.SOURCE_EPOCH, expected, size, deadline, parent)
    try:
        launch_atomic(sources, args, owned, launch)
    finally:
        close_phase(owned, (null, launch['cancel_child'], launch['result_child'],
                            launch['error_child']))


def wait_handle(owner, state):
    core.need(owner[0] >= 0 and not state['wait_lost'], 'monitor wait ownership lost')
    try:
        observed = os.waitid(os.P_PIDFD, owner[0], os.WEXITED | os.WNOHANG)
    except ChildProcessError:
        state['wait_lost'] = True
        raise
    if observed is not None:
        state['exit'] = observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status


def collect_owner(owner, streams, deadline, state, discard=False):
    core.need(owner[0] >= 0, 'monitor not created')
    with selectors.DefaultSelector() as selector:
        for name, fd in streams.items():
            if not state[name + '_eof']:
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_READ, name)
        for _ in range(core.ITERATIONS):
            left = deadline - time.monotonic_ns()
            core.need(left > 0, 'contained completion deadline')
            for event, _mask in selector.select(min(left / 1000000000, 0.05)):
                name = event.data
                try:
                    cap = core.RESULT_CAP if discard else core.RESULT_CAP + 1 - len(state[name])
                    block = os.read(event.fd, cap)
                except BlockingIOError:
                    continue
                if not block:
                    state[name + '_eof'] = True; selector.unregister(event.fd)
                elif not discard:
                    state[name].extend(block)
                    core.need(len(state[name]) <= core.RESULT_CAP, 'contained channel bound')
            if state['result_eof'] and state['error_eof']:
                wait_handle(owner, state)
                if state['exit'] is not None:
                    return
    raise SupervisorError('contained completion iteration bound')


def cancellation_reap(owner, streams, state):
    if owner[0] < 0:
        return 'NOT_CREATED'
    try:
        signal.pidfd_send_signal(owner[0], signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        return 'UNKNOWN:stable-handle signal:' + type(error).__name__
    if state['wait_lost']:
        return 'UNKNOWN:monitor wait ownership lost; stable target killed; no wait retry'
    try:
        # Missing channels can only occur in a failed launch. Never acceptance.
        for name in ('result', 'error'):
            if name not in streams:
                state[name + '_eof'] = True
        collect_owner(owner, streams, time.monotonic_ns() + core.CLEANUP_NS, state, discard=True)
        return 'OBSERVED_EXIT_' + str(state['exit'])
    except BaseException as error:
        return 'UNKNOWN:' + type(error).__name__ + ':' + str(error)[:128]


def close_handle(launch):
    owner = launch.get('pid')
    if owner is not None and owner[0] >= 0:
        fd, owner[0] = owner[0], -1
        os.close(fd)


def verify_dependencies(launch):
    dependencies = launch.get('dependencies')
    core.need(type(dependencies) is list and len(dependencies) == 4, 'contained dependency roster')
    core.need(all(type(row) is tuple and len(row) == 3 for row in dependencies), 'dependency row')
    core.need(len({row[0] for row in dependencies}) == 4 and
              [row[1] for row in dependencies] == [core.SOURCE_CAP, 1048576, core.NATIVE_CAP, BRIDGE_CAP],
              'contained dependency roles')
    for fd, cap, held in dependencies:
        core.need(core.descriptor_hash(fd, cap) == held, 'contained dependency changed during exec')


def run(native_fd, wire_fd, output_fd, expected_native_sha256, output_limit):
    return core.run_profile(native_fd, wire_fd, output_fd, expected_native_sha256,
                            output_limit, sys.modules[__name__])


def check_namespace():
    core.need(len(sys.argv) == 11 and sys.argv[1] == '--contained-decoder-v1', 'contained argv')
    core.need(sys.argv[2] == SOURCE_EPOCH and
              core.descriptor_hash(10, core.SOURCE_CAP)[0] == SOURCE_EPOCH, 'contained source')
    core.need(os.getpid() == 1 and os.readlink('/proc/self') == '1', 'private PID1 required')
    for name, old in zip(NAMESPACES, sys.argv[7:], strict=True):
        current = os.readlink('/proc/self/ns/' + name)
        core.need(old.startswith(name + ':[') and old.endswith(']') and old != current,
                  'namespace separation refused')
    core.need(os.readlink('/proc/1/ns/pid') == os.readlink('/proc/self/ns/pid'), 'private proc view')
    for fd in (8, 9, 10):
        os.close(fd)


def main():
    check_namespace()
    sys.argv = ['/proc/self/fd/3', '--owned-decoder-v1', *sys.argv[3:7]]
    return core.main()


SOURCE_EPOCH = core.loaded_source(__file__, sys._getframe().f_code)

if __name__ == '__main__':
    sys.exit(main())
