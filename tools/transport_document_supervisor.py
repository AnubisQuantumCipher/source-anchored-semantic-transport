"""Pinned exec owner for document decoder children; never an authority engine.

The embedding caller cancels through pipe EOF and never signals numeric IDs.
Only the fresh single-thread supervisor owns the decoder's wait status. This
does not contain descendants after an uncatchable supervisor death.
"""
import fcntl
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

SCHEMA = 'transport/document-supervisor-result/1'
FIELDS = ('schema', 'status', 'reason', 'child_exit', 'diagnostic', 'cleanup')
REASONS = ('NONE', 'CANCELLED', 'TIMEOUT', 'DIAGNOSTIC', 'NONZERO', 'STDERR_LIMIT',
           'OWNERSHIP', 'SPAWN', 'PROTOCOL', 'RESOURCE', 'INTERNAL')
SOURCE_CAP = 65536
NATIVE_CAP = 16777216
WIRE_CAP = 4294967296
OUTPUT_CAP = 1073741824
RESULT_CAP = 4096
ITERATIONS = 8192
WALL_NS = 120000000000
CLEANUP_NS = 5000000000
TERMINATION = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class SupervisorError(ValueError):
    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


def need(condition, message):
    if condition is not True:
        raise SupervisorError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate result field')
        result[key] = value
    return result


def no_number(_value):
    raise SupervisorError('noninteger result number')


def checked_result(raw):
    need(type(raw) is bytes and 0 < len(raw) <= RESULT_CAP, 'result byte bound')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_float=no_number,
                           parse_constant=no_number)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SupervisorError('invalid result JSON') from error
    need(type(value) is dict and set(value) == set(FIELDS), 'result fields')
    need(raw == canonical(value) and value['schema'] == SCHEMA, 'result encoding/schema')
    need(value['status'] in ('OK', 'REFUSED') and value['reason'] in REASONS,
         'result status/reason')
    need(value['cleanup'] in ('OWNED_REAPED', 'UNKNOWN'), 'result cleanup')
    code = value['child_exit']
    need(code is None or type(code) is int and -255 <= code <= 255, 'result child status')
    diagnostic = value['diagnostic']
    need(type(diagnostic) is str and len(diagnostic) <= 512 and
         all(ord(c) < 128 or c == '\ufffd' for c in diagnostic), 'result diagnostic')
    success = value['reason'] == 'NONE' and code == 0 and type(code) is int and \
        diagnostic == '' and value['cleanup'] == 'OWNED_REAPED'
    need((value['status'] == 'OK') == success, 'inconsistent result success')
    return value


def descriptor_identity(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular(fd, cap, access):
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= cap, 'descriptor type/size')
    need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access, 'descriptor access')
    return descriptor_identity(fd)


def descriptor_hash(fd, cap):
    before, used, result = regular(fd, cap, os.O_RDONLY), 0, hashlib.sha256()
    for _ in range(cap // 65536 + 1):
        block = os.pread(fd, min(65536, cap + 1 - used), used)
        if not block:
            break
        used += len(block)
        need(used <= cap, 'descriptor hash bound')
        result.update(block)
    need(used == before[2] and descriptor_identity(fd) == before, 'descriptor changed')
    return result.hexdigest(), before


def loaded_source(path, code):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = regular(fd, SOURCE_CAP, os.O_RDONLY)
        raw = os.pread(fd, SOURCE_CAP + 1, 0)
        need(len(raw) == before[2] and descriptor_identity(fd) == before, 'source read changed')
        need(compile(raw, path, 'exec', dont_inherit=True,
                     optimize=sys.flags.optimize) == code, 'loaded supervisor source differs')
        return hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def clamp_limits(output_limit, descriptors):
    for key, requested in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 120),
                           (resource.RLIMIT_NOFILE, descriptors), (resource.RLIMIT_CORE, 0),
                           (resource.RLIMIT_FSIZE, output_limit)):
        current = resource.getrlimit(key)
        bound = min([requested] + [v for v in current if v != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))


def native_setup(output_limit):
    clamp_limits(output_limit, 16)
    signal.pthread_sigmask(signal.SIG_SETMASK, ())


def close_owned(owned, fd):
    if fd in owned:
        owned.remove(fd)
        os.close(fd)


def close_remaining(owned):
    close_batch(owned, tuple(owned))


def close_batch(owned, selected):
    first = None
    for fd in selected:
        try:
            close_owned(owned, fd)
        except OSError as error:
            if first is None:
                first = error
    if first is not None:
        raise first


def spawn_owner(native_fd, wire_fd, output_fd, expected, output_limit, deadline, owned, launch):
    module = os.open(Path(__file__), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    owned.append(module)
    held = descriptor_hash(module, SOURCE_CAP)
    need(held[0] == SOURCE_EPOCH, 'supervisor source changed before exec')
    cancel_read, cancel_write = os.pipe2(os.O_CLOEXEC)
    owned.extend((cancel_read, cancel_write))
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    owned.extend((result_read, result_write))
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    owned.extend((error_read, error_write))
    null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    owned.append(null)
    sources = (null, result_write, error_write, module, native_fd, wire_fd, output_fd, cancel_read)
    duplicates = []
    try:
        for fd in sources:
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 16)
            owned.append(duplicate); duplicates.append(duplicate)
        actions = [(os.POSIX_SPAWN_DUP2, fd, number) for number, fd in enumerate(duplicates)]
        actions.append((os.POSIX_SPAWN_CLOSEFROM, 8))
        args = [sys.executable, '-I', '-S', '-B'] + (['-O'] if sys.flags.optimize else [])
        args += ['/proc/self/fd/3', '--owned-decoder-v1', SOURCE_EPOCH, expected,
                 str(output_limit), str(deadline)]
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, (*TERMINATION, signal.SIGALRM))
        try:
            pid = os.posix_spawn(sys.executable, args, {'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                file_actions=actions, setsigmask=(),
                                setsigdef=(signal.SIGCHLD, *TERMINATION), setsid=True)
            launch.update(pid=pid, cancel=cancel_write, result=result_read, error=error_read,
                          module=module, held=held)
        finally:
            try:
                close_batch(owned, (*duplicates, null, cancel_read, result_write, error_write))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    finally:
        close_batch(owned, (*duplicates, null, cancel_read, result_write, error_write))


def original_deadline():
    now, bound = time.monotonic_ns(), WALL_NS
    remaining, _interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining > 0:
        bound = min(bound, max(1, int(remaining * 1000000000)))
    return now + bound


def collect_owner(pid, channels, deadline, state, discard=False):
    with selectors.DefaultSelector() as selector:
        for name, fd in channels.items():
            if not state[name + '_eof']:
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_READ, name)
        for _ in range(ITERATIONS):
            remaining = deadline - time.monotonic_ns()
            need(remaining > 0, 'supervisor completion deadline')
            for event, _mask in selector.select(min(remaining / 1000000000, 0.05)):
                name = event.data
                try:
                    cap = RESULT_CAP if discard else RESULT_CAP + 1 - len(state[name])
                    block = os.read(event.fd, cap)
                except BlockingIOError:
                    continue
                if not block:
                    state[name + '_eof'] = True
                    selector.unregister(event.fd)
                elif not discard:
                    state[name].extend(block)
                    need(len(state[name]) <= RESULT_CAP, 'supervisor channel bound')
            if state['result_eof'] and state['error_eof']:
                need(not state['wait_lost'], 'supervisor ownership lost')
                try:
                    observed, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    state['wait_lost'] = True
                    raise
                if observed:
                    need(observed == pid, 'supervisor wait identity')
                    state['exit'] = os.waitstatus_to_exitcode(status)
                    return
    raise SupervisorError('supervisor completion iteration bound')


def cancellation_reap(pid, channels, state):
    if state['wait_lost']:
        return 'UNKNOWN:supervisor ownership lost; no wait retry'
    try:
        collect_owner(pid, channels, time.monotonic_ns() + CLEANUP_NS, state, discard=True)
        return 'OBSERVED_EXIT_' + str(state['exit'])
    except BaseException as error:
        return 'UNKNOWN:' + type(error).__name__ + ':' + str(error)[:128]


def result_failure(value):
    reason = value['reason']
    if reason in ('DIAGNOSTIC', 'NONZERO'):
        return 'native document refusal: ' + value['diagnostic']
    if reason == 'STDERR_LIMIT':
        return 'native stderr limit exceeded'
    if reason == 'TIMEOUT':
        return 'native decoder timed out'
    return 'native supervisor refused: ' + reason


def finish_descriptors(driver, launch, owned):
    first = None
    try:
        if driver is not None:
            driver.close_handle(launch)
    except OSError as error:
        first = error
    try:
        close_remaining(owned)
    except OSError as error:
        if first is None:
            first = error
        else:
            first.add_note('additional descriptor cleanup failure: ' + str(error))
    if first is not None:
        raise first


def abort_launch(backend, driver, launch, owned, state, failure):
    if 'pid' not in launch or state['exit'] is not None:
        return
    if driver is not None and launch['pid'][0] < 0:
        return
    if 'cancel' in launch:
        try:
            close_owned(owned, launch['cancel'])
        except OSError as error:
            failure.add_note('cancellation close failed: ' + type(error).__name__)
    channels = {key: launch[key] for key in ('result', 'error') if key in launch}
    failure.add_note('supervisor cancellation cleanup: ' +
                     backend.cancellation_reap(launch['pid'], channels, state))


def run(native_fd, wire_fd, output_fd, expected_native_sha256, output_limit):
    return run_profile(native_fd, wire_fd, output_fd, expected_native_sha256, output_limit, None)


def run_profile(native_fd, wire_fd, output_fd, expected_native_sha256, output_limit, driver):
    # Only trusted software supplies a lifecycle driver; no package field does.
    backend = sys.modules[__name__] if driver is None else driver
    need(type(output_limit) is int and 0 <= output_limit <= OUTPUT_CAP, 'output bound')
    need(type(expected_native_sha256) is str and len(expected_native_sha256) == 64 and
         all(c in '0123456789abcdef' for c in expected_native_sha256), 'native digest')
    before = descriptor_hash(native_fd, NATIVE_CAP)
    need(before[0] == expected_native_sha256, 'native descriptor digest')
    wire = regular(wire_fd, WIRE_CAP, os.O_RDONLY)
    output = regular(output_fd, 0, os.O_WRONLY)
    need(os.fstat(output_fd).st_nlink == 1, 'output ownership')
    owned, launch = [], {}
    state = {'result': bytearray(), 'error': bytearray(), 'result_eof': False,
             'error_eof': False, 'exit': None, 'wait_lost': False}
    try:
        deadline = original_deadline()
        backend.spawn_owner(native_fd, wire_fd, output_fd, expected_native_sha256,
                    output_limit, deadline, owned, launch)
        channels = {key: launch[key] for key in ('result', 'error')}
        backend.collect_owner(launch['pid'], channels, deadline + CLEANUP_NS, state)
        need(state['exit'] == 0 and not state['error'], 'supervisor exit/diagnostic refusal')
        value = checked_result(bytes(state['result']))
        if driver is not None:
            driver.verify_dependencies(launch)
        need(descriptor_hash(launch['module'], SOURCE_CAP) == launch['held'],
             'supervisor source changed during exec')
        need(descriptor_hash(native_fd, NATIVE_CAP) == before and
             descriptor_identity(wire_fd) == wire, 'decoder input descriptor changed')
        need(descriptor_identity(output_fd)[:2] == output[:2], 'output descriptor identity')
        if value['status'] != 'OK':
            raise SupervisorError(result_failure(value), value)
        return value
    except BaseException as failure:
        abort_launch(backend, driver, launch, owned, state, failure)
        raise
    finally:
        failure = sys.exception()
        try:
            finish_descriptors(driver, launch, owned)
        except OSError as error:
            if failure is None:
                raise
            failure.add_note('descriptor cleanup failed: ' + type(error).__name__)


def entry_arguments():
    need(len(sys.argv) == 6 and sys.argv[1] == '--owned-decoder-v1', 'supervisor argv')
    own, native, size, deadline = sys.argv[2:]
    for value in (own, native):
        need(len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'entry digest')
    need(size.isascii() and size.isdecimal() and len(size) <= 10, 'entry output integer')
    need(deadline.isascii() and deadline.isdecimal() and len(deadline) <= 20, 'entry deadline')
    need(str(int(size)) == size and str(int(deadline)) == deadline, 'entry canonical integers')
    size, deadline = int(size), int(deadline)
    need(0 <= size <= OUTPUT_CAP and 0 < deadline - time.monotonic_ns() <= WALL_NS,
         'entry resource/deadline bound')
    need(own == SOURCE_EPOCH and descriptor_hash(3, SOURCE_CAP)[0] == own, 'entry source identity')
    need(descriptor_hash(4, NATIVE_CAP)[0] == native, 'entry native identity')
    regular(5, WIRE_CAP, os.O_RDONLY); regular(6, 0, os.O_WRONLY)
    need(os.fstat(6).st_nlink == 1, 'entry output ownership')
    identities = [descriptor_identity(fd)[:2] for fd in (1, 2, 3, 4, 5, 6, 7)]
    need(len(set(identities)) == len(identities), 'entry descriptor alias')
    for fd, access in ((1, os.O_WRONLY), (2, os.O_WRONLY), (7, os.O_RDONLY)):
        need(stat.S_ISFIFO(os.fstat(fd).st_mode) and
             fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access, 'entry channel type/access')
    return native, size, deadline


def cancellation(fd):
    if select_ready(fd):
        data = os.read(fd, 1)
        raise SupervisorError('CANCELLED' if data == b'' else 'PROTOCOL')


def select_ready(fd):
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        return bool(selector.select(0))


def cancelled_signal(_number, _frame):
    raise SupervisorError('CANCELLED')


# linux/pidfd.h PIDFD_SIGNAL_PROCESS_GROUP. A scratch observation on this kernel
# accepted the integer 4. Kernel pidfd behavior is ASSUMED, not proved.
PIDFD_SIGNAL_PROCESS_GROUP = 4


def pidfd_exit_code(info, pid):
    need(info is not None and info.si_pid == pid, 'OWNERSHIP')
    if info.si_code == os.CLD_EXITED:
        return info.si_status
    if info.si_code == os.CLD_KILLED or info.si_code == os.CLD_DUMPED:
        return -info.si_status
    raise SupervisorError('OWNERSHIP')


def owned_cleanup(child):
    # Two non-consuming waitids refuse a foreign reap inside the first
    # observation. pidfd_open is reached only after both return. The open is
    # not atomic with that confirmation, so a PID reused by another child of
    # this process remains an UNPROVEN window. The group signal and reap then
    # use the fd, not kill, killpg, getpgid, getsid, or waitpid. This does not
    # discharge PRIORITY-A.
    need(child.returncode is None, 'OWNERSHIP')
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    os.waitid(os.P_PID, child.pid, flags)
    os.waitid(os.P_PID, child.pid, flags)
    descriptor = os.pidfd_open(child.pid)
    try:
        os.waitid(os.P_PID, child.pid, flags)
        signal_error = None
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, PIDFD_SIGNAL_PROCESS_GROUP)
        except ProcessLookupError:
            pass
        except OSError as error:
            signal_error = error
        deadline = time.monotonic_ns() + CLEANUP_NS
        info = None
        for _ in range(ITERATIONS):
            info = os.waitid(os.P_PIDFD, descriptor, os.WEXITED | os.WNOHANG)
            if info is not None:
                break
            need(time.monotonic_ns() < deadline, 'OWNERSHIP')
            time.sleep(0.01)
        code = pidfd_exit_code(info, child.pid)
        child.returncode = code
        if signal_error is not None:
            raise signal_error
        return code
    finally:
        os.close(descriptor)


def reap_decoder(child):
    deadline = time.monotonic_ns() + CLEANUP_NS
    for _ in range(ITERATIONS):
        observed, status = os.waitpid(child.pid, os.WNOHANG)
        if observed:
            need(observed == child.pid, 'OWNERSHIP')
            child.returncode = os.waitstatus_to_exitcode(status)
            return child.returncode
        need(time.monotonic_ns() < deadline, 'OWNERSHIP')
        time.sleep(0.01)
    raise SupervisorError('OWNERSHIP')


def monitor(child, deadline):
    stderr, eof = bytearray(), False
    with selectors.DefaultSelector() as selector:
        selector.register(7, selectors.EVENT_READ, 'cancel')
        selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
        for _ in range(ITERATIONS):
            need(time.monotonic_ns() < deadline, 'TIMEOUT')
            cancellation(7)
            try:
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except OSError as error:
                raise SupervisorError('OWNERSHIP') from error
            if eof and observed is not None:
                cancellation(7)
                return bytes(stderr)
            wait = min((deadline - time.monotonic_ns()) / 1000000000, 0.05)
            need(wait > 0, 'TIMEOUT')
            for event, _mask in selector.select(wait):
                if event.data == 'cancel':
                    cancellation(7)
                else:
                    block = os.read(child.stderr.fileno(), 4097 - len(stderr))
                    if not block:
                        eof = True; selector.unregister(child.stderr)
                    else:
                        stderr.extend(block)
                        need(len(stderr) <= 4096, 'STDERR_LIMIT')
    raise SupervisorError('RESOURCE')


def result_record(reason, code, diagnostic, cleanup):
    success = reason == 'NONE' and code == 0 and diagnostic == '' and cleanup == 'OWNED_REAPED'
    return {'schema': SCHEMA, 'status': 'OK' if success else 'REFUSED', 'reason': reason,
            'child_exit': code, 'diagnostic': diagnostic, 'cleanup': cleanup}


def supervise(size, deadline):
    child, reason, code, diagnostic, cleanup = None, 'NONE', None, '', 'UNKNOWN'
    try:
        cancellation(7)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION)
        try:
            child = subprocess.Popen(['/proc/self/fd/4', '/proc/self/fd/5'],
                pass_fds=(4, 5), stdin=subprocess.DEVNULL, stdout=6, stderr=subprocess.PIPE,
                start_new_session=True, preexec_fn=partial(native_setup, size),
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        diagnostic = monitor(child, deadline)[:512].decode('ascii', errors='replace')
    except SupervisorError as error:
        reason = str(error) if str(error) in REASONS else 'INTERNAL'
    except OSError:
        reason = 'INTERNAL' if child is not None else 'SPAWN'
    except BaseException:
        reason = 'INTERNAL'
    finally:
        if child is not None:
            signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION)
            try:
                need(reason != 'OWNERSHIP', 'OWNERSHIP')
                code = owned_cleanup(child)
                cleanup = 'OWNED_REAPED'
            except (OSError, ValueError):
                reason, cleanup = 'OWNERSHIP', 'UNKNOWN'
                # Never let Popen's destructor silently reap after lost ownership.
                child.returncode = 255
            finally:
                child.stderr.close()
    if reason == 'NONE':
        reason = 'NONZERO' if code != 0 else 'DIAGNOSTIC' if diagnostic else 'NONE'
    if reason == 'NONE':
        try:
            cancellation(7)
            need(not set(TERMINATION).intersection(signal.sigpending()), 'CANCELLED')
            need(time.monotonic_ns() < deadline, 'TIMEOUT')
        except SupervisorError as error:
            reason = str(error)
    return result_record(reason, code, diagnostic, cleanup)


def main():
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        for number in TERMINATION:
            signal.signal(number, cancelled_signal)
        with os.scandir('/proc/self/task') as tasks:
            need(next(tasks, None) is not None and next(tasks, None) is None, 'single owner thread')
        native, size, deadline = entry_arguments()
        pins = {fd: descriptor_identity(fd) for fd in (3, 4, 5)}
        clamp_limits(size, 64)
        value = supervise(size, deadline)
        if any(descriptor_identity(fd) != held for fd, held in pins.items()) or \
                descriptor_hash(4, NATIVE_CAP)[0] != native:
            value = result_record('PROTOCOL', value['child_exit'], '', value['cleanup'])
    except BaseException:
        value = result_record('PROTOCOL', None, '', 'UNKNOWN')
    raw = canonical(value)
    checked_result(raw)
    need(os.write(1, raw) == len(raw), 'short supervisor result write')
    return 0


SOURCE_EPOCH = loaded_source(__file__, sys._getframe().f_code)

if __name__ == '__main__':
    sys.exit(main())
