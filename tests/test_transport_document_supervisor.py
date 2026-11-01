"""Bounded actual-Python supervisor controls; --case runs exactly one scenario.

These fixtures do not qualify the native decoder, process-death containment,
book semantics, or the complete product. No test signals a foreign numeric PID.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document_supervisor as supervisor

CASES = ('clean', 'diagnostic', 'nonzero', 'stderr_overflow', 'deadline',
         'parent_interrupt', 'same_group_descendant', 'parent_cancellation_eof',
         'caller_not_decoder_parent', 'foreign_caller_reaper', 'descriptor_roster',
         'source_drift', 'result_protocol', 'status_mismatch', 'unknown_decoder_ownership')
WAITING = ('deadline', 'parent_interrupt', 'parent_cancellation_eof', 'caller_not_decoder_parent')


def require(condition, message):
    if condition is not True:
        raise ValueError(message)


def clamp():
    for key, wanted in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 20),
                        (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_FSIZE, 1048576),
                        (resource.RLIMIT_CORE, 0)):
        bounds = resource.getrlimit(key)
        bound = min([wanted] + [v for v in bounds if v != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))
    remaining, _interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining <= 0 or remaining > 15:
        signal.setitimer(signal.ITIMER_REAL, 15)


def digest(path):
    result, size = hashlib.sha256(), 0
    with open(path, 'rb') as stream:
        for _ in range(257):
            block = stream.read(65536)
            if not block:
                break
            size += len(block)
            require(size <= 16777216, 'hash bound')
            result.update(block)
    return result.hexdigest()


def read_small(path):
    with open(path, 'rb') as stream:
        raw = stream.read(8193)
    require(len(raw) <= 8192, 'output read bound')
    return raw


def process_state(pid):
    try:
        raw = read_small('/proc/' + str(pid) + '/stat')
    except FileNotFoundError:
        return None
    fields = raw[raw.rindex(b')') + 2:].split()
    return {'pid': pid, 'state': fields[0].decode(), 'ppid': int(fields[1]),
            'group': int(fields[2]), 'session': int(fields[3]), 'start': int(fields[19])}


def terminal(held):
    for _ in range(50):
        observed = process_state(held['pid'])
        if observed is None:
            return 'ABSENT'
        require(observed['start'] == held['start'], 'numeric identity changed; no signal attempted')
        if observed['state'] == 'Z':
            return 'ZOMBIE_TERMINATED_NOT_HARNESS_REAPED'
        time.sleep(0.02)
    raise ValueError('owned fixture still running; self-alarm remains the safety bound')


def fixture_script(case):
    if case in ('clean', 'diagnostic', 'nonzero', 'foreign_caller_reaper'):
        name, mode = 'transport_process_fixture.py', case if case != 'foreign_caller_reaper' else 'clean'
    else:
        name = 'transport_supervisor_fixture.py'
        mode = 'waiting' if case in WAITING else 'descendant' if case == 'same_group_descendant' else \
            'overflow' if case == 'stderr_overflow' else 'roster'
    path = str(ROOT / 'tests' / name)
    return ('import runpy,sys\nsys.argv=[' + repr(path) + ',' + repr(mode) + ']\n' +
            'runpy.run_path(' + repr(path) + ',run_name="__main__")\n').encode()


def files(stack, directory, case):
    wire, output = directory / 'wire.py', directory / 'output'
    with wire.open('xb') as stream:
        stream.write(fixture_script(case))
    python = stack.enter_context(open(sys.executable, 'rb'))
    script = stack.enter_context(wire.open('rb'))
    result = stack.enter_context(output.open('xb'))
    return (python.fileno(), script.fileno(), result.fileno(), digest(sys.executable), 65536), output


def ready(output, launch):
    for _ in range(150):
        raw = read_small(output)
        if raw.endswith(b'\n'):
            value = json.loads(raw)
            require(type(value) is dict and 'identity' in value, 'fixture readiness record')
            if all(key in launch for key in ('pid', 'cancel', 'owned')):
                return value
        time.sleep(0.02)
    raise ValueError('fixture or captured launch readiness timeout')


def thread_action(case, output, launch, events, errors, owned):
    try:
        value = ready(output, launch)
        events.append({'ready': value})
        if case == 'parent_interrupt':
            owned['kill'](os.getpid(), signal.SIGINT)
        else:
            if case == 'caller_not_decoder_parent':
                try:
                    owned['waitpid'](value['identity']['pid'], os.WNOHANG)
                except ChildProcessError:
                    events.append({'caller_wait_decoder': 'ECHILD'})
                else:
                    raise ValueError('caller unexpectedly owns decoder wait status')
            supervisor.close_owned(launch['owned'], launch['cancel'])
            events.append({'cancellation': 'WRITER_CLOSED'})
    except BaseException as error:
        errors.append(type(error).__name__ + ':' + str(error))


def instrumentation(stack, launch, events, channels, owned, case):
    original_spawn, original_read = supervisor.spawn_owner, os.read
    def spawn(*args):
        original_spawn(*args)
        launch.update(args[-1])
        launch['owned'] = args[-2]
        events.append({'supervisor_pid': launch['pid']})
    def read(fd, size):
        raw = original_read(fd, size)
        for name in ('result', 'error'):
            if fd == launch.get(name):
                channels[name].extend(raw)
                require(len(channels[name]) <= 4096, 'captured protocol bound')
                if raw == b'':
                    events.append({'eof': name})
        return raw
    def forbidden(*_args):
        raise ValueError('caller attempted numeric process signalling')
    def foreign_wait(pid, flags):
        require(pid == launch['pid'], 'foreign-reaper exact supervisor identity')
        owned['waitpid'](pid, 0)
        events.append({'foreign_wait': 'SUPERVISOR_REAPED'})
        raise ChildProcessError('controlled caller reaper consumed supervisor status')
    stack.enter_context(patch.object(supervisor, 'spawn_owner', spawn))
    stack.enter_context(patch.object(os, 'read', read))
    stack.enter_context(patch.object(os, 'kill', forbidden))
    stack.enter_context(patch.object(os, 'killpg', forbidden))
    if case == 'foreign_caller_reaper':
        stack.enter_context(patch.object(os, 'waitpid', foreign_wait))
    if case == 'deadline':
        stack.enter_context(patch.object(supervisor, 'original_deadline',
                                         lambda: time.monotonic_ns() + 500000000))


def execute(case, arguments, output):
    launch, events, errors = {}, [], []
    channels = {'result': bytearray(), 'error': bytearray()}
    owned = {'kill': os.kill, 'waitpid': os.waitpid}
    value, failure, worker = None, None, None
    with ExitStack() as stack:
        instrumentation(stack, launch, events, channels, owned, case)
        if case in ('parent_interrupt', 'parent_cancellation_eof', 'caller_not_decoder_parent'):
            worker = threading.Thread(target=thread_action,
                args=(case, output, launch, events, errors, owned), daemon=False)
            worker.start()
        try:
            value = supervisor.run(*arguments)
        except (supervisor.SupervisorError, KeyboardInterrupt, ChildProcessError) as error:
            failure = {'type': type(error).__name__, 'message': str(error),
                       'notes': getattr(error, '__notes__', [])}
            value = getattr(error, 'result', None)
        finally:
            if worker is not None:
                worker.join(4)
                require(not worker.is_alive(), 'caller thread failed to join')
    require(not errors, 'caller thread failure: ' + repr(errors))
    if value is None and channels['result']:
        value = supervisor.checked_result(bytes(channels['result']))
    return {'result': value, 'failure': failure, 'events': events,
            'raw_result': channels['result'].decode('ascii'),
            'raw_error': channels['error'].decode('ascii'), 'launch_pid': launch.get('pid')}


def check_live(case, record, output):
    value, failure = record['result'], record['failure']
    reasons = {'diagnostic': 'DIAGNOSTIC', 'nonzero': 'NONZERO', 'stderr_overflow': 'STDERR_LIMIT',
               'deadline': 'TIMEOUT', 'parent_cancellation_eof': 'CANCELLED',
               'caller_not_decoder_parent': 'CANCELLED', 'parent_interrupt': 'CANCELLED'}
    if case == 'foreign_caller_reaper':
        require(failure is not None and failure['type'] == 'ChildProcessError', 'foreign reaper refusal')
    elif case == 'parent_interrupt':
        require(failure is not None and failure['type'] == 'KeyboardInterrupt', 'SIGINT propagation')
    elif case in reasons:
        require(failure is not None and failure['type'] == 'SupervisorError', 'expected bounded refusal')
    else:
        require(failure is None, 'unexpected fixture refusal: ' + repr(failure))
    require(value is not None and value['reason'] == reasons.get(case, 'NONE'), 'result reason')
    require(value['cleanup'] == 'OWNED_REAPED', 'decoder cleanup admission')
    expected_code = 7 if case == 'nonzero' else -signal.SIGKILL if case in WAITING else 0
    if case != 'stderr_overflow':
        require(value['child_exit'] == expected_code, 'exact decoder exit status')
    if case == 'foreign_caller_reaper':
        require(record['events'].count({'foreign_wait': 'SUPERVISOR_REAPED'}) == 1,
                'exactly one real foreign wait required')
    if case == 'diagnostic':
        require(value['diagnostic'] == 'bounded diagnostic\n', 'diagnostic preservation')
    require(record['raw_error'] == '', 'supervisor stderr')
    require({'eof': 'result'} in record['events'] and {'eof': 'error'} in record['events'], 'channel EOF')
    require(process_state(record['launch_pid']) is None, 'supervisor was not reaped')
    raw = read_small(output)
    record['output'] = json.loads(raw) if raw else None
    if case in ('same_group_descendant', 'descriptor_roster'):
        require(record['output'] is not None, 'fixture output missing')
        validate_fixture(record, case)
    if case == 'caller_not_decoder_parent':
        require({'caller_wait_decoder': 'ECHILD'} in record['events'], 'parenthood evidence missing')


def validate_fixture(record, case):
    value = record['output']
    leader = value['identity']
    require(leader['ppid'] == record['launch_pid'] and leader['group'] == leader['pid'] and
            leader['session'] == leader['pid'], 'independent fixture parent/session identity')
    roster = value['descriptors']
    require(set(roster).issubset({'0', '1', '2', '4', '5'}), 'unexpected inherited descriptor')
    require(roster.get('0') == '/dev/null' and roster.get('2', '').startswith('pipe:['), 'stdio roster')
    require(not any(target.startswith('pipe:[') for fd, target in roster.items() if fd != '2'),
            'cancellation/result pipe leaked into decoder')
    if case == 'same_group_descendant':
        child = value['descendant']
        require(child['group'] == leader['group'] and child['session'] == leader['session'],
                'descendant group/session identity')
        record['descendant_terminal'] = terminal(child)


def expect_refusal(name, action, results):
    try:
        action()
    except (supervisor.SupervisorError, ChildProcessError):
        results.append({'control': name, 'result': 'REFUSED'})
    else:
        raise ValueError('negative control accepted: ' + name)


def protocol_controls():
    valid = supervisor.result_record('NONE', 0, '', 'OWNED_REAPED')
    raw = supervisor.canonical(valid)
    mutated = [(name, dict(valid, **change)) for name, change in (
        ('unknown_field', {'extra': 1}), ('wrong_schema', {'schema': 'other'}),
        ('boolean_exit', {'child_exit': True}), ('false_success', {'cleanup': 'UNKNOWN'}),
        ('unknown_reason', {'reason': 'OTHER'}), ('nonascii', {'diagnostic': '\u1234'}))]
    samples = [('empty', b''), ('truncated', raw[:-3]), ('oversized', b'x' * 4097),
               ('duplicate', raw[:-2] + b',"status":"OK"}\n'), ('multiple', raw + raw),
               ('missing_newline', raw[:-1]), ('whitespace', b' ' + raw), ('array', b'[]\n'),
               ('nonfinite', raw.replace(b'"child_exit":0', b'"child_exit":NaN'))]
    samples.extend((name, supervisor.canonical(value)) for name, value in mutated)
    results = []
    for name, value in samples:
        expect_refusal(name, lambda value=value: supervisor.checked_result(value), results)
    state = {'result': bytearray(raw), 'error': bytearray(), 'result_eof': False,
             'error_eof': True, 'exit': None, 'wait_lost': False}
    with patch.object(supervisor.time, 'monotonic_ns', lambda: 2):
        expect_refusal('valid_record_missing_EOF',
                       lambda: supervisor.collect_owner(4242, {}, 1, state), results)
    return results


def pure_controls(case, arguments):
    results = []
    if case == 'result_protocol':
        results = protocol_controls()
    elif case == 'source_drift':
        with patch.object(supervisor, 'SOURCE_EPOCH', '0' * 64):
            expect_refusal('loaded_source_pin', lambda: supervisor.run(*arguments), results)
        wrong = (*arguments[:3], '0' * 64, arguments[4])
        expect_refusal('native_pin', lambda: supervisor.run(*wrong), results)
    elif case == 'unknown_decoder_ownership':
        child, calls = SimpleNamespace(returncode=None, pid=4242), []
        def unknown(*_args):
            calls.append('waitid'); raise ChildProcessError('controlled unknown ownership')
        def forbidden(*_args):
            raise ValueError('numeric/reap operation after unknown ownership')
        with ExitStack() as stack:
            stack.enter_context(patch.object(os, 'waitid', unknown))
            for name in ('getpgid', 'getsid', 'killpg', 'kill', 'pidfd_open'):
                stack.enter_context(patch.object(os, name, forbidden))
            stack.enter_context(patch.object(signal, 'pidfd_send_signal', forbidden))
            stack.enter_context(patch.object(supervisor, 'reap_decoder', forbidden))
            expect_refusal('unknown_ownership', lambda: supervisor.owned_cleanup(child), results)
        require(calls == ['waitid'], 'unknown ownership must stop at observation')
        later, closed = [], []

        def third(*_args):
            later.append('waitid')
            if later.count('waitid') == 3:
                raise ChildProcessError('lost after open')
            return SimpleNamespace(si_pid=child.pid)

        def opened(pid, flags=0):
            require(pid == child.pid and flags == 0, 'pidfd open target')
            later.append('pidfd_open')
            return 77

        def closed_fd(fd):
            require(fd == 77, 'pidfd close target')
            closed.append(fd)

        child.returncode = None
        with ExitStack() as stack:
            stack.enter_context(patch.object(os, 'waitid', third))
            stack.enter_context(patch.object(os, 'pidfd_open', opened))
            stack.enter_context(patch.object(os, 'close', closed_fd))
            for name in ('getpgid', 'getsid', 'killpg', 'kill'):
                stack.enter_context(patch.object(os, name, forbidden))
            stack.enter_context(patch.object(signal, 'pidfd_send_signal', forbidden))
            stack.enter_context(patch.object(supervisor, 'reap_decoder', forbidden))
            expect_refusal('lost_after_open', lambda: supervisor.owned_cleanup(child), results)
        require(later == ['waitid', 'waitid', 'pidfd_open', 'waitid'],
                'post-open loss must refuse before the signal')
        require(closed == [77], 'opened pidfd must be closed without signaling')
    elif case == 'status_mismatch':
        def spawn(*args):
            args[-1].update(pid=4242, cancel=-1, result=-1, error=-1)
        def collect(_pid, _channels, _deadline, state, discard=False):
            state.update(exit=7, result=bytearray(supervisor.canonical(
                supervisor.result_record('NONE', 0, '', 'OWNED_REAPED'))))
        with patch.object(supervisor, 'spawn_owner', spawn), patch.object(supervisor, 'collect_owner', collect):
            expect_refusal('valid_OK_nonzero_supervisor', lambda: supervisor.run(*arguments), results)
    return {'controls': results, 'control_count': len(results), 'processes_spawned': 0}


def no_process_dispatch(*_args, **_kwargs):
    raise ValueError('pure control attempted process dispatch')


def main():
    require(len(sys.argv) == 3 and sys.argv[1] == '--case' and sys.argv[2] in CASES, 'one admitted case required')
    case, started = sys.argv[2], time.monotonic_ns()
    clamp()
    pins = {str(path.relative_to(ROOT)): digest(path) for path in (
        ROOT / 'tools/transport_document_supervisor.py', Path(__file__),
        ROOT / 'tests/transport_supervisor_fixture.py', ROOT / 'tests/transport_process_fixture.py')}
    with tempfile.TemporaryDirectory(prefix='sast-supervisor61-', dir='/dev/shm') as name:
        with ExitStack() as stack:
            arguments, output = files(stack, Path(name), case)
            if case in ('source_drift', 'result_protocol', 'status_mismatch', 'unknown_decoder_ownership'):
                with patch.object(os, 'posix_spawn', no_process_dispatch):
                    record = pure_controls(case, arguments)
            else:
                record = execute(case, arguments, output)
                check_live(case, record, output)
    require(all(digest(ROOT / path) == pin for path, pin in pins.items()), 'test source drift')
    record.update(case=case, classification='PYTHON_FIXTURE_NOT_NATIVE_DECODER', passed=True,
                  elapsed_ns=time.monotonic_ns() - started, source_pins=pins,
                  python_sha256=digest(sys.executable), python_version=sys.version,
                  fixture_startup='ASSUMED_TRUSTED_INSTALLED_PYTHON_STARTUP_NOT_ISOLATED',
                  supervisor_startup='PINNED_SOURCE_WITH_I_S_B_FLAGS',
                  argv=sys.argv, optimized=sys.flags.optimize,
                  deadline='SHORTENED_NOT_NATURAL_120_SECOND' if case == 'deadline' else 'DEFAULT_BOUND',
                  resource_limits={str(key): list(resource.getrlimit(key)) for key in (
                      resource.RLIMIT_AS, resource.RLIMIT_CPU, resource.RLIMIT_NOFILE,
                      resource.RLIMIT_FSIZE, resource.RLIMIT_CORE)})
    raw = json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    require(len(raw) <= 32768 and os.write(1, raw) == len(raw), 'receipt output bound')


if __name__ == '__main__':
    main()
