"""Private PID1 controls fixed mount, tool execution, cleanup and final capture."""
import json
import os
from pathlib import Path
import sys
from .capture import snapshot
from .common import ENTRY_CAP, PRIVATE_CAP, json_new, limits, need, read_bytes, usage
from .process import drain_children, mount_command, private_pids
from .worker import run
from .identity import verify_roster

MOUNT = ['/usr/bin/mount', '-n', '--options-source', 'disable', '--options-mode', 'replace']
QUOTA = 'size=67108864,nr_inodes=4096,nodev,nosuid,mode=0700,uid=0,gid=0'


def bind_readonly(path, logs, deadline):
    mount_command(MOUNT + ['--bind', str(path), str(path)], logs, deadline)
    mount_command(MOUNT + ['-o', 'remount,bind,ro,nodev,nosuid', str(path), str(path)], logs, deadline)
    need(bool(os.statvfs(path).f_flag & os.ST_RDONLY), 'source/tool/runtime readonly absent')


def setup(config, out, work):
    need(os.getpid() == 1 and not private_pids(), 'private PID1/initial quiescence required')
    names = ('user', 'mnt', 'pid', 'net')
    observed = {name: os.readlink('/proc/self/ns/' + name) for name in names}
    need(all(observed[name] != config['parent_namespaces'][name] for name in names), 'namespace separation refused')
    mount_command(['/usr/bin/mount', '-n', '--make-rprivate', '/'], out, config['global_deadline'])
    mount_command(MOUNT + ['-t', 'tmpfs', '-o', QUOTA, 'document-private', str(work)], out, config['global_deadline'])
    fs = os.statvfs(work)
    need(fs.f_blocks * fs.f_frsize == PRIVATE_CAP and fs.f_files == ENTRY_CAP, 'hard quota unavailable')
    for path in (Path(config['source_root']), Path(config['toolchain_root'])):
        bind_readonly(path, work, config['global_deadline'])
    from .launcher import source_pins
    config['identity_before'] = verify_roster(config)
    need(source_pins(Path(config['source_root'])) == config['source_pins'], 'dispatch source epoch changed')
    return observed


def execute(config, out, work):
    failures, result, captured = [], None, None
    try:
        result = run(work, config)
        if result['failure']:
            failures.append(result['failure'])
    except (ValueError, OSError, UnicodeError) as error:
        failures.append(type(error).__name__ + ':' + str(error)[:4096])
    cleanup = drain_children()
    identity_after = None
    try:
        identity_after = verify_roster(config)
        need(identity_after == config['identity_before'], 'declared identity before/after mismatch')
    except (ValueError, OSError) as error:
        failures.append('IDENTITY_AFTER_FAILED:' + str(error)[:4096])
    readonly = False
    try:
        mount_command(MOUNT + ['-t', 'tmpfs', '-o', 'remount,ro,' + QUOTA,
                              'document-private', str(work)], out, config['global_deadline'])
        fs = os.statvfs(work)
        need(bool(fs.f_flag & os.ST_RDONLY), 'readonly remount flag absent')
        need(fs.f_blocks * fs.f_frsize == PRIVATE_CAP and fs.f_files == ENTRY_CAP, 'remount lost quota')
        readonly = True
    except (ValueError, OSError) as error:
        failures.append('READONLY_REMOUNT_FAILED:' + str(error)[:4096])
    captured = snapshot(work, out, readonly)
    if not captured['complete']:
        failures.append('CAPTURE_INCOMPLETE:' + captured.get('failure', 'unknown'))
    return {'status': 'BUILT_AND_LEDGER_PROOF_CHECKED' if not failures else 'FAILED',
            'failures': failures, 'worker': result, 'cleanup': cleanup, 'capture': captured,
            'readonly_qualified': readonly, 'external_bytes': usage(out, work),
            'identity_before': config['identity_before'], 'identity_after': identity_after}



def failed_setup_capture(work, out, config):
    readonly = False
    try:
        mount_command(MOUNT + ['-t', 'tmpfs', '-o', 'remount,ro,' + QUOTA,
                              'document-private', str(work)], out, config['global_deadline'])
        fs = os.statvfs(work)
        readonly = bool(fs.f_flag & os.ST_RDONLY)
        need(fs.f_blocks * fs.f_frsize == PRIVATE_CAP and fs.f_files == ENTRY_CAP, 'lost quota')
    except (ValueError, OSError):
        readonly = False
    drain_children()
    return snapshot(work, out, readonly)


def main():
    limits()
    out = Path(sys.argv[2])
    config = json.loads(read_bytes(out / 'launch.json'))
    work = out / 'private'
    record = {'status': 'FAILED', 'failure': 'namespace setup incomplete'}
    baseline_device = work.stat().st_dev
    setup_complete = False
    try:
        observed = setup(config, out, work)
        setup_complete = True
        record = execute(config, out, work)
        record['namespaces'] = observed
    except (ValueError, OSError, UnicodeError) as error:
        record['failure'] = type(error).__name__ + ':' + str(error)[:4096]
        record['failure_stage'] = 'EXECUTE_OR_CAPTURE' if setup_complete else 'SETUP'
        record['capture_retry_performed'] = False
        drain_children()
        if not setup_complete and work.stat().st_dev != baseline_device:
            record['setup_failure_capture'] = failed_setup_capture(work, out, config)
    finally:
        record['terminal_cleanup'] = drain_children()
        try:
            json_new(out / 'namespace-result.json', record)
        except (ValueError, OSError) as error:
            record['status'] = 'FAILED'
            record['terminal_record_lost'] = str(error)[:4096]
            print(json.dumps(record)[:32768], file=sys.stderr)
    return 0 if record['status'] == 'BUILT_AND_LEDGER_PROOF_CHECKED' else 2


if __name__ == '__main__':
    sys.exit(main())
