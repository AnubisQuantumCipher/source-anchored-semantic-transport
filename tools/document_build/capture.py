"""Complete quiescent payload capture; special files remain inert metadata."""
import hashlib
import json
import os
from pathlib import Path
import stat
from .common import ENTRY_CAP, EXTERNAL_CAP, META_CAP, PRIVATE_CAP, bounded_names, json_new, need, usage
from .process import private_pids


def census(work):
    need(not private_pids(), 'capture requires no owned children')
    pending, rows = [(work, '.')], []
    for _ in range(ENTRY_CAP):
        if not pending:
            return rows
        path, name = pending.pop()
        info = path.lstat()
        row = {'path': name, 'mode': info.st_mode, 'dev': info.st_dev, 'ino': info.st_ino,
               'nlink': info.st_nlink, 'uid': info.st_uid, 'gid': info.st_gid, 'bytes': info.st_size,
               'blocks': info.st_blocks, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
               'rdev': info.st_rdev}
        if stat.S_ISDIR(info.st_mode):
            names = sorted(item.name for item in bounded_names(path, ENTRY_CAP))
            need(len(pending) + len(names) + len(rows) < ENTRY_CAP, 'capture entry bound')
            pending.extend((path / item, item if name == '.' else name + '/' + item) for item in names)
            row['kind'] = 'directory'
        elif stat.S_ISREG(info.st_mode):
            need(info.st_size <= PRIVATE_CAP, 'regular payload bound')
            row['kind'] = 'regular'
        else:
            row['kind'] = 'special-inert-metadata'
            if stat.S_ISLNK(info.st_mode):
                row['target'] = os.readlink(path)
                need(len(os.fsencode(row['target'])) <= 4096, 'symlink metadata bound')
        rows.append(row)
    need(not pending, 'capture traversal bound')
    return rows


def copy_payload(source, target, size):
    digest = hashlib.sha256()
    with source.open('rb') as left, target.open('xb') as right:
        before = os.fstat(left.fileno())
        used = 0
        for _ in range(1025):
            block = left.read(65536)
            if not block:
                break
            used += len(block)
            need(used <= size, 'capture payload growth')
            digest.update(block)
            need(right.write(block) == len(block), 'capture short write')
        after = os.fstat(left.fileno())
        need(used == size and left.read(1) == b'', 'incomplete capture')
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'capture changed')
    check = hashlib.sha256()
    with target.open('rb') as stream:
        for _ in range(1025):
            block = stream.read(65536)
            if not block:
                break
            check.update(block)
    need(check.digest() == digest.digest(), 'capture readback mismatch')
    return digest.hexdigest()



def progress(folder, record):
    path = folder / 'progress.jsonl'
    raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(path.stat().st_size + len(raw) <= 2_097_152, 'capture progress byte bound')
    with path.open('ab') as stream:
        need(stream.write(raw) == len(raw), 'capture progress short write')


def capture_payloads(work, folder, payloads):
    for ordinal, row in enumerate(payloads.values()):
        name = 'payload-%04d.bin' % ordinal
        progress(folder, {'event': 'START', 'ordinal': ordinal, 'payload': name, 'bytes': row['bytes']})
        try:
            hashed = copy_payload(work / row['path'], folder / name, row['bytes'])
        except (ValueError, OSError) as error:
            failure = type(error).__name__ + ':' + str(error)[:4096]
            progress(folder, {'event': 'FAILED', 'ordinal': ordinal, 'payload': name, 'failure': failure})
            raise
        row['payload'], row['sha256'] = name, hashed
        progress(folder, {'event': 'COMPLETE_READBACK', 'ordinal': ordinal, 'payload': name, 'sha256': hashed})


def capture_inventory(work, out, folder, readonly):
    rows = census(work)
    payloads = {}
    for row in rows:
        if row['kind'] == 'regular':
            payloads.setdefault((row['dev'], row['ino']), row)
    total = sum(row['bytes'] for row in payloads.values())
    need(total <= PRIVATE_CAP, 'unique logical payload total bound')
    need(usage(out, work) + total + 3 * META_CAP + 2_097_152 <= EXTERNAL_CAP, 'export coexistence reserve')
    json_new(folder / 'census.json', {'entries': rows, 'complete_quiescent_census': True}, META_CAP)
    capture_payloads(work, folder, payloads)
    for row in rows:
        if row['kind'] == 'regular':
            unique = payloads[(row['dev'], row['ino'])]
            row['payload'], row['sha256'] = unique['payload'], unique['sha256']
    need(not private_pids(), 'children appeared during capture')
    record = {'entries': rows, 'unique_payload_bytes': total, 'complete_quiescent_census': True,
              'readonly_qualified': readonly, 'readonly_observed': bool(os.statvfs(work).f_flag & os.ST_RDONLY),
              'capture_state': 'QUIESCENT_READONLY' if readonly else 'QUIESCENT_FAILED_REMOUNT_UNQUALIFIED',
              'specials': 'inert metadata only; never followed/opened/executed'}
    json_new(folder / 'inventory.json', record, META_CAP)
    usage(out, work)
    return {'inventory': 'capture/inventory.json', 'payload_bytes': total,
            'readonly_qualified': readonly, 'complete': True}


def snapshot(work, out, readonly):
    folder = out / 'capture'
    created = False
    try:
        need(not private_pids(), 'capture requires no owned children')
        folder.mkdir(mode=0o700)
        created = True
        with (folder / 'progress.jsonl').open('xb'):
            pass
        return capture_inventory(work, out, folder, readonly)
    except (ValueError, OSError) as error:
        record = {'complete': False, 'readonly_qualified': readonly,
                  'failure': type(error).__name__ + ':' + str(error)[:4096],
                  'capture_state': 'INCOMPLETE_AVAILABLE_EXPORTS_RETAINED',
                  'lost_state': 'unexported private bytes may be lost at namespace exit; host crashes/external IO are not guaranteed'}
        if created:
            try:
                json_new(folder / 'failure.json', record)
            except (ValueError, OSError) as save_error:
                record['failure_record_lost'] = type(save_error).__name__ + ':' + str(save_error)[:4096]
        return record
