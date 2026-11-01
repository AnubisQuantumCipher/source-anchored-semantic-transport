"""Bounded data collation only; never executes/imports any evidence member."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

OUT = Path(__file__).resolve().parent
STAGE = OUT.parent
N = Path('/dev/shm/semantic-transport-proof-ipc-design-20261029')
T2 = Path('/dev/shm/semantic-transport-proof-ipc-20261029')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
T2_FILES = ('before.json', 'terminal.json', 'launch-admission.json', 'build-process.json',
            'build.stdout', 'build.stderr')
D_FILES = ('clean-repro-cli-boundary-admission-01.json', 'verification-evidence-collation-admission-01.json',
    'proof-ipc-diagnostic-design-admission-01.json', 'proof-ipc-implementation-admission-01.json',
    'proof-ipc-calendar-adoption-01.json', 'proof-ipc-implementation-final-review-01.json',
    'proof-ipc-launch-01.json', 'proof-ipc-launch-01.stdout', 'proof-ipc-launch-01.stderr',
    'proof-ipc-launch-01.exit', 'proof-ipc-attempt-review-01.json')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    parts = PurePosixPath(name).parts
    need(parts and not name.startswith('/') and len(parts) <= 12, 'relative member path')
    need(all(p not in ('', '.', '..') and re.fullmatch(r'[A-Za-z0-9._-]+', p)
         for p in parts), 'safe member components')
    return name


def read(path, cap=1048576):
    need(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink read path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'regular bounded input')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
         for k in keys), 'input mutation')
    return raw


def stat_row(path):
    row = path.lstat()
    return {key: getattr(row, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_size',
            'st_blocks', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_nlink')}


def tree(root, prefix):
    files, omissions, stack, seen = {}, [], [(root, prefix, 0)], 0
    for _ in range(512):
        if not stack:
            return files, omissions
        parent, relative, depth = stack.pop()
        need(depth <= 10 and not parent.is_symlink(), 'source directory depth/type')
        with os.scandir(parent) as entries:
            for entry in entries:
                seen += 1
                need(seen <= 512, 'source entry bound')
                path, name = Path(entry.path), safe_name(relative + '/' + entry.name)
                row = stat_row(path)
                if stat.S_ISDIR(row['st_mode']):
                    stack.append((path, name, depth + 1))
                elif stat.S_ISREG(row['st_mode']):
                    need(name not in files, 'duplicate source name')
                    files[name] = dict(path=str(path), source_stat=row)
                else:
                    omission = dict(name=name, source_stat=row, reason='SYMLINK_OR_SPECIAL_NOT_DEREFERENCED')
                    if stat.S_ISLNK(row['st_mode']):
                        target = os.readlink(path)
                        need(len(target.encode('utf-8')) <= 4096, 'link target bound')
                        omission['target_string_only'] = target
                    omissions.append(omission)
    raise ValueError('source traversal bound')


def inventory():
    files, omissions = tree(N, 'N')
    for root, prefix, names in ((T2, 'T2', T2_FILES), (D, 'D', D_FILES)):
        for name in names:
            path = root / name
            need(stat.S_ISREG(path.lstat().st_mode), 'required selected regular file')
            files[prefix + '/' + name] = dict(path=str(path), source_stat=stat_row(path))
    need(len(files) <= 512, 'archive member count')
    return dict(files=dict(sorted(files.items())), omissions=sorted(omissions, key=lambda r: r['name']))


def capacity():
    total, count, stack = 0, 0, [(STAGE, 0)]
    for _ in range(1024):
        if not stack:
            need(total <= 8388608, 'shared collation allocation cap')
            return total
        path, depth = stack.pop()
        row = path.lstat()
        total += max(row.st_size, row.st_blocks * 512)
        need(total <= 8388608 and depth <= 10, 'allocated collation bound')
        if stat.S_ISDIR(row.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    count += 1
                    need(count <= 1024 and not entry.is_symlink(), 'shared stage entry/type')
                    stack.append((Path(entry.path), depth + 1))
        else:
            need(stat.S_ISREG(row.st_mode), 'shared stage regular file')
    raise ValueError('shared stage traversal bound')


def scan(raw):
    patterns = (rb'-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----',
                rb'sk-proj-[A-Za-z0-9_-]{16,}', rb'ghp_[A-Za-z0-9]{20,}', rb'AKIA[A-Z0-9]{16}')
    need(not any(re.search(pattern, raw) for pattern in patterns), 'credential-pattern match; refuse')


def create_archive(before):
    path, rows, total = OUT / 'observations.zip', {}, 0
    capacity()
    with path.open('xb') as output:
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, source in before['files'].items():
                raw = read(Path(source['path']))
                scan(raw)
                total += len(raw)
                need(total <= 4194304, 'expanded bytes cap')
                info = zipfile.ZipInfo(safe_name(name), date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system, info.external_attr = 3, (stat.S_IFREG | 0o400) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, raw)
                rows[name] = dict(bytes=len(raw), sha256=sha(raw), **source)
                need(output.tell() <= 4194304, 'archive stream bound')
    path.chmod(0o400)
    raw = read(path, 4194304)
    need(len(raw) <= 4194304, 'archive final bound')
    capacity()
    return dict(archive=dict(bytes=len(raw), sha256=sha(raw)), files=rows,
                member_count=len(rows), expanded_bytes=total, omissions=before['omissions'])


def verify_archive(index):
    path = OUT / 'observations.zip'
    raw = read(path, 4194304)
    need(len(raw) == index['archive']['bytes'] and sha(raw) == index['archive']['sha256'], 'archive pin')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        need(len(infos) <= 512 and len(infos) == len(index['files']), 'archive count')
        names = [safe_name(info.filename) for info in infos]
        need(len(set(names)) == len(names) and set(names) == set(index['files']), 'unique exact inventory')
        total = 0
        for info in infos:
            need(stat.S_ISREG(info.external_attr >> 16) and not info.flag_bits & 1, 'member type/encryption')
            need(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'member compression')
            expected = index['files'][info.filename]
            total += info.file_size
            need(info.file_size == expected['bytes'] and info.file_size <= 1048576
                 and total <= 4194304, 'expanded member bound')
            with archive.open(info) as stream:
                member = stream.read(info.file_size + 1)
            need(len(member) == expected['bytes'] and sha(member) == expected['sha256'], 'member identity')
    need(total == index['expanded_bytes'], 'expanded aggregate identity')


def write(path, raw):
    need(len(raw) <= 262144, 'derived file bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short derived write')
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)
    capacity()


def outcomes():
    review_raw = read(D / 'proof-ipc-attempt-review-01.json')
    review = json.loads(review_raw)
    terminal = json.loads(read(T2 / 'terminal.json'))
    build = json.loads(read(T2 / 'build-process.json'))
    need(terminal['status'] == 'FAILED' and build['status'] == 'FAILED', 'retained failed attempt')
    need(build['returncode'] == 0 and build['capture_complete'] is False, 'native-exit versus harness status')
    need('tmp/GPR.880304' in build['final_inventory_failure'], 'retained refusal identity')
    need(not (T2 / 'proof-process.json').exists(), 'proof record unexpectedly exists')
    return dict(review_sha256=sha(review_raw), review=review, terminal=terminal, build=build)


def readme(index, observations):
    text = '# Second native clean-proof attempt: retained failure\n\n'
    text += ('Observed terminal status: **FAILED**. The recorded native build process returned '
        'exit0, with 686 stdout bytes and empty stderr. The enclosing attempt failed: its final '
        'inventory could not re-open the bound path `tmp/GPR.880304`, and `capture_complete` is '
        'false. This does not establish a clean native build. **Proof was NOT_RUN.** No successor '
        'proposal is treated as an implementation or execution.\n\n')
    text += ('The data-only ZIP contains ' + str(index['member_count']) + ' unique regular-file '
        'members and ' + str(index['expanded_bytes']) + ' expanded bytes. The index explicitly '
        'records ' + str(len(index['omissions'])) + ' intentional symlink/special omissions, '
        'including the FIFO; symlink target strings are recorded without dereferencing. Nested '
        'ZIPs remain opaque data.\n\n')
    text += ('N/ contains every regular file under the frozen IPC-driver design tree, including '
        'v1/v2 preservation, source/helper snapshots, failed controls, design/implementation/calendar '
        'reviews and receipts. T2/ contains only the selected root before/launch/build-process/raw '
        'stream/terminal records. Compiled objects, new binaries and T2/source/tmp content are '
        'outside this selected collation. D/ contains the original relevant admissions, root '
        'launch records/streams/exit, final implementation review and actual-attempt review.\n\n')
    text += ('The independent actual-attempt review is pinned in the index: SHA256 '
        + observations['review_sha256'] + '. It is an engineering evidence review, not '
        'external-human validation. Preserve its exact findings and all prior failed/UNRUN '
        'states. This bundle makes no formal-proof, semantic-benefit, study or ACCEPTED_V1 claim.\n\n')
    text += ('The earlier collation atime-cause attribution is **UNKNOWN** and must not be '
        'attributed to an identified reader without evidence. This corrected note does not rewrite '
        'any original receipt. Source-byte and selected stat inventories were compared before '
        'and after this collation; access times are not an identity claim.\n\n')
    text += ('Raw command, cwd and environment are retained in T2/build-process.json and the '
        'frozen command/launch records. Recorded build argv (data only):\n\n```json\n'
        + json.dumps(observations['build']['command'], indent=2) + '\n```\n\n')
    text += ('Historical paths, local GNAT tool identities and Linux IPC/process-group assumptions '
        'are part of this exact local profile. The archived drivers are historical records, not '
        'portable automatic launchers. Inspect their frozen contracts, literal oracles, tool/source '
        'identities and all failure reviews before separately authorized reproduction. This '
        'collation authorizes no driver, compiler, proof or archive-member execution.\n\n')
    text += ('`python3 -I -S -B -Werror collate.py check` performs bounded archive membership and '
        'byte/hash checks only. It executes no archive content. The fixed raw credential-pattern '
        'scan found no match; that is a heuristic observation, not proof of secret absence. '
        'No private participant data was supplied in this scope.\n')
    return text.encode('utf-8')


def main():
    if sys.argv[1:] == ['check']:
        verify_archive(json.loads(read(OUT / 'index.json', 262144)))
        print('CHECKED_DATA_MEMBERS_AND_HASHES_ONLY')
        return
    need(sys.argv[1:] == [], 'fixed collate or check syntax')
    before, observations = inventory(), outcomes()
    index = create_archive(before)
    need(inventory() == before, 'source inventory changed during collation')
    index.update(schema='transport/second-failed-proof-attempt-bundle/1',
        status='COLLATED_FAILED_ATTEMPT_RAW_BYTES_DATA_ONLY', terminal_status='FAILED',
        native_build_process_exit=0, native_clean_claim='NOT_ESTABLISHED', proof='NOT_RUN',
        source_roots=dict(N=str(N), T2=str(T2), D=str(D)),
        selected_T2_files=list(T2_FILES), T2_excluded='compiled objects, binaries, source and tmp content',
        independent_actual_review_sha256=observations['review_sha256'],
        atime_cause='UNKNOWN_NO_READER_ATTRIBUTION',
        credential_scan='FIXED_RAW_BYTE_PATTERNS_NO_MATCH_HEURISTIC_ONLY',
        nested_archives='OPAQUE_NOT_EXECUTED_OR_RECURSIVELY_EXTRACTED')
    verify_archive(index)
    write(OUT / 'index.json', canonical(index) + b'\n')
    write(OUT / 'README.md', readme(index, observations))
    print(json.dumps(dict(status=index['status'], members=index['member_count'],
                         expanded_bytes=index['expanded_bytes'], archive=index['archive'])))


if __name__ == '__main__':
    main()
