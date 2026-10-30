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
M = Path('/dev/shm/semantic-transport-proof-lifetime-design-20261029')
T3 = Path('/dev/shm/semantic-transport-proof-lifetime-20261029')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
REVIEW_SHA = 'f2cc83d375d5e0c77a0f92a02050dc6a8e0fafd1d47b890f8a723201df7d7dd7'
T3_FILES = ('before.json', 'terminal.json', 'launch-admission.json', 'build-process.json',
            'build.stdout', 'build.stderr')
D_FILES = ('verification-evidence-collation-admission-01.json', 'proof-directory-lifetime-design-01.json',
    'proof-ipc-calendar-adoption-01.json', 'proof-lifetime-design-admission-01.json',
    'proof-lifetime-design-review-01.json', 'proof-lifetime-implementation-admission-01.json',
    'proof-lifetime-implementation-review-01.json', 'proof-lifetime-launch-01.json',
    'proof-lifetime-launch-01.stdout', 'proof-lifetime-launch-01.stderr',
    'proof-lifetime-launch-01.exit', 'proof-lifetime-attempt-review-01.json')


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
    for _ in range(2048):
        if not stack:
            return files, omissions
        parent, relative, depth = stack.pop()
        need(depth <= 10 and not parent.is_symlink(), 'source directory depth/type')
        with os.scandir(parent) as entries:
            for entry in entries:
                seen += 1
                need(seen <= 2048, 'source entry bound')
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
    files, omissions = tree(M, 'M')
    source_files, source_omissions = tree(T3 / 'source', 'T3/source')
    need(not source_omissions and len(source_files) == 38, 'strict exact38 source inventory')
    manifest = json.loads(read(M / 'source-manifest.json'))
    expected = {'T3/source/' + row['path']: row for row in manifest['items']}
    need(set(source_files) == set(expected), 'exact source-manifest names')
    for name, row in source_files.items():
        raw = read(Path(row['path']))
        need(len(raw) == expected[name]['bytes'] and sha(raw) == expected[name]['sha256'], 'source pin')
    files.update(source_files)
    for root, prefix, names in ((T3, 'T3', T3_FILES), (D, 'D', D_FILES)):
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
    review_raw = read(D / 'proof-lifetime-attempt-review-01.json')
    need(len(review_raw) == 15040 and sha(review_raw) == REVIEW_SHA, 'held actual-review pin')
    review = json.loads(review_raw)
    need(review['verdict'] == 'VERIFIED_TERMINAL_FAILURE_PROOF_NOT_RUN', 'actual-review verdict')
    terminal = json.loads(read(T3 / 'terminal.json'))
    build = json.loads(read(T3 / 'build-process.json'))
    need(terminal['status'] == 'FAILED' and build['status'] == 'FAILED', 'retained failed third attempt')
    need(build['returncode'] == -15 and not build['capture_complete'], 'retained interrupted build')
    failure = build['runtime_inventory']['last_failed_observation']
    need(failure['id'] == 76 and 'tmp/ccFoAVu8.s' in failure['error'], 'retained acquisition failure')
    absent = ('proof-process.json', 'proof.stdout', 'proof.stderr', 'obj/gnatprove/gnatprove.out')
    need(not any((T3 / name).exists() for name in absent), 'unexpected proof record/stream/summary')
    return dict(review_sha256=sha(review_raw), review=review, terminal=terminal, build=build)


def readme(index, observations):
    text = '# Third native clean-proof attempt: retained failure\n\n'
    text += ('Observed terminal status: **FAILED**. The runtime scanner refused an entry that '
        'was listed but absent at lstat: `tmp/ccFoAVu8.s` at observation76. The owned build '
        'attempt was interrupted. **Proof was NOT_RUN; no new proof summary exists.** T1/T2/T3 '
        'remain failed. No fourth attempt, forgiveness, source edit or execution is authorized '
        'by this data bundle.\n\n')
    text += ('The archive contains ' + str(index['member_count']) + ' unique regular files, '
        + str(index['expanded_bytes']) + ' expanded bytes, and '
        + str(len(index['omissions'])) + ' explicit intentional-special omissions. Symlinks '
        'are recorded by target string only, never dereferenced. Nested ZIPs remain opaque.\n\n')
    text += ('M/ contains every frozen regular design/helper/review/preservation file. T3/source/ '
        'contains exactly the38 manifest-pinned source/GPR files, checked against the held manifest. '
        'Other T3/ entries are selected before/launch/build-process/raw-stream/terminal records. '
        'D/ contains design/implementation/calendar grants and reviews, parent launch captures '
        'and the independent actual-attempt review. Compiler objects, new binaries and cache '
        'remain outside this archive. Tool and canonical binary identities are pinned metadata, '
        'not redistributed binaries.\n\n')
    text += ('Independent actual-review SHA256: ' + observations['review_sha256'] + '. '
        'Independent engineering review does not substitute for external humans. Raw diagnostics '
        'and UNKNOWN fields are preserved: exact path creator, deletion syscall/time and '
        'authenticated provenance are not established. Historical T1/T2 outcomes and the earlier '
        'atime-cause UNKNOWN correction remain unchanged.\n\n')
    text += ('Raw argv/cwd/environment live in T3/build-process.json, launch/command records '
        'and the original stream files. These absolute-path drivers are historical local records, '
        'not portable automatic launchers. Inspect the frozen contracts, oracle, all38 source '
        'pins, tool/canonical identities and actual review before any separately admitted '
        'reproduction. No archived program is executed by this collation.\n\n')
    text += ('`python3 -I -S -B -Werror collate.py check` checks only bounded archive inventory '
        'and byte/hash identities, without executing members. Source inventories were compared '
        'before/after collation; every archived raw file was read back by hash. The fixed raw '
        'credential-pattern scan found no match; this is heuristic, not proof of secret absence. '
        'No formal proof, whole-system assurance, benefit, study validity or ACCEPTED_V1 follows.\n')
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
    index.update(schema='transport/third-failed-proof-attempt-bundle/1',
        status='COLLATED_FAILED_ATTEMPT_RAW_BYTES_DATA_ONLY', terminal_status='FAILED',
        native_build_process_exit=observations['build'].get('returncode'),
        native_clean_claim='NOT_ESTABLISHED', proof='NOT_RUN', proof_summary='ABSENT',
        exact_source_files=38, source_roots=dict(M=str(M), T3=str(T3), D=str(D)),
        selected_T3_files=list(T3_FILES), excluded='compiler objects, binaries, cache and tmp content',
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
