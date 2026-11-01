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
Q = Path('/dev/shm/semantic-transport-proof-quiescent-design-20261029')
T4 = Path('/dev/shm/semantic-transport-proof-quiescent-20261029')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
T4_FILES = ('before.json', 'terminal.json', 'launch-admission.json', 'build-process.json',
            'build.stdout', 'build.stderr', 'proof-process.json', 'proof.stdout', 'proof.stderr')
D_FILES = ('verification-evidence-collation-admission-01.json',
    'proof-quiescent-calendar-adoption-01.json', 'proof-quiescent-calendar-amendment-02.json',
    'proof-quiescent-calendar-review-02.json', 'proof-quiescent-calendar-review-02.json.invalid-serialization-01',
    'proof-quiescent-calendar-scope-amendment-01.json', 'proof-quiescent-calendar-scope-review-01.json',
    'proof-quiescent-calendar-scope-review-01.json.invalid-serialization-01',
    'proof-quiescent-calendar-v3-packaging-01.json', 'proof-quiescent-draft-counterexample-01.json',
    'proof-quiescent-fixture-compaction-admission-01.json', 'proof-quiescent-fixture-compaction-admission-02.json',
    'proof-quiescent-fixture-resource-recovery-01.json', 'proof-quiescent-implementation-review-01.json',
    'proof-quiescent-observation-design-review-01.json', 'proof-quiescent-observation-implementation-admission-01.json',
    'proof-quiescent-observation-owner-design-01.json', 'proof-quiescent-observation-owner-design-review-01.json',
    'proof-quiescent-v3-final-review-01.json', 'proof-quiescent-launch-01.json',
    'proof-quiescent-launch-01.stdout', 'proof-quiescent-launch-01.stderr', 'proof-quiescent-launch-01.exit',
    'proof-quiescent-attempt-review-01.json', 'clean-proof-attempt-review-01.json',
    'proof-ipc-attempt-review-01.json', 'proof-lifetime-attempt-review-01.json')
HELD = {'Q/runner-index.json': (7266, '4fda3d407ad754ff3508088b39b3219a814e64a76dc95b6b362bd18d2e65fa20'),
    'D/proof-quiescent-attempt-review-01.json': (14353, '2bce039ee3163530abb5ea8942641e25e689924a9b7b03486ec78d5ec007c504'),
    'D/proof-quiescent-launch-01.json': (6639, '7c9c14fd58d1b2640ff0e99f4f4d77f5e9a3c647dc1d9911c0236ce7218ecbcf'),
    'T4/terminal.json': (96695, 'b81cff2d24328bad542720c104d196f9bbd00fa401ea2393d4ade1a4252ab62e'),
    'T4/build-process.json': (26569, '0f44967e16c39596ab85365f29718b75cf283679feb675b4e8495af599b3f13f'),
    'T4/proof-process.json': (39267, '426d6d6c91fd76f916823d75fbfe888c2aee5d912713db195eb054aef142ee1e')}


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
    files, omissions = tree(Q, 'Q')
    for name in tuple(files):
        path = PurePosixPath(name)
        if '__pycache__' in path.parts or path.suffix in ('.pyc', '.o', '.ali'):
            row = files.pop(name)
            omissions.append(dict(name=name, source_stat=row['source_stat'], reason='COMPILED_OBJECT_OR_CACHE_EXCLUDED'))
    source_files, source_omissions = tree(T4 / 'source', 'T4/source')
    need(not source_omissions and len(source_files) == 38, 'strict exact38 source inventory')
    manifest = json.loads(read(Q / 'source-manifest.json'))
    expected = {'T4/source/' + row['path']: row for row in manifest['items']}
    need(set(source_files) == set(expected), 'exact source-manifest names')
    for name, row in source_files.items():
        raw = read(Path(row['path']))
        need(len(raw) == expected[name]['bytes'] and sha(raw) == expected[name]['sha256'], 'source pin')
    files.update(source_files)
    for root, prefix, names in ((T4, 'T4', T4_FILES), (D, 'D', D_FILES)):
        for name in names:
            path = root / name
            need(stat.S_ISREG(path.lstat().st_mode), 'required selected regular file')
            files[prefix + '/' + name] = dict(path=str(path), source_stat=stat_row(path))
    for name, held in HELD.items():
        raw = read(Path(files[name]['path']))
        need(len(raw) == held[0] and sha(raw) == held[1], 'explicit root held pin')
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
    review_raw = read(D / 'proof-quiescent-attempt-review-01.json')
    review = json.loads(review_raw)
    need(review['verdict'] == 'VERIFIED_TERMINAL_FAILURE_PROOF_INCOMPLETE', 'actual-review verdict')
    terminal = json.loads(read(T4 / 'terminal.json'))
    build = json.loads(read(T4 / 'build-process.json'))
    proof = json.loads(read(T4 / 'proof-process.json'))
    need(terminal['status'] == 'FAILED', 'permanent failed terminal')
    need(build['status'] == 'SUCCESS' and build['returncode'] == 0
         and build['capture_complete'] and build['terminal_group_absent'], 'qualified build observation')
    need(proof['status'] == 'FAILED' and proof['returncode'] == -9
         and not proof['capture_complete'], 'incomplete interrupted proof')
    need(not (T4 / 'obj/gnatprove/gnatprove.out').exists(), 'unexpected complete proof summary')
    need(not (T4 / 'obj/gnatprove/why3.conf').exists(), 'unexpected generated config must be explicitly scoped')
    need(len(read(T4 / 'proof.stdout')) == 64 and len(read(T4 / 'proof.stderr')) == 0, 'raw phase1-only proof capture')
    return dict(review_sha256=sha(review_raw), review=review, terminal=terminal, build=build, proof=proof)


def readme(index, observations):
    text = '# Fourth native clean-proof attempt: retained failure\n\n'
    text += ('T4 remains **FAILED**. The build record is SUCCESS: exit0, complete capture and '
        'owned group absent. Proof then returned -9 with incomplete capture after the fixed '
        'round8 global proc census failed before identifying missing PID1032727. The only proof '
        'stdout is the64-byte Phase1 heading; stderr is empty. There is no complete gnatprove '
        'summary or generated Why3 config. The exact proof oracle is **NOT_SATISFIED**, and no '
        'zero-diagnostic/count/proof result follows.\n\n')
    text += ('Correction: root initially called the missing PID foreign and immediately '
        'corrected that attribution. PID1032727 group/session/owner/creator/deletion cause remain '
        '**UNKNOWN**. This archive does not classify it as foreign, owned, hostile or harmless. '
        'Recorded timestamps describe observations, not authenticated creator/deletion times.\n\n')
    text += ('The data-only archive has ' + str(index['member_count']) + ' unique regular '
        'members, ' + str(index['expanded_bytes']) + ' expanded bytes, and '
        + str(len(index['omissions'])) + ' explicit omissions. Symlinks and special test entries '
        'are never dereferenced; target strings alone are retained for links. Nested ZIPs are '
        'opaque bytes. Direct compiler objects/binaries/cache are excluded.\n\n')
    text += ('Q/ preserves current Qv3 indexed source/design/baseline/control/failure/compaction '
        'and calendar histories. T4/source/ contains the exact38 held-manifest source/GPR files; '
        'other T4/ records are selected before/launch/build/proof/raw/terminal evidence. D/ includes '
        'the operative adoption/calendar02/v3 reviews, invalid administrative JSON originals as '
        'raw bytes, launch captures and full actual/earlier-failure reviews. No unrelated cgroup '
        'or future proposal is selected. Qv2 in the earlier collation plan is historical; actual '
        'launch used the independently reviewed Qv3/calendar02 adoption.\n\n')
    text += ('Preserve distinct scopes:18 current narrow pure controls and a separate23 '
        'independent controls receipt were not rerun here. Earlier65 logic PASS coexists with '
        'aggregate FAILED_RESOURCE_BOUND. Three earlier actual Python controls apply only to '
        'their older pinned source. Restored Q1MiB is a separate observed readback, never '
        'retroactive compliance. T1/T2/T3/T4 remain failed; prior atime-cause attribution is UNKNOWN.\n\n')
    text += ('Independent actual-review SHA256: ' + observations['review_sha256'] + '. '
        'Engineering review is not external-human validation. Exact argv/cwd/environment and '
        'local tool/canonical/source identities are retained in raw records. These historical '
        'absolute-path drivers are not portable automatic launchers. No archived/native/CLI/model '
        'code, signal or proc census was executed by this collation.\n\n')
    text += ('`python3 -I -S -B -Werror collate.py check` checks only bounded archive membership '
        'and byte/hash identities; add -O for the optimized data check. Complete selected source '
        'inventories are compared before/after; all archived bytes are read back. Access times '
        'are not source identity. Credential-pattern checks are heuristic only. No formal proof, '
        'whole-system assurance, semantic/study benefit, release or ACCEPTED_V1 is claimed.\n')
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
    index.update(schema='transport/fourth-failed-proof-attempt-bundle/1',
        status='COLLATED_FAILED_ATTEMPT_RAW_BYTES_DATA_ONLY', terminal_status='FAILED',
        native_build_process_exit=0, build='SUCCESS_COMPLETE_CAPTURE_GROUP_ABSENT',
        fresh_full_proof='NOT_ESTABLISHED', proof='FAILED_INCOMPLETE_RETURN_MINUS9',
        proof_summary='ABSENT', generated_why3_config='ABSENT', proof_oracle='NOT_SATISFIED',
        exact_source_files=38, source_roots=dict(Q=str(Q), T4=str(T4), D=str(D)),
        selected_T4_files=list(T4_FILES), excluded='compiler objects, binaries, cache and tmp content',
        missing_PID1032727_group_creator='UNKNOWN_CORRECTED_NO_FOREIGN_ATTRIBUTION',
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
