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
C = Path('/dev/shm/semantic-transport-cli-boundary-design-20261029')
Q = Path('/dev/shm/semantic-transport-cli-boundary-qualification-20261029')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
D_FILES = ('clean-repro-cli-boundary-admission-01.json', 'verification-evidence-collation-admission-01.json',
    'cli-boundary-launch-01.stdout', 'cli-boundary-launch-01.stderr', 'cli-boundary-launch-01.exit',
    'cli-boundary-attempt-review-01.json')
REVIEW_SHA = '786c587c1bbaa5612a36694c09e1d2733e58c71964ceb4ca6dcd0690b691fefd'


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


def read(path, cap=4194304):
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
    files, omissions = {}, []
    for root, prefix in ((C, 'C'), (Q, 'Q')):
        rows, omitted = tree(root, prefix)
        need(not set(files).intersection(rows), 'duplicate name inventory')
        files.update(rows)
        omissions.extend(omitted)
    for name in D_FILES:
        path = D / name
        need(stat.S_ISREG(path.lstat().st_mode), 'required D regular file')
        files['D/' + name] = dict(path=str(path), source_stat=stat_row(path))
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
    raw = read(path)
    need(len(raw) <= 4194304, 'archive final bound')
    capacity()
    return dict(archive=dict(bytes=len(raw), sha256=sha(raw)), files=rows,
                member_count=len(rows), expanded_bytes=total, omissions=before['omissions'])


def verify_archive(index):
    path = OUT / 'observations.zip'
    raw = read(path)
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
            need(info.file_size == expected['bytes'] and total <= 4194304, 'expanded member bound')
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
    review = read(D / 'cli-boundary-attempt-review-01.json')
    need(sha(review) == REVIEW_SHA, 'independent actual-review pin')
    result = json.loads(read(Q / 'terminal-result-v2.json'))
    need(result['status'] == 'TESTED_CLI_BOUNDARIES_NORMAL_AND_OPTIMIZED', 'actual terminal')
    rows = result['inventory']
    need(len(rows) == 6 and all(r['status'] == 'PASS' for r in rows), 'six actual observations')
    need(json.loads(review)['decision'] == 'PASS_FINITE_ACTUAL_CLI_BOUNDARY_QUALIFICATION', 'review decision')
    return rows


def readme(index, rows):
    text = '# Actual accounting CLI boundary qualification\n\n'
    text += ('TESTED local observation: six recorded calls PASS in normal and optimized Python. '
        'Exact-plan and exact-ledger return INCOMPLETE with exit0; overflow returns the literal '
        'OUTPUT_BOUND refusal with exit1. Every complete stdout equals its frozen qualified API '
        'reference including the final LF; all stderr files are empty. This is API/CLI byte '
        'equivalence, not an independent semantic oracle or formal proof.\n\n')
    text += ('The data-only ZIP contains ' + str(index['member_count']) + ' unique regular-file members, '
        + str(index['expanded_bytes']) + ' expanded bytes, and ' + str(len(index['omissions']))
        + ' explicit symlink/special omissions. The index retains source paths, exact bytes/hashes '
        'and original stat observations. Nested ZIPs remain opaque bytes; no archived code was executed.\n\n')
    text += ('C/ retains design, literal expectations, v1 failures/preservation, both runners, helpers '
        'and implementation reviews. Q/ retains preparation, exact inputs, API references, root '
        'launch admission, all six dispatch journals/raw streams, mode reports and terminal result. '
        'D/ retains parent launch streams/exit, admissions and the independent actual-result review. '
        'The independent GPT-6.1 review is engineering review, not external-human validation.\n\n')
    text += ('Historical API-only/CLI-UNRUN receipts are unchanged. This additive result closes only '
        'the named actual-CLI boundary item. Benefit, measurement truth, study validity, whole-system '
        'proof and ACCEPTED_V1 remain unestablished.\n\n')
    text += ('Local runtime: /usr/bin/python3.14, executable SHA256 '
        'c6bc1ef497b896b7575c546b13f9bafe52e2066f184fdd3fec6af4b5b6349947, '
        'supported source HEAD b8aefc51a51d6f391e58460b95074f28f654f50a. This profile does not attest '
        'libraries/OS or establish portability to another host.\n\n')
    text += ('Historical root command (inspect only; it requires its original private paths and '
        'create-only launch state):\n\n```text\n/usr/bin/python3.14 -I -S -B -Werror '
        '/dev/shm/semantic-transport-cli-boundary-design-20261029/runner_v2.py run\n```\n\n')
    text += 'Recorded actual CLI argv arrays, preserved verbatim in Q/dispatch-v2/*--intent.json:\n\n```json\n'
    text += json.dumps([r['intent']['argv'] for r in rows], indent=2) + '\n```\n\n'
    text += ('Inspect the archive/index as untrusted data. `python3 -I -S -B -Werror collate.py check` '
        'checks only bounded archive membership/bytes/hashes; it executes no archive content. '
        'Historical absolute-path drivers are not portable automatic launchers. For separately '
        'authorized reproduction, use the existing comparison/accounting/check.py request interface: '
        'stage pinned plan/ledger/evidence bytes in a new private directory, construct a new canonical '
        'transport/accounting-request/1 with those absolute paths and held bytes/SHA256 descriptors, '
        'then supply --request NEW_REQUEST --expect-plan-sha256 HELD_PLAN_SHA '
        '--expect-ledger-sha256 HELD_LEDGER_SHA. Preserve independent pins and use the recorded '
        '-I -S -B -Werror flags, adding -O for the optimized mode. No automatic reproduction or '
        'new execution is authorized by this bundle.\n\n')
    text += ('Credential scan: fixed private-key/provider-token patterns found no match in the '
        'raw bytes archived here. This is a heuristic observation, not proof that arbitrary secrets '
        'cannot exist; no private participant data was supplied in this admitted scope.\n')
    return text.encode('utf-8')


def main():
    if sys.argv[1:] == ['check']:
        verify_archive(json.loads(read(OUT / 'index.json', 262144)))
        print('CHECKED_DATA_MEMBERS_AND_HASHES_ONLY')
        return
    need(sys.argv[1:] == [], 'fixed collate or check syntax')
    before, rows = inventory(), outcomes()
    index = create_archive(before)
    need(inventory() == before, 'source inventory changed during collation')
    index.update(schema='transport/actual-cli-qualification-bundle/1',
        status='COLLATED_RAW_BYTES_DATA_ONLY', actual_cli_observations=6, actual_cli_PASS=6,
        source_roots=dict(C=str(C), Q=str(Q), D=str(D)),
        independent_actual_review_sha256=REVIEW_SHA,
        credential_scan='FIXED_RAW_BYTE_PATTERNS_NO_MATCH_HEURISTIC_ONLY',
        nested_archives='OPAQUE_NOT_EXECUTED_OR_RECURSIVELY_EXTRACTED')
    verify_archive(index)
    write(OUT / 'index.json', canonical(index) + b'\n')
    write(OUT / 'README.md', readme(index, rows))
    print(json.dumps(dict(status=index['status'], members=index['member_count'],
                         expanded_bytes=index['expanded_bytes'], archive=index['archive'])))


if __name__ == '__main__':
    main()
