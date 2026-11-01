"""DRAFT: bounded inert-data collation; never execute or extract evidence members."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

OUT = Path(__file__).resolve().parent
A = OUT.parent
C = Path('/dev/shm/semantic-transport-proof-cgroup-design-20261029')
T5 = Path('/dev/shm/semantic-transport-proof-cgroup-20261029')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
ARCHIVE_CAP = 4194304
PARENT_CAP = 8388608
W = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
REVIEW_ROOT = Path('/dev/shm/semantic-transport-cgroup-independent-review-20261029/evidence')
W_HEAD = 'b8aefc51a51d6f391e58460b95074f28f654f50a'
INDEX_PIN = dict(bytes=7497, sha256='1a4dfd81899fad0a709c305fe98e6766c8dc3395d73a8826b393927a29f68783')
QUAL_PIN = dict(bytes=9878, sha256='405b94267e2009d8f7b9629d053e81e6752cb2b8099e3bc876b437b898634a33')
MANIFEST_PIN = dict(bytes=6560, sha256='7b61c16882b649141bd3288b8289ef635cfe04a01c3dd53341238a4c0cd4efd2')
REVIEW_PIN = dict(bytes=9062, sha256='480df57e36f370a3c5ef4a6e83df7b5edfa28f010ba14722da15a0d7f2a6af17')
NOTRUN_PIN = dict(bytes=2030, sha256='5c5a175906c360ca8f84e3a82b79460c2a2259c7a3fffc27f72a5847ecbbe869')
ARITH_PIN = dict(bytes=1426, sha256='0cc5d5e823b2a2b3851390bdd7e7e3cdea476a905b63e6b616fca97ac3c7a477')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    need(type(name) is str and 0 < len(name.encode('ascii')) <= 4096, 'ASCII name bound')
    parts = PurePosixPath(name).parts
    need(parts and not name.startswith('/') and len(parts) <= 12, 'relative member path')
    need(all(part not in ('', '.', '..') and re.fullmatch(r'[A-Za-z0-9._-]+', part)
         for part in parts), 'safe member components')
    need('/'.join(parts) == name, 'canonical relative path')
    return name


def file_stat(path):
    row = path.lstat()
    return {key: getattr(row, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_size',
            'st_blocks', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_nlink')}


def read(path, cap=1048576):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), 'no-follow read')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'regular bounded input')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    need(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
         for k in keys), 'stable bounded read')
    return raw


def prebudget(extra):
    need(type(extra) is int and 0 <= extra <= PARENT_CAP, 'prebudget argument')
    total, count, stack = 0, 0, [(A, 0)]
    for _ in range(1024):
        if not stack:
            need(total + extra <= PARENT_CAP, 'shared A allocated-byte prebudget')
            return total
        path, depth = stack.pop()
        row = path.lstat()
        total += max(row.st_size, row.st_blocks * 512)
        need(total + extra <= PARENT_CAP and depth <= 12, 'shared A allocation/depth')
        if stat.S_ISDIR(row.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    count += 1
                    need(count <= 1024, 'shared A entries')
                    stack.append((Path(entry.path), depth + 1))
        # Shared-parent intentional specials are allocation metadata only; never followed.
    raise ValueError('shared A traversal bound')


def write_new(path, raw, cap=262144):
    need(path.parent == OUT and type(raw) is bytes and len(raw) <= cap, 'derived output bound/path')
    prebudget(len(raw) + 4096)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, 'wb', buffering=0) as stream:
        need(stream.write(raw) == len(raw), 'short derived write')
        stream.flush()
        os.fsync(stream.fileno())
    prebudget(0)


class BoundedArchiveWriter:
    def __init__(self, stream):
        self.stream, self.extent = stream, 0
    def tell(self):
        return self.stream.tell()
    def seek(self, offset, whence=0):
        return self.stream.seek(offset, whence)
    def flush(self):
        self.stream.flush()
    def write(self, raw):
        end = self.stream.tell() + len(raw)
        need(end <= ARCHIVE_CAP, 'archive write/central-directory bound')
        prebudget(max(0, end - self.extent) + 4096 + 393216)
        written = self.stream.write(raw)
        need(written == len(raw), 'short archive write')
        self.extent = max(self.extent, end)
        return written


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
                need(seen <= 2048, 'source metadata entry bound')
                path, name = Path(entry.path), safe_name(relative + '/' + entry.name)
                row = file_stat(path)
                if stat.S_ISDIR(row['st_mode']):
                    stack.append((path, name, depth + 1))
                elif stat.S_ISREG(row['st_mode']):
                    need(name not in files, 'unique regular member name')
                    files[name] = dict(path=str(path), source_stat=row)
                else:
                    omission = dict(name=name, source_stat=row, reason='SYMLINK_OR_SPECIAL_NOT_DEREFERENCED')
                    if stat.S_ISLNK(row['st_mode']):
                        target = os.readlink(path)
                        need(len(target.encode('utf-8')) <= 4096, 'link target string bound')
                        omission['target_string_only'] = target
                    omissions.append(omission)
    raise ValueError('source directory traversal bound')


def held_read(path, descriptor, cap=1048576):
    need(type(descriptor) is dict and type(descriptor.get('bytes')) is int
         and 0 <= descriptor['bytes'] <= cap, 'held descriptor bound')
    raw = read(path, cap)
    need(len(raw) == descriptor['bytes'] and sha(raw) == descriptor['sha256'], 'held byte/hash identity')
    return raw


def require_task_absent():
    try:
        T5.lstat()
    except FileNotFoundError:
        return
    raise ValueError('T5 unexpectedly exists; no actual-task data accepted by this mode')


def metadata_dir():
    marker = W / '.git'
    need(not marker.is_symlink(), 'git marker symlink')
    if marker.is_dir():
        return marker
    raw = read(marker, 4096).decode('ascii').strip()
    need(raw.startswith('gitdir: ') and len(raw.splitlines()) == 1, 'git worktree marker')
    target = Path(raw[8:])
    return Path(os.path.abspath(target if target.is_absolute() else W / target))


def source_head():
    gitdir = metadata_dir()
    head = read(gitdir / 'HEAD', 4096).decode('ascii').strip()
    if re.fullmatch('[0-9a-f]{40}', head):
        return head
    need(head.startswith('ref: refs/'), 'git HEAD format')
    ref = safe_name(head[5:])
    common = gitdir
    if (gitdir / 'commondir').exists():
        relative = read(gitdir / 'commondir', 4096).decode('ascii').strip()
        common = Path(os.path.abspath(gitdir / relative))
    for parent in (gitdir, common):
        path = parent / ref
        if path.exists():
            value = read(path, 4096).decode('ascii').strip()
            need(re.fullmatch('[0-9a-f]{40}', value), 'loose git ref')
            return value
    raw = read(common / 'packed-refs', 1048576).decode('ascii')
    matches = [line.split(' ', 1)[0] for line in raw.splitlines()
               if line.endswith(' ' + ref) and re.fullmatch('[0-9a-f]{40} .+', line)]
    need(len(matches) == 1, 'exact packed git ref')
    return matches[0]


def qualification_readiness():
    value = json.loads(read(OUT / 'READY-QUALIFICATION.json', 65536))
    need(value['status'] == 'ADMITTED_FIFTH_QUALIFICATION_ONLY_COLLATION', 'separate root READY required')
    need(value['C_frozen'] is True and value['W_source_freeze'] is True
         and value['include_W_original_native'] is True, 'explicit original-source snapshot admission')
    held_read(Path(__file__).resolve(), value['collator'], 32768)
    require_task_absent()
    index = json.loads(held_read(C / 'runner-index.json', INDEX_PIN))
    qual = json.loads(held_read(C / 'qualification-01.json', QUAL_PIN))
    manifest = json.loads(held_read(C / 'source-manifest.json', MANIFEST_PIN))
    review = json.loads(held_read(D / 'proof-cgroup-implementation-review-01.json', REVIEW_PIN))
    held_read(D / 'proof-cgroup-native-not-run-01.json', NOTRUN_PIN)
    held_read(D / 'proof-cgroup-native-not-run-arithmetic-01.json', ARITH_PIN)
    need(review['verdict'] == 'NOT_NATIVE_READY_IMPLEMENTATION_QUALIFICATION_INCOMPLETE', 'retained review verdict')
    need(review['review_aggregate'] == 'FAILED_REVIEWER_CONTROL_ISOLATION_WITH_SEPARATELY_SCOPED_PASS_EVIDENCE', 'review isolation failure retained')
    need(qual['status'] == 'PURE_LOGIC_PASS_IMPLEMENTATION_QUALIFICATION_INCOMPLETE', 'incomplete qualification scope')
    need(all(number == 0 for number in qual['no_actual_actions'].values()), 'authored actual-action scope')
    need(len(index['files']) == 32 and len(review['readback']['evidence']) == 9, 'frozen source/reviewer rosters')
    need(source_head() == W_HEAD, 'separately checked original W HEAD')
    need(type(value['compaction_dependencies']) is list and 3 <= len(value['compaction_dependencies']) <= 32,
         'complete explicit compaction dependency roster')
    return value, index, qual, manifest, review


def merge_pins(target, additional):
    need(type(additional) is dict and len(additional) <= 64, 'bounded held map')
    for name, pin in additional.items():
        safe_name(name)
        if name in target:
            need(target[name] == pin, 'conflicting held member pins')
        target[name] = pin


def record(files, member, path, pin=None):
    safe_name(member)
    need(member not in files and stat.S_ISREG(path.lstat().st_mode), 'unique regular record')
    row = dict(path=str(path), source_stat=file_stat(path))
    if pin is not None:
        held_read(path, pin, member_cap(member))
        row['held_pin'] = pin
    files[member] = row


def parent_records(files, index, qual, ready):
    external = dict(index['external_receipts'])
    for path, pin in qual['external_bound_receipts'].items():
        need(path not in external or external[path] == pin, 'external receipt conflict')
        external[path] = pin
    external.update({str(D / 'proof-cgroup-implementation-review-01.json'): REVIEW_PIN,
        str(D / 'proof-cgroup-native-not-run-01.json'): NOTRUN_PIN,
        str(D / 'proof-cgroup-native-not-run-arithmetic-01.json'): ARITH_PIN})
    extra = ready.get('parent_records', {})
    need(type(extra) is dict and len(extra) <= 32, 'extra parent receipt bound')
    for name, pin in extra.items():
        safe_name(name)
        need('/' not in name and name.startswith('proof-cgroup-'), 'scoped extra parent data')
        path = str(D / name)
        need(path not in external or external[path] == pin, 'extra parent conflict')
        external[path] = pin
    for text, pin in external.items():
        path = Path(text)
        need(path.parent == D and path.name.startswith('proof-cgroup-'), 'fixed D scope')
        record(files, 'D/' + path.name, path, pin)


def compaction_records(files, ready):
    roles = set()
    for item in ready['compaction_dependencies']:
        member = safe_name('Compaction/' + item['member'])
        path = Path(item['path'])
        need(path.is_absolute() and path.is_relative_to(A) and not path.is_relative_to(OUT),
             'explicit nonrecursive A compaction dependency')
        need(type(item['roles']) is list and item['roles'] and len(item['roles']) <= 4,
             'compaction provenance roles')
        roles.update(item['roles'])
        record(files, member, path, item['pin'])
    need({'archive', 'index', 'receipt', 'restore_evidence'} <= roles,
         'embed archive/index/receipt/full restore evidence')


def original_native_records(files, manifest):
    need(manifest['all_project_units'] is True and len(manifest['items']) == 38, 'original38 manifest')
    names = set()
    for item in manifest['items']:
        relative = safe_name(item['path'])
        need(relative not in names and Path(relative).suffix in ('.adb', '.ads', '.gpr'), 'native source path')
        names.add(relative)
        record(files, 'W-original-native/' + relative, W / relative, item)
    need(source_head() == W_HEAD, 'original W HEAD changed')


def qualification_inventory(ready, index, qual, manifest, review):
    files, omissions = tree(C, 'C')
    for name in tuple(files):
        path = PurePosixPath(name)
        if '__pycache__' in path.parts or path.suffix in ('.pyc', '.o', '.ali'):
            row = files.pop(name)
            omissions.append(dict(name=name, source_stat=row['source_stat'], reason='DIRECT_COMPILED_OBJECT_OR_CACHE_EXCLUDED'))
    held = dict(index['files'])
    merge_pins(held, qual['raw_evidence'])
    merge_pins(held, qual['retained_history'])
    merge_pins(held, {'runner-index.json': INDEX_PIN, 'source-manifest.json': MANIFEST_PIN})
    for name, pin in held.items():
        member = safe_name('C/' + name)
        need(member in files, 'all held C members present')
        held_read(Path(files[member]['path']), pin)
        files[member]['held_pin'] = pin
    original_native_records(files, manifest)
    parent_records(files, index, qual, ready)
    compaction_records(files, ready)
    need(review['review_evidence_root'] == str(REVIEW_ROOT), 'fixed reviewer root')
    for name, pin in review['readback']['evidence'].items():
        safe_name(name)
        need('/' not in name, 'review evidence leaf')
        record(files, 'Reviewer/' + name, REVIEW_ROOT / name, pin)
    need(len(files) <= 512, 'direct member ceiling')
    need(sum(row['source_stat']['st_size'] for row in files.values()) <= ARCHIVE_CAP, 'expanded preflight cap')
    require_task_absent()
    return dict(files=dict(sorted(files.items())), omissions=sorted(omissions, key=lambda row: row['name']))


def member_cap(name):
    return ARCHIVE_CAP if name.startswith('Compaction/') and name.endswith('.zip') else 1048576


def credential_scan(raw):
    patterns = (rb'-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----',
                rb'sk-proj-[A-Za-z0-9_-]{16,}', rb'ghp_[A-Za-z0-9]{20,}', rb'AKIA[A-Z0-9]{16}')
    need(not any(re.search(pattern, raw) for pattern in patterns), 'credential-pattern hit; refuse')


def create_archive(before):
    path, files, total = OUT / 'observations.zip', {}, 0
    prebudget(4096 + 393216)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb', buffering=0) as stream:
        target = BoundedArchiveWriter(stream)
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, source in before['files'].items():
                raw = read(Path(source['path']), member_cap(name))
                credential_scan(raw)
                total += len(raw)
                need(total <= ARCHIVE_CAP, 'expanded archive ceiling')
                info = zipfile.ZipInfo(safe_name(name), date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system, info.external_attr = 3, (stat.S_IFREG | 0o400) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, raw)
                files[name] = dict(bytes=len(raw), sha256=sha(raw), **source)
        target.flush()
        os.fsync(stream.fileno())
    raw = read(path, ARCHIVE_CAP)
    prebudget(0)
    return dict(archive=dict(bytes=len(raw), sha256=sha(raw)), files=files,
                member_count=len(files), expanded_bytes=total, omissions=before['omissions'])


def verify_archive(index):
    raw = held_read(OUT / 'observations.zip', index['archive'], ARCHIVE_CAP)
    need(len(raw) <= ARCHIVE_CAP, 'archive byte ceiling')
    with zipfile.ZipFile(OUT / 'observations.zip') as archive:
        infos = archive.infolist()
        need(len(infos) == len(index['files']) <= 512, 'exact bounded archive roster')
        names = [safe_name(info.filename) for info in infos]
        need(all(name.split('/')[0] in ('C', 'D', 'Compaction', 'Reviewer', 'W-original-native')
                 for name in names), 'qualification-only namespaces; no T5 data')
        need(len(set(names)) == len(names) and set(names) == set(index['files']), 'unique complete names')
        total = 0
        for info in infos:
            row = index['files'][info.filename]
            need(stat.S_ISREG(info.external_attr >> 16) and not info.flag_bits & 1, 'regular unencrypted member')
            need(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'declared compression only')
            need(info.file_size == row['bytes'] <= member_cap(info.filename), 'member-size cap')
            total += info.file_size
            need(total <= ARCHIVE_CAP, 'expanded aggregate bound')
            with archive.open(info) as stream:
                member = stream.read(info.file_size + 1)
            need(len(member) == row['bytes'] and sha(member) == row['sha256'], 'member identity readback')
    need(total == index['expanded_bytes'], 'expanded byte identity')


def qualification_readme(result, qual, review):
    text = '# Fifth item: qualification-only; native NOT_RUN\n\n'
    text += ('T5 is absent. No task launch/terminal/source-copy/cleanup/proof data is fabricated. '
        'W-original-native/ is only the38 manifest/HEAD-checked original sources, never T5/source.\n\n')
    text += ('Current status: NOT_NATIVE_READY_IMPLEMENTATION_QUALIFICATION_INCOMPLETE. '
        'Total-three-second actual-control harness UNIMPLEMENTED; complete integrated exception '
        'qualification pending; current authored cgroup/native actual controls NOT_RUN. Retained69 '
        'normal/69 optimized selected pure/mock passes were not rerun by this collator.\n\n')
    text += ('Review aggregate remains FAILED_REVIEWER_CONTROL_ISOLATION_WITH_SEPARATELY_SCOPED_PASS_EVIDENCE. '
        'Corrected local3/3 passes in each mode do not erase failed reviewer source/streams. '
        'Stale missing-kill concern DISPROVED. Failed reviewer runs reached raw waitpid query code; '
        'count/result has no independent syscall telemetry. Authored actualcontrols0 is not '
        'blanket zero process API calls.\n\n')
    text += ('C/ retains current files, raw pure evidence and nested baseline/diff/failure archives. '
        'Reviewer/ embeds all9 pinned raw files. Compaction/ embeds archive/index/receipt/full '
        'restore evidence, not dangling A paths. Some overwritten old draft bytes were never '
        'retained; hash/findings-only limits remain. Nested ZIPs are opaque.\n\n')
    text += ('D/ preserves final review, original NOT_RUN and later arithmetic addendum. This does '
        'not reset cutoff or retroactively admit native work. T1-T4 failures, resource/invalid-admin '
        'histories and UNKNOWN attribution remain unchanged; restored footprint is not retroactive compliance.\n\n')
    text += ('Members: ' + str(result['member_count']) + '; expanded bytes: ' + str(result['expanded_bytes'])
        + '; explicit omissions: ' + str(len(result['omissions'])) + '. No archived symlinks/specials '
        'or direct caches/objects. Source inventories and W HEAD checked before/after.\n\n')
    text += ('Inert collation only: no native/cgroup/model/provider operation, signalling or proc '
        'census. collate_qualification.py check examines bounded archive-byte/hash identities only; '
        '-O is a separate data check. Historical drivers are not portable launchers. Engineering '
        'review is not external-human validation; clean proof reproduction/whole-system correctness '
        'and ACCEPTED_V1 remain unproved.\n')
    return text.encode('utf-8')


def collate_qualification():
    ready, index, qual, manifest, review = qualification_readiness()
    before = qualification_inventory(ready, index, qual, manifest, review)
    result = create_archive(before)
    need(qualification_inventory(ready, index, qual, manifest, review) == before, 'source inventory changed')
    require_task_absent()
    need(source_head() == W_HEAD, 'W HEAD unchanged')
    result.update(schema='transport/fifth-qualification-only-not-run-bundle/1',
        status='COLLATED_QUALIFICATION_ONLY_NATIVE_NOT_RUN', native_task='ABSENT_NO_T5_DATA',
        current_native_readiness=review['verdict'], review_aggregate=review['review_aggregate'],
        source_roots=dict(C=str(C), W_original_native=str(W), D=str(D), Reviewer=str(REVIEW_ROOT)),
        original_native_source_files=38, original_W_HEAD=W_HEAD,
        actual_authored_actions=qual['no_actual_actions'], reviewer_process_API_scope='RAW_WAITPID_PATH_NOT_BLANKET_ZERO',
        proof='NOT_RUN_NO_SUMMARY', nested_archives='OPAQUE_NOT_EXTRACTED_OR_EXECUTED',
        credential_scan='FIXED_RAW_BYTE_PATTERNS_ONLY', acceptance='NOT_ASSESSED')
    verify_archive(result)
    write_new(OUT / 'index.json', canonical(result) + bytes((10,)))
    write_new(OUT / 'README.md', qualification_readme(result, qual, review), 4096)
    print(json.dumps(dict(status=result['status'], members=result['member_count'],
                         expanded_bytes=result['expanded_bytes'], archive=result['archive'])))


def main():
    if sys.argv[1:] == ['check']:
        verify_archive(json.loads(read(OUT / 'index.json', 262144)))
        print('CHECKED_QUALIFICATION_ONLY_INERT_MEMBERS_AND_HASHES')
    elif sys.argv[1:] == ['collate-qualification']:
        collate_qualification()
    else:
        raise ValueError('fixed collate-qualification/check syntax; separate root READY required')


if __name__ == '__main__':
    main()
