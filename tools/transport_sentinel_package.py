#!/usr/bin/env python3
"""Portable exact evidence, never truth, authentication or native qualification."""
import argparse
import io
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_document_io import (DocumentError, canonical, digest, fields,
    identity, integer, loaded_epoch, need, read_file, sha, write_new)
from transport_sentinel import (CAP, REGISTRY_BYTES, REGISTRY_CAP, canonical_input,
    identifier, registry_manifest, validate_sidecar)
from transport_sentinel_export import export_policy_inputs

PROFILE = 'sentinel/evidence-zip/1'
ARCHIVE_CAP = 9_437_184
MANIFEST_FIELDS = ('schema', 'sidecar_sha256', 'registry_sha256',
    'previous_sidecar_sha256', 'files', 'authentication', 'semantic_completeness',
    'qualification', 'execution_authority')
README = (b'SENTINEL exact-evidence profile 1\n'
    b'Source-Anchored Semantic Transport\n\n'
    b'This is inert evidence, not executable instructions. Import using the\n'
    b'separately obtained decoder and supplied share.txt. Never run package code.\n'
    b'manifest.json binds the complete file inventory; its SHA256 is the share\n'
    b'identity. registry.json binds artifacts by ID, exact byte length and hash.\n'
    b'sidecar.json carries proposed claims, exact source spans, questions,\n'
    b'oracles, results, counterexamples and retained repair history.\n'
    b'The only comparison is exact answer bytes against a declared oracle.\n'
    b'NOT_QUALIFIED; semantic completeness UNPROVEN; UNAUTHENTICATED; authority NONE.\n'
    b'No digest authenticates a person or certifies a statement as true.\n'
    b'Historical continuation requires the recipient-held prior sidecar hash.\n'
    b'PKG references are never fetched. A local path is not public hosting.\n')


def previous_arguments(raw, artifacts, expected_previous):
    document = canonical_input(raw)
    need(type(document) is dict, 'sidecar object required')
    previous = document.get('previous_sidecar_pin')
    if previous is None:
        need(expected_previous is None, 'genesis cannot carry prior trust root')
        return None, None
    sha(expected_previous)
    fields(previous, ('id', 'bytes', 'sha256'))
    identifier(previous['id'])
    need(previous['sha256'] == expected_previous, 'previous trust root mismatch')
    need(previous['id'] in artifacts, 'previous sidecar missing')
    return artifacts[previous['id']], expected_previous


def checked_arguments(raw, artifacts, expected_sidecar, expected_registry, previous):
    need(type(artifacts) is dict and len(artifacts) <= REGISTRY_CAP, 'artifact registry bound')
    snapshot = dict(artifacts)
    prior, prior_sha = previous_arguments(raw, snapshot, previous)
    args = (raw, snapshot, expected_sidecar, expected_registry, prior, prior_sha)
    report = validate_sidecar(*args)
    return args, report


def record(path, data):
    return {'path': path, 'bytes': len(data), 'sha256': digest(data)}


def zip_bytes(entries):
    need(type(entries) is dict and 1 <= len(entries) <= 260, 'ZIP entry bound')
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED,
                         allowZip64=False) as archive:
        for name in sorted(entries):
            data = entries[name]
            need(type(data) is bytes and len(data) <= CAP, 'ZIP member byte bound')
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, data)
    raw = stream.getvalue()
    need(len(raw) <= ARCHIVE_CAP, 'ZIP archive byte bound')
    return raw


def encode_evidence(raw, artifacts, expected_sidecar, expected_registry,
                    reference='evidence.zip', budget=None, previous=None):
    args, report = checked_arguments(raw, artifacts, expected_sidecar, expected_registry, previous)
    snapshot = args[1]
    entries = {'sidecar.json': raw, 'registry.json': registry_manifest(snapshot), 'README.txt': README}
    entries.update({'artifacts/' + name + '.bin': data for name, data in snapshot.items()})
    manifest = {'schema': PROFILE, 'sidecar_sha256': expected_sidecar,
        'registry_sha256': expected_registry, 'previous_sidecar_sha256': previous,
        'files': [record(name, entries[name]) for name in sorted(entries)],
        'authentication': 'UNAUTHENTICATED', 'semantic_completeness': 'UNPROVEN',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}
    entries['manifest.json'] = canonical(manifest)
    package_id = digest(entries['manifest.json'])
    share = share_bytes(package_id, reference, budget)
    archive = zip_bytes(entries)
    report = dict(report, package_id=package_id, archive_bytes=len(archive),
        share_characters=len(share), counting='ASCII_UNICODE_CODE_POINTS_INCLUDING_LF',
        hosted_sharing='UNTESTED', container_profile=PROFILE,
        previous_sidecar_sha256=previous)
    return share, archive, report


def share_bytes(package_id, reference, budget):
    sha(package_id)
    need(type(reference) is str and 1 <= len(reference) <= 256
         and all(33 <= ord(c) <= 126 for c in reference), 'invalid package reference')
    raw = ('SENTINEL1:' + package_id + '\nPKG:' + reference + '\n').encode('ascii')
    if budget is not None:
        integer(budget, 1, 1024)
        need(len(raw) <= budget, 'complete share does not fit character budget')
    return raw


def checked_share(raw):
    need(type(raw) is bytes and len(raw) <= 512, 'share byte bound')
    try:
        lines = raw.decode('ascii').split('\n')
    except UnicodeError as error:
        raise DocumentError('non-ASCII evidence share') from error
    need(len(lines) == 3 and lines[2] == '' and lines[0].startswith('SENTINEL1:')
         and lines[1].startswith('PKG:'), 'invalid evidence share')
    package_id, reference = lines[0][10:], lines[1][4:]
    need(share_bytes(package_id, reference, None) == raw, 'noncanonical evidence share')
    return package_id


def checked_entries(raw):
    need(type(raw) is bytes and 0 < len(raw) <= ARCHIVE_CAP, 'ZIP archive bound')
    entries, used = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw), 'r', allowZip64=False) as archive:
        infos = archive.infolist()
        need(1 <= len(infos) <= 260 and archive.comment == b'', 'ZIP count or comment')
        need(len({info.filename for info in infos}) == len(infos), 'duplicate ZIP entry')
        for info in infos:
            name = info.filename
            need(type(name) is str and name not in entries, 'duplicate ZIP entry')
            fixed = name in ('manifest.json', 'sidecar.json', 'registry.json', 'README.txt')
            artifact = name.startswith('artifacts/') and name.endswith('.bin')
            need(fixed or artifact, 'unsupported ZIP path')
            if artifact:
                identifier(name[10:-4])
            need(info.flag_bits == 0 and info.compress_type == zipfile.ZIP_STORED
                 and info.extra == b'' and info.comment == b''
                 and info.create_system == 3 and info.date_time == (1980, 1, 1, 0, 0, 0)
                 and info.external_attr == (stat.S_IFREG | 0o600) << 16,
                 'unsafe or noncanonical ZIP entry')
            integer(info.file_size, 0, CAP)
            need(info.compress_size == info.file_size, 'ZIP expansion refused')
            used += info.file_size
            need(used <= REGISTRY_BYTES + 4 * CAP, 'ZIP aggregate bound')
            entries[name] = read_member(archive, info)
            need(len(entries[name]) == info.file_size, 'ZIP member truncated')
    need(zip_bytes(entries) == raw, 'noncanonical ZIP bytes')
    return entries


def read_member(archive, info):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            return archive.read(info)
    except Warning as error:
        raise DocumentError('ZIP member warning refused') from error


def checked_manifest(entries, package_id):
    need('manifest.json' in entries, 'manifest missing')
    manifest_raw = entries['manifest.json']
    need(digest(manifest_raw) == package_id, 'share and archive mismatch')
    manifest = canonical_input(manifest_raw)
    fields(manifest, MANIFEST_FIELDS)
    need(manifest['schema'] == PROFILE, 'unsupported evidence version')
    for key, value in (('authentication', 'UNAUTHENTICATED'),
            ('semantic_completeness', 'UNPROVEN'), ('qualification', 'NOT_QUALIFIED'),
            ('execution_authority', 'NONE')):
        need(manifest[key] == value, 'invalid container claim')
    rows = manifest['files']
    need(type(rows) is list and 1 <= len(rows) <= 259, 'file inventory bound')
    for row in rows:
        fields(row, ('path', 'bytes', 'sha256'))
        need(type(row['path']) is str, 'inventory path type')
        integer(row['bytes'], 0, CAP)
        sha(row['sha256'])
    actual = [record(name, entries[name]) for name in sorted(entries) if name != 'manifest.json']
    need(rows == actual, 'entry set, size or digest mismatch')
    need(all(name in entries for name in ('sidecar.json', 'registry.json', 'README.txt')),
         'required entry missing')
    need(entries['README.txt'] == README, 'decoder instructions mismatch')
    sha(manifest['sidecar_sha256'])
    sha(manifest['registry_sha256'])
    return manifest


def decode_evidence(archive, share, previous=None):
    package_id = checked_share(share)
    entries = checked_entries(archive)
    manifest = checked_manifest(entries, package_id)
    need(manifest['previous_sidecar_sha256'] == previous, 'independently held prior root required')
    artifacts = {name[10:-4]: data for name, data in entries.items()
                 if name.startswith('artifacts/')}
    need(entries['registry.json'] == registry_manifest(artifacts), 'registry inventory mismatch')
    args, report = checked_arguments(entries['sidecar.json'], artifacts,
        manifest['sidecar_sha256'], manifest['registry_sha256'], previous)
    return args, dict(report, package_id=package_id, container_profile=PROFILE)


def read_artifacts(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    artifacts, total = {}, 0
    try:
        with os.scandir(fd) as stream:
            for index, entry in enumerate(stream):
                need(index < REGISTRY_CAP, 'artifact directory count')
                need(entry.name.endswith('.bin'), 'artifact suffix required')
                name = entry.name[:-4]
                identifier(name)
                data = read_artifact(fd, entry.name)
                total += len(data)
                need(total <= REGISTRY_BYTES and name not in artifacts, 'artifact aggregate or duplicate')
                artifacts[name] = data
    finally:
        os.close(fd)
    return artifacts


def read_artifact(directory_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= CAP,
             'artifact regular file or byte bound')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            before = identity(source)
            data = source.read(CAP + 1)
            need(before == identity(source) and len(data) == before[2], 'artifact changed')
            return data
    finally:
        os.close(fd)


def export_directory(out, share, archive, report):
    path = Path(out)
    path.mkdir(mode=0o700)
    write_new(path / 'share.txt', share)
    with (path / 'evidence.zip').open('xb') as stream:
        need(stream.write(archive) == len(archive), 'short evidence archive write')
        stream.flush()
        os.fsync(stream.fileno())
    _, checked = decode_evidence(read_file(path / 'evidence.zip', ARCHIVE_CAP),
        read_file(path / 'share.txt', 512), report.get('previous_sidecar_sha256'))
    need(checked['package_id'] == report['package_id'], 'final readback identity mismatch')
    write_new(path / 'report.json', canonical(report))
    return report


def parser():
    result = argparse.ArgumentParser(description='Source-Anchored Semantic Transport: SENTINEL evidence')
    commands = result.add_subparsers(dest='command', required=True)
    encode = commands.add_parser('encode')
    for flag in ('sidecar', 'artifacts', 'out'):
        encode.add_argument('--' + flag, type=Path, required=True)
    encode.add_argument('--sidecar-sha256', required=True)
    encode.add_argument('--registry-sha256', required=True)
    encode.add_argument('--reference', default='evidence.zip')
    encode.add_argument('--budget', type=int)
    for name in ('inspect', 'staging'):
        item = commands.add_parser(name)
        item.add_argument('--archive', type=Path, required=True)
        item.add_argument('--share', type=Path, required=True)
        if name == 'staging':
            item.add_argument('--out', type=Path, required=True)
    for item in (encode, *list(commands.choices.values())[1:]):
        item.add_argument('--previous-sha256')
    return result


def timeout_handler(_signum, _frame):
    raise DocumentError('evidence command wall-time bound exceeded')


def cli_limits():
    for key, requested in ((resource.RLIMIT_AS, 268_435_456), (resource.RLIMIT_FSIZE, ARCHIVE_CAP),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
        soft, hard = resource.getrlimit(key)
        bound = min([requested] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))
    previous = signal.getitimer(signal.ITIMER_REAL)[0]
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, min(30.0, previous) if previous else 30.0)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        cli_limits()
        if args.command == 'encode':
            output = encode_evidence(read_file(args.sidecar, CAP), read_artifacts(args.artifacts),
                args.sidecar_sha256, args.registry_sha256, args.reference, args.budget, args.previous_sha256)
            share, archive, report = output
            report['previous_sidecar_sha256'] = args.previous_sha256
            value = export_directory(args.out, share, archive, report)
        else:
            checked, value = decode_evidence(read_file(args.archive, ARCHIVE_CAP),
                read_file(args.share, 512), args.previous_sha256)
            if args.command == 'staging':
                write_new(args.out, export_policy_inputs(*checked))
        sys.stdout.buffer.write(canonical(value) + b'\n')
        return 0
    except (DocumentError, OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print('SENTINEL_REFUSED: ' + str(error)[:512], file=sys.stderr)
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
if __name__ == '__main__':
    sys.exit(main())
