"""Prepare a pinned versioned source overlay; qualification remains in fixed builders.

The supplied repository, existing toolchain and kernel are trusted. Preparation is
not a proof receipt or authority decision. No installed decoder is replaced.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import resource
from pathlib import Path, PurePosixPath
import stat
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_v1.common import (SentinelError, depth_checked, fields, hash_checked,
                                no_number, require, unique_pairs)

SOURCE_CAP = 131_072
MANIFEST_CAP = 1_048_576
ARCHIVE_CAP = 524_288
JSON_CAP = 8_388_608
ORACLE_FILE_CAP = 1_048_577
SECTION_CAP = 8_388_608
PREPARE_CAP = 8_388_608
VERSION = 'qualification/v2/'
OVERRIDES = {name: VERSION + name.split('/')[-1] for name in
             ('sentinel_native/sentinel_policy.ads', 'sentinel_native/sentinel_policy.adb',
              'sentinel_native/sentinel_policy_fixtures.adb')}
CONTROLLERS = ('wire_checks.py', 'wire_controller.py', 'wire_worker.py')
PREPARERS = ('tools/sentinel_v1/__init__.py', 'tools/sentinel_v1/common.py',
             'tools/sentinel_v1/native_build.py')
EVIDENCE = ('pure-receipt.json', 'pure-result.json', 'pure-proof.txt', 'pure-proof.spark',
            'pure-checks.stdout', 'pure-checks.stderr', 'pure-review.json',
            'wire-receipt.json', 'wire-result.json', 'wire-progress.jsonl', 'wire-review.json')
SOURCES = ('document_native/check_ledger.py',
 'document_native/check_native.py',
 'document_native/document_binary_io.adb',
 'document_native/document_binary_io.ads',
 'document_native/document_buffer_proof.gpr',
 'document_native/document_checks.gpr',
 'document_native/document_frame_ledger.adb',
 'document_native/document_frame_ledger.ads',
 'document_native/document_framed_decode.adb',
 'document_native/document_framed_decode.ads',
 'document_native/document_ledger_checks.adb',
 'document_native/document_ledger_proof.gpr',
 'document_native/document_native.gpr',
 'document_native/document_native_decode.adb',
 'document_native/document_transport_buffers.adb',
 'document_native/qualify_native.py',
 'sentinel_native/sentinel_build_profile.py',
 'sentinel_native/sentinel_policy.adb',
 'sentinel_native/sentinel_policy.ads',
 'sentinel_native/sentinel_policy.gpr',
 'sentinel_native/sentinel_policy_checks.adb',
 'sentinel_native/sentinel_policy_fixtures.adb',
 'sentinel_native/sentinel_policy_fixtures.ads',
 'sentinel_native/sentinel_policy_proof.gpr',
 'sentinel_native/sentinel_qualification.py',
 'sentinel_native/sentinel_wire.gpr',
 'sentinel_native/sentinel_wire_io.adb',
 'sentinel_native/sentinel_wire_io.ads',
 'sentinel_native/sentinel_wire_main.adb',
 'src/transport_buffers.adb',
 'src/transport_buffers.ads',
 'src/transport_decoder.adb',
 'src/transport_decoder.ads',
 'src/transport_graph_parse.adb',
 'src/transport_graph_parse.ads',
 'src/transport_graphs.adb',
 'src/transport_graphs.ads',
 'src/transport_io.adb',
 'src/transport_io.ads',
 'src/transport_native.adb',
 'src/transport_paths.adb',
 'src/transport_paths.ads',
 'src/transport_temporal.adb',
 'src/transport_temporal.ads',
 'src/transport_temporal_format.adb',
 'src/transport_temporal_format.ads',
 'src/transport_temporal_parse.adb',
 'src/transport_temporal_parse.ads',
 'src/transport_types.ads',
 'tools/build_document_decoder.py',
 'tools/build_sentinel_policy.py',
 'tools/document_build/__init__.py',
 'tools/document_build/capture.py',
 'tools/document_build/common.py',
 'tools/document_build/identity.py',
 'tools/document_build/launcher.py',
 'tools/document_build/namespace.py',
 'tools/document_build/process.py',
 'tools/document_build/proof.py',
 'tools/document_build/worker.py',
 'tools/transport_document_io.py')
ORACLES = ('bad-magic.stn',
 'bad-version.stn',
 'bind-identity-mismatch.stn',
 'candidate-mismatch.stn',
 'claim-L-length-inconsistent.stn',
 'claim-L-outside-range.stn',
 'claim-complete-L-zero-length45.stn',
 'claim-complete-L17-length4.stn',
 'claim-doc-range-before-ordinal.stn',
 'claim-impossible-header-length.stn',
 'claim-truncated-before-L-check.stn',
 'claim-valid-fields-wrong-ordinal.stn',
 'conflict-both-match.stn',
 'conflict-both-match.str',
 'duplicate-answer.stn',
 'duplicate-claim-ordinal.stn',
 'duplicate-q-row.stn',
 'file-cap-plus-one.stn',
 'init-wrong-length.stn',
 'invalid-blocker-enum.stn',
 'invalid-context-boolean.stn',
 'invalid-documentary-enum.stn',
 'literal-oracle.json',
 'maximum-complete-transcript.stn',
 'maximum-complete-transcript.str',
 'missing-answer.stn',
 'missing-answer.str',
 'missing-finish.stn',
 'missing-q-row.stn',
 'missing-repair-parent.stn',
 'nonzero-reserved.stn',
 'open-challenge.stn',
 'oversized-declared-payload.stn',
 'q-subject-range-before-ordinal.stn',
 'q-valid-fields-wrong-ordinal.stn',
 'repair-retains-failure.stn',
 'repair-retains-failure.str',
 'repeated-init.stn',
 'required-adjudication-missing.stn',
 'required-context-missing.stn',
 'trailing-byte-after-qualified.stn',
 'truncated-frame-header.stn',
 'truncated-init-payload.stn',
 'truncated-prefix.stn',
 'unknown-neither-match.stn',
 'unknown-neither-match.str',
 'unknown-opcode.stn',
 'unknown-to-false.stn',
 'unknown-to-false.str',
 'wire-epoch-02.json',
 'wire-epoch-03.json',
 'wire-epoch-04.json',
 'wire-epoch-05.json',
 'zero-actual-answer-native.stn',
 'zero-answer-receipt-native.stn',
 'zero-expected-answer-native.stn',
 'zero-init-candidate-native.stn',
 'zero-link-anchor-native.stn',
 'zero-oracle-pin-native.stn',
 'zero-probe-input-native.stn',
 'zero-refine-candidate-native.stn',
 'zero-refine-repair-native.stn')


def root_checked(path):
    path = Path(path).absolute()
    require(len(path.parts) <= 64, 'repository/output path depth')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        mode = current.lstat().st_mode
        require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), 'directory alias refused')
    return path


def safe_path(root, name):
    require(type(name) is str and 0 < len(name) <= 160, 'fixed input path bound')
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and relative.as_posix() == name
            and 1 <= len(relative.parts) <= 4
            and all(part not in ('.', '..') for part in relative.parts), 'unsafe input path')
    current = root
    for part in relative.parts[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), 'non-directory input parent')
    return root / name


def read_regular(root, name, cap):
    path = safe_path(root, name)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap,
                'regular input or byte bound')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(descriptor)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key)
                for key in keys), 'input changed while reading')
        return raw
    finally:
        os.close(descriptor)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def json_bytes(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode('ascii')
    require(len(raw) <= MANIFEST_CAP, 'manifest/receipt byte bound')
    return raw


def load_json(raw, cap):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON byte bound')
    depth_checked(raw)
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_float=no_number, parse_constant=no_number)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SentinelError('invalid closed JSON') from error


def decode_archive(raw, names, schema, file_cap):
    require(type(raw) is bytes and 0 < len(raw) <= ARCHIVE_CAP, 'compressed data bound')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
            expanded = stream.read(JSON_CAP + 1)
        value = load_json(expanded, JSON_CAP)
        fields(value, ('schema', 'items'))
        require(value['schema'] == schema, 'compressed data schema')
        items = value['items']
        require(type(items) is dict and set(items) == set(names), 'fixed compressed data roster')
        result, total = {}, 0
        for name in names:
            require(type(items[name]) is str and len(items[name]) <= 4 * ((file_cap + 2) // 3),
                    'encoded item byte bound')
            item = base64.b64decode(items[name], validate=True)
            total += len(item)
            require(len(item) <= file_cap and total <= SECTION_CAP, 'raw item byte bound')
            result[name] = item
        return result
    except (OSError, EOFError, ValueError, UnicodeError) as error:
        raise SentinelError('closed compressed data refused') from error


def decode_oracles(raw):
    return decode_archive(raw, ORACLES, 'sentinel/literal-fixtures/1', ORACLE_FILE_CAP)


def decode_evidence(raw):
    return decode_archive(raw, EVIDENCE, 'sentinel/native-evidence/2', 2_097_152)


def read_section(root, names, prefix, cap):
    result, total = {}, 0
    for name in names:
        raw = read_regular(root, prefix + name, cap)
        total += len(raw)
        require(total <= SECTION_CAP, 'fixed section aggregate byte bound')
        result[name] = raw
    return result


def inputs(root):
    source, total = {}, 0
    for name in SOURCES:
        raw = read_regular(root, OVERRIDES.get(name, name), SOURCE_CAP)
        total += len(raw)
        require(total <= SECTION_CAP, 'source aggregate byte bound')
        source[name] = raw
    archive = read_regular(root, VERSION + 'literal-fixtures.json.gz', ARCHIVE_CAP)
    evidence = read_regular(root, VERSION + 'evidence.json.gz', ARCHIVE_CAP)
    require(len(archive) + len(evidence) <= ARCHIVE_CAP, 'persistent compressed data budget')
    return {'sources': source,
            'preparation_sources': read_section(root, PREPARERS, '', SOURCE_CAP),
            'controllers': read_section(root, CONTROLLERS, VERSION + 'controller/', SOURCE_CAP),
            'oracles': decode_oracles(archive), 'archive': archive, 'evidence_archive': evidence,
            'proof_roster': read_regular(root, VERSION + 'proof-roster.json', MANIFEST_CAP),
            'evidence': decode_evidence(evidence)}


def manifest_of(data):
    return {'schema': 'sentinel/versioned-native-inputs/2',
            'scope': 'PINNED_SOURCE_AND_SYNTHETIC_QUALIFICATION_ONLY',
            **{name: {path: pin(raw) for path, raw in data[name].items()}
               for name in ('sources', 'preparation_sources', 'controllers', 'oracles', 'evidence')},
            'archive': pin(data['archive']), 'evidence_archive': pin(data['evidence_archive']),
            'proof_roster': pin(data['proof_roster'])}


def derive_manifest(root):
    """Derive bytes/pins only; writing or approving a new epoch is a separate action."""
    return manifest_of(inputs(root_checked(root)))


def checked_pin_record(value):
    require(type(value) is dict and len(value) == 2, 'closed bounded pin record')
    fields(value, ('bytes', 'sha256'))
    require(type(value['bytes']) is int and 0 <= value['bytes'] <= SECTION_CAP,
            'pin byte count requires bounded integer')
    hash_checked(value['sha256'])


def checked_pin_records(manifest):
    for section in ('sources', 'preparation_sources', 'controllers', 'oracles', 'evidence'):
        require(type(manifest[section]) is dict and len(manifest[section]) <= 64,
                'pin section type or record bound')
        for value in manifest[section].values():
            checked_pin_record(value)
    for name in ('archive', 'evidence_archive', 'proof_roster'):
        checked_pin_record(manifest[name])


def checked_inputs(root, expected_manifest_sha):
    root = root_checked(root)
    hash_checked(expected_manifest_sha)
    raw = read_regular(root, VERSION + 'manifest.json', MANIFEST_CAP)
    require(pin(raw)['sha256'] == expected_manifest_sha, 'caller-held manifest SHA mismatch')
    manifest = load_json(raw, MANIFEST_CAP)
    fields(manifest, ('schema', 'scope', 'sources', 'preparation_sources', 'controllers', 'oracles', 'evidence',
                      'archive', 'evidence_archive', 'proof_roster'))
    checked_pin_records(manifest)
    data = inputs(root)
    require(json_bytes(manifest) == json_bytes(manifest_of(data)) == raw,
            'fixed current inputs differ from retained manifest')
    roster = load_json(data['proof_roster'], MANIFEST_CAP)
    fields(roster, ('schema', 'status', 'unit', 'sources', 'entities'))
    names = ('sentinel_policy.ads', 'sentinel_policy.adb',
             'sentinel_policy.gpr', 'sentinel_policy_proof.gpr')
    require(roster['schema'] == 'sentinel/proof-roster/1'
            and roster['status'] == 'SOURCE_DERIVED_FROZEN_BEFORE_PROVER'
            and roster['unit'] == 'sentinel_policy'
            and roster['sources'] == {'sentinel_native/' + name:
                manifest['sources']['sentinel_native/' + name]['sha256'] for name in names},
            'proof roster source binding')
    return manifest, data


def check_package(root, expected_manifest_sha):
    manifest, _data = checked_inputs(root, expected_manifest_sha)
    return {'status': 'PINNED_PACKAGE_CHECKED_UNQUALIFIED',
            'manifest_sha256': expected_manifest_sha, 'source_files': len(manifest['sources']),
            'literal_files': len(manifest['oracles']), 'execution_authority': 'NONE'}


def output_checked(path):
    path = Path(path).absolute()
    require(path.is_relative_to(Path('/dev/shm')) and path != Path('/dev/shm')
            and '..' not in path.parts, 'private tmpfs output required')
    parent = root_checked(path.parent)
    info = parent.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
            'output parent must be owned and private')
    require(not path.exists() and not path.is_symlink(), 'create-only output required')
    return path


def payloads(data):
    result = {}
    for section, prefix in (('sources', 'source/'), ('controllers', 'controller/'),
                            ('oracles', 'oracles/')):
        result.update({prefix + name: raw for name, raw in data[section].items()})
    native = {name.split('/')[-1]: pin(data['sources'][name])['sha256']
              for name in SOURCES if name.startswith('sentinel_native/')
              and name.split('/')[-1] in ('sentinel_policy.ads', 'sentinel_policy.adb',
              'sentinel_policy.gpr', 'sentinel_policy_proof.gpr', 'sentinel_policy_checks.adb',
              'sentinel_policy_fixtures.ads', 'sentinel_policy_fixtures.adb',
              'sentinel_wire_io.ads', 'sentinel_wire_io.adb', 'sentinel_wire_main.adb',
              'sentinel_wire.gpr')}
    result['proof-roster.json'] = data['proof_roster']
    result['held-wire.json'] = json_bytes({'schema': 'sentinel/wire-qualification-inputs/1',
        'native': native, 'controller': {name: pin(raw)['sha256']
        for name, raw in data['controllers'].items()}, 'oracle': {name: pin(raw)['sha256']
        for name, raw in data['oracles'].items()}})
    require(len(native) == 11 and len(result) <= 160
            and sum(len(raw) for raw in result.values()) <= PREPARE_CAP,
            'prepared payload count or byte bound')
    return result


def write_payloads(out, items):
    out.mkdir(mode=0o700)
    directories = {out}
    for name, raw in items.items():
        parts = PurePosixPath(name).parts
        require(1 <= len(parts) <= 4, 'prepared relative path depth')
        parent = out
        for part in parts[:-1]:
            parent /= part
            if parent not in directories:
                parent.mkdir(mode=0o700)
                directories.add(parent)
        descriptor = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, 'wb') as stream:
            require(stream.write(raw) == len(raw), 'overlay short write')
        require(read_regular(out, name, max(len(raw), 1)) == raw, 'overlay readback mismatch')
    require(len(directories) <= 640, 'prepared directory bound')
    for directory in sorted(directories - {out}, key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o500)


def prepare_overlay(root, out, expected_manifest_sha):
    out = output_checked(out)
    manifest, data = checked_inputs(root, expected_manifest_sha)
    items = payloads(data)
    report = {'schema': 'sentinel/prepared-native-overlay/2',
              'status': 'SOURCE_PREPARED_UNQUALIFIED', 'manifest_sha256': expected_manifest_sha,
              'out': str(out), 'files': {name: pin(raw) for name, raw in items.items()},
              'execution_authority': 'NONE'}
    items['preparation.json'] = json_bytes(report)
    require(sum(len(raw) for raw in items.values()) <= PREPARE_CAP and len(items) <= 160,
            'aggregate preparation including receipt bound')
    try:
        write_payloads(out, items)
    except (OSError, ValueError) as error:
        raise SentinelError('overlay incomplete; partial bytes retained at ' + str(out)) from error
    return report


def qualification_command(prepared, mode, toolchain_root, source_root, expected_manifest_sha):
    require(type(prepared) is dict and len(prepared) == 6, 'closed bounded preparation report')
    fields(prepared, ('schema', 'status', 'manifest_sha256', 'out', 'files',
                      'execution_authority'))
    require(prepared['schema'] == 'sentinel/prepared-native-overlay/2'
            and prepared['status'] == 'SOURCE_PREPARED_UNQUALIFIED'
            and prepared['execution_authority'] == 'NONE', 'prepared source report required')
    require(type(prepared['out']) is str and 0 < len(prepared['out']) <= 4096,
            'prepared output path bound')
    expected = {'source/' + name for name in SOURCES} | {'controller/' + name for name
                in CONTROLLERS} | {'oracles/' + name for name in ORACLES}
    expected |= {'proof-roster.json', 'held-wire.json'}
    require(type(prepared['files']) is dict and len(prepared['files']) == len(expected),
            'prepared fixed file count/type')
    require(set(prepared['files']) == expected, 'prepared fixed file roster')
    for value in prepared['files'].values():
        checked_pin_record(value)
    _manifest, data = checked_inputs(source_root, expected_manifest_sha)
    require(prepared['manifest_sha256'] == expected_manifest_sha,
            'prepared report differs from caller-held manifest SHA')
    expected_pins = {name: pin(raw) for name, raw in payloads(data).items()}
    require(json_bytes(prepared['files']) == json_bytes(expected_pins),
            'prepared payload pins differ from caller-held package')
    require(mode in ('policy', 'wire'), 'fixed qualification mode required')
    out = root_checked(prepared['out'])
    require(json_bytes(load_json(read_regular(out, 'preparation.json', MANIFEST_CAP), MANIFEST_CAP))
            == json_bytes(prepared), 'prepared report changed')
    for name, expected_pin in prepared['files'].items():
        checked_pin_record(expected_pin)
        require(pin(read_regular(out, name, ORACLE_FILE_CAP)) == expected_pin,
                'prepared payload changed before qualification')
    toolchain = root_checked(toolchain_root)
    source = out / 'source'
    command = ['/usr/bin/python3', '-I', '-S', '-B', '-Werror']
    if mode == 'policy':
        return command + [str(source / 'tools/build_sentinel_policy.py'),
            '--source-root', str(source), '--toolchain-root', str(toolchain),
            '--roster', str(out / 'proof-roster.json'), '--roster-sha256',
            prepared['files']['proof-roster.json']['sha256'], '--out', str(out / 'policy-result')]
    return command + [str(out / 'controller/wire_controller.py'), '--source-root', str(source),
        '--oracle-root', str(out / 'oracles'), '--toolchain-root', str(toolchain),
        '--pins', str(out / 'held-wire.json'), '--pins-sha256',
        prepared['files']['held-wire.json']['sha256'], '--out', str(out / 'wire-result')]


def cli_limits():
    for kind, bound in ((resource.RLIMIT_AS, 1_073_741_824),
                        (resource.RLIMIT_FSIZE, 8_388_608),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64)):
        soft, hard = resource.getrlimit(kind)
        resource.setrlimit(kind, (bound if soft == resource.RLIM_INFINITY else min(soft, bound),
                                 bound if hard == resource.RLIM_INFINITY else min(hard, bound)))


def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
        parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
        parser.add_argument('--manifest-sha256', required=True)
        parser.add_argument('--out', type=Path)
        parser.add_argument('--toolchain-root', type=Path)
        parser.add_argument('--mode', choices=('check', 'prepare', 'policy', 'wire'), default='prepare')
        args = parser.parse_args()
        cli_limits()
        if args.mode == 'check':
            require(args.out is None and args.toolchain_root is None, 'check has no output/toolchain')
            result = check_package(args.source_root, args.manifest_sha256)
        else:
            require(args.out is not None, 'new private output required')
            require(args.mode == 'prepare' or args.toolchain_root is not None,
                    'existing toolchain root required for qualification')
            result = prepare_overlay(args.source_root, args.out, args.manifest_sha256)
            if args.mode != 'prepare':
                command = qualification_command(result, args.mode, args.toolchain_root,
                                                args.source_root, args.manifest_sha256)
                os.execv(command[0], command)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (MemoryError, OSError, ValueError, KeyError, TypeError) as error:
        print('SENTINEL_NATIVE_BUILD_REFUSED:' + str(error)[:4096], file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
