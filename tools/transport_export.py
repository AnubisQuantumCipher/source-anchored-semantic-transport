"""Export exact source files and separately marked, unverified AI explanation data.

Uses the existing Source-Anchored Semantic Transport decoder. Hash integrity is
not authentication, factual certification, or proof of semantic completeness.
Raw source files and the exact UTF-8 explanation text are normative; no HTML is
generated. Input JSON serialization is hashed, not claimed recoverable bytewise.
"""

import argparse
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import transport_package as package
from transport_cli import rename_new
from transport_schema import canonical, fields, json_value, require, sha
from transport_wire import MAX_SOURCE, MAX_WIRE, read_bounded, write_new

BASE_RUNTIME_SHA256 = '4ca9cc4d226679663abd2f7375854ec5c10eb330ee2745110e9ad9173726da8a'
ENVELOPE_SCHEMA = 'transport/explanation-envelope/1'
EXPORT_SCHEMA = 'transport/export/1'
RUNTIME_SCHEMA = 'transport/export-runtime/1'
SOURCE_ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
PAIR_ID = re.compile(r'STS1:[0-9a-f]{64}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
TEXT_NAME = 'UNVERIFIED_AI_EXPLANATION.txt'
FLAT_FILES = {'metadata.json', TEXT_NAME, 'export.json'}
MAX_FILES = 19


@dataclass(frozen=True)
class Rendered:
    files: dict[str, bytes]
    package_identity: str
    envelope_sha256: str


def runtime_identity() -> dict:
    root = Path(package.__file__).resolve().parents[1]
    raw = read_bounded(root / 'RUNTIME.json', MAX_SOURCE)
    require(sha(raw) == BASE_RUNTIME_SHA256, 'Transport export requires the pinned base runtime manifest')
    manifest = json_value(raw, MAX_SOURCE)
    require(manifest == package.runtime_contract(), 'Transport export base runtime dependency mismatch')
    source = read_bounded(Path(__file__).resolve(), MAX_WIRE)
    return dict(schema=RUNTIME_SCHEMA, renderer=dict(path='tools/transport_export.py', bytes=len(source), sha256=sha(source)),
                base_manifest=dict(path='RUNTIME.json', bytes=len(raw), sha256=sha(raw)), base_decoder=manifest,
                boundary='External trusted renderer and decoder; hash-then-use does not isolate hostile concurrent same-user mutation.')


def source_bindings(decoded: dict) -> list:
    result, total = [], 0
    require(type(decoded['sources']) is list and 1 <= len(decoded['sources']) <= 16, 'Transport export source count failure')
    for item in decoded['sources']:
        name, data = item['id'], item['data']
        require(type(name) is str and SOURCE_ID.fullmatch(name), 'Transport export unsafe source identifier')
        require(type(data) is bytes and len(data) == item['bytes'] and sha(data) == item['sha256'],
                'Transport export decoded source identity mismatch')
        total += len(data)
        require(total <= MAX_SOURCE, 'Transport export aggregate source byte bound exceeded')
        result.append(dict(id=name, bytes=len(data), sha256=sha(data)))
    require(len({item['id'] for item in result}) == len(result), 'Transport export duplicate source identifier')
    return result


def explanation(data: bytes, identity: str, sources: list) -> tuple[dict, bytes]:
    require(type(data) is bytes and len(data) <= MAX_SOURCE, 'Transport explanation envelope byte bound exceeded')
    value = json_value(data, MAX_SOURCE)
    fields(value, {'schema', 'package_identity', 'sources', 'text'})
    require(value['schema'] == ENVELOPE_SCHEMA and type(value['package_identity']) is str
            and value['package_identity'] == identity, 'Transport explanation package binding mismatch')
    require(type(value['sources']) is list and len(value['sources']) == len(sources),
            'Transport explanation must bind every source in declared order')
    for item in value['sources']:
        fields(item, {'id', 'bytes', 'sha256'})
        require(type(item['id']) is str and type(item['bytes']) is int and type(item['sha256']) is str,
                'Transport explanation source binding types invalid')
    require(canonical(value['sources']) == canonical(sources), 'Transport explanation ordered source bindings mismatch')
    require(type(value['text']) is str, 'Transport explanation text must be a string')
    text = value['text'].encode('utf-8', errors='strict')
    require(len(text) <= MAX_SOURCE, 'Transport explanation text byte bound exceeded')
    return value, text


def file_record(path: str, data: bytes) -> dict:
    return dict(path=path, bytes=len(data), sha256=sha(data))


def check_files(files: dict) -> None:
    require(type(files) is dict and 4 <= len(files) <= MAX_FILES, 'Transport export file count failure')
    total = 0
    for name, data in files.items():
        require(type(name) is str and (name in FLAT_FILES or
                re.fullmatch(r'sources/[A-Z][A-Z0-9_]{0,31}\.bin', name)), 'Transport export unsafe artifact path')
        require(type(data) is bytes and len(data) <= MAX_WIRE, 'Transport export artifact byte bound exceeded')
        total += len(data)
        require(total <= MAX_WIRE, 'Transport export exceeds aggregate 131072-byte representability bound; no files dropped')
    require(FLAT_FILES <= set(files), 'Transport export fixed artifacts missing')


def export_manifest(decoded: dict, bindings: list, envelope: bytes, text: bytes,
                    files: dict, runtime: dict, share: bytes, archive: bytes) -> dict:
    sources = [dict(item, path='sources/' + item['id'] + '.bin') for item in bindings]
    meaning = dict(schema=ENVELOPE_SCHEMA, package_identity=decoded['identity'], sources=bindings,
        text_artifact=file_record(TEXT_NAME, text), input_envelope_bytes=len(envelope), input_envelope_sha256=sha(envelope),
        role='UNVERIFIED_AI_EXPLANATION', execution_authority='NONE', factual_certification='NOT_PERFORMED',
        logical_envelope_reconstruction='Use schema, package_identity, ordered sources, and strict UTF-8 text artifact; raw input JSON serialization is not reconstructed.')
    return dict(schema=EXPORT_SCHEMA, package_identity=decoded['identity'], sources=sources, explanation=meaning,
        inputs=dict(share=dict(bytes=len(share), sha256=sha(share)), archive=dict(bytes=len(archive), sha256=sha(archive))),
        metadata_artifact='metadata.json', runtime=runtime,
        files=[file_record(name, files[name]) for name in sorted(files)],
        assurance=dict(source_bytes='EXACT_NATIVE_DECODED_AND_HASH_CHECKED', declarations='UNVERIFIED',
            author_authentication='NOT_AUTHENTICATED', factual_truth='NOT_CERTIFIED',
            semantic_completeness='NOT_CLAIMED', explanation_entailment='UNPROVEN', execution_authority='NONE'))


def render(share: bytes, archive: bytes, envelope_data: bytes) -> Rendered:
    require(type(share) is bytes and len(share) <= MAX_WIRE and type(archive) is bytes
            and len(archive) <= MAX_WIRE, 'Transport export pair input byte bound exceeded')
    require(type(envelope_data) is bytes and len(envelope_data) <= MAX_SOURCE,
            'Transport explanation envelope byte bound exceeded')
    runtime = runtime_identity()
    decoded = package.decode(share, archive)
    bindings = source_bindings(decoded)
    _, text = explanation(envelope_data, decoded['identity'], bindings)
    files = {'sources/' + item['id'] + '.bin': item['data'] for item in decoded['sources']}
    files['metadata.json'] = canonical(package.metadata_view(decoded))
    files[TEXT_NAME] = text
    files['export.json'] = canonical(export_manifest(decoded, bindings, envelope_data, text, files, runtime, share, archive))
    check_files(files)
    return Rendered(files, decoded['identity'], sha(envelope_data))


def verify_export(share: bytes, archive: bytes, envelope_data: bytes, files: dict,
                  expected_identity: str, expected_envelope_sha256: str) -> dict:
    require(type(expected_identity) is str and PAIR_ID.fullmatch(expected_identity), 'Transport export expected pair identity required')
    require(type(expected_envelope_sha256) is str and DIGEST.fullmatch(expected_envelope_sha256),
            'Transport export expected envelope digest required')
    require(type(envelope_data) is bytes and len(envelope_data) <= MAX_SOURCE
            and sha(envelope_data) == expected_envelope_sha256, 'Transport export external envelope pin mismatch')
    expected = render(share, archive, envelope_data)
    require(expected.package_identity == expected_identity, 'Transport export external pair pin mismatch')
    check_files(files)
    require(set(files) == set(expected.files), 'Transport export artifact membership mismatch')
    for name in expected.files:
        require(files[name] == expected.files[name], 'Transport export regenerated artifact mismatch: ' + name)
    return dict(status='VERIFIED_AGAINST_PINNED_INPUTS', package_identity=expected.package_identity,
        envelope_sha256=expected.envelope_sha256, files=len(files), aggregate_bytes=sum(map(len, files.values())),
        export_sha256=sha(files['export.json']), explanation_role='UNVERIFIED_AI_EXPLANATION',
        authentication='NOT_PROVIDED', factual_certification='NOT_PERFORMED', semantic_completeness='NOT_CLAIMED')


def read_export(directory: Path) -> dict:
    require(directory.is_dir() and not directory.is_symlink(), 'Transport export regular directory required')
    files, observed = {}, set()
    for number, path in enumerate(directory.iterdir()):
        require(number < 4 and not path.is_symlink(), 'Transport export root entry bound or symlink failure')
        require((path.name == 'sources' and path.is_dir()) or (path.name in FLAT_FILES and path.is_file()),
                'Transport export unexpected root entry')
        observed.add(path.name)
        if path.name != 'sources':
            files[path.name] = read_bounded(path, MAX_WIRE)
    require(observed == FLAT_FILES | {'sources'}, 'Transport export missing root artifact')
    for number, path in enumerate((directory / 'sources').iterdir()):
        require(number < 16 and path.is_file() and not path.is_symlink()
                and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}\.bin', path.name), 'Transport export unsafe source entry')
        files['sources/' + path.name] = read_bounded(path, MAX_WIRE)
    check_files(files)
    return files


def cleanup_stage(stage: Path, identity: os.stat_result, names: list,
                  source_identity: os.stat_result | None) -> None:
    current = stage.lstat()
    require((current.st_dev, current.st_ino, current.st_uid) == (identity.st_dev, identity.st_ino, identity.st_uid),
            'Transport export stage identity changed; cleanup refused')
    require(len(names) <= MAX_FILES, 'Transport export cleanup file count failure')
    require(all(type(name) is str and (name in FLAT_FILES or
                re.fullmatch(r'sources/[A-Z][A-Z0-9_]{0,31}\.bin', name)) for name in names),
            'Transport export cleanup unsafe artifact path')
    sources = stage / 'sources'
    if source_identity is None:
        require(not sources.exists() and not sources.is_symlink(), 'Transport export unexpected sources directory; cleanup refused')
    else:
        current = sources.lstat()
        require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid()
                and (current.st_dev, current.st_ino, current.st_uid) ==
                (source_identity.st_dev, source_identity.st_ino, source_identity.st_uid),
                'Transport export source directory identity changed; cleanup refused')
    for name in names:
        if source_identity is not None or name in FLAT_FILES:
            (stage / name).unlink(missing_ok=True)
    if source_identity is not None:
        sources.rmdir()
    stage.rmdir()


def publish(directory: Path, files: dict) -> None:
    check_files(files)
    require(not directory.exists() and not directory.is_symlink(), 'Transport export destination already exists')
    stage = Path(tempfile.mkdtemp(prefix='.transport-export-', dir=directory.parent))
    identity = stage.lstat()
    require(stat.S_ISDIR(identity.st_mode) and identity.st_uid == os.geteuid()
            and stat.S_IMODE(identity.st_mode) == 0o700, 'Transport export stage ownership mismatch')
    published, source_identity = False, None
    try:
        (stage / 'sources').mkdir(mode=0o700)
        source_identity = (stage / 'sources').lstat()
        require(stat.S_ISDIR(source_identity.st_mode) and source_identity.st_uid == os.geteuid()
                and stat.S_IMODE(source_identity.st_mode) == 0o700, 'Transport export source stage ownership mismatch')
        for name in sorted(files):
            warning = write_new(stage / name, files[name])
            require(not warning, 'Transport export write cleanup warning: ' + warning)
            require(read_bounded(stage / name, MAX_WIRE) == files[name], 'Transport export write readback mismatch')
        require(read_export(stage) == files, 'Transport export complete stage readback mismatch')
        rename_new(stage, directory)
        published = True
    finally:
        if not published:
            cleanup_stage(stage, identity, sorted(files), source_identity)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('render', 'verify'):
        command = commands.add_parser(action)
        command.add_argument('share', type=Path)
        command.add_argument('output', type=Path)
        command.add_argument('--archive', type=Path, required=True)
        command.add_argument('--explanation', type=Path, required=True,
                             help='Closed package-bound explanation envelope JSON; UTF-8 text remains unverified data')
        if action == 'verify':
            command.add_argument('--expect-pair', required=True)
            command.add_argument('--expect-envelope-sha256', required=True)
    return parser.parse_args()


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_WIRE, MAX_WIRE))
    args = arguments()
    try:
        share = read_bounded(args.share, MAX_WIRE)
        archive = read_bounded(args.archive, MAX_WIRE)
        envelope = read_bounded(args.explanation, MAX_SOURCE)
        if args.action == 'verify':
            result = verify_export(share, archive, envelope, read_export(args.output), args.expect_pair, args.expect_envelope_sha256)
        else:
            rendered = render(share, archive, envelope)
            publish(args.output, rendered.files)
            result = dict(status='EXACT_SOURCES_AND_UNVERIFIED_EXPLANATION_EXPORTED', package_identity=rendered.package_identity,
                envelope_sha256=rendered.envelope_sha256, files=len(rendered.files), aggregate_bytes=sum(map(len, rendered.files.values())),
                export_sha256=sha(rendered.files['export.json']), explanation_role='UNVERIFIED_AI_EXPLANATION',
                factual_certification='NOT_PERFORMED', execution_authority='NONE')
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 0
    except (ValueError, OSError, MemoryError, UnicodeError, subprocess.TimeoutExpired) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
