"""SNE1 data CLI. Existing SAST owns ZIP parsing and native source recovery."""
import argparse
import json
from pathlib import Path
import resource
import signal
import sys
import hashlib
import importlib
import os
import stat

SEMANTIC_FILES = ('sentinel_v1/__init__.py', 'sentinel_v1/common.py', 'sentinel_v1/bindings.py', 'sentinel_v1/graph.py', 'sentinel_v1/census.py', 'sentinel_v1/challenges.py', 'sentinel_v1/refinement.py', 'sentinel_v1/assessments.py', 'sentinel_v1/locators.py', 'sentinel_v1/bundle.py', 'sentinel_v1/cli.py', 'transport_document.py', 'transport_document_io.py', 'transport_document_archive.py', 'transport_document_reading.py', 'transport_document_context.py', 'transport_semantics.py', 'transport_meaning.py', 'transport_schema.py', 'transport_operators.py', 'transport_structure.py', 'transport_references.py', 'transport_wire.py')


def fixed_snapshot():
    root, result, total = Path(__file__).resolve().parents[1], {}, 0
    for relative in SEMANTIC_FILES:
        fd = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= 1048576:
                raise ValueError('semantic decoder source file bound/type')
            blocks, count = [], 0
            for _ in range(17):
                block = os.read(fd, 65536)
                if not block:
                    break
                count += len(block); total += len(block)
                if count > 1048576 or total > 16777216:
                    raise ValueError('semantic decoder aggregate source bound')
                blocks.append(block)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(before, key) != getattr(after, key) for key in fields) or count != before.st_size:
                raise ValueError('semantic decoder source changed during pin')
            result[relative] = {'sha256': hashlib.sha256(b''.join(blocks)).hexdigest(), 'bytes': count}
        finally:
            os.close(fd)
    return result


def fresh_bootstrap(argv):
    if len(argv) > 128 or any(type(v) is not str or len(v.encode('utf-8')) > 4096 for v in argv):
        raise ValueError('bootstrap argument bound')
    positions = [i for i, value in enumerate(argv) if value == '--semantic-root']
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise ValueError('fresh CLI requires one independently held --semantic-root')
    held = argv[positions[0] + 1]
    before = fixed_snapshot()
    raw = json.dumps(before, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    if hashlib.sha256(raw).hexdigest() != held:
        raise ValueError('independently held semantic source root mismatch')
    names = [name[:-3].replace('/', '.') for name in SEMANTIC_FILES
             if name not in ('sentinel_v1/__init__.py', 'sentinel_v1/cli.py')]
    if any(name in sys.modules for name in names):
        raise ValueError('operative semantic dependency was imported before bootstrap')
    root = Path(__file__).resolve().parents[1]
    for name in names:
        module = importlib.import_module(name)
        if Path(module.__file__).resolve() != root / (name.replace('.', '/') + '.py'):
            raise ValueError('semantic module loaded outside fixed trusted installation')
    closed_imports(root)
    if fixed_snapshot() != before:
        raise ValueError('semantic sources changed during trusted import')
    return {'root_sha256': held, 'sources': before,
            'scope': 'FRESH_FIXED_TRUSTED_IMPORTS_ASSUMED_SINGLE_OWNER_NON_ABA_NOT_HOST_ATTESTATION'}


def limits():
    for kind, cap in ((resource.RLIMIT_AS, 1_073_741_824), (resource.RLIMIT_FSIZE, 67_108_864),
                      (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CPU, 450)):
        soft, hard = resource.getrlimit(kind)
        bound = cap if hard == resource.RLIM_INFINITY else min(hard, cap)
        bound = bound if soft == resource.RLIM_INFINITY else min(soft, bound)
        resource.setrlimit(kind, (bound, hard))
    def timeout(_signal, _frame):
        raise ValueError('receiving wall limit')
    signal.signal(signal.SIGALRM, timeout)
    prior, _interval = signal.getitimer(signal.ITIMER_REAL)
    signal.setitimer(signal.ITIMER_REAL, min(prior, 450) if prior > 0 else 450)



def closed_imports(root):
    if len(sys.modules) > 512:
        raise ValueError('bootstrap imported module count bound')
    allowed = set(SEMANTIC_FILES)
    for ordinal, module in enumerate(sys.modules.values()):
        if ordinal >= 512:
            raise ValueError('bootstrap imported module count bound')
        path = getattr(module, '__file__', None)
        if type(path) is not str:
            continue
        try:
            relative = Path(path).resolve().relative_to(root)
        except ValueError:
            continue
        if relative.as_posix() not in allowed:
            raise ValueError('undeclared local semantic dependency imported')


def memory_refusal():
    raw = b'{"execution_authority":"NONE","reason":"memory limit","status":"REFUSED"}\n'
    if sys.stdout.buffer.write(raw) != len(raw):
        raise OSError('short memory refusal write')


def bootstrap_or_refuse(argv):
    try:
        return fresh_bootstrap(argv)
    except MemoryError:
        memory_refusal()
        raise SystemExit(1)
    except (ValueError, OSError) as error:
        print(json.dumps({'status': 'REFUSED', 'reason': str(error)[:256], 'execution_authority': 'NONE'}))
        raise SystemExit(1)


SEMANTIC_BOOTSTRAP = None
if __name__ == '__main__':
    limits()
    SEMANTIC_BOOTSTRAP = bootstrap_or_refuse(sys.argv[1:])

from transport_document_io import read_file
from . import bundle
from .common import (METADATA, canonical, digest, fields, held_record, identity,
                     pin_checked, require, REGISTRY)
from .bindings import registry_root


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('CLI arguments: ' + message[:160])


def arguments(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--semantic-root')
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('pack', allow_abbrev=False)
    pack.add_argument('--input-dir', type=Path, required=True)
    pack.add_argument('--manifest', type=Path, required=True)
    pack.add_argument('--expect-manifest', required=True)
    pack.add_argument('--output', type=Path, required=True)
    inspect = commands.add_parser('inspect-payload', allow_abbrev=False)
    inspect.add_argument('--payload', type=Path, required=True)
    inspect.add_argument('--expect-payload', required=True)
    inspect.add_argument('--decoder-identity', required=True)
    inspect.add_argument('--export', type=Path)
    inspect.add_argument('--display-profile', choices=('COMPLETE', 'OVERVIEW'), default='COMPLETE')
    for name in ('decode', 'resolve'):
        command = commands.add_parser(name, allow_abbrev=False)
        for key in ('archive', 'share', 'native'):
            command.add_argument('--' + key, type=Path, required=True)
        command.add_argument('--decoder-identity', required=True)
        command.add_argument('--display-profile', choices=('COMPLETE', 'OVERVIEW'), default='COMPLETE')
        if name == 'resolve':
            command.add_argument('--registrations', type=Path, required=True)
            command.add_argument('--expect-registrations', required=True)
            command.add_argument('--expect-base-root', required=True)
    encode = commands.add_parser('encode', allow_abbrev=False)
    for key in ('payload', 'output', 'native'):
        encode.add_argument('--' + key, type=Path, required=True)
    encode.add_argument('--expect-payload', required=True)
    encode.add_argument('--title', default='SENTINEL proposed graph')
    encode.add_argument('--reference', default='meaning.zip')
    encode.add_argument('--budget', type=int)
    encode.add_argument('--display-profile', choices=('COMPLETE', 'OVERVIEW'), default='COMPLETE')
    return parser.parse_args(argv)


def input_manifest(folder, raw, held):
    value = held_record(raw, held)
    fields(value, ('schema', 'records', 'artifacts', 'bases', 'decoder_identity_sha256'))
    require(value['schema'] == 'sentinel/bundle-input/1', 'input manifest version')
    require(type(value['records']) is dict and len(value['records']) <= len(bundle.RECORDS), 'input record bound')
    require(type(value['artifacts']) is dict and len(value['artifacts']) <= 256, 'input registry bound')
    manifest_pins(value)
    records, artifacts, retained = {}, {}, 0
    for name, pin in value['records'].items():
        require(name in bundle.RECORDS, 'input record name')
        pin_checked(pin); require(pin['bytes'] <= METADATA, 'input record byte bound')
        data = read_file(folder / (name + '.json'), METADATA)
        require(identity(data) == pin, 'input record identity')
        records[name] = data
    for key, pin in value['artifacts'].items():
        from .common import hash_checked
        hash_checked(key); pin_checked(pin)
        require(pin['bytes'] <= METADATA and retained + pin['bytes'] <= REGISTRY, 'input artifact aggregate bound')
        retained += pin['bytes']
        data = read_file(folder / (key + '.bin'), METADATA)
        require(identity(data) == pin and digest(data) == key, 'input artifact identity')
        artifacts[key] = data
    return records, artifacts, value


def graph_summary(index, records, artifacts, display_profile='COMPLETE'):
    sections, lexicon, visible = bundle.presentation(index, records, artifacts, display_profile=display_profile)
    return {'schema': 'sentinel/receiving-summary/1', 'profile': index['schema'],
        'graph_sha256': index['graph_sha256'], 'visible_graph': visible, 'lexicon': lexicon,
        'display_profile': display_profile, 'semantic_decoder_binding': 'PROFILE1_UNBOUND'
            if index['schema'] == bundle.PROFILE else 'FRESH_TRUSTED_SOURCE_ROSTER_NOT_HOST_ATTESTATION',
        'base_dependencies': index['bases'], 'base_resolution': 'NOT_PERFORMED_GRAPH_ONLY',
        'admissions': 'BUNDLED_PINS_NOT_INDEPENDENTLY_HELD',
        'native_receipts': 'POINTERS_NOT_PROOF_VERIFICATION',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE',
        'semantic_completeness': 'UNPROVEN'}


def registrations(raw, held):
    value = held_record(raw, held)
    require(type(value) is dict and len(value) <= 64, 'registered base config bound')
    result = {}
    for key, row in value.items():
        fields(row, ('archive', 'share', 'native'))
        require(all(type(path) is str and len(path.encode('utf-8')) <= 4096 for path in row.values()),
                'operator registered path bound')
        result[key] = {name: Path(path) for name, path in row.items()}
    return result


def execute(args):
    if args.command == 'pack':
        records, artifacts, value = input_manifest(args.input_dir, read_file(args.manifest, METADATA), args.expect_manifest)
        packer = bundle.pack if args.semantic_root is None else bundle.pack_bound
        extra = () if args.semantic_root is None else (args.semantic_root,)
        raw = packer(records, artifacts, registry_root(artifacts), value['bases'], value['decoder_identity_sha256'], *extra)
        bundle.write_payload(args.output, raw)
        return {'status': 'SNE1_DATA_WRITTEN_NOT_SAST_ENCODED', **identity(raw), 'models': 'NOT_DISPATCHED'}
    if args.command == 'inspect-payload':
        raw = read_file(args.payload, bundle.PAYLOAD_CAP)
        index, records, artifacts = bundle.decode_payload(raw, args.expect_payload, args.decoder_identity, args.semantic_root)
        result = graph_summary(index, records, artifacts, args.display_profile)
        if args.export is not None:
            result['export'] = bundle.export_entries(index, records, artifacts, args.export)
        return result
    if args.command == 'encode':
        raw = read_file(args.payload, bundle.PAYLOAD_CAP)
        require(digest(raw) == args.expect_payload, 'held encoder payload mismatch')
        return bundle.encode_with_sast(args.payload, args.output, args.title, args.reference, args.budget, args.native, args.expect_payload,
                                       args.display_profile, args.semantic_root)
    decoded = bundle.decode_with_sast(args.archive, args.share, args.decoder_identity, args.native, args.semantic_root)
    result = graph_summary(decoded['index'], decoded['records'], decoded['artifacts'], args.display_profile)
    if args.command == 'resolve':
        config = registrations(read_file(args.registrations, METADATA), args.expect_registrations)
        result['source_evidence'] = bundle.resolve_registered(decoded, config, args.expect_base_root)
        result['base_resolution'] = result['source_evidence']['status']
    return result


def main(argv=None):
    try:
        value = execute(arguments(argv))
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
        require(len(raw) + 1 <= METADATA, 'CLI output byte bound')
        sys.stdout.buffer.write(raw + b'\n')
        return 0
    except MemoryError:
        memory_refusal()
        return 1
    except (ValueError, OSError, TypeError, KeyError) as error:
        raw = canonical({'status': 'REFUSED', 'reason': str(error)[:256], 'execution_authority': 'NONE'})
        sys.stdout.buffer.write(raw + b'\n')
        return 1




def manifest_pins(value):
    """Reject an overbudget or path-bearing input manifest before any input read."""
    from .common import hash_checked
    total = 0
    for name, pin in value['records'].items():
        require(name in bundle.RECORDS, 'input record name')
        pin_checked(pin); require(pin['bytes'] <= METADATA, 'input record byte bound')
    for key, pin in value['artifacts'].items():
        hash_checked(key); pin_checked(pin)
        require(pin['sha256'] == key and pin['bytes'] <= METADATA, 'input artifact pin')
        total += pin['bytes']
        require(total <= REGISTRY, 'input artifact aggregate bound')


from transport_document_io import loaded_epoch as _loaded_epoch
SOURCE_EPOCH = _loaded_epoch(__file__, sys._getframe().f_code)


if __name__ == '__main__':
    limits()
    raise SystemExit(main())
