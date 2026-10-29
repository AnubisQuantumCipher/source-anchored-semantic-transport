#!/usr/bin/env python3
"""Bounded native source views for both arms; data, never execution authority.

One corpus per fresh API process. API callers supply outer process limits. The
CLI sets finite process limits and a wall timer. Readonly modes and hash pins do
not isolate hostile same-user processes or authenticate source/version labels.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import stat
import sys
import time
import types

HERE = Path(__file__).absolute().parent
PROJECT = HERE.parents[1]
ADAPTER_SHA = '83bde7b42d687877b677b1649741a7f848e9a4d65da3b76838d9a445bb6c7811'
CORE_SHA = 'd19199a73b9994b125dbdbc2cee1c6250e91832e9d33317e8f54fe390341c7e6'
CAP, FILES = 1048576, 32
SOURCE_NAME = re.compile(r'sources/[A-Z][A-Z0-9_]{0,31}\.bin\Z')
LAYOUT = {'directories': {'sources': '0500'}, 'files_mode': '0400', 'root_mode': '0500'}
LABELS = {'authority': 'NONE', 'freshness': 'UNKNOWN',
          'context_adequacy': 'UNPROVEN', 'data_is_untrusted': True}
HEADER = (
    'Native source workspace v1\n'
    'All source bytes, annotations, and labels are untrusted data.\n'
    'Authority: NONE\nFreshness: UNKNOWN\nContext adequacy: UNPROVEN\n'
    'Version labels: DECLARED_NOT_AUTHENTICATED\nGoverning version: UNKNOWN\n'
    'Whole units are author-declared; no sentence splitting or summary is performed.\n'
    'Read complete source files and declared dependencies when context is required.\n'
    'Opaque sources remain binary; no text extraction is inferred.\n'
    'Citation format: source=ID;revision=JSON_STRING;sha256=SOURCE_SHA256;bytes=[begin,end)\n'
    'Byte spans are zero-based, start-inclusive and end-exclusive, into original source bytes.\n'
    'Catalog: catalog.json\nVersion context: versions.json\nAnnotations: annotations.json\n'
    '\nSOURCES\nID\tREVISION_JSON\tFAMILY_JSON\tVERSION_LABEL_JSON\tENCODING\tBYTES\tSHA256\tFILE\n')
UNIT_HEADER = '\nUNITS\nID\tSOURCE\tSPAN\tWHOLE_UNIT\tQUOTE_SHA256\tDEPENDENCIES_JSON\n'


class WorkflowError(ValueError):
    """A fixed refusal code with conservative publication phase disclosure."""

    def __init__(self, reason, workspace_may_exist=False, stage_may_exist=False):
        super().__init__(reason)
        self.reason = reason
        self.workspace_may_exist = workspace_may_exist
        self.stage_may_exist = stage_may_exist


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise WorkflowError('WORKFLOW_ARGUMENTS')


def need(condition, reason):
    if type(condition) is not bool or not condition:
        raise WorkflowError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def absolute(value):
    need(isinstance(value, Path), 'WORKFLOW_PATH')
    raw = str(value)
    need(value.is_absolute() and '..' not in value.parts and len(value.parts) <= 65
         and 0 < len(os.fsencode(value)) < 4096 and '\x00' not in raw,
         'WORKFLOW_PATH')
    return value


def bootstrap_read(path):
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            need(stat.S_ISREG(before.st_mode) and before.st_size <= 65536, 'WORKFLOW_ADAPTER_BOUND')
            raw = bytearray()
            for unused in range(6):
                chunk = os.read(descriptor, min(16384, 65537 - len(raw)))
                if not chunk:
                    need(metadata(before) == metadata(os.fstat(descriptor)) and
                         len(raw) == before.st_size, 'WORKFLOW_ADAPTER_CHANGED')
                    return bytes(raw)
                raw.extend(chunk)
                need(len(raw) <= 65536, 'WORKFLOW_ADAPTER_BOUND')
            raise WorkflowError('WORKFLOW_ADAPTER_BOUND')
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def bootstrap():
    path = PROJECT / 'comparison/retrieval/adapter.py'
    raw = bootstrap_read(path)
    need(pin(raw)['sha256'] == ADAPTER_SHA, 'WORKFLOW_ADAPTER_PIN')
    module = types.ModuleType('_native_workflow_adapter')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    inputs = module.approved_helpers()
    core = module.load_core(CORE_SHA)
    return module, inputs, sys.modules['transport_install_support'], core


def metadata(value):
    return tuple(getattr(value, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def cell(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def index_bytes(result):
    rows = [HEADER]
    for item in result['sources']:
        attributes = item['attributes']
        fields = (item['id'], cell(item['revision']), cell(attributes.get('family_id')),
                  cell(attributes.get('version_state')), item['encoding'], str(item['bytes']),
                  item['sha256'], 'sources/' + item['id'] + '.bin')
        rows.append('\t'.join(fields) + '\n')
    rows.append(UNIT_HEADER)
    for item in result['units']:
        begin, end = item['span']
        fields = (item['id'], item['source'], '[' + str(begin) + ',' + str(end) + ')',
                  'true', item['sha256'], cell(item['dependencies']))
        rows.append('\t'.join(fields) + '\n')
    rows.append('\nUNRESOLVED_DEPENDENCIES_JSON\t' + cell(result['unresolved_dependency_ids']) + '\n')
    return ''.join(rows).encode('ascii', errors='strict')


def versions_bytes(result):
    return canonical({'schema': 'transport/native-workflow-versions/1', 'authority': 'NONE',
        'freshness': 'UNKNOWN', 'version_labels': 'DECLARED_NOT_AUTHENTICATED',
        'governing_version': 'UNKNOWN',
        'sources': [{key: item[key] for key in ('id', 'revision', 'attributes')}
                    for item in result['sources']],
        'units': [{key: item[key] for key in ('id', 'source', 'dependencies')}
                  for item in result['units']]})


def render(sources, annotations, core):
    started = time.monotonic_ns()
    corpus = core.Corpus(sources, annotations, pin(annotations)['sha256'])
    try:
        raw = corpus.call(b'{"action":"catalog"}')
        catalog = json.loads(raw)
        need(catalog['status'] == 'OK' and catalog['call'] == 1, 'WORKFLOW_CATALOG')
        metrics = corpus.metrics()
    finally:
        corpus.close()
    catalogued = time.monotonic_ns()
    result = catalog['result']
    files = {'sources/' + name + '.bin': data for name, data in sources.items()}
    files.update({'annotations.json': annotations, 'catalog.json': raw,
                  'index.txt': index_bytes(result), 'versions.json': versions_bytes(result)})
    costs = {'catalog_ns': catalogued - started, 'index_version_ns': time.monotonic_ns() - catalogued,
             'core': metrics}
    return files, catalog['snapshot'], costs


def manifest_bytes(arm, inputs, snapshot, files):
    return canonical(dict(LABELS, schema='transport/native-source-workspace/1', arm=arm,
        inputs=inputs, source_snapshot=snapshot, layout=LAYOUT,
        files={name: pin(raw) for name, raw in files.items()}, self_binding='EXTERNALLY_HELD_SHA256'))


def bounded(files):
    need(1 <= len(files) <= FILES and sum(len(raw) for raw in files.values()) <= CAP,
         'WORKFLOW_WORKSPACE_BOUND')
    need(all(type(raw) is bytes and len(raw) <= CAP for raw in files.values()),
         'WORKFLOW_WORKSPACE_BOUND')


def overlap(left, right):
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def private_parent(path, support):
    descriptor = support._directory(path.parent)
    try:
        item = os.fstat(descriptor)
        need(item.st_uid == os.geteuid() and stat.S_IMODE(item.st_mode) & 0o077 == 0,
             'WORKFLOW_PARENT_PRIVATE')
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise WorkflowError('WORKFLOW_OUTPUT_EXISTS')
    finally:
        os.close(descriptor)


def output_paths(manifest, annotations, frozen, root, workspace, receipt, support):
    protected = [PROJECT, manifest.parent, annotations.parent, root]
    if frozen['arm'] == 'transport':
        protected.append(absolute(Path(frozen['bundle']['path'])))
    need(not overlap(workspace, receipt), 'WORKFLOW_PATH_OVERLAP')
    for path in (workspace, receipt):
        need(all(not overlap(path, item) for item in protected), 'WORKFLOW_PATH_OVERLAP')
        private_parent(path, support)


def admitted(manifest, held_manifest, annotations, held_annotations, held_core, workspace, receipt, loaded):
    adapter, inputs, support, core = loaded
    need(held_core == CORE_SHA, 'WORKFLOW_CORE_PIN')
    for path in (manifest, annotations, workspace, receipt):
        absolute(path)
    started = time.monotonic_ns()
    frozen, root, data = inputs.frozen_manifest(manifest, held_manifest)
    raw_manifest = support.read_regular(manifest, 65536)
    need(pin(raw_manifest)['sha256'] == inputs.digest(held_manifest), 'WORKFLOW_MANIFEST_PIN')
    output_paths(manifest, annotations, frozen, root, workspace, receipt, support)
    checked = time.monotonic_ns()
    sources = adapter.recovered_sources(inputs, frozen, root, data)
    recovered = time.monotonic_ns()
    raw = support.read_regular(annotations, 65536)
    need(pin(raw)['sha256'] == inputs.digest(held_annotations), 'WORKFLOW_ANNOTATION_PIN')
    costs = {'source_admission_ns': checked - started, 'source_recovery_ns': recovered - checked,
             'annotation_read_ns': time.monotonic_ns() - recovered,
             'carrier_bytes': sum(len(value) for value in data.values()),
             'source_bytes': sum(len(value) for value in sources.values()),
             'cache_state': 'FRESH_PROCESS_HOST_CACHE_UNCONTROLLED'}
    pins = {'handoff_manifest': pin(raw_manifest), 'annotations': pin(raw),
            'core_sha256': CORE_SHA, 'adapter_sha256': ADAPTER_SHA}
    return frozen, data, sources, raw, pins, costs


def revalidate(manifest, held_manifest, annotations, raw, frozen, data, loaded):
    unused, inputs, support, unused_core = loaded
    current, unused_root, fresh = inputs.frozen_manifest(manifest, held_manifest)
    need(current == frozen and fresh == data and support.read_regular(annotations, 65536) == raw,
         'WORKFLOW_INPUT_CHANGED')
    if frozen['arm'] == 'transport':
        snapshot = sys.modules['test_portable_handoff'].bundle_snapshot(Path(frozen['bundle']['path']))
        need(pin(canonical(snapshot))['sha256'] == frozen['bundle']['snapshot_sha256'],
             'WORKFLOW_BUNDLE_CHANGED')


def mode_directory(path, mode, support):
    descriptor = support._directory(path)
    try:
        need(os.fstat(descriptor).st_uid == os.geteuid(), 'WORKFLOW_DIRECTORY_OWNER')
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_stage(workspace, files, support, phase):
    stage = workspace.parent / ('.native-source-' + secrets.token_hex(12))
    parent = support._directory(workspace.parent)
    try:
        phase['stage_may_exist'] = True
        os.mkdir(stage.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    os.mkdir(stage / 'sources', mode=0o700)
    for name, raw in sorted(files.items()):
        path = stage / name
        support.write_new(path, raw, CAP)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    mode_directory(stage / 'sources', 0o500, support)
    return stage


def directory_metadata(descriptor):
    item = os.fstat(descriptor)
    need(stat.S_ISDIR(item.st_mode) and item.st_uid == os.geteuid()
         and stat.S_IMODE(item.st_mode) == 0o500, 'WORKFLOW_DIRECTORY_MODE')
    return metadata(item)


def read_child(descriptor, name, support):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=descriptor)
    try:
        before = os.fstat(child)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400,
             'WORKFLOW_FILE_MODE')
        raw = support._read_fd(child, CAP)
        need(metadata(before) == metadata(os.fstat(child)), 'WORKFLOW_FILE_CHANGED')
        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        need(metadata(before) == metadata(current), 'WORKFLOW_FILE_CHANGED')
        return raw
    finally:
        os.close(child)


def directory_names(descriptor):
    names = []
    with os.scandir(descriptor) as entries:
        for unused in range(FILES + 2):
            entry = next(entries, None)
            if entry is None:
                return sorted(names)
            need(len(names) < FILES + 1, 'WORKFLOW_FILE_BOUND')
            names.append(entry.name)
    raise WorkflowError('WORKFLOW_FILE_BOUND')


def tree_bytes(workspace, support):
    descriptor = support._directory(workspace)
    source_fd = None
    try:
        initial = directory_metadata(descriptor)
        names = directory_names(descriptor)
        need(set(names) == {'sources', 'workspace.json', 'annotations.json', 'catalog.json',
                            'index.txt', 'versions.json'}, 'WORKFLOW_TREE_LAYOUT')
        source_fd = os.open('sources', support.DIRECTORY_FLAGS, dir_fd=descriptor)
        source_initial = directory_metadata(source_fd)
        source_names = directory_names(source_fd)
        need(1 <= len(source_names) <= 16, 'WORKFLOW_SOURCE_COUNT')
        files = {}
        for name in source_names:
            relative = 'sources/' + name
            need(SOURCE_NAME.fullmatch(relative) is not None, 'WORKFLOW_SOURCE_PATH')
            files[relative] = read_child(source_fd, name, support)
            bounded(files)
        for name in names:
            if name != 'sources':
                files[name] = read_child(descriptor, name, support)
                bounded(files)
        need(directory_metadata(source_fd) == source_initial and directory_names(source_fd) == source_names
             and directory_metadata(descriptor) == initial and directory_names(descriptor) == names,
             'WORKFLOW_TREE_CHANGED')
        return files
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(descriptor)


def pin_record(value, inputs):
    inputs.fields(value, ('bytes', 'sha256'))
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= CAP, 'WORKFLOW_PIN_SIZE')
    inputs.digest(value['sha256'])


def checked_manifest(raw, held, inputs):
    need(pin(raw)['sha256'] == inputs.digest(held), 'WORKFLOW_HELD_MANIFEST_PIN')
    value = inputs.json_value(raw, CAP)
    inputs.fields(value, ('schema', 'arm', 'inputs', 'source_snapshot', 'layout', 'files',
                          'self_binding', *LABELS))
    need(canonical(value) == raw and value['schema'] == 'transport/native-source-workspace/1'
         and value['arm'] in ('original', 'transport') and value['layout'] == LAYOUT
         and value['self_binding'] == 'EXTERNALLY_HELD_SHA256', 'WORKFLOW_MANIFEST_SCHEMA')
    need(all(type(value[key]) is type(expected) and value[key] == expected
             for key, expected in LABELS.items()), 'WORKFLOW_LABELS')
    inputs.digest(value['source_snapshot'])
    record = value['inputs']
    inputs.fields(record, ('handoff_manifest', 'annotations', 'core_sha256', 'adapter_sha256'))
    need(record['core_sha256'] == CORE_SHA and record['adapter_sha256'] == ADAPTER_SHA,
         'WORKFLOW_CODE_PIN')
    for key in ('handoff_manifest', 'annotations'):
        pin_record(record[key], inputs)
        need(record[key]['bytes'] <= 65536, 'WORKFLOW_INPUT_BOUND')
    need(type(value['files']) is dict and 1 <= len(value['files']) < FILES,
         'WORKFLOW_INVENTORY_BOUND')
    for name, item in value['files'].items():
        need(type(name) is str and (name in ('annotations.json', 'catalog.json', 'index.txt',
             'versions.json') or SOURCE_NAME.fullmatch(name) is not None), 'WORKFLOW_INVENTORY_PATH')
        pin_record(item, inputs)
    return value


def verify_loaded(workspace, held, loaded):
    unused, inputs, support, core = loaded
    started = time.monotonic_ns()
    files = tree_bytes(absolute(workspace), support)
    manifest = checked_manifest(files['workspace.json'], held, inputs)
    actual = {name: pin(raw) for name, raw in files.items() if name != 'workspace.json'}
    need(actual == manifest['files'] and pin(files['annotations.json']) == manifest['inputs']['annotations'],
         'WORKFLOW_FILE_PIN')
    sources = {name[8:-4]: raw for name, raw in files.items() if name.startswith('sources/')}
    expected, snapshot, costs = render(sources, files['annotations.json'], core)
    expected['workspace.json'] = manifest_bytes(manifest['arm'], manifest['inputs'], snapshot, expected)
    need(files == expected and snapshot == manifest['source_snapshot'], 'WORKFLOW_DERIVED_MISMATCH')
    return dict(LABELS, schema='transport/native-workflow-verification/1', status='VERIFIED_NATIVE_FILES',
        workspace_manifest=pin(files['workspace.json']), source_snapshot=snapshot,
        file_count=len(files), workspace_bytes=sum(len(raw) for raw in files.values()),
        costs={'verification_ns': time.monotonic_ns() - started,
               'cache_state': 'HOST_CACHE_UNCONTROLLED', 'derived': costs})


def failure(error, phase):
    reason = error.reason if isinstance(error, WorkflowError) else 'WORKFLOW_VALIDATION_OR_IO'
    return WorkflowError(reason, phase['workspace_may_exist'], phase['stage_may_exist'])


def verify_workspace(workspace, held_workspace_manifest_sha256):
    try:
        return canonical(verify_loaded(workspace, held_workspace_manifest_sha256, bootstrap()))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, MemoryError, TimeoutError) as error:
        raise failure(error, {'workspace_may_exist': True, 'stage_may_exist': False}) from error


def prepare_loaded(manifest, held_manifest, annotations, held_annotations, held_core,
                   workspace, receipt, loaded, phase):
    unused, unused_inputs, support, core = loaded
    frozen, data, sources, raw, pins, costs = admitted(manifest, held_manifest, annotations,
        held_annotations, held_core, workspace, receipt, loaded)
    files, snapshot, rendered = render(sources, raw, core)
    costs.update(rendered)
    files['workspace.json'] = manifest_bytes(frozen['arm'], pins, snapshot, files)
    bounded(files)
    copying = time.monotonic_ns()
    stage = write_stage(workspace, files, support, phase)
    costs['copy_ns'] = time.monotonic_ns() - copying
    revalidate(manifest, held_manifest, annotations, raw, frozen, data, loaded)
    publishing = time.monotonic_ns()
    phase['workspace_may_exist'] = True
    support.atomic_publish(stage, workspace)
    phase['stage_may_exist'] = False
    mode_directory(workspace, 0o500, support)
    costs['publication_ns'] = time.monotonic_ns() - publishing
    checked = verify_loaded(workspace, pin(files['workspace.json'])['sha256'], loaded)
    costs['final_verification'] = checked['costs']
    result = dict(checked, schema='transport/native-workflow-receipt/1',
        status='PREPARED_VERIFIED_NATIVE_FILES', workspace=str(workspace), arm=frozen['arm'], costs=costs)
    answer = canonical(result)
    need(len(answer) <= 65536, 'WORKFLOW_RECEIPT_BOUND')
    support.write_new(receipt, answer, 65536)
    need(support.read_regular(receipt, 65536) == answer, 'WORKFLOW_RECEIPT_READBACK')
    return answer


def prepare_workspace(manifest, held_manifest_sha256, annotations, held_annotations_sha256,
                      held_core_sha256, workspace, receipt):
    phase = {'workspace_may_exist': False, 'stage_may_exist': False}
    try:
        return prepare_loaded(manifest, held_manifest_sha256, annotations, held_annotations_sha256,
                              held_core_sha256, workspace, receipt, bootstrap(), phase)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, MemoryError, TimeoutError) as error:
        raise failure(error, phase) from error


def refusal(error):
    return canonical(dict(LABELS, schema='transport/native-workflow-refusal/1', status='REFUSED',
        reason=error.reason, workspace_may_exist=error.workspace_may_exist,
        stage_may_exist=error.stage_may_exist))


def arguments():
    need(1 <= len(sys.argv) <= 32 and all(len(os.fsencode(arg)) <= 4096 for arg in sys.argv)
         and sum(len(os.fsencode(arg)) for arg in sys.argv) <= 32768, 'WORKFLOW_ARGUMENTS')
    parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest='action', required=True)
    prepare = actions.add_parser('prepare', add_help=False, allow_abbrev=False)
    for name in ('manifest', 'annotations', 'workspace', 'receipt'):
        prepare.add_argument('--' + name, required=True, type=path_argument)
    for name in ('manifest', 'annotations', 'core'):
        prepare.add_argument('--expect-' + name + '-sha256', required=True)
    verify = actions.add_parser('verify', add_help=False, allow_abbrev=False)
    verify.add_argument('--workspace', required=True, type=path_argument)
    verify.add_argument('--expect-workspace-manifest-sha256', required=True)
    return parser.parse_args()


def path_argument(value):
    need(type(value) is str and str(Path(value)) == value, 'WORKFLOW_PATH')
    return absolute(Path(value))


def timed_out(unused_signal, unused_frame):
    raise TimeoutError('WORKFLOW_TIMEOUT')


def process_limits():
    for kind, value in ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 120),
                        (resource.RLIMIT_FSIZE, 33554432), (resource.RLIMIT_NOFILE, 128)):
        unused, hard = resource.getrlimit(kind)
        limit = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(kind, (limit, limit))
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(30)


def emit(raw, code, possible):
    framed = raw + b'\n'
    offset = 0
    try:
        for unused in range(65538):
            if offset == len(framed):
                return code
            count = os.write(1, framed[offset:offset + 16384])
            need(type(count) is int and 0 < count <= min(16384, len(framed) - offset),
                 'WORKFLOW_OUTPUT_COUNT')
            offset += count
        raise WorkflowError('WORKFLOW_OUTPUT_BOUND')
    except (OSError, ValueError, TimeoutError):
        diagnostic = refusal(WorkflowError('WORKFLOW_OUTPUT_INCOMPLETE', possible)) + b'\n'
        try:
            os.write(2, diagnostic)
        except OSError:
            pass
        return 1


def main():
    possible, code = False, 0
    try:
        process_limits()
        args = arguments()
        possible = True
        if args.action == 'prepare':
            raw = prepare_workspace(args.manifest, args.expect_manifest_sha256, args.annotations,
                args.expect_annotations_sha256, args.expect_core_sha256, args.workspace, args.receipt)
        else:
            raw = verify_workspace(args.workspace, args.expect_workspace_manifest_sha256)
    except WorkflowError as error:
        raw, possible, code = refusal(error), error.workspace_may_exist, 1
    except (OSError, ValueError, TimeoutError):
        raw, code = refusal(WorkflowError('WORKFLOW_CLI_LIMITS_OR_IO', possible)), 1
    try:
        return emit(raw, code, possible)
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
