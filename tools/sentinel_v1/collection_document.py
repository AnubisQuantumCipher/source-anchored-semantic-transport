"""Nested SAST/SNC1 document integrity; proposed text never grants authority."""
from contextlib import contextmanager
import ast
import dis
from pathlib import Path
import sys
import tempfile
import types
import transport_document as document
from transport_document_io import read_file, identity as file_identity
from . import collection, document_analysis, locators
from .common import (METADATA, canonical, digest, fields, hash_checked, identity,
                     integer, parse, require)

PROFILE = 'sentinel/collection-document/1'
ADAPTER_SOURCES = ('sentinel_v1/__init__.py', 'sentinel_v1/common.py', 'sentinel_v1/census.py',
    'sentinel_v1/graph.py', 'sentinel_v1/bindings.py', 'sentinel_v1/assessments.py',
    'sentinel_v1/analysis.py', 'sentinel_v1/document_analysis.py', 'sentinel_v1/collection.py',
    'sentinel_v1/locators.py', 'sentinel_v1/collection_document.py', 'transport_document.py',
    'transport_document_io.py', 'transport_document_archive.py', 'transport_document_reading.py',
    'transport_document_context.py')


def adapter_sources():
    root, pins, total = Path(__file__).resolve().parent.parent, {}, 0
    for name in ADAPTER_SOURCES:
        key, size = document.file_digest(root / name, METADATA)
        total += size; require(total <= METADATA, 'adapter source aggregate bound')
        pins[name] = {'bytes': size, 'sha256': key}
    return pins


MODULE_EPOCH = tuple((name, pin['bytes'], pin['sha256']) for name, pin in adapter_sources().items())


def literal_equal(actual, expected):
    pending = [(actual, expected)]
    for _ in range(4096):
        if not pending:
            return True
        left, right = pending.pop()
        if type(left) is not type(right):
            return False
        if type(right) is tuple:
            if len(left) != len(right) or len(pending) + len(right) > 4096:
                return False
            pending.extend(zip(left, right))
        elif type(right) in (type(None), bool, int, float, complex, str, bytes):
            if left != right:
                return False
        else:
            return False
    require(not pending, 'adapter literal comparison bound')
    return True


def function_checked(actual, expected):
    require(type(actual) is types.FunctionType, 'loaded adapter function missing/type')
    if actual.__code__ == expected:
        return actual
    wrapped = actual.__dict__.get('__wrapped__')
    require(type(wrapped) is types.FunctionType and wrapped.__code__ == expected,
            'loaded adapter function differs from compiled source')
    require(actual.__code__ == contextmanager(wrapped).__code__, 'unknown adapter function wrapper')
    closure = actual.__closure__
    require(closure is not None and len(closure) == 1 and closure[0].cell_contents is wrapped,
            'adapter contextmanager closure differs')
    return wrapped


def default_matches(actual, expression, namespace):
    if isinstance(expression, ast.Constant):
        return literal_equal(actual, expression.value)
    if isinstance(expression, ast.Tuple) and not expression.elts:
        return literal_equal(actual, ())
    if isinstance(expression, ast.Name):
        require(expression.id in namespace, 'adapter default binding missing')
        return literal_equal(actual, namespace[expression.id])
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        module = namespace.get(expression.value.id)
        require(type(module) is types.ModuleType and expression.attr in module.__dict__,
                'adapter default module binding missing')
        return actual is module.__dict__[expression.attr]
    require(False, 'unsupported adapter default expression')
    return False


def defaults_checked(actual, node, namespace):
    positional, keywords = node.args.defaults, node.args.kw_defaults
    require(len(positional) <= 64 and len(keywords) <= 64, 'adapter default count bound')
    defaults = actual.__defaults__
    require((defaults is None and not positional) or type(defaults) is tuple
            and len(defaults) == len(positional), 'loaded adapter default arity differs')
    for value, expression in zip(defaults or (), positional):
        require(default_matches(value, expression, namespace), 'loaded adapter default differs from source')
    expected = {argument.arg: expression for argument, expression in
                zip(node.args.kwonlyargs, keywords) if expression is not None}
    supplied = actual.__kwdefaults__
    require((supplied is None and not expected) or type(supplied) is dict
            and set(supplied) == set(expected), 'loaded adapter keyword default arity differs')
    for name, expression in expected.items():
        require(default_matches(supplied[name], expression, namespace),
                'loaded adapter keyword default differs from source')


def bindings_checked(namespace, code, class_scope=False):
    previous, count = None, 0
    for instruction in dis.get_instructions(code):
        count += 1; require(count <= 65536, 'adapter module instruction bound')
        if instruction.opname == 'STORE_NAME':
            if class_scope and instruction.argval in ('__classcell__', '__classdictcell__'):
                continue  # Compiler cells are consumed by type creation, not public class bindings.
            require(instruction.argval in namespace, 'loaded adapter binding missing')
            if previous is not None and previous.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and type(previous.argval) is not types.CodeType:
                require(literal_equal(namespace[instruction.argval], previous.argval),
                        'loaded adapter literal differs from source')
        previous = instruction


def aliases_checked(module, tree):
    require(len(tree.body) <= 4096, 'adapter top-level statement bound')
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        require(len(node.names) <= 4096, 'adapter import alias bound')
        for alias in node.names:
            if isinstance(node, ast.Import):
                name = alias.name if alias.asname else alias.name.split('.')[0]
                expected = sys.modules.get(name); bound = alias.asname or name
            else:
                package = module.__package__.split('.')
                require(node.level <= len(package), 'adapter relative import bound')
                prefix = '.'.join(package[:len(package) - node.level + 1]) if node.level else ''
                name = '.'.join(part for part in (prefix, node.module) if part)
                parent = sys.modules.get(name)
                require(parent is not None, 'loaded adapter import missing')
                expected = parent.__dict__.get(alias.name, sys.modules.get(name + '.' + alias.name))
                bound = alias.asname or alias.name
            require(expected is not None and module.__dict__.get(bound) is expected,
                    'loaded adapter import alias differs')


def module_checked(module, raw, path):
    require(type(module) is types.ModuleType and Path(module.__file__).resolve() == path.resolve(),
            'loaded adapter module path mismatch')
    code = compile(raw, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    bindings_checked(module.__dict__, code)
    require(len(code.co_consts) <= 4096, 'adapter top-level code constant bound')
    tree = ast.parse(raw, str(path))
    declarations = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    require(len(declarations) <= 4096, 'adapter declaration bound')
    for node in declarations:
        matches = [item for item in code.co_consts if type(item) is types.CodeType and item.co_name == node.name]
        require(len(matches) == 1, 'adapter compiled declaration missing/duplicate')
        entry = matches[0]
        actual = module.__dict__.get(entry.co_name)
        if type(actual) is type:
            namespace = dict(actual.__dict__, __qualname__=actual.__qualname__)
            bindings_checked(namespace, entry, True)
            require(len(entry.co_consts) <= 4096, 'adapter class method bound')
            for method in entry.co_consts:
                if type(method) is types.CodeType:
                    definitions = [part for part in node.body if isinstance(part, ast.FunctionDef)
                                   and part.name == method.co_name]
                    require(len(definitions) == 1, 'adapter method syntax missing/duplicate')
                    function = function_checked(actual.__dict__.get(method.co_name), method)
                    defaults_checked(function, definitions[0], dict(module.__dict__, **namespace))
        else:
            defaults_checked(function_checked(actual, entry), node, module.__dict__)
    aliases_checked(module, tree)


def loaded_checked(sources):
    root = Path(__file__).resolve().parent.parent
    for name in ADAPTER_SOURCES:
        path = root / name; raw = read_file(path, METADATA)
        require(identity(raw) == sources[name], 'adapter source changed during code check')
        module_name = name[:-3].replace('/', '.')
        if module_name.endswith('.__init__'):
            module_name = module_name[:-9]
        module_checked(sys.modules.get(module_name), raw, path)


def adapter_runtime(native):
    sources = adapter_sources()
    epoch = {name: {'bytes': size, 'sha256': key} for name, size, key in MODULE_EPOCH}
    require(sources == epoch, 'adapter source changed since import')
    loaded_checked(sources)
    key, size = document.file_digest(native, 16777216)
    return {'schema': 'sentinel/collection-document-decoder/1', 'sources': sources,
        'native': {'bytes': size, 'sha256': key},
        'legacy_runtime_sha256': digest(document.canonical(document.runtime(native)))}


def adapter_checked(native, expected):
    require(digest(canonical(adapter_runtime(native))) == expected, 'held adapter descriptor differs')


def held_checked(held):
    fields(held, ('collection_sha256', 'base_archive', 'base_share', 'decoder_root_sha256',
                  'outer_share', 'adapter_descriptor_sha256'))
    hash_checked(held['collection_sha256']); hash_checked(held['decoder_root_sha256'])
    hash_checked(held['adapter_descriptor_sha256'])
    for key, cap in (('base_archive', collection.MAX_SOURCE), ('base_share', document.MAX_META),
                     ('outer_share', document.MAX_META)):
        fields(held[key], ('sha256', 'bytes')); hash_checked(held[key]['sha256'])
        integer(held[key]['bytes'], 1, cap)
    return parse(canonical(held))


def full_share_checked(share, pin):
    key, size = document.file_digest(share, document.MAX_META)
    require({'sha256': key, 'bytes': size} == pin, 'complete share differs from independently admitted bytes')


def decode_plan(archive, share, native):
    with document.opened(archive) as (opened, names):
        body, package_id, _sections, _record = document.verified_metadata(opened, names, share, native)
        derived = body['reading'] is not None and body['reading']['mode'] == 'derived'
        frames = body['frames'] + (body['reading']['frames'] if derived else [])
        sizes = body['source']['bytes'] + (body['reading']['bytes'] if derived else 0)
        needed = file_identity(opened.fp)[2] + sizes + 32
        needed += sum(frame['wire_bytes'] + 20 for frame in frames) + document.MAX_META
        integer(needed, 0, document.MAX_TEMP)
        return needed, body['source']['sha256'], package_id


def reserve_nested(root, outer, exports, inner=0):
    for value in (outer, exports, inner):
        integer(value, 0, document.MAX_TEMP)
    total = outer + exports + inner
    integer(total, 0, document.MAX_TEMP)
    document.reserve(root, total)
    return total


def one(index, kind):
    rows = [row for row in index['items'] if row['kind'] == kind]
    require(len(rows) == 1, 'required unique document collection entry')
    return rows[0]


def selected_bytes(stream, index, body, kind):
    row = one(index, kind)
    return collection.entry_bytes(stream, index, body, row['id'])


def readable_checked(raw):
    value = parse(raw)
    fields(value, ('schema', 'text', 'status', 'execution_authority'))
    require(value['schema'] == 'sentinel/collection-readable/1'
        and value['status'] == 'PROPOSED_UNREVIEWED' and value['execution_authority'] == 'NONE',
        'readable collection text cannot grant authority or acceptance')
    text = value['text']
    require(type(text) is str and text and all(ord(c) >= 32 or c in '\n\r\t' for c in text),
            'readable proposed UTF8 text required')
    return value


def revisions_checked(raw, binding):
    value = parse(raw)
    fields(value, ('schema', 'records'))
    require(value['schema'] == 'sentinel/collection-revisions/1', 'collection revision envelope')
    rows = value['records']
    require(type(rows) is list and 1 <= len(rows) <= locators.REVISION_CAP, 'collection revision count')
    registry = {}
    for row in rows:
        encoded = canonical(row)
        require(len(encoded) <= locators.REVISION_BYTES, 'collection revision byte bound')
        key = digest(encoded); require(key not in registry, 'duplicate collection revision')
        registry[key] = encoded
    locators.revision_records(registry, binding)
    return registry


def document_metadata(stream, index, body):
    raw = selected_bytes(stream, index, body, 'DOCUMENT_INDEX')
    rows = [row for row in index['items'] if row['kind'] == 'CENSUS_BLOCK']
    require(len(rows) <= document_analysis.MAX_BLOCKS, 'collection document block count')
    require(len(raw) + sum(row['bytes'] for row in rows) <= document_analysis.TOTAL_METADATA,
            'collection document metadata aggregate before reads')
    blocks = {}
    for row in rows:
        require(row['sha256'] not in blocks, 'duplicate document block identity')
        blocks[row['sha256']] = collection.entry_bytes(stream, index, body, row['id'])
    docs = {kind: readable_checked(selected_bytes(stream, index, body, kind))
            for kind in ('DICTIONARY', 'INSTRUCTIONS')}
    revisions = revisions_checked(selected_bytes(stream, index, body, 'REVISION'), index['binding'])
    return raw, blocks, docs, revisions


def bound_metadata(source, body, package_id, index, metadata):
    path, _record = locators.package_binding(index['binding'], source, body, package_id)
    integer(index['binding']['representation']['bytes'], 0, document_analysis.MAX_READING)
    reading = read_file(path, document_analysis.MAX_READING)
    raw, blocks, docs, revisions = metadata
    document_index, groups = document_analysis.document_checked(reading, canonical(index['binding']),
        raw, digest(raw), blocks)
    return document_index, groups, docs, revisions


class VerifiedDocument:
    """Context-owned validated package; it ceases to be usable on manager exit."""
    __slots__ = ('_active', '_source', '_body', '_package', '_sections', '_binding',
                 '_revisions', '_summary')

    def __init__(self, source, body, package_id, sections, index, metadata, budget, held):
        document_index, groups, docs, revisions = bound_metadata(source, body, package_id, index, metadata)
        self._active, self._source = True, Path(source)
        self._body, self._package = document.canonical(body), package_id
        self._sections, self._binding = document.canonical(sections), canonical(index['binding'])
        self._revisions = revisions
        self._summary = canonical({'schema': PROFILE, 'binding': index['binding'],
            'index_sha256': digest(metadata[0]), 'paragraph_count': document_index['paragraph_count'],
            'job_count': document_index['job_count'], 'group_count': len(groups),
            'readable': docs, 'nested_reservation_bytes': budget, 'qualification': 'NOT_QUALIFIED',
            'adapter_descriptor_sha256': held['adapter_descriptor_sha256'],
            'legacy_decoder_root_sha256': held['decoder_root_sha256'],
            'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'})

    def report(self):
        require(self._active, 'collection document context closed')
        return parse(self._summary)


def export_base(stream, index, body, held, folder):
    paths = []
    for kind, key, name in (('BASE_ARCHIVE', 'base_archive', 'base.zip'),
                             ('BASE_SHARE', 'base_share', 'share.txt')):
        row = one(index, kind)
        require({key: row[key] for key in ('bytes', 'sha256')} == held[key], 'held inner package pin mismatch')
        path = folder / name
        require(collection.export_entry(stream, index, body, row['id'], path) == held[key],
                'inner package export differs')
        paths.append(path)
    return paths


@contextmanager
def verified_document(archive, share, held, native=None):
    held = held_checked(held); full_share_checked(share, held['outer_share'])
    native = document.native_path(native)
    runtime = document.runtime(native)
    require(digest(document.canonical(runtime)) == held['decoder_root_sha256'], 'held decoder identity differs')
    adapter_checked(native, held['adapter_descriptor_sha256'])
    root = document.scratch_root()
    outer, source_sha, outer_id = decode_plan(archive, share, native)
    require(source_sha == held['collection_sha256'], 'outer source is not held collection')
    exports = held['base_archive']['bytes'] + held['base_share']['bytes']
    reserve_nested(root, outer, exports)
    current = None
    try:
        full_share_checked(share, held['outer_share'])
        with document.validated(archive, share, native) as (recovered, outer_body, actual_id, _sections):
            require(actual_id == outer_id and outer_body['source']['sha256'] == source_sha,
                    'outer package changed since preflight')
            with collection.verified_file(recovered, held['collection_sha256'], held['decoder_root_sha256']) as selected:
                stream, index, start = selected
                with tempfile.TemporaryDirectory(prefix='collection-base-', dir=root) as folder:
                    base, base_share = export_base(stream, index, start, held, Path(folder))
                    inner, _inner_sha, inner_id = decode_plan(base, base_share, native)
                    budget = reserve_nested(root, outer, exports, inner)
                    metadata = document_metadata(stream, index, start)
                    full_share_checked(base_share, held['base_share'])
                    with document.validated(base, base_share, native) as bound:
                        source, body, package_id, sections = bound
                        require(package_id == inner_id, 'inner package changed since preflight')
                        full_share_checked(share, held['outer_share'])
                        full_share_checked(base_share, held['base_share'])
                        adapter_checked(native, held['adapter_descriptor_sha256'])
                        current = VerifiedDocument(source, body, package_id, sections, index, metadata, budget, held)
                        yield current
                        full_share_checked(share, held['outer_share'])
                        adapter_checked(native, held['adapter_descriptor_sha256'])
    finally:
        if current is not None:
            current._active = False


def bound_files_checked(context):
    body, binding = document.loads(context._body), parse(context._binding)
    expected = {key: body['source'][key] for key in ('sha256', 'bytes')}
    key, size = document.file_digest(context._source, expected['bytes'])
    require({'sha256': key, 'bytes': size} == expected, 'complete original source changed')
    path, _record = locators.package_binding(binding, context._source, body, context._package)
    expected = {key: binding['representation'][key] for key in ('sha256', 'bytes')}
    key, size = document.file_digest(path, expected['bytes'])
    require({'sha256': key, 'bytes': size} == expected, 'complete bound representation changed')


def selected_source(context, locator_raw, held_locator_sha256, locator_registry,
                    held_locator_registry_sha256):
    require(type(context) is VerifiedDocument and context._active, 'live verified collection document required')
    bound_files_checked(context)
    revisions = context._revisions
    revision_root = digest(canonical({key: identity(raw) for key, raw in revisions.items()}))
    left, right = locators.snapshots(locator_raw, held_locator_sha256, locator_registry,
        held_locator_registry_sha256, revisions, revision_root)
    records = locators.locator_records(left, held_locator_sha256)
    binding = parse(context._binding)
    require(all(all(row[key] == binding[key] for key in ('source', 'representation', 'revision'))
                for row in records.values()), 'collection selection binding mismatch')
    result = locators._resolve_bound(context._source, document.loads(context._body), context._package,
        document.loads(context._sections), held_locator_sha256, left, right)
    result['section_references'] = [{'locator_sha256': key, 'section_id': row['selector']['section_id']}
        for key, row in records.items() if row['selector']['kind'] == 'SECTION']
    clean = dict(result, parts=[{key: value for key, value in part.items() if key != 'data'}
                               for part in result['parts']])
    require(len(canonical(clean)) <= METADATA, 'collection selection metadata bound')
    bound_files_checked(context)
    return result
