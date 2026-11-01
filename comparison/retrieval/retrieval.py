"""Bounded matched retrieval over verified bytes and pinned, untrusted annotations.

Literal search, declared dependency closure and change enclosures are mechanical.
No result establishes source truth, semantic adequacy, freshness or authority.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
try:
    import sqlite3
except ImportError:
    sqlite3 = None
import time
import types

CAP = 65536
RESPONSE_CAP = 131072
ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
PREPARE_SHA = '23119618174b44cf9fd411014c861751a87317d59a5bb333842b5fa7c356d830'


class RetrievalError(ValueError):
    """A named, fail-closed data-processing refusal; never an authority verdict."""


def _need(condition, reason='REFUSED_SCHEMA'):
    if not condition:
        raise RetrievalError(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _preparer():
    # This is fixed approved application code, never a payload-chosen program.
    path = Path(__file__).resolve().parents[2] / 'install/prepare_quorum_replay.py'
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    _need(len(raw) <= CAP and _sha(raw) == PREPARE_SHA, 'REFUSED_VERSION')
    module = types.ModuleType('_retrieval_approved_json')
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


_PREPARE = _preparer()


def _document(raw):
    _need(type(raw) is bytes, 'REFUSED_SCHEMA')
    _need(0 < len(raw) <= CAP, 'REFUSED_BOUND')
    try:
        return _PREPARE.document(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise RetrievalError('REFUSED_SCHEMA') from error


def _fields(value, fields):
    _need(type(value) is dict and set(value) == set(fields))


def _identifier(value):
    _need(type(value) is str and ID.fullmatch(value) is not None)
    return value


def _digest(value):
    _need(type(value) is str and DIGEST.fullmatch(value) is not None)
    return value


def _identifiers(values, maximum, reason, allow_empty=False):
    _need(type(values) is list, reason)
    _need(len(values) <= maximum, 'REFUSED_BOUND')
    _need(bool(values) or allow_empty, reason)
    _need(all(type(x) is str and ID.fullmatch(x) is not None for x in values), reason)
    _need(len(set(values)) == len(values), reason)
    return sorted(values)


def _text(raw):
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise RetrievalError('REFUSED_UTF8') from error


def _source_record(item, sources):
    _fields(item, ('id', 'revision', 'encoding', 'media_type', 'bytes', 'sha256', 'attributes'))
    name = _identifier(item['id'])
    _need(name in sources, 'REFUSED_SOURCE_PIN')
    _need(type(item['revision']) is str and 0 < len(item['revision'].encode()) <= 32)
    _need(item['encoding'] in ('utf-8', 'opaque'))
    _need(type(item['media_type']) is str and 0 < len(item['media_type'].encode()) <= 1024)
    _need(type(item['attributes']) is dict)
    _need(type(item['bytes']) is int and 0 <= item['bytes'] <= CAP, 'REFUSED_BOUND')
    raw = sources[name]
    _need(type(raw) is bytes, 'REFUSED_SOURCE_PIN')
    _need(len(raw) == item['bytes'] and _sha(raw) == _digest(item['sha256']), 'REFUSED_SOURCE_PIN')
    if item['encoding'] == 'utf-8':
        _text(raw)
    return name


def _unit_record(item, sources, metadata):
    _fields(item, ('id', 'source', 'span', 'sha256', 'whole_unit', 'dependencies', 'annotations'))
    name = _identifier(item['id'])
    source = _identifier(item['source'])
    _need(source in sources, 'REFUSED_ANCHOR')
    span = item['span']
    _need(type(span) is list and len(span) == 2 and all(type(x) is int for x in span), 'REFUSED_ANCHOR')
    _need(0 <= span[0] < span[1] <= len(sources[source]), 'REFUSED_ANCHOR')
    raw = sources[source][span[0]:span[1]]
    _need(_sha(raw) == _digest(item['sha256']), 'REFUSED_ANCHOR')
    _need(item['whole_unit'] is True and type(item['annotations']) is dict)
    _identifiers(item['dependencies'], 16, 'REFUSED_SCHEMA', allow_empty=True)
    if metadata[source]['encoding'] == 'utf-8':
        _text(raw)
    return name


def _inventory(sources, document):
    _fields(document, ('schema', 'sources', 'units'))
    _need(document['schema'] == 'transport/retrieval-annotations/1', 'REFUSED_VERSION')
    _need(type(sources) is dict and 1 <= len(sources) <= 16, 'REFUSED_BOUND')
    _need(all(type(v) is bytes for v in sources.values()), 'REFUSED_SOURCE_PIN')
    _need(sum(len(v) for v in sources.values()) <= CAP, 'REFUSED_BOUND')
    _need(type(document['sources']) is list and len(document['sources']) == len(sources))
    metadata = {}
    for item in document['sources']:
        name = _source_record(item, sources)
        _need(name not in metadata)
        metadata[name] = item
    _need(set(metadata) == set(sources), 'REFUSED_SOURCE_PIN')
    _need(type(document['units']) is list and len(document['units']) <= 16, 'REFUSED_BOUND')
    units, edges = {}, 0
    for item in document['units']:
        name = _unit_record(item, sources, metadata)
        _need(name not in units)
        units[name] = item
        edges += len(item['dependencies'])
    _need(edges <= 64, 'REFUSED_BOUND')
    return metadata, units


def _closure(roots, units):
    selected = set(roots)
    for unused in range(16):
        additions = set()
        for name in sorted(selected):
            _need(name in units, 'REFUSED_MISSING_DEPENDENCY')
            additions.update(units[name]['dependencies'])
        _need(all(name in units for name in additions), 'REFUSED_MISSING_DEPENDENCY')
        expanded = selected | additions
        if expanded == selected:
            break
        selected = expanded
    remaining = set(selected)
    for unused in range(16):
        leaves = {name for name in remaining if not (set(units[name]['dependencies']) & remaining)}
        remaining -= leaves
        if not remaining:
            return sorted(selected)
    _need(not remaining, 'REFUSED_DEPENDENCY_CYCLE')
    return sorted(selected)


def _difference(left, right):
    prefix = 0
    for index in range(min(len(left), len(right))):
        if left[index] != right[index]:
            break
        prefix += 1
    suffix = 0
    for index in range(min(len(left), len(right)) - prefix):
        if left[len(left) - index - 1] != right[len(right) - index - 1]:
            break
        suffix += 1
    return [prefix, len(left) - suffix], [prefix, len(right) - suffix]


def _token_run_bound(raw):
    run = 0
    for byte in raw:
        run = 0 if byte in (9, 10, 11, 12, 13, 32) else run + 1
        # Unicode61 folds to at most one scalar; allow four UTF8 bytes per input byte.
        _need(run <= 8192, 'REFUSED_FTS_TOKEN_BOUND')


class Corpus:
    """One bounded source snapshot. Only serialized data crosses the API."""

    def __init__(self, sources, annotations, expected_annotations_sha256):
        started = time.monotonic_ns()
        _digest(expected_annotations_sha256)
        _need(type(annotations) is bytes, 'REFUSED_SCHEMA')
        _need(len(annotations) <= CAP, 'REFUSED_BOUND')
        _need(_sha(annotations) == expected_annotations_sha256, 'REFUSED_ANNOTATION_PIN')
        document = _document(annotations)
        self._metadata, self._units = _inventory(sources, document)
        self._sources = dict(sources)
        pins = [{'id': name, 'bytes': len(raw), 'sha256': _sha(raw)}
                for name, raw in sorted(sources.items())]
        self._snapshot = _sha(_canonical({'annotation_sha256': expected_annotations_sha256, 'sources': pins}))
        self._count, self._closed, self._db = 0, False, None
        self._fts_rows, self._steps = [], 0
        self._cost = {'source_bytes': sum(len(x) for x in sources.values()),
                      'annotation_bytes': len(annotations), 'setup_ns': time.monotonic_ns() - started,
                      'query_ns': 0, 'processed_calls': 0, 'index_setup_ns': 0, 'index_bytes': 0}

    def metrics(self):
        return dict(self._cost)

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
        self._sources.clear()
        self._units.clear()
        self._metadata.clear()
        self._fts_rows.clear()
        self._closed = True

    def _envelope(self, result, status):
        value = {'schema': 'transport/matched-retrieval-response/1', 'snapshot': self._snapshot,
                 'call': self._count, 'status': status, 'authority': 'NONE', 'freshness': 'UNKNOWN',
                 'context_adequacy': 'UNPROVEN', 'data_is_untrusted': True, 'result': result}
        raw = _canonical(value) + b'\n'
        _need(len(raw) <= RESPONSE_CAP, 'REFUSED_OUTPUT_BOUND')
        return raw

    def call(self, raw):
        started = time.monotonic_ns()
        self._count = min(self._count + 1, 33)
        try:
            _need(not self._closed, 'REFUSED_CLOSED')
            _need(self._count <= 32, 'REFUSED_CALL_BOUND')
            request = _document(raw)
            result = self._dispatch(request)
            return self._envelope(result, 'OK')
        except RetrievalError as error:
            return self._envelope({'reason': str(error)}, 'REFUSED')
        finally:
            self._cost['query_ns'] = min(9223372036854775807,
                                         self._cost['query_ns'] + time.monotonic_ns() - started)
            self._cost['processed_calls'] = self._count

    def _dispatch(self, request):
        _need(type(request) is dict and type(request.get('action')) is str)
        action = request['action']
        if action == 'catalog':
            _fields(request, ('action',))
            return self._catalog()
        if action in ('search', 'query'):
            return self._search(request, action)
        if action == 'expand':
            _fields(request, ('action', 'units'))
            roots = _identifiers(request['units'], 16, 'REFUSED_QUERY')
            _need(all(x in self._units for x in roots), 'REFUSED_QUERY')
            scope = sorted({self._units[x]['source'] for x in roots})
            return self._expanded(roots, scope, [], [])
        if action == 'page':
            _fields(request, ('action', 'source', 'offset'))
            return self._page(request)
        if action == 'trace':
            _fields(request, ('action', 'source'))
            return self._trace(self._source_id(request['source']))
        raise RetrievalError('REFUSED_SCHEMA')

    def _catalog(self):
        missing = {d for u in self._units.values() for d in u['dependencies'] if d not in self._units}
        return {'sources': [self._metadata[x] for x in sorted(self._metadata)],
                'units': [self._units[x] for x in sorted(self._units)],
                'unresolved_dependency_ids': sorted(missing),
                'source_coverage': 'ALL_HELD_ORIGINAL_BYTES', 'interpretation_validation': 'NOT_PERFORMED'}

    def _source_id(self, value):
        _need(type(value) is str and value in self._sources, 'REFUSED_SOURCE_SCOPE')
        return value

    def _search_arguments(self, request, action):
        fields = ('action', 'query', 'mode', 'sources', 'field')
        _fields(request, fields + (('offset', 'limit') if action == 'search' else ()))
        query = request['query']
        _need(type(query) is str, 'REFUSED_QUERY')
        encoded = query.encode('utf-8', errors='strict')
        _need(bool(encoded), 'REFUSED_QUERY')
        _need(len(encoded) <= 256, 'REFUSED_BOUND')
        _need(request['mode'] in ('exact_phrase', 'all_tokens', 'fts5'), 'REFUSED_QUERY')
        _need(request['field'] in ('source', 'annotation', 'both'), 'REFUSED_QUERY')
        scope = _identifiers(request['sources'], 16, 'REFUSED_SOURCE_SCOPE')
        _need(all(x in self._sources for x in scope), 'REFUSED_SOURCE_SCOPE')
        if action == 'search':
            _need(type(request['offset']) is int and 0 <= request['offset'] <= 16, 'REFUSED_BOUND')
            _need(type(request['limit']) is int and 1 <= request['limit'] <= 16, 'REFUSED_BOUND')
        tokens = [x for x in encoded.split(b' ') if x]
        if request['mode'] == 'all_tokens':
            _need(bool(tokens), 'REFUSED_QUERY')
            _need(len(tokens) <= 32, 'REFUSED_BOUND')
        return scope, encoded, tokens

    def _literal(self, raw, encoded, tokens, mode):
        if mode == 'exact_phrase':
            return encoded in raw
        return all(token in raw for token in tokens)

    def _rows(self):
        rows = []
        for name in sorted(self._metadata):
            item = self._metadata[name]
            if item['encoding'] == 'utf-8':
                rows.append((name, None, 'source', self._sources[name]))
            rows.append((name, None, 'annotation', _canonical(item['attributes'])))
        for name in sorted(self._units):
            item = self._units[name]
            if self._metadata[item['source']]['encoding'] == 'utf-8':
                begin, end = item['span']
                rows.append((item['source'], name, 'source', self._sources[item['source']][begin:end]))
            rows.append((item['source'], name, 'annotation', _canonical(item['annotations'])))
        return sorted(rows, key=lambda row: (row[0], row[1] or '', row[2]))

    def _matches(self, request, scope, encoded, tokens):
        rows = self._rows()
        if request['mode'] == 'fts5':
            indices = self._fts_matches(rows, encoded)
        else:
            indices = [i for i, row in enumerate(rows)
                       if self._literal(row[3], encoded, tokens, request['mode'])]
        units, whole, order = {}, {}, []
        for index in indices:
            source, unit, origin, unused = rows[index]
            if source not in scope or request['field'] not in (origin, 'both'):
                continue
            if unit is None:
                whole.setdefault(source, set()).add(origin)
            else:
                if unit not in units:
                    order.append(unit)
                units.setdefault(unit, set()).add(origin)
        if request['mode'] != 'fts5':
            order.sort()
        matches = [{key: self._units[name][key] for key in ('id', 'source', 'span', 'sha256')}
                   | {'origins': sorted(units[name])} for name in order]
        sources = [{'source': name, 'origins': sorted(whole[name])} for name in sorted(whole)]
        return matches, sources

    def _search(self, request, action):
        scope, encoded, tokens = self._search_arguments(request, action)
        matches, whole = self._matches(request, scope, encoded, tokens)
        opaque = [x for x in scope if self._metadata[x]['encoding'] == 'opaque']
        if action == 'query':
            return self._expanded(sorted(x['id'] for x in matches), scope, whole, opaque)
        begin, limit = request['offset'], request['limit']
        end = min(begin + limit, len(matches))
        outcome = 'MATCHES' if matches or whole else ('UNKNOWN_NON_TEXT' if opaque == scope else 'UNKNOWN_NO_MATCH')
        return {'outcome': outcome, 'unit_matches': matches[begin:end],
                'total_unit_matches': len(matches), 'offset': begin,
                'next_offset': end if end < len(matches) else None,
                'whole_source_matches': whole, 'opaque_sources': opaque, 'source_scope': scope,
                'ranking': 'SQLITE_FTS5_BM25' if request['mode'] == 'fts5' else 'LITERAL_ID_ORDER'}

    def _expanded(self, roots, scope, whole, opaque):
        selected = _closure(roots, self._units)
        source_ids = {self._units[x]['source'] for x in selected}
        payload = []
        for name in selected:
            item = self._units[name]
            begin, end = item['span']
            raw = self._sources[item['source']][begin:end]
            payload.append(dict(item, bytes_base64=base64.b64encode(raw).decode('ascii')))
        if roots:
            outcome = 'EXPAND_COMPLETE'
        elif whole:
            outcome = 'SOURCE_MATCH_NO_DECLARED_UNIT'
        else:
            outcome = 'UNKNOWN_NON_TEXT' if opaque and opaque == scope else 'UNKNOWN_NO_MATCH'
        return {'outcome': outcome, 'root_units': roots, 'unit_ids': selected, 'units': payload,
                'sources': [self._metadata[x] for x in sorted(source_ids | {x['source'] for x in whole})],
                'context_sources': sorted(source_ids - set(scope)), 'whole_source_matches': whole,
                'opaque_sources': opaque, 'source_scope': scope,
                'dependency_closure': 'ALL_REACHABLE_DECLARED_EDGES', 'unit_adequacy': 'DECLARED_NOT_PROVEN'}

    def _page(self, request):
        name = self._source_id(request['source'])
        begin = request['offset']
        _need(type(begin) is int)
        _need(0 <= begin <= len(self._sources[name]), 'REFUSED_QUERY')
        raw = self._sources[name][begin:begin + 4096]
        try:
            text = _text(raw) if self._metadata[name]['encoding'] == 'utf-8' else None
        except RetrievalError:
            text = None
        return {'source': name, 'source_bytes': len(self._sources[name]),
                'source_sha256': _sha(self._sources[name]), 'span': [begin, begin + len(raw)],
                'bytes': len(raw), 'sha256': _sha(raw), 'bytes_base64': base64.b64encode(raw).decode('ascii'),
                'utf8': text, 'end': begin + len(raw) == len(self._sources[name]),
                'units': [self._units[x] for x in sorted(self._units) if self._units[x]['source'] == name],
                'annotation_scope': 'ALL_UNITS_BELONGING_TO_SOURCE', 'coverage': 'RETURNED_BYTE_SPAN_ONLY'}

    def _dependency_keys(self, item):
        result = []
        for name in sorted(item['dependencies']):
            if name not in self._units:
                result.append({'unit': name, 'missing': True})
            else:
                source = self._units[name]['source']
                result.append({'unit': name, 'source': source, 'revision': self._metadata[source]['revision'],
                               'sha256': self._metadata[source]['sha256']})
        return result

    def _trace(self, name):
        family = self._metadata[name]['attributes'].get('family_id')
        family = family if type(family) is str and family else None
        versions = [x for x in sorted(self._metadata) if x == name or
                    (family is not None and self._metadata[x]['attributes'].get('family_id') == family)]
        comparisons, bindings = [], []
        for other in versions:
            if other == name:
                continue
            left, right = _difference(self._sources[name], self._sources[other])
            comparisons.append({'from': name, 'to': other, 'bytes_equal': self._sources[name] == self._sources[other],
                                'from_span': left, 'to_span': right, 'scope': 'ONE_CONSERVATIVE_REPLACEMENT_ENCLOSURE'})
            for a in sorted(self._units):
                if self._units[a]['source'] != name:
                    continue
                for b in sorted(self._units):
                    if self._units[b]['source'] == other and self._units[a]['sha256'] == self._units[b]['sha256']:
                        bindings.append({'left': a, 'right': b, 'quote_unchanged': True,
                            'dependency_ids_changed': sorted(self._units[a]['dependencies']) != sorted(self._units[b]['dependencies']),
                            'dependency_source_keys_changed': self._dependency_keys(self._units[a]) != self._dependency_keys(self._units[b])})
        return {'source': name, 'family': family, 'versions': [self._metadata[x] for x in versions],
                'comparisons': comparisons, 'unit_bindings': sorted(bindings, key=lambda x: (x['left'], x['right'])),
                'version_labels': 'DECLARED_NOT_AUTHENTICATED', 'governing_version': 'UNKNOWN'}

    def _progress(self):
        self._steps += 1
        return int(self._steps > 10000)

    def _build_index(self, rows):
        started = time.monotonic_ns()
        for row in rows:
            _token_run_bound(row[3])
        _need(sqlite3 is not None, 'REFUSED_FTS_UNAVAILABLE')
        database = sqlite3.connect(':memory:')
        try:
            _need(hasattr(database, 'enable_load_extension') and hasattr(database, 'serialize'),
                  'REFUSED_FTS_UNAVAILABLE')
            database.enable_load_extension(False)
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8388608)
            database.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 16)
            database.set_progress_handler(self._progress, 100)
            database.execute('PRAGMA page_size=4096')
            database.execute('PRAGMA max_page_count=2048')
            database.execute('PRAGMA temp_store=MEMORY')
            database.execute('PRAGMA trusted_schema=OFF')
            database.execute("CREATE VIRTUAL TABLE documents USING fts5(text,tokenize='unicode61 remove_diacritics 0')")
            database.executemany('INSERT INTO documents(rowid,text) VALUES(?,?)',
                                 [(i + 1, _text(row[3])) for i, row in enumerate(rows)])
            database.execute("CREATE VIRTUAL TABLE query_tokens USING fts5(text,tokenize='unicode61 remove_diacritics 0')")
            database.execute("CREATE VIRTUAL TABLE query_vocab USING fts5vocab(query_tokens,'row')")
            size = len(database.serialize())
            _need(size <= 8388608, 'REFUSED_BOUND')
            self._db, self._fts_rows = database, rows
            self._cost['index_bytes'] = size
        except BaseException:
            database.close()
            raise
        finally:
            self._cost['index_setup_ns'] += time.monotonic_ns() - started

    def _fts_matches(self, rows, query):
        _need(sqlite3 is not None, 'REFUSED_FTS_UNAVAILABLE')
        self._steps = 0
        try:
            if self._db is None:
                self._build_index(rows)
            self._db.execute('DELETE FROM query_tokens')
            self._db.execute('INSERT INTO query_tokens(text) VALUES(?)', (_text(query),))
            vocab = list(self._db.execute('SELECT term,cnt FROM query_vocab ORDER BY term LIMIT 33'))
            _need(bool(vocab), 'REFUSED_QUERY')
            _need(sum(row[1] for row in vocab) <= 32, 'REFUSED_FTS_TOKEN_BOUND')
            terms = [row[0] for row in vocab]
            expression = ' AND '.join('"' + term.replace('"', '""') + '"' for term in terms)
            found = self._db.execute('SELECT rowid FROM documents WHERE documents MATCH ? ORDER BY bm25(documents),rowid',
                                     (expression,)).fetchmany(65)
            _need(len(found) <= 64, 'REFUSED_BOUND')
            return [row[0] - 1 for row in found]
        except sqlite3.Error as error:
            reason = 'REFUSED_FTS_WORK_BOUND' if self._steps > 10000 else 'REFUSED_SEARCH_ENGINE'
            if 'no such module' in str(error):
                reason = 'REFUSED_FTS_UNAVAILABLE'
            if self._db is not None:
                self._db.close()
                self._db = None
            raise RetrievalError(reason) from error
