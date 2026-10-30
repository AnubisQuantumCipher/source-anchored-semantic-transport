"""Declared derived reading views. These never replace original source bytes."""
import sys
import codecs
from transport_document_io import (FRAME_SOURCE, MAX_META, canonical, fields, integer,
                                   loaded_epoch, need, open_regular, read_file, sha)

MAX_READING = 33_554_432
MAX_READING_FRAMES = 512
MAX_SEGMENTS = 65_536
EMPTY = {'schema': 'transport/reading-view/1', 'status': 'NOT_REQUESTED',
         'uncertainty': ['Only original source bytes are carried; no reading extraction requested.']}


def bounded_text(value, limit):
    need(type(value) is str and len(value.encode('utf-8')) <= limit, 'reading text metadata bound')


def segment_checked(item, previous, size):
    fields(item, ('id', 'label', 'start', 'end', 'kind', 'source_locator'))
    bounded_text(item['id'], 64); bounded_text(item['label'], 1024)
    integer(item['start'], 0, size); integer(item['end'], item['start'], size)
    need(item['start'] == previous, 'reading page/section partition gap or overlap')
    need(item['kind'] in ('page', 'epub-spine', 'heading', 'line'), 'unsupported reading segment')
    locator = item['source_locator']
    need(type(locator) is dict and len(canonical(locator)) <= 4096, 'reading source locator bound')
    if item['kind'] == 'page':
        fields(locator, ('page',)); integer(locator['page'], 1, 16_384)
    elif item['kind'] == 'epub-spine':
        fields(locator, ('path', 'idref'))
        bounded_text(locator['path'], 1024); bounded_text(locator['idref'], 1024)
    else:
        fields(locator, ('line', 'source_start', 'source_end'))
        integer(locator['line'], 1, MAX_SEGMENTS)
        integer(locator['source_start'], 0, size)
        integer(locator['source_end'], locator['source_start'], size)
        need((locator['source_start'], locator['source_end']) == (item['start'], item['end']),
             'text reading/source byte locator mismatch')
    return item['end']


def record_checked(record, source_hash):
    fields(record, ('schema', 'format', 'tool_versions', 'source_sha256', 'text_sha256',
                    'text_bytes', 'segments', 'uncertainty', 'coverage', 'text_path'))
    need(record['schema'] == 'transport/reading-view/1' and record['format'] in
         ('pdf', 'epub', 'markdown', 'text') and record['text_path'] == 'reading.txt', 'reading version or format')
    sha(record['source_sha256']); sha(record['text_sha256'])
    need(record['source_sha256'] == source_hash, 'reading view belongs to a different source')
    integer(record['text_bytes'], 0, MAX_READING)
    need(type(record['segments']) is list and len(record['segments']) <= MAX_SEGMENTS,
         'reading segment count')
    end, ids = 0, set()
    for segment in record['segments']:
        end = segment_checked(segment, end, record['text_bytes'])
        need(segment['id'] not in ids, 'duplicate reading segment id')
        ids.add(segment['id'])
    need(end == record['text_bytes'], 'reading partition incomplete')
    need(type(record['tool_versions']) is dict and len(record['tool_versions']) <= 8, 'reading tool count')
    for key, value in record['tool_versions'].items():
        bounded_text(key, 128); bounded_text(value, 1024)
    need(type(record['uncertainty']) is list and 1 <= len(record['uncertainty']) <= 64,
         'reading uncertainty must remain explicit')
    for value in record['uncertainty']:
        bounded_text(value, 2048)
    need(type(record['coverage']) is dict and len(canonical(record['coverage'])) <= MAX_META,
         'reading coverage metadata')
    if record['format'] in ('markdown', 'text'):
        need(record['text_sha256'] == source_hash, 'text reading must preserve original bytes')
    return record


def supplied(view, source_hash):
    if view is None:
        return None, EMPTY
    need(type(view) is dict and 'text_path' in view and 'reading_json_path' in view,
         'reading extraction artifacts required')
    from transport_document_io import loads
    record = record_checked(loads(read_file(view['reading_json_path'])), source_hash)
    return view['text_path'], record



def utf8_checked(path, record):
    try:
        with open_regular(path, MAX_READING) as stream:
            for segment in record['segments']:
                remaining = segment['end'] - segment['start']
                decoder = codecs.getincrementaldecoder('utf-8')('strict')
                for _ in range(MAX_READING_FRAMES + 1):
                    if remaining == 0:
                        break
                    data = stream.read(min(remaining, FRAME_SOURCE))
                    need(bool(data), 'reading UTF-8 input truncated')
                    decoder.decode(data, final=False)
                    remaining -= len(data)
                need(remaining == 0, 'reading UTF-8 traversal limit')
                decoder.decode(b'', final=True)
            need(stream.read(1) == b'', 'reading UTF-8 partition incomplete')
    except UnicodeError as error:
        from transport_document_io import DocumentError
        raise DocumentError('reading UTF-8 or segment boundary is invalid') from error


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
