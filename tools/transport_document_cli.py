#!/usr/bin/env python3
"""Local document interface. Data packages never grant execution authority."""
import argparse
import json
import subprocess
import resource
import signal
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from transport_document import (decode_document, decode_reading, encode_document, inspect_document,
                                list_reading_segments, read_reading_segment, read_section, read_span, scratch_root)
from transport_document_io import DocumentError, MAX_META, loads, read_file, write_new


def parser():
    result = argparse.ArgumentParser(description='Source-Anchored Semantic Transport: large documents')
    sub = result.add_subparsers(dest='command', required=True)
    encode = sub.add_parser('encode', help='emit share.txt + meaning.zip + readable lexicon')
    encode.add_argument('source', type=Path)
    encode.add_argument('--out', type=Path, required=True)
    encode.add_argument('--title', required=True)
    encode.add_argument('--reference', default='meaning.zip')
    encode.add_argument('--budget', type=int)
    encode.add_argument('--sections', type=Path, help='JSON array of globally anchored sections')
    encode.add_argument('--native', type=Path)
    encode.add_argument('--opaque', action='store_true', help='carry original bytes without a derived reading')
    encode.add_argument('--reading-json', type=Path, help='explicit existing extraction reading.json; source binding is verified')
    for name in ('inspect', 'decode', 'span', 'section', 'reading', 'reading-segment', 'reading-index'):
        item = sub.add_parser(name)
        item.add_argument('--archive', type=Path, required=True)
        item.add_argument('--share', type=Path, required=True)
        item.add_argument('--native', type=Path)
        if name not in ('inspect', 'reading-index'):
            item.add_argument('--out', type=Path, required=True)
        if name == 'span':
            item.add_argument('--start', type=int, required=True)
            item.add_argument('--end', type=int, required=True)
        if name in ('section', 'reading-segment'):
            item.add_argument('--id', required=True)
        if name == 'reading-index':
            item.add_argument('--start', type=int, default=0)
            item.add_argument('--count', type=int, default=32)
    return result


def encode_command(args):
    sections = loads(read_file(args.sections, MAX_META)) if args.sections else ()
    if args.reading_json:
        record = loads(read_file(args.reading_json))
        reading = dict(record, text_path=args.reading_json.parent / 'reading.txt',
                       reading_json_path=args.reading_json)
        return encode_document(args.source, args.out, args.title, args.reference,
                               args.budget, sections, args.native, reading)
    if args.opaque or args.source.suffix.lower() not in ('.pdf', '.epub', '.md', '.txt'):
        return encode_document(args.source, args.out, args.title, args.reference,
                               args.budget, sections, args.native)
    try:
        from transport_document_media import extract_reading
    except ImportError as error:
        raise DocumentError('declared extraction dependency missing; use --opaque for exact bytes only') from error
    with tempfile.TemporaryDirectory(prefix='document-extract-', dir=scratch_root()) as folder:
        reading = extract_reading(args.source, Path(folder) / 'view')
        return encode_document(args.source, args.out, args.title, args.reference,
                               args.budget, sections, args.native, reading)


def timeout_handler(_signum, _frame):
    raise DocumentError('document command wall-time bound exceeded')


def cli_limits():
    for key, requested in ((resource.RLIMIT_AS, 1_073_741_824),
                           (resource.RLIMIT_FSIZE, 2_147_483_648),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
        current, hard = resource.getrlimit(key)
        bound = min([requested] + [v for v in (current, hard) if v != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(450)


def main():
    args = parser().parse_args()
    try:
        cli_limits()
        if args.command == 'encode':
            value = encode_command(args)
        elif args.command == 'inspect':
            value = inspect_document(args.archive, args.share, args.native)
        elif args.command == 'reading-index':
            value = list_reading_segments(args.archive, args.share, args.start, args.count, args.native)
        elif args.command == 'reading':
            value = decode_reading(args.archive, args.share, args.out, args.native)
        elif args.command == 'reading-segment':
            value = read_reading_segment(args.archive, args.share, args.id, args.native)
            data = value.pop('data')
            write_new(args.out, data)
            value['selected_bytes'] = len(data)
        elif args.command == 'decode':
            value = decode_document(args.archive, args.share, args.out, args.native)
        else:
            if args.command == 'span':
                data = read_span(args.archive, args.share, args.start, args.end, args.native)
            else:
                data = read_section(args.archive, args.share, args.id, args.native)
            write_new(args.out, data)
            value = {'status': 'CHECKED', 'selected_bytes': len(data),
                     'scope': 'Recovered bytes; no narrative or current action authority'}
        print(json.dumps(value, ensure_ascii=True, sort_keys=True))
        return 0
    except (DocumentError, OSError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
        print('DOCUMENT_REFUSED: ' + str(error)[:512], file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
