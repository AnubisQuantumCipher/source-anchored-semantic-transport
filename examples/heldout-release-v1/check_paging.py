#!/usr/bin/env python3
"""Qualify full focus pagination in a separate session, without a model."""
import argparse
import base64
import json
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT / 'install'))
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new


def request(args, output, value, index):
    argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(args.receiver / 'helpers/transport_handoff_reader.py'),
            '--manifest', str(args.receiver / 'manifest.json'), '--expect-manifest-sha256', args.manifest_sha256,
            '--session', str(output / 'session'), '--request-json', canonical(value).decode('utf-8')]
    result = run_bounded(argv, output, dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'), timeout=35, cap=8192)
    for stream in ('stdout', 'stderr'):
        write_new(output / ('call-%02d.%s' % (index, stream)), result[stream], 8192)
    receipt = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    write_new(output / ('call-%02d.json' % index), canonical(receipt))
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and result['stderr'] == b'',
            'page process refused or output bound exceeded')
    value = json.loads(result['stdout'])
    require(value['status'] == 'OK', 'reader refused; partial evidence retained')
    return value['result']


def collect(args, output, expected):
    request(args, output, dict(action='describe'), 0)
    chunks, offset, held = [], 0, None
    for number in range(1, 32):
        page = request(args, output, dict(action='focus_page', unit=args.unit, offset=offset), number)
        identity = {key: page[key] for key in ('unit', 'package_identity', 'total_bytes', 'sha256')}
        require(held is None or identity == held, 'page sequence identity changed')
        held = identity
        chunk = base64.b64decode(page['bytes_base64'], validate=True)
        require(page['offset'] == offset and len(chunk) == page['bytes'] <= 4096
                and sha(chunk) == page['page_sha256'], 'page byte identity mismatch')
        chunks.append(chunk)
        offset += len(chunk)
        require(offset <= 131072, 'reassembly byte bound')
        if page['next_offset'] is None:
            raw = b''.join(chunks)
            require(page['end'] is True and offset == held['total_bytes'] and sha(raw) == held['sha256'],
                    'complete focus byte identity mismatch')
            require(raw == expected and canonical(json.loads(raw)) == raw, 'focus differs from full reference')
            return dict(status='EXACT_FOCUS_REASSEMBLY', pages=number, bytes=len(raw), sha256=sha(raw),
                        package_identity=held['package_identity'], semantic_completeness='UNPROVEN')
        require(page['end'] is False and page['next_offset'] == offset and len(chunk) > 0,
                'page continuity or progress mismatch')
    raise ValueError('complete focus cannot fit remaining unchanged call budget')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--focus-reference', required=True, type=Path)
    parser.add_argument('--focus-sha256', required=True)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (536870912, 1073741824))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
    expected_file = read_regular(args.focus_reference, 131072)
    require(sha(expected_file) == args.focus_sha256, 'held reference mismatch')
    expected = canonical(json.loads(expected_file))
    require(sha(read_regular(args.receiver / 'manifest.json')) == args.manifest_sha256, 'held manifest mismatch')
    require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent,
            'canonical output parent required')
    require(not args.output.is_relative_to(args.receiver) and not args.receiver.is_relative_to(args.output),
            'output overlaps receiver')
    args.output.mkdir(mode=0o700)
    result = collect(args, args.output, expected)
    require(read_regular(args.focus_reference, 131072) == expected_file, 'reference changed')
    require(sha(read_regular(args.receiver / 'manifest.json')) == args.manifest_sha256, 'manifest changed')
    write_new(args.output / 'receipt.json', canonical(result))
    print(canonical(result).decode('utf-8'))


if __name__ == '__main__':
    main()
