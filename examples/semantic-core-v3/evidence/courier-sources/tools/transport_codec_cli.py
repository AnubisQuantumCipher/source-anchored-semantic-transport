#!/usr/bin/env python3
"""Local tool adapter for the single Source-Anchored Semantic Transport knowledge-codec API. No network or AI."""

import argparse
import json
import resource
import subprocess
import sys
from pathlib import Path

from transport_codec import decode, encode, export_dictionary, inspect, validate
from transport_schema import canonical, require, sha
from transport_wire import MAX_SOURCE, MAX_WIRE, read_bounded, write_new


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('encode', 'validate', 'decode', 'inspect'):
        command = commands.add_parser(action)
        command.add_argument('input', type=Path)
        command.add_argument('output', type=Path)
        command.add_argument('--dictionary', action='append', type=Path, default=[])
        if action == 'encode':
            command.add_argument('--plan', type=Path)
            command.add_argument('--profile', choices=('self-contained', 'shared'), default='self-contained')
        else:
            command.add_argument('--expected-sha256')
            if action == 'inspect':
                command.add_argument('--export-dictionary', choices=('operators', 'symbols'))
            if action != 'inspect':
                command.add_argument('--canonical', type=Path)
            if action == 'decode':
                views = command.add_mutually_exclusive_group()
                views.add_argument('--source-only', action='store_true')
                views.add_argument('--meaning-only', action='store_true')
    return parser.parse_args()


def encode_file(args: argparse.Namespace) -> bytes:
    require(len(args.dictionary) == (2 if args.profile == 'shared' else 0),
            'shared encoding requires both previously exported dictionaries')
    source = read_bounded(args.input, MAX_SOURCE)
    plan = read_bounded(args.plan, MAX_SOURCE) if args.plan else None
    result = encode(source, plan, args.profile)
    supplied = tuple(read_bounded(path, MAX_SOURCE) for path in args.dictionary)
    if args.profile == 'shared':
        validate(result.package, supplied, canonical_source=source)
    return result.package


def read_package(args: argparse.Namespace) -> bytes:
    require(len(args.dictionary) <= 2, 'dependency input budget exceeded')
    package = read_bounded(args.input, MAX_WIRE)
    dependencies = tuple(read_bounded(path, MAX_SOURCE) for path in args.dictionary)
    if args.action == 'inspect':
        if args.export_dictionary:
            require(args.expected_sha256 is None, 'dictionary export uses the checked package identity, not an ignored expectation')
            return export_dictionary(package, args.export_dictionary, dependencies)
        return canonical(inspect(package, dependencies, args.expected_sha256))
    source = read_bounded(args.canonical, MAX_SOURCE) if args.canonical else None
    if args.action == 'validate':
        return canonical(validate(package, dependencies, args.expected_sha256, source))
    result = decode(package, dependencies, args.expected_sha256, source, args.source_only, args.meaning_only)
    return result if args.source_only else canonical(result)


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (268_435_456, 268_435_456))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    args = arguments()
    try:
        output = encode_file(args) if args.action == 'encode' else read_package(args)
        warning = write_new(args.output, output)
        print(json.dumps({'status': 'PUBLISHED_WITH_CLEANUP_WARNING' if warning else 'PUBLISHED',
                          'output_sha256': sha(output), 'cleanup_warning': warning,
                          'semantic_completeness': 'UNPROVEN'}))
        return 0
    except (ValueError, OSError, MemoryError, subprocess.TimeoutExpired) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
