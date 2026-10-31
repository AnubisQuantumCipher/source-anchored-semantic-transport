#!/usr/bin/env python3
"""Package and evaluate the closed semantic core using explicitly pinned local tools."""
import argparse
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'install'))
import transport_core as core
import transport_core_bridge as bridge
from transport_core_language import parse_fragment
from transport_schema import canonical, require
from transport_install_support import read_regular, write_new
from transport_core_process import limit


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    draft = commands.add_parser('draft')
    draft.add_argument('--source', type=Path, required=True)
    draft.add_argument('--output', type=Path, required=True)
    for action in ('encode', 'evaluate'):
        command = commands.add_parser(action)
        command.add_argument('--decoder', type=Path, required=True)
        command.add_argument('--decoder-sha256', required=True)
        command.add_argument('--native', type=Path, required=True)
        command.add_argument('--native-sha256', required=True)
        command.add_argument('--work', type=Path, required=True)
        if action == 'encode':
            command.add_argument('--source', type=Path, required=True)
            command.add_argument('--plan', type=Path, required=True)
            command.add_argument('--model', type=Path)
            command.add_argument('--budget', type=int, default=512)
            command.add_argument('--reference', default='attached:meaning.zip')
        else:
            command.add_argument('--share', type=Path, required=True)
            command.add_argument('--archive', type=Path, required=True)
    return parser.parse_args()


def draft(args):
    source = read_regular(args.source, 65536)
    result = parse_fragment(source)
    require(result['status'] == 'IN_FRAGMENT', 'NOT_IN_FRAGMENT: preserve as a declared documentary reading')
    value = {'schema': core.PLAN, 'symbols': result['symbols'], 'tree': result['tree'],
             'translation': 'requirement'}
    raw = canonical(value)
    core.plan(raw, source)
    write_new(args.output, raw, 65536)
    return {'status': 'CONTROLLED_PLAN_WRITTEN', 'source_sha256': result['source_sha256'],
            'model': 'NOT_SUPPLIED', 'evaluation': 'NOT_EVALUATED', 'execution_authority': 'NONE'}


def run(args):
    if args.action == 'draft':
        return draft(args)
    for path in (args.decoder, args.native):
        require(path.is_absolute(), 'CORE_EXPLICIT_ABSOLUTE_TOOL_REQUIRED')
    root = bridge.workspace(args.work)
    common = (args.decoder, args.decoder_sha256, args.native, args.native_sha256, root)
    if args.action == 'encode':
        source, plan = read_regular(args.source, 65536), read_regular(args.plan, 65536)
        model = None if args.model is None else read_regular(args.model, 65536)
        return bridge.encode(source, plan, model, *common, args.budget, args.reference)
    return bridge.decode(args.share.absolute(), args.archive.absolute(), *common)


def main():
    try:
        limit(resource.RLIMIT_AS, 536870912)
        limit(resource.RLIMIT_CPU, 120)
        limit(resource.RLIMIT_FSIZE, 4194304)
        result = run(arguments())
        raw = canonical(result) + b'\n'
        require(len(raw) <= 131072, 'CORE_RESULT_BOUND')
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, MemoryError) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
