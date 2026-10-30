"""Local bounded work-record validation; inputs remain untrusted data."""
import argparse
import json
import os
from pathlib import Path
import resource
import stat
import sys
import types

sys.dont_write_bytecode = True


def core():
    path = Path(__file__).resolve().with_name('accounting.py')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if not 0 < len(raw) <= 65536:
        raise ValueError('core source bound')
    module = types.ModuleType('_accounting_core')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


A = None


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise A.Refusal('SCHEMA_INVALID')


def limits():
    for kind, cap in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                      (resource.RLIMIT_FSIZE, 131072), (resource.RLIMIT_NOFILE, 64)):
        soft, hard = resource.getrlimit(kind)
        next_hard = cap if hard == resource.RLIM_INFINITY else min(hard, cap)
        next_soft = next_hard if soft == resource.RLIM_INFINITY else min(soft, next_hard)
        resource.setrlimit(kind, (next_soft, next_hard))


def arguments(argv):
    A.need(len(argv) <= 16 and all(len(s.encode('utf-8')) <= 4096 for s in argv),
           'INPUT_BOUND')
    parser = Parser(description=__doc__)
    parser.add_argument('--request', required=True)
    parser.add_argument('--expect-plan-sha256', required=True)
    parser.add_argument('--expect-ledger-sha256', required=True)
    return parser.parse_args(argv)


def read(path, cap=65536):
    A.need(type(path) is str and path.startswith('/') and '\x00' not in path
           and len(path.encode('utf-8')) <= 4096, 'CLI_IO')
    parts = path.split('/')[1:]
    A.need(0 < len(parts) <= 256 and all(p not in ('', '.', '..') for p in parts), 'CLI_IO')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=descriptor)
    finally:
        os.close(descriptor)
    try:
        before = os.fstat(leaf)
        A.need(stat.S_ISREG(before.st_mode), 'CLI_IO')
        A.need(0 < before.st_size <= cap, 'INPUT_BOUND')
        with os.fdopen(leaf, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(leaf)
        names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        A.need(all(getattr(before, k) == getattr(after, k) for k in names)
               and len(raw) == before.st_size, 'CLI_IO')
        return raw
    finally:
        os.close(leaf)


def bound_input(row, mismatch='PIN_MISMATCH'):
    A.fields(row, ('path', 'bytes', 'sha256'))
    A.integer(row['bytes'], A.MAX_INT, 1)
    A.need(row['bytes'] <= 65536, 'INPUT_BOUND')
    A.digest(row['sha256'])
    raw = read(row['path'])
    A.need(len(raw) == row['bytes'] and A.sha(raw) == row['sha256'], mismatch)
    return raw


def request(args):
    value = A.document(read(args.request))
    A.fields(value, ('schema', 'plan', 'ledger', 'artifacts'))
    A.need(value['schema'] == 'transport/accounting-request/1', 'SCHEMA_INVALID')
    A.array(value['artifacts'], 32)
    bindings, descriptors = {}, {}
    for row in value['artifacts']:
        A.fields(row, ('id', 'path', 'bytes', 'sha256'))
        A.identifier(row['id'])
        A.need(row['id'] not in descriptors, 'BINDING_MISMATCH')
        descriptors[row['id']] = {k: row[k] for k in ('path', 'bytes', 'sha256')}
    plan, ledger = bound_input(value['plan']), bound_input(value['ledger'])
    A.need(value['plan']['sha256'] == args.expect_plan_sha256
           and value['ledger']['sha256'] == args.expect_ledger_sha256, 'PIN_MISMATCH')
    for name, descriptor in descriptors.items():
        bindings[name] = bound_input(descriptor, 'ARTIFACT_PIN')
    return A.validate(plan, args.expect_plan_sha256, ledger,
                      args.expect_ledger_sha256, bindings)


def main(argv=None):
    global A
    A = None
    try:
        limits()
        A = core()
        result = request(arguments(sys.argv[1:] if argv is None else argv))
    except (OSError, ValueError, UnicodeError, MemoryError, SyntaxError) as error:
        reason = str(error) if A is not None and isinstance(error, A.Refusal) else 'CLI_IO'
        if A is None and str(error) == 'PIN_MISMATCH':
            reason = 'PIN_MISMATCH'
        result = dict(schema='transport/accounting-completeness-refusal/1',
                      status='REFUSED', reason=reason, authority='NONE')
    raw = json.dumps(result, ensure_ascii=True, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    if len(raw) > 131072:
        result = dict(schema='transport/accounting-completeness-refusal/1',
                      status='REFUSED', reason='OUTPUT_BOUND', authority='NONE')
        raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'
    try:
        written = sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    except (OSError, ValueError):
        return 1
    return 1 if written != len(raw) or result['status'] == 'REFUSED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
