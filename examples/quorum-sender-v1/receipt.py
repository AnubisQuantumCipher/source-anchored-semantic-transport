"""Derive/check this checkpoint's source and retained observation identities.

This checks a receipt, not a new native installation or an empirical claim.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCES = ('install/prepare_quorum_sender.py', 'install/test_quorum_sender.py',
    'install/prepare_quorum_replay.py', 'install/transport_public_share.py',
    'install/transport_quorum_bootstrap.py', 'install/SOURCE.json',
    'docs/QUORUM_SENDER.md', '.github/workflows/quorum-sender.yml',
    'examples/quorum-sender-v1/receipt.py') + tuple(
        'tools/transport_quorum_' + name + '.py' for name in
        ('input', 'shape', 'source', 'claim', 'graph', 'impact', 'context', 'reading', 'replay'))


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path):
    need(path.is_file() and not path.is_symlink(), 'regular file required')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    need(len(raw) <= 1048576, 'file byte bound')
    return raw


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def inventory():
    pending, rows, total = [HERE], {}, 0
    for unused in range(256):
        if not pending:
            return rows
        path = pending.pop()
        need(not path.is_symlink(), 'symlinks refused')
        if path.is_dir():
            for index, child in enumerate(path.iterdir()):
                need(index < 128 and len(pending) < 256, 'tree bound')
                need(child.name != '__pycache__', 'bytecode is not evidence')
                pending.append(child)
        elif path.name not in ('receipt.py', 'receipt.json'):
            raw = read(path)
            total += len(raw)
            need(total <= 4194304, 'aggregate evidence bound')
            rows[path.relative_to(HERE).as_posix()] = pin(raw)
    raise ValueError('tree work bound')


def local_controls():
    result = {}
    for name in SOURCES[:2] + ('examples/quorum-sender-v1/receipt.py',):
        tree = ast.parse(read(ROOT / name))
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        need(all(n.end_lineno - n.lineno + 1 <= 60 for n in functions), 'function span bound')
        need(not any(isinstance(n, (ast.Assert, ast.While)) for n in ast.walk(tree)),
             'new code requires explicit errors and bounded loops')
        result[name] = dict(functions=len(functions),
                           max_function_lines=max(n.end_lineno - n.lineno + 1 for n in functions))
    return result


def build():
    controls = local_controls()
    results = json.loads(read(HERE / 'observations/final-results.json'))
    rows = results['results']
    need(len(rows) == 28 and all(r['status'] == 'PASS' for r in rows), 'recorded outcomes differ')
    return dict(schema='quorum/sender-source-observation-receipt/1',
        parent_source_commit='f3a3f7a44bfbcddeb87a56af13663903d404374b',
        sources={name: pin(read(ROOT / name)) for name in SOURCES},
        evidence=inventory(), local_static_controls=controls,
        verification='Source/file identities and retained outcomes only; actual execution is recorded evidence.',
        source_authentication='UNVERIFIED', formal_proof_of_new_adapter='UNPROVEN',
        semantic_completeness='UNPROVEN', external_validation='EXTERNAL_VALIDATION_PENDING',
        behavioral_superiority='NOT_ESTABLISHED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true')
    action.add_argument('--create', action='store_true')
    args = parser.parse_args()
    raw = json.dumps(build(), sort_keys=True, ensure_ascii=False,
                     separators=(',', ':'), allow_nan=False).encode() + b'\n'
    destination = HERE / 'receipt.json'
    if args.check:
        need(read(destination) == raw, 'receipt/source/evidence mismatch')
        print('Sender checkpoint source and retained observation identities match')
    else:
        with destination.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'incomplete receipt write')


if __name__ == '__main__':
    main()
