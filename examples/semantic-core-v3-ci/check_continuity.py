"""Bounded continuity gate for one import-only test repair; never reseals evidence."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

CAP = 1048576
FROZEN = '54c2b2a67acfbda9c6629b6b298d0dca111b1ec384abccca0ab18cfb0180a9a1'
LANGUAGE = 'tests/test_transport_core_language.py'
CORE = {'transport_core.py', 'transport_core_bridge.py', 'transport_core_cli.py',
        'transport_core_language.py', 'transport_core_process.py'}
BOOTSTRAP = (b"ROOT = Path(__file__).resolve().parents[1]\n"
             b"sys.path.insert(0, str(ROOT / 'tools'))\n\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(root, name):
    path = Path(name)
    require(not path.is_absolute() and path.parts and
            all(part not in ('.', '..') for part in path.parts), 'unsafe path')
    target = root
    for part in path.parts:
        target = target / part
        require(not target.is_symlink(), 'symlink refused')
    info = target.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= CAP, 'file cap/type')
    with target.open('rb') as stream:
        raw = stream.read(CAP + 1)
    require(len(raw) == info.st_size and len(raw) <= CAP, 'file changed/cap')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_language(raw):
    marker = b'import sys\nimport unittest\n'
    anchor = b'from pathlib import Path\n\n'
    require(raw.count(marker) == 1 and raw.count(anchor + BOOTSTRAP) == 1,
            'required exact import bootstrap absent')
    original = raw.replace(marker, b'import unittest\n', 1)
    original = original.replace(anchor + BOOTSTRAP, anchor, 1)
    require(original.count(b'import unittest\n') == 1 and
            original.count(anchor) == 1, 'ambiguous original imports')
    restored = original.replace(b'import unittest\n', marker, 1)
    restored = restored.replace(anchor, anchor + BOOTSTRAP, 1)
    require(restored == raw, 'noncanonical import repair')
    return original


def entries(directory):
    result = []
    with os.scandir(directory) as stream:
        for item in stream:
            require(len(result) < 512, 'directory cap')
            require(not item.is_symlink(), 'symlink refused')
            result.append(item)
    return result


def artifact_names(root):
    pending = [('', 0)]
    result = set()
    for unused in range(512):
        if not pending:
            break
        prefix, depth = pending.pop()
        require(depth <= 10, 'directory depth')
        for item in entries(root / prefix):
            name = str(Path(prefix) / item.name)
            if item.is_dir(follow_symlinks=False):
                require(len(pending) < 512, 'pending directory cap')
                pending.append((name, depth + 1))
            else:
                result.add(name)
                require(len(result) <= 512, 'artifact cap')
    require(not pending, 'directory traversal cap')
    return result


def check_rows(root, rows, allow_import=False):
    require(type(rows) is list and len(rows) <= 512, 'inventory cap/type')
    seen = set()
    total = 0
    for item in rows:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256'},
                'inventory row shape')
        name = item['path']
        require(type(name) is str and name not in seen, 'duplicate source path')
        seen.add(name)
        raw = read(root, name)
        if allow_import and name == LANGUAGE:
            raw = original_language(raw)
        require(type(item['bytes']) is int and len(raw) == item['bytes'] and
                sha(raw) == item['sha256'], 'source/evidence pin mismatch: ' + name)
        total += len(raw)
        require(total <= 4194304, 'inventory byte cap')
    return seen


def static_core(root):
    names = {item.name for item in entries(root / 'tools')
             if item.name.startswith('transport_core') and item.name.endswith('.py')}
    require(names == CORE, 'core source coverage')
    functions = []
    for name in sorted(names):
        tree = ast.parse(read(root, 'tools/' + name), filename=name)
        for index, node in enumerate(ast.walk(tree)):
            require(index < 32768, 'AST node cap')
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines = node.end_lineno - node.lineno + 1
                require(lines <= 60, 'function exceeds 60 lines: ' + node.name)
                functions.append({'file': name, 'function': node.name, 'lines': lines})
                require(len(functions) <= 1024, 'function cap')
    require(functions, 'no core functions inspected')
    return functions


def check(root):
    example = root / 'examples/semantic-core-v3'
    raw = read(example, 'receipt.json')
    require(sha(raw) == FROZEN, 'sealed receipt changed')
    receipt = json.loads(raw)
    require(receipt['schema'] == 'transport/semantic-core-evidence/1', 'receipt schema')
    sources = check_rows(root, receipt['source_files'], allow_import=True)
    require(LANGUAGE in sources, 'language test missing from sealed inventory')
    artifacts = check_rows(example, receipt['artifacts'])
    require(artifact_names(example) == artifacts | {'receipt.json'},
            'sealed evidence inventory changed')
    functions = static_core(root)
    return {'status': 'CHECKED_IMPORT_ONLY_CONTINUITY', 'sealed_receipt_sha256': FROZEN,
            'current_source_files': len(sources), 'core_functions': functions,
            'allowed_change': LANGUAGE + ': exact isolated import bootstrap only',
            'runtime_drift': 'NONE_IN_SEALED_SOURCE_INVENTORY',
            'proof_scope': 'Existing sealed receipt unchanged; no new proof claim'}


def main():
    try:
        result = check(Path(__file__).resolve().parents[2])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, SyntaxError, RecursionError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
