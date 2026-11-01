"""Explicit additive signing AST profile; mechanical checks are not formal proof."""
import resource

for limit, value in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                     (resource.RLIMIT_FSIZE, 2097152), (resource.RLIMIT_NOFILE, 64),
                     (resource.RLIMIT_CORE, 0)):
    inherited_soft, inherited_hard = resource.getrlimit(limit)
    finite = [bound for bound in (inherited_soft, inherited_hard)
              if bound != resource.RLIM_INFINITY]
    admitted = min([value] + finite)
    resource.setrlimit(limit, (admitted, admitted))

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('__init__.py', 'build_provider.py', 'fetch_sources.py', 'manifest.py')
PRODUCTION = tuple('tools/manifest_signing/' + name for name in MODULES) + (
    'tools/transport_signed_document.py',)
CONTROLS = ('tests/test_manifest_signing_workflow.py', 'tests/test_manifest_signing_native.py',
            'tests/test_transport_signed_document.py', 'tests/check_manifest_signing.py',
            'examples/sentinel-v1-integration/ci_gate.py',
            'examples/sentinel-v1-integration/readback.py')
CAP = 131072


def source(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular non-symlink source required: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    if len(raw) > CAP:
        raise ValueError('source byte cap exceeded: ' + str(path))
    return raw


def bounded_iterator(node, relative, owner):
    if relative != 'tools/manifest_signing/manifest.py' or owner != 'bounded':
        raise ValueError('unreviewed while loop: ' + relative)
    if not isinstance(node.test, ast.Name) or node.test.id != 'pending':
        raise ValueError('iterator-stack condition changed')
    text = ast.unparse(node)
    guards = ('used <= MAX_NODES', 'depth <= MAX_DEPTH',
              'len(pending) <= MAX_DEPTH', 'encoded_bytes <= MAX_BYTES',
              'used += 1', 'pending.pop()', 'pending.append((children, depth + 1))')
    if any(guard not in text for guard in guards):
        raise ValueError('bounded traversal guard changed')


def checked_tree(relative):
    tree = ast.parse(source(ROOT / relative), filename=relative)
    compile(tree, relative, 'exec', dont_inherit=True)
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    if any(isinstance(n, ast.AsyncFunctionDef) for n in ast.walk(tree)):
        raise ValueError('async control outside this profile: ' + relative)
    if relative in PRODUCTION and any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        raise ValueError('assertion used in production boundary: ' + relative)
    for function in functions:
        if function.end_lineno - function.lineno + 1 > 60:
            raise ValueError('function exceeds60: ' + relative + ':' + function.name)
        for node in ast.walk(function):
            if isinstance(node, ast.While):
                bounded_iterator(node, relative, function.name)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == function.name:
                    raise ValueError('direct recursion: ' + relative + ':' + function.name)
    return len(functions)


def main():
    if sys.argv[1:]:
        raise ValueError('no arguments accepted')
    directory = ROOT / 'tools/manifest_signing'
    observed = set()
    for index, path in enumerate(directory.iterdir()):
        if index >= 16:
            raise ValueError('signing directory entry bound')
        if path.suffix == '.py':
            observed.add(path.name)
    if observed != set(MODULES):
        raise ValueError('closed signing Python inventory mismatch')
    count = sum(checked_tree(name) for name in PRODUCTION + CONTROLS)
    print('CHECKED_STATIC_ONLY: explicit signing inventory; ' + str(count) + ' short functions')
    print('Traversal guards are syntactic checks; transitive termination, memory, C and host proof remain UNPROVEN.')


if __name__ == '__main__':
    main()
