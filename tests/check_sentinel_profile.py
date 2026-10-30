"""Explicit SENTINEL source inventory and short-function guard; not a proof."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ('tools/build_sentinel_policy.py', 'tools/transport_document_context.py',
    'tools/transport_sentinel.py', 'tools/transport_sentinel_export.py',
    'tools/transport_sentinel_package.py', 'sentinel_native/sentinel_build_profile.py',
    'sentinel_native/sentinel_qualification.py', 'tests/test_sentinel_qualification.py',
    'tests/test_transport_document_context.py', 'tests/test_transport_sentinel.py',
    'tests/test_transport_sentinel_package.py', 'tests/check_sentinel_profile.py',
    'examples/sentinel-exact-v1/create_fixture.py',
    'examples/sentinel-exact-v1/freeze_receipt.py', 'tests/test_sentinel_checkpoint.py')


def main():
    functions = 0
    if len(FILES) != len(set(FILES)):
        raise ValueError('duplicate source inventory entry')
    for name in FILES:
        path = ROOT / name
        with path.open('rb') as stream:
            raw = stream.read(131_073)
        if len(raw) > 131_072:
            raise ValueError('source byte bound: ' + name)
        tree = ast.parse(raw, filename=name)
        compile(tree, name, 'exec', dont_inherit=True)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if node.end_lineno - node.lineno + 1 > 60:
                    raise ValueError('function exceeds 60 lines: ' + name + ':' + node.name)
    print('SENTINEL AST/function-size guard passed:', len(FILES), 'files,', functions,
          'functions; no termination, interpretation or native-proof claim')


if __name__ == '__main__':
    main()
