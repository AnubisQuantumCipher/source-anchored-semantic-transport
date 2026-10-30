"""Bounded AST/function-size check; no document implementation is executed."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sources():
    files = sorted((ROOT / 'tools').glob('*document*.py'))
    files += sorted((ROOT / 'tests').glob('test_transport_document*.py'))
    files += sorted((ROOT / 'tools/document_build').glob('*.py'))
    files.append(ROOT / 'tests/test_document_build_helper.py')
    files += sorted((ROOT / 'document_native').glob('*.py'))
    files.append(Path(__file__).resolve())
    if not 1 <= len(files) <= 48 or len(set(files)) != len(files):
        raise ValueError('document source inventory bound or duplicate')
    return files


def main():
    files = sources()
    functions = 0
    for path in files:
        with path.open('rb') as stream:
            raw = stream.read(131073)
        if len(raw) > 131072:
            raise ValueError('document source byte bound: ' + str(path))
        tree = ast.parse(raw, filename=str(path))
        compile(tree, str(path), 'exec', dont_inherit=True)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if node.end_lineno - node.lineno + 1 > 60:
                    raise ValueError('function exceeds 60 lines: ' + str(path) + ':' + node.name)
    print('AST and function-size checks passed:', len(files), 'files,', functions,
          'functions; this check is not a termination or correctness proof')


if __name__ == '__main__':
    main()
