"""Closed additive Python inventory and mechanical Power-of-Ten equivalents."""
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('__init__', 'common', 'bindings', 'census', 'graph', 'locators', 'challenges',
           'refinement', 'assessments', 'comparison', 'bundle', 'cli', 'jobs', 'analysis',
           'native_build', 'native')
TESTS = ('common', 'meaning', 'locators', 'challenges', 'refinement', 'assessments',
         'analysis', 'bundle', 'adversarial')
CORE = ('__init__', 'common', 'bindings', 'census', 'graph', 'locators', 'challenges', 'refinement')


def checked_tree(path, production):
    if path.is_symlink() or not path.is_file():
        raise ValueError('source must be a regular non-symlink: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072:
        raise ValueError('source byte bound: ' + str(path))
    tree = ast.parse(raw, filename=str(path))
    compile(tree, str(path), 'exec', dont_inherit=True)
    count = 0
    for node in ast.walk(tree):
        if production and isinstance(node, (ast.Assert, ast.While, ast.AsyncFunctionDef)):
            raise ValueError('unchecked assertion or unbounded/async control: ' + str(path))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            count += 1
            if node.end_lineno - node.lineno + 1 > 60:
                raise ValueError('function exceeds60: ' + str(path) + ':' + node.name)
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    if child.func.id == node.name:
                        raise ValueError('direct recursion: ' + str(path) + ':' + node.name)
    return count


def main():
    if sys.argv[1:] not in ([], ['--core']):
        raise ValueError('use no arguments or --core')
    core = bool(sys.argv[1:])
    directory = ROOT / 'tools/sentinel_v1'
    files = {entry.name for entry in directory.iterdir() if entry.name != '__pycache__'}
    expected = {name + '.py' for name in MODULES}
    required = {name + '.py' for name in CORE} if core else expected
    if not required <= files <= expected or len(expected) > 16:
        raise ValueError('closed additive module inventory mismatch: ' + repr(files ^ expected))
    count = sum(checked_tree(directory / name, True) for name in sorted(files))
    suites = TESTS[:5] if core else TESTS
    count += sum(checked_tree(ROOT / ('tests/test_sentinel_' + name + '.py'), False)
                 for name in suites)
    count += checked_tree(Path(__file__).resolve(), False)
    print('SENTINEL v1 additive inventory: ' + str(len(files)) + ' modules, '
          + str(len(suites)) + ' suites, ' + str(count) + ' short functions checked; '
          + ('CORE_SCOPE' if core else 'FULL_SCOPE'))
    print('No transitive-call termination, language understanding or whole-system proof claim.')


if __name__ == '__main__':
    main()
