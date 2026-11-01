"""Bounded mandatory CI actions; no provider fallback and no skipped acceptance."""
import resource
import sys

FILE_LIMIT = 16777216 if sys.argv[1:] in (['crypto'], ['signed']) else 2097152

ACTION_LIMITS = ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                 (resource.RLIMIT_FSIZE, FILE_LIMIT), (resource.RLIMIT_NOFILE, 64),
                 (resource.RLIMIT_CORE, 0))
for limit, value in ACTION_LIMITS:
    inherited_soft, inherited_hard = resource.getrlimit(limit)
    finite = [bound for bound in (inherited_soft, inherited_hard)
              if bound != resource.RLIM_INFINITY]
    admitted = min([value] + finite)
    resource.setrlimit(limit, (admitted, admitted))

import importlib.util
import os
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = ('acquire', 'normal', 'rng-fault-0', 'rng-fault-1', 'crypto', 'signed')


def required_directory(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError('required CI directory missing: ' + name)
    return Path(value)


def executable(path):
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('required regular executable absent: ' + str(path))


def provider_gate():
    normal = required_directory('SAST_MLDSA87_BUILD')
    faults = required_directory('SAST_MLDSA87_RNG_FAULT_ROOT')
    directories = (normal, faults / 'rng-fault-0', faults / 'rng-fault-1')
    for directory in directories:
        executable(directory / 'sast-mldsa87-provider')
        if not (directory / 'build-receipt.json').is_file():
            raise ValueError('required build receipt absent: ' + str(directory))


def helper(action):
    directory = ROOT / 'tools/manifest_signing'
    source = required_directory('SAST_MLDSA87_SOURCE')
    sys.path.insert(0, str(directory))
    if action == 'acquire':
        source.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        script = directory / 'fetch_sources.py'
        sys.argv = [str(script), '--output', str(source)]
    else:
        compiler = Path('/usr/bin/cc')
        if not compiler.is_file() or not os.access(compiler, os.X_OK):
            raise ValueError('existing /usr/bin/cc required; no installation fallback')
        script = directory / 'build_provider.py'
        output = required_directory('SAST_MLDSA87_BUILD') if action == 'normal' else (
            required_directory('SAST_MLDSA87_RNG_FAULT_ROOT') / action)
        sys.argv = [str(script), '--source', str(source), '--output', str(output)]
        if action != 'normal':
            sys.argv += ['--rng-test-fail-after', action[-1]]
    runpy.run_path(str(script), run_name='__main__')


def controls(action):
    provider_gate()
    name, expected = ('test_manifest_signing_native', 23) if action == 'crypto' else (
        'test_transport_signed_document', 22)
    path = ROOT / 'tests' / (name + '.py')
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError('test import specification missing')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    if suite.countTestCases() != expected:
        raise ValueError('test roster changed; review required before updating exact count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun != expected:
        raise ValueError('mandatory signing controls failed, skipped or incomplete')
    print('TESTED: ' + action + '; all declared controls executed; skipped=0')
    if action == 'signed':
        print('MOCKED_PROVIDER_AND_DOCUMENT_NATIVE; actual document-native roundtrip NOT_PERFORMED')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ACTIONS:
        raise ValueError('exactly one declared CI action required')
    action = sys.argv[1]
    if action in ('crypto', 'signed'):
        controls(action)
    else:
        helper(action)


if __name__ == '__main__':
    main()
