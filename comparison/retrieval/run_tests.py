"""Portable runner for the unchanged frozen suite plus strict FTS capabilities.

Only the frozen suite's ARCHIVE location is rebound to byte-identical repository
fixture copies. No core, expectation, test method, result, or source pin is mocked
or changed. This runner writes no files and needs no /dev/shm state.

Run with Python -Werror, then repeat with Python -O -Werror. Retain complete
captures and source pins outside this runner before making any repairs.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PINS = {
    'test_retrieval.py':
        '9b7a24a04c9b909f48244f0b52a4773b9b6eceb0d884022a6fc7881028ac7a61',
    'test_fts_capability.py':
        'dde12321e1d5a7919bf144a9c89fb553a89b786467dbd0a33731f19a0cf3fd51',
    'evidence/oracle.initial.raw.json':
        'b93bda359afd87920e1ff1b073b6deaf4174f454b58628ca49bc276079dfeb37',
    'evidence/oracle.v2.raw.json':
        '23525546f46513b5d1c45acfa2161d6d5266ae2446d88deff66f4aa7d5a690f3',
    'evidence/oracle.initial.receipt.json':
        '61f9d107fd7ef64cf2218c2ed2427d2bf91be55dee4f9a57327b2cf7d2dbf872',
}


def verify_sources():
    for name, expected in PINS.items():
        actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f'Portable test source pin mismatch: {name}')


def load_test_module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    if spec is None or spec.loader is None:
        raise ValueError(f'Test module loader unavailable: {name}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    verify_sources()
    frozen = load_test_module('test_retrieval')
    frozen.ARCHIVE = HERE / 'evidence'
    capability = load_test_module('test_fts_capability')
    loader = unittest.TestLoader()
    original_suite = loader.loadTestsFromModule(frozen)
    capability_suite = loader.loadTestsFromModule(capability)
    if original_suite.countTestCases() != 58:
        raise ValueError('Frozen original test count changed')
    if capability_suite.countTestCases() != 13:
        raise ValueError('Frozen additive capability test count changed')
    suite = unittest.TestSuite([original_suite, capability_suite])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
