"""Retain the existing independent controls' raw records; no new oracle."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAX_RESULT = 1048576


def file_pin(path, cap):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        raise ValueError('regular file and size cap required')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) != info.st_size or len(raw) > cap:
        raise ValueError('file changed or size cap exceeded')
    return hashlib.sha256(raw).hexdigest()


def lower_limit(category, ceiling):
    soft, hard = resource.getrlimit(category)
    chosen = min([ceiling] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY])
    resource.setrlimit(category, (chosen, chosen))


def main():
    if len(sys.argv) != 2:
        raise ValueError('supply a new absolute output file')
    target = Path(sys.argv[1])
    if not target.is_absolute() or target.exists():
        raise ValueError('output must be new and absolute')
    source = ROOT / 'tests/test_transport_core.py'
    native = Path(os.environ['TRANSPORT_CORE_NATIVE'])
    pin = file_pin(native, 4194304)
    if pin != os.environ['TRANSPORT_CORE_NATIVE_SHA256']:
        raise ValueError('native pin mismatch')
    spec = importlib.util.spec_from_file_location('core_controls', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = []

    class Capture(unittest.TextTestResult):
        def stopTest(self, test):
            records.extend(module.RESULTS)
            super().stopTest(test)

    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(verbosity=2, resultclass=Capture).run(suite)
    if file_pin(native, 4194304) != pin:
        raise ValueError('native changed')
    report = {'schema': 'transport/frozen-controls-capture/1', 'cases': records,
              'native_sha256': pin, 'test_source_sha256': file_pin(source, MAX_RESULT),
              'argv': sys.orig_argv,
              'test_groups': result.testsRun, 'skips': len(result.skipped),
              'errors': len(result.errors), 'failures': len(result.failures),
              'successful': result.wasSuccessful(), 'python': sys.version,
              'capture_sha256': file_pin(Path(__file__), MAX_RESULT)}
    raw = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
    if len(raw) > MAX_RESULT:
        raise ValueError('record cap exceeded')
    with target.open('xb') as stream:
        stream.write(gzip.compress(raw, mtime=0))
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == '__main__':
    lower_limit(resource.RLIMIT_AS, 536870912)
    lower_limit(resource.RLIMIT_FSIZE, 1048576)
    lower_limit(resource.RLIMIT_CPU, 120)
    raise SystemExit(main())
