#!/usr/bin/env python3
"""Run unchanged self-contained codec suites against a copied installed runtime."""

import argparse
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_install_build import command
from transport_install_layout import checked_json, record
from transport_install_support import canonical, read_regular, require, sha, write_new

ROOT = Path(__file__).resolve().parents[1]
SUITES = ('test_transport', 'test_semantic_transport', 'test_transport_authoring', 'test_transport_export')
FIXTURES = ('fixtures/transport-general-v1', 'fixtures/semantic-transport-v1', 'fixtures/semantic-examples-v1')
SCRIPT = ('import sys,unittest;sys.path[:0]=[sys.argv[1]+"/tools",sys.argv[1]+"/tests"];'
          'suite=unittest.defaultTestLoader.loadTestsFromNames(sys.argv[2:]);'
          'result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not result.wasSuccessful())')


def copy_inputs(bundle: Path, stage: Path) -> list[dict]:
    manifest = checked_json(read_regular(bundle / 'INSTALL.json'))
    records = []
    for item in manifest['files']:
        data = read_regular(bundle / item['path'])
        require(sha(data) == item['sha256'] and len(data) == item['bytes'], 'installed regression input changed')
        target = stage / item['path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, data)
        if item['path'].startswith('bin/'):
            target.chmod(0o700)
    names = [ROOT / 'tests' / (name + '.py') for name in SUITES]
    names += [ROOT / 'corpus/codec-cases.json', ROOT / 'corpus/codec-semantics-cases.json']
    for directory in FIXTURES:
        names += sorted((ROOT / directory).iterdir())
    require(len(names) <= 128, 'regression fixture count exceeded')
    for path in names:
        name = path.relative_to(ROOT).as_posix()
        data = read_regular(path)
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, data)
        records.append(record(name, data))
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700)
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')
    result = dict(status='FAILED', suites=list(SUITES), installed_manifest_sha256=sha(read_regular(args.bundle / 'INSTALL.json')),
                  historical_frozen_recipient_suites='NOT_RETARGETED; separate original fixtures required')
    try:
        with tempfile.TemporaryDirectory(prefix='transport-regression-') as temporary:
            stage = Path(temporary)
            result['unchanged_inputs'] = copy_inputs(args.bundle, stage)
            command([sys.executable, '-I', '-S', '-B', '-Werror', '-c', SCRIPT, str(stage), *SUITES],
                    stage, env, args.evidence, 'regression')
            result['status'] = 'PASS'
    finally:
        write_new(args.evidence / 'receipt.json', canonical(result))
    print(canonical(result).decode())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        sys.exit(1)
