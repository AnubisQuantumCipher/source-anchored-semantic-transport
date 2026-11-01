#!/usr/bin/env python3
"""Build pinned, already acquired mldsa-native sources without install scripts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

COMMIT = '17ebc1aa493265515a92239c76507ae28777cd4a'
FLAGS = ['-std=c99', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
         '-Wconversion', '-Wsign-conversion', '-Wshadow', '-Wstrict-prototypes',
         '-Wmissing-prototypes', '-Wpointer-arith', '-Wformat=2', '-fno-common',
         '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3',
         '-DMLD_CONFIG_FILE="provider_config.h"']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def material_sizes(source):
    header = (source / 'mldsa/mldsa_native.h').read_text()
    result = {}
    for name in ('PUBLICKEYBYTES', 'SECRETKEYBYTES', 'BYTES'):
        matches = re.findall(r'^#define MLDSA87_' + name + r' ([0-9]+)$', header, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError('pinned upstream material-size declaration mismatch')
        result[name] = int(matches[0])
    return result


def build(source, output, rng_test_fail_after=None):
    source = source.resolve(strict=True)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    files = sorted(p for p in source.rglob('*') if p.is_file())
    if not files or len(files) > 1024 or sum(p.stat().st_size for p in files) > 16777216:
        raise ValueError('upstream source footprint refused')
    inventory = {str(p.relative_to(source)): digest(p) for p in files}
    acquisition = json.loads((source / 'source-acquisition.json').read_text())
    retained = dict(inventory)
    retained.pop('source-acquisition.json', None)
    if acquisition['commit'] != COMMIT or acquisition['source_inventory'] != retained:
        raise ValueError('source acquisition identity or inventory mismatch')
    compiler = Path('/usr/bin/cc').resolve(strict=True)
    binary = output / 'sast-mldsa87-provider'
    command = [str(compiler), *FLAGS, '-I' + str(here), '-I' + str(source / 'mldsa'),
               str(here / 'provider.c'), str(source / 'mldsa/mldsa_native.c'),
               '-Wl,-z,relro,-z,now,-z,noexecstack', '-o', str(binary)]
    if rng_test_fail_after is not None:
        if type(rng_test_fail_after) is not int or rng_test_fail_after not in (0, 1):
            raise ValueError('test RNG fault control refused')
        command.extend(['-DSAST_TEST_RNG_FAIL_AFTER=' + str(rng_test_fail_after),
                        str(here / 'rng_failure_test.c'), '-Wl,--wrap=getrandom'])
    result = subprocess.run(command, capture_output=True, timeout=90, check=False)
    (output / 'build.stdout').write_bytes(result.stdout)
    (output / 'build.stderr').write_bytes(result.stderr)
    version = subprocess.run([str(compiler), '--version'], capture_output=True,
                             timeout=5, check=True).stdout.decode('ascii')
    receipt = {'schema': 'sast/mldsa-native-build/1', 'upstream_commit': COMMIT,
               'upstream_repository': 'https://github.com/pq-code-package/mldsa-native',
               'source_inventory': inventory, 'compiler_path': str(compiler),
               'compiler_sha256': digest(compiler), 'compiler_version': version,
               'command': command, 'returncode': result.returncode,
               'provider_source_sha256': digest(here / 'provider.c'),
               'config_sha256': digest(here / 'provider_config.h'),
               'backend': 'mldsa-native portable C, parameter set 87 only',
               'material_sizes_from_upstream_header': material_sizes(source),
               'test_only_rng_fault_after_calls': rng_test_fail_after,
               'local_upstream_proof_rerun': 'UNRUN', 'production_key_admission': 'NONE'}
    if result.returncode == 0:
        receipt['binary_sha256'] = digest(binary)
        receipt['binary_bytes'] = binary.stat().st_size
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if result.returncode != 0:
        raise ValueError('strict provider build failed; retained build.stderr')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rng-test-fail-after', type=int, choices=(0, 1))
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.output, args.rng_test_fail_after), sort_keys=True))
