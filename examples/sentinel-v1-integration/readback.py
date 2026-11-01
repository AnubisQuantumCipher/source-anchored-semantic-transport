"""Recompute public metadata receipt; does not interpret private text or grant authority."""
import resource

for limit, value in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                     (resource.RLIMIT_FSIZE, 2097152), (resource.RLIMIT_NOFILE, 64),
                     (resource.RLIMIT_CORE, 0)):
    inherited_soft, inherited_hard = resource.getrlimit(limit)
    finite = [bound for bound in (inherited_soft, inherited_hard)
              if bound != resource.RLIM_INFINITY]
    admitted = min([value] + finite)
    resource.setrlimit(limit, (admitted, admitted))

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_BYTES = 131072
MAX_FILES = 64
INPUTS = ('source-snapshot.json', 'acceptance-matrix.json', 'synthetic-source.txt')
SUPPORT = ('readback.py', 'ci_gate.py', 'README.md')


def raw(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular input required: ' + str(path))
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('input byte cap exceeded')
    return data


def pin(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def checked_source(snapshot):
    sources = snapshot['current_source_pins']
    if type(sources) is not dict or not 1 <= len(sources) <= MAX_FILES:
        raise ValueError('source inventory bound')
    for relative, expected in sources.items():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or len(path.parts) > 8:
            raise ValueError('source path refused')
        if pin(raw(ROOT / path)) != expected:
            raise ValueError('source drift: ' + relative)
    return len(sources)


def receipt():
    inputs = {name: raw(HERE / name) for name in INPUTS}
    snapshot = json.loads(inputs['source-snapshot.json'])
    matrix = json.loads(inputs['acceptance-matrix.json'])
    if snapshot['schema'] != 'sast/sanitized-integration-snapshot/1':
        raise ValueError('snapshot schema refused')
    if matrix['status'] != 'UNRUN_FOR_FINAL_COMBINED_REVISION':
        raise ValueError('preparatory matrix cannot grant final acceptance')
    count = checked_source(snapshot)
    return {'schema': 'sast/public-integration-readback/2',
            'classification': 'CHECKED_METADATA_AND_SYNTHETIC_BYTES_ONLY',
            'previous_public_receipt': pin(raw(HERE / 'receipt.json')),
            'previous_receipt_scope': 'HISTORICAL_BYTES_ONLY_NOT_RETARGETED',
            'workflow_context_profile': pin(raw(ROOT / 'tests/test_manifest_signing_workflow.py')),
            'inputs': {name: pin(data) for name, data in inputs.items()},
            'current_source_files_checked': count,
            'public_support': {name: pin(raw(HERE / name)) for name in SUPPORT},
            'workflow': pin(raw(ROOT / '.github/workflows/manifest-signing.yml')),
            'static_profile': pin(raw(ROOT / 'tests/check_manifest_signing.py')),
            'integration_doc': pin(raw(ROOT / 'docs/SAST_MAIN_INTEGRATION.md')),
            'synthetic_fixture': pin(inputs['synthetic-source.txt']),
            'private_originals': 'HASH_IDENTITIES_ONLY_NOT_PUBLICLY_REPRODUCED',
            'historical_receipts': 'UNCHANGED_NOT_RETARGETED',
            'combined_revision_acceptance': 'NOT_ESTABLISHED',
            'semantic_entailment': 'UNPROVEN', 'execution_authority': 'NONE'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    value = (json.dumps(receipt(), sort_keys=True, indent=2) + '\n').encode('ascii')
    target = HERE / 'receipt-ci-context-v2.json'
    if args.check:
        if raw(target) != value:
            raise ValueError('derived receipt differs; retain prior receipt and review source change')
        print('CHECKED public source identities and deterministic metadata derivation; no acceptance granted')
    else:
        with target.open('xb') as stream:
            if stream.write(value) != len(value):
                raise OSError('short receipt write')


if __name__ == '__main__':
    main()
