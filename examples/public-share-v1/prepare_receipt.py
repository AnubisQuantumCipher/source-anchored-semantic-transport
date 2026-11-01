"""Reproduce byte identities for this presentation feature and retained evidence."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SOURCE = (
    '.github/workflows/public-share.yml', 'docs/PUBLIC_SHARE.md',
    'install/transport_public_share.py', 'install/test_public_share.py',
    'examples/public-share-v1/README.md', 'examples/public-share-v1/oracle.json',
    'examples/public-share-v1/prepare_receipt.py',
    'examples/public-share-v1/public-share.txt',
)
UNCHANGED = (
    'install/SOURCE.json', 'tools/transport_package.py', 'tools/transport_cli.py',
    'tools/transport_authoring.py',
    'examples/quorum-replay-v1/recipient/share.txt',
    'examples/quorum-replay-v1/recipient/meaning.zip',
    'examples/quorum-replay-v1/recipient/lexicon.md',
    'examples/quorum-replay-v1/receipt.json',
)
REQUIRED_EVIDENCE = {
    'formatter-final-normal.json', 'formatter-final-optimized.json',
    'wrapper-results.json', 'independent-final-review.json', 'owner-checks.json',
}
FIXTURE_GROUPS = ('inputs', 'direct-encode', 'direct-encode-plan',
                  'direct-tight', 'direct-tight-encode')


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular evidence file')
    with path.open('rb') as stream:
        raw = stream.read(2097153)
    if len(raw) > 2097152:
        raise ValueError('Evidence file exceeds bound')
    return raw


def pin(path):
    raw = read(path)
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def evidence():
    rows = []
    for path in (HERE / 'evidence').iterdir():
        if len(rows) >= 64:
            raise ValueError('Evidence entry bound exceeded')
        rows.append(pin(path))
    names = {Path(row['path']).name for row in rows}
    if not REQUIRED_EVIDENCE <= names:
        raise ValueError('Missing required qualification observations')
    return sorted(rows, key=lambda row: row['path'])


def fixtures():
    root = HERE / 'wrapper'
    rows = [pin(root / 'run.py'), pin(root / 'oracle.json')]
    for group in FIXTURE_GROUPS:
        entries = []
        for path in (root / group).iterdir():
            if len(entries) >= 5:
                raise ValueError('Fixture group exceeds bound')
            entries.append(pin(path))
        if not entries:
            raise ValueError('Missing fixture group')
        rows.extend(entries)
    return sorted(rows, key=lambda row: row['path'])


def prepare():
    return {
        'schema': 'transport/public-share-receipt/1',
        'scope': 'TESTED_PRESENTATION_AND_QUALIFIED_ENCODER_WORKFLOW',
        'source': [pin(ROOT / name) for name in SOURCE],
        'unchanged_codec_and_example': [pin(ROOT / name) for name in UNCHANGED],
        'observations': evidence(),
        'wrapper_reproduction_inputs': fixtures(),
        'limits': 'File identities bind retained observations; they do not prove '
                  'authorship, semantics, arbitrary platform compatibility or execution authority.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = (json.dumps(prepare(), sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    path = HERE / 'receipt.json'
    if args.check:
        if read(path) != raw:
            raise ValueError('Presentation receipt does not reproduce')
        print('Public share source and observation receipt matches')
    else:
        with path.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('Incomplete receipt write')
        print('Created public share source and observation receipt')


if __name__ == '__main__':
    main()
