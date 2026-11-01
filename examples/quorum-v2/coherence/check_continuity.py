"""Check the one exact coherence correction against the retained original receipt."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OLD_SUMS = 'e2a04a41d63fd423dea82ec73c20d8f56ceb356048d61673ebcd656900bf107f'
SCHEMA = 'tools/transport_quorum_v2_schema.py'
OLD_SCHEMA = '346e7a84c6267ef7d748991c305c8491a59531dc7f232cd902dde18d0f517c92'
NEW_SCHEMA = 'd756de0c3b3bf89b85a26450f3bd426653ef2e3928d3397405944cb75968d745'
EXTRA = {
    'examples/quorum-v2/coherence/independent-review.json': '464e7962cdc8575d8304e4b3e4490d566bb3981520ca25f480e685307ba5ec0d',
    'examples/quorum-v2/coherence/inventory.json': '6aad1d93aa320bed5e0d042f4bf38bbeb22b8cd3d9b307c380f6db97de47f762',
    'examples/quorum-v2/coherence/evidence.tar.gz': '9d46d103a71601478658c2f9321fd9611bd58188058ffa3406dbf5931d05a2d2',
    'docs/quorum-v2-coherence-addendum.json':
        '6e82c5fe36f649e1f4b2897a7035834ed05f262325d8bff940fdc0646146205c',
    'install/test_quorum_v2_coherence.py':
        '20678cffa9b4c38e7bc0fa32726220c7983d4c0d8f87362eaa2e926ee60c3a91',
    'examples/quorum-v2/coherence/schema-before.py': OLD_SCHEMA,
}


def need(value, code):
    if not value:
        raise ValueError(code)


def read(root, name):
    relative = Path(name)
    need(not relative.is_absolute() and '..' not in relative.parts, 'PATH')
    path = root / relative
    need(not path.is_symlink() and path.is_file(), 'FILE_KIND')
    need(path.stat().st_size <= 4194304, 'FILE_BOUND')
    return path.read_bytes()


def pinned(root, name, expected):
    raw = read(root, name)
    need(hashlib.sha256(raw).hexdigest() == expected, 'PIN:' + name)
    return raw


def check(root):
    raw = pinned(root, 'examples/quorum-v2/SHA256SUMS', OLD_SUMS)
    lines = raw.decode('ascii').splitlines()
    need(len(lines) == 31, 'INVENTORY_COUNT')
    seen = set()
    for line in lines:
        expected, name = line.split('  ', 1)
        need(name not in seen, 'DUPLICATE')
        seen.add(name)
        if name == SCHEMA:
            need(expected == OLD_SCHEMA, 'OLD_SCHEMA_PIN')
            expected = NEW_SCHEMA
        pinned(root, name, expected)
    need(SCHEMA in seen, 'SCHEMA_MISSING')
    for name, expected in EXTRA.items():
        pinned(root, name, expected)
    return dict(status='CHECKED_EXACT_COHERENCE_CORRECTION', original_files=31,
        current_schema_sha256=NEW_SCHEMA, historical_schema_sha256=OLD_SCHEMA,
        scope='Prior receipts retained; only this exact schema correction is admitted.',
        proof='No new formal proof claim')


if __name__ == '__main__':
    print(json.dumps(check(ROOT), sort_keys=True))
