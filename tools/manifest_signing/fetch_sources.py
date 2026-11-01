#!/usr/bin/env python3
"""Bounded official-source acquisition; no clone, install or upstream execution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request

from build_provider import COMMIT

REPOSITORY = 'https://github.com/pq-code-package/mldsa-native'
DOCS = {'README.md', 'SOUNDNESS.md', 'API-CONVENTIONS.md', 'LICENSE',
        'LICENSE-APACHE', 'LICENSE-MIT', 'LICENSE-ISC', 'LICENSE.md'}
NETWORK_CAP = 8388608
EXPANDED_CAP = 16777216
FILE_CAP = 1048576


def fetch(url, cap):
    with urllib.request.urlopen(url, timeout=20) as response:
        data = response.read(cap + 1)
    if len(data) > cap:
        raise ValueError('source response byte cap')
    return data


def acquire(output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tree_url = 'https://api.github.com/repos/pq-code-package/mldsa-native/git/trees/'
    metadata = fetch(tree_url + COMMIT + '?recursive=1', FILE_CAP)
    tree = json.loads(metadata)
    if tree.get('truncated') is not False or len(tree.get('tree', [])) > 8192:
        raise ValueError('upstream metadata truncated or oversized')
    candidates = [row for row in tree['tree'] if row['type'] == 'blob' and
                  (row['path'].startswith('mldsa/') or row['path'] in DOCS)]
    if not candidates or len(candidates) > 1024:
        raise ValueError('source file count refused')
    total = sum(row['size'] for row in candidates)
    if total > EXPANDED_CAP or total + len(metadata) > NETWORK_CAP:
        raise ValueError('source footprint refused before file transfer')
    inventory = {}
    for row in candidates:
        relative = PurePosixPath(row['path'])
        if relative.is_absolute() or '..' in relative.parts or row['mode'] != '100644':
            raise ValueError('nonregular upstream source refused')
        data = fetch('https://raw.githubusercontent.com/pq-code-package/mldsa-native/'
                     + COMMIT + '/' + str(relative), min(row['size'], FILE_CAP))
        blob = b'blob ' + str(len(data)).encode('ascii') + b'\0' + data
        if len(data) != row['size'] or hashlib.sha1(blob).hexdigest() != row['sha']:
            raise ValueError('git blob or size mismatch')
        target = output / str(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        inventory[str(relative)] = hashlib.sha256(data).hexdigest()
    receipt = {'schema': 'sast/mldsa-native-source/1', 'repository': REPOSITORY,
               'commit': COMMIT, 'tree_sha': tree['sha'], 'source_bytes': total,
               'network_bytes': total + len(metadata), 'source_inventory': inventory,
               'metadata_sha256': hashlib.sha256(metadata).hexdigest()}
    (output / 'source-acquisition.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = acquire(args.output)
    print(json.dumps({k: v for k, v in result.items() if k != 'source_inventory'}))
