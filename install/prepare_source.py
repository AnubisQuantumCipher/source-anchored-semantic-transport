#!/usr/bin/env python3
"""Derive the fixed source inventory; --check reproduces bytes without changing them."""

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_install_layout import input_names, record
from transport_install_support import canonical, confined, read_regular, require, sha, write_new


def inventory(root: Path) -> bytes:
    entries = [record(name, read_regular(confined(root, name))) for name in sorted(input_names())]
    require(len(entries) <= 128 and sum(item['bytes'] for item in entries) <= 4_194_304,
            'source inventory bound exceeded')
    return canonical(dict(schema='transport/install-source/1',
                          product='Source-Anchored Semantic Transport', files=entries,
                          excluded=['install/SOURCE.json']))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    expected = inventory(root)
    target = root / 'install/SOURCE.json'
    if args.check:
        require(read_regular(target) == expected, 'source inventory differs from derived bytes')
    else:
        write_new(target, expected)
    print(canonical(dict(status='SOURCE_INVENTORY_CHECKED' if args.check else 'SOURCE_INVENTORY_WRITTEN',
                         sha256=sha(expected), bytes=len(expected), authentication='NOT_PROVIDED')).decode())


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        sys.exit(1)
