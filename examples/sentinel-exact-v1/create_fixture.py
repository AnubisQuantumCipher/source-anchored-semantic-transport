#!/usr/bin/env python3
"""Known manual development case: two bad interpretations, then a repair.

Requires the complete source checkout, including its declared test fixture.
This generator is not an AI encoder or independently adjudicated source reading.
"""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from transport_document_io import canonical, digest, write_new
from transport_sentinel import registry_manifest
from test_transport_sentinel import Fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture()
    raw, artifacts, source_hash, registry_hash = fixture.arguments()
    args.out.mkdir(mode=0o700)
    folder = args.out / 'artifacts'
    folder.mkdir(mode=0o700)
    for name, data in artifacts.items():
        write_new(folder / (name + '.bin'), data)
    write_new(args.out / 'sidecar.json', raw)
    write_new(args.out / 'registry.json', registry_manifest(artifacts))
    pins = {'sidecar_sha256': source_hash, 'registry_sha256': registry_hash,
            'oracle': 'MANUAL_DEVELOPMENT_FIXTURE', 'qualification': 'NOT_QUALIFIED',
            'execution_authority': 'NONE'}
    write_new(args.out / 'pins.json', canonical(pins))
    sys.stdout.buffer.write(canonical(pins) + b'\n')


if __name__ == '__main__':
    main()
