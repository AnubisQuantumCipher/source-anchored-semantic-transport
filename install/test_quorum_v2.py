#!/usr/bin/env python3
"""Run the independent literal threshold oracle; no provider/model execution."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_quorum_v2_input import canonical, read_regular
from transport_quorum_v2_policy import NAMES, evaluate

ORACLE_SHA = '20d24834b1890a6e09130ea58bdaa9e225ded525bdfcf96391f54d068ffde428'
CONTRACT_SHA = 'b18d82dedcfd9a90dfa4e6576ae453296c2f6f32baa222c5c83b27c0cbdd43ae'
CONFIG = {}
OUTCOMES = []


def frozen(path, expected):
    raw = read_regular(path, 1048576)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('frozen oracle input changed: ' + str(path))
    return raw


def inputs(case):
    result = []
    for name in NAMES:
        pin = case['inputs'][name]
        if CONFIG.get('fixtures') is None:
            raw = frozen(CONFIG['oracle'].parent / pin['path'], pin['sha256'])
        else:
            raw = archived_input(CONFIG['fixtures'], pin)
        if len(raw) != pin['bytes']:
            raise ValueError('frozen byte length mismatch')
        result.append(raw)
    return tuple(result)


def archived_input(path, expected):
    if path.is_symlink() or path.stat().st_size > 1048576:
        raise ValueError('fixture archive file bound')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if (len(entries) > 512 or len(set(names)) != len(names)
                or sum(entry.file_size for entry in entries) > 2097152):
            raise ValueError('fixture archive inventory bound')
        for entry in entries:
            parts = entry.filename.split('/')
            if (not entry.filename.startswith('cases/') or any(v in ('', '.', '..') for v in parts)
                    or entry.is_dir() or (entry.external_attr >> 16) & 0o170000 not in (0, 0o100000)
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or entry.flag_bits & 1):
                raise ValueError('unsafe fixture archive entry')
        entry = archive.getinfo(expected['path'])
        if entry.file_size != expected['bytes'] or entry.file_size > 1048576:
            raise ValueError('fixture archive entry bound')
        with archive.open(entry) as stream:
            raw = stream.read(entry.file_size + 1)
    if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise ValueError('fixture archive entry identity')
    return raw


def source_inventory():
    names = ('tools/transport_quorum_v2_input.py', 'tools/transport_quorum_v2_schema.py',
             'tools/transport_quorum_v2_policy.py', 'tools/transport_quorum_v2.py',
             'install/test_quorum_v2.py', 'docs/quorum-v2-contract.json')
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def projection(result, expected):
    if expected['status'] == 'REFUSED':
        code = result.get('code')
        return {'status': result['status'],
                'code': 'NONEMPTY_FIXED_CODE' if type(code) is str and code else code,
                'no_partial_threshold_result': 'verdict' not in result}
    value = {name: result[name] for name in expected
             if name not in ('eligible_reading_ids', 'ineligible_reasons')}
    value['eligible_reading_ids'] = [row['reading_id'] for row in result['dispositions']
                                     if row['eligible']]
    value['ineligible_reasons'] = {row['reading_id']: row['reasons']
                                   for row in result['dispositions'] if not row['eligible']}
    return value


class IndependentOracle(unittest.TestCase):
    def test_all_literal_cases(self):
        oracle = json.loads(frozen(CONFIG['oracle'], ORACLE_SHA))
        frozen(ROOT / 'docs/quorum-v2-contract.json', CONTRACT_SHA)
        for case in oracle['cases']:
            with self.subTest(case=case['id']):
                result = evaluate(inputs(case), case['held_sha256'])
                actual = projection(result, case['expected'])
                OUTCOMES.append(dict(id=case['id'], actual=actual,
                                     matched=actual == case['expected'], result=result))
                self.assertEqual(actual, case['expected'])
                if result['status'] == 'REFUSED':
                    self.assertTrue(result['code'])
                    self.assertNotIn('verdict', result)
                else:
                    self.assertEqual(result['scope']['authority'], 'NONE')
                    self.assertEqual(result['scope']['source_truth'], 'NOT_ASSESSED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    CONFIG['oracle'] = args.oracle
    CONFIG['fixtures'] = args.fixtures
    before = source_inventory()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IndependentOracle)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = source_inventory()
    passed = result.wasSuccessful() and before == after
    report = dict(schema='quorum/independent-oracle-run/2', oracle_sha256=ORACLE_SHA,
                  passed=passed, outcomes=OUTCOMES, source_before=before, source_after=after,
                  source_unchanged=before == after,
                  semantic_proof='UNPROVEN', model_runs='NONE')
    with args.output.open('xb') as stream:
        stream.write(canonical(report) + b'\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
