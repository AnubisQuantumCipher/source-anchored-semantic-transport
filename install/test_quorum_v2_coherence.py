"""Independent literal controls for the versioned model/family addendum."""

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from transport_quorum_v2_policy import evaluate

ADDENDUM_SHA = '6e82c5fe36f649e1f4b2897a7035834ed05f262325d8bff940fdc0646146205c'
BASE_SHA = 'b18d82dedcfd9a90dfa4e6576ae453296c2f6f32baa222c5c83b27c0cbdd43ae'
NAMES = ('policy', 'registry', 'admissions', 'ballot')


def pinned(path, expected):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular pinned file required')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('pin or bound mismatch')
    return raw


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


class CoherenceControls(unittest.TestCase):
    def test_frozen_literal_cases(self):
        path = ROOT / 'docs/quorum-v2-coherence-addendum.json'
        document = json.loads(pinned(path, ADDENDUM_SHA))
        pinned(ROOT / 'docs/quorum-v2-contract.json', BASE_SHA)
        self.assertEqual(document['base_contract_sha256'], BASE_SHA)
        self.assertEqual(len(document['cases']), 9)
        for case in document['cases']:
            with self.subTest(case=case['id']):
                raws = tuple(encoded(case['inputs'][name]) for name in NAMES)
                actual = evaluate(raws, case['held_sha256'])
                self.check_result(actual, case['expected'])

    def check_result(self, actual, expected):
        for key, value in expected.items():
            self.assertIn(key, actual)
            self.assertIs(type(actual[key]), type(value), key)
            self.assertEqual(actual[key], value, key)
        if expected['status'] == 'REFUSED':
            self.assertEqual(set(actual), {'schema', 'status', 'code', 'authority'})
            self.assertEqual(actual['schema'], 'quorum/threshold-refusal/2')
            self.assertEqual(actual['authority'], 'NONE')
        else:
            self.assertEqual(actual['scope']['authority'], 'NONE')
            self.assertEqual(actual['scope']['source_truth'], 'NOT_ASSESSED')
            self.assertEqual(actual['scope']['interpretation'], 'NOT_CHECKED')
            for family in actual['support_families']:
                self.assertIs(type(family), str)


if __name__ == '__main__':
    unittest.main()
