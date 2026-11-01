"""Tamper controls over real copied evidence; no native program is executed."""
import gzip
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('core_receipt', HERE / 'receipt.py')
RECEIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPT)


class ReceiptChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='semantic-core-receipt-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.example = self.root / 'examples/semantic-core-v3'
        before = RECEIPT.inventory(HERE)
        self.assertLessEqual(len(before), RECEIPT.FILE_CAP)
        shutil.copytree(HERE, self.example)
        current = RECEIPT.load(HERE, 'receipt.json')
        for item in current['source_files']:
            target = self.root / item['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(RECEIPT.read(ROOT, item['path']))

    def reject(self):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            RECEIPT.check(self.root, self.example)

    def edit_json(self, relative, mutate):
        path = self.example / relative
        value = json.loads(path.read_bytes())
        mutate(value)
        path.write_bytes(RECEIPT.canonical(value))

    def test_complete_evidence_matches(self):
        result = RECEIPT.check(self.root, self.example)
        self.assertEqual(result['status'], 'CHECKED_SOURCE_BOUND_SCOPED_EVIDENCE')
        self.assertEqual(result['proof']['unproved'], 0)
        self.assertEqual(result['proof']['justified'], 0)

    def test_current_source_change_refused(self):
        path = self.root / 'tools/transport_core.py'
        path.write_bytes(path.read_bytes() + b'\n# changed\n')
        self.reject()

    def test_source_inventory_addition_refused(self):
        (self.root / 'evaluation/src/uncovered.ads').write_bytes(b'package Uncovered is end;')
        self.reject()

    def test_proof_failure_hidden_by_summary_swap_refused(self):
        base = self.example / 'evidence/native'
        (base / 'proof-03-summary.out').write_bytes((base / 'proof-04-summary.out').read_bytes())
        self.reject()

    def test_final_unproved_obligation_refused(self):
        path = self.example / 'evidence/native/proof-04-summary.out'
        raw = path.read_text()
        old = next(line for line in raw.splitlines() if line.startswith('Total '))
        path.write_text(raw.replace(old, old.rsplit('.', 1)[0] + '1'))
        self.reject()

    def test_swapped_archive_refused_even_after_inventory_regeneration(self):
        path = self.example / 'meaning.zip'
        path.write_bytes((self.example / 'evidence/product-03/meaning.zip').read_bytes())
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_altered_model_refused(self):
        self.edit_json('model.json', lambda value: value['tuples'][0].update(
            truth='KNOWN_FALSE'))
        self.reject()

    def test_missing_lexicon_refused(self):
        (self.example / 'lexicon.md').unlink()
        self.reject()

    def test_no_model_semantic_claim_refused(self):
        self.edit_json('evidence/no-model/roundtrip-result.json', lambda value:
                       value.update(semantic_scope='CLOSED_FORMULA_IN_SUPPLIED_FINITE_MODEL'))
        self.reject()

    def test_error_control_failure_refused(self):
        self.edit_json('evidence/review/process-review/error-results.json', lambda value:
                       value['cases'][0].update({'pass': False}))
        self.reject()

    def test_original_failure_erasure_refused(self):
        path = self.example / 'evidence/review/schema-review/results.json.gz'
        data = RECEIPT.load(self.example, str(path.relative_to(self.example)))
        for case in data['cases']:
            case['pass'] = True
        path.write_bytes(gzip.compress(RECEIPT.canonical(data), mtime=0))
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_duplicate_json_key_refused(self):
        (self.example / 'recipient-result.json').write_bytes(b'{"status":1,"status":2}')
        self.reject()

    def test_excessive_json_depth_refused(self):
        raw = b'[' * 49 + b'0' + b']' * 49
        with self.assertRaisesRegex(ValueError, 'depth'):
            RECEIPT.json_bytes(raw)

    def test_unsafe_path_and_symlink_refused(self):
        with self.assertRaises(ValueError):
            RECEIPT.read(self.example, '../source.txt')
        (self.example / 'extra').symlink_to(self.example / 'source.txt')
        self.reject()

    def test_gzip_expansion_and_truncation_refused(self):
        raw = gzip.compress(b'x' * (RECEIPT.CAP + 1), mtime=0)
        with self.assertRaises(ValueError):
            RECEIPT.expand(raw)
        with self.assertRaises(ValueError):
            RECEIPT.expand(gzip.compress(b'{}', mtime=0)[:-1])

    def test_extra_evidence_refused(self):
        (self.example / 'unrecorded.txt').write_bytes(b'extra')
        self.reject()

    def test_legacy_contract_prefix_change_refused(self):
        path = self.root / 'evaluation/src/transport_eval.ads'
        path.write_bytes(b'-- altered\n' + path.read_bytes())
        self.reject()

    def test_relocated_input_pair_change_refused(self):
        def change(value):
            for name in value['held_inputs']:
                if name.endswith('/meaning.zip'):
                    value['held_inputs'][name] = '0' * 64
        self.edit_json('evidence/relocated-recipient/receipt.json', change)
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_boolean_exit_is_not_integer_zero(self):
        self.edit_json('evidence/native/receipt.json', lambda value:
                       value['proof'].update(process_exit=False))
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_float_count_is_not_integer_zero(self):
        self.edit_json('evidence/integration/test-normal-04.run.json', lambda value:
                       value.update(exit_code=0.0))
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_nonfinite_json_is_not_a_timing_measurement(self):
        for raw in (b'{"time": NaN}', b'{"time": Infinity}', b'{"time": 1e999}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    RECEIPT.json_bytes(raw)
        self.assertEqual(RECEIPT.json_bytes(b'{"time": 1.25}'), {'time': 1.25})

    def test_detail_contradicting_zero_unproved_refused(self):
        path = self.example / 'evidence/native/proof-04-summary.out'
        path.write_bytes(path.read_bytes() + b'\ncontract not proved\n')
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)

    def test_frozen_courier_source_change_refused(self):
        path = self.example / 'evidence/courier-sources/tools/transport_authoring.py'
        path.write_bytes(path.read_bytes() + b'\n# changed\n')
        with self.assertRaises(ValueError):
            RECEIPT.expected(self.root, self.example)


if __name__ == '__main__':
    unittest.main()
