"""Independent mutations of frozen evidence; no native or model execution."""
import copy
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import receipt as subject


def encoded(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


def bundle(rows):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw, kind in rows:
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode, entry.size = kind, 0o644, len(raw)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                entry.linkname = 'target'
                entry.size = 0
            archive.addfile(entry, io.BytesIO(raw))
    return gzip.compress(buffer.getvalue(), mtime=0)


class ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = subject.read(subject.HERE / 'evidence.tar.gz', subject.TOTAL)
        cls.files = subject.unpack(cls.archive)

    def changed(self, name, change):
        result = dict(self.files)
        value = subject.load(result[name])
        change(value)
        result[name] = encoded(value)
        return result

    def test_positive_frozen_evidence(self):
        result = subject.observations(self.files)
        self.assertEqual(result['exact_source_entries'], 12)
        self.assertEqual(result['citations']['citation_count'], 11)
        self.assertEqual(result['assessment']['independent_completion'], 'NOT_ASSERTED')

    def test_truncated_gzip(self):
        with self.assertRaises((EOFError, OSError, ValueError)):
            subject.unpack(self.archive[:-9])

    def test_expansion_bound(self):
        with self.assertRaisesRegex(ValueError, 'EXPANSION_BOUND'):
            subject.unpack(gzip.compress(b'0' * (subject.TOTAL + 1), mtime=0))

    def test_unsafe_archive_paths(self):
        for name in ('../escape', '/absolute', 'a/../b', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                subject.unpack(bundle([(name, b'x', tarfile.REGTYPE)]))

    def test_archive_link_types(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                subject.unpack(bundle([('entry', b'', kind)]))

    def test_duplicate_archive_entries(self):
        with self.assertRaisesRegex(ValueError, 'ENTRY_TYPE_OR_DUPLICATE'):
            subject.unpack(bundle([('same', b'a', tarfile.REGTYPE), ('same', b'b', tarfile.REGTYPE)]))

    def test_oversized_entry(self):
        with self.assertRaisesRegex(ValueError, 'ENTRY_TYPE_OR_DUPLICATE'):
            subject.unpack(bundle([('large', b'x' * (subject.CAP + 1), tarfile.REGTYPE)]))

    def test_inventory_missing_entry(self):
        with self.assertRaisesRegex(ValueError, 'INVENTORY_COVERAGE'):
            subject.unpack(bundle([('_inventory.json', b'{}', tarfile.REGTYPE),
                                   ('extra', b'x', tarfile.REGTYPE)]))

    def test_inventory_boolean_size(self):
        metadata = {'empty': dict(path='/observed', bytes=False, sha256=subject.pin(b'')['sha256'])}
        with self.assertRaisesRegex(ValueError, 'INVENTORY_PIN'):
            subject.unpack(bundle([('_inventory.json', encoded(metadata), tarfile.REGTYPE),
                                   ('empty', b'', tarfile.REGTYPE)]))

    def test_changed_held_answer_even_if_inventory_resealed(self):
        files = dict(self.files)
        files['trial/receivers/transport/answer.json'] += b' '
        inventory = subject.load(files['_inventory.json'])
        inventory['trial/receivers/transport/answer.json'].update(subject.pin(
            files['trial/receivers/transport/answer.json']))
        files['_inventory.json'] = encoded(inventory)
        with self.assertRaisesRegex(ValueError, 'HELD_INPUT_CHANGED'):
            subject.held_inputs(files)

    def test_changed_current_source(self):
        with patch.object(subject, 'read', return_value=b'changed'):
            with self.assertRaisesRegex(ValueError, 'CURRENT_SOURCE_CHANGED'):
                subject.source_pins(self.files)

    def test_swapped_source_identity(self):
        files = dict(self.files)
        prefix = 'trial/receivers/transport/source-workspace/sources/'
        files[prefix + 'S_DEF_NEW.bin'] = files[prefix + 'S_DEF_OLD.bin']
        with self.assertRaisesRegex(ValueError, 'SOURCE_RECOVERY_CHANGED'):
            subject.exact_sources(files)

    def test_dropped_citation(self):
        files = self.changed('trial/receivers/transport/answer.json', lambda x: x['evidence'].pop())
        with self.assertRaises(ValueError):
            subject.citations(files)

    def test_changed_quantity_citation(self):
        def change(value):
            row = value['evidence'][-1]
            row['quote'] = row['quote'].replace('12 L', '13 L')
        with self.assertRaises(ValueError):
            subject.citations(self.changed('trial/receivers/transport/answer.json', change))

    def test_final_text_substitution(self):
        files = dict(self.files)
        files['receiver-capture/final-01.txt'] += b' '
        with self.assertRaisesRegex(ValueError, 'FINAL_BYTES'):
            subject.capture(files, 'receiver-capture', self.files['trial/receivers/transport/answer.json'])

    def test_raw_journal_extra_in_capture(self):
        files = dict(self.files)
        files['receiver-capture/raw-journal.jsonl'] = b'{}'
        with self.assertRaisesRegex(ValueError, 'UNDECLARED_CAPTURE_FILE'):
            subject.capture(files, 'receiver-capture')

    def test_forbidden_event_kind(self):
        def change(value):
            value['events'][0]['kind'] = 'reasoning'
        with self.assertRaisesRegex(ValueError, 'CAPTURE_EVENT_KIND'):
            subject.capture(self.changed('receiver-capture/report.json', change), 'receiver-capture')

    def test_false_model_identity(self):
        def change(value):
            for item in value['metadata']:
                if item['kind'] == 'TURN_MODEL_METADATA':
                    item['fields']['model'] = 'invented-model'
        with self.assertRaisesRegex(ValueError, 'OBSERVED_MODEL_CHANGED'):
            subject.capture(self.changed('receiver-capture/report.json', change), 'receiver-capture')

    def test_source_assessment_claim_upgrade(self):
        files = self.changed('assessment/assessment.json',
                             lambda x: x.update(independent_completion_claim='PROVED'))
        with self.assertRaisesRegex(ValueError, 'ASSESSMENT_LIMITS'):
            subject.assessment(files)

    def test_erased_masking_limitation(self):
        files = self.changed('assessment/assessment.json', lambda x: x.update(limitations=[]))
        with self.assertRaisesRegex(ValueError, 'MASKING_LIMITATION_MISSING'):
            subject.assessment(files)

    def test_erased_first_failure(self):
        files = self.changed('first-failed/answer.json', lambda x: x.update(narrative='Succeeded'))
        with self.assertRaisesRegex(ValueError, 'FIRST_FAILURE'):
            subject.failures(files)

    def test_boolean_native_exit(self):
        files = self.changed('trial/preflight/native-02/run.json', lambda x: x.update(exit_code=False))
        with self.assertRaisesRegex(ValueError, 'EXACT_INTEGER'):
            subject.failures(files)

    def test_missing_receiver_engineering_finding(self):
        files = self.changed('observations/independent-postlaunch-review.json',
                             lambda x: x.update(findings=[]))
        with self.assertRaisesRegex(ValueError, 'ENGINEERING_FINDING_ERASED'):
            subject.failures(files)

    def test_duplicate_and_deep_json(self):
        for raw in (b'{"a":0,"a":1}', b'[' * 65 + b'0' + b']' * 65):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                subject.load(raw)


    def test_review_capture_crosslink(self):
        files = dict(self.files)
        files['receiver-capture/report.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'REVIEW_CAPTURE_PIN'):
            subject.provenance(files)

    def test_review_native_crosslink(self):
        files = dict(self.files)
        files['trial/receivers/transport/decode-receipt.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'REVIEW_NATIVE_PIN'):
            subject.provenance(files)

    def test_assessment_input_crosslink(self):
        files = dict(self.files)
        files['assessment/oracle.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'ASSESSMENT_INPUT_PIN'):
            subject.assessment(files)

    def test_dispatch_settings_changed(self):
        files = self.changed('assessment/launch.json', lambda x: x.update(fork_turns='all'))
        with self.assertRaisesRegex(ValueError, 'DECLARED_DISPATCH_CHANGED'):
            subject.provenance(files)


if __name__ == '__main__':
    unittest.main()
