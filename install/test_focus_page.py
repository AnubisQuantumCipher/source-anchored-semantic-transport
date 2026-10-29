#!/usr/bin/env python3
"""Bounded focus paging and real session-log controls using a synthetic receiver.

The synthetic receiver stands for an already checked decoder response. Worker
tests verify package-freeze/receiver construction runs each call; these tests do
not claim native decoder, external tool-display or model acceptance.
"""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
import transport_handoff_prepare as preparation
import transport_handoff_reader as reader
import transport_handoff_session as sessions
from transport_install_support import canonical, sha

IDENTITY = 'STS1:' + 'a' * 64
UNIT = 'MU_TESTABLE_RULE'


class SyntheticReceiver:
    def __init__(self):
        self.decoded = {'identity': IDENTITY}
        self.calls, self.failure = [], None
        self.value = dict(schema='transport/focus/1', identity=IDENTITY, selected_unit=UNIT,
            meaning_units=[dict(id=UNIT, context=['MU_RULE_CONTEXT'],
                meaning=dict(schema='transport/meaning/1', nodes=[{'op': 'atom', 'symbol': 'OPAQUE'}],
                             root=0, ambiguities=[dict(note='interpretation remains unproved')]))],
            uncertainties=[dict(id='U_REPORTS', text='Conflicting historical claims remain unresolved.')],
            source_excerpts=[dict(source='RULE', bytes_base64=base64.b64encode(b'fixture source').decode())],
            padding='x\U0001f9fe' * 3000, context_adequacy='UNPROVEN', execution_authority='NONE')

    def call(self, name, arguments):
        if len(self.calls) >= 64:
            raise ValueError('synthetic decoder call bound')
        self.calls.append((name, copy.deepcopy(arguments)))
        if self.failure is not None:
            raise ValueError(self.failure)
        if name != 'transport_focus' or arguments != {'unit': UNIT}:
            raise ValueError('synthetic checked decoder missing unit')
        return copy.deepcopy(self.value)


class FocusPageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='transport-focus-page-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receiver = SyntheticReceiver()
        self.manifest = {'arm': 'transport', 'bundle': {'path': str(self.root / 'bundle')}}
        self.manifest_path = self.root / 'manifest.json'
        self.manifest_path.write_bytes(canonical(self.manifest))
        self.serial = 0

    def action(self, request, receiver=None, arm='transport'):
        return reader.action_result(request, {'arm': arm}, self.receiver if receiver is None else receiver, None)

    def page(self, offset=0):
        result, candidate = self.action(dict(action='focus_page', unit=UNIT, offset=offset))
        self.assertIsNone(candidate)
        return result

    def args(self, request):
        raw = canonical(request)
        path = self.root / ('request-%02d.json' % self.serial)
        self.serial += 1
        path.write_bytes(raw)
        return SimpleNamespace(manifest=self.manifest_path, expect_manifest_sha256=sha(self.manifest_path.read_bytes()),
            session=self.root / 'session', request=path, input_bytes=len(raw), request_error='')

    def logged(self, request):
        args = self.args(request)
        return inputs.json_value(reader.logged_call(args, self.manifest, self.receiver, None,
                                                   args.request.read_bytes(), args.input_bytes), inputs.CAP)

    def test_exact_full_canonical_focus_reassembles_without_lost_fields(self):
        expected = canonical(self.receiver.value)
        pieces, offset, pages, split_utf8 = [], 0, 0, False
        for _ in range(32):
            result = self.page(offset)
            raw = base64.b64decode(result['bytes_base64'], validate=True)
            self.assertLessEqual(len(raw), 4096)
            self.assertEqual((result['offset'], result['bytes']), (offset, len(raw)))
            self.assertEqual(result['page_sha256'], sha(raw))
            self.assertEqual(result['sha256'], sha(expected))
            self.assertEqual(result['total_bytes'], len(expected))
            self.assertEqual((result['unit'], result['package_identity']), (UNIT, IDENTITY))
            self.assertEqual(result['encoding'], 'base64')
            self.assertEqual(result['serialization'], 'CANONICAL_UTF8_JSON')
            self.assertNotIn('meaning_units', result)
            self.assertEqual(result['context_adequacy'], 'UNPROVEN')
            pieces.append(raw)
            pages += 1
            try:
                raw.decode('utf-8')
            except UnicodeError:
                split_utf8 = True
            if result['next_offset'] is None:
                self.assertTrue(result['end'])
                break
            self.assertFalse(result['end'])
            self.assertEqual(result['next_offset'], offset + len(raw))
            offset = result['next_offset']
        else:
            self.fail('synthetic complete focus exceeded fixed paging loop')
        self.assertEqual(b''.join(pieces), expected)
        self.assertEqual(json.loads(b''.join(pieces)), self.receiver.value)
        self.assertEqual(len(self.receiver.calls), pages)
        self.assertTrue(split_utf8)

    def test_page_response_is_bounded_and_eof_is_explicit(self):
        result = self.page(0)
        raw = reader.response('transport', 'focus_page', 'OK', result, 32)
        self.assertLessEqual(len(raw), 8192)
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(base64.b64decode(result['bytes_base64']), canonical(self.receiver.value)[:4096])
        end = self.page(len(canonical(self.receiver.value)))
        self.assertEqual(end['bytes'], 0)
        self.assertEqual(end['bytes_base64'], '')
        self.assertEqual(end['page_sha256'], sha(b''))
        self.assertTrue(end['end'])
        self.assertIsNone(end['next_offset'])

    def test_closed_fields_exact_integer_offsets_and_unit_validation(self):
        valid = dict(action='focus_page', unit=UNIT, offset=0)
        cases = [{key: value for key, value in valid.items() if key != 'offset'},
                 dict(valid, extra=True), dict(valid, source='RULE')]
        cases += [dict(valid, offset=value) for value in (True, False, 1.0, '0', -1, inputs.CAP)]
        cases += [dict(valid, unit=value) for value in ('lowercase', '../unit', '', 'X' * 33, 1, None)]
        for request in cases:
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.action(request)
        self.assertEqual(self.receiver.calls, [])
        with self.assertRaises(ValueError):
            self.page(len(canonical(self.receiver.value)) + 1)
        with self.assertRaises(ValueError):
            self.action(dict(valid, unit='MU_MISSING'))

    def test_original_arm_refuses_paged_focus_and_legacy_focus_is_unchanged(self):
        with self.assertRaises(ValueError):
            reader.action_result(dict(action='focus_page', unit=UNIT, offset=0), {'arm': 'original'}, None, {})
        value, candidate = self.action(dict(action='focus', unit=UNIT))
        self.assertIsNone(candidate)
        self.assertEqual(canonical(value), canonical(self.receiver.value))
        self.assertEqual(self.receiver.calls, [('transport_focus', {'unit': UNIT})])

    def test_invalid_full_focus_identity_shape_and_size_refuse_without_page(self):
        original = copy.deepcopy(self.receiver.value)
        for key, value in (('identity', 'STS1:' + 'b' * 64), ('selected_unit', 'MU_OTHER'),
                           ('schema', 'transport/focus/999'), ('padding', 'x' * inputs.CAP)):
            self.receiver.value = dict(original, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.page(0)
        self.receiver.value = original
        self.receiver.failure = 'whole package integrity check failed'
        with self.assertRaisesRegex(ValueError, 'whole package integrity'):
            self.page(0)

    def test_describe_and_new_interface_recommend_complete_bounded_paging(self):
        transport, original = reader.describe('transport'), reader.describe('original')
        self.assertIn('focus_page', transport['actions'])
        self.assertIn('focus', transport['actions'])
        self.assertNotIn('focus_page', original['actions'])
        self.assertEqual(transport['focus_page_response_bytes_including_newline'], 8192)
        self.assertEqual(transport['maximum_calls_including_refusals'], 32)
        self.assertEqual(inputs.CAP, 131072)
        state = dict(config=dict(arm='transport', python=dict(path=sys.executable)), task=b'Draft data only.')
        text = preparation.interface(self.root, state, {}).decode('utf-8')
        for required in ('focus_page', 'next_offset', 'sha256 before parsing', '8192 bytes',
                         'Partial pages are not complete', 'remaining 32-call session', 'Legacy focus'):
            self.assertIn(required, text)

    def test_each_worker_call_rechecks_frozen_inputs_and_stops_before_log_on_corruption(self):
        frozen = (self.manifest, self.root / 'content', {})
        with mock.patch.object(reader.resource, 'setrlimit'):
            with mock.patch.object(inputs, 'frozen_manifest', return_value=frozen) as freeze:
                with mock.patch.object(inputs, 'transport_receiver', side_effect=lambda *args: SyntheticReceiver()) as construct:
                    first = inputs.json_value(reader.worker(self.args({'action': 'describe'})), inputs.CAP)
                    second = inputs.json_value(reader.worker(self.args(dict(action='focus_page', unit=UNIT, offset=0))), inputs.CAP)
                    self.assertEqual((first['status'], second['status']), ('OK', 'OK'))
                    before = {path.name: path.read_bytes() for path in (self.root / 'session').iterdir()}
                    freeze.side_effect = ValueError('frozen package changed')
                    with self.assertRaisesRegex(ValueError, 'frozen package changed'):
                        reader.worker(self.args(dict(action='focus_page', unit=UNIT, offset=4096)))
                    self.assertEqual(freeze.call_count, 3)
                    self.assertEqual(construct.call_count, 2)
        self.assertEqual({path.name: path.read_bytes() for path in (self.root / 'session').iterdir()}, before)
        self.assertFalse((self.root / 'session/call-03.json').exists())

    def test_admitted_refusals_are_counted_and_no_partial_candidate_is_saved(self):
        self.assertEqual(self.logged({'action': 'describe'})['call'], 1)
        failed = self.logged(dict(action='focus_page', unit=UNIT, offset=True))
        self.assertEqual((failed['status'], failed['call']), ('REFUSED', 2))
        good = self.logged(dict(action='focus_page', unit=UNIT, offset=0))
        self.assertEqual((good['status'], good['call']), ('OK', 3))
        self.assertLessEqual(len((self.root / 'session/response-03.json').read_bytes()), 8192)
        self.assertFalse((self.root / 'session/candidate.json').exists())

    def test_session_call_bound_stays_32_with_paged_focus(self):
        self.logged({'action': 'describe'})
        for number in range(2, 33):
            answer = self.logged(dict(action='focus_page', unit=UNIT, offset=0))
            self.assertEqual((answer['status'], answer['call']), ('OK', number))
        before = sorted(path.name for path in (self.root / 'session').iterdir())
        with self.assertRaises(ValueError):
            self.logged(dict(action='focus_page', unit=UNIT, offset=4096))
        self.assertEqual(sorted(path.name for path in (self.root / 'session').iterdir()), before)
        self.assertEqual(sessions.MAX_CALLS, 32)


if __name__ == '__main__':
    unittest.main()
