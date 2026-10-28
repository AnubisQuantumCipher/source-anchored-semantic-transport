"""Bounded UTF-8 source pages and log-derived coverage before first narrative."""

import base64
import hashlib
import json
import unittest

import transport_package as package
import transport_recipient_runner as runner
import test_transport_recipient_runner as fixtures
from transport_schema import canonical

OLD_TEST_SHA256 = 'b616a4368068f88d8dba8b7ad5a07fe4496d082b186efaaf6b6834f9da4b1be1'
NARRATIVE = b'{"schema":"transport/recipient-narrative/1","narrative":"Authored paging control."}'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare_source(case, data, media_type='text/plain; charset=utf-8'):
    plan = {'schema': 'transport/transport-plan/1', 'sources': [{'id': 'RECIPE',
        'label': 'Authored paging fixture', 'media_type': media_type,
        'provenance': 'Controlled byte fixture; no execution authority.'}],
        'interpretations': [], 'uncertainties': [], 'relations': []}
    pair = package.encode((data,), canonical(plan))
    target = case.handoff / 'inputs/recipe'
    (target / 'share.txt').write_bytes(pair.text)
    (target / 'meaning.zip').write_bytes(pair.archive)


class PageLayoutTests(unittest.TestCase):
    def test_existing_35_control_source_remains_byte_exact(self):
        path = fixtures.ROOT / 'tests/test_transport_recipient_runner.py'
        self.assertEqual(digest(path.read_bytes()), OLD_TEST_SHA256)

    def test_ascii_sizes_empty_exact_boundary_tail_and_maximum(self):
        self.assertEqual(runner.PAGE_BYTES, 4096)
        self.assertEqual(runner.MAX_PAGES, 17)
        for size in (0, 1, 4095, 4096, 4097, 65_536):
            data = b'A' * size
            expected = [[begin, min(begin + 4096, size)] for begin in range(0, size, 4096)] or [[0, 0]]
            with self.subTest(size=size):
                self.assertEqual(runner.page_spans(data), expected)
                self.assertEqual(b''.join(data[a:b] for a, b in expected), data)
                self.assertLessEqual(len(expected), 17)

    def test_multibyte_boundary_is_greedy_and_never_splits_utf8(self):
        for tail in ('é', '€', '🙂', 'é€🙂'):
            prefix, suffix = b'A' * 4095, tail.encode()
            data = prefix + suffix
            with self.subTest(tail=tail):
                self.assertEqual(runner.page_spans(data), [[0, len(prefix)], [len(prefix), len(data)]])
                for begin, end in runner.page_spans(data):
                    self.assertEqual(data[begin:end].decode().encode(), data[begin:end])
                    self.assertLessEqual(end - begin, 4096)

    def test_invalid_utf8_over_budget_and_nonbytes_layouts_refuse(self):
        for data in (b'\xff', b'\xf0\x9f', b'A' * 65_537, 'text', bytearray(b'A')):
            with self.subTest(data_type=type(data).__name__), self.assertRaises((ValueError, UnicodeError)):
                runner.page_spans(data)


class PaginationTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.RecipientRunnerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def action(self, *arguments, profile='paged'):
        return self.case.run_action('--profile', profile, *arguments)

    def start_recovered(self, data=b'A', media_type='text/plain; charset=utf-8'):
        prepare_source(self.case, data, media_type)
        result, value = self.action('describe')
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual(value['profile'], 'paged')
        result, value = self.action('recover', 'recipe', 'RECIPE')
        self.assertEqual(result.returncode, 0, value)
        return data

    def finish(self):
        return self.action('finish', '--data-base64', base64.b64encode(NARRATIVE).decode())

    def assert_page(self, value, data, index, span, count):
        self.assertEqual(set(value), {'status', 'domain', 'source', 'package_identity', 'source_identity',
            'page_index', 'total_pages', 'span', 'slice_sha256', 'text', 'more', 'execution_authority'})
        self.assertEqual((value['status'], value['domain'], value['source']), ('SOURCE_PAGE', 'recipe', 'RECIPE'))
        self.assertEqual(value['source_identity'], {'bytes': len(data), 'sha256': digest(data),
            'media_type': 'text/plain; charset=utf-8'})
        metadata = json.loads((self.case.session / 'recovered/recipe/RECIPE.json').read_bytes())['metadata']
        self.assertEqual(value['package_identity'], metadata['identity'])
        self.assertEqual((value['page_index'], value['total_pages'], value['span']), (index, count, span))
        part = data[span[0]:span[1]]
        self.assertEqual(value['text'].encode(), part)
        self.assertEqual(value['slice_sha256'], digest(part))
        self.assertLessEqual(len(part), 4096)
        self.assertIs(value['more'], index + 1 < count)
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertLessEqual(len(runner.process.canonical(value)) + 1, runner.PAGE_RESPONSE_CAP)

    def test_unicode_pages_identity_exact_log_bytes_and_complete_finish(self):
        data = self.start_recovered(b'A' * 4095 + '🙂é€'.encode())
        spans = [[0, 4095], [4095, len(data)]]
        parts = []
        for index, span in enumerate(spans):
            result, value = self.action('page', 'recipe', 'RECIPE', str(index))
            self.assertEqual(result.returncode, 0, value)
            self.assert_page(value, data, index, span, len(spans))
            parts.append(value['text'].encode())
            directory = self.case.last_action()
            self.assertEqual((directory / 'response.bin').read_bytes(), result.stdout)
            self.assertEqual(json.loads((directory / 'record.json').read_bytes())['children'], [])
        self.assertEqual(b''.join(parts), data)
        checked = runner.verify_session(self.case.session)
        self.assertEqual(checked['page_coverage'], {'recipe:RECIPE': 2})
        result, value = self.finish()
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual((self.case.session / 'candidate.json').read_bytes(), NARRATIVE)

    def test_maximum_source_can_require_and_cover_all_seventeen_pages(self):
        data = b'A' * 4095 + ('🙂' * 15_360).encode() + b'Z'
        self.assertEqual(len(data), 65_536)
        self.start_recovered(data)
        spans = runner.page_spans(data)
        self.assertEqual(len(spans), 17)
        parts = []
        for index, span in enumerate(spans):
            result, value = self.action('page', 'recipe', 'RECIPE', str(index))
            self.assertEqual(result.returncode, 0, value)
            self.assert_page(value, data, index, span, 17)
            parts.append(value['text'].encode())
        self.assertEqual(b''.join(parts), data)
        self.assertEqual(self.finish()[0].returncode, 0)

    def test_empty_text_needs_its_single_empty_page_before_finish(self):
        data = self.start_recovered(b'')
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())
        result, value = self.action('page', 'recipe', 'RECIPE', '0')
        self.assertEqual(result.returncode, 0, value)
        self.assert_page(value, data, 0, [0, 0], 1)
        self.assertEqual(self.finish()[0].returncode, 0)

    def test_escape_heavy_pages_are_bounded_and_instruction_text_is_only_data(self):
        data = b'$(touch SENTINEL) __import__("os")\n' + b'\x00' * 4096
        self.start_recovered(data)
        parts = []
        for index, span in enumerate(runner.page_spans(data)):
            result, value = self.action('page', 'recipe', 'RECIPE', str(index))
            self.assertEqual(result.returncode, 0, value)
            self.assert_page(value, data, index, span, 2)
            self.assertLessEqual(len(result.stdout), 32_768)
            parts.append(value['text'].encode())
        self.assertEqual(b''.join(parts), data)
        self.assertFalse((self.case.root / 'SENTINEL').exists())

    def test_page_requires_recovery_and_paged_profile_refuses_full_view(self):
        self.assertEqual(self.action('describe')[0].returncode, 0)
        self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        self.assertEqual(self.action('recover', 'recipe', 'RECIPE')[0].returncode, 0)
        self.assertNotEqual(self.action('view', 'recipe', 'RECIPE')[0].returncode, 0)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())

    def test_canonical_decimal_indices_unknown_domain_source_and_bool_api_refuse(self):
        self.start_recovered()
        for index in ('-1', '+0', '00', '0.0', 'True', '０', '17', '9' * 128):
            with self.subTest(index=index):
                self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', index)[0].returncode, 0)
        for domain, source in (('MISSING', 'RECIPE'), ('recipe', 'HISTORY'), ('opaque', 'RECIPE')):
            self.assertNotEqual(self.action('page', domain, source, '0')[0].returncode, 0)
        for index in (True, False, -1, 17):
            with self.subTest(index=index), self.assertRaises(ValueError):
                runner.page_value(self.case.session, 'recipe', 'RECIPE', index)
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)

    def test_skips_repeats_out_of_range_and_refusals_cannot_advance_coverage(self):
        self.start_recovered(b'A' * 4097)
        self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '1')[0].returncode, 0)
        self.assertEqual(runner.verify_session(self.case.session)['page_coverage'], {})
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        for index in ('0', '2'):
            self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', index)[0].returncode, 0)
        self.assertEqual(runner.verify_session(self.case.session)['page_coverage'], {'recipe:RECIPE': 1})
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '1')[0].returncode, 0)
        self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '2')[0].returncode, 0)
        self.assertEqual(self.finish()[0].returncode, 0)

    def test_finish_requires_nonempty_recovery_set_and_complete_contiguous_pages(self):
        self.assertEqual(self.action('describe')[0].returncode, 0)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.case.session = self.case.root / 'partial-coverage'
        self.start_recovered(b'A' * 4097)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '1')[0].returncode, 0)
        self.assertEqual(self.finish()[0].returncode, 0)

    def test_every_recovered_source_must_have_its_own_pages(self):
        self.start_recovered()
        self.assertEqual(self.action('recover', 'oral-history', 'HISTORY')[0].returncode, 0)
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())
        self.assertEqual(self.action('page', 'oral-history', 'HISTORY', '0')[0].returncode, 0)
        self.assertEqual(self.finish()[0].returncode, 0)

    def test_binary_and_invalid_utf8_refuse_without_display_fallback(self):
        for index, (data, media) in enumerate(((b'ASCII', 'application/octet-stream'), (b'\xff\x00', 'text/plain'))):
            self.case.session = self.case.root / ('opaque-' + str(index))
            self.start_recovered(data, media)
            self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
            self.assertNotEqual(self.action('view', 'recipe', 'RECIPE')[0].returncode, 0)
            self.assertNotEqual(self.finish()[0].returncode, 0)
            self.assertFalse((self.case.session / 'candidate.json').exists())

    def test_profile_is_session_bound_and_default_full_behavior_is_preserved(self):
        self.assertEqual(self.action('describe')[0].returncode, 0)
        self.assertNotEqual(self.action('describe', profile='full')[0].returncode, 0)
        self.case.session = self.case.root / 'full-profile'
        self.assertEqual(self.case.run_action('describe')[0].returncode, 0)
        self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '0', profile='full')[0].returncode, 0)
        self.assertEqual(self.case.run_action('finish', stdin=NARRATIVE)[0].returncode, 0)

    def test_recovered_bytes_or_binding_tamper_and_missing_page_log_fail_closed(self):
        self.start_recovered(b'Original')
        for path in (self.case.session / 'recovered/recipe/RECIPE.bin',
                     self.case.session / 'recovered/recipe/RECIPE.json'):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            self.assertNotEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
            path.write_bytes(original)
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        (self.case.last_action() / 'response.bin').unlink()
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())

    def test_rehashed_page_response_tamper_including_bool_int_aliases_refuses(self):
        self.start_recovered(b'A')
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        directory = self.case.last_action()
        response_path, record_path = directory / 'response.bin', directory / 'record.json'
        response_original, record_original = response_path.read_bytes(), record_path.read_bytes()
        original = json.loads(response_original)
        variants = [dict(original, text='Z'), dict(original, span=[0, 0]),
            dict(original, slice_sha256='0' * 64), dict(original, package_identity='0' * 64),
            dict(original, page_index=False), dict(original, total_pages=True),
            dict(original, span=[False, 1]), dict(original, more=0),
            dict(original, source_identity=dict(original['source_identity'], bytes=True)),
            dict(original, source_identity=dict(original['source_identity'], sha256='0' * 64))]
        for value in variants:
            try:
                altered = runner.process.canonical(value) + b'\n'
                response_path.write_bytes(altered)
                record = json.loads(record_original)
                record['response_sha256'] = digest(altered)
                record_path.write_bytes(runner.process.canonical(record))
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'page response'):
                    runner.verify_session(self.case.session)
            finally:
                response_path.write_bytes(response_original)
                record_path.write_bytes(record_original)
        self.assertEqual(runner.verify_session(self.case.session)['page_coverage'], {'recipe:RECIPE': 1})

    def test_rehashed_finished_history_cannot_remove_its_successful_page_coverage(self):
        self.start_recovered(b'A')
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        page_directory = self.case.last_action()
        self.assertEqual(self.finish()[0].returncode, 0)
        finish_directory = self.case.last_action()
        candidate = (self.case.session / 'candidate.json').read_bytes()
        response = runner.process.canonical({'status': 'REFUSED', 'reason': 'Authored omitted coverage control.'}) + b'\n'
        (page_directory / 'response.bin').write_bytes(response)
        page_record = json.loads((page_directory / 'record.json').read_bytes())
        page_record['launcher_exit'] = 1
        page_record['response_sha256'] = digest(response)
        page_bytes = runner.process.canonical(page_record)
        (page_directory / 'record.json').write_bytes(page_bytes)
        finish_record = json.loads((finish_directory / 'record.json').read_bytes())
        finish_record['previous_sha256'] = digest(page_bytes)
        (finish_directory / 'record.json').write_bytes(runner.process.canonical(finish_record))
        with self.assertRaisesRegex(ValueError, 'coverage'):
            runner.verify_session(self.case.session)
        self.assertEqual((self.case.session / 'candidate.json').read_bytes(), candidate)

    def test_rehashed_page_request_cannot_skip_contiguous_coverage(self):
        self.start_recovered(b'A' * 4097)
        self.assertEqual(self.action('page', 'recipe', 'RECIPE', '0')[0].returncode, 0)
        directory = self.case.last_action()
        request_path, response_path, record_path = [directory / name for name in ('request.json', 'response.bin', 'record.json')]
        request = json.loads(request_path.read_bytes())
        request['page_index'] = 1
        request_path.write_bytes(runner.process.canonical(request))
        response_path.write_bytes(runner.process.canonical(runner.page_value(self.case.session, 'recipe', 'RECIPE', 1)) + b'\n')
        record = json.loads(record_path.read_bytes())
        record['request_sha256'] = digest(request_path.read_bytes())
        record['response_sha256'] = digest(response_path.read_bytes())
        record_path.write_bytes(runner.process.canonical(record))
        with self.assertRaisesRegex(ValueError, 'page log sequence'):
            runner.verify_session(self.case.session)
        self.assertNotEqual(self.finish()[0].returncode, 0)
        self.assertFalse((self.case.session / 'candidate.json').exists())


if __name__ == '__main__':
    unittest.main()
