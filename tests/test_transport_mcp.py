"""Actual SDK stdio integration and adversarial read-only adapter checks."""

import asyncio
import base64
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import transport_mcp as adapter
import transport_package as package

ROOT = Path(__file__).resolve().parents[1]
PAIR = ROOT / 'deliverables/semantic-transport-v2/controller'
SOURCE = ROOT / 'fixtures/semantic-examples-v1/controller.txt'
SERVER = ROOT / 'tools/transport_mcp.py'


def supplied_pair():
    share, archive = (PAIR / 'share.txt').read_bytes(), (PAIR / 'meaning.zip').read_bytes()
    identity = package.decode(share, archive)['identity']
    return share, archive, identity


def server_parameters(identity):
    return StdioServerParameters(command=sys.executable,
        args=['-I', '-B', '-Werror', str(SERVER), str(PAIR / 'share.txt'),
              '--archive', str(PAIR / 'meaning.zip'), '--expect-pair', identity], cwd=str(ROOT))


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.share, self.archive, self.identity = supplied_pair()
        self.receiver = adapter.Receiver(self.share, self.archive, self.identity)

    def test_exact_page_matches_separately_held_source(self):
        result = self.receiver.call('transport_source_page', dict(source='SOURCE', offset=0))
        original = SOURCE.read_bytes()
        self.assertEqual(base64.b64decode(result['base64']), original)
        self.assertEqual(result['utf8'].encode(), original)
        self.assertEqual(result['source_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(result['span'], [0, len(original)])
        self.assertEqual(result['authority'], 'NONE')
        self.assertTrue(result['end'])

    def test_closed_arguments_unknown_units_and_authority_are_not_silently_accepted(self):
        cases = [('transport_inspect', {'path': '/etc/passwd'}),
                 ('transport_source_page', {'source': '../escape', 'offset': 0}),
                 ('transport_source_page', {'source': 'SOURCE', 'offset': True}),
                 ('transport_source_page', {'source': 'SOURCE', 'offset': -1}),
                 ('transport_source_page', {'source': 'SOURCE', 'offset': 65537}),
                 ('transport_source_page', {'source': 'MISSING', 'offset': 0}),
                 ('transport_source_page', {'source': 'SOURCE', 'offset': 999}),
                 ('transport_focus', {'unit': 'MISSING'}), ('execute', {})]
        for name, arguments in cases:
            with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                self.receiver.call(name, arguments)

    def test_checked_focus_and_metadata_match_authoritative_codec(self):
        self.assertEqual(self.receiver.call('transport_inspect', {}),
                         package.inspect(self.share, self.archive))
        self.assertEqual(self.receiver.call('transport_focus', {'unit': 'MEANING'}),
                         package.focus(self.share, self.archive, 'MEANING'))
        self.assertNotIn('data', self.receiver.call('transport_inspect', {})['sources'][0])

    def test_wrong_pair_pin_and_truncated_archive_refuse(self):
        with self.assertRaises(ValueError):
            adapter.Receiver(self.share, self.archive, 'STS1:' + '0' * 64)
        with self.assertRaises(ValueError):
            adapter.Receiver(self.share, self.archive[:-1], self.identity)

    def test_missing_or_incompatible_sdk_dependencies_refuse(self):
        adapter.check_dependencies()
        for name in ('mcp', 'anyio', 'pydantic-core'):
            def wrong_version(requested):
                return '0.0.0' if requested == name else adapter.SDK_DEPENDENCIES[requested]
            with self.subTest(name=name), patch.object(adapter.importlib.metadata, 'version', wrong_version):
                with self.assertRaises(ValueError):
                    adapter.check_dependencies()
        with patch.object(adapter.importlib.metadata, 'version', side_effect=adapter.importlib.metadata.PackageNotFoundError('mcp')):
            with self.assertRaises(adapter.importlib.metadata.PackageNotFoundError):
                adapter.check_dependencies()

    def test_binary_and_empty_objects_remain_exact_without_fabricated_utf8(self):
        fixture = ROOT / 'fixtures/transport-general-v1'
        plan = (fixture / 'opaque-plan.json').read_bytes()
        encoded = package.encode(((fixture / 'opaque.bin').read_bytes(), b''),
                                 plan, 'attached:meaning.zip', 4096)
        identity = package.decode(encoded.text, encoded.archive)['identity']
        receiver = adapter.Receiver(encoded.text, encoded.archive, identity)
        page = receiver.call('transport_source_page', dict(source='OPAQUE', offset=0))
        self.assertEqual(base64.b64decode(page['base64']), bytes(range(256)))
        self.assertIsNone(page['utf8'])
        empty = receiver.call('transport_source_page', dict(source='EMPTY', offset=0))
        self.assertEqual(base64.b64decode(empty['base64']), b'')
        self.assertTrue(empty['end'])

    def test_response_size_refuses_instead_of_truncating(self):
        with self.assertRaises(ValueError):
            adapter.reply({'text': '\\' * 65536})

    def test_bounded_input_accepts_complete_lines_and_refuses_size_count_utf8_and_truncation(self):
        async def read(data, count=0):
            stream = adapter.BoundedInput(io.BytesIO(data))
            stream.lines = count
            return await stream.__anext__()
        self.assertEqual(asyncio.run(read(b'{}\n')), '{}\n')
        for data, count in [(b'x' * 8193, 0), (b'{}', 0), (b'\xff\n', 0), (b'{}\n', 128)]:
            with self.subTest(size=len(data), count=count), self.assertRaises((ValueError, UnicodeError)):
                asyncio.run(read(data, count))

    def test_real_stdio_sdk_discovery_inspect_page_focus_and_error(self):
        async def run():
            with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
                async with stdio_client(server_parameters(self.identity), errlog=errors) as (read, write):
                    async with ClientSession(read, write) as session:
                        initialized = await session.initialize()
                        self.assertEqual(initialized.serverInfo.version, '1.0.0')
                        discovered = (await session.list_tools()).tools
                        self.assertEqual({item.name for item in discovered},
                                         {'transport_inspect', 'transport_source_page', 'transport_focus'})
                        self.assertTrue(all(item.annotations.readOnlyHint for item in discovered))
                        inspected = await session.call_tool('transport_inspect', {})
                        self.assertFalse(inspected.isError)
                        self.assertEqual(json.loads(inspected.content[0].text)['identity'], self.identity)
                        page = await session.call_tool('transport_source_page', {'source': 'SOURCE', 'offset': 0})
                        self.assertFalse(page.isError)
                        self.assertEqual(base64.b64decode(json.loads(page.content[0].text)['base64']), SOURCE.read_bytes())
                        focused = await session.call_tool('transport_focus', {'unit': 'MEANING'})
                        self.assertFalse(focused.isError)
                        invalid = await session.call_tool('transport_source_page', {'source': 'SOURCE', 'offset': True})
                        self.assertTrue(invalid.isError)
                        after_error = await session.call_tool('transport_inspect', {})
                        self.assertFalse(after_error.isError)
                errors.seek(0)
                self.assertNotIn('Traceback', errors.read())
        asyncio.run(asyncio.wait_for(run(), timeout=30))

    def test_real_startup_wrong_identity_and_wire_bound_are_explicit_failures(self):
        for identity, data in [('STS1:' + '0' * 64, b''), (self.identity, b'x' * 8193 + b'\n')]:
            params = server_parameters(identity)
            result = subprocess.run([params.command, *params.args], input=data, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'SOURCE', result.stdout)


if __name__ == '__main__':
    unittest.main()
