"""Developmental deterministic data-boundary controls; no semantic truth oracle."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sentinel_v1 import common as c


class BoundaryTests(unittest.TestCase):
    def test_canonical_exact_unicode(self):
        raw = '{"name":"Compressed RAM","quantity":"225Q","µ":"100 ms"}'.encode()
        self.assertEqual(c.canonical(c.parse(raw)), raw)
        self.assertEqual(c.identity(raw)['bytes'], len(raw))

    def test_bad_json_and_noncanonical_refuse(self):
        values = (b'{"x":1,"x":2}', b'{ "x":1}', b'{"x":1.0}',
                  b'{"x":NaN}', b'{"x":Infinity}', b'{}\n', b'\xff',
                  b'[' * 17 + b'0' + b']' * 17, b'"unterminated',
                  b'1' * 5000, b'{"x":"\\ud800"}')
        for raw in values:
            with self.subTest(raw=raw[:40]), self.assertRaises(c.SentinelError):
                c.parse(raw)

    def test_types_integer_and_shape(self):
        for value in (True, 1.0, '1', None, -1, 11):
            with self.subTest(value=value), self.assertRaises(c.SentinelError):
                c.integer(value, 0, 10)
        for value in ({'extra': 1}, [], {'x': 1, 'y': 2}):
            with self.assertRaises(c.SentinelError):
                c.fields(value, ('x',))
        self.assertEqual(c.fields({'x': 1}, ('x',)), {'x': 1})

    def test_unsupported_values_and_resource_bounds(self):
        for value in (1.0, set(), object(), {'x': [0] * 262144}, 2 ** 63):
            with self.assertRaises(c.SentinelError):
                c.canonical(value)
        for raw, cap in ((b'{}', 1), (b'{}', True), (b'', 10)):
            with self.assertRaises(c.SentinelError):
                c.parse(raw, cap)

    def test_registry_snapshot_before_root_hash(self):
        raw = b'evidence'; key = c.digest(raw)
        source = {key: raw}
        held = c.digest(c.canonical({key: c.identity(raw)}))
        manifest = c.canonical({key: c.identity(raw)})
        original = c.digest
        def interleaved(value):
            if value == manifest:
                source.clear()
            return original(value)
        with patch.object(c, 'digest', side_effect=interleaved):
            snapshot = c.registry_snapshot(source, held)
        self.assertEqual(snapshot, {key: raw})
        self.assertEqual(source, {})

    def test_registry_mismatch_and_mutable_bytes_refuse(self):
        raw = b'evidence'; key = c.digest(raw)
        held = c.digest(c.canonical({key: c.identity(raw)}))
        for registry, root in (({key: b'edited'}, held), ({key: bytearray(raw)}, held),
                               ({key: raw}, '0' * 64), ({}, held)):
            with self.assertRaises(c.SentinelError):
                c.registry_snapshot(registry, root)

    def test_aggregate_rejected_before_json_materialization(self):
        values = (['x' * 1048576, 'y' * 1048576], ['\x00' * 200000])
        for value in values:
            with patch.object(c.json, 'dumps', side_effect=AssertionError('must preflight')):
                with self.assertRaises(c.SentinelError):
                    c.canonical(value)

    def test_json_size_preflight_preserves_exact_bytes(self):
        values = ([None, True, False, -13], {'µ': '"\\😄\n\t\x00'}, [], {}, 'λ')
        for value in values:
            raw = c.json.dumps(value, sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode()
            self.assertEqual(c.canonical(value), raw)
            self.assertEqual(c.parse(raw), value)

    def test_serialization_uses_private_bounded_tree(self):
        original = {'a': ['small']}
        dumps = c.json.dumps
        seen = []
        def mutate_caller(value, **options):
            original['a'].extend(['x' * 1048576, 'y' * 1048576])
            seen.append(value is original or value['a'] is original['a'])
            return dumps(value, **options)
        with patch.object(c.json, 'dumps', side_effect=mutate_caller):
            self.assertEqual(c.canonical(original), b'{"a":["small"]}')
        self.assertEqual(seen, [False])

    def test_exact_container_depth_empty_and_nonempty(self):
        for leaf in ([], 0):
            for depth in (16, 17):
                value = leaf
                for _ in range(depth - (1 if type(leaf) is list else 0)):
                    value = [value]
                if depth == 16:
                    raw = c.canonical(value)
                    self.assertEqual(c.parse(raw), value)
                else:
                    with self.assertRaises(c.SentinelError): c.canonical(value)


if __name__ == '__main__':
    unittest.main()
