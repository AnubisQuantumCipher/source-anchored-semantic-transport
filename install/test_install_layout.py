"""Deterministic controls for the closed source and generated transformation contract."""

import ast
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_source import inventory
from transport_install_layout import (assignment, checked_json, exact_tree, generated, input_names,
                                      launcher, package_source, pin_value, source_inputs)
from transport_install_support import read_regular, sha

ROOT = Path(__file__).resolve().parents[1]


class LayoutTests(unittest.TestCase):
    def test_inventory_reproduces_and_closed_inputs(self):
        expected = inventory(ROOT)
        self.assertEqual(expected, read_regular(ROOT / 'install/SOURCE.json'))
        manifest, files = source_inputs(ROOT, sha(expected))
        self.assertEqual(set(files), input_names())
        self.assertEqual(len(manifest['files']), len(files))

    def test_wrong_held_source_identity_refused(self):
        with self.assertRaisesRegex(ValueError, 'independently held'):
            source_inputs(ROOT, '0' * 64)

    def test_named_digest_substitution_only(self):
        before = b"P = '" + b'0' * 64 + b"'\ntext = 'untouched'\n"
        after = assignment(before, 'P', '0' * 64, '1' * 64)
        self.assertEqual(after, before.replace(b'0' * 64, b'1' * 64))
        self.assertEqual(pin_value(after, 'P'), '1' * 64)

    def test_duplicate_assignment_refused(self):
        raw = b"P = '" + b'0' * 64 + b"'\nP = '" + b'1' * 64 + b"'\n"
        with self.assertRaisesRegex(ValueError, 'multiple'):
            assignment(raw, 'P', '0' * 64, '2' * 64)

    def test_missing_expected_pin_refused(self):
        with self.assertRaises(ValueError):
            assignment(b"P = '" + b'1' * 64 + b"'\n", 'P', '0' * 64, '2' * 64)

    def test_original_package_unchanged_except_declared_native_pin(self):
        original = read_regular(ROOT / 'tools/transport_package.py')
        current = package_source(original, '1' * 64, 'aarch64')
        expected = assignment(original, 'CORE_SHA256', pin_value(original, 'CORE_SHA256'), '1' * 64)
        self.assertEqual(current, expected)
        self.assertEqual(read_regular(ROOT / 'tools/transport_package.py'), original)

    def test_x86_transformation_is_syntax_checked_not_execution_qualified(self):
        original = read_regular(ROOT / 'tools/transport_package.py')
        converted = package_source(original, '1' * 64, 'x86_64')
        ast.parse(converted)
        self.assertIn(b"platform.machine() == 'x86_64'", converted)
        self.assertNotIn(b"'platform': 'Linux-aarch64'", converted)

    def test_unknown_architecture_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            package_source(b'', '1' * 64, 'unknown')

    def test_launcher_expansion_and_no_site(self):
        template = read_regular(ROOT / 'install/launcher.py.in')
        result = launcher(template, '2' * 64, '/usr/bin/python3.14')
        self.assertTrue(result.startswith(b'#!/usr/bin/python3.14 -IS\n'))
        self.assertNotIn(b'@MANIFEST@', result)
        ast.parse(result)

    def test_unsafe_launcher_path_refused(self):
        for path in ('relative', '/tmp/python with spaces', '/tmp/python\ncode'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                launcher(read_regular(ROOT / 'install/launcher.py.in'), '2' * 64, path)

    def test_json_duplicate_depth_and_truncation_refused(self):
        for raw in (b'{"a":1,"a":2}', b'[' * 13 + b']' * 13, b'{"a":'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                checked_json(raw)

    def test_exact_tree_refuses_extra_missing_and_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'file').write_bytes(b'x')
            exact_tree(root, {'file'})
            for expected in (set(), {'file', 'absent'}):
                with self.assertRaises(ValueError):
                    exact_tree(root, expected)
            (root / 'link').symlink_to('file')
            with self.assertRaises(ValueError):
                exact_tree(root, {'file', 'link'})

    def test_generated_uses_only_declared_runtime_members(self):
        _, files = source_inputs(ROOT, sha(inventory(ROOT)))
        result = generated(files, b'not an executable - layout test only', 'aarch64')
        self.assertTrue(all(name.startswith(('tools/', 'bin/')) or name in ('LICENSE', 'LICENSE-SCOPE.md')
                            for name in result))
        self.assertNotIn('transport.gpr', result)


if __name__ == '__main__':
    unittest.main()
