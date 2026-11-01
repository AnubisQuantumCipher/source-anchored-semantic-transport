"""Pure profile partition counterexamples; never build or execute analyzed code."""
import ast
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bounded_source_check', ROOT / 'install/check_source.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ProfileControls(unittest.TestCase):
    def roster(self, root):
        return [root / 'tools' / name for name in CHECK.DOCUMENT_NAMES]

    def test_original_budget_allows_128_and_refuses_129_legacy(self):
        root = Path('/declared')
        legacy = [root / 'tools' / ('legacy_%03d.py' % index) for index in range(129)]
        self.assertEqual(len(CHECK.partition(legacy[:128] + self.roster(root), root)[0][1]), 128)
        with self.assertRaises(ValueError):
            CHECK.partition(legacy + self.roster(root), root)

    def test_every_missing_declared_document_member_refuses(self):
        root = Path('/declared')
        document = self.roster(root)
        for absent in document:
            with self.subTest(absent=absent), self.assertRaises(ValueError):
                CHECK.partition([root / 'tools/legacy.py'] + [path for path in document if path != absent], root)

    def test_unknown_document_name_remains_in_legacy_profile(self):
        root = Path('/declared')
        unknown = root / 'tools/transport_document_future.py'
        legacy, document = CHECK.partition([unknown] + self.roster(root), root)
        self.assertEqual(legacy[1], [unknown])
        self.assertNotIn(unknown, document[1])

    def test_partition_is_complete_disjoint_and_duplicate_refuses(self):
        root = Path('/declared')
        selected = [root / 'install/legacy.py'] + self.roster(root)
        profiles = CHECK.partition(selected, root)
        flattened = [path for _label, paths in profiles for path in paths]
        self.assertCountEqual(flattened, selected)
        with self.assertRaises(ValueError):
            CHECK.partition(selected + [selected[0]], root)

    def test_standalone_parses_every_selected_file_and_bounds_new_functions(self):
        profiles = CHECK.sources()
        selected = [path for _label, paths in profiles for path in paths]
        seen = []
        original = ast.parse
        def tracked(raw, filename):
            seen.append(Path(filename))
            return original(raw, filename=filename)
        with patch.object(CHECK.ast, 'parse', side_effect=tracked):
            CHECK.main()
        self.assertCountEqual(seen, selected)
        self.assertTrue(all(CHECK.bounded_functions(ROOT / 'tools' / name) for name in CHECK.DOCUMENT_NAMES))

    def test_declared_document_long_function_and_invalid_syntax_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'build_document_decoder.py'
            path.write_text('def oversized():\n' + '    pass\n' * 60)
            with patch.object(CHECK, 'bounded_functions', return_value=True):
                with self.assertRaises(ValueError):
                    CHECK.analyze([path])
            path.write_text('await missing_context()\n')
            with self.assertRaises(SyntaxError):
                CHECK.analyze([path])


class ExtensionProfileControls(unittest.TestCase):
    def roster(self, root):
        document = [root / 'tools' / name for name in CHECK.DOCUMENT_NAMES]
        extension = [root / 'tools' / name for name in CHECK.TRANSPORT_EXTENSION_NAMES]
        return document, extension

    def test_extension_roster_is_explicit_unique_and_disjoint(self):
        expected = ('transport_document_supervisor.py', 'transport_document_namespace.py',
                    'transport_workflow_cli.py', 'transport_workflow_endpoint.py',
                    'transport_workflow_mcp.py')
        self.assertEqual(CHECK.TRANSPORT_EXTENSION_NAMES, expected)
        self.assertEqual(len(set(expected)), 5)
        self.assertFalse(set(expected).intersection(CHECK.DOCUMENT_NAMES))
        self.assertEqual(len(CHECK.DOCUMENT_NAMES), 9)

    def test_unchanged_128_129_legacy_bound_with_complete_extension(self):
        root = Path('/declared')
        document, extension = self.roster(root)
        legacy = [root / 'tools' / ('legacy_%03d.py' % index) for index in range(129)]
        profiles = CHECK.partition(legacy[:128] + document + extension, root)
        self.assertEqual(profiles[0], ('legacy', legacy[:128]))
        self.assertEqual(profiles[-1], ('transport-extension/1', sorted(extension)))
        with self.assertRaisesRegex(ValueError, 'legacy source file bound exceeded'):
            CHECK.partition(legacy + document + extension, root)

    def test_every_partial_extension_roster_refuses(self):
        root = Path('/declared')
        document, extension = self.roster(root)
        for absent in extension:
            selected = [root / 'tools/legacy.py'] + document + [p for p in extension if p != absent]
            with self.subTest(absent=absent), self.assertRaisesRegex(ValueError, 'extension roster missing'):
                CHECK.partition(selected, root)
        historical = [root / 'tools/legacy.py'] + document
        self.assertEqual(len(CHECK.partition(historical, root)), 2)
        with self.assertRaisesRegex(ValueError, 'extension roster missing'):
            CHECK.extension_sources(historical, root, required=True)

    def test_sources_refuses_when_all_extensions_are_missing(self):
        with patch.object(Path, 'glob', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'extension roster missing'):
                CHECK.sources()

    def test_future_extension_name_stays_in_legacy_profile(self):
        root = Path('/declared')
        document, extension = self.roster(root)
        unknown = root / 'tools/transport_workflow_future.py'
        profiles = CHECK.partition([unknown] + document + extension, root)
        self.assertEqual(profiles[0], ('legacy', [unknown]))
        self.assertNotIn(unknown, profiles[-1][1])

    def test_extended_partition_complete_disjoint_and_duplicate_refuses(self):
        root = Path('/declared')
        document, extension = self.roster(root)
        selected = [root / 'install/legacy.py'] + document + extension
        profiles = CHECK.partition(selected, root)
        flattened = [path for _label, paths in profiles for path in paths]
        self.assertCountEqual(flattened, selected)
        self.assertEqual(len(flattened), len(set(flattened)))
        for repeated in extension:
            with self.subTest(repeated=repeated), self.assertRaisesRegex(ValueError, 'duplicate'):
                CHECK.partition(selected + [repeated], root)

    def test_each_extension_gets_real_function_syntax_and_byte_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'tools').mkdir()
            with patch.object(CHECK, 'ROOT', root):
                for name in CHECK.TRANSPORT_EXTENSION_NAMES:
                    path = root / 'tools' / name
                    self.assertTrue(CHECK.bounded_functions(path))
                    path.write_text('def oversized():\n' + '    pass\n' * 60)
                    with self.subTest(name=name, case='function'), self.assertRaisesRegex(ValueError, 'exceeds 60'):
                        CHECK.analyze([path])
                    path.write_text('await missing_context()\n')
                    with self.subTest(name=name, case='syntax'), self.assertRaises(SyntaxError):
                        CHECK.analyze([path])
                    path.write_bytes(b'#' * 131073)
                    with self.subTest(name=name, case='bytes'), self.assertRaisesRegex(ValueError, 'unsupported'):
                        CHECK.analyze([path])


class WorkflowAttemptProfileControls(unittest.TestCase):
    def roster(self, root):
        document = [root / 'tools' / name for name in CHECK.DOCUMENT_NAMES]
        extension = [root / 'tools' / name for name in CHECK.TRANSPORT_EXTENSION_NAMES]
        attempt = [root / 'tools' / name for name in CHECK.WORKFLOW_ATTEMPT_NAMES]
        return document, extension, attempt

    def test_attempt_roster_is_explicit_unique_and_disjoint(self):
        expected = ('transport_workflow_attempts.py', 'transport_workflow_capture.py',
                    'transport_workflow_catalog.py')
        self.assertEqual(CHECK.WORKFLOW_ATTEMPT_NAMES, expected)
        self.assertEqual(len(set(expected)), 3)
        self.assertFalse(set(expected).intersection(CHECK.DOCUMENT_NAMES))
        self.assertFalse(set(expected).intersection(CHECK.TRANSPORT_EXTENSION_NAMES))
        self.assertEqual(len(CHECK.TRANSPORT_EXTENSION_NAMES), 5)
        self.assertEqual(len(CHECK.DOCUMENT_NAMES), 9)

    def test_unchanged_128_129_legacy_bound_with_complete_attempt_roster(self):
        root = Path('/declared')
        document, extension, attempt = self.roster(root)
        legacy = [root / 'tools' / ('legacy_%03d.py' % index) for index in range(129)]
        profiles = CHECK.partition(legacy[:128] + document + extension + attempt, root)
        self.assertEqual(profiles[0], ('legacy', legacy[:128]))
        self.assertEqual(profiles[-2], ('transport-extension/1', sorted(extension)))
        self.assertEqual(profiles[-1], ('transport-workflow-attempt/1', sorted(attempt)))
        with self.assertRaisesRegex(ValueError, 'legacy source file bound exceeded'):
            CHECK.partition(legacy + document + extension + attempt, root)

    def test_every_partial_attempt_roster_refuses(self):
        root = Path('/declared')
        document, extension, attempt = self.roster(root)
        for absent in attempt:
            selected = [root / 'tools/legacy.py'] + document + extension + [p for p in attempt if p != absent]
            with self.subTest(absent=absent), self.assertRaisesRegex(ValueError, 'attempt roster missing'):
                CHECK.partition(selected, root)
        historical = [root / 'tools/legacy.py'] + document + extension
        self.assertEqual(CHECK.partition(historical, root)[-1][0], 'transport-extension/1')
        with self.assertRaisesRegex(ValueError, 'attempt roster missing'):
            CHECK.attempt_sources(historical, root, required=True)

    def test_future_attempt_name_stays_in_legacy_profile(self):
        root = Path('/declared')
        document, extension, attempt = self.roster(root)
        unknown = root / 'tools/transport_workflow_future_attempt.py'
        profiles = CHECK.partition([unknown] + document + extension + attempt, root)
        self.assertEqual(profiles[0], ('legacy', [unknown]))
        self.assertNotIn(unknown, profiles[-1][1])

    def test_attempt_partition_complete_disjoint_and_duplicate_refuses(self):
        root = Path('/declared')
        document, extension, attempt = self.roster(root)
        selected = [root / 'install/legacy.py'] + document + extension + attempt
        profiles = CHECK.partition(selected, root)
        flattened = [path for _label, paths in profiles for path in paths]
        self.assertCountEqual(flattened, selected)
        self.assertEqual(len(flattened), len(set(flattened)))
        for repeated in attempt:
            with self.subTest(repeated=repeated), self.assertRaisesRegex(ValueError, 'duplicate'):
                CHECK.partition(selected + [repeated], root)

    def test_each_attempt_module_gets_real_function_syntax_and_byte_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'tools').mkdir()
            with patch.object(CHECK, 'ROOT', root):
                for name in CHECK.WORKFLOW_ATTEMPT_NAMES:
                    path = root / 'tools' / name
                    self.assertTrue(CHECK.bounded_functions(path))
                    path.write_text('def oversized():\n' + '    pass\n' * 60)
                    with self.subTest(name=name, case='function'), self.assertRaisesRegex(ValueError, 'exceeds 60'):
                        CHECK.analyze([path])
                    path.write_text('await missing_context()\n')
                    with self.subTest(name=name, case='syntax'), self.assertRaises(SyntaxError):
                        CHECK.analyze([path])
                    path.write_bytes(b'#' * 131073)
                    with self.subTest(name=name, case='bytes'), self.assertRaisesRegex(ValueError, 'unsupported'):
                        CHECK.analyze([path])

    def test_live_attempt_modules_leave_the_legacy_profile(self):
        profiles = dict(CHECK.sources())
        attempt = profiles['transport-workflow-attempt/1']
        self.assertEqual([path.name for path in attempt], list(CHECK.WORKFLOW_ATTEMPT_NAMES))
        legacy_names = {path.name for path in profiles['legacy']}
        self.assertTrue(set(CHECK.WORKFLOW_ATTEMPT_NAMES).isdisjoint(legacy_names))
        self.assertLessEqual(len(profiles['legacy']), 128)


if __name__ == '__main__':
    unittest.main()
