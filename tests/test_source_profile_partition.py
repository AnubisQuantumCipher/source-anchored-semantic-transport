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


if __name__ == '__main__':
    unittest.main()
