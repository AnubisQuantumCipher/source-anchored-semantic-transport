"""Portable pure controls: no compiler, prover, namespace or private document runs."""
import ast
import importlib
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from document_build.common import FILE_CAP, limits, read_bytes
from document_build.launcher import preflight, source_pins
from document_build.proof import EXPECTED, parse_proof, source_gate
from document_build.worker import commands


def clean_summary():
    rows = ['Analyzed 1 unit', 'in unit document_frame_ledger, 8 subprograms and packages out of 8 analyzed',
            'Total 16 10 (63%) 6 (38%) . .']
    for name, count in EXPECTED.items():
        rows.append('  ' + name + ' at document_frame_ledger.ads:1 flow analyzed '
                    '(0 errors, 0 checks, 0 warnings and 0 pragma Assume statements) '
                    'and proved (' + str(count) + ' checks)')
    return ('\n'.join(rows) + '\n').encode()


class ProofControls(unittest.TestCase):
    def test_complete_clean_fixed_profile(self):
        self.assertEqual(parse_proof(clean_summary())['prover'], 6)

    def test_each_weakened_or_missing_evidence_refuses(self):
        good = clean_summary()
        changes = [(b'Total 16 10 (63%) 6 (38%) . .', b'Total 0 0 0 . .'),
                   (b'6 (38%) . .', b'6 (38%) 1 .'), (b'6 (38%) . .', b'6 (38%) . 1'),
                   (b'8 subprograms', b'7 subprograms'), (b'0 warnings', b'1 warnings'),
                   (b'0 pragma Assume', b'1 pragma Assume'), (b'0 errors', b'1 errors'),
                   (b'in unit document_frame_ledger', b'in unit unrelated'),
                   (b'proved (3 checks)', b'proved (2 checks)'),
                   (b'Analyzed 1 unit', b'Analyzed 2 unit')]
        for old, new in changes:
            with self.subTest(new=new), self.assertRaises(ValueError):
                parse_proof(good.replace(old, new))
        for raw in (b'', good + b'Total 16 10 6 . .\n', good + b'warning: ignored\n', good * 10000):
            with self.assertRaises(ValueError):
                parse_proof(raw)

    def test_duplicate_subprogram_and_missing_report_refuse(self):
        raw = clean_summary().replace(b'Document_Frame_Ledger.Valid', b'Document_Frame_Ledger.Complete')
        with self.assertRaises(ValueError):
            parse_proof(raw)
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(OSError):
            read_bytes(Path(folder) / 'absent')

    def test_assume_and_justification_source_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'document_native').mkdir()
            for pragma in ('Assume (True)', 'Annotate (GNATprove, False_Positive, "x")', 'Suppress (All_Checks)'):
                for suffix in ('ads', 'adb'):
                    (root / ('document_native/document_frame_ledger.' + suffix)).write_text('pragma ' + pragma + ';')
                with self.assertRaises(ValueError):
                    source_gate(root)


class LaunchControls(unittest.TestCase):
    def test_commands_fixed_bounded_and_assertions_enabled(self):
        specs = commands(Path('/supplied'), {'gprbuild': '/gnat/gprbuild', 'gnatprove': '/gnat/gnatprove'})
        self.assertEqual([seconds for _name, seconds, _argv in specs], [120, 300])
        self.assertIn('-R', specs[0][2])
        self.assertIn('-gnata', specs[0][2])
        for flag in ('-U', '--level=2', '--report=all', '--warnings=error', '-j1', '--prover=z3'):
            self.assertIn(flag, specs[1][2])
        self.assertTrue(all('-j1' in argv for _name, _seconds, argv in specs))

    def test_limits_preserve_inherited_stricter_caps(self):
        requested = []
        with patch('resource.getrlimit', return_value=(17, 19)), patch('resource.setrlimit', side_effect=lambda *args: requested.append(args)):
            limits()
        self.assertEqual(len(requested), 4)
        self.assertTrue(all(pair == (17, 17) for kind, pair in requested if kind != resource.RLIMIT_CORE))
        self.assertEqual(dict(requested)[resource.RLIMIT_CORE], (0, 0))

    def test_limits_infinite_values_receive_fixed_caps(self):
        requested = []
        with patch('resource.getrlimit', return_value=(-1, -1)), patch('resource.setrlimit', side_effect=lambda *args: requested.append(args)):
            limits()
        values = dict(requested)
        self.assertEqual(values[resource.RLIMIT_FSIZE], (8_388_608, 8_388_608))
        self.assertEqual(values[resource.RLIMIT_NOFILE], (64, 64))

    def test_nontmpfs_output_refuses_before_discovery_or_creation(self):
        from argparse import Namespace
        target = Path('/tmp') / ('transport-build-must-not-exist-' + str(os.getpid()))
        args = Namespace(source_root=ROOT, out=target, toolchain_root=None)
        with patch('document_build.launcher.discover_toolchain') as discover:
            with patch.object(Path, 'mkdir') as create:
                with self.assertRaises(ValueError):
                    preflight(args)
                discover.assert_not_called()
                create.assert_not_called()
        self.assertFalse(target.exists())

    def test_symlink_and_oversized_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'payload'
            target.write_bytes(b'1234')
            with self.assertRaises(ValueError):
                read_bytes(target, 3)
            link = Path(folder) / 'link'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                read_bytes(link)

    def test_census_accepts_exact_directory_inode_quota_and_refuses_overflow(self):
        from document_build.capture import census
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            for ordinal in range(4095):
                with (work / ('empty-%04d' % ordinal)).open('xb'):
                    pass
            with patch('document_build.capture.private_pids', return_value=[]):
                rows = census(work)
                self.assertEqual(len(rows), 4096)
                self.assertEqual(sum(row['kind'] == 'directory' for row in rows), 1)
                self.assertEqual(sum(row['kind'] == 'regular' for row in rows), 4095)
                with (work / 'one-too-many').open('xb'):
                    pass
                with self.assertRaises(ValueError):
                    census(work)

    def test_fixed_identity_roster_rechecks_and_refuses_changes(self):
        from document_build.identity import verify_roster
        from document_build.launcher import pin_regular
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'runtime'
            path.write_bytes(b'original')
            config = {name: {} for name in ('tool_pins', 'runtime_pins', 'compiler_runtime_pins', 'system_runtime_pins')}
            config['tool_pins']['declared'] = pin_regular(path)
            before = verify_roster(config)
            self.assertEqual(before, verify_roster(config))
            self.assertEqual(before['files'], 1)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                verify_roster(config)
            path.unlink()
            with self.assertRaises(OSError):
                verify_roster(config)

    def test_global_deadline_reserves_terminal_work_and_refuses_late_dispatch(self):
        from document_build.process import admit_phase, phase
        with patch('document_build.process.time.monotonic', return_value=0):
            self.assertEqual(admit_phase(120, 450, 90), 360)
        with patch('document_build.process.time.monotonic', return_value=70):
            with self.assertRaises(ValueError):
                admit_phase(300, 450, 90)
        with patch('document_build.process.time.monotonic', return_value=451):
            with patch('document_build.process.subprocess.Popen') as child:
                with self.assertRaises(ValueError):
                    phase(['/never/dispatched'], 120, 450, Path('/unused'), 'x', {})
                child.assert_not_called()

    def test_partial_capture_is_retained_and_never_retried(self):
        from document_build.capture import snapshot, copy_payload
        with tempfile.TemporaryDirectory() as folder:
            out, work = Path(folder), Path(folder) / 'private'
            work.mkdir()
            for name in ('a', 'b'):
                (work / name).write_bytes(b'payload')
            rows = [{'kind': 'regular', 'dev': 1, 'ino': index, 'path': name, 'bytes': 7}
                    for index, name in enumerate(('a', 'b'))]
            def failing_copy(source, target, size):
                if source.name == 'b':
                    target.write_bytes(b'partial')
                    raise OSError('injected external IO failure')
                return copy_payload(source, target, size)
            with patch('document_build.capture.private_pids', return_value=[]):
                with patch('document_build.capture.census', return_value=rows):
                    with patch('document_build.capture.copy_payload', side_effect=failing_copy):
                        result = snapshot(work, out, True)
                self.assertFalse(result['complete'])
                first = (out / 'capture/payload-0000.bin').read_bytes()
                partial = (out / 'capture/payload-0001.bin').read_bytes()
                journal = (out / 'capture/progress.jsonl').read_bytes()
                self.assertIn(b'COMPLETE_READBACK', journal)
                self.assertIn(b'FAILED', journal)
                second = snapshot(work, out, True)
                self.assertFalse(second['complete'])
                self.assertEqual(first, (out / 'capture/payload-0000.bin').read_bytes())
                self.assertEqual(partial, (out / 'capture/payload-0001.bin').read_bytes())
                self.assertEqual(journal, (out / 'capture/progress.jsonl').read_bytes())

    def test_private_cleanup_refuses_host_pid(self):
        from document_build.process import drain_children
        with patch('os.getpid', return_value=42), patch('os.pidfd_open') as descriptor:
            with self.assertRaises(ValueError):
                drain_children()
            descriptor.assert_not_called()

    def test_strict_source_structure(self):
        files = [ROOT / 'tools/build_document_decoder.py', *sorted((ROOT / 'tools/document_build').glob('*.py'))]
        for path in files:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                self.assertNotIsInstance(node, (ast.Assert, ast.While, ast.AsyncFunctionDef, ast.Lambda))
                if isinstance(node, ast.FunctionDef):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (path.name, node.name))
            self.assertNotIn('/home/sicarii', path.read_text())
            self.assertNotIn('os.kill(', path.read_text())
            self.assertNotIn('killpg(', path.read_text())


if __name__ == '__main__':
    unittest.main()
