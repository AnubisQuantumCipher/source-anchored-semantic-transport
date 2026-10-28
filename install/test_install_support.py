"""Targeted observed controls for installer support; not a whole-system proof."""

import argparse
import ast
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import transport_install_support as support

RECORDS = []
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}


def child(root: Path, program: str, timeout: float = 2, cap: int = 4096) -> dict:
    result = support.run_bounded([sys.executable, '-I', '-c', program], root,
                                 ENVIRONMENT, timeout, cap)
    RECORDS.append(result)
    return result


class FileControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='install-support-test-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_regular_file_bounds_and_create_only(self):
        path = self.root / 'file'
        support.write_new(path, b'abcd', 4)
        self.assertEqual(support.read_regular(path, 4), b'abcd')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            support.read_regular(path, 3)
        with self.assertRaises(FileExistsError):
            support.write_new(path, b'new')
        with self.assertRaises(ValueError):
            support.write_new(self.root / 'large', b'large', 4)
        self.assertFalse((self.root / 'large').exists())

    def test_empty_file_and_fifo_refusal(self):
        support.write_new(self.root / 'empty', b'', 0)
        self.assertEqual(support.read_regular(self.root / 'empty', 0), b'')
        os.mkfifo(self.root / 'fifo')
        with self.assertRaises(ValueError):
            support.read_regular(self.root / 'fifo')

    def test_confined_names(self):
        for name in ('', '.', '..', '../outside', '/absolute', 'a//b', 'a/./b',
                     'a/../b', 'a\\b', 'a/', 'a\0b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                support.confined(self.root, name)
        self.assertEqual(support.confined(self.root, 'new'), self.root / 'new')

    def test_leaf_and_parent_links_refused(self):
        (self.root / 'real').mkdir()
        support.write_new(self.root / 'real' / 'file', b'content')
        (self.root / 'link').symlink_to(self.root / 'real', target_is_directory=True)
        (self.root / 'leaf').symlink_to(self.root / 'real' / 'file')
        for name in ('link/file', 'leaf'):
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                support.confined(self.root, name)
            with self.subTest(name=name), self.assertRaises(OSError):
                support.read_regular(self.root / name)
        with self.assertRaises(OSError):
            support.write_new(self.root / 'link' / 'new', b'content')
        self.assertFalse((self.root / 'real' / 'new').exists())

    def test_parent_swapped_after_confined_refused(self):
        (self.root / 'inside').mkdir()
        support.write_new(self.root / 'inside' / 'file', b'content')
        path = support.confined(self.root, 'inside/file')
        (self.root / 'inside').rename(self.root / 'moved')
        (self.root / 'inside').symlink_to(self.root / 'moved', target_is_directory=True)
        with self.assertRaises(OSError):
            support.read_regular(path)
        with self.assertRaises(OSError):
            support.write_new(self.root / 'inside' / 'new', b'content')

    def test_write_swap_does_not_remove_replacement(self):
        path = self.root / 'file'
        original_write = support._write_fd

        def swapped(descriptor, data):
            original_write(descriptor, data)
            path.rename(self.root / 'original')
            path.write_bytes(b'replacement')

        with mock.patch.object(support, '_write_fd', swapped):
            with self.assertRaisesRegex(ValueError, 'cleanup refused'):
                support.write_new(path, b'original')
        self.assertEqual(path.read_bytes(), b'replacement')
        self.assertEqual((self.root / 'original').read_bytes(), b'original')

    def test_permission_failure_removes_created_file(self):
        path = self.root / 'file'
        with mock.patch.object(support.os, 'fchmod', side_effect=OSError('injected failure')):
            with self.assertRaisesRegex(OSError, 'injected failure'):
                support.write_new(path, b'content')
        self.assertFalse(path.exists())

    def test_initial_identity_failure_recovers_or_refuses_cleanup(self):
        path = self.root / 'file'
        original_fstat = os.fstat
        first = True

        def fail_once(descriptor):
            nonlocal first
            if first:
                first = False
                raise OSError('injected identity failure')
            return original_fstat(descriptor)

        with mock.patch.object(support.os, 'fstat', fail_once):
            with self.assertRaisesRegex(OSError, 'injected identity failure'):
                support.write_new(path, b'content')
        self.assertFalse(path.exists())
        with mock.patch.object(support.os, 'fstat', side_effect=OSError('unavailable')):
            with self.assertRaisesRegex(ValueError, 'identity unavailable; cleanup refused'):
                support.write_new(path, b'content')
        self.assertEqual(path.read_bytes(), b'')

    def test_publication_is_create_only(self):
        stage, destination = self.root / 'stage', self.root / 'published'
        stage.mkdir(mode=0o700)
        support.write_new(stage / 'file', b'content')
        support.atomic_publish(stage, destination)
        self.assertFalse(stage.exists())
        self.assertEqual(support.read_regular(destination / 'file'), b'content')
        stage.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            support.atomic_publish(stage, destination)
        (self.root / 'linked').symlink_to(self.root / 'absent')
        with self.assertRaises(FileExistsError):
            support.atomic_publish(stage, self.root / 'linked')
        stage.chmod(0o755)
        with self.assertRaises(ValueError):
            support.atomic_publish(stage, self.root / 'new')

    def test_publication_stage_swap_refused(self):
        stage, destination = self.root / 'stage', self.root / 'published'
        stage.mkdir(mode=0o700)
        original_fsync = os.fsync
        swapped = False

        def swap_on_sync(descriptor):
            nonlocal swapped
            original_fsync(descriptor)
            if not swapped:
                stage.rename(self.root / 'original')
                stage.mkdir(mode=0o700)
                swapped = True

        with mock.patch.object(support.os, 'fsync', swap_on_sync):
            with self.assertRaisesRegex(ValueError, 'stage identity changed'):
                support.atomic_publish(stage, destination)
        self.assertFalse(destination.exists())


class ValueControls(unittest.TestCase):
    def test_canonical_exact_types_and_order(self):
        self.assertEqual(support.canonical({'z': [1, True, None], 'a': 'value'}),
                         b'{"a":"value","z":[1,true,null]}')
        for value in ({'x': 0.5}, {'x': float('nan')}, {1: 'value'}, {'x': (1,)}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                support.canonical(value)

    def test_canonical_depth_cycles_and_size(self):
        cyclic = {}
        cyclic['self'] = cyclic
        with self.assertRaises(ValueError):
            support.canonical(cyclic)
        with self.assertRaises(ValueError):
            support.canonical({'x': 'x' * support.MAX_JSON})
        with self.assertRaises(ValueError):
            support.canonical({'x': [0] * 4097})

    def test_function_lengths(self):
        for path in (Path(support.__file__), Path(__file__)):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    with self.subTest(path=path.name, function=node.name):
                        self.assertLessEqual(node.end_lineno - node.lineno + 1, 60)


class ProcessControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='install-process-test-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_success_complete_raw_streams_and_limits(self):
        program = ('import os,resource; '
                   'assert resource.getrlimit(resource.RLIMIT_AS)==(1073741824,1073741824); '
                   'assert resource.getrlimit(resource.RLIMIT_CPU)==(120,120); '
                   'assert resource.getrlimit(resource.RLIMIT_FSIZE)==(33554432,33554432); '
                   'assert resource.getrlimit(resource.RLIMIT_NOFILE)==(128,128); '
                   'os.write(1,b"\\x00out\\xff"); os.write(2,b"err\\x00")')
        result = child(self.root, program)
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['stdout'], b'\0out\xff')
        self.assertEqual(result['stderr'], b'err\0')

    def test_cwd_and_environment_are_explicit(self):
        result = child(self.root, 'import os; print(os.getcwd()); print(os.environ.get("HOME"))')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['stdout'], os.fsencode(self.root) + b'\nNone\n')

    def test_nonzero_and_launch_failure(self):
        result = child(self.root, 'import sys; sys.exit(7)')
        self.assertEqual(result['status'], 'EXIT_NONZERO')
        self.assertEqual(result['exit_code'], 7)
        result = support.run_bounded(['/definitely/missing/installer-command'], self.root,
                                     ENVIRONMENT, timeout=1)
        RECORDS.append(result)
        self.assertEqual(result['status'], 'REFUSED_LAUNCH')
        self.assertIsNone(result['exit_code'])

    def test_exact_output_limit_and_flood(self):
        exact = child(self.root, 'import os; os.write(1,b"x"*4096)', cap=4096)
        self.assertEqual(exact['status'], 'SUCCESS')
        flooded = child(self.root, 'import os; os.write(1,b"x"*65536)', cap=4096)
        self.assertTrue(flooded['status'].startswith('REFUSED_OUTPUT_LIMIT'))
        self.assertEqual(flooded['stdout'], b'x' * 4096)
        flooded = child(self.root, 'import os; os.write(2,b"e"*65536)', cap=4096)
        self.assertTrue(flooded['status'].startswith('REFUSED_OUTPUT_LIMIT'))
        self.assertEqual(flooded['stderr'], b'e' * 4096)

    def test_timeout_preserves_prefix(self):
        result = child(self.root, 'import os,time; os.write(1,b"before"); time.sleep(20)',
                       timeout=0.2)
        self.assertTrue(result['status'].startswith('REFUSED_TIMEOUT'))
        self.assertEqual(result['stdout'], b'before')
        self.assertIsNotNone(result['exit_code'])

    def test_parent_exit_with_child_holding_pipes(self):
        program = ('import os,subprocess,sys; '
                   'p=subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(20)"]); '
                   'os.write(1,str(p.pid).encode()+b"\\n"); os._exit(0)')
        result = child(self.root, program, timeout=0.2)
        self.assertTrue(result['status'].startswith('REFUSED_TIMEOUT'))
        pid = int(result['stdout'].strip())
        process_state = Path(f'/proc/{pid}/stat')
        if process_state.exists():
            self.assertEqual(process_state.read_text().rsplit(')', 1)[1].split()[0], 'Z')

    def test_closed_pipe_descendant_prevents_success(self):
        program = ('import os,subprocess,sys; '
                   'p=subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(20)"],'
                   'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                   'os.write(1,str(p.pid).encode()+b"\\n"); os._exit(0)')
        result = child(self.root, program, timeout=2)
        self.assertNotEqual(result['status'], 'SUCCESS')
        pid = int(result['stdout'].strip())
        process_state = Path(f'/proc/{pid}/stat')
        if process_state.exists():
            self.assertEqual(process_state.read_text().rsplit(')', 1)[1].split()[0], 'Z')

    def test_argument_and_environment_budget_refusals(self):
        for argv in ([], ['x'] * 33, ['x' * 4097], ['x\0y']):
            with self.subTest(argv=argv[:1]), self.assertRaises(ValueError):
                support.run_bounded(argv, self.root, ENVIRONMENT)
        with self.assertRaises(ValueError):
            support.run_bounded(['true'], self.root, {'BAD=KEY': 'value'})
        with self.assertRaises(ValueError):
            support.run_bounded(['true'], self.root, ENVIRONMENT, timeout=121)


def write_evidence(directory: Path, result: unittest.TestResult) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    records = []
    for index, record in enumerate(RECORDS):
        entry = {key: value for key, value in record.items() if key not in ('stdout', 'stderr')}
        for name in ('stdout', 'stderr'):
            data = record[name]
            filename = f'process-{index:02d}.{name}.bin'
            support.write_new(directory / filename, data)
            entry[name] = {'file': filename, 'bytes': len(data), 'sha256': support.sha(data)}
        records.append(entry)
    files = {path.name: support.sha(support.read_regular(path))
             for path in (Path(support.__file__), Path(__file__))}
    receipt = {'status': 'TESTED' if result.wasSuccessful() else 'FAILED',
               'tests_run': result.testsRun, 'failures': len(result.failures),
               'errors': len(result.errors), 'python': sys.version, 'source_sha256': files,
               'processes': records,
               'limits': 'Observed focused controls only; no formal or whole-system proof.'}
    support.write_new(directory / 'receipt.json', support.canonical(receipt) + b'\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.evidence is not None:
        write_evidence(args.evidence, result)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
