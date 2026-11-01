"""Contained loader contract for the shipped namespace __main__ path.

Requirement: milestone 1 Power of Ten repair of the unpinned namespace loader.
Artifact: tools/transport_document_namespace.py.
Pass: the parent import keeps the on-disk supervisor epoch; a wrong digest, an
uppercase digest, a mismatched image, and an oversize image refuse with
'contained core source identity' and do not run an image marker; a matching
mutated image runs that marker; the matching supervisor image reaches the
shipped contained-argv check with and without -O.
"""
import ast
import fcntl
import hashlib
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = ROOT / 'tools' / 'transport_document_namespace.py'
SUPERVISOR = ROOT / 'tools' / 'transport_document_supervisor.py'
IDENTITY = 'contained core source identity'
MARKER = 'CHECKED_CORE_BYTES_EXECUTED'
OVERSIZE = 'OVERSIZE_EXECUTED'
CAP = 65536


def digest_of(raw):
    return hashlib.sha256(raw).hexdigest()


def image_fd(raw):
    fd = os.memfd_create('contained-loader-fixture', os.MFD_CLOEXEC)
    written = 0
    try:
        for _ in range(CAP + 2):
            if written == len(raw):
                break
            count = os.write(fd, raw[written:])
            if type(count) is not int or count <= 0:
                raise OSError('fixture write stalled')
            written += count
        if written != len(raw):
            raise OSError('fixture write incomplete')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def install_fd3(source):
    try:
        saved = os.dup(3)
    except OSError:
        saved = None
    os.dup2(source, 3)
    flags = fcntl.fcntl(3, fcntl.F_GETFD)
    fcntl.fcntl(3, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
    return saved


def restore_fd3(saved):
    if saved is None:
        os.close(3)
        return
    os.dup2(saved, 3)
    os.close(saved)


def confine_limits():
    for key, requested in ((resource.RLIMIT_AS, 536870912),
                           (resource.RLIMIT_CPU, 10),
                           (resource.RLIMIT_CORE, 0),
                           (resource.RLIMIT_FSIZE, 1048576),
                           (resource.RLIMIT_NOFILE, 64)):
        current = resource.getrlimit(key)
        bound = min([requested] + [item for item in current if item != resource.RLIM_INFINITY])
        resource.setrlimit(key, (bound, bound))
    signal.alarm(12)


def run_image(raw, declared, optimized=False, slots=True):
    fd = image_fd(raw)
    saved = install_fd3(fd)
    command = [sys.executable, '-I', '-S', '-B']
    if optimized:
        command.append('-O')
    command.append(str(NAMESPACE))
    if slots:
        command.extend(('slot1', 'slot2', declared))
    try:
        return subprocess.run(
            command, check=False, timeout=15, pass_fds=(3,),
            preexec_fn=confine_limits, stdin=subprocess.DEVNULL,
            capture_output=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    finally:
        restore_fd3(saved)
        os.close(fd)


def text_of(result):
    return result.stderr.decode('ascii', 'replace') + result.stdout.decode('ascii', 'replace')


def oversize_image():
    marker = ("raise SystemExit('" + OVERSIZE + "')\n").encode('ascii')
    if not 0 < len(marker) <= CAP:
        raise ValueError('oversize marker bound')
    return marker + b'#' * (CAP + 1 - len(marker))


def mutated_image(original):
    image = original + ("\nraise SystemExit('" + MARKER + "')\n").encode('ascii')
    if len(image) > CAP:
        raise ValueError('mutated image exceeds contained cap')
    return image


class ContainedLoader(unittest.TestCase):
    def test_shipped_loader_has_no_exec_and_stays_short(self):
        tree = ast.parse(NAMESPACE.read_bytes(), filename=str(NAMESPACE))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ('exec', 'eval'))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)
                for child in ast.walk(node):
                    called = isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                    self.assertFalse(called and child.func.id == node.name, node.name)

    def test_parent_import_keeps_ondisk_supervisor_epoch(self):
        script = (
            'import hashlib, pathlib, sys\n'
            'sys.path.insert(0, sys.argv[1])\n'
            'import transport_document_namespace as namespace\n'
            'raw = pathlib.Path(namespace.core.__file__).read_bytes()\n'
            'if namespace.core.SOURCE_EPOCH != hashlib.sha256(raw).hexdigest():\n'
            '    raise SystemExit(2)\n'
            'if namespace.__name__ != "transport_document_namespace":\n'
            '    raise SystemExit(3)\n')
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', script, str(ROOT / 'tools')],
            check=False, timeout=20, capture_output=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        self.assertEqual(result.returncode, 0, text_of(result))

    def test_wrong_digest_does_not_run_the_image(self):
        raw = mutated_image(SUPERVISOR.read_bytes())
        result = run_image(raw, '0' * 64)
        body = text_of(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(IDENTITY, body)
        self.assertNotIn(MARKER, body)
        self.assertNotIn('contained argv', body)

    def test_uppercase_digest_refuses(self):
        raw = SUPERVISOR.read_bytes()
        result = run_image(raw, digest_of(raw).upper())
        body = text_of(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(IDENTITY, body)
        self.assertNotIn('contained argv', body)

    def test_mismatched_image_refuses(self):
        raw = ("raise SystemExit('" + MARKER + "')\n").encode('ascii')
        result = run_image(raw, digest_of(SUPERVISOR.read_bytes()))
        body = text_of(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(IDENTITY, body)
        self.assertNotIn(MARKER, body)

    def test_oversize_image_refuses_even_when_its_digest_matches(self):
        raw = oversize_image()
        self.assertEqual(len(raw), CAP + 1)
        result = run_image(raw, digest_of(raw))
        body = text_of(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(IDENTITY, body)
        self.assertNotIn(OVERSIZE, body)

    def test_missing_digest_refuses(self):
        result = run_image(SUPERVISOR.read_bytes(), '', slots=False)
        body = text_of(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(IDENTITY, body)
        self.assertNotIn('contained argv', body)

    def test_matching_mutated_bytes_execute(self):
        raw = mutated_image(SUPERVISOR.read_bytes())
        result = run_image(raw, digest_of(raw))
        body = text_of(result)
        self.assertIn(MARKER, body)
        self.assertNotIn(IDENTITY, body)
        self.assertNotIn('contained argv', body)

    def test_matching_supervisor_reaches_contained_argv(self):
        raw = SUPERVISOR.read_bytes()
        self.assertLessEqual(len(raw), CAP)
        for optimized in (False, True):
            result = run_image(raw, digest_of(raw), optimized)
            body = text_of(result)
            self.assertNotEqual(result.returncode, 0, body)
            self.assertIn('contained argv', body)
            self.assertNotIn(IDENTITY, body)


if __name__ == '__main__':
    unittest.main(verbosity=1)
