"""Pure OCR boundary controls: all tool/process operations mocked."""
import hashlib
import io
import unittest
import importlib.util
import json
from pathlib import Path
import sys
import os
import stat
import tempfile
import threading
import time
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'tools/transport_document_ocr.py'
ROOT = Path(os.environ.get('TRANSPORT_DOCUMENT_TEST_SCRATCH',
                           '/dev/shm/transport-document-tests')) / 'ocr'



def need(condition, message):
    if not condition:
        raise ValueError(message)



def check_storage(root):
    pending, total = [root], 0
    for _ in range(4096):
        if not pending:
            need(total + 65536 <= 8388608, 'portable fixture storage cap')
            return
        path = pending.pop()
        info = path.lstat()
        total += max(info.st_size, info.st_blocks * 512)
        need(total + 65536 <= 8388608, 'portable fixture storage cap')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    need(len(pending) < 4096, 'portable fixture entry cap')
                    pending.append(Path(entry.path))
    raise ValueError('portable fixture inventory cap')


def refused(module, function, *args):
    try:
        function(*args)
    except (module.OCRError, UnicodeError):
        return
    raise ValueError('expected refusal absent')


def resource_controls(module):
    for inherited, expected in [((123, 456), '--as=123:456'),
                                ((1073741824, 1073741824), '--as=536870912:536870912'),
                                ((-1, -1), '--as=536870912:536870912')]:
        with patch.object(module.resource, 'getrlimit', return_value=inherited):
            command = module.bounded_command(['/usr/bin/never-executed'])
        need(command[0] == '/usr/bin/prlimit' and expected in command and
             '--core=0:0' in command and command[-2:] == ['--', '/usr/bin/never-executed'],
             'integrated inherited command limits')
    budget = module.Budget()
    budget.charge('text', module.MAX_READING)
    refused(module, budget.charge, 'text', 1)
    need(budget.used['text'] == module.MAX_READING, 'refusal changed budget')
    refused(module, budget.charge, 'metadata', -1)
    return 5


def cleanup_controls(module):
    actions = []
    class Child:
        def wait(self, timeout):
            actions.append('reap')
    def signal_control(expected, number):
        actions.append(number)
        if number == module.signal.SIGTERM:
            raise OSError('synthetic TERM refusal')
    with patch.object(module, 'signal_owned', side_effect=signal_control):
        with patch.object(module.time, 'sleep'), patch.object(module, 'kill_direct_child'):
            errors = module.cleanup_child(Child(), (1, 2, 3, 4, 5), True)
    need(actions == [module.signal.SIGTERM, module.signal.SIGKILL, 'reap'] and errors,
         'cleanup did not continue independently')
    return 1


def file_controls(module, folder):
    good = folder / 'good.png'
    prefix = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    good.write_bytes(prefix + (2000).to_bytes(4, 'big') * 2)
    need(module.png_dimensions(good) == (2000, 2000), 'pixel ceiling')
    bad = folder / 'bad.png'
    bad.write_bytes(prefix + (2001).to_bytes(4, 'big') + (1).to_bytes(4, 'big'))
    refused(module, module.png_dimensions, bad)
    bad.write_bytes(b'NOPE' + b'0' * 20)
    refused(module, module.png_dimensions, bad)
    text = folder / 'good.txt'
    text.write_bytes(b'A\xc3\xa9\n')
    need(module.validate_utf8(text) == (hashlib.sha256(text.read_bytes()).hexdigest(), 4), 'UTF8 hash')
    text.write_bytes(b'\xff')
    refused(module, module.validate_utf8, text)
    return 5


def spawn_control(module, folder):
    target = folder / 'spawn-failure'
    target.mkdir()
    with patch.object(module.subprocess, 'Popen', side_effect=module.subprocess.SubprocessError('synthetic spawn refusal')):
        refused(module, module.run_child, ['never-executed'], target, 'spawn',
                time.monotonic() + 5, threading.Event(), module.Budget())
    record = json.loads((target / 'spawn.process.json').read_text())
    need(record['failure'].startswith('SubprocessError:') and record['returncode'] is None,
         'spawn failure evidence missing')
    return 1


def collection_control(module, folder):
    source = folder / 'synthetic-source.pdf'
    source.write_bytes(b'%PDF-1.4\nsynthetic mocked source\n')
    def job(fd, destination, page, deadline, stopped, budget):
        return {'page': page}
    target = folder / 'collection'
    target.mkdir()
    with patch.object(module, 'page_job', side_effect=job):
        result = module.collect_pages(source, target, [1, 2, 3, 4, 5],
                                      time.monotonic() + 5, module.Budget())
    need([item['page'] for item in result] == [1, 2, 3, 4, 5], 'ordered page collection')
    return 1


def combine_controls(module, folder):
    text = folder / 'page.txt'
    text.write_bytes(b'control\n')
    record = {'page': 1, 'text_path': str(text), 'text_bytes': 8,
              'text_sha256': hashlib.sha256(text.read_bytes()).hexdigest(),
              'source_locator': {'page': 1}}
    good = folder / 'combine-good'
    good.mkdir()
    segments, digest, size = module.combine(good, [record], module.Budget(), time.monotonic() + 5)
    need(size == 8 and segments[0]['end'] == 8 and digest == record['text_sha256'], 'combined text exactness')
    bad = folder / 'combine-gap'
    bad.mkdir()
    refused(module, module.combine, bad, [dict(record, page=2)], module.Budget(), time.monotonic() + 5)
    return 2


def hash_controls(module, folder):
    fixtures = folder / 'hash-fixtures'
    fixtures.mkdir()
    for size in [0, 1, 65536, 65537]:
        (fixtures / ('hash-' + str(size))).write_bytes(b'x' * size)
    (fixtures / 'over-cap').write_bytes(b'xx')
    for size in [0, 1, 65536, 65537]:
        path = fixtures / ('hash-' + str(size))
        data = path.read_bytes()
        digest, identity = module.digest_file(path, size)
        need(digest == hashlib.sha256(data).hexdigest() and identity[2] == size,
             'exact cap including partial final read')
    refused(module, module.digest_file, fixtures / 'over-cap', 1)
    return 5


def page_deadline_controls(module, folder):
    def child(argv, destination, label, deadline, stopped, budget, text=False, source_fd=None):
        need(deadline == 8, 'two-second cleanup reserve inside ten-second page total')
        output = destination / (label + '.txt' if text else label + '.stdout')
        output.write_bytes(b'control' if text else b'')
        if not text:
            (destination / 'render.png').write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + (1).to_bytes(4, 'big') * 2)
        return output
    for name, clocks, should_fail in [('timely', [0, 1, 2, 3, 4], False),
                                       ('late_final', [0, 1, 2, 3, 11], True)]:
        target = folder / name
        target.mkdir()
        with patch.object(module, 'run_child', side_effect=child):
            with patch.object(module.time, 'monotonic', side_effect=clocks):
                if should_fail:
                    refused(module, module.page_job, 999, target, 1, 100, threading.Event(), module.Budget())
                else:
                    result = module.page_job(999, target, 1, 100, threading.Event(), module.Budget())
                    need(result['page'] == 1, 'timely page result')
    return 2


def generic_controls(module):
    need(module.page_count(b'Title: control\nPages: 2\n') == 2, 'bounded page-count parse')
    refused(module, module.page_count, b'Pages: 1\nPages: 2\n')
    refused(module, module.page_count, b'Pages: 0\n')
    refused(module, module.page_count, b'Pages: 16385\n')
    plan = module.schedule_fit(476, 1890)
    need(plan['batches'] == 159 and plan['conditional_scheduled_seconds'] == 1890,
         'fixed independently computed schedule')
    refused(module, module.schedule_fit, 476, 1889)
    refused(module, module.schedule_fit, 1000, 3000)
    refused(module, module.schedule_fit, 1, 3001)
    return 8



class MockChild:
    pid = 12345
    returncode = None
    def __init__(self):
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
    def wait(self, timeout):
        self.returncode = 0
        return 0


def rejected_identity_controls(module, folder):
    identities = [('wrong_uid', (12345, os.getuid() + 1, 12345, 12345, 7)),
                  ('wrong_pgid', (12345, os.getuid(), 22222, 12345, 7)),
                  ('wrong_sid', (12345, os.getuid(), 12345, 22222, 7))]
    for name, identity in identities:
        target = folder / name
        target.mkdir()
        with patch.object(module.subprocess, 'Popen', return_value=MockChild()):
            with patch.object(module, 'child_identity', return_value=identity):
                with patch.object(module.os, 'killpg') as group, patch.object(module.os, 'kill') as direct:
                    with patch.object(module.time, 'sleep'):
                        refused(module, module.run_child, ['never-executed'], target, 'child',
                                time.monotonic() + 5, threading.Event(), module.Budget())
        record = json.loads((target / 'child.process.json').read_text())
        need(group.call_count == 0 and direct.call_count == 1 and
             direct.call_args.args == (12345, module.signal.SIGKILL),
             'rejected identity authorized group signal or lost owned direct cleanup')
        need(record['failure'] and len(record['cleanup_errors']) == 2,
             'rejected identity cleanup failures not retained')
    return 3


def identity_loss_controls(module, folder):
    valid = (12345, os.getuid(), 12345, 12345, 7)
    actions = []
    def group(pid, number):
        actions.append(number)
    with patch.object(module, 'child_identity', return_value=valid):
        with patch.object(module.os, 'killpg', side_effect=group), patch.object(module.os, 'kill') as direct:
            with patch.object(module.time, 'sleep'):
                errors = module.cleanup_child(MockChild(), valid, True)
    need(not errors and actions == [module.signal.SIGTERM, module.signal.SIGKILL] and
         direct.call_count == 0, 'valid identity cleanup sequence')
    target = folder / 'initial-identity-loss'
    target.mkdir()
    with patch.object(module.subprocess, 'Popen', return_value=MockChild()):
        with patch.object(module, 'child_identity', side_effect=FileNotFoundError('synthetic owner read loss')):
            with patch.object(module.os, 'killpg') as group_call, patch.object(module.os, 'kill') as direct:
                refused(module, module.run_child, ['never-executed'], target, 'child',
                        time.monotonic() + 5, threading.Event(), module.Budget())
    record = json.loads((target / 'child.process.json').read_text())
    need(group_call.call_count == 0 and direct.call_count == 1 and record['cleanup_errors'],
         'initial identity loss must retain failure and use direct child only')
    with patch.object(module, 'child_identity', side_effect=FileNotFoundError('synthetic later owner loss')):
        with patch.object(module.os, 'killpg') as group_call, patch.object(module.os, 'kill') as direct:
            with patch.object(module.time, 'sleep'):
                errors = module.cleanup_child(MockChild(), valid, True)
    need(group_call.call_count == 0 and direct.call_count == 1 and len(errors) == 2,
         'later identity loss must retain failures and avoid group signal')
    return 3


def main(mode):
    data = SOURCE.read_bytes()
    pin = hashlib.sha256(data).hexdigest()
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_storage(ROOT)
    folder = Path(tempfile.mkdtemp(prefix=mode + '-', dir=ROOT))
    (folder / 'source.py.inert').write_bytes(data)
    spec = importlib.util.spec_from_file_location('frozen_ocr', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    count = resource_controls(module) + cleanup_controls(module)
    count += file_controls(module, folder) + spawn_control(module, folder)
    count += collection_control(module, folder) + combine_controls(module, folder)
    count += hash_controls(module, folder)
    count += page_deadline_controls(module, folder)
    count += generic_controls(module)
    count += rejected_identity_controls(module, folder) + identity_loss_controls(module, folder)
    need(SOURCE.read_bytes() == data, 'source changed')
    result = {'PASS': True, 'controls': count, 'extractor_sha256': pin, 'mode': mode}
    check_storage(ROOT)
    (folder / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


class OCRControls(unittest.TestCase):
    def test_controls(self):
        main('optimized' if sys.flags.optimize else 'normal')


if __name__ == '__main__':
    unittest.main()
