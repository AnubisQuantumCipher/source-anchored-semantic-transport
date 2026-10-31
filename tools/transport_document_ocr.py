"""Optional local OCR reading view; accuracy and semantic completeness UNPROVEN.

A bounded trusted parent owns each unreaped child/session. This is not a sandbox,
crash-safe cleanup guarantee, or adversarial operating-system containment claim.
"""
import codecs
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

MAX_PAGES = 16384
MAX_SOURCE = 1073741824
WORKERS = 3
PAGE_SECONDS = 10
ORCHESTRATION_MARGIN_SECONDS = 100
MERGE_MARGIN_SECONDS = 200
MAX_CHILD = 8388608
MAX_READING = 33554432
MAX_WORKING = 134217728
MAX_DIAGNOSTICS = 4194304
MAX_METADATA = 4194304
CHUNK = 65536
TRAINED = Path('/usr/share/tessdata/eng.traineddata')


class OCRError(ValueError):
    """Refusal; partial artifacts remain provisional and retained."""


def need(condition, message):
    if not condition:
        raise OCRError(message)


def check_clock(deadline, stopped):
    need(not stopped.is_set(), 'OCR sibling failure stop')
    need(time.monotonic() < deadline, 'OCR finite deadline')


def digest_file(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'OCR regular file bound')
        before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        digest, total = hashlib.sha256(), 0
        for _ in range((cap + CHUNK - 1) // CHUNK + 1):
            data = stream.read(CHUNK)
            if not data:
                after = os.fstat(stream.fileno())
                need(before == (after.st_dev, after.st_ino, after.st_size,
                                after.st_mtime_ns, after.st_ctime_ns), 'OCR file changed')
                return digest.hexdigest(), before
            total += len(data)
            need(total <= cap, 'OCR file growth')
            digest.update(data)
    raise OCRError('OCR file traversal bound')


def bounded_command(argv):
    result = ['/usr/bin/prlimit']
    for kind, name, ceiling in [(resource.RLIMIT_AS, 'as', 536870912),
                                 (resource.RLIMIT_FSIZE, 'fsize', MAX_CHILD),
                                 (resource.RLIMIT_CORE, 'core', 0)]:
        soft, hard = resource.getrlimit(kind)
        new_hard = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
        new_soft = new_hard if soft == resource.RLIM_INFINITY else min(soft, new_hard)
        result.append('--' + name + '=' + str(new_soft) + ':' + str(new_hard))
    return result + ['--'] + argv


def child_identity(pid):
    path = Path('/proc') / str(pid)
    with (path / 'stat').open('rb') as stream:
        raw = stream.read(4097)
    need(len(raw) <= 4096, 'OCR child stat bound')
    end = raw.rfind(b')')
    fields = raw[end + 2:].split()
    need(end > 0 and len(fields) >= 20 and int(raw.split(b' ', 1)[0]) == pid,
         'OCR malformed child identity')
    return (pid, path.stat().st_uid, int(fields[2]), int(fields[3]), int(fields[19]))


def signal_owned(expected, number):
    need(len(expected) == 5 and expected[0] > 0 and
         expected[1:4] == (os.getuid(), expected[0], expected[0]),
         'OCR group authority session pin refused')
    need(child_identity(expected[0]) == expected, 'OCR child ownership UNKNOWN')
    os.killpg(expected[0], number)


def kill_direct_child(proc):
    # Trusted parent has never reaped this direct Popen child. Its PID cannot
    # be reused before wait; no session or numeric group authority is inferred.
    need(proc.returncode is None and proc.pid > 0, 'OCR direct child already reaped')
    os.kill(proc.pid, signal.SIGKILL)


def cleanup_child(proc, expected, failed):
    errors = []
    numbers = [signal.SIGTERM, signal.SIGKILL] if failed else [signal.SIGKILL]
    for number in numbers:
        try:
            signal_owned(expected, number)
        except (OSError, OCRError) as error:
            errors.append(type(error).__name__ + ':' + str(error)[:128])
        if number == signal.SIGTERM:
            time.sleep(0.1)
    if errors:
        try:
            kill_direct_child(proc)
        except (OSError, OCRError) as error:
            errors.append(type(error).__name__ + ':' + str(error)[:128])
    try:
        proc.wait(timeout=1)
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(type(error).__name__ + ':' + str(error)[:128])
    return errors


def finalize_child(proc, expected, failed, selector):
    errors = []
    if proc is not None:
        if expected is None:
            errors.append('initial full child identity UNKNOWN; never a successful verdict')
            try:
                kill_direct_child(proc)
                proc.wait(timeout=1)
            except (OSError, OCRError, subprocess.SubprocessError) as error:
                errors.append(type(error).__name__ + ':' + str(error)[:128])
        else:
            errors.extend(cleanup_child(proc, expected, failed))
        for pipe in [proc.stdout, proc.stderr]:
            try:
                pipe.close()
            except OSError as error:
                errors.append(type(error).__name__ + ':' + str(error)[:128])
    selector.close()
    return errors


class Budget:
    def __init__(self):
        self.lock = threading.Lock()
        self.used = {'text': 0, 'diagnostic': 0, 'metadata': 0}

    def charge(self, kind, amount):
        caps = {'text': MAX_READING, 'diagnostic': MAX_DIAGNOSTICS,
                'metadata': MAX_METADATA}
        with self.lock:
            need(0 <= amount and self.used[kind] + amount <= caps[kind],
                 'OCR cumulative ' + kind + ' bound')
            self.used[kind] += amount


def json_record(path, record, budget):
    data = json.dumps(record, sort_keys=True, ensure_ascii=True, indent=2,
                      allow_nan=False).encode('utf-8') + b'\n'
    budget.charge('metadata', len(data))
    with path.open('xb') as stream:
        need(stream.write(data) == len(data), 'OCR metadata short write')


def drain(selector, outputs, counts, budget):
    for key, _ in selector.select(timeout=0.01):
        kind = key.data
        cap = MAX_CHILD if kind == 'text' else 65536
        data = os.read(key.fd, min(CHUNK, cap - counts[kind] + 1))
        if not data:
            selector.unregister(key.fd)
        else:
            need(counts[kind] + len(data) <= cap, 'OCR child stream bound')
            budget.charge('diagnostic' if kind == 'errors' else kind, len(data))
            need(outputs[kind].write(data) == len(data), 'OCR capture short write')
            counts[kind] += len(data)


def run_child(argv, folder, label, deadline, stopped, budget, text=False, source_fd=None):
    output = folder / (label + ('.txt' if text else '.stdout'))
    error = folder / (label + '.stderr')
    check_clock(deadline, stopped)
    expected, failure, proc = None, None, None
    counts = {'text' if text else 'diagnostic': 0, 'errors': 0}
    with output.open('xb') as stdout, error.open('xb') as stderr:
        env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C',
               'LC_ALL': 'C', 'TMPDIR': str(folder), 'OMP_NUM_THREADS': '1',
               'OMP_THREAD_LIMIT': '1', 'TESSDATA_PREFIX': str(TRAINED.parent)}
        selector = selectors.DefaultSelector()
        try:
            proc = subprocess.Popen(bounded_command(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env,
                                    start_new_session=True,
                                    pass_fds=() if source_fd is None else (source_fd,))
            expected = child_identity(proc.pid)
            need(expected[1:4] == (os.getuid(), proc.pid, proc.pid), 'OCR child session pin')
            for pipe, kind in [(proc.stdout, 'text' if text else 'diagnostic'),
                               (proc.stderr, 'errors')]:
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, kind)
            outputs = {'text' if text else 'diagnostic': stdout, 'errors': stderr}
            for _ in range(6002):
                check_clock(deadline, stopped)
                drain(selector, outputs, counts, budget)
                done = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if done is not None and not selector.get_map():
                    break
            else:
                raise OCRError('OCR process observation bound')
        except BaseException as error_value:
            failure = type(error_value).__name__ + ':' + str(error_value)[:256]
        finally:
            cleanup_errors = finalize_child(proc, expected, failure is not None, selector)
    json_record(folder / (label + '.process.json'),
                {'argv': argv, 'bounded_argv': bounded_command(argv),
                 'returncode': None if proc is None else proc.returncode, 'failure': failure,
                 'cleanup_errors': cleanup_errors,
                 'counts': counts, 'child_identity': expected}, budget)
    need(failure is None and not cleanup_errors and proc is not None and proc.returncode == 0,
         'OCR tool refused: ' + str(failure) + repr(cleanup_errors))
    check_clock(deadline, stopped)
    return output


def png_dimensions(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        head = stream.read(24)
    need(stat.S_ISREG(info.st_mode) and 24 <= info.st_size <= MAX_CHILD,
         'OCR rendered image file bound')
    need(head[:16] == b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR', 'OCR PNG header')
    width, height = int.from_bytes(head[16:20], 'big'), int.from_bytes(head[20:24], 'big')
    need(0 < width <= 2000 and 0 < height <= 2000 and width * height <= 4000000,
         'OCR rendered pixel bound')
    return width, height


def validate_utf8(path):
    digest, used = hashlib.sha256(), 0
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    with path.open('rb') as stream:
        for _ in range(MAX_CHILD // CHUNK + 1):
            data = stream.read(CHUNK)
            if not data:
                decoder.decode(b'', final=True)
                return digest.hexdigest(), used
            used += len(data)
            need(used <= MAX_CHILD, 'OCR page text byte bound')
            decoder.decode(data, final=False)
            digest.update(data)
    raise OCRError('OCR text traversal bound')


def page_job(source, folder, page, deadline, stopped, budget):
    start = time.monotonic()
    page_deadline = min(deadline, start + PAGE_SECONDS)
    work_deadline = page_deadline - 2
    page_dir = folder / ('page-' + str(page).zfill(4))
    page_dir.mkdir(mode=0o700)
    image = page_dir / 'render.png'
    render = ['/usr/bin/pdftoppm', '-f', str(page), '-l', str(page), '-singlefile',
              '-r', '150', '-scale-to', '2000', '-png',
              '/proc/self/fd/' + str(source), str(page_dir / 'render')]
    run_child(render, page_dir, 'render', work_deadline, stopped, budget, source_fd=source)
    width, height = png_dimensions(image)
    image_hash, image_identity = digest_file(image, MAX_CHILD)
    command = ['/usr/bin/tesseract', str(image), 'stdout', '-l', 'eng', '--psm', '3']
    text = run_child(command, page_dir, 'ocr', work_deadline, stopped, budget, text=True)
    text_hash, size = validate_utf8(text)
    check_clock(page_deadline, stopped)
    record = {'page': page, 'render_sha256': image_hash, 'render_bytes': image_identity[2],
              'render_dimensions': [width, height], 'render_dpi': 150, 'max_side': 2000,
              'text_sha256': text_hash, 'text_bytes': size, 'text_path': str(text),
              'source_locator': {'page': page},
              'elapsed_seconds': time.monotonic() - start,
              'accuracy': 'UNPROVEN', 'image_retention': 'named successful ephemeral removal after verified hash'}
    json_record(page_dir / 'page.json', record, budget)
    check_clock(page_deadline, stopped)
    final_hash, final_identity = digest_file(image, MAX_CHILD)
    need(final_hash == image_hash and final_identity == image_identity, 'OCR image changed before removal')
    image.unlink()
    check_clock(page_deadline, stopped)
    return record


def footprint(folder):
    total, entries = 0, 0
    for base, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            info = (Path(base) / name).lstat()
            total += max(info.st_size, info.st_blocks * 512)
            entries += 1
            need(total <= MAX_WORKING and entries <= 16384, 'OCR working storage bound')
    return {'allocated_or_logical_bytes': total, 'entries': entries}


def open_pdf_source(source):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= MAX_SOURCE,
             'OCR source descriptor')
        return fd
    except BaseException:
        os.close(fd)
        raise


def collect_pages(source, folder, pages, deadline, budget):
    stopped, records, pending = threading.Event(), {}, {}
    iterator = iter(pages)
    fd = open_pdf_source(source)
    executor = None
    try:
        executor = ThreadPoolExecutor(max_workers=WORKERS)
        for _ in range(min(WORKERS, len(pages))):
            page = next(iterator)
            future = executor.submit(page_job, fd, folder, page, deadline, stopped, budget)
            pending[future] = page
        for _ in range(30002):
            check_clock(deadline, stopped)
            done, _ = wait(pending, timeout=min(0.1, max(0, deadline - time.monotonic())),
                           return_when=FIRST_COMPLETED)
            if not done:
                continue
            for future in done:
                page = pending.pop(future)
                records[page] = future.result()
                footprint(folder)
                try:
                    new_page = next(iterator)
                except StopIteration:
                    continue
                new = executor.submit(page_job, fd, folder, new_page, deadline, stopped, budget)
                pending[new] = new_page
            if not pending:
                break
        need(not pending and len(records) == len(pages), 'OCR page collection incomplete')
    except BaseException:
        stopped.set()
        raise
    finally:
        try:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
        finally:
            os.close(fd)
    return [records[page] for page in pages]


def combine(folder, records, budget, deadline):
    segments, digest, size = [], hashlib.sha256(), 0
    with (folder / 'reading.txt').open('xb') as output:
        for number, record in enumerate(records, 1):
            need(record['page'] == number, 'OCR ordered complete page index')
            start = size
            path = Path(record['text_path'])
            actual_hash, actual_size = validate_utf8(path)
            need(actual_hash == record['text_sha256'] and actual_size == record['text_bytes'],
                 'OCR retained page text mismatch')
            with path.open('rb') as stream:
                for _ in range(MAX_CHILD // CHUNK + 1):
                    check_clock(deadline, threading.Event())
                    data = stream.read(CHUNK)
                    if not data:
                        break
                    need(size + len(data) <= MAX_READING, 'OCR complete reading byte bound')
                    need(output.write(data) == len(data), 'OCR reading short write')
                    size += len(data)
                    digest.update(data)
            segments.append({'id': 's' + str(number), 'label': 'Page ' + str(number),
                             'start': start, 'end': size, 'kind': 'page',
                             'source_locator': {'page': number}})
    return segments, digest.hexdigest(), size


def query_tools(folder, deadline, budget):
    versions = {}
    stopped = threading.Event()
    for tool, args in [('tesseract', ['--version']), ('pdftoppm', ['-v']),
                       ('pdfinfo', ['-v']), ('prlimit', ['--version'])]:
        output = run_child(['/usr/bin/' + tool] + args, folder, tool + '-version',
                           min(deadline, time.monotonic() + 8), stopped, budget)
        raw = output.read_bytes() + (folder / (tool + '-version.stderr')).read_bytes()
        lines = raw.decode('utf-8', 'strict').splitlines()
        need(bool(lines) and len(lines[0]) <= 256, 'OCR tool version missing or bound')
        versions[tool] = lines[0]
    versions['language'] = 'eng'
    versions['eng.traineddata-sha256'] = digest_file(TRAINED, 33554432)[0]
    return versions


def query_pages(source, folder, deadline, budget):
    fd = open_pdf_source(source)
    try:
        output = run_child(['/usr/bin/pdfinfo', '/proc/self/fd/' + str(fd)], folder,
                           'pdfinfo', min(deadline, time.monotonic() + 8),
                           threading.Event(), budget, source_fd=fd)
    finally:
        os.close(fd)
    data = output.read_bytes()
    return page_count(data)


def page_count(data):
    need(type(data) is bytes and len(data) <= 65536, 'OCR pdfinfo output bound')
    matches = re.findall(rb'^Pages:[ \t]+([0-9]{1,5})[ \t]*\r?$', data, re.MULTILINE)
    need(len(matches) == 1, 'OCR PDF page count missing or ambiguous')
    pages = int(matches[0])
    need(1 <= pages <= MAX_PAGES, 'OCR PDF page count bound')
    return pages


def schedule_fit(pages, seconds):
    need(type(pages) is int and 1 <= pages <= MAX_PAGES, 'OCR page count bound')
    need(type(seconds) is int and 1 <= seconds <= 3000, 'OCR requested seconds bound')
    batches = (pages + WORKERS - 1) // WORKERS
    scheduled = batches * PAGE_SECONDS + ORCHESTRATION_MARGIN_SECONDS + MERGE_MARGIN_SECONDS
    need(scheduled <= seconds, 'OCR complete page schedule does not fit')
    # Conservative file-allocation padding for eight named entries per page.
    reserve = MAX_READING * 2 + MAX_CHILD * WORKERS + MAX_DIAGNOSTICS + MAX_METADATA
    reserve += pages * 8 * 4096 + 1048576
    need(reserve <= MAX_WORKING, 'OCR complete working-storage schedule does not fit')
    return {'pages': pages, 'workers': WORKERS, 'batches': batches,
            'page_total_seconds': PAGE_SECONDS, 'orchestration_merge_margin_seconds': ORCHESTRATION_MARGIN_SECONDS + MERGE_MARGIN_SECONDS,
            'conditional_scheduled_seconds': scheduled, 'reserved_bytes': reserve}


def extract_ocr_reading(source, out_dir, seconds=3000):
    started = time.monotonic()
    need(type(seconds) is int and 1 <= seconds <= 3000, 'OCR requested seconds bound')
    deadline, budget = started + seconds, Budget()
    source = Path(source)
    source_hash, source_identity = digest_file(source, MAX_SOURCE)
    folder = Path(out_dir)
    folder.mkdir(mode=0o700)
    versions = query_tools(folder, deadline, budget)
    pages = query_pages(source, folder, deadline, budget)
    plan = schedule_fit(pages, seconds)
    check_clock(min(deadline, started + ORCHESTRATION_MARGIN_SECONDS), threading.Event())
    records = collect_pages(source, folder, list(range(1, pages + 1)),
                            deadline - MERGE_MARGIN_SECONDS, budget)
    segments, text_hash, text_bytes = combine(folder, records, budget, deadline)
    final_hash, final_identity = digest_file(source, MAX_SOURCE)
    need(final_hash == source_hash and final_identity == source_identity, 'OCR source changed')
    report = {'schema': 'transport/reading-view/1', 'format': 'pdf',
              'tool_versions': versions, 'source_sha256': source_hash,
              'text_sha256': text_hash, 'text_bytes': text_bytes,
              'text_path': 'reading.txt', 'segments': segments,
              'coverage': {'pages': pages, 'ocr_pages': len(records), 'method': 'tesseract-eng-psm3',
                           'schedule': plan,
                           'blank_ocr_pages': [r['page'] for r in records if r['text_bytes'] == 0]},
              'uncertainty': ['OCR accuracy and semantic completeness UNPROVEN.',
                              'Names, numbers and quotations may be wrong; verify against original pages.',
                              'Empty OCR text does not prove that the original page is blank.',
                              'Diagrams, equations, layout and reading order are not preserved.']}
    json_record(folder / 'reading.json', report, budget)
    observed, _ = digest_file(folder / 'reading.txt', MAX_READING)
    need(observed == text_hash, 'OCR complete reading hash readback')
    footprint(folder)
    check_clock(deadline, threading.Event())
    return dict(report, text_path=folder / 'reading.txt', reading_json_path=folder / 'reading.json')
