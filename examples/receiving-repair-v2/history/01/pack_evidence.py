"""Create-only collation of this public trial; never copy raw model journals."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

REPO = Path(__file__).resolve().parents[2]
BASE = Path('/dev/shm/semantic-transport-core-20261029/evidence')
FINAL = BASE / 'receiving-repair-02/final'
TESTS = BASE / 'receiving-repair-tests-02'
OLD = Path('/dev/shm/semantic-transport-receiving-20261029')
CAP, TOTAL, COUNT = 1048576, 4194304, 512


def need(ok, reason):
    if type(ok) is not bool or not ok:
        raise ValueError(reason)


def read(path):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_size <= CAP, 'REGULAR_BOUNDED_SOURCE')
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    need(len(raw) == meta.st_size, 'SOURCE_CHANGED_OR_BOUND')
    return raw


def add(data, origins, name, path):
    need(name not in data and len(data) < COUNT, 'DUPLICATE_OR_COUNT')
    raw = read(path)
    need(sum(len(value) for value in data.values()) + len(raw) <= TOTAL, 'TOTAL_BOUND')
    data[name] = raw
    origins[name] = {'path': str(path), 'bytes': len(raw),
                     'sha256': hashlib.sha256(raw).hexdigest()}


def tree(data, origins, prefix, root):
    queue = [root]
    for unused in range(128):
        if not queue:
            return
        directory = queue.pop(0)
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries):
                need(count < 128 and len(queue) < 128, 'DIRECTORY_BOUND')
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    queue.append(path)
                else:
                    add(data, origins, prefix + '/' + str(path.relative_to(root)), path)
    raise ValueError('TREE_DEPTH_BOUND')


def capture(data, origins, prefix, root):
    report = json.loads(read(root / 'report.json'))
    need(report['schema'] == 'transport/handoff-trace-capture/5', 'CAPTURE_SCHEMA')
    names = {'report.json'}
    for event in report['events']:
        need(event['kind'] in ('custom_tool_call', 'custom_tool_call_output',
                              'function_call', 'function_call_output'), 'EVENT_KIND')
        names.add(event['path'])
        if 'source' in event:
            names.add(event['source']['path'])
    for record in report['final_responses']:
        names.add(record['text_file']['path'])
    for name in sorted(names):
        need(Path(name).name == name and name not in ('.', '..'), 'CAPTURE_PATH')
        add(data, origins, prefix + '/' + name, root / name)


def collect():
    data, origins = {}, {}
    tree(data, origins, 'trial', FINAL)
    tree(data, origins, 'source/comparison/receiving', REPO / 'comparison/receiving')
    tree(data, origins, 'assessment', TESTS / 'assessment-X07')
    tree(data, origins, 'citation-check', TESTS / 'citation-check')
    capture(data, origins, 'receiver-capture', TESTS / 'receiver-capture')
    capture(data, origins, 'assessor-capture', TESTS / 'assessment-capture-02')
    capture(data, origins, 'first-failed/capture', OLD / 'captures/transport-02')
    for name in ('answer.json', 'launch.json', 'input/interface.txt', 'input/task.txt'):
        add(data, origins, 'first-failed/' + name, OLD / 'receivers/transport' / name)
    for name in ('dispatch.json', 'dispatch-time-clarification.json',
                 'independent-postlaunch-review.json', 'independent-postlaunch-review-attempt01.json',
                 'assessment-capture-scope.json', 'root-comparison-mode-observation.json'):
        add(data, origins, 'observations/' + name, TESTS / name)
    for stem in ('normal', 'optimized', 'normal-02', 'optimized-02'):
        for suffix in ('.stdout', '.stderr', '.run.json'):
            add(data, origins, 'staging-controls/' + stem + suffix, TESTS / (stem + suffix))
    for name in ('final-seal.json', 'post-attempt-metadata-review.json',
                 'post-attempt-repair-admission.json', 'capture-before-candidate-repair.py',
                 'capture-before-integer-repair.py', 'trace-support-before-integer-repair.py'):
        add(data, origins, 'first-failed/preflight/' + name, OLD / 'preflight' / name)
    return data, origins


def dependencies(data, origins):
    config = json.loads(data['trial/preflight/config.json'])
    for item in config['dependencies']:
        path = Path(item['path'])
        if path.is_relative_to(REPO) and path.suffix == '.py':
            name = 'source/' + str(path.relative_to(REPO))
            if name not in data:
                add(data, origins, name, path)
        elif path.suffix == '.py':
            add(data, origins, 'installed-python/' + path.name, path)
    qualified = json.loads(data['trial/preflight/qualified-controls.json'])
    for number, run in enumerate(qualified['runs']):
        for name in ('receipt', 'results', 'exit'):
            add(data, origins, f'qualified-controls/{number}/{name}.json', Path(run[name]['path']))
        for index, record in enumerate(run.get('cli', [])):
            for name in ('result', 'stdout', 'stderr'):
                add(data, origins, f'qualified-controls/{number}/cli-{index}/{name}',
                    Path(record[name]['path']))


def archive(data, origins):
    data['_inventory.json'] = json.dumps(origins, sort_keys=True, separators=(',', ':')).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
        for name, raw in sorted(data.items()):
            record = tarfile.TarInfo(name)
            record.size, record.mode, record.mtime = len(raw), 0o644, 0
            bundle.addfile(record, io.BytesIO(raw))
    need(buffer.tell() <= TOTAL, 'TAR_BOUND')
    return gzip.compress(buffer.getvalue(), mtime=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data, origins = collect()
    dependencies(data, origins)
    raw = archive(data, origins)
    with args.out.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'SHORT_WRITE')
    print(json.dumps({'files': len(data), 'archive_bytes': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest()}))


if __name__ == '__main__':
    main()
