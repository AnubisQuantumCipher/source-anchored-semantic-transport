#!/usr/bin/env python3
"""Replay seven unchanged receipt derivations using two explicit historical controls."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMPONENTS = ('graph', 'input', 'source', 'claim', 'impact', 'context', 'reading')
ALIASES = ('install/check_source.py', '.github/workflows/source.yml')
FILE_CAP = 1_048_576
TOTAL_CAP = 16_777_216
ROW_CAP = 511  # Plus the retained receipt: at most 512 staged payload files.


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(name):
    require(isinstance(name, str) and 0 < len(name) <= 4096, 'input path byte bound')
    require(not name.startswith('/') and '\\' not in name and '\x00' not in name, 'unsafe input path')
    parts = name.split('/')
    require(len(parts) <= 32 and all(part not in ('', '.', '..') and len(part) <= 255 for part in parts),
            'unsafe input path component')
    return Path(*parts)


def read(root, name):
    path = root / relative(name)
    for parent in (path, *path.parents):
        if parent == root:
            break
        require(not parent.is_symlink(), 'symlink receipt input refused')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= FILE_CAP, 'receipt regular file/byte bound')
    with path.open('rb') as stream:
        raw = stream.read(FILE_CAP + 1)
    require(len(raw) == info.st_size and len(raw) <= FILE_CAP, 'receipt changed/oversized input')
    return raw


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def historical(here):
    base = here / 'historical-inputs'
    manifest = json.loads(read(base, 'manifest.json'))
    require(manifest['schema'] == 'document-profile/historical-controls/1', 'historical schema')
    require(manifest['origin_git_commit'] == 'ad2befaf7e89e73790bd5ab462158225f4b864b2', 'historical origin')
    require(set(manifest['aliases']) == set(ALIASES), 'exact two historical aliases required')
    found = {}
    for name in ALIASES:
        expected = manifest['aliases'][name]
        require(expected['path'] == name, 'historical alias path changed')
        raw = read(base, name)
        require(pin(raw) == {key: expected[key] for key in ('bytes', 'sha256')}, 'historical bytes changed')
        found[name] = raw
    return found



def profile(here, component):
    manifest = json.loads(read(here / 'historical-inputs', 'manifest.json'))
    require(set(manifest['profiles']) == set(COMPONENTS), 'exact seven retained profile roster')
    return manifest['profiles'][component]


def selected(root, here, component):
    require(component in COMPONENTS, 'unknown fixed receipt component')
    receipt_name = 'examples/quorum-' + component + '-v1/receipt.json'
    receipt_raw = read(root, receipt_name)
    expected_profile = profile(here, component)
    require(expected_profile['receipt']['path'] == receipt_name, 'fixed retained receipt path')
    require(pin(receipt_raw) == {key: expected_profile['receipt'][key] for key in ('bytes', 'sha256')},
            'retained receipt identity changed')
    receipt = json.loads(receipt_raw)
    rows = receipt['files']
    require(isinstance(rows, list) and 1 <= len(rows) <= ROW_CAP, 'receipt file roster bound')
    aliases = historical(here)
    paths, total, data = set(), len(receipt_raw), {}
    for row in rows:
        name = row['path']
        relative(name)
        require(name not in paths and name != receipt_name, 'duplicate/cyclic receipt input')
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= FILE_CAP, 'declared file byte bound')
        paths.add(name)
        total += row['bytes']
        require(total <= TOTAL_CAP, 'receipt aggregate byte bound')
        raw = aliases[name] if name in aliases else read(root, name)
        require(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'current or historical input mismatch: ' + name)
        data[name] = raw
    require(set(ALIASES).issubset(paths), 'both historical control aliases must be declared')
    preparer = 'examples/quorum-' + component + '-v1/prepare_receipt.py'
    require(preparer in data and expected_profile['preparer']['path'] == preparer, 'fixed receipt-pinned preparer required')
    require(pin(data[preparer]) == {key: expected_profile['preparer'][key] for key in ('bytes', 'sha256')},
            'unchanged preparer identity required')
    data[receipt_name] = receipt_raw
    return data, preparer


def stage(folder, data):
    require(len(data) <= 512 and sum(len(raw) for raw in data.values()) <= TOTAL_CAP, 'staging budget')
    for name, raw in data.items():
        target = folder / relative(name)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            require(stream.write(raw) == len(raw), 'staged input short write')
        require(read(folder, name) == raw, 'staged input readback mismatch')


def child_limits():
    for kind, cap in ((resource.RLIMIT_AS, 1_073_741_824), (resource.RLIMIT_FSIZE, 65_536),
                      (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64)):
        soft, hard = resource.getrlimit(kind)
        bound = min([cap] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (bound, bound))


def replay(root, here, component):
    data, preparer = selected(root, here, component)
    with tempfile.TemporaryDirectory(prefix='quorum-historical-replay-') as name:
        folder = Path(name)
        stage(folder, data)
        stdout, stderr = folder / 'replay.stdout', folder / 'replay.stderr'
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-Werror', str(folder / preparer), '--check'],
                cwd=folder, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                                 'TMPDIR': str(folder)}, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                timeout=30, check=False, preexec_fn=child_limits)
        out_raw, err_raw = read(folder, 'replay.stdout'), read(folder, 'replay.stderr')
        require(result.returncode == 0 and not err_raw, 'historical derivation failed: ' + err_raw[:4096].decode('utf8', 'replace'))
    return {'component': component, 'status': 'HISTORICAL_RECEIPT_REPLAY_CHECKED',
            'input_files': len(data), 'input_bytes': sum(len(raw) for raw in data.values()),
            'historical_aliases': list(ALIASES), 'current_non_alias_inputs': 'MATCH_RETAINED_PINS',
            'current_static_controls': 'RUN_SEPARATELY; no current CI equivalence claimed',
            'preparer_stdout': out_raw.decode('ascii').strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=COMPONENTS, required=True)
    args = parser.parse_args()
    print(json.dumps(replay(ROOT, HERE, args.component), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('HISTORICAL_REPLAY_REFUSED: ' + str(error)[:4096], file=sys.stderr)
        sys.exit(2)
