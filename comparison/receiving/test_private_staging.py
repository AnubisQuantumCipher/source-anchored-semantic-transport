#!/usr/bin/env python3
"""Literal private-chain controls in new synthetic trees; no live repair."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPER_SHA = 'f4ad19ca3bfdd480697213c51c7578ef96dec7bcbb4c15f5a01dacde0eba9f6a'
ORACLE_SHA = '9dadb0102c7862c6323ad87667bb002bc65bb4e4962d6b1b68a845ed5af8b984'
LIVE = Path('/dev/shm/semantic-transport-receiving-20261029/receivers')


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def read(path, cap=1048576):
    need(path.is_file() and not path.is_symlink(), 'regular nonsymlink fixture')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'fixture byte bound')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = value if type(value) is bytes else encode(value)
    need(len(raw) <= 1048576, 'fixture output bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short fixture write')
    need(read(path) == raw, 'fixture readback')
    return dict(bytes=len(raw), sha256=sha(raw))


def mode(path):
    return '0%03o' % stat.S_IMODE(path.lstat().st_mode)


def observe(function, *args):
    try:
        value = function(*args)
        return dict(status='PASS', value=str(value) if isinstance(value, Path) else value)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        return dict(status='REFUSED', reason=str(error)[:256])


def load():
    path = HERE / 'private_staging.py'
    specification = importlib.util.spec_from_file_location('private_staging_under_test', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def live_pins():
    result = {}
    for arm in ('original', 'transport'):
        directory = LIVE / arm
        value = dict(mode=mode(directory), uid=directory.lstat().st_uid)
        raw = read(directory / 'answer.json', 32768)
        value['answer'] = dict(bytes=len(raw), sha256=sha(raw), mode=mode(directory / 'answer.json'))
        result[arm] = value
    return result


def fixture(root, case):
    directory = root / case['id']
    directory.mkdir(mode=0o700)
    anchor = directory / 'anchor'
    anchor.mkdir(mode=0o700)
    os.chmod(anchor, int(case['input']['anchor_mode'], 8))
    for item in case['input']['existing']:
        path = anchor / item['path']
        if item['kind'] == 'directory':
            path.mkdir(mode=0o700)
            os.chmod(path, int(item['mode'], 8))
            if 'marker_utf8' in item:
                save(path / 'marker', item['marker_utf8'].encode('utf-8'))
        elif item['kind'] == 'symlink':
            path.symlink_to(item['target_relative'])
        else:
            need(item['kind'] == 'regular_file', 'literal fixture kind')
            save(path, item['raw_utf8'].encode('utf-8'))
    return anchor


def missing(anchor, relative, case_id):
    path = anchor / relative
    try:
        path.lstat()
        return False
    except FileNotFoundError:
        return True
    except PermissionError:
        need(case_id == 'restrictive_umask_no_silent_permission_repair'
             and relative == 'receivers/transport' and mode(anchor / 'receivers') == '0000',
             'unexpected inaccessible fixture')
        parent = anchor / 'receivers'
        os.chmod(parent, 0o700)
        try:
            return not any(parent.iterdir())
        finally:
            os.chmod(parent, 0o000)


def expected_state(anchor, case):
    expected, observed, passed = case['expected'], {}, True
    for relative, required in expected.get('modes', {}).items():
        actual = mode(anchor / relative)
        observed[relative] = actual
        passed = passed and actual == required
    for relative in expected.get('must_not_exist', []):
        absent = missing(anchor, relative, case['id'])
        observed[relative + ':absent'] = absent
        passed = passed and absent
    if 'anchor_mode' in expected:
        observed['anchor'] = mode(anchor)
        passed = passed and observed['anchor'] == expected['anchor_mode']
    if 'created_receivers_mode' in expected:
        observed['created_receivers_mode'] = mode(anchor / 'receivers')
        passed = passed and observed['created_receivers_mode'] == expected['created_receivers_mode']
    for item in case['input']['existing']:
        path = anchor / item['path']
        if 'marker_utf8' in item:
            passed = passed and read(path / 'marker') == item['marker_utf8'].encode('utf-8')
        if item['kind'] == 'regular_file':
            passed = passed and read(path) == item['raw_utf8'].encode('utf-8')
        if item['kind'] == 'symlink':
            passed = passed and path.is_symlink() and os.readlink(path) == item['target_relative']
    return observed, passed


def literal_case(root, case, helper):
    anchor = fixture(root, case)
    previous = os.umask(int(case['input']['umask'], 8))
    try:
        actual = observe(helper.chain, anchor, case['input']['requested_relative'])
    finally:
        os.umask(previous)
    state, passed = expected_state(anchor, case)
    passed = passed and actual['status'] == case['expected']['disposition']
    if actual['status'] == 'PASS':
        passed = passed and actual['value'] == str(anchor / case['input']['requested_relative'])
    return dict(name=case['id'], expected=case['expected'], observed=actual, state=state, passed=passed)


def private_fixture(root, name):
    directory = root / name
    directory.mkdir(mode=0o700)
    anchor = directory / 'anchor'
    anchor.mkdir(mode=0o700)
    parent = anchor
    for component in ('receivers', 'transport', 'input'):
        parent = parent / component
        parent.mkdir(mode=0o700)
    return anchor, parent


def additional_cases(root, helper):
    results = []
    anchor, parent = private_fixture(root, 'wrong-owner')
    actual_uid = os.geteuid()
    with patch.object(helper.os, 'geteuid', return_value=actual_uid + 1):
        actual = observe(helper.chain, anchor, 'receivers/transport/input', False)
    results.append(dict(name='wrong_owner_refuses', observed=actual, expected='REFUSED',
                        passed=actual['status'] == 'REFUSED' and not any(parent.iterdir())))
    anchor, parent = private_fixture(root, 'mode-drift')
    os.chmod(parent.parent, 0o755)
    actual = observe(helper.write_new, anchor, 'receivers/transport/input', 'payload.bin', b'INERT')
    results.append(dict(name='mode_drift_before_use_refuses', observed=actual, expected='REFUSED',
        passed=actual['status'] == 'REFUSED' and mode(parent.parent) == '0755' and not (parent / 'payload.bin').exists()))
    anchor, parent = private_fixture(root, 'existing-payload')
    save(parent / 'payload.bin', b'KEEP_PAYLOAD')
    actual = observe(helper.write_new, anchor, 'receivers/transport/input', 'payload.bin', b'REPLACE_FORBIDDEN')
    results.append(dict(name='existing_payload_refuses', observed=actual, expected='REFUSED',
        passed=actual['status'] == 'REFUSED' and read(parent / 'payload.bin') == b'KEEP_PAYLOAD'))
    return results


def freeze(root):
    pins = {}
    for index, name in enumerate(('private_staging.py', 'private-staging-oracle.json', 'test_private_staging.py')):
        raw = read(HERE / name)
        pins[name] = save(root / ('source-%02d.bin' % index), raw)
    need(pins['private_staging.py']['sha256'] == HELPER_SHA, 'held helper differs')
    need(pins['private-staging-oracle.json']['sha256'] == ORACLE_SHA, 'held oracle differs')
    save(root / 'source-pins.json', pins)
    return pins, json.loads(read(HERE / 'private-staging-oracle.json'))


def static_control():
    report = {}
    for name in ('private_staging.py', 'test_private_staging.py'):
        tree = ast.parse(read(HERE / name))
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        lengths = {n.name: n.end_lineno - n.lineno + 1 for n in functions}
        need(all(size <= 60 for size in lengths.values()), 'function size bound')
        need(not any(isinstance(n, (ast.Assert, ast.While, ast.AsyncFor)) for n in ast.walk(tree)),
             'bounded explicit control flow and runtime checks')
        if name == 'private_staging.py':
            need(not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                         and n.func.attr in ('chmod', 'fchmod', 'chown', 'fchown') for n in ast.walk(tree)),
                 'no helper permission or ownership repair')
        report[name] = lengths
    return report


def run(root):
    need(root.is_absolute() and root.parent.is_dir() and not root.exists(), 'new synthetic test root')
    root.mkdir(mode=0o700)
    cases_root = root / 'cases'
    cases_root.mkdir(mode=0o700)
    pins, oracle = freeze(root)
    save(root / 'static-controls.json', static_control())
    before = live_pins()
    save(root / 'live-before.json', before)
    helper = load()
    results = [literal_case(cases_root, case, helper) for case in oracle['cases']]
    results.extend(additional_cases(cases_root, helper))
    after = live_pins()
    save(root / 'live-after.json', after)
    results.append(dict(name='frozen_live_paths_untouched', expected=dict(changed=False),
                        observed=dict(changed=after != before), passed=after == before))
    for name, pin in pins.items():
        raw = read(HERE / name)
        need(dict(bytes=len(raw), sha256=sha(raw)) == pin, 'source changed during controls')
    save(root / 'results.json', results)
    paths = list(root.rglob('*'))
    need(len(paths) <= 128, 'fixture member bound')
    total = sum(p.lstat().st_size for p in paths if p.is_file() and not p.is_symlink())
    need(total <= 1048576, 'fixture byte bound')
    failed = [item['name'] for item in results if not item['passed']]
    receipt = dict(schema='transport/private-staging-controls/1', status='PASS' if not failed else 'FAILED',
        optimized=bool(sys.flags.optimize), literal_cases=14, additional_cases=4, failed_cases=failed,
        code_pins=pins, actual_fixture_bytes_before_receipt=total, models='UNRUN', live_path_repair=False,
        first_attempt_transport_outcome='FAILED_RETAINED', authority='NONE', os_confinement='UNPROVEN')
    save(root / 'receipt.json', receipt)
    print(encode(receipt).decode('ascii'))
    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    for kind, bound in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_FSIZE, 4194304), (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(kind, (bound, bound))
    return run(args.evidence)


if __name__ == '__main__':
    sys.exit(main())
