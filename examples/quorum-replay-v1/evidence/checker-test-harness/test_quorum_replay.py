#!/usr/bin/env python3
"""Portable pure-core replay controls. Host qualification is tested separately.

These tests supply synthetic private host observations. They do not qualify an
installed decoder, exercise a ZIP adapter or authenticate any record.
"""

import argparse
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_quorum_replay as product

HERE = ROOT / 'examples/quorum-replay-v1'
ORACLES = {
    'literal-controls': 'b099e497db319db078e7d42a0b3a1a3100ebc3adc0a52442c47d0a0b36d4bec8',
    'additional-literals/revision-02': '09a3bd98b47cb6e265979437731a9ba301d08348c0e47f974712d299fe104e72',
}
ARRAYS = ('blobs', 'challenges', 'claims', 'dependencies', 'history', 'input_manifests',
          'provenance', 'reading_withdrawals', 'readings', 'rules', 'run_evidence',
          'selectors', 'sources', 'tasks', 'updates')
RESULTS = []


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected regular fixture file')
    with path.open('rb') as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError('Fixture byte bound')
    return raw


def C(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def record(value, address=None):
    return dict(id=value['id'] if address is None else address, **pin(C(value)))


def source_key(label, raw=b''):
    return dict(logical_source_id=label, **pin(raw))


def qualification():
    # Deliberately synthetic: no public host receipt or qualification is claimed.
    return dict(wire_schema=source_key('WIRE_SCHEMA', read(ROOT / 'tools/transport_quorum_body.schema.json')),
        protocol_rules=source_key('PROTOCOL_RULES', read(ROOT / 'tools/transport_quorum_protocol-rules.json')),
        checker=dict(supported_platform='LINUX_OMARCHY_ONLY',
            checker_descriptor=source_key('SYNTHETIC_CHECKER'),
            runtime_descriptor=source_key('SYNTHETIC_RUNTIME'),
            decoder_install_descriptor=source_key('SYNTHETIC_INSTALL')))


def request(body, raw, package, qualified):
    pins = [record(body['registry']), record(body['policy'])]
    pins += [record(r) for r in body['registry']['seats']]
    for name in ARRAYS:
        for row in body[name]:
            address = row['id'] + ':' + row['revision'] if name == 'claims' else row['id']
            pins.append(record(row, address))
    return dict(schema='quorum/replay-request/1', package=pin(package), quorum_body=pin(raw),
        task=record(body['tasks'][0]), registry=record(body['registry']),
        rules=sorted([record(r) for r in body['rules']], key=C), policy=record(body['policy']),
        wire_schema=qualified['wire_schema'], protocol_rules=qualified['protocol_rules'],
        checker=copy.deepcopy(qualified['checker']), record_pins=sorted(pins, key=C),
        input_manifest_pins=sorted([record(r) for r in body['input_manifests']], key=C),
        external_source_pins=sorted({C(r['key']): r['key'] for r in body['sources']}.values(), key=C))


def overrides(value, held, patches):
    for patch in patches:
        scope = patch['scope']
        if scope == 'held_Request':
            held[patch['path'].lstrip('/')] = patch['value']
        elif scope == 'Request':
            parent, parts = value, patch['path'].strip('/').split('/')
            for part in parts[:-1]:
                parent = parent[part]
            parent[parts[-1]] = patch['value']
        elif scope == 'Request.record_pins':
            if 'remove_id' in patch:
                value['record_pins'] = [r for r in value['record_pins'] if r['id'] != patch['remove_id']]
            else:
                for row in value['record_pins']:
                    if row['id'] == patch['id']:
                        row[patch['path'].lstrip('/')] = patch['value']
        else:
            raise ValueError('Unadmitted mechanical override')


def expected_with_request(value, held):
    result, pending = copy.deepcopy(value), []
    pending.append(result)
    for unused in range(8192):
        if not pending:
            return result
        item = pending.pop()
        if type(item) is dict:
            for name, child in list(item.items()):
                if type(child) is dict and set(child) == {'$mechanical'}:
                    item[name] = dict(id='REPLAY_REQUEST', **held)
                elif type(child) in (list, dict):
                    pending.append(child)
        elif type(item) is list:
            pending.extend(child for child in item if type(child) in (list, dict))
    raise ValueError('Expected template work bound')


def inputs(files):
    raw, qualified = files['body.json'], qualification()
    frozen_host = C(qualified)
    try:
        body = json.loads(raw)
    except (UnicodeError, ValueError):
        body = json.loads(read(HERE / 'literal-controls/F01_ORIGINAL_ACCEPT/body.json'))
    originals = tuple((r['alias_id'], r['key'], base64.b64decode(r['base64'], validate=True))
                      for r in json.loads(files['originals.json'])['items'])
    package = files['original-source-envelope.json']
    value, mutation = request(body, raw, package, qualified), json.loads(files['materialization.json'])
    changes = mutation['identity_overrides_after_mechanical_pin_derivation']
    overrides(value, {}, [p for p in changes if p['scope'] != 'held_Request'])
    request_raw = C(value)
    held = pin(request_raw)
    overrides(value, held, [p for p in changes if p['scope'] == 'held_Request'])
    auxiliary, receipt = None, None
    if 'auxiliary-input.json' in files:
        row = json.loads(files['auxiliary-input.json'])
        data = base64.b64decode(row['base64'], validate=True)
        auxiliary = (row['alias_id'], row['key'], data, row['key'])
        receipt = dict(validate_import=mutation['receipt_validate_import'],
            received_result_source=row['key'], received_result_sha256=row['key']['sha256'],
            received_result_bytes=row['key']['bytes'], claimed_verdict=mutation['claimed_verdict'])
    envelope = dict(schema='quorum/external-replay-envelope/1', request=value, untrusted_receipt=receipt)
    if C(qualified) != frozen_host:
        raise ValueError('Candidate mutated host observations')
    expected = expected_with_request(json.loads(files['expected.json']), held)
    return (request_raw, C(envelope), raw, originals, package, held, qualified, auxiliary), expected


def cases(group):
    raw = read(HERE / group / 'oracle.json')
    if hashlib.sha256(raw).hexdigest() != ORACLES[group]:
        raise ValueError('Independent oracle changed')
    result = json.loads(raw)['cases']
    if len(result) > 23:
        raise ValueError('Case bound')
    return result


def case_files(group, case):
    result = {}
    for row in case['files']:
        name = Path(row['path']).name
        raw = read(HERE / group / case['id'] / name)
        if pin(raw) != dict(bytes=row['bytes'], sha256=row['sha256']):
            raise ValueError('Independent literal changed')
        result[name] = raw
    return result


class ReplayTests(unittest.TestCase):
    def test_frozen_complete_replay_results(self):
        for group in ORACLES:
            for case in cases(group):
                with self.subTest(group=group, case=case['id']):
                    files = case_files(group, case)
                    mutation = json.loads(files['materialization.json'])
                    if mutation['outer_host_mutations']:
                        self.assertEqual(case['id'], 'F08_MISSING_CHECKER_AND_GRAPH')
                        continue  # Only this frozen outer-host case is outside core scope.
                    args, expected = inputs(files)
                    actual = product._replay(*args)
                    RESULTS.append(dict(case=case['id'], actual=actual, expected=expected))
                    self.assertEqual(actual, expected)
                    self.assertLessEqual(len(C(actual)) + 1, 131072)

    def test_bounded_source_structure(self):
        for relative in ('tools/transport_quorum_replay.py', 'install/transport_quorum_bootstrap.py'):
            tree = ast.parse(read(ROOT / relative))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)
                self.assertNotIsInstance(node, (ast.Assert, ast.While))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests))
    if args.evidence:
        payload = dict(schema='quorum/portable-core-controls/1', passed=result.wasSuccessful(),
            outputs=RESULTS, oracle_pins=ORACLES, python=sys.version,
            scope='PURE_CORE_WITH_SYNTHETIC_HOST_OBSERVATIONS; NOT_HOST_OR_ZIP_ACCEPTANCE',
            source_pins={str(p.relative_to(ROOT)): pin(read(p)) for p in
                sorted((ROOT / 'tools').glob('transport_quorum_*.py'))},
            authority='NONE', semantic_completeness='UNPROVEN', product_acceptance=False)
        raw = C(payload)
        if len(raw) > 1048576:
            raise ValueError('Evidence byte bound')
        with args.evidence.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('Short evidence write')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
