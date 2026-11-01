"""Independent synthetic proof/build boundary controls; all process launches denied."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'sentinel_native'))
import sentinel_qualification as subject
import sentinel_build_profile as profile
import build_sentinel_policy as builder

CATEGORIES = ('Data Dependencies', 'Flow Dependencies', 'Initialization', 'Non-Aliasing',
              'Run-time Checks', 'Assertions', 'Functional Contracts', 'LSP Verification',
              'Termination', 'Concurrency')
ENTITIES = [{'name': 'Sentinel_Policy', 'file': 'sentinel_policy.ads', 'line': 1,
             'minimum_proved_checks': 0, 'explicit_postcondition': False},
            {'name': 'Sentinel_Policy.Initialize', 'file': 'sentinel_policy.ads', 'line': 10,
             'minimum_proved_checks': 1, 'explicit_postcondition': True},
            {'name': 'Sentinel_Policy.Qualify', 'file': 'sentinel_policy.ads', 'line': 20,
             'minimum_proved_checks': 1, 'explicit_postcondition': True}]


def summary():
    rows = ['SPARK Analysis results Total Flow Provers Justified Unproved']
    for name in CATEGORIES:
        cells = '3 . 3 . .' if name == 'Functional Contracts' else (
            '2 2 . . .' if name == 'Termination' else '. . . . .')
        rows.append(name + ' ' + cells)
    rows.extend(['Total 5 2 3 . .', 'Analyzed 1 unit',
                 'in unit sentinel_policy, 3 subprograms and packages out of 3 analyzed'])
    for name, number, count in [('Sentinel_Policy', 1, 0),
                               ('Sentinel_Policy.Initialize', 10, 1),
                               ('Sentinel_Policy.Qualify', 20, 2)]:
        rows.append('  ' + name + ' at sentinel_policy.ads:' + str(number) +
                    ' flow analyzed (0 errors, 0 checks, 0 warnings and 0 pragma Assume statements) '
                    'and proved (' + str(count) + ' checks)')
    return ('\n'.join(rows) + '\n').encode('ascii')


def machine_report():
    return {'assumptions': [], 'entities': {str(i): {} for i in range(3)},
        'flow': [{'severity': 'info', 'how_proved': 'flow'} for _ in range(2)],
        'pragma_assume': [], 'progress': 'PROGRESS_PROOF',
        'proof': [{'severity': 'info', 'how_proved': 'prover'} for _ in range(3)],
        'skip_flow_proof': [], 'skip_proof': [], 'spark': {str(i): {} for i in range(3)},
        'stop_reason': 'STOP_REASON_NONE', 'timings': {'irrelevant': 0.015444}, 'warn_error': []}


def proof_mutations(raw):
    total = b'Total 5 2 3 . .\n'
    contract = b'Functional Contracts 3 . 3 . .\n'
    unit = b'in unit sentinel_policy, 3 subprograms and packages out of 3 analyzed\n'
    detail = raw.splitlines(keepends=True)[-1]
    zero = raw.replace(contract, b'Functional Contracts . . . . .\n')
    zero = zero.replace(b'Termination 2 2 . . .\n', b'Termination . . . . .\n')
    zero = zero.replace(total, b'Total . . . . .\n')
    zero = zero.replace(b'proved (1 checks)', b'proved (0 checks)')
    zero = zero.replace(b'proved (2 checks)', b'proved (0 checks)')
    return {
        'missing-total': raw.replace(total, b''),
        'duplicate-total': raw.replace(total, total * 2),
        'malformed-total': raw.replace(total, b'Total -5 2 3 . .\n'),
        'zero-total': zero,
        'justified-nonzero': raw.replace(total, b'Total 6 2 3 1 .\n'),
        'unproved-nonzero': raw.replace(total, b'Total 6 2 3 . 1\n'),
        'hidden-category-unproved': raw.replace(total, total + b'Functional Contracts 1 . . . 1\n'),
        'missing-functional-contracts': raw.replace(contract, b''),
        'zero-functional-contracts': raw.replace(contract, b'Functional Contracts . . . . .\n').replace(
            b'Run-time Checks . . . . .', b'Run-time Checks 3 . 3 . .'),
        'duplicate-category': raw.replace(contract, contract * 2),
        'unknown-category': raw.replace(contract, contract + b'Unknown Category . . . . .\n'),
        'bad-conservation': raw.replace(total, b'Total 6 2 3 . .\n'),
        'missing-unit': raw.replace(unit, b''),
        'wrong-unit': raw.replace(b'in unit sentinel_policy,', b'in unit other_policy,'),
        'duplicate-unit': raw.replace(unit, unit * 2),
        'partial-analysis': raw.replace(b'3 subprograms and packages out of 3',
                                         b'2 subprograms and packages out of 3'),
        'unexpected-extra-unit': raw.replace(b'Analyzed 1 unit', b'Analyzed 2 units'),
        'missing-entity': raw.replace(detail, b''),
        'duplicate-entity': raw + detail,
        'unexpected-entity': raw.replace(b'Sentinel_Policy.Qualify', b'Sentinel_Policy.Grant_Authority'),
        'wrong-coordinate': raw.replace(b'ads:20 ', b'ads:21 '),
        'zero-postcondition-entity': raw.replace(b'proved (2 checks)', b'proved (0 checks)'),
        'detail-prover-disagreement': raw.replace(b'proved (2 checks)', b'proved (3 checks)'),
        'nonzero-flow-errors': raw.replace(b'0 errors', b'1 errors', 1),
        'nonzero-flow-checks': raw.replace(b'0 checks, 0 warnings', b'1 checks, 0 warnings', 1),
        'nonzero-warnings': raw.replace(b'0 warnings', b'1 warnings', 1),
        'nonzero-assume': raw.replace(b'0 pragma Assume', b'1 pragma Assume', 1),
        'raw-warning': b'warning: synthetic diagnostic\n' + raw,
        'raw-unproved': b'postcondition not proved\n' + raw,
        'truncated-or-nonascii': raw[:-12] + b'\xff',
        'overbound': b' ' * 1048577}


def scratch_reserve(root):
    pending, used, entries = [root], 0, 0
    for _ in range(1025):
        if not pending:
            if used + 2097152 > 8388608:
                raise ValueError('test scratch reserve')
            return
        path = pending.pop()
        info = path.lstat()
        used += info.st_size
        if path.is_dir() and not path.is_symlink():
            with os.scandir(path) as rows:
                for _ in range(1025):
                    row = next(rows, None)
                    if row is None:
                        break
                    entries += 1
                    if entries > 1024:
                        raise ValueError('test scratch entry bound')
                    pending.append(Path(row.path))
                else:
                    raise ValueError('test scratch enumeration bound')
    raise ValueError('test scratch traversal bound')


class QualificationControls(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('SENTINEL_QUALIFICATION_TEST_SCRATCH',
                                   tempfile.gettempdir())) / 'sentinel-qualification-tests'
        base.mkdir(parents=True, exist_ok=True)
        scratch_reserve(base)
        folder = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / 'sentinel_native').mkdir()
        (self.root / 'tools').mkdir()
        for name in ('sentinel_policy.ads', 'sentinel_policy.adb',
                     'sentinel_policy.gpr', 'sentinel_policy_proof.gpr'):
            (self.root / 'sentinel_native' / name).write_bytes(b'-- synthetic uncompiled fixture\n')
        (self.root / 'tools/build_sentinel_policy.py').write_bytes(b'# synthetic fixture\n')
        (self.root / 'tools/transport_document_io.py').write_bytes(b'# synthetic dependency bytes\n')
        self.roster = {'schema': 'sentinel/proof-roster/1',
                       'status': 'SOURCE_DERIVED_FROZEN_BEFORE_PROVER', 'unit': 'sentinel_policy',
                       'sources': {name: value for name, value in subject.source_gate(self.root).items()
                                   if name.startswith('sentinel_native/')},
                       'entities': copy.deepcopy(ENTITIES)}
        self.roster_path = self.root / 'roster.json'
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/process forbidden')).start()

    def held_roster(self, value=None):
        raw = json.dumps(value or self.roster, sort_keys=True).encode()
        self.roster_path.write_bytes(raw)
        return subject.checked_roster(self.root, self.roster_path, hashlib.sha256(raw).hexdigest())

    def test_synthetic_positive_requires_nonvacuous_exact_roster(self):
        value = subject.parse_proof(summary(), self.held_roster())
        self.assertEqual((value['total'], value['flow'], value['prover']), (5, 2, 3))
        self.assertEqual(value['unproved'], 0)
        self.assertEqual(value['justified'], 0)
        self.assertEqual(set(value['entities']), {row['name'] for row in ENTITIES})

    def test_fixed_tool_mixed_display_annotations_keep_strict_counts(self):
        for raw in ('8 . 8 (Trivial 33%, Z3 67%) . .', '8 . 8 (Z3 100%) . .',
                    '8 . 8 (Trivial 100%) . .'):
            self.assertEqual(subject.cells(raw), [8, 0, 8, 0, 0])
        for raw in ('8 . 8 (Other 100%) . .', '8 . 8 (Trivial 101%) . .',
                    '8 . 8 (Trivial 50%, Trivial 50%) . .', '8 . 8 (Z3 -1%) . .',
                    '8 . 8 (Trivial 33%, Z3 67%) 1 .', '8 . 8 (Trivial 33%, Z3 67%) . 1'):
            with self.subTest(cell=raw), self.assertRaises(ValueError):
                subject.cells(raw)

    def test_machine_positive_and_timing_tokens_have_no_numeric_authority(self):
        report = subject.parse_proof(summary(), self.held_roster())
        raw = json.dumps(machine_report()).encode()
        checked = subject.machine_diagnostics(raw, report)
        self.assertEqual((checked['proof_records'], checked['flow_records'], checked['entities']), (3, 2, 3))
        self.assertEqual(subject.machine_json(raw)['timings']['irrelevant'], 'UNUSED_TIMING_TOKEN')
        changed = dict(report, prover=3.0)
        with self.assertRaises(ValueError):
            subject.machine_diagnostics(raw, changed)

    def test_machine_diagnostics_skips_counts_status_and_schema_fail_closed(self):
        report = subject.parse_proof(summary(), self.held_roster())
        variants = [('warn_error', [{'severity': 'warning', 'how_proved': 'trivial'}]),
            ('pragma_assume', [{}]), ('skip_proof', [{}]), ('skip_flow_proof', [{}]),
            ('proof', []), ('flow', []), ('entities', {}), ('spark', {}),
            ('progress', 'OTHER'), ('stop_reason', 'STOP_REASON_ERROR'), ('warn_error', None)]
        for key, value in variants:
            data = machine_report()
            data[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                subject.machine_diagnostics(json.dumps(data).encode(), report)
        for key in ('unknown_field', 'missing_field'):
            data = machine_report()
            if key == 'missing_field':
                del data['warn_error']
            else:
                data[key] = []
            with self.assertRaises(ValueError):
                subject.machine_diagnostics(json.dumps(data).encode(), report)

    def test_machine_records_suppression_and_unaccepted_methods_refuse(self):
        report = subject.parse_proof(summary(), self.held_roster())
        for field, value in (('severity', 'warning'), ('severity', 'error'),
                             ('suppressed', 'justified'), ('how_proved', 'unknown')):
            data = machine_report()
            data['proof'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.machine_diagnostics(json.dumps(data).encode(), report)

    def test_machine_malformed_duplicate_nonfinite_deep_and_overbound_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{',
                    b'[' * 33 + b']' * 33, b' ' * 1048577, b'\xff'):
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                subject.machine_json(raw)

    def test_worker_rejects_raw_machine_diagnostic_before_binary_acceptance(self):
        data = machine_report()
        data['warn_error'] = [{'severity': 'warning', 'how_proved': 'trivial'}]
        report = subject.parse_proof(summary(), self.held_roster())
        def read(path, *_args):
            if path.name == 'checks.stdout':
                return b'SENTINEL_POLICY_CHECKS_PASS\n'
            if path.name == 'sentinel_policy.spark':
                return json.dumps(data).encode()
            return b''
        config = {'source_root': str(self.root), 'sentinel_source_pins': {}, 'proof_roster': {},
                  'tools': {'gprbuild': '/fixed/build', 'gnatprove': '/fixed/prove'}, 'global_deadline': 450}
        with patch.object(profile, 'source_gate', return_value={}), \
             patch.object(profile, 'environment', return_value={}), \
             patch.object(profile, 'admit_phase', return_value=360), \
             patch.object(profile, 'phase', return_value={'returncode': 0}), \
             patch.object(profile, 'json_new'), patch.object(profile, 'read_bytes', side_effect=read), \
             patch.object(profile, 'parse_proof', return_value=report), \
             patch.object(profile, 'digest', side_effect=AssertionError('premature binary acceptance')):
            with self.assertRaisesRegex(ValueError, 'machine diagnostic or skip refused'):
                profile.worker(self.root, config)

    def test_frozen_35_oracle_summary_refusals(self):
        variants = proof_mutations(summary())
        self.assertEqual(len(variants), 31)
        for name, raw in variants.items():
            with self.subTest(case=name), self.assertRaises((ValueError, UnicodeError)):
                subject.parse_proof(raw, self.roster)

    def test_source_drift_refuses_held_roster(self):
        self.held_roster()
        (self.root / 'sentinel_native/sentinel_policy.adb').write_bytes(b'-- changed\n')
        with self.assertRaises(ValueError):
            self.held_roster()

    def test_assumption_justification_suppression_source_refusals(self):
        target = self.root / 'sentinel_native/sentinel_policy.adb'
        for raw in (b'pragma Assume (True);', b'pragma Annotate (GNATprove, False_Positive);',
                    b'pragma Suppress (All_Checks);', b'pragma Assertion_Policy (Ignore);'):
            target.write_bytes(raw)
            with self.subTest(source=raw), self.assertRaises(ValueError):
                subject.source_gate(self.root)

    def test_roster_unfrozen_wrong_unit_or_missing_sources_refuse(self):
        for key, value in [('status', 'SYNTHETIC'), ('unit', 'other'), ('sources', {})]:
            changed = copy.deepcopy(self.roster)
            changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.held_roster(changed)

    def test_duplicate_roster_and_source_post_minimum_refuse_before_dispatch(self):
        changed = copy.deepcopy(self.roster)
        changed['entities'].append(copy.deepcopy(changed['entities'][1]))
        with self.assertRaises(ValueError):
            self.held_roster(changed)
        changed = copy.deepcopy(self.roster)
        changed['entities'][1]['minimum_proved_checks'] = 0
        with self.assertRaises(ValueError):
            self.held_roster(changed)

    def test_invalid_roster_sha_types_coordinates_and_contract_absence_refuse(self):
        self.held_roster()
        with self.assertRaises(ValueError):
            subject.checked_roster(self.root, self.roster_path, '0' * 64)
        for field, value in [('line', True), ('line', 0), ('file', 'other.ads'),
                             ('minimum_proved_checks', False), ('explicit_postcondition', 1)]:
            changed = copy.deepcopy(self.roster)
            changed['entities'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.held_roster(changed)
        changed = copy.deepcopy(self.roster)
        for row in changed['entities']:
            row['explicit_postcondition'] = False
        with self.assertRaises(ValueError):
            self.held_roster(changed)

    def test_source_gate_symlink_special_entry_and_gpr_checks(self):
        target = self.root / 'sentinel_native/unexpected'
        target.mkdir()
        with self.assertRaises(ValueError):
            subject.source_gate(self.root)

        target.rmdir()
        target = self.root / 'sentinel_native/linked.ads'
        target.symlink_to(self.root / 'sentinel_native/sentinel_policy.ads')
        with self.assertRaises(ValueError):
            subject.source_gate(self.root)
        target.unlink()
        gpr = self.root / 'sentinel_native/sentinel_policy.gpr'
        gpr.write_bytes(b'for Switches use ("-gnatp");')
        with self.assertRaises(ValueError):
            subject.source_gate(self.root)

    def test_source_gate_directory_count_refuses_seventeenth_entry(self):
        for index in range(13):
            (self.root / 'sentinel_native' / ('extra' + str(index) + '.md')).write_bytes(b'fixture')
        with self.assertRaisesRegex(ValueError, 'count|cardinality'):
            subject.source_gate(self.root)

    def test_source_gate_binds_the_new_io_dependency(self):
        before = subject.source_gate(self.root)
        self.assertIn('tools/transport_document_io.py', before)
        (self.root / 'tools/transport_document_io.py').write_bytes(b'# changed dependency\n')
        self.assertNotEqual(subject.source_gate(self.root), before)

    def test_fixed_commands_preserve_flags_and_phase_budgets(self):
        rows = profile.commands(Path('/declared'), {'gprbuild': '/tools/build', 'gnatprove': '/tools/prove'})
        self.assertEqual([(name, seconds) for name, seconds, _ in rows],
                         [('build', 90), ('checks', 30), ('proof', 180)])
        self.assertIn('-R', rows[0][2])
        self.assertIn('-gnata', rows[0][2])
        for flag in ('-U', '--level=2', '--report=all', '--warnings=error'):
            self.assertIn(flag, rows[2][2])

    def test_execute_failure_cleanup_readonly_capture_stays_failed(self):
        config = {'source_root': str(self.root), 'sentinel_source_pins': {},
                  'identity_before': {'held': 'pin'}, 'global_deadline': 450}
        with patch.object(profile, 'worker', side_effect=ValueError('refused')), \
             patch.object(profile, 'drain_children', return_value={'remaining': 0}), \
             patch.object(profile, 'verify_roster', return_value={'held': 'pin'}), \
             patch.object(profile, 'source_gate', return_value={}), \
             patch.object(profile, 'mount_command'), \
             patch.object(profile.os, 'statvfs', return_value=SimpleNamespace(
                 f_flag=os.ST_RDONLY, f_blocks=16384, f_frsize=4096, f_files=4096)), \
             patch.object(profile, 'snapshot', return_value={'complete': True}), \
             patch.object(profile, 'usage', return_value=0):
            result = profile.execute(self.root, self.root, config)
        self.assertEqual(result['status'], 'FAILED')
        self.assertTrue(result['readonly_qualified'])
        self.assertTrue(any('refused' in value for value in result['failures']))

    def test_invalid_roster_preflight_cannot_discover_or_launch_tools(self):
        args = SimpleNamespace(source_root=self.root, out=Path('/dev/shm/declared/output'),
                               roster=self.roster_path, roster_sha256='0' * 64,
                               toolchain_root=Path('/declared/tools'))
        with patch.object(builder, 'directory', side_effect=lambda value, **_kw: value), \
             patch.object(builder.os, 'statvfs', return_value=SimpleNamespace(
                 f_bavail=1048576, f_frsize=4096)), \
             patch.object(builder, 'checked_roster', side_effect=ValueError('bad held roster')), \
             patch.object(builder, 'discover_toolchain', side_effect=AssertionError('tool discovery')), \
             patch.object(builder.os, 'pidfd_open', side_effect=AssertionError('PID action')):
            with self.assertRaisesRegex(ValueError, 'bad held roster'):
                builder.preflight(args)

    def execute_with_capture(self, flag, blocks, inodes, complete):
        config = {'source_root': str(self.root), 'sentinel_source_pins': {},
                  'identity_before': {}, 'global_deadline': 450}
        with patch.object(profile, 'worker', return_value={'status': builder.SUCCESS}), \
             patch.object(profile, 'drain_children', return_value={'remaining': 0}), \
             patch.object(profile, 'verify_roster', return_value={}), \
             patch.object(profile, 'source_gate', return_value={}), \
             patch.object(profile, 'mount_command'), \
             patch.object(profile.os, 'statvfs', return_value=SimpleNamespace(
                 f_flag=flag, f_blocks=blocks, f_frsize=4096, f_files=inodes)), \
             patch.object(profile, 'snapshot', return_value={'complete': complete}), \
             patch.object(profile, 'usage', return_value=0):
            return profile.execute(self.root, self.root, config)

    def test_readonly_quota_and_complete_capture_are_independent_gates(self):
        self.assertEqual(self.execute_with_capture(os.ST_RDONLY, 16384, 4096, True)['status'],
                         builder.SUCCESS)
        for flag, blocks, inodes, complete in ((0, 16384, 4096, True),
                (os.ST_RDONLY, 16383, 4096, True), (os.ST_RDONLY, 16384, 4095, True),
                (os.ST_RDONLY, 16384, 4096, False)):
            with self.subTest(boundary=(flag, blocks, inodes, complete)):
                value = self.execute_with_capture(flag, blocks, inodes, complete)
                self.assertEqual(value['status'], 'FAILED')
                self.assertTrue(value['failures'])

    def test_runtime_marker_refuses_before_proof_parsing(self):
        def read(path, *_args):
            return b'WRONG_MARKER\n' if path.name == 'checks.stdout' else b''
        config = {'source_root': str(self.root), 'sentinel_source_pins': {},
                  'tools': {'gprbuild': '/fixed/build', 'gnatprove': '/fixed/prove'},
                  'global_deadline': 450}
        with patch.object(profile, 'source_gate', return_value={}), \
             patch.object(profile, 'environment', return_value={}), \
             patch.object(profile, 'admit_phase', return_value=360), \
             patch.object(profile, 'phase', return_value={'returncode': 0}), \
             patch.object(profile, 'json_new'), patch.object(profile, 'read_bytes', side_effect=read), \
             patch.object(profile, 'parse_proof', side_effect=AssertionError('unadmitted proof')):
            with self.assertRaisesRegex(ValueError, 'runtime fixture success'):
                profile.worker(self.root, config)

    def test_namespace_failure_still_records_terminal_cleanup(self):
        (self.root / 'private').mkdir()
        (self.root / 'launch.json').write_text(json.dumps(
            {'source_root': str(self.root), 'sentinel_source_pins': {}}))
        with patch.object(profile, 'limits'), \
             patch.object(profile.sys, 'argv', ['-c', '/tools', '/sentinel', str(self.root)]), \
             patch.object(profile.container, 'setup', return_value={}), \
             patch.object(profile, 'source_gate', return_value={}), \
             patch.object(profile, 'execute', side_effect=ValueError('capture refused')), \
             patch.object(profile, 'drain_children', return_value={'remaining': 0}):
            self.assertEqual(profile.namespace_main(), 2)
        value = json.loads((self.root / 'namespace-result.json').read_bytes())
        self.assertEqual(value['status'], 'FAILED')
        self.assertIn('capture refused', value['failure'])
        self.assertEqual(value['terminal_cleanup']['remaining'], 0)

    def terminal_launch(self, child, index):
        out = self.root / ('launch-' + str(index))
        actual_json_new = builder.json_new
        def emit(path, value):
            actual_json_new(path, value)
            if path.name == 'launch.json':
                actual_json_new(out / 'namespace-result.json', child)
        with patch.object(builder, 'limits'), \
             patch.object(builder.subprocess, 'Popen', return_value=SimpleNamespace(pid=123, returncode=0)), \
             patch.object(builder.os, 'pidfd_open', return_value=999), \
             patch.object(builder.os, 'close'), patch.object(builder, 'collect', return_value=0), \
             patch.object(builder, 'json_new', side_effect=emit), \
             patch.object(builder, 'source_gate', return_value={}), \
             patch.object(builder, 'source_pins', return_value={}):
            with self.assertRaisesRegex(ValueError, 'SENTINEL build refused'):
                builder.launch(self.root, out, {})
        return json.loads((out / 'receipt.json').read_bytes())

    def test_parent_retains_bad_terminal_failure_receipt(self):
        variants = [{'status': 'FAILED', 'readonly_qualified': True, 'capture': {'complete': True}},
                    {'status': builder.SUCCESS, 'readonly_qualified': False, 'capture': {'complete': True}},
                    {'status': builder.SUCCESS, 'readonly_qualified': True, 'capture': {'complete': False}},
                    {'status': builder.SUCCESS}]
        for index, child in enumerate(variants):
            value = self.terminal_launch(child, index)
            self.assertEqual(value['status'], 'FAILED')
            self.assertTrue(value['failure'])


if __name__ == '__main__':
    unittest.main()
