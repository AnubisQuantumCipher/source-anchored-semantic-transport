"""Actual pinned-courier and native-evaluator integration; retained run directories.

The caller supplies TRANSPORT_CORE_TEST_ROOT (a new child of a private directory),
TRANSPORT_CORE_NATIVE, TRANSPORT_CORE_NATIVE_SHA256, TRANSPORT_CORE_DECODER, and
TRANSPORT_CORE_DECODER_SHA256. No downloaded executable or model service is used.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'install'))

import transport_core as core
import transport_core_bridge as bridge
from transport_core_language import parse_fragment
from transport_schema import canonical
from transport_wire import TransportError

SOURCE = b'REQ_AUDIT: When E, A shall Q, unless X.\n'
CLI = ROOT / 'tools/transport_core_cli.py'
LIMIT = 131072
LEGACY_PINS = {
    'tools/transport_package.py': 'c7746908cb1885914f83aa3d4ed97ca57b5f44a86f6442ca1ad837d76ea9810d',
    'tools/transport_requirement_language.py': 'e9bd5b8fa360da23f9c2fd55aea9597260da453083b8ab64462a031e444d965b',
    'tools/transport_schema.py': '1c324b661314bd3a92f23b4502207f38a483baa6565d479838de450f110eeb1a',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(truths=('KNOWN_TRUE', 'KNOWN_FALSE', 'KNOWN_FALSE')):
    parsed = parse_fragment(SOURCE)
    plan = {'schema': core.PLAN, 'symbols': parsed['symbols'], 'tree': parsed['tree'],
            'translation': 'requirement'}
    rows = [{'predicate': name, 'terms': terms, 'truth': truth}
            for name, terms, truth in zip(('EVENT', 'ACTION', 'EXCEPTION'),
                                         ([], ['ACTOR'], []), truths, strict=True)]
    return plan, {'schema': core.MODEL, 'symbols': plan['symbols'], 'tuples': rows}


class CoreBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = Path(os.environ['TRANSPORT_CORE_TEST_ROOT'])
        cls.native = Path(os.environ['TRANSPORT_CORE_NATIVE'])
        cls.native_sha = os.environ['TRANSPORT_CORE_NATIVE_SHA256']
        cls.decoder = Path(os.environ['TRANSPORT_CORE_DECODER'])
        cls.decoder_sha = os.environ['TRANSPORT_CORE_DECODER_SHA256']
        bridge.workspace(cls.artifacts)
        bridge.pinned(cls.native, cls.native_sha)
        bridge.pinned(cls.decoder, cls.decoder_sha)
        cls.dependencies = bridge.runtime(cls.decoder_sha, cls.native_sha)
        cls.initial_pins = {name: digest(ROOT / name) for name in LEGACY_PINS}

    def setUp(self):
        self.root = bridge.workspace(self.artifacts / self._testMethodName)
        self.assertEqual(digest(self.native), self.native_sha)
        self.assertEqual(digest(self.decoder), self.decoder_sha)

    def tearDown(self):
        self.assertEqual(digest(self.native), self.native_sha)
        self.assertEqual(digest(self.decoder), self.decoder_sha)
        self.assertEqual(bridge.runtime(self.decoder_sha, self.native_sha), self.dependencies)
        self.assertEqual({name: digest(ROOT / name) for name in LEGACY_PINS}, LEGACY_PINS)
        size = sum(path.stat().st_size for path in self.artifacts.rglob('*') if path.is_file())
        self.assertLessEqual(size, 6 * 1024 * 1024)

    def common(self, root):
        return self.decoder, self.decoder_sha, self.native, self.native_sha, root

    def encoded(self, name='sender', truths=('KNOWN_TRUE', 'KNOWN_FALSE', 'KNOWN_FALSE'),
                model_present=True):
        plan, model = fixture(truths)
        root = bridge.workspace(self.root / name)
        model_raw = canonical(model) if model_present else None
        result = bridge.encode(SOURCE, canonical(plan), model_raw, *self.common(root))
        return root, result, plan, model_raw

    def command(self, label, arguments):
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(CLI)] + arguments
        env = dict(bridge.ENV)
        run = subprocess.run(argv, cwd=self.root, env=env, capture_output=True,
                             check=False, timeout=120)
        self.assertLessEqual(len(run.stdout), LIMIT)
        self.assertLessEqual(len(run.stderr), LIMIT)
        (self.root / (label + '.stdout')).write_bytes(run.stdout)
        (self.root / (label + '.stderr')).write_bytes(run.stderr)
        (self.root / (label + '.json')).write_bytes(canonical({
            'argv': argv, 'exit_code': run.returncode,
            'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()}))
        return run

    def test_01_encode_and_fresh_recipient_recover_exact_source_model_and_verdict(self):
        root, result, plan, model = self.encoded()
        self.assertEqual(result['exact_source_recovery'], 'BYTE_COMPARISON_PASS')
        self.assertEqual(result['replay'], 'ORIGINAL_RECOVERED_VALUES_MATCH')
        replay = json.loads((root / 'replay.json').read_bytes())
        self.assertEqual(replay['original'], replay['recovered'])
        self.assertEqual(replay['package_identity'], result['package_identity'])
        self.assertEqual((root / 'original.stc3').read_bytes(),
                         (root / 'roundtrip.stc3').read_bytes())
        self.assertEqual(result['result'], {
            'node': 6, 'sort': 'NORM', 'truth': 'UNRESOLVED', 'outcome': 'VIOLATED'})
        self.assertEqual(result['nodes'][1]['truth'], 'KNOWN_FALSE')
        self.assertEqual(result['nodes'][5]['truth'], 'KNOWN_FALSE')
        self.assertEqual(result['translation'], 'CHECKED_CONTROLLED_TRANSLATION')
        recipient = bridge.workspace(self.root / 'recipient')
        for name in ('share.txt', 'meaning.zip'):
            (recipient / name).write_bytes((root / 'product' / name).read_bytes())
        run = self.command('receive-cli', ['evaluate', '--share', str(recipient / 'share.txt'),
            '--archive', str(recipient / 'meaning.zip'), '--decoder', str(self.decoder),
            '--decoder-sha256', self.decoder_sha, '--native', str(self.native),
            '--native-sha256', self.native_sha, '--work', str(recipient / 'work')])
        self.assertEqual(run.returncode, 0, run.stderr)
        received = json.loads(run.stdout)
        self.assertEqual(received['nodes'], result['nodes'])
        self.assertEqual(received['package_identity'], result['package_identity'])
        self.assertEqual((recipient / 'work/receive-SOURCE.bin').read_bytes(), SOURCE)
        self.assertEqual((recipient / 'work/receive-MODEL.bin').read_bytes(), model)
        self.assertEqual(received['execution_authority'], 'NONE')
        self.assertEqual(received['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(received['world_truth'], 'NOT_CERTIFIED')
        self.assertEqual(received['reading_status'], 'PROPOSED_STRUCTURED_READING')
        self.assertEqual(received['interpretation_entailment'], 'UNPROVEN')
        self.assertEqual(received['entailment'], 'NOT_CHECKED')

    def test_02_model_changes_preserve_unknown_and_conditional_satisfaction(self):
        cases = [
            ('guard-unknown', ('UNRESOLVED', 'KNOWN_FALSE', 'KNOWN_FALSE'), 'UNKNOWN'),
            ('exception-active', ('KNOWN_TRUE', 'KNOWN_FALSE', 'KNOWN_TRUE'), 'SATISFIED'),
            ('event-false', ('KNOWN_FALSE', 'KNOWN_FALSE', 'KNOWN_FALSE'), 'SATISFIED')]
        for name, truths, outcome in cases:
            with self.subTest(name=name):
                _, result, _, _ = self.encoded(name, truths)
                self.assertEqual(result['result']['outcome'], outcome)
                self.assertEqual(result['result']['truth'], 'UNRESOLVED')
                self.assertEqual(result['nodes'][1]['truth'], 'KNOWN_FALSE')

    def test_03_missing_model_is_not_evaluated(self):
        root, result, _, _ = self.encoded(model_present=False)
        self.assertEqual(result['status'], 'NOT_EVALUATED')
        self.assertEqual(result['semantic_scope'], 'NONE_NO_MODEL')
        self.assertEqual(result['reading_status'], 'PROPOSED_STRUCTURED_READING')
        self.assertEqual(result['nodes'], [])
        self.assertIsNone(result['result'])
        self.assertIsNone(result['model_sha256'])
        self.assertFalse((root / 'roundtrip.stc3').exists())
        self.assertFalse((root / 'original.stc3').exists())
        replay = json.loads((root / 'replay.json').read_bytes())
        self.assertEqual(result['replay'], 'NOT_EVALUATED')
        self.assertEqual(replay['status'], 'NOT_EVALUATED')
        self.assertEqual(replay['original'], replay['recovered'])

    def test_04_cli_draft_matches_literal_requirement_scope(self):
        source = self.root / 'source.txt'
        source.write_bytes(SOURCE)
        target = self.root / 'plan.json'
        run = self.command('draft', ['draft', '--source', str(source), '--output', str(target)])
        self.assertEqual(run.returncode, 0, run.stderr)
        written = json.loads(target.read_bytes())
        self.assertEqual(written['tree']['nodes'][5], {'op': 'if', 'args': [4, 1]})
        self.assertEqual(written['tree']['nodes'][6], {'op': 'must', 'args': [5]})
        self.assertEqual(json.loads(run.stdout)['evaluation'], 'NOT_EVALUATED')
        refusal = self.command('draft-create-only',
                               ['draft', '--source', str(source), '--output', str(target)])
        self.assertEqual(refusal.returncode, 1)

    def test_05_envelope_model_source_operator_and_version_tampering_refused(self):
        plan, model = fixture()
        model_raw = canonical(model)
        raw = bridge.envelope(SOURCE, canonical(plan), model_raw, self.dependencies)
        self.assertEqual(bridge.check_envelope(raw, SOURCE, model_raw, self.dependencies)['plan'], plan)
        changes = [('schema', 'transport/core-envelope/4'), ('source_sha256', '0' * 64),
                   ('operators', {'schema': 'transport/core-operators/3', 'entries': {}}),
                   ('model', {'source': 'MODEL', 'sha256': '0' * 64}),
                   ('runtime', dict(self.dependencies, native_sha256='0' * 64)),
                   ('translation', {'status': 'CHECKED_CONTROLLED_TRANSLATION'})]
        for name, value in changes:
            altered = json.loads(raw)
            altered[name] = value
            with self.subTest(name=name), self.assertRaises(TransportError):
                bridge.check_envelope(canonical(altered), SOURCE, model_raw, self.dependencies)
        with self.assertRaises(TransportError):
            bridge.check_envelope(raw, SOURCE.replace(b'A shall', b'B shall'), model_raw, self.dependencies)
        changed = copy.deepcopy(model)
        changed['tuples'][1]['truth'] = 'KNOWN_TRUE'
        with self.assertRaises(TransportError):
            bridge.check_envelope(raw, SOURCE, canonical(changed), self.dependencies)
        with self.assertRaises(TransportError):
            bridge.check_envelope(raw, SOURCE, None, self.dependencies)

    def test_06_present_malformed_model_is_never_treated_as_absent(self):
        plan, model = fixture()
        bad = [b'{}', b'null', b'{', b'{"schema":"transport/finite-model/1","schema":"x"}']
        changed = copy.deepcopy(model)
        changed['tuples'][0]['truth'] = False
        bad.append(canonical(changed))
        changed = copy.deepcopy(model)
        changed['tuples'][1]['terms'] = []
        bad.append(canonical(changed))
        for index, raw in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(TransportError):
                bridge.envelope(SOURCE, canonical(plan), raw, self.dependencies)
        with self.assertRaises(TransportError):
            bridge.evaluate({}, None, SOURCE, self.native, self.native_sha, self.root, 'malformed')

    def test_07_authored_tree_and_role_binding_mismatches_refused(self):
        plan, model = fixture()
        for mutation in ('condition', 'actor-binding', 'bool-index'):
            value = copy.deepcopy(plan)
            if mutation == 'condition':
                value['tree']['nodes'][5]['op'] = 'and'
            elif mutation == 'actor-binding':
                value['symbols'][1]['binding'] = {'kind': 'name', 'name': 'A'}
            else:
                value['tree']['nodes'][5]['args'][1] = True
            with self.subTest(mutation=mutation), self.assertRaises(TransportError):
                bridge.envelope(SOURCE, canonical(value), canonical(model), self.dependencies)

    def test_08_clock_source_requires_explicit_documentary_translation_status(self):
        source = b'R: When E, A shall Q within 100 ms, unless X.'
        plan, model = fixture()
        for symbol in plan['symbols']:
            symbol['binding'] = {'kind': 'name', 'name': symbol['id']}
        model['symbols'] = plan['symbols']
        with self.assertRaisesRegex(TransportError, 'NOT_IN_FRAGMENT'):
            bridge.envelope(source, canonical(plan), canonical(model), self.dependencies)
        plan['translation'] = 'declared'
        root = bridge.workspace(self.root / 'sender')
        result = bridge.encode(source, canonical(plan), canonical(model), *self.common(root))
        self.assertEqual(result['translation'], 'NOT_IN_FRAGMENT')
        self.assertEqual(result['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(result['interpretation_entailment'], 'UNPROVEN')
        self.assertEqual(result['entailment'], 'NOT_CHECKED')
        self.assertEqual((root / 'roundtrip-SOURCE.bin').read_bytes(), source)

    def test_09_swapped_archive_and_truncated_archive_refuse_before_evaluation(self):
        first, _, _, _ = self.encoded('first')
        second, _, _, _ = self.encoded('second', ('KNOWN_TRUE', 'KNOWN_TRUE', 'KNOWN_FALSE'))
        share = first / 'product/share.txt'
        archive = second / 'product/meaning.zip'
        receiver = bridge.workspace(self.root / 'swap')
        with self.assertRaises(TransportError):
            bridge.decode(share, archive, *self.common(receiver))
        self.assertFalse((receiver / 'receive.stc3').exists())
        truncated = self.root / 'truncated.zip'
        truncated.write_bytes(archive.read_bytes()[:-1])
        receiver = bridge.workspace(self.root / 'truncated')
        with self.assertRaises(TransportError):
            bridge.decode(second / 'product/share.txt', truncated, *self.common(receiver))
        self.assertFalse((receiver / 'receive.stc3').exists())

    def test_10_missing_and_conflicting_tuples_stay_unresolved(self):
        plan, model = fixture()
        missing = copy.deepcopy(model)
        missing['tuples'] = [row for row in missing['tuples'] if row['predicate'] != 'ACTION']
        conflict = copy.deepcopy(model)
        conflict['tuples'].append({'predicate': 'EVENT', 'terms': [], 'truth': 'KNOWN_FALSE'})
        for name, finite in (('missing', missing), ('conflicting', conflict)):
            root = bridge.workspace(self.root / name)
            result = bridge.evaluate(plan, finite, SOURCE, self.native, self.native_sha, root, name)
            self.assertEqual(result['result']['outcome'], 'UNKNOWN')
            self.assertEqual(result['result']['truth'], 'UNRESOLVED')
        self.assertEqual((self.root / 'missing/missing.stc3').read_bytes()[:4], b'STC3')

    def test_11_dependency_pin_and_private_parent_errors_refuse(self):
        with self.assertRaisesRegex(TransportError, 'CORE_DEPENDENCY_IDENTITY'):
            bridge.pinned(self.native, '0' * 64)
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        with self.assertRaisesRegex(TransportError, 'CORE_PRIVATE_PARENT'):
            bridge.workspace(public / 'child')
        self.assertFalse((public / 'child').exists())
        self.assertEqual(public.stat().st_mode & 0o777, 0o755)

    def test_12_child_limits_never_increase_and_workspace_descriptor_is_closed(self):
        script = '''import json, os, resource, stat
directories = []
for descriptor in range(3, 128):
    try:
        mode = os.fstat(descriptor).st_mode
    except OSError:
        continue
    if stat.S_ISDIR(mode):
        directories.append(descriptor)
print(json.dumps({'directories': directories,
 'limits': [resource.getrlimit(resource.RLIMIT_AS),
            resource.getrlimit(resource.RLIMIT_FSIZE)]}))
'''
        run = bridge.run_bounded([sys.executable, '-I', '-S', '-B', '-c', script],
                                 self.root, bridge.ENV, timeout=10, cap=LIMIT)
        for stream in ('stdout', 'stderr'):
            (self.root / ('limits.' + stream)).write_bytes(run[stream])
        self.assertEqual(run['status'], 'SUCCESS')
        self.assertEqual(run['exit_code'], 0)
        value = json.loads(run['stdout'])
        self.assertEqual(value['directories'], [])
        for pair, category, ceiling in zip(value['limits'],
                (resource.RLIMIT_AS, resource.RLIMIT_FSIZE), (536870912, 4194304), strict=True):
            expected = min([ceiling] + [v for v in resource.getrlimit(category)
                                       if v != resource.RLIM_INFINITY])
            self.assertEqual(pair, [expected, expected])


if __name__ == '__main__':
    for category, ceiling in ((resource.RLIMIT_AS, 536870912),
                              (resource.RLIMIT_FSIZE, 1048576),
                              (resource.RLIMIT_CPU, 120)):
        current = [v for v in resource.getrlimit(category) if v != resource.RLIM_INFINITY]
        bounded = min([ceiling] + current)
        resource.setrlimit(category, (bounded, bounded))
    unittest.main()
