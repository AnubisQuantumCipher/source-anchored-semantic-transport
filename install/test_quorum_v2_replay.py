#!/usr/bin/env python3
"""Live source replay and bounded negative controls; uses an existing qualified bundle."""

import argparse
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'install'))
import transport_quorum_v2_replay as product
from transport_quorum_v2_input import Refusal, canonical, sha
from transport_quorum_v2_policy import NAMES, evaluate
from transport_quorum_v2_process import run_bounded

CONFIG = {}
OUTCOMES = []


def source_inventory():
    names = ('input', 'schema', 'policy', 'process', 'replay')
    files = ['tools/transport_quorum_v2_' + name + '.py' for name in names]
    files += ['tools/transport_quorum_v2.py', 'install/test_quorum_v2_replay.py',
              'install/transport_install_support.py', 'docs/quorum-v2-replay-admitted.json',
              'docs/quorum-v2-replay-contract.json']
    return {name: sha((ROOT / name).read_bytes()) for name in files}


def fixture():
    root = ROOT / 'examples/quorum-v2/source-replay-example'
    raws = tuple((root / (name + '.json')).read_bytes() for name in NAMES)
    return raws, json.loads((root / 'held-roots.json').read_bytes())


def record(name, result):
    OUTCOMES.append(dict(id=name, result=result))
    return result


def changed_context(raws, key):
    docs = [json.loads(raw) for raw in raws]
    docs[0]['context'][key] = '0' * 64
    docs[3]['context'][key] = '0' * 64
    for row in docs[3]['readings']:
        row['context'][key] = '0' * 64
    for row in docs[2]['runs']:
        row['context'][key] = '0' * 64
        reading = next(item for item in docs[3]['readings'] if item['run_id'] == row['run_id'])
        row['reading_sha256'] = sha(canonical(reading))
    changed = tuple(canonical(doc) for doc in docs)
    return changed, {name: sha(raw) for name, raw in zip(NAMES[:3], changed[:3], strict=True)}


class ReplayIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raws, cls.held = fixture()
        cls.options = json.loads(CONFIG['options'].read_bytes())
        cls.setup = product._setup(cls.options, cls.raws)
        cls.threshold = evaluate(cls.raws, cls.held)
        argv = [str(Path(sys.executable).resolve()), '-I', '-S', cls.options['bootstrap'],
                cls.options['invocation'], '--expect-invocation-sha256', cls.options['invocation_sha256'],
                '--expect-bootstrap-sha256', product.BOOTSTRAP_SHA]
        cls.process = run_bounded(argv, ROOT, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        record('capture', {k: v for k, v in cls.process.items() if k not in ('stdout', 'stderr')})

    def test_live_source_dimensions(self):
        result = record('live', product.replay(self.raws, self.held, self.options))
        self.assertEqual(result['status'], 'EVALUATED_DIMENSIONS')
        self.assertEqual(result['source_replay']['claims'][0]['change_impact'], 'NEEDS_REVALIDATION')
        self.assertEqual(result['threshold']['provenance_class'], 'SYNTHETIC_ONLY')
        self.assertEqual(result['threshold']['verdict'], 'RECORDED_SUPPORT_THRESHOLD_MET')
        self.assertEqual(canonical(result['source_replay']) + b'\n', self.process['stdout'])
        self.assertEqual(canonical(result['host_qualification']) + b'\n', self.process['stderr'])

    def test_no_unadmitted_launch(self):
        for field in ('bootstrap_sha256', 'invocation_sha256', 'request_sha256'):
            with self.subTest(field=field), patch.object(product, 'run_bounded') as launch:
                options = dict(self.options, **{field: '0' * 64})
                result = record(field, product.replay(self.raws, self.held, options))
                self.assertEqual(result['status'], 'REFUSED')
                launch.assert_not_called()

    def test_source_context_tampering(self):
        for field in ('claim_sha256', 'task_sha256', 'source_set_sha256'):
            with self.subTest(field=field):
                raws, held = changed_context(self.raws, field)
                result = record(field, product.replay(raws, held, self.options))
                self.assertEqual(result['status'], 'REFUSED')
                self.assertEqual(result['code'], 'REPLAY_POLICY_CONTEXT')

    def test_output_validator_mutations(self):
        cases = [('exit_code', 1), ('status', 'REFUSED_TIMEOUT'), ('stderr', b''),
                 ('stdout', self.process['stdout'][:-1]),
                 ('stdout', self.process['stdout'] + b'\n'),
                 ('stdout', self.process['stdout'] + b'{}\n'),
                 ('stderr', self.process['stderr'] + b'{}\n'),
                 ('stdout', b'x' * 131073)]
        for index, (field, value) in enumerate(cases):
            with self.subTest(index=index):
                candidate = dict(self.process, **{field: value})
                with self.assertRaises(Refusal):
                    product.compose(candidate, self.setup, self.options, self.threshold)
                record('capture-mutation-' + str(index), {'status': 'REFUSED'})

    def test_typed_result_mutations(self):
        original = json.loads(self.process['stdout'])
        for field, value in (('accepted_result', 1), ('schema', 'quorum/replay-result/99'),
                             ('replay', 'SELF_ASSERTED'), ('request', {}),
                             ('claims', original['claims'] * 2)):
            with self.subTest(field=field):
                changed = dict(original, **{field: value})
                candidate = dict(self.process, stdout=canonical(changed) + b'\n')
                with self.assertRaises(Refusal):
                    product.compose(candidate, self.setup, self.options, self.threshold)
                record('result-' + field, {'status': 'REFUSED'})

    def test_cli_same_dimensions(self):
        root = ROOT / 'examples/quorum-v2/source-replay-example'
        argv = [str(Path(sys.executable).resolve()), '-I', '-B',
                str(ROOT / 'tools/transport_quorum_v2_replay.py')]
        for name in NAMES:
            argv.append('--' + name + '=' + str(root / (name + '.json')))
        for name, digest in self.held.items():
            argv.append('--expect-' + name + '-sha256=' + digest)
        for name, value in self.options.items():
            flag = '--expect-' + name[:-7] + '-sha256' if name.endswith('_sha256') else '--' + name
            argv.append(flag.replace('_', '-') + '=' + value)
        observed = run_bounded(argv, ROOT, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        self.assertEqual(observed['exit_code'], 0)
        result = json.loads(observed['stdout'])
        self.assertEqual(result['status'], 'EVALUATED_DIMENSIONS')
        record('cli', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--options', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    CONFIG['options'] = args.options
    before = source_inventory()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReplayIntegration)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = source_inventory()
    passed = result.wasSuccessful() and before == after
    report = dict(schema='quorum/live-integration-test/2', passed=passed,
                  outcomes=OUTCOMES, source_before=before, source_after=after,
                  source_unchanged=before == after, model_execution='NONE', semantic_proof='UNPROVEN')
    with args.output.open('xb') as stream:
        stream.write(canonical(report) + b'\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
