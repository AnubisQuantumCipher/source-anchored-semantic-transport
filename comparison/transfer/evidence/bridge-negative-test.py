#!/usr/bin/env python3
"""Bounded guard tests. Codec work is stubbed; executable launches are trapped."""
import hashlib
import json
from pathlib import Path
import resource
import sys
import types
import unittest

ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
HERE = Path(__file__).resolve().parent
BRIDGE = ROOT/'comparison/transfer/bridge.py'
EXPECTED = '807c30cd3c507a9d66eda710ae92d7124e13bafb9f79151a538b146f2333911a'
OLD = Path('/dev/shm/semantic-transport-sender-20261029/identifier-closure/normal-POSITIVE/output')
OBS = ROOT/'examples/quorum-sender-v1/observations'
ORIGINAL = (OLD/'original-invocation.json').read_bytes()
TRANSPORT = (OLD/'transport-invocation.json').read_bytes()
SOURCE = BRIDGE.read_bytes()
RESULTS = []


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def write(path, raw):
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise RuntimeError('SHORT_WRITE')


def module():
    if pin(SOURCE)['sha256'] != EXPECTED:
        raise RuntimeError('SOURCE_PIN')
    result = types.ModuleType('_frozen_bridge_prelaunch')
    result.__file__ = str(BRIDGE)
    exec(compile(SOURCE,str(BRIDGE),'exec'),result.__dict__)
    return result


def inputs(root):
    root.mkdir(mode=0o700)
    observations = root/'observations'
    observations.mkdir(mode=0o700)
    for arm in ('original','transport'):
        for suffix in ('execution.json','stdout.bin'):
            name = 'normal-'+arm+'-'+suffix
            write(observations/name,(OBS/name).read_bytes())
    write(root/'original-invocation.json',ORIGINAL)
    write(root/'transport-invocation.json',TRANSPORT)
    return observations


class Prelaunch(unittest.TestCase):
    def exercise(self, name, arm, changed):
        root = HERE/name
        obs = inputs(root)
        frozen = module()
        calls = []
        def forbid(*unused, **also_unused):
            calls.append('FORBIDDEN_BOOTSTRAP_LAUNCH')
            raise AssertionError('bootstrap launch attempted')
        frozen.execute = forbid
        frozen.launch = forbid
        frozen.load_core = lambda observed: None
        frozen.prepare = lambda out, observed: {}
        frozen.reconstruct = lambda core, report, out, data: out/'recipient'
        if changed == 'invocation':
            self.alter_invocation(root,obs,arm)
            reason = 'BRIDGE_'+arm.upper()+'_INVOCATION_PIN'
        else:
            self.alter_expected(obs,arm)
            reason = 'BRIDGE_'+arm.upper()+'_EXPECTED_PIN'
        with self.assertRaisesRegex(ValueError,'^'+reason+'$'):
            if arm == 'original':
                frozen.run(root/'run',root/'original-invocation.json',
                           root/'transport-invocation.json',obs)
            else:
                frozen.transport(root,root/'transport-invocation.json',obs,{})
        self.assertEqual(calls,[])
        RESULTS.append(dict(case=name,status='PASS',reason=reason,bootstrap_calls=calls,
                            stubs='load_core/prepare/reconstruct only; execute/launch forbidden'))

    def alter_invocation(self, root, obs, arm):
        path = root/(arm+'-invocation.json')
        value = json.loads(path.read_bytes())
        value['checker_descriptor']['path'] = str(root/'attacker-checker.json')
        value['bootstrap_entry']['sha256'] = '0'*64
        raw = canonical(value)
        path.write_bytes(raw)
        record = obs/('normal-'+arm+'-execution.json')
        expected = json.loads(record.read_bytes())
        expected['argv'][6] = pin(raw)['sha256']
        record.write_bytes(canonical(expected))

    def alter_expected(self, obs, arm):
        path = obs/('normal-'+arm+'-stdout.bin')
        raw = path.read_bytes()+b'\n'
        path.write_bytes(raw)
        record = obs/('normal-'+arm+'-execution.json')
        expected = json.loads(record.read_bytes())
        expected['stdout'] = pin(raw)
        record.write_bytes(canonical(expected))

    def test_original_coherent_invocation_forgery(self):
        self.exercise('original-invocation-forgery','original','invocation')

    def test_transport_coherent_invocation_forgery(self):
        self.exercise('transport-invocation-forgery','transport','invocation')

    def test_original_coherent_stdout_forgery(self):
        self.exercise('original-stdout-forgery','original','stdout')

    def test_transport_coherent_stdout_forgery(self):
        self.exercise('transport-stdout-forgery','transport','stdout')


def main():
    for kind,limit in ((resource.RLIMIT_AS,1073741824),(resource.RLIMIT_CPU,120),
                       (resource.RLIMIT_FSIZE,2097152)):
        resource.setrlimit(kind,(limit,limit))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Prelaunch)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    unchanged = BRIDGE.read_bytes() == SOURCE
    report = dict(schema='transport/checker-bridge-prelaunch-controls/1',
        source=pin(SOURCE),own_script=pin(Path(__file__).read_bytes()),
        original_invocation=pin(ORIGINAL),transport_invocation=pin(TRANSPORT),
        cases=RESULTS,source_unchanged=unchanged,python=sys.version,
        tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        status='PASS' if result.wasSuccessful() and unchanged else 'FAIL',
        scope='Guard rejection before executable launch; not end-to-end codec or client testing')
    write(HERE/'result.json',canonical(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
