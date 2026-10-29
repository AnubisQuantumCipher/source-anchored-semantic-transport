#!/usr/bin/env python3
"""Bounded source-linked submission controls; optional real installed decoder.

Run with a new absolute --evidence directory. With --bundle, the existing pinned
decoder encodes one synthetic source and both receiving arms are exercised.
The test never executes source or candidate text and does not assess entailment.
"""
import argparse
import ast
import base64
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_checked_finish as checked
import transport_handoff_inputs as inputs
import transport_handoff_prepare as preparation
from test_portable_handoff import bundle_snapshot
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

HERE = Path(__file__).absolute().parent
CONFIG = {}
SOURCE = ('Keeper Mira shall log every sample within 100 ms unless maintenance is active.\n'
          'Observer Noah shall record 225Q events from a base of 87T.\n'
          'Same quotation.\nSame quotation.\n'
          'λ😀 approved yesterday; approval is revoked today.\n').encode('utf-8')
MAX_OUTPUT_BYTES, MAX_OUTPUT_FILES, MAX_PROCESSES = 20971520, 2048, 128


def pin(path):
    raw = read_regular(path)
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))


def save(path, value):
    write_new(path, canonical(value), inputs.CAP)


def closure():
    names = set(inputs.BOOTSTRAP) | {'transport_handoff_client.py', 'transport_checked_finish.py',
            'transport_response_contract.py', 'transport_response_contract_model.py',
            'transport_handoff_prepare.py', 'transport_handoff_prepare_inputs.py',
            'test_portable_handoff.py', 'test_evidence_finish.py'}
    paths = [HERE / name for name in sorted(names)] + [Path(sys.executable).resolve()]
    require(len(paths) <= 16 and len(set(paths)) == len(paths), 'test source closure bound')
    return [pin(path) for path in paths]


def invoke(argv):
    number = CONFIG['processes']
    require(number < MAX_PROCESSES, 'test process count bound')
    CONFIG['processes'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=45, cap=inputs.CAP)
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / ('process-%03d.%s' % (number, stream)), result[stream], inputs.CAP)
    record = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    record.update(argv=argv, **{key: inputs.record(result[key]) for key in ('stdout', 'stderr')})
    save(CONFIG['evidence'] / ('process-%03d.json' % number), record)
    return result


def source_metadata():
    return dict(id='SOURCE', label='Synthetic requirement and history', media_type='text/plain; charset=utf-8',
                provenance='Synthetic test data; not an authenticated statement.')


def prepare_transport():
    root = CONFIG['evidence'] / 'transport-fixture'
    root.mkdir(mode=0o700)
    write_new(root / 'source.txt', SOURCE)
    anchor = dict(source='SOURCE', span=[0, len(SOURCE)])
    plan = dict(schema='transport/transport-plan/2', sources=[source_metadata()],
                interpretations=[dict(id='I_SOURCE', label='SOURCE', text='Unverified synthetic source record.',
                                      status='proposed', provenance='Integration fixture.', anchors=[anchor])],
                meaning_units=[dict(id='U_SOURCE', source='SOURCE', interpretation='I_SOURCE', kind='source_claim', context=[],
                                    plan=dict(schema='transport/encoding-plan/1', symbols=dict(BLOCK=SOURCE.decode('utf-8')),
                                              meaning=dict(schema='transport/meaning/1', root=0, ambiguities=[],
                                                           nodes=[dict(op='atom', symbol='BLOCK', span=[0, len(SOURCE)])])))],
                relations=[], uncertainties=[])
    save(root / 'plan.json', plan)
    argv = [str(CONFIG['bundle'] / 'bin/semantic-transport'), 'encode-plan', str(root / 'plan.json'),
            str(root / 'encoded'), '--budget', '8192', '--reference', 'attached:meaning.zip',
            '--source', 'SOURCE=' + str(root / 'source.txt')]
    result = invoke(argv)
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and not result['stderr'],
            'installed fixture encoding refused; process evidence retained')
    share = read_regular(root / 'encoded/share.txt', inputs.CAP)
    identity = 'STS1:' + share.decode('utf-8').split('STS1:', 1)[1].split()[0]
    require(inputs.re.fullmatch(r'STS1:[0-9a-f]{64}', identity) is not None, 'fixture identity format')
    CONFIG['pair'] = dict(share=share, archive=read_regular(root / 'encoded/meaning.zip', inputs.CAP), identity=identity)


def contract():
    nodes = [dict(id='TEXT', type='string', description='Exact string data.', min_bytes=1, max_bytes=4096),
             dict(id='OFFSET', type='integer', description='Byte offset.', min=0, max=65536),
             dict(id='CITATION', type='object', description='Exact source span.',
                  fields=dict(source_id='TEXT', source_sha256='TEXT', start='OFFSET', end='OFFSET', quote='TEXT')),
             dict(id='CITATIONS', type='array', description='Explicit citation locations.', items='CITATION',
                  min_items=1, max_items=16, unique=False, unique_by=None),
             dict(id='APPROVAL', type='string', description='A claim, not authority.', min_bytes=1, max_bytes=16,
                  enum=['APPROVED', 'REVOKED', 'UNKNOWN']),
             dict(id='RESPONSE', type='object', description='Closed candidate envelope.',
                  fields=dict(citations='CITATIONS', approval='APPROVAL'))]
    return canonical(dict(schema='transport/response-contract/1', description='Syntax only; no semantic finding.',
                          root='RESPONSE', nodes=nodes))


def citation(quote, start=None):
    raw = quote.encode('utf-8')
    begin = SOURCE.index(raw) if start is None else start
    require(SOURCE[begin:begin + len(raw)] == raw, 'test citation construction differs')
    return dict(source_id='SOURCE', source_sha256=sha(SOURCE), start=begin, end=begin + len(raw), quote=quote)


def candidate():
    return dict(citations=[citation(SOURCE.splitlines()[0].decode('utf-8'))], approval='UNKNOWN')


def fixture(root, arm):
    for path in (root, root / 'content', root / 'sessions'):
        path.mkdir(mode=0o700)
    names, raw_helpers = preparation.helper_inputs(arm)
    helpers = preparation.copy_helpers(root, names, raw_helpers)
    content = {'source.txt': SOURCE} if arm == 'original' else dict(share_txt=CONFIG['pair']['share'],
                                                                    meaning_zip=CONFIG['pair']['archive'])
    for name, raw in content.items():
        write_new(root / 'content' / name, raw, inputs.CAP)
    metadata = dict(source_metadata(), bytes=len(SOURCE))
    if arm == 'original':
        metadata['path'] = 'source.txt'
    manifest = dict(schema=inputs.SCHEMA, arm=arm, helpers=helpers, python=pin(Path(sys.executable).resolve()),
                    content=dict(root=str(root / 'content'), files=[dict(pin(root / 'content' / name), path=name) for name in content]),
                    sources=[metadata], held_source_sha256=dict(SOURCE=sha(SOURCE)))
    if arm == 'transport':
        snapshot = CONFIG['bundle_snapshot']
        manifest.update(bundle=dict(path=str(CONFIG['bundle']), install_sha256=snapshot['install_manifest']['sha256'],
                                    snapshot_sha256=sha(canonical(snapshot))),
                        pair=dict(share='share_txt', archive='meaning_zip', identity=CONFIG['pair']['identity']))
    save(root / 'manifest.json', manifest)
    save(root / 'binding.json', preparation.binding_value(root, manifest))
    write_new(root / 'contract.json', contract())
    evidence = canonical(dict(schema='transport/response-evidence-contract/1', description='Check selected source spans only.',
                              response_contract_sha256=sha(contract()), selectors=[['citations', '*']]))
    write_new(root / 'evidence-contract.json', evidence)
    write_new(root / 'candidate.json', canonical(candidate()))
    return SimpleNamespace(binding=root / 'binding.json', expect_binding_sha256=pin(root / 'binding.json')['sha256'],
                           contract=root / 'contract.json', expect_contract_sha256=sha(contract()),
                           evidence_contract=root / 'evidence-contract.json', expect_evidence_contract_sha256=sha(evidence),
                           candidate=root / 'candidate.json', session=root / 'sessions/recipient', root=root, arm=arm)


def command(args):
    argv = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-Werror', str(HERE / 'transport_checked_finish.py'),
            '--contract', str(args.contract), '--expect-contract-sha256', args.expect_contract_sha256,
            '--candidate', str(args.candidate), '--binding', str(args.binding), '--expect-binding-sha256', args.expect_binding_sha256]
    if args.evidence_contract is not None:
        argv.extend(['--evidence-contract', str(args.evidence_contract)])
    if args.expect_evidence_contract_sha256 is not None:
        argv.extend(['--expect-evidence-contract-sha256', args.expect_evidence_contract_sha256])
    return argv


class Controls(unittest.TestCase):
    def setUp(self):
        self.root = CONFIG['evidence'] / self._testMethodName
        self.root.mkdir(mode=0o700)

    def cases(self, tag='case'):
        for arm in CONFIG['arms']:
            yield fixture(self.root / (tag + '-' + arm), arm)

    def call(self, args):
        result = invoke(command(args))
        self.assertEqual(result['stderr'], b'')
        self.assertTrue(result['stdout'].endswith(b'\n'))
        return result, json.loads(result['stdout'])

    def accepted(self, args):
        raw = read_regular(args.candidate, inputs.CANDIDATE_CAP)
        result, value = self.call(args)
        self.assertEqual((result['status'], result['exit_code'], value['status']), ('SUCCESS', 0, 'DRAFT_SAVED_SOURCE_LINKED'))
        self.assertEqual(read_regular(args.session / 'candidate.json', inputs.CANDIDATE_CAP), raw)
        self.assertEqual(value['source_evidence_verdict']['status'], 'SOURCE_SPANS_MATCH')
        self.assertEqual(value['source_evidence_verdict']['candidate_sha256'], sha(raw))
        self.assertEqual(value['semantics'], 'NOT_ASSESSED')
        self.assertEqual(value['source_approval'], 'NOT_ASSESSED')
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertEqual([call['action'] for call in value['calls']], ['describe', 'finish_evidence'])
        return value

    def refused(self, args, before_dispatch=False):
        result, value = self.call(args)
        self.assertNotEqual(result['exit_code'], 0)
        self.assertFalse((args.session / 'candidate.json').exists())
        if before_dispatch:
            self.assertFalse(value['client_dispatched'])
            self.assertFalse(args.session.exists())
        else:
            self.assertEqual(value['calls'][-1]['action'], 'finish_evidence')
            self.assertTrue(value['calls'][-1]['stdout']['capture_complete'])
        return value

    def test_exact_original_and_real_transport_custody(self):
        for args in self.cases():
            with self.subTest(arm=args.arm):
                self.accepted(args)

    def test_fabricated_quote_actor_number_digest_source_and_span_refuse(self):
        mutations = [('quote', 'Invented quotation.'), ('quote', candidate()['citations'][0]['quote'].replace('Mira', 'Noah')),
                     ('quote', candidate()['citations'][0]['quote'].replace('100', '101')), ('source_sha256', '0' * 64),
                     ('source_id', 'ABSENT'), ('start', 1), ('end', len(SOURCE) + 1)]
        for index, (field, replacement) in enumerate(mutations):
            for args in self.cases('mutation-%02d' % index):
                with self.subTest(arm=args.arm, field=field, replacement=replacement):
                    value = candidate()
                    value['citations'][0][field] = replacement
                    args.candidate.write_bytes(canonical(value))
                    self.refused(args)

    def test_repeated_quotes_have_explicit_locations_and_utf8_byte_offsets(self):
        first = SOURCE.index(b'Same quotation.')
        second = SOURCE.index(b'Same quotation.', first + 1)
        for args in self.cases():
            value = candidate()
            value['citations'] = [citation('Same quotation.', first), citation('Same quotation.', second), citation('λ😀')]
            args.candidate.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8') + b'\n')
            answer = self.accepted(args)
            self.assertEqual(answer['source_evidence_verdict']['selected_records'], 3)

    def test_character_offsets_do_not_substitute_for_byte_offsets(self):
        for args in self.cases():
            value = candidate()
            value['citations'] = [citation('λ😀')]
            value['citations'][0]['end'] = value['citations'][0]['start'] + len('λ😀')
            args.candidate.write_bytes(canonical(value))
            self.refused(args)

    def test_missing_evidence_flag_pairs_and_contract_refuse_before_dispatch(self):
        for mode in ('path-only', 'pin-only', 'missing-file'):
            for args in self.cases(mode):
                if mode == 'path-only':
                    args.expect_evidence_contract_sha256 = None
                elif mode == 'pin-only':
                    args.evidence_contract = None
                else:
                    args.evidence_contract.unlink()
                self.refused(args, before_dispatch=True)

    def test_wrong_evidence_pin_structure_pin_and_tampered_contract_refuse(self):
        for mode in ('evidence-pin', 'structure-pin', 'contract-drift', 'different-structure'):
            for args in self.cases(mode):
                if mode == 'evidence-pin':
                    args.expect_evidence_contract_sha256 = '0' * 64
                elif mode == 'structure-pin':
                    args.expect_contract_sha256 = '0' * 64
                elif mode == 'contract-drift':
                    args.evidence_contract.write_bytes(read_regular(args.evidence_contract) + b' ')
                else:
                    value = json.loads(read_regular(args.evidence_contract))
                    value['response_contract_sha256'] = '0' * 64
                    args.evidence_contract.write_bytes(canonical(value))
                    args.expect_evidence_contract_sha256 = pin(args.evidence_contract)['sha256']
                self.refused(args, before_dispatch=True)

    def test_frozen_helper_and_source_or_archive_tamper_refuse(self):
        for mode in ('helper', 'content'):
            for args in self.cases(mode):
                if mode == 'helper':
                    path = args.root / 'helpers/transport_response_evidence.py'
                else:
                    path = args.root / 'content' / ('source.txt' if args.arm == 'original' else 'meaning_zip')
                path.write_bytes(read_regular(path) + b' ')
                self.refused(args, before_dispatch=True)

    def test_evidence_and_candidate_maximum_roundtrip(self):
        for args in self.cases():
            raw = read_regular(args.candidate)
            args.candidate.write_bytes(raw + b' ' * (32768 - len(raw)))
            raw = read_regular(args.evidence_contract)
            args.evidence_contract.write_bytes(raw + b' ' * (8192 - len(raw)))
            args.expect_evidence_contract_sha256 = pin(args.evidence_contract)['sha256']
            self.assertEqual(args.candidate.stat().st_size, 32768)
            self.assertEqual(args.evidence_contract.stat().st_size, 8192)
            self.accepted(args)

    def test_adjacent_candidate_and_evidence_limits_refuse_before_dispatch(self):
        for mode, cap in (('candidate', 32769), ('evidence_contract', 8193)):
            for args in self.cases(mode):
                path = getattr(args, mode)
                raw = read_regular(path)
                path.write_bytes(raw + b' ' * (cap - len(raw)))
                if mode == 'evidence_contract':
                    args.expect_evidence_contract_sha256 = pin(path)['sha256']
                self.refused(args, before_dispatch=True)

    def test_false_approval_with_true_revocation_quote_is_not_semantic_acceptance(self):
        for args in self.cases():
            value = dict(citations=[citation('approval is revoked today.')], approval='APPROVED')
            args.candidate.write_bytes(canonical(value))
            answer = self.accepted(args)
            self.assertEqual(answer['source_evidence_verdict']['semantics'], 'NOT_ASSESSED')
            self.assertEqual(answer['source_evidence_verdict']['context_adequacy'], 'UNPROVEN')

    def test_finished_session_refuses_further_call_and_preserves_exact_candidate(self):
        for args in self.cases():
            self.accepted(args)
            saved = read_regular(args.session / 'candidate.json')
            result, value = self.call(args)
            self.assertNotEqual(result['exit_code'], 0)
            self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')
            self.assertEqual(read_regular(args.session / 'candidate.json'), saved)
            stream = value['calls'][0]['stdout']
            self.assertTrue(stream['capture_complete'])
            self.assertIn('finished', base64.b64decode(stream['base64']).decode('utf-8'))

    def test_post_save_evidence_drift_preserves_raw_capture_and_unknown_custody(self):
        for args in self.cases():
            original, output = checked.client_call, io.BytesIO()
            raw = read_regular(args.candidate)
            def drift(state, binding, request):
                answer = original(state, binding, request)
                if request['action'] == 'finish_evidence':
                    args.evidence_contract.write_bytes(b'{}')
                return answer
            with patch.object(checked, 'client_call', drift), patch.object(checked.resource, 'setrlimit'), \
                 patch.object(checked.sys, 'argv', ['checked'] + command(args)[6:]), \
                 patch.object(checked.sys, 'stdout', SimpleNamespace(buffer=output)):
                status = checked.main()
            value = json.loads(output.getvalue())
            write_new(args.root / 'post-save-response.json', output.getvalue(), inputs.CAP)
            self.assertEqual((status, value['status']), (2, 'REFUSED'))
            self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')
            self.assertTrue(value['reader_action_may_be_recorded'])
            self.assertEqual(read_regular(args.session / 'candidate.json'), raw)
            stream = value['calls'][-1]['stdout']
            captured = base64.b64decode(stream['base64'])
            self.assertTrue(stream['capture_complete'])
            self.assertEqual(stream['sha256'], sha(captured))
            self.assertEqual(json.loads(captured)['result']['status'], 'DRAFT_SAVED_SOURCE_LINKED')

    def test_old_finish_remains_available_without_evidence_contract(self):
        for args in self.cases():
            args.evidence_contract = args.expect_evidence_contract_sha256 = None
            result, value = self.call(args)
            self.assertEqual((result['exit_code'], value['status']), (0, 'DRAFT_SAVED_STRUCTURALLY_CHECKED'))
            self.assertNotIn('source_evidence_verdict', value)
            self.assertEqual(value['scope'], 'STRUCTURE_AND_DRAFT_CUSTODY_ONLY')

    def test_short_functions_and_no_direct_recursion(self):
        tree = ast.parse(read_regular(Path(__file__).absolute()))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)
                calls = [item for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)]
                self.assertFalse(any(item.func.id == node.name for item in calls), node.name)


def output_inventory(root):
    entries, total, pending, seen = [], 0, [root], 0
    for _ in range(MAX_OUTPUT_FILES):
        if not pending:
            break
        path = pending.pop()
        seen += 1
        require(not path.is_symlink(), 'test evidence symlink refused')
        if path.is_dir():
            for child in path.iterdir():
                require(seen + len(pending) < MAX_OUTPUT_FILES, 'test output entry count bound')
                pending.append(child)
        else:
            require(path.is_file(), 'nonregular evidence refused')
            item = dict(pin(path), path=path.relative_to(root).as_posix())
            total += item['bytes']
            require(total <= MAX_OUTPUT_BYTES, 'test output byte budget')
            entries.append(item)
    require(not pending, 'test output traversal bound')
    return dict(bytes=total, files=sorted(entries, key=lambda item: item['path']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    require(args.evidence.is_absolute() and not args.evidence.exists() and not args.evidence.is_symlink(),
            'new absolute evidence directory required')
    require(args.bundle is None or args.bundle.is_absolute(), 'explicit absolute installed bundle required')
    before = closure()
    snapshot = bundle_snapshot(args.bundle) if args.bundle is not None else None
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(evidence=args.evidence, processes=0, bundle=args.bundle, bundle_snapshot=snapshot,
                  arms=('original', 'transport') if snapshot is not None else ('original',))
    save(args.evidence / 'input-freeze.json', dict(files=before, bundle=snapshot))
    if snapshot is not None:
        prepare_transport()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    require(closure() == before, 'test implementation changed during run')
    require(snapshot is None or bundle_snapshot(args.bundle) == snapshot, 'installed decoder changed during run')
    inventory = output_inventory(args.evidence)
    value = dict(schema='transport/evidence-finish-controls/1', status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED',
                 tests_run=result.testsRun, processes=CONFIG['processes'], failures=[item for _, item in result.failures],
                 errors=[item for _, item in result.errors], arms=list(CONFIG['arms']),
                 input_freeze_sha256=pin(args.evidence / 'input-freeze.json')['sha256'],
                 outputs=inventory, models='UNRUN', semantics='NOT_ASSESSED', formal_proof='UNPERFORMED',
                 transport_decoder='TESTED_PINNED_EXISTING_BUNDLE' if snapshot is not None else 'UNRUN',
                 scope='DECLARED_SOURCE_SPANS_STRUCTURAL_CHECK_AND_EXACT_DRAFT_CUSTODY')
    write_new(args.evidence / 'receipt.json', canonical(value) + b'\n', 1048576)
    output_inventory(args.evidence)
    return 0 if result.wasSuccessful() else 1


def guarded_main():
    try:
        return main()
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError) as error:
        root = CONFIG.get('evidence')
        if root is not None:
            failure = dict(schema='transport/evidence-finish-setup-failure/1', status='FAILED_PARTIAL_RETAINED',
                           reason=str(error)[:512], processes=CONFIG.get('processes', 0))
            save(root / 'failure.json', failure)
        sys.stderr.write(str(error)[:512] + '\n')
        return 2


if __name__ == '__main__':
    sys.exit(guarded_main())
