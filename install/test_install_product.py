"""Installed-bundle controls, using only installed public routes for product work."""

import argparse
import ast
import asyncio
import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_install_support import canonical, confined, read_regular, require, run_bounded, sha, write_new
import source_page_review_checks as source_review

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
PRODUCT = {'share.txt', 'meaning.zip', 'lexicon.md', 'plan.json', 'review.json'}
MAX_COMMANDS = 128


def inventory(root):
    pending, result = [root], {}
    for _ in range(128):
        if not pending:
            return result
        for entry in pending.pop().iterdir():
            require(len(result) < 256 and not entry.is_symlink(), 'inventory entry bound or symlink')
            metadata = entry.lstat()
            directory = stat.S_ISDIR(metadata.st_mode)
            require(directory or stat.S_ISREG(metadata.st_mode), 'inventory special file')
            result[entry.relative_to(root).as_posix()] = {
                'kind': 'directory' if directory else 'file', 'mode': stat.S_IMODE(metadata.st_mode)}
            if directory:
                pending.append(entry)
    raise ValueError('inventory directory bound')


def check_focus(value, source, identity, expected):
    require(value['schema'] == 'transport/focus/1' and value['identity'] == identity
            and value['selected_unit'] == 'MEANING', 'focused identity or schema mismatch')
    require(value['execution_authority'] == 'NONE' and value['context_adequacy'] == 'UNPROVEN'
            and value['dependency_closure'] == 'ALL_DECLARED_LINKS_CHECKED', 'focused assurance mismatch')
    require([item['id'] for item in value['meaning_units']] == ['MEANING']
            and [item['id'] for item in value['interpretations']] == ['READING'], 'focus dependency IDs')
    unit = value['meaning_units'][0]
    require(unit['interpretation'] == 'READING' and unit['source'] == 'SOURCE'
            and unit['meaning'] == expected['meaning_units'][0]['plan']['meaning'], 'focused meaning mismatch')
    require(len(value['source_excerpts']) == 1, 'controller excerpt count')
    excerpt = value['source_excerpts'][0]
    require(excerpt['span'] == [0, len(source)] and excerpt['source'] == 'SOURCE'
            and excerpt['sha256'] == sha(source)
            and base64.b64decode(excerpt['bytes_base64'], validate=True) == source, 'focus source excerpt mismatch')


def authored(source: bytes, raw: bytes) -> dict:
    document = json.loads(raw)
    document['schema'] = 'transport/authoring/1'
    document['sources'][0]['sha256'] = sha(source)
    document.setdefault('meaning_units', [])
    pending = [document]
    for _ in range(4096):
        if not pending:
            return document
        item = pending.pop()
        if type(item) is dict:
            for key in ('span', 'cue'):
                if key in item and type(item[key]) is list:
                    begin, end = item[key]
                    require(type(begin) is int and type(end) is int
                            and 0 <= begin <= end <= len(source), 'fixture span invalid')
                    selection = None if begin == end else {'quote': source[begin:end].decode(), 'at': begin}
                    if key == 'span' and 'source' in item:
                        del item[key]
                        item['selection'] = selection
                    else:
                        item[key] = selection
            require(len(item) <= 64, 'fixture object bound')
            pending.extend(item.values())
        elif type(item) is list:
            require(len(item) <= 256, 'fixture list bound')
            pending.extend(item)
        require(len(pending) <= 4096, 'fixture pending bound')
    raise ValueError('fixture traversal bound')


class Campaign:
    def __init__(self, args, scratch):
        self.args, self.root, self.bundle = args, scratch, args.bundle.absolute()
        self.evidence = args.evidence.absolute()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.commands, self.inputs, self.products = [], {}, {}
        self.test_inputs = {str(path): sha(read_regular(path)) for path in
            (Path(__file__), Path(source_review.__file__), Path(__file__).parent / 'transport_install_support.py')}
        self.before = self.bundle_hashes(self.bundle)
        self.before_inventory = inventory(self.bundle)

    def bundle_hashes(self, bundle):
        manifest = json.loads(read_regular(bundle / 'INSTALL.json'))
        require(type(manifest['files']) is list and len(manifest['files']) <= 128, 'bundle file bound')
        names = [item['path'] for item in manifest['files']] + ['INSTALL.json', 'bin/semantic-transport']
        return {name: sha(read_regular(confined(bundle, name))) for name in names}

    def command(self, name, arguments, bundle=None, argv=None):
        require(len(self.commands) < MAX_COMMANDS, 'campaign command bound')
        executable = (bundle or self.bundle) / 'bin/semantic-transport'
        invocation = argv or [str(executable), *map(str, arguments)]
        result = run_bounded(invocation, self.root, ENVIRONMENT, timeout=30, cap=262144)
        entry = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
        entry['name'] = name
        for stream in ('stdout', 'stderr'):
            filename = f'{len(self.commands):03d}-{name}.{stream}.bin'
            write_new(self.evidence / filename, result[stream])
            entry[stream] = {'file': filename, 'bytes': len(result[stream]), 'sha256': sha(result[stream])}
        self.commands.append(entry)
        return result

    def success(self, name, arguments, bundle=None, argv=None):
        result = self.command(name, arguments, bundle, argv)
        require(result['status'] == 'SUCCESS' and result['exit_code'] == 0,
                name + ': ' + repr(result['stderr'][:512]))
        return json.loads(result['stdout'])

    def refuse(self, name, arguments, bundle=None):
        result = self.command(name, arguments, bundle)
        require(result['status'] == 'EXIT_NONZERO' and result['exit_code'] != 0
                and b'REFUSED:' in result['stderr'], name + ': expected explicit refusal')
        require(not result['stdout'], name + ': refusal exposed product output')
        return result

    def fixture(self, name, directory, source_name, plan_name):
        source_path, plan_path = directory / source_name, directory / plan_name
        source, raw = read_regular(source_path, 65536), read_regular(plan_path, 65536)
        self.inputs[str(source_path)] = sha(source)
        self.inputs[str(plan_path)] = sha(raw)
        document = authored(source, raw)
        source_id = document['sources'][0]['id']
        copied, spec, pair = self.root / (name + '.input'), self.root / (name + '.json'), self.root / name
        write_new(copied, source)
        write_new(spec, canonical(document))
        expected_path = self.root / (name + '.expected-plan.json')
        write_new(expected_path, raw)
        result = self.success(name + '-encode', ['encode', spec, pair, '--source',
                              source_id + '=' + str(copied), '--budget', '65536'])
        require(result['status'] == 'MATCHED_PAIR_WRITTEN', 'authoring status mismatch')
        require({item.name for item in pair.iterdir()} == PRODUCT, 'authoring membership mismatch')
        view = self.success(name + '-inspect', ['inspect', pair / 'share.txt', '--archive', pair / 'meaning.zip'])
        self.products[name] = {'pair': pair, 'source': source, 'source_id': source_id,
                               'identity': view['identity'], 'spec': spec, 'input': copied,
                               'expected': json.loads(raw), 'expected_path': expected_path}

    def clone(self, name):
        destination = self.root / name
        destination.mkdir(mode=0o700)
        total = 0
        for relative in self.before:
            source = confined(self.bundle, relative)
            data = read_regular(source)
            total += len(data)
            require(total <= 8388608, 'bundle copy aggregate bound')
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_new(target, data)
            if relative.startswith('bin/'):
                target.chmod(0o700)
        self.success(name + '-baseline', ['check'], destination)
        return destination


class ProductControls(unittest.TestCase):
    campaign = None

    @classmethod
    def setUpClass(cls):
        c = cls.campaign
        checked = c.success('installed-check', ['check'])
        require(checked['status'] == 'INSTALLED_CONTENTS_CHECKED', 'installed check status')
        c.fixture('controller', c.args.fixtures / 'semantic-examples-v1', 'controller.txt', 'controller-plan.json')
        c.fixture('recipe', c.args.fixtures / 'transport-general-v1', 'recipe.txt', 'recipe-plan.json')

    def test_validate_recover_and_selected_focus(self):
        c = self.campaign
        for name, product in c.products.items():
            pair, recovered = product['pair'], c.root / (name + '.recovered')
            c.success(name + '-validate', ['validate', pair / 'share.txt', '--archive', pair / 'meaning.zip'])
            c.success(name + '-recover', ['recover', pair / 'share.txt', recovered,
                      '--archive', pair / 'meaning.zip', '--source', product['source_id']])
            self.assertEqual(read_regular(recovered), product['source'])
        pair = c.products['controller']['pair']
        focused = c.success('controller-focus', ['focus', pair / 'share.txt', '--archive',
                                               pair / 'meaning.zip', '--unit', 'MEANING'])
        product = c.products['controller']
        check_focus(focused, product['source'], product['identity'], product['expected'])
        c.refuse('missing-focus', ['focus', pair / 'share.txt', '--archive', pair / 'meaning.zip', '--unit', 'MISSING'])
        missing = c.root / 'missing.recovered'
        c.refuse('missing-source', ['recover', pair / 'share.txt', missing, '--archive',
                                    pair / 'meaning.zip', '--source', 'MISSING'])
        self.assertFalse(missing.exists())

    def test_render_verify_and_nonrepair(self):
        c, product = self.campaign, self.campaign.products['controller']
        pair, rendered, envelope_path = product['pair'], c.root / 'rendered', c.root / 'envelope.json'
        envelope = {'schema': 'transport/explanation-envelope/1', 'package_identity': product['identity'],
                    'sources': [{'id': product['source_id'], 'bytes': len(product['source']),
                                 'sha256': sha(product['source'])}],
                    'text': 'Synthetic integration explanation; interpretation remains unverified.'}
        raw = canonical(envelope)
        write_new(envelope_path, raw)
        common = [pair / 'share.txt', rendered, '--archive', pair / 'meaning.zip', '--explanation', envelope_path]
        c.success('render', ['render', *common])
        verified = c.success('verify', ['verify', *common, '--expect-pair', product['identity'],
                                       '--expect-envelope-sha256', sha(raw)])
        self.assertEqual(verified['status'], 'VERIFIED_AGAINST_PINNED_INPUTS')
        self.assertEqual(read_regular(rendered / 'sources' / 'SOURCE.bin'), product['source'])
        self.assertEqual(read_regular(rendered / 'UNVERIFIED_AI_EXPLANATION.txt'), envelope['text'].encode())
        c.refuse('verify-wrong-pair', ['verify', *common, '--expect-pair', 'STS1:' + '0' * 64,
                                      '--expect-envelope-sha256', sha(raw)])
        envelope_path.write_bytes(json.dumps(envelope, indent=2).encode())
        c.refuse('verify-envelope-reserialized', ['verify', *common, '--expect-pair', product['identity'],
                                                 '--expect-envelope-sha256', sha(raw)])
        envelope_path.write_bytes(raw)
        artifact = rendered / 'UNVERIFIED_AI_EXPLANATION.txt'
        artifact.write_bytes(b'changed')
        c.refuse('verify-changed-export', ['verify', *common, '--expect-pair', product['identity'],
                                          '--expect-envelope-sha256', sha(raw)])
        self.assertEqual(read_regular(artifact), b'changed')

    def test_mutated_installed_members_refuse(self):
        c = self.campaign
        cases = [('missing', 'tools/transport_codec.py'), ('module', 'tools/transport_package.py'),
                 ('manifest', 'INSTALL.json'), ('runtime', 'RUNTIME.json'),
                 ('extension', 'tools/transport_authoring.py'), ('native', 'bin/transport_native'),
                 ('unused', 'LICENSE'), ('extra', 'unexpected'), ('symlink', 'tools/transport_wire.py')]
        for label, relative in cases:
            with self.subTest(case=label):
                clone = c.clone('mutation-' + label)
                target = clone / relative
                if label in ('missing', 'symlink'):
                    target.unlink()
                    if label == 'symlink':
                        target.symlink_to(c.bundle / relative)
                elif label == 'extra':
                    write_new(target, b'not a declared member')
                else:
                    target.write_bytes(read_regular(target) + b'\n')
                c.refuse('mutation-' + label + '-refused', ['check'], clone)

    def test_swapped_and_altered_packages_refuse(self):
        c = self.campaign
        controller, recipe = c.products['controller']['pair'], c.products['recipe']['pair']
        c.refuse('swapped-pair', ['validate', controller / 'share.txt', '--archive', recipe / 'meaning.zip'])
        altered = c.root / 'altered.zip'
        write_new(altered, read_regular(controller / 'meaning.zip')[:-1])
        c.refuse('altered-archive', ['validate', controller / 'share.txt', '--archive', altered])
        share = c.root / 'altered-share.txt'
        write_new(share, b'X' + read_regular(controller / 'share.txt')[1:])
        c.refuse('altered-share', ['validate', share, '--archive', controller / 'meaning.zip'])

    def test_existing_output_is_preserved(self):
        c, product = self.campaign, self.campaign.products['controller']
        existing = c.root / 'existing-output'
        existing.mkdir(mode=0o700)
        write_new(existing / 'marker', b'preserve')
        c.refuse('encode-existing', ['encode', product['spec'], existing, '--source',
                  product['source_id'] + '=' + str(product['input']), '--budget', '65536'])
        self.assertEqual(read_regular(existing / 'marker'), b'preserve')
        recovered = c.root / 'existing-recovery'
        write_new(recovered, b'preserve')
        c.refuse('recover-existing', ['recover', product['pair'] / 'share.txt', recovered,
                  '--archive', product['pair'] / 'meaning.zip', '--source', product['source_id']])
        self.assertEqual(read_regular(recovered), b'preserve')
        stages = [path.name for path in c.root.iterdir() if path.name.startswith('.transport-')]
        self.assertEqual(stages, [])

    def test_mcp_actual_sdk_stdio(self):
        c, product = self.campaign, self.campaign.products['controller']
        pair = product['pair']
        startup = c.command('mcp-sdk-gate', ['mcp', pair / 'share.txt', '--archive',
                            pair / 'meaning.zip', '--expect-pair', product['identity']])
        if startup['status'] != 'SUCCESS':
            dependency = any(item in startup['stderr'] for item in
                             (b'dependency version mismatch', b'declared SDK', b'No package metadata'))
            require(dependency and b'REFUSED:' in startup['stderr'], 'unexpected MCP startup failure')
            self.skipTest('UNRUN: installed MCP SDK dependency gate refused; raw evidence retained')
        worker = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--mcp-worker',
                  str(c.bundle), str(pair), str(product['input']), product['identity'],
                  str(product['expected_path'])]
        exchange = c.success('mcp-sdk-exchange', [], argv=worker)
        self.assertEqual(exchange['status'], 'ACTUAL_SDK_STDIO_TESTED')

    def test_mcp_source_page_review(self):
        c = self.campaign
        configuration, product = source_review.prepare(c)
        pair = Path(product['pair'])
        startup = c.command('source-review-sdk-gate', ['mcp', pair / 'share.txt', '--archive',
                            pair / 'meaning.zip', '--expect-pair', product['identity']])
        if startup['status'] != 'SUCCESS':
            dependency = any(item in startup['stderr'] for item in
                             (b'dependency version mismatch', b'declared SDK', b'No package metadata'))
            require(dependency and b'REFUSED:' in startup['stderr'], 'unexpected source review MCP startup failure')
            self.skipTest('UNRUN: source review MCP SDK dependency gate refused; raw evidence retained')
        worker = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--source-review-worker',
                  str(c.bundle), str(configuration)]
        exchange = c.success('source-review-sdk-exchange', [], argv=worker)
        self.assertEqual(exchange['status'], 'SOURCE_PAGE_REVIEW_ACTUAL_SDK_STDIO_TESTED')

    def test_optional_historical_runtime_incompatibility(self):
        c = self.campaign
        if c.args.historical_pair is None or c.args.historical_decoder is None:
            self.skipTest('UNRUN: historical pair and decoder must both be explicitly supplied')
        pair = c.args.historical_pair
        decoder = c.args.historical_decoder / 'tools' / 'transport_cli.py'
        old_runtime = c.args.historical_decoder / 'RUNTIME.json'
        for path in (decoder, old_runtime, pair / 'share.txt', pair / 'meaning.zip'):
            c.inputs[str(path)] = sha(read_regular(path))
        self.assertNotEqual(c.inputs[str(old_runtime)], c.before['RUNTIME.json'])
        prefix = [sys.executable, '-E', '-s', '-S', '-B', '-Werror', str(decoder)]
        c.success('historical-positive-validate', [], argv=prefix + ['validate',
            str(pair / 'share.txt'), '--archive', str(pair / 'meaning.zip')])
        held = c.success('historical-positive-inspect', [], argv=prefix + ['inspect',
            str(pair / 'share.txt'), '--archive', str(pair / 'meaning.zip')])
        self.assertTrue(held['identity'].startswith('STS1:'))
        refused = c.refuse('historical-pair-refused', ['validate', pair / 'share.txt', '--archive', pair / 'meaning.zip'])
        self.assertIn(b'incompatible decoder dependency identity', refused['stderr'])
        new = c.products['controller']['pair']
        argv = prefix + ['validate', str(new / 'share.txt'), '--archive', str(new / 'meaning.zip')]
        result = c.command('historical-decoder-refused-new', [], argv=argv)
        self.assertEqual(result['status'], 'EXIT_NONZERO')
        self.assertIn(b'REFUSED: Transport missing or incompatible decoder dependency identity', result['stderr'])
        self.assertFalse(result['stdout'])

    def test_functions_are_bounded_in_size(self):
        for path in (Path(__file__), Path(source_review.__file__)):
            for node in ast.walk(ast.parse(read_regular(path).decode())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    with self.subTest(path=path.name, function=node.name):
                        self.assertLessEqual(node.end_lineno - node.lineno + 1, 60)


async def sdk_calls(session, source, identity, expected):
    initialized = await session.initialize()
    discovered = await session.list_tools()
    require({tool.name for tool in discovered.tools} ==
            {'transport_inspect', 'transport_source_page', 'transport_focus'}, 'MCP tool closure')
    require(all(tool.annotations.readOnlyHint for tool in discovered.tools), 'MCP read-only annotations')
    inspected = await session.call_tool('transport_inspect', {})
    require(not inspected.isError and json.loads(inspected.content[0].text)['identity'] == identity,
            'MCP inspected identity mismatch')
    page = await session.call_tool('transport_source_page', {'source': 'SOURCE', 'offset': 0})
    body = json.loads(page.content[0].text)
    require(not page.isError and base64.b64decode(body['base64'], validate=True) == source
            and body['authority'] == 'NONE', 'MCP source bytes or authority mismatch')
    focused = await session.call_tool('transport_focus', {'unit': 'MEANING'})
    require(not focused.isError, 'MCP selected focus failed')
    check_focus(json.loads(focused.content[0].text), source, identity, expected)
    invalid = await session.call_tool('transport_source_page', {'source': 'SOURCE', 'offset': True})
    extra = await session.call_tool('transport_inspect', {'path': '/etc/passwd'})
    after_error = await session.call_tool('transport_inspect', {})
    require(invalid.isError and extra.isError and not after_error.isError, 'MCP error contract')
    return [value.model_dump(mode='json') for value in
            (initialized, discovered, inspected, page, focused, invalid, extra, after_error)]


async def sdk_exchange(bundle, pair, source, identity, expected):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=str(bundle / 'bin/semantic-transport'),
        args=['mcp', str(pair / 'share.txt'), '--archive', str(pair / 'meaning.zip'),
              '--expect-pair', identity], cwd=str(pair.parent), env=ENVIRONMENT)
    async with stdio_client(parameters, errlog=sys.stderr) as (incoming, outgoing):
        async with ClientSession(incoming, outgoing) as session:
            return await sdk_calls(session, source, identity, expected)


def worker(arguments):
    require(len(arguments) == 5, 'MCP worker argument count')
    bundle, pair, source_path = map(Path, arguments[:3])
    result = asyncio.run(asyncio.wait_for(sdk_exchange(bundle, pair,
                         read_regular(source_path, 65536), arguments[3],
                         json.loads(read_regular(Path(arguments[4]), 65536))), timeout=20))
    sys.stdout.buffer.write(canonical({'status': 'ACTUAL_SDK_STDIO_TESTED',
        'trace_kind': 'SDK response serialization; not original wire byte serialization',
        'responses': result}) + b'\n')
    return 0


def receipt(campaign, result):
    final_check = campaign.command('installed-final-check', ['check'])
    unchanged = (campaign.bundle_hashes(campaign.bundle) == campaign.before
                 and inventory(campaign.bundle) == campaign.before_inventory
                 and final_check['status'] == 'SUCCESS' and final_check['exit_code'] == 0)
    test_inputs_unchanged = all(sha(read_regular(Path(path))) == digest
                                for path, digest in campaign.test_inputs.items())
    fixture_inputs_unchanged = all(sha(read_regular(Path(path))) == digest
                                   for path, digest in campaign.inputs.items())
    status = 'TESTED_SCOPED_WITH_UNRUN' if result.skipped else 'TESTED_SCOPED'
    if not result.wasSuccessful() or not unchanged or not test_inputs_unchanged or not fixture_inputs_unchanged:
        status = 'FAILED'
    evidence = {'status': status, 'tests_run': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'skipped': [{'test': str(test), 'reason': reason} for test, reason in result.skipped],
        'bundle': str(campaign.bundle), 'bundle_unchanged': unchanged,
        'bundle_sha256': campaign.before, 'bundle_inventory': campaign.before_inventory,
        'fixture_sha256': campaign.inputs,
        'fixture_inputs_unchanged': fixture_inputs_unchanged, 'test_inputs_unchanged': test_inputs_unchanged,
        'test_inputs_sha256': campaign.test_inputs,
        'test_sha256': sha(read_regular(Path(__file__))),
        'support_sha256': sha(read_regular(Path(__file__).parent / 'transport_install_support.py')),
        'source_review_checks_sha256': sha(read_regular(Path(source_review.__file__))),
        'commands': campaign.commands, 'python': sys.version,
        'limits': ['No model trials, build, publication or whole-system proof.',
                   'Execution assumes trusted tools that do not escape their process group.',
                   'MCP trace preserves SDK response serialization, not original wire bytes.',
                   'Launcher trust is external; launcher self-authentication is not established.']}
    write_new(campaign.evidence / 'receipt.json', canonical(evidence) + b'\n')
    return status != 'FAILED'


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('TRANSPORT_TEST_BUNDLE'))
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, default=ROOT / 'fixtures')
    parser.add_argument('--historical-pair', type=Path)
    parser.add_argument('--historical-decoder', type=Path)
    args = parser.parse_args()
    require(args.bundle is not None, '--bundle or TRANSPORT_TEST_BUNDLE required')
    require(args.historical_decoder is None or args.historical_pair is not None,
            'historical decoder requires explicitly supplied historical pair')
    return args


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--source-review-worker':
        return source_review.worker(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == '--mcp-worker':
        return worker(sys.argv[2:])
    args = arguments()
    with tempfile.TemporaryDirectory(prefix='transport-installed-product-') as directory:
        campaign = Campaign(args, Path(directory))
        ProductControls.campaign = campaign
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProductControls)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if receipt(campaign, result) else 1


if __name__ == '__main__':
    raise SystemExit(main())
