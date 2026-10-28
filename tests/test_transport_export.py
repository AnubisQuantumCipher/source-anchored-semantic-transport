"""Public deterministic export conformance; byte integrity is not source truth."""

import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'tools/transport_cli.py'
EXPORT = ROOT / 'tools/transport_export.py'
TEXT = 'UNVERIFIED_AI_EXPLANATION.txt'
LIMIT = 131_072


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def inventory(directory):
    files = {}
    for number, path in enumerate(sorted(directory.rglob('*'))):
        if number >= 40:
            raise AssertionError('test inventory exceeded bounded export layout')
        if path.is_file() and not path.is_symlink():
            files[str(path.relative_to(directory))] = path.read_bytes()
    return files


def replace_hashes(value, replacements):
    pending = [value]
    for _ in range(4096):
        if not pending:
            return value
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if type(child) is str and child in replacements:
                    item[key] = replacements[child]
                elif isinstance(child, (dict, list)):
                    pending.append(child)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                if type(child) is str and child in replacements:
                    item[index] = replacements[child]
                elif isinstance(child, (dict, list)):
                    pending.append(child)
    raise AssertionError('bounded authored manifest traversal exceeded')


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0
        self.sources = [('ZED', b'Original source\n', 'text/plain'),
                        ('ALPHA', b'\x00\xff', 'application/octet-stream')]
        self.prepare(self.sources)

    def command(self, arguments, tool=EXPORT, isolated=True):
        prefix = [sys.executable] + (['-I'] if isolated else []) + ['-S', '-B', '-Werror', str(tool)]
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'HOME': str(self.root), 'TMPDIR': str(self.root)}
        result = subprocess.run(prefix + list(arguments), cwd=self.root, env=env,
                                capture_output=True, timeout=60, check=False)
        self.assertLessEqual(len(result.stdout), LIMIT + 1)
        self.assertLessEqual(len(result.stderr), 4096)
        log = os.environ.get('TRANSPORT_EXPORT_TEST_LOG')
        if log:
            directory = Path(log) / (self._testMethodName + '-' + str(self.sequence))
            self.sequence += 1
            directory.mkdir()
            for name, data in [('stdout.bin', result.stdout), ('stderr.bin', result.stderr),
                    ('request.json', json_bytes({'argv': prefix + list(arguments), 'cwd': str(self.root),
                      'env': env, 'exit': result.returncode}))]:
                with (directory / name).open('xb') as stream:
                    stream.write(data)
        return result

    def ok(self, result):
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def prepare(self, sources, typed=False):
        self.sources = sources
        plan = {'schema': 'transport/transport-plan/1', 'sources': [{'id': name, 'label': name,
            'media_type': media, 'provenance': 'Independently held authored fixture.'} for name, _, media in sources],
            'interpretations': [], 'uncertainties': [], 'relations': []}
        if typed:
            plan['schema'] = 'transport/transport-plan/2'
            plan['interpretations'] = [{'id': 'I', 'label': 'Proposed', 'text': 'Declared reading.',
                'status': 'proposed', 'provenance': 'Authored test.',
                'anchors': [{'source': sources[0][0], 'span': [0, len(sources[0][1])]}]}]
            plan['meaning_units'] = [{'id': 'U', 'source': sources[0][0], 'interpretation': 'I',
                'kind': 'source_claim', 'context': [], 'plan': {'schema': 'transport/encoding-plan/1',
                'symbols': {'S': 'Claim'}, 'meaning': {'schema': 'transport/meaning/1',
                'nodes': [{'op': 'text', 'symbol': 'S', 'span': [0, 5]},
                          {'op': 'pred', 'args': [0], 'cue': [0, 0]}], 'root': 1, 'ambiguities': []}}}]
        token = str(len(list(self.root.glob('pair-*'))))
        directory = self.root / ('pair-' + token)
        plan_path = self.root / ('plan-' + token + '.json')
        plan_path.write_bytes(json_bytes(plan))
        arguments = ['encode', str(plan_path), str(directory), '--budget', '65536']
        for name, data, _ in sources:
            path = self.root / ('held-' + token + '-' + name)
            path.write_bytes(data)
            arguments += ['--source', name + '=' + str(path)]
        self.ok(self.command(arguments, CLI, isolated=False))
        self.share, self.archive = directory / 'share.txt', directory / 'meaning.zip'
        self.metadata = self.ok(self.command(['inspect', str(self.share), '--archive', str(self.archive)], CLI, False))
        self.identity = self.metadata['identity']
        self.envelope = {'schema': 'transport/explanation-envelope/1', 'package_identity': self.identity,
            'sources': [{'id': name, 'bytes': len(data), 'sha256': sha(data)} for name, data, _ in sources],
            'text': 'Unverified authored explanation.'}
        self.envelope_path = self.root / 'explanation.json'
        self.save_envelope()

    def save_envelope(self, raw=None):
        self.envelope_path.write_bytes(json_bytes(self.envelope) if raw is None else raw)

    def render(self, name='output', tool=EXPORT):
        output = self.root / name
        result = self.command(['render', str(self.share), str(output), '--archive', str(self.archive),
                               '--explanation', str(self.envelope_path)], tool)
        return result, output

    def verify(self, output, identity=None, envelope_pin=None, tool=EXPORT):
        return self.command(['verify', str(self.share), str(output), '--archive', str(self.archive),
            '--explanation', str(self.envelope_path), '--expect-pair', identity or self.identity,
            '--expect-envelope-sha256', envelope_pin or sha(self.envelope_path.read_bytes())], tool)

    def refused_without_output(self, result, output):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob('.transport-export-*')), [])

    def test_exact_sources_prose_manifest_and_public_recover_oracle(self):
        result, output = self.render()
        status = self.ok(result)
        files = inventory(output)
        self.assertEqual(set(files), {'sources/ZED.bin', 'sources/ALPHA.bin', 'metadata.json', TEXT, 'export.json'})
        self.assertEqual(files[TEXT], self.envelope['text'].encode())
        for name, held, _ in self.sources:
            recovered = self.root / ('recovered-' + name)
            self.ok(self.command(['recover', str(self.share), str(recovered), '--archive', str(self.archive),
                '--source', name], CLI, False))
            self.assertEqual(files['sources/' + name + '.bin'], held)
            self.assertEqual(files['sources/' + name + '.bin'], recovered.read_bytes())
        manifest = json.loads(files['export.json'])
        self.assertEqual(manifest['package_identity'], self.identity)
        self.assertEqual([item['id'] for item in manifest['sources']], ['ZED', 'ALPHA'])
        self.assertEqual(manifest['explanation']['role'], 'UNVERIFIED_AI_EXPLANATION')
        self.assertEqual(manifest['explanation']['execution_authority'], 'NONE')
        self.assertEqual(manifest['explanation']['factual_certification'], 'NOT_PERFORMED')
        self.assertEqual(manifest['explanation']['input_envelope_sha256'], sha(self.envelope_path.read_bytes()))
        for item in manifest['files']:
            self.assertEqual((item['bytes'], item['sha256']), (len(files[item['path']]), sha(files[item['path']])))
        self.assertEqual(status['export_sha256'], sha(files['export.json']))
        self.assertEqual(status['aggregate_bytes'], sum(map(len, files.values())))
        checked = self.ok(self.verify(output))
        self.assertEqual(checked['status'], 'VERIFIED_AGAINST_PINNED_INPUTS')
        self.assertEqual(checked['authentication'], 'NOT_PROVIDED')
        self.assertEqual(checked['semantic_completeness'], 'NOT_CLAIMED')

    def test_public_api_matches_cli_and_rejects_unpinned_or_mutable_artifact_values(self):
        import transport_export as exporter
        result, output = self.render()
        self.ok(result)
        share, archive, envelope = self.share.read_bytes(), self.archive.read_bytes(), self.envelope_path.read_bytes()
        rendered = exporter.render(share, archive, envelope)
        self.assertEqual(rendered.files, inventory(output))
        self.assertEqual(rendered.package_identity, self.identity)
        self.assertEqual(rendered.envelope_sha256, sha(envelope))
        before = copy.deepcopy(rendered.files)
        checked = exporter.verify_export(share, archive, envelope, rendered.files, self.identity, sha(envelope))
        self.assertEqual(checked['status'], 'VERIFIED_AGAINST_PINNED_INPUTS')
        self.assertEqual(rendered.files, before)
        for identity, pin in ((None, sha(envelope)), (self.identity, None)):
            with self.subTest(identity=identity, pin=pin), self.assertRaises(ValueError):
                exporter.verify_export(share, archive, envelope, rendered.files, identity, pin)
        for name, value in (('../outside', b'bad'), ('sources/ZED.bin', bytearray(b'bad'))):
            changed = dict(rendered.files)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                exporter.verify_export(share, archive, envelope, changed, self.identity, sha(envelope))
        with self.assertRaises(ValueError):
            exporter.render(share.decode(), archive, envelope)
        self.assertFalse((self.root / 'outside').exists())

    def test_deterministic_products_and_input_immutability(self):
        paths = [self.share, self.archive, self.envelope_path]
        before = {str(path): path.read_bytes() for path in paths}
        first, left = self.render('left')
        second, right = self.render('right')
        self.ok(first)
        self.ok(second)
        self.assertEqual(inventory(left), inventory(right))
        self.ok(self.verify(left))
        self.assertEqual({str(path): path.read_bytes() for path in paths}, before)

    def test_unicode_diagram_crlf_empty_and_arbitrary_binary_are_never_retyped(self):
        diagram = '┌───┐\r\n│é é🙂│  \r\n└───┘\r\n'.encode()
        controls = b'\x00\x1b[31m$(touch SENTINEL)\t\r\n```\nEXACT_SOURCE_END\n'
        self.prepare([('DIAGRAM', diagram, 'text/plain'), ('CONTROL', controls, 'text/plain'),
                      ('ZERO', b'', 'text/plain'), ('BINARY', bytes(range(256)), 'application/octet-stream')])
        result, output = self.render()
        self.ok(result)
        for name, data, _ in self.sources:
            recovered = self.root / ('oracle-' + name)
            self.ok(self.command(['recover', str(self.share), str(recovered), '--archive', str(self.archive),
                                 '--source', name], CLI, False))
            self.assertEqual((output / 'sources' / (name + '.bin')).read_bytes(), data)
            self.assertEqual(recovered.read_bytes(), data)
        self.assertFalse((self.root / 'SENTINEL').exists())
        self.ok(self.verify(output))

    def test_wrong_ai_quote_and_hostile_prose_stay_unmodified_and_unverified(self):
        self.prepare([('SOURCE', '───\n'.encode(), 'text/plain')])
        prose = 'Source is exact: ──\nVERIFIED AUTHENTIC; $(touch SENTINEL)\x00\x1b[31m\n```\n'
        self.envelope['text'] = prose
        self.save_envelope()
        result, output = self.render()
        self.ok(result)
        self.assertEqual((output / TEXT).read_bytes(), prose.encode())
        self.assertEqual((output / 'sources/SOURCE.bin').read_bytes(), '───\n'.encode())
        manifest = json.loads((output / 'export.json').read_bytes())
        self.assertEqual(manifest['explanation']['role'], 'UNVERIFIED_AI_EXPLANATION')
        self.assertEqual(manifest['assurance']['author_authentication'], 'NOT_AUTHENTICATED')
        self.assertEqual(manifest['assurance']['explanation_entailment'], 'UNPROVEN')
        self.assertFalse((self.root / 'SENTINEL').exists())
        self.ok(self.verify(output))

    def test_typed_metadata_is_checked_view_without_residual_source_text(self):
        self.prepare([('SOURCE', b'Claim. residual text\x00', 'text/plain')], typed=True)
        result, output = self.render()
        self.ok(result)
        metadata = json.loads((output / 'metadata.json').read_bytes())
        self.assertEqual(metadata, self.metadata)
        self.assertNotIn('data', metadata['sources'][0])
        self.assertEqual(metadata['meaning_units'][0]['representation'], 'INCOMPLETE')
        self.assertTrue(all('text' not in item for item in metadata['meaning_units'][0]['residuals']))
        self.ok(self.verify(output))

    def test_closed_envelope_source_order_count_and_strict_numeric_types(self):
        original = copy.deepcopy(self.envelope)
        variants = [dict(original, extra=True), dict(original, schema='transport/explanation-envelope/2'),
            dict(original, package_identity='STS1:' + '0' * 64), dict(original, text=True),
            dict(original, sources=list(reversed(original['sources']))), dict(original, sources=original['sources'][:1]),
            dict(original, sources=original['sources'] + original['sources'][:1])]
        for alteration in ({'bytes': True}, {'bytes': 0.0}, {'sha256': '0' * 64}, {'id': '../BAD'}, {'extra': True}):
            value = copy.deepcopy(original)
            value['sources'][0].update(alteration)
            variants.append(value)
        for index, value in enumerate(variants):
            self.envelope = value
            self.save_envelope()
            result, output = self.render('invalid-' + str(index))
            with self.subTest(index=index):
                self.refused_without_output(result, output)

    def test_invalid_utf8_surrogate_duplicate_and_truncated_envelope_refuse_atomically(self):
        original = json_bytes(self.envelope)
        variants = [b'\xff', b'{', original[:-1], original[:-1] + b',"text":"duplicate"}',
                    json_bytes(dict(self.envelope, text='\ud800'))]
        for index, data in enumerate(variants):
            self.save_envelope(data)
            result, output = self.render('bad-envelope-' + str(index))
            with self.subTest(index=index):
                self.refused_without_output(result, output)

    def test_wrong_pair_truncated_archive_and_changed_share_refuse_without_publication(self):
        original_share, original_archive = self.share.read_bytes(), self.archive.read_bytes()
        self.prepare([('OTHER', b'Different source', 'text/plain')])
        second_archive = self.archive.read_bytes()
        self.share.write_bytes(original_share)
        for index, archive in enumerate((second_archive, original_archive[:-1], original_archive[:40])):
            self.archive.write_bytes(archive)
            result, output = self.render('bad-pair-' + str(index))
            self.refused_without_output(result, output)
        self.archive.write_bytes(original_archive)
        self.share.write_bytes(original_share + b'\n')
        self.refused_without_output(*self.render('changed-share'))

    def test_literal_truncation_marker_is_data_not_evidence_of_missing_bytes(self):
        data = 'Source literal: …1792 tokens truncated…\r\n'.encode()
        self.prepare([('SOURCE', data, 'text/plain')])
        self.envelope['text'] = 'Prose literal: …1792 tokens truncated…'
        self.save_envelope()
        result, output = self.render()
        self.ok(result)
        self.assertEqual((output / 'sources/SOURCE.bin').read_bytes(), data)
        self.assertEqual((output / TEXT).read_bytes(), self.envelope['text'].encode())
        self.ok(self.verify(output))

    def test_external_pair_and_raw_envelope_pins_are_mandatory(self):
        result, output = self.render()
        self.ok(result)
        before = inventory(output)
        for identity, pin in [('STS1:' + '0' * 64, sha(self.envelope_path.read_bytes())),
                              (self.identity, '0' * 64)]:
            self.assertNotEqual(self.verify(output, identity, pin).returncode, 0)
        args = ['verify', str(self.share), str(output), '--archive', str(self.archive),
                '--explanation', str(self.envelope_path)]
        self.assertNotEqual(self.command(args).returncode, 0)
        original_pin = sha(self.envelope_path.read_bytes())
        self.save_envelope(json.dumps(self.envelope, indent=2).encode())
        self.assertNotEqual(self.verify(output, envelope_pin=original_pin).returncode, 0)
        self.assertEqual(inventory(output), before)

    def test_postpublication_tamper_missing_extra_and_nested_paths_refuse_without_repair(self):
        result, output = self.render()
        self.ok(result)
        original = inventory(output)
        for name in ('sources/ZED.bin', TEXT, 'metadata.json', 'export.json'):
            path = output / name
            path.write_bytes(original[name] + b' ')
            changed = inventory(output)
            self.assertNotEqual(self.verify(output).returncode, 0)
            self.assertEqual(inventory(output), changed)
            path.write_bytes(original[name])
        target = output / 'sources/ZED.bin'
        target.unlink()
        self.assertNotEqual(self.verify(output).returncode, 0)
        target.write_bytes(original['sources/ZED.bin'])
        (output / 'extra').write_bytes(b'extra')
        self.assertNotEqual(self.verify(output).returncode, 0)
        (output / 'extra').unlink()
        (output / 'sources/nested').mkdir()
        self.assertNotEqual(self.verify(output).returncode, 0)
        (output / 'sources/nested').rmdir()
        self.ok(self.verify(output))

    def test_coherently_rehashed_wrong_source_and_prose_cannot_replace_pinned_inputs(self):
        result, output = self.render()
        self.ok(result)
        manifest_path = output / 'export.json'
        source_path = output / 'sources/ZED.bin'
        old_source = source_path.read_bytes()
        new_source = b'Z' * len(old_source)
        source_path.write_bytes(new_source)
        metadata_path = output / 'metadata.json'
        old_metadata = metadata_path.read_bytes()
        metadata = json.loads(old_metadata)
        metadata['sources'][0]['sha256'] = sha(new_source)
        new_metadata = json_bytes(metadata)
        metadata_path.write_bytes(new_metadata)
        old_text = (output / TEXT).read_bytes()
        new_text = b'X' * len(old_text)
        (output / TEXT).write_bytes(new_text)
        manifest = replace_hashes(json.loads(manifest_path.read_bytes()),
            {sha(old_source): sha(new_source), sha(old_metadata): sha(new_metadata), sha(old_text): sha(new_text)})
        manifest_path.write_bytes(json_bytes(manifest))
        for item in manifest['files']:
            actual = (output / item['path']).read_bytes()
            self.assertEqual((item['bytes'], item['sha256']), (len(actual), sha(actual)))
        changed = inventory(output)
        self.assertNotEqual(self.verify(output).returncode, 0)
        self.assertEqual(inventory(output), changed)

    def test_destination_collisions_and_source_symlinks_never_overwrite(self):
        result, output = self.render()
        self.ok(result)
        original = inventory(output)
        second, same = self.render()
        self.assertEqual(same, output)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(inventory(output), original)
        link = self.root / 'output-link'
        link.symlink_to(output, target_is_directory=True)
        self.assertNotEqual(self.render('output-link')[0].returncode, 0)
        self.assertNotEqual(self.verify(link).returncode, 0)
        path = output / 'sources/ZED.bin'
        held = self.root / 'held-symlink-target'
        held.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(held)
        self.assertNotEqual(self.verify(output).returncode, 0)
        self.assertEqual(held.read_bytes(), original['sources/ZED.bin'])
        self.assertEqual(list(self.root.glob('.transport-export-*')), [])

    def test_source_maximum_and_envelope_maximum_inputs_do_not_relax_aggregate_cap(self):
        self.prepare([('SOURCE', b'A' * 65_536, 'text/plain')])
        result, output = self.render('source-maximum')
        self.ok(result)
        self.assertEqual((output / 'sources/SOURCE.bin').read_bytes(), b'A' * 65_536)
        self.envelope['text'] = 'X' * 64_000
        self.save_envelope()
        self.assertLessEqual(self.envelope_path.stat().st_size, 65_536)
        self.refused_without_output(*self.render('aggregate-overflow'))
        self.envelope['text'] = 'X' * 65_536
        self.save_envelope()
        self.assertGreater(self.envelope_path.stat().st_size, 65_536)
        self.refused_without_output(*self.render('envelope-overflow'))

    def test_sixteen_distinct_empty_sources_are_not_deduplicated_or_dropped(self):
        self.prepare([('S' + str(index), b'', 'application/octet-stream') for index in range(16)])
        self.envelope['text'] = ''
        self.save_envelope()
        result, output = self.render()
        status = self.ok(result)
        self.assertEqual(status['files'], 19)
        for name, data, _ in self.sources:
            self.assertEqual((output / 'sources' / (name + '.bin')).read_bytes(), data)
        self.assertEqual((output / TEXT).read_bytes(), b'')
        self.ok(self.verify(output))

    def test_original_export_binds_exact_pair_bytes_not_only_logical_identity(self):
        result, output = self.render()
        self.ok(result)
        original = self.archive.read_bytes()
        buffer = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(original)) as archive, zipfile.ZipFile(buffer, 'w') as changed:
            for info in reversed(archive.infolist()):
                changed.writestr(copy.copy(info), archive.read(info.filename))
        alternate = buffer.getvalue()
        self.assertNotEqual(sha(alternate), sha(original))
        self.archive.write_bytes(alternate)
        checked = self.ok(self.command(['inspect', str(self.share), '--archive', str(self.archive)], CLI, False))
        self.assertEqual(checked, self.metadata)
        self.assertNotEqual(self.verify(output).returncode, 0)
        alternate_result, alternate_output = self.render('alternate-serialization')
        self.ok(alternate_result)
        manifest = json.loads((alternate_output / 'export.json').read_bytes())
        self.assertEqual(manifest['inputs']['archive'], {'bytes': len(alternate), 'sha256': sha(alternate)})
        self.ok(self.verify(alternate_output))

    def test_source_directory_creation_failure_cleans_owned_stage_without_partial_product(self):
        import transport_export as exporter
        rendered = exporter.render(self.share.read_bytes(), self.archive.read_bytes(), self.envelope_path.read_bytes())
        output = self.root / 'failed-publication'
        before = set(self.root.iterdir())
        original = Path.mkdir
        def fail_source_directory(path, *args, **kwargs):
            if path.name == 'sources' and path.parent.parent == self.root:
                raise OSError(28, 'Authored directory-creation failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'mkdir', fail_source_directory), self.assertRaises(OSError):
            exporter.publish(output, rendered.files)
        self.assertFalse(output.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_copied_runtime_positive_control_then_dependency_and_renderer_changes_refuse(self):
        clone = self.root / 'runtime'
        manifest = json.loads((ROOT / 'RUNTIME.json').read_bytes())
        for item in manifest['files']:
            target = clone / item['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / item['path'], target)
        shutil.copy2(ROOT / 'RUNTIME.json', clone / 'RUNTIME.json')
        copied_export = clone / 'tools/transport_export.py'
        shutil.copy2(EXPORT, copied_export)
        result, output = self.render('cloned-output', copied_export)
        self.ok(result)
        self.ok(self.verify(output, tool=copied_export))
        copied_export.write_bytes(copied_export.read_bytes() + b'\n')
        self.assertNotEqual(self.verify(output, tool=copied_export).returncode, 0)
        shutil.copy2(EXPORT, copied_export)
        native = clone / 'bin/transport_native'
        native.unlink()
        self.refused_without_output(*self.render('missing-native', copied_export))
        self.assertNotEqual(self.verify(output, tool=copied_export).returncode, 0)


if __name__ == '__main__':
    unittest.main()
