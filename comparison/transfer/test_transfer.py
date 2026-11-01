#!/usr/bin/env python3
"""Independent literal-oracle tests for conventional transfer mechanics only."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ORACLE_SHA256 = '1dccb032103e98984c6143cd4fc33f6bf077ee32868d4cb1c875994d0b282563'
INPUT_SCHEMA = 'transport/transfer-comparison-input/1'
MANIFEST_SCHEMA = 'transport/conventional-transfer-manifest/1'
CAP = 1048576
ARCHIVE_CAP = 2097152
REQUEST_CAP = 65536
LABELS = ('stored', 'deflate9', 'bzip2-9', 'lzma', 'zstd19')
RSYNC_SHA256 = 'cdd6759b34905d289e4b993efc726f7586fe2c12a0e84d712fcf254b1b3ef4b8'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def read(path, cap=ARCHIVE_CAP):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
        raise ValueError('test input must be a bounded regular file')
    with path.open('rb') as stream:
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise ValueError('test input read bound')
    return data


def write(path, data):
    if len(data) > ARCHIVE_CAP or path.is_symlink():
        raise ValueError('test fixture write bound or symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as stream:
        if stream.write(data) != len(data):
            raise OSError('short test fixture write')
    if read(path) != data:
        raise OSError('test fixture readback differs')


def load_oracle():
    raw = read(HERE / 'oracle.json', REQUEST_CAP)
    if digest(raw) != ORACLE_SHA256:
        raise ValueError('independent literal oracle pin differs')
    value = json.loads(raw)
    for item in value['contents'].values():
        data = item['utf8'].encode('utf-8')
        if item['bytes'] != len(data) or item['sha256'] != digest(data):
            raise ValueError('oracle literal content pin differs')
    return value


def load_product():
    spec = importlib.util.spec_from_file_location('conventional_transfer_under_test',
                                                  HERE / 'transfer.py')
    if spec is None or spec.loader is None:
        raise ValueError('transfer API loader absent')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def row(root, arm, alias, revision, data):
    path = root / arm / (alias + '.bin')
    write(path, data)
    return {'id': alias, 'revision': revision, 'path': str(path),
            'bytes': len(data), 'sha256': digest(data)}


def fixture(root, oracle):
    request = {'schema': INPUT_SCHEMA, 'current': [], 'prior': []}
    for arm in ('current', 'prior'):
        for item in oracle[arm]:
            data = oracle['contents'][item['content']]['utf8'].encode('utf-8')
            request[arm].append(row(root, arm, item['id'], item['revision'], data))
    path = root / 'request.json'
    write(path, canonical(request))
    return path, request


def cache_for(oracle):
    result = {}
    for item in oracle['prior']:
        content = oracle['contents'][item['content']]
        result[content['sha256']] = content['utf8'].encode('utf-8')
    return result


def recovered_for(oracle, arm):
    return {item['id']: oracle['contents'][item['content']]['utf8'].encode('utf-8')
            for item in oracle[arm]}


def archive_edit(raw, replacement=None, extra=None):
    if len(raw) > ARCHIVE_CAP:
        raise ValueError('mutation archive bound')
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        entries = source.infolist()
        if len(entries) > 34:
            raise ValueError('mutation member bound')
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as output:
            for entry in entries:
                if entry.file_size > CAP:
                    raise ValueError('mutation expanded member bound')
                data = source.read(entry.filename)
                if replacement is not None and entry.filename == replacement[0]:
                    data = replacement[1]
                output.writestr(entry.filename, data)
            if extra is not None:
                output.writestr(extra[0], extra[1])
    result = target.getvalue()
    if len(result) > ARCHIVE_CAP:
        raise ValueError('mutation output archive bound')
    return result


def tree_bytes(root):
    if not root.exists():
        return {}
    pending, result, total = [root], {}, 0
    for _ in range(2):
        if not pending:
            return result
        for path in pending.pop().iterdir():
            if path.is_symlink():
                raise ValueError('rsync test tree symlink')
            if path.is_dir():
                if path != root / 'files':
                    raise ValueError('unexpected rsync test directory')
                pending.append(path)
            else:
                if len(result) >= 34:
                    raise ValueError('rsync test file count bound')
                data = read(path)
                total += len(data)
                if total > ARCHIVE_CAP:
                    raise ValueError('rsync test aggregate byte bound')
                result[path.relative_to(root).as_posix()] = data
    if pending:
        raise ValueError('rsync test tree depth bound')
    return result


class TransferControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oracle = load_oracle()
        cls.product = load_product()
        temporary = tempfile.TemporaryDirectory(prefix='transfer-oracle-')
        cls.addClassCleanup(temporary.cleanup)
        cls.baseline = Path(temporary.name)
        request, unused = fixture(cls.baseline, cls.oracle)
        cls.baseline_out = cls.baseline / 'out'
        cls.report = cls.product.prepare(request, cls.baseline_out)
        cls.cache = cache_for(cls.oracle)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='transfer-control-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.request_path, self.request = fixture(self.root, self.oracle)
        self.out = self.root / 'out'

    def prepare_refused(self):
        write(self.request_path, canonical(self.request))
        with self.assertRaises(self.product.BaselineError):
            self.product.prepare(self.request_path, self.out)
        self.assertFalse(self.out.exists(), 'preflight refusal published output')

    def artifact(self, candidate, kind, out=None):
        item = candidate[kind]
        name = PurePosixPath(item['path'])
        self.assertFalse(name.is_absolute())
        self.assertEqual(name.as_posix(), item['path'])
        self.assertNotIn('..', name.parts)
        path = (out or self.baseline_out) / name
        raw = read(path)
        self.assertEqual((len(raw), digest(raw)), (item['bytes'], item['sha256']))
        self.assertRegex(item['manifest_sha256'], r'^[0-9a-f]{64}$')
        for timing in ('encode_ns', 'decode_ns'):
            self.assertIs(type(item[timing]), int)
            self.assertGreaterEqual(item[timing], 0)
        return item, raw

    def stored(self, kind='cold'):
        return self.artifact(self.report['candidates']['stored'], kind)

    def restore_refused(self, raw, manifest_sha=None, cache=None, archive_sha=None):
        held = manifest_sha or self.report['manifest']['sha256']
        with self.assertRaises(self.product.BaselineError):
            self.product.restore(raw, archive_sha or digest(raw), held,
                                 {} if cache is None else cache)

    def positive_request(self, current, prior=()):
        request = {'schema': INPUT_SCHEMA, 'current': [], 'prior': []}
        for arm, values in (('current', current), ('prior', prior)):
            self.assertLessEqual(len(values), 32)
            for index, data in enumerate(values):
                request[arm].append(row(self.root, arm, 'X' + str(index), 'r1', data))
        write(self.request_path, canonical(request))
        report = self.product.prepare(self.request_path, self.out)
        self.assertEqual(report['status'], 'TESTED_TRANSFER_MECHANICS')
        cache = {digest(data): data for data in prior}
        wanted = {'X' + str(index): data for index, data in enumerate(current)}
        for label, candidate in report['candidates'].items():
            if candidate['status'] == 'TESTED':
                for kind in ('cold', 'warm'):
                    with self.subTest(label=label, kind=kind):
                        item, raw = self.artifact(candidate, kind, self.out)
                        self.assertEqual(self.product.restore(raw, item['sha256'],
                            item['manifest_sha256'], cache if kind == 'warm' else {}), wanted)
        return report

    def test_literal_object_sets_and_alias_recovery(self):
        self.assertEqual(self.report['status'], 'TESTED_TRANSFER_MECHANICS')
        expected = self.oracle['expected']
        actual_changes = self.report['plan']['changes']
        wanted_changes = [{'id': key, 'status': value}
                          for key, value in sorted(expected['changes'].items())]
        self.assertEqual(actual_changes, wanted_changes)
        for key, source in (('hits', 'warm_hits'), ('needed', 'warm_needed')):
            wanted = sorted(self.oracle['contents'][name]['sha256'] for name in expected[source])
            self.assertEqual(self.report['plan'][key], wanted)
        self.assertEqual(set(self.report['candidates']), set(LABELS))
        for label in self.oracle['required_compressors']:
            self.assertEqual(self.report['candidates'][label]['status'], 'TESTED')
        for label, candidate in self.report['candidates'].items():
            self.assertIn(candidate['status'], ('TESTED', 'UNAVAILABLE'))
            if candidate['status'] == 'UNAVAILABLE':
                self.assertIn(label, self.oracle['optional_compressors'])
                self.assertTrue(candidate['reason'])
            else:
                self.check_candidate(label, candidate)

    def check_candidate(self, label, candidate):
        expected = self.oracle['expected']
        for kind in ('setup', 'cold', 'warm'):
            with self.subTest(candidate=label, kind=kind):
                item, raw = self.artifact(candidate, kind)
                arm = 'prior' if kind == 'setup' else 'current'
                restored = self.product.restore(raw, item['sha256'], item['manifest_sha256'],
                                                self.cache if kind == 'warm' else {})
                self.assertEqual(restored, recovered_for(self.oracle, arm))
                if kind == 'setup':
                    objects = {entry['sha256'] for entry in self.oracle['contents'].values()
                               if entry['sha256'] in self.cache}
                else:
                    key = 'warm_needed' if kind == 'warm' else 'cold_needed'
                    objects = {self.oracle['contents'][name]['sha256'] for name in expected[key]}
                self.check_members(raw, item, objects, arm, kind)

    def check_members(self, raw, item, objects, arm, kind):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            wanted = {'manifest.json', 'index.md'} | {'objects/' + name + '.bin' for name in objects}
            self.assertEqual(set(names), wanted)
            self.assertEqual(len(names), len(wanted), 'duplicate archive member')
            manifest_raw = archive.read('manifest.json')
            self.assertEqual(digest(manifest_raw), item['manifest_sha256'])
            manifest = json.loads(manifest_raw)
            self.assertEqual(manifest['schema'], MANIFEST_SCHEMA)
            self.assertEqual((manifest['authority'], manifest['freshness']), ('NONE', 'UNKNOWN'))
            catalog = archive.read('index.md')
            self.assertEqual(manifest['catalog'], {'bytes': len(catalog), 'sha256': digest(catalog)})
            actual = {row['id']: row for row in manifest['sources']}
            self.assertEqual(len(actual), len(manifest['sources']))
            self.assertEqual(set(actual), {row['id'] for row in self.oracle[arm]})
            for row_value in self.oracle[arm]:
                row_actual = actual[row_value['id']]
                content = self.oracle['contents'][row_value['content']]
                self.assertEqual(set(row_actual), {'id', 'revision', 'name', 'bytes', 'sha256'})
                self.assertEqual((row_actual['revision'], row_actual['bytes'], row_actual['sha256']),
                                 (row_value['revision'], content['bytes'], content['sha256']))
            if kind != 'setup':
                self.assertEqual(self.report['manifest'], {'bytes': len(manifest_raw),
                                                           'sha256': digest(manifest_raw)})

    def test_stale_prior_declared_hash(self):
        self.request['prior'][0]['sha256'] = '0' * 64
        self.prepare_refused()

    def test_missing_prior_file(self):
        Path(self.request['prior'][0]['path']).unlink()
        self.prepare_refused()

    def test_duplicate_current_id(self):
        self.request['current'].append(dict(self.request['current'][0]))
        self.prepare_refused()

    def test_duplicate_prior_id(self):
        self.request['prior'].append(dict(self.request['prior'][0]))
        self.prepare_refused()

    def test_traversal_id(self):
        self.request['current'][0]['id'] = '../ESCAPE'
        self.prepare_refused()

    def test_changed_current_pin(self):
        path = Path(self.request['current'][0]['path'])
        data = read(path)
        write(path, bytes([data[0] ^ 1]) + data[1:])
        self.prepare_refused()

    def test_unknown_schema(self):
        self.request['schema'] = 'transport/transfer-comparison-input/999'
        self.prepare_refused()

    def test_existing_destination(self):
        self.out.mkdir()
        marker = self.out / 'marker'
        write(marker, b'PRESERVE')
        with self.assertRaises(self.product.BaselineError):
            self.product.prepare(self.request_path, self.out)
        self.assertEqual(read(marker), b'PRESERVE')
        self.assertEqual(list(self.out.iterdir()), [marker])

    def test_final_report_is_charged_to_output_bound(self):
        sampled = {'entries': 0, 'bytes': self.product.OUT_CAP}
        with patch.object(self.product, 'output_accounting', return_value=sampled):
            with self.assertRaisesRegex(self.product.BaselineError, 'BASELINE_OUTPUT_BOUND'):
                self.product.prepare(self.request_path, self.out)
        self.assertFalse((self.out / 'report.json').exists())

    def test_malformed_archive(self):
        self.restore_refused(b'not a ZIP archive')

    def test_truncated_archive(self):
        unused, raw = self.stored()
        self.restore_refused(raw[:-1])

    def test_trailing_archive_data(self):
        unused, raw = self.stored()
        self.restore_refused(raw + b'UNDECLARED_TRAILING_DATA')

    def test_corrupt_archive_member(self):
        unused, raw = self.stored()
        name = self.oracle['contents']['NEW']['sha256']
        changed = archive_edit(raw, replacement=('objects/' + name + '.bin', b'corrupted'))
        self.restore_refused(changed)

    def test_wrong_held_archive_digest(self):
        unused, raw = self.stored()
        self.restore_refused(raw, archive_sha='0' * 64)

    def test_wrong_held_manifest_digest(self):
        unused, raw = self.stored()
        self.restore_refused(raw, manifest_sha='0' * 64)

    def test_missing_warm_cache(self):
        item, raw = self.stored('warm')
        self.restore_refused(raw, manifest_sha=item['manifest_sha256'], cache={})

    def test_wrong_cache_bytes(self):
        item, raw = self.stored('warm')
        cache = dict(self.cache)
        cache[self.oracle['contents']['KEEP']['sha256']] = b'wrong cached bytes'
        self.restore_refused(raw, manifest_sha=item['manifest_sha256'], cache=cache)

    def test_cache_aggregate_over_cap(self):
        item, raw = self.stored('warm')
        cache = dict(self.cache)
        extra = b'Z' * CAP
        self.assertEqual(len(extra), CAP)
        cache[digest(extra)] = extra
        self.assertGreater(sum(len(data) for data in cache.values()), CAP)
        self.assertTrue(all(len(data) <= CAP and digest(data) == key
                            for key, data in cache.items()))
        self.restore_refused(raw, manifest_sha=item['manifest_sha256'], cache=cache)

    def test_unsafe_archive_name(self):
        unused, raw = self.stored()
        self.restore_refused(archive_edit(raw, extra=('../ESCAPE', b'inert')))

    def test_unsupported_archive_version(self):
        unused, raw = self.stored()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            manifest = json.loads(archive.read('manifest.json'))
        manifest['schema'] = 'transport/conventional-transfer-manifest/999'
        replacement = canonical(manifest)
        changed = archive_edit(raw, replacement=('manifest.json', replacement))
        self.restore_refused(changed, manifest_sha=digest(replacement))

    def test_exact_aggregate_cap(self):
        self.positive_request([b'x' * CAP])

    def test_exact_prior_aggregate_cap(self):
        self.positive_request([b'current'], [b'p' * CAP])

    def test_source_over_cap(self):
        self.request['current'] = [row(self.root, 'oversize', 'BIG', 'r1', b'x' * (CAP + 1))]
        self.request['prior'] = []
        self.prepare_refused()

    def aggregate_over_cap(self, arm):
        self.request[arm] = [row(self.root, arm, 'BIG_A', 'r1', b'a' * (CAP // 2)),
                             row(self.root, arm, 'BIG_B', 'r1', b'b' * (CAP // 2 + 1))]
        self.prepare_refused()

    def test_current_aggregate_over_cap(self):
        self.aggregate_over_cap('current')

    def test_prior_aggregate_over_cap(self):
        self.aggregate_over_cap('prior')

    def test_exact_row_count_cap(self):
        self.positive_request([b'x'] * 32)

    def too_many_rows(self, arm):
        self.request[arm] = [row(self.root, arm, 'X' + str(index), 'r1', b'x')
                             for index in range(33)]
        self.prepare_refused()

    def test_too_many_current_rows(self):
        self.too_many_rows('current')

    def test_too_many_prior_rows(self):
        self.too_many_rows('prior')

    def test_request_over_cap(self):
        self.request['current'][0]['path'] = '/' + 'x' * REQUEST_CAP
        self.assertGreater(len(canonical(self.request)), REQUEST_CAP)
        self.prepare_refused()

    def test_source_symlink(self):
        source = Path(self.request['current'][0]['path'])
        link = self.root / 'source-link'
        link.symlink_to(source)
        self.request['current'][0]['path'] = str(link)
        self.prepare_refused()

    def test_invalid_revision(self):
        for revision in ('', 'bad revision', 'x' * 33, '\u00e9'):
            with self.subTest(revision=revision):
                self.request['current'][0]['revision'] = revision
                self.prepare_refused()

    def test_empty_source_bytes(self):
        self.positive_request([b''])

    def test_binary_source_bytes(self):
        self.positive_request([bytes(range(256))])

    def test_empty_prior_setup_is_restored_and_validated(self):
        original, observed = self.product.restore, []
        def record(raw, archive_sha, manifest_sha, cache):
            result = original(raw, archive_sha, manifest_sha, cache)
            if result == {}:
                self.assertLess(len(observed), len(LABELS))
                observed.append(digest(raw))
            return result
        with patch.object(self.product, 'restore', side_effect=record):
            report = self.positive_request([b'new without prior'])
        self.assertCountEqual(observed, [candidate['setup']['sha256']
            for candidate in report['candidates'].values() if candidate['status'] == 'TESTED'])
        for label, candidate in report['candidates'].items():
            if candidate['status'] == 'TESTED':
                with self.subTest(candidate=label):
                    item, raw = self.artifact(candidate, 'setup', self.out)
                    self.assertEqual(self.product.restore(raw, item['sha256'],
                                                         item['manifest_sha256'], {}), {})
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        self.assertEqual(set(archive.namelist()), {'manifest.json', 'index.md'})
                        manifest = json.loads(archive.read('manifest.json'))
                        self.assertEqual(manifest['sources'], [])
                    self.restore_refused(raw + b'TRAILING', manifest_sha=item['manifest_sha256'])

    def observe_rsync(self, records):
        original = self.product.run_rsync
        def record(*args, **kwargs):
            self.assertLess(len(records), 8, 'rsync observation process bound')
            before = tree_bytes(self.out / 'rsync-warm')
            result = original(*args, **kwargs)
            source, destination = map(Path, result['argv'][-2:])
            self.assertTrue(source.is_relative_to(self.out))
            self.assertTrue(destination.is_relative_to(self.out))
            records.append({'result': result, 'source': source.name,
                            'destination': destination.name, 'before_warm': before,
                            'after_destination': tree_bytes(destination)})
            return result
        return record

    def expected_rsync_tree(self, candidate, kind, literal=None):
        item, raw = self.artifact(candidate, kind, self.out)
        arm = 'prior' if kind == 'setup' else 'current'
        values = recovered_for(self.oracle, arm) if literal is None else literal
        expected = {'files/' + name + '.bin': data for name, data in values.items()}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            manifest = archive.read('manifest.json')
            self.assertEqual(digest(manifest), item['manifest_sha256'])
            expected.update({'manifest.json': manifest, 'index.md': archive.read('index.md')})
        return expected

    def check_rsync_setup(self, report, records, prior):
        setup = [index for index, row in enumerate(records)
                 if row['source'] == 'rsync-setup-source']
        warm = [index for index, row in enumerate(records)
                if row['source'] == 'rsync-source' and row['destination'] == 'rsync-warm']
        self.assertEqual(len(setup), 1)
        self.assertEqual(len(warm), 1)
        self.assertLess(setup[0], warm[0])
        self.assertEqual(records[setup[0]]['before_warm'], {})
        self.assertEqual(records[setup[0]]['after_destination'], prior)
        self.assertEqual(records[warm[0]]['before_warm'], prior)
        setup_result = report['rsync']['setup']
        self.assertEqual(setup_result['argv'], records[setup[0]]['result']['argv'])
        self.assertEqual(setup_result['exit_code'], 0)
        self.assertEqual(setup_result['stats']['Matched data'], 0)
        self.assertEqual(setup_result['stats']['Literal data'], sum(map(len, prior.values())))
        for name in ('stdout', 'stderr'):
            data = read(self.out / ('rsync-setup.' + name))
            self.assertEqual(setup_result[name], {'bytes': len(data), 'sha256': digest(data)})

    def require_pinned_rsync(self):
        binary = Path('/usr/bin/rsync')
        if binary.is_symlink() or not binary.is_file() or digest(read(binary, 4194304)) != RSYNC_SHA256:
            self.skipTest('UNRUN: exact independently held local rsync binary unavailable')

    def test_actual_pinned_rsync_metadata_and_setup_before_warm(self):
        self.require_pinned_rsync()
        records = []
        with patch.object(self.product, 'run_rsync', side_effect=self.observe_rsync(records)):
            report = self.product.prepare(self.request_path, self.out,
                                          with_rsync=True, expected_rsync=RSYNC_SHA256)
        self.assertEqual(report['rsync']['setup_status'], 'TESTED_EMPTY_TO_PRIOR')
        self.assertEqual(report['rsync']['metadata'], 'EXACT_CURRENT_ZIP_MANIFEST_AND_CATALOG')
        candidate = report['candidates']['stored']
        prior = self.expected_rsync_tree(candidate, 'setup')
        current = self.expected_rsync_tree(candidate, 'cold')
        self.assertEqual(tree_bytes(self.out / 'rsync-setup-source'), prior)
        self.assertEqual(tree_bytes(self.out / 'rsync-source'), current)
        self.assertEqual(tree_bytes(self.out / 'rsync-warm'), current)
        self.check_rsync_setup(report, records, prior)

    def test_actual_pinned_rsync_partial_block_reuse(self):
        self.require_pinned_rsync()
        prior = bytes(range(256)) * 1024
        middle = len(prior) // 2
        current = prior[:middle] + bytes([prior[middle] ^ 1]) + prior[middle + 1:]
        self.assertEqual(len(current), len(prior))
        self.assertLessEqual(len(current), CAP)
        self.assertEqual(sum(left != right for left, right in zip(prior, current)), 1)
        request = {'schema': INPUT_SCHEMA,
            'prior': [row(self.root, 'prior', 'BLOCK', 'r1', prior)],
            'current': [row(self.root, 'current', 'BLOCK', 'r2', current)]}
        write(self.request_path, canonical(request))
        records = []
        with patch.object(self.product, 'run_rsync', side_effect=self.observe_rsync(records)):
            report = self.product.prepare(self.request_path, self.out,
                                          with_rsync=True, expected_rsync=RSYNC_SHA256)
        self.assertEqual(report['rsync']['setup_status'], 'TESTED_EMPTY_TO_PRIOR')
        candidate = report['candidates']['stored']
        prior_tree = self.expected_rsync_tree(candidate, 'setup', {'BLOCK': prior})
        current_tree = self.expected_rsync_tree(candidate, 'cold', {'BLOCK': current})
        self.check_rsync_setup(report, records, prior_tree)
        self.assertEqual(tree_bytes(self.out / 'rsync-warm'), current_tree)
        warm = [entry for entry in records if entry['source'] == 'rsync-source'
                and entry['destination'] == 'rsync-warm']
        self.assertEqual(len(warm), 1)
        self.assertGreater(warm[0]['result']['stats']['Matched data'], 0)
        for kind in ('cold', 'warm'):
            item, raw = self.artifact(candidate, kind, self.out)
            cache = {digest(prior): prior} if kind == 'warm' else {}
            self.assertEqual(self.product.restore(raw, item['sha256'],
                item['manifest_sha256'], cache), {'BLOCK': current})


if __name__ == '__main__':
    unittest.main(verbosity=2)
