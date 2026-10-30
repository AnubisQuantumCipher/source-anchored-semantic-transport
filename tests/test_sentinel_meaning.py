"""Developmental literal controls; no native, model, package or truth acceptance."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from sentinel_v1 import census, graph
from sentinel_v1.common import SentinelError, canonical, digest, identity


def binding(raw, derived=False):
    source = identity(b'original binary') if derived else identity(raw)
    source['package_id'] = digest(b'package fixture only')
    return {'source': source,
            'revision': {'id': 'R1', 'artifact_sha256': digest(b'revision fixture'),
                         'previous_sha256': None},
            'representation': {'kind': 'DERIVED_UTF8' if derived else 'ORIGINAL',
                               **identity(raw),
                               'record_sha256': digest(b'reading fixture') if derived else None}}


def root_of(registry):
    return digest(canonical({key: identity(raw) for key, raw in registry.items()}))


def fixture(raw=b'A--B', derived=False):
    source = {'id': 'S1', **binding(raw, derived),
              'window': {'start': 0, 'end': len(raw), 'sha256': digest(raw)}}
    evidence = {'source_id': 'S1', 'start': 0, 'end': 1, 'quote_sha256': digest(raw[:1])}
    node = {'id': 'C1', 'kind': 'PROPOSITION', 'origin': 'SOURCE_OCCURRENCE',
            'text': 'A proposed reading, not a truth verdict.', 'evidence': [evidence],
            'documentary_state': 'NEITHER', 'support_records': [], 'refutation_records': [],
            'assurance': dict(graph.ASSURANCE)}
    value = {'schema': graph.PROFILE, 'source_set': [source], 'nodes': [node],
             'edges': [], 'assurance': dict(graph.ASSURANCE)}
    return value, {digest(raw): raw}


class FindCounter:
    """Test-only direct-helper probe; public census accepts exact bytes only."""
    def __init__(self, raw):
        self.raw, self.calls = raw, {}

    def __len__(self):
        return len(self.raw)

    def find(self, needle, start=0):
        self.calls[needle] = self.calls.get(needle, 0) + 1
        return self.raw.find(needle, start)


class MeaningControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')).start()

    def census(self, raw, regions=None, dependencies=None, derived=False):
        return census.build_census(raw, canonical(binding(raw, derived)),
            None if regions is None else canonical(regions),
            None if dependencies is None else canonical(dependencies))

    def check(self, value, registry):
        raw = canonical(value)
        return graph.validate_graph(raw, registry, root_of(registry), digest(raw))

    def record(self, value, registry, polarity, note='declared test evidence only'):
        record = {'schema': 'sentinel/documentary-record/1', 'claim_id': 'C1',
                  'polarity': polarity, 'evidence': deepcopy(value['nodes'][0]['evidence']),
                  'note': note}
        raw = canonical(record)
        registry[digest(raw)] = raw
        field = 'support_records' if polarity == 'SUPPORT' else 'refutation_records'
        value['nodes'][0][field].append(digest(raw))
        return record

    def test_empty_census_and_exact_paragraph_partition(self):
        empty = self.census(b'')
        self.assertEqual((empty['paragraphs'], empty['shards']), ([], []))
        raw = 'Aé\n\nB\r\n\r\nC'.encode()
        result = self.census(raw)
        self.assertEqual([row['span'] for row in result['paragraphs']], [[0, 5], [5, 10], [10, 11]])
        rebuilt = b''.join(raw[row['span'][0]:row['span'][1]] for row in result['paragraphs'])
        self.assertEqual(rebuilt, raw)
        self.assertEqual(result['coverage']['reading'], 'ALL_BYTES_OPERATIONALLY_ACCOUNTED')
        self.assertEqual(result['semantic_completeness'], 'UNPROVEN')

    def test_exact_job_cap_and_opaque_long_paragraph(self):
        raw = b'x' * 65536
        result = self.census(raw)
        self.assertEqual(result['shards'][0]['identity'], identity(raw))
        self.assertEqual(result['shards'][0]['span'], [0, 65536])
        opaque = self.census(raw + b'x')
        self.assertEqual(opaque['paragraphs'][0]['status'], 'OPAQUE')
        self.assertEqual(opaque['shards'], [])
        self.assertEqual(opaque['unprocessed'], [{'span': [0, 65537], 'status': 'OPAQUE'}])

    def test_linear_cached_delimiters_preserve_literal_partition_and_bound(self):
        cases = ((b'A\n\nB\n\nC', [(0, 3), (3, 6), (6, 7)]),
                 (b'A\r\n\r\nB\r\n\r\nC', [(0, 5), (5, 10), (10, 11)]),
                 (b'A\r\n\r\n\nB\n\nC', [(0, 5), (5, 9), (9, 10)]),
                 (b'\n\n\r\n\r\nA', [(0, 2), (2, 6), (6, 7)]))
        for raw, expected in cases:
            self.assertEqual(census.paragraphs(raw), expected)
        probe = FindCounter(b'A\n\n' * 4095 + b'TAIL')
        spans = census.paragraphs(probe)
        self.assertEqual(len(spans), 4096)
        self.assertEqual(spans[-1][1], len(probe))
        self.assertEqual(probe.calls[b'\r\n\r\n'], 1)
        with self.assertRaises(SentinelError):
            census.paragraphs(b'A\n\n' * 4096 + b'TAIL')

    def test_hierarchy_context_and_independent_shard_receipts(self):
        raw = b'Rule.\n\nException.\n\nAppendix.'
        regions = [dict(id='DOC', parent=None, kind='DOCUMENT', start=0, end=len(raw)),
                   dict(id='RULE', parent='DOC', kind='CHAPTER', start=0, end=7),
                   dict(id='EXC', parent='DOC', kind='SECTION', start=7, end=19),
                   dict(id='APP', parent='DOC', kind='DIVISION', start=19, end=len(raw))]
        dependencies = [{'from': 'RULE', 'to': 'EXC'}, {'from': 'EXC', 'to': 'APP'}]
        result = self.census(raw, regions, dependencies)
        self.assertEqual(result['shards'][0]['dependency_regions'], ['APP', 'DOC', 'EXC'])
        self.assertEqual(len(result['shards']), 3)
        for row in result['shards']:
            body = {key: value for key, value in row.items() if key != 'receipt_sha256'}
            self.assertEqual(row['receipt_sha256'], digest(canonical(body)))
            self.assertEqual(row['identity'], identity(raw[slice(*row['span'])]))
            self.assertEqual(row['binding_sha256'], digest(canonical(binding(raw))))
        changed_binding = binding(raw); changed_binding['revision']['id'] = 'R2'
        changed = census.build_census(raw, canonical(changed_binding), canonical(regions),
                                       canonical(dependencies))
        self.assertNotEqual(result['shards'][0]['receipt_sha256'],
                            changed['shards'][0]['receipt_sha256'])

    def test_hierarchy_bad_boundaries_overlap_parent_and_types(self):
        raw = b'A\n\nB'
        base = [dict(id='DOC', parent=None, kind='DOCUMENT', start=0, end=4),
                dict(id='A', parent='DOC', kind='SECTION', start=0, end=3)]
        variants = []
        for key, value in (('start', True), ('end', 2), ('parent', 'MISSING'), ('kind', 'SENTENCE')):
            rows = deepcopy(base); rows[1][key] = value; variants.append(rows)
        variants.append(base + [dict(id='B', parent='DOC', kind='SECTION', start=0, end=3)])
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(SentinelError):
                self.census(raw, rows)

    def test_dependencies_cycle_missing_duplicate_and_self_refuse(self):
        raw = b'A\n\nB'
        rows = [dict(id='D', parent=None, kind='DOCUMENT', start=0, end=4),
                dict(id='A', parent='D', kind='SECTION', start=0, end=3),
                dict(id='B', parent='D', kind='SECTION', start=3, end=4)]
        for edges in ([{'from': 'A', 'to': 'B'}, {'from': 'B', 'to': 'A'}],
                      [{'from': 'A', 'to': 'X'}], [{'from': 'A', 'to': 'A'}],
                      [{'from': 'A', 'to': 'B'}] * 2):
            with self.subTest(edges=edges), self.assertRaises(SentinelError):
                self.census(raw, rows, edges)

    def test_census_inputs_and_density_refuse(self):
        for raw in (bytearray(b'A'), b'\xff', b'A\n\n' * 4097):
            with self.subTest(kind=type(raw)), self.assertRaises(SentinelError):
                census.build_census(raw, canonical(binding(bytes(raw))))
        bound = binding(b'A'); bound['representation']['sha256'] = digest(b'B')
        with self.assertRaises(SentinelError):
            census.build_census(b'A', canonical(bound))
        with self.assertRaises(SentinelError):
            census.build_census(b'A', canonical(binding(b'AB', True)))

    def test_derived_census_does_not_promote_extraction(self):
        result = self.census('é\n\nB'.encode(), derived=True)
        self.assertEqual(result['coverage']['source'], 'EXTRACTION_FIDELITY_UNPROVEN')
        self.assertEqual(result['coverage']['candidate_propositions'], 'UNPERFORMED')
        self.assertEqual(result['coverage']['semantic_tests'], 'UNPERFORMED')
        self.assertEqual(result['potential_claims'], [])
        self.assertEqual(result['execution_authority'], 'NONE')
        bound = binding(b'A', True); bound['representation']['bytes'] = 33554433
        with self.assertRaises(SentinelError):
            census.binding_checked(bound)

    def test_graph_exact_source_window_and_hashes(self):
        value, registry = fixture()
        result = self.check(value, registry)
        self.assertEqual(result['graph_sha256'], digest(canonical(value)))
        self.assertEqual(result['source_set_sha256'], digest(canonical(value['source_set'])))
        self.assertEqual(result['source_binding'], 'SUPPLIED_WINDOW_BYTES_ONLY')
        self.assertEqual(result['assurance']['package_binding'], 'UNPROVEN')
        self.assertEqual(result['nodes'][0]['assurance']['qualification'], 'NOT_QUALIFIED')

    def test_node_kinds_origins_and_documentary_neither_are_distinct(self):
        for kind in graph.KINDS:
            for origin in graph.ORIGINS:
                value, registry = fixture()
                value['nodes'][0].update(kind=kind, origin=origin)
                result = self.check(value, registry)
                self.assertEqual(result['nodes'][0]['origin'], origin)
                self.assertEqual(result['nodes'][0]['documentary_state'], 'NEITHER')
                self.assertEqual(result['assurance']['world_truth'], 'UNPROVEN')

    def test_four_documentary_states_require_pinned_records(self):
        for support, refutation, expected in ((False, False, 'NEITHER'), (True, False, 'SUPPORTED'),
                                              (False, True, 'REFUTED'), (True, True, 'BOTH')):
            value, registry = fixture()
            if support: self.record(value, registry, 'SUPPORT')
            if refutation: self.record(value, registry, 'REFUTATION')
            value['nodes'][0]['documentary_state'] = expected
            result = self.check(value, registry)
            self.assertEqual(result['nodes'][0]['documentary_state'], expected)
            self.assertEqual(result['documentary_records'], 'DECLARED_UNADJUDICATED')
        value, registry = fixture(); value['nodes'][0]['documentary_state'] = 'SUPPORTED'
        with self.assertRaisesRegex(SentinelError, 'lacks declared records'):
            self.check(value, registry)

    def test_documentary_record_tamper_target_polarity_and_quote(self):
        for key, replacement in (('claim_id', 'OTHER'), ('polarity', 'REFUTATION'),
                                  ('schema', 'authority/1')):
            value, registry = fixture(); record = self.record(value, registry, 'SUPPORT')
            old = value['nodes'][0]['support_records'].pop(); del registry[old]
            record[key] = replacement; raw = canonical(record)
            registry[digest(raw)] = raw; value['nodes'][0]['support_records'] = [digest(raw)]
            value['nodes'][0]['documentary_state'] = 'SUPPORTED'
            with self.subTest(key=key), self.assertRaises(SentinelError):
                self.check(value, registry)
        value, registry = fixture(); self.record(value, registry, 'SUPPORT')
        value['nodes'][0]['support_records'] *= 2
        with self.assertRaises(SentinelError): self.check(value, registry)

    def test_quote_tamper_and_exact_integer_boundaries_refuse(self):
        for key, replacement in (('quote_sha256', digest(b'B')), ('start', True), ('end', False),
                                  ('end', 0), ('end', 5), ('source_id', 'OTHER')):
            value, registry = fixture(); value['nodes'][0]['evidence'][0][key] = replacement
            with self.subTest(key=key, value=replacement), self.assertRaises(SentinelError):
                self.check(value, registry)

    def test_windows_bind_full_and_partial_source_coordinates(self):
        value, registry = fixture()
        source = value['source_set'][0]
        source['source'].update(sha256=digest(b'X-A--B-Y'), bytes=8)
        source['representation'].update(sha256=digest(b'X-A--B-Y'), bytes=8)
        source['window'].update(start=2, end=6)
        value['nodes'][0]['evidence'][0].update(start=2, end=3)
        result = self.check(value, registry)
        self.assertEqual(result['source_set'][0]['source']['sha256'], digest(b'X-A--B-Y'))
        self.assertEqual(result['assurance']['package_binding'], 'UNPROVEN')
        source['window']['end'] = 7
        with self.assertRaises(SentinelError): self.check(value, registry)

    def test_derived_window_and_quote_require_utf8(self):
        value, registry = fixture('éB'.encode(), True)
        value['nodes'][0]['evidence'][0].update(end=2, quote_sha256=digest('é'.encode()))
        self.check(value, registry)
        value['nodes'][0]['evidence'][0].update(start=1, quote_sha256=digest(b'\xa9'))
        with self.assertRaises(SentinelError): self.check(value, registry)
        value, registry = fixture(b'\xff', True)
        with self.assertRaises(SentinelError): self.check(value, registry)

    def test_source_revision_graph_and_registry_held_identity_refuse(self):
        value, registry = fixture(); raw = canonical(value)
        with self.assertRaises(SentinelError):
            graph.validate_graph(raw, registry, root_of(registry), digest(b'wrong graph'))
        with self.assertRaises(SentinelError):
            graph.validate_graph(raw, registry, digest(b'wrong registry'), digest(raw))
        changed = deepcopy(value); changed['source_set'][0]['revision']['id'] = 'R2'
        self.assertNotEqual(digest(canonical(changed['source_set'])), digest(canonical(value['source_set'])))
        with self.assertRaises(SentinelError):
            graph.validate_graph(canonical(changed), registry, root_of(registry), digest(raw))

    def test_registry_missing_unused_mutable_wrong_key_refuse(self):
        value, registry = fixture()
        variants = [{}, {**registry, digest(b'extra'): b'extra'},
                    {digest(b'A--B'): bytearray(b'A--B')}, {digest(b'wrong'): b'A--B'}]
        raw = canonical(value)
        for variant in variants:
            with self.subTest(variant=list(variant)), self.assertRaises(SentinelError):
                graph.validate_graph(raw, variant, root_of(registry), digest(raw))

    def test_caller_mutation_after_snapshot_cannot_change_graph_bytes(self):
        value, registry = fixture(); held = root_of(registry)
        original = graph.source_set_checked
        def interleave(rows, snapshot):
            registry[digest(b'A--B')] = b'BAD!'
            registry[digest(b'HIDDEN')] = b'HIDDEN'
            return original(rows, snapshot)
        raw = canonical(value)
        with patch.object(graph, 'source_set_checked', interleave):
            result = graph.validate_graph(raw, registry, held, digest(raw))
        self.assertEqual(result['nodes'][0]['evidence'][0]['quote_sha256'], digest(b'A'))
        self.assertEqual(result['source_binding'], 'SUPPLIED_WINDOW_BYTES_ONLY')

    def test_duplicate_nodes_edges_and_promoted_assurance_refuse(self):
        value, registry = fixture()
        duplicate = deepcopy(value); duplicate['nodes'] *= 2
        promoted = deepcopy(value); promoted['nodes'][0]['assurance']['world_truth'] = 'PROVED'
        promoted_graph = deepcopy(value); promoted_graph['assurance']['qualification'] = 'QUALIFIED'
        self_edge = deepcopy(value); self_edge['edges'] = [{'from': 'C1', 'to': 'C1', 'kind': 'SUPPORTS'}]
        for variant in (duplicate, promoted, promoted_graph, self_edge):
            with self.assertRaises(SentinelError): self.check(variant, registry)

    def test_node_claim_source_edge_and_evidence_count_limits(self):
        value, registry = fixture(); node = value['nodes'][0]
        for count, kind in ((257, 'ENTITY'), (65, 'PROPOSITION')):
            variant = deepcopy(value)
            variant['nodes'] = [{**deepcopy(node), 'id': 'N%d' % n, 'kind': kind} for n in range(count)]
            with self.subTest(count=count), self.assertRaises(SentinelError): self.check(variant, registry)
        variant = deepcopy(value); variant['edges'] = [{}] * 513
        with self.assertRaises(SentinelError): self.check(variant, registry)
        variant = deepcopy(value); variant['source_set'] *= 65
        with self.assertRaises(SentinelError): self.check(variant, registry)
        variant = deepcopy(value); variant['nodes'][0]['evidence'] *= 17
        with self.assertRaises(SentinelError): self.check(variant, registry)

    def test_dependency_revision_time_cycles_refuse_contradictions_remain(self):
        value, registry = fixture()
        second = deepcopy(value['nodes'][0]); second['id'] = 'C2'; value['nodes'].append(second)
        for kind in ('DEPENDS_ON', 'REVISES', 'TEMPORALLY_BEFORE', 'CONTRADICTS'):
            node_kind = 'REVISION' if kind == 'REVISES' else (
                'EVENT' if kind == 'TEMPORALLY_BEFORE' else 'PROPOSITION')
            for node in value['nodes']:
                node['kind'] = node_kind
            value['edges'] = [{'from': 'C1', 'to': 'C2', 'kind': kind},
                              {'from': 'C2', 'to': 'C1', 'kind': kind}]
            if kind == 'CONTRADICTS':
                self.assertEqual(self.check(value, registry)['assurance']['world_truth'], 'UNPROVEN')
            else:
                with self.subTest(kind=kind), self.assertRaises(SentinelError): self.check(value, registry)
        value['edges'] = [{'from': 'C1', 'to': 'C2', 'kind': 'SUPPORTS'}] * 2
        with self.assertRaises(SentinelError): self.check(value, registry)

    def test_every_relation_checks_declared_endpoint_sorts(self):
        self.assertEqual(set(graph.EDGE_TYPES), set(graph.RELATIONS))
        for relation, (sources, targets) in graph.EDGE_TYPES.items():
            for source, target in ((sources[0], targets[0]), ('OPAQUE', 'OPAQUE')):
                value, registry = fixture()
                value['nodes'][0]['kind'] = source
                second = deepcopy(value['nodes'][0]); second.update(id='C2', kind=target)
                value['nodes'].append(second)
                value['edges'] = [{'from': 'C1', 'to': 'C2', 'kind': relation}]
                if source in sources and target in targets:
                    self.check(value, registry)
                else:
                    with self.subTest(relation=relation), self.assertRaises(SentinelError):
                        self.check(value, registry)

    def test_closed_canonical_metadata_and_proposal_text_bound(self):
        value, registry = fixture(); raw = canonical(value)
        with self.assertRaises(SentinelError):
            graph.validate_graph(raw + b' ', registry, root_of(registry), digest(raw + b' '))
        for field, replacement in (('text', 'é' * 2049), ('kind', 'AUTHORITY'),
                                    ('origin', 'WORLD_TRUTH')):
            changed = deepcopy(value); changed['nodes'][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(SentinelError): self.check(changed, registry)
        value['extra'] = 'unknown'
        with self.assertRaises(SentinelError): self.check(value, registry)

    def test_formal_fragment_uses_unchanged_existing_codec(self):
        source = b'Claim. Unrepresented residual text.'
        plan = {'schema': 'transport/encoding-plan/1', 'symbols': {'S0': 'Claim'},
                'meaning': {'schema': 'transport/meaning/1', 'nodes': [
                    {'op': 'text', 'symbol': 'S0', 'span': [0, 5]},
                    {'op': 'pred', 'args': [0], 'cue': [0, 0]}], 'root': 1, 'ambiguities': []}}
        result = graph.checked_formal_fragment(source, canonical(plan))
        self.assertEqual(result['payload']['meaning']['schema'], 'transport/meaning/1')
        self.assertEqual(result['source_identity'], identity(source))
        self.assertEqual(result['assurance']['world_truth'], 'UNPROVEN')
        self.assertEqual(result['adapter'], 'EXISTING_TYPED_CODEC_NO_COMPACTION')
        plan['symbols']['S0'] = 'Absent'
        with self.assertRaises(ValueError): graph.checked_formal_fragment(source, canonical(plan))

    def test_formal_adapter_bounds_whole_return_before_publication(self):
        import transport_semantics
        with patch.object(transport_semantics, 'dictionary_pair', return_value=('G', [], {})), \
             patch.object(transport_semantics, 'checked_payload', return_value={'x': 'a' * 65500}):
            with self.assertRaisesRegex(SentinelError, 'formal result byte bound'):
                graph.checked_formal_fragment(b'A', canonical({'meaning': {}}))


if __name__ == '__main__':
    unittest.main()
