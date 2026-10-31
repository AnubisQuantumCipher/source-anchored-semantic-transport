"""Additive public development controls requiring working SQLite FTS5.

Every positive case requires OK with fixed source-linked matches. There are no
skips, optional-backend branches, alternate lanes, or acceptance of refusal for
positive expectations. The original 58 tests remain byte-identical.

References used before execution:
https://sqlite.org/fts5.html#unicode61_tokenizer
https://sqlite.org/fts5.html#the_bm25_function
https://www.unicode.org/Public/6.1.0/ucd/CaseFolding.txt
U+023A has common simple fold U+2C65 in the Unicode 6.1 data. The large fixture
exercises UTF-8 byte growth under that fold without claiming semantic equality.
The conservative raw non-whitespace-run guard is 8192 bytes, declared by the
parent before this additive test source was frozen.
"""

from __future__ import annotations

import base64
import unittest

import test_retrieval as base


class RequiredFtsCapabilityTests(base.ResponseCase):
    def hard_search(self, corpus, query, sources=None, field='source'):
        result = self.ok(corpus, base.search_request(
            query=query, sources=sources, mode='fts5', field=field,
            limit=16, offset=0))
        self.assertEqual(result['ranking'], 'SQLITE_FTS5_BM25')
        return result

    def test_positive_token_and_requires_every_token(self):
        records = [('S_A', ['U_A'], b'red blue copper', 'capability'),
                   ('S_B', ['U_B'], b'red copper', 'capability'),
                   ('S_C', ['U_C'], b'blue copper', 'capability'),
                   ('S_D', ['U_D'], b'red OR blue', 'capability')]
        corpus = self.new(*base.small_declared_corpus(records))
        result = self.hard_search(corpus, 'red blue', ['S_A', 'S_B', 'S_C', 'S_D'])
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual({u['id'] for u in result['unit_matches']}, {'U_A', 'U_D'})
        self.assertEqual(result['total_unit_matches'], 2)
        self.assertEqual(result['whole_source_matches'],
                         [base.source_hit('S_A'), base.source_hit('S_D')])

    def test_supplied_or_is_quoted_as_a_required_token(self):
        records = [('S_A', ['U_A'], b'red blue copper', 'capability'),
                   ('S_B', ['U_B'], b'red copper', 'capability'),
                   ('S_C', ['U_C'], b'blue copper', 'capability'),
                   ('S_D', ['U_D'], b'red OR blue', 'capability')]
        corpus = self.new(*base.small_declared_corpus(records))
        result = self.hard_search(corpus, 'red OR blue', ['S_A', 'S_B', 'S_C', 'S_D'])
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_D'])
        self.assertEqual(result['whole_source_matches'], [base.source_hit('S_D')])

    def test_bm25_frequency_ranking_precedes_identity_order(self):
        records = [('S_A', ['U_A'], b'needle other other', 'capability'),
                   ('S_Z', ['U_Z'], b'needle needle needle', 'capability')]
        corpus = self.new(*base.small_declared_corpus(records))
        result = self.hard_search(corpus, 'needle', ['S_A', 'S_Z'])
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_Z', 'U_A'])
        self.assertEqual(result['total_unit_matches'], 2)

    def test_equal_score_tie_orders_source_then_unit(self):
        records = [('S_A', ['U_Z'], b'shared identical token', 'capability'),
                   ('S_B', ['U_A'], b'shared identical token', 'capability')]
        corpus = self.new(*base.small_declared_corpus(records))
        result = self.hard_search(corpus, 'shared', ['S_A', 'S_B'])
        self.assertEqual([(u['source'], u['id']) for u in result['unit_matches']],
                         [('S_A', 'U_Z'), ('S_B', 'U_A')])

    def test_unicode_casefold_preserves_diacritics_and_original_bytes(self):
        records = [('S_ACCENT', ['U_ACCENT'], 'CAFÉ'.encode('utf-8'), 'capability'),
                   ('S_ASCII', ['U_ASCII'], b'CAFE', 'capability')]
        corpus = self.new(*base.small_declared_corpus(records))
        scope = ['S_ACCENT', 'S_ASCII']
        accent = self.hard_search(corpus, 'café', scope)
        plain = self.hard_search(corpus, 'cafe', scope)
        self.assertEqual([u['id'] for u in accent['unit_matches']], ['U_ACCENT'])
        self.assertEqual([u['id'] for u in plain['unit_matches']], ['U_ASCII'])
        result = self.ok(corpus, base.search_request(
            'query', query='café', sources=scope, mode='fts5'))
        self.complete(corpus, result, ['U_ACCENT'], ['U_ACCENT'], scope,
                      [base.source_hit('S_ACCENT')])
        self.assertEqual(base64.b64decode(result['units'][0]['bytes_base64'],
                                         validate=True), 'CAFÉ'.encode('utf-8'))

    def test_unicode_simple_fold_can_increase_utf8_bytes(self):
        corpus = self.new(*base.synthetic('\u023a'))
        result = self.hard_search(corpus, '\u2c65')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_SYNTH'])
        literal = self.ok(corpus, base.search_request('query', query='\u2c65'))
        self.assertEqual(literal['outcome'], 'UNKNOWN_NO_MATCH')

    def test_annotation_fts_origin_is_explicit(self):
        corpus = self.new(*base.synthetic('nebula', {'tag': 'glimmer'}))
        result = self.hard_search(corpus, 'glimmer', field='annotation')
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_SYNTH'])
        self.assertEqual(result['unit_matches'][0]['origins'], ['annotation'])
        self.assertEqual(result['whole_source_matches'], [])

    def test_duplicate_query_tokens_accept_32_occurrences(self):
        corpus = self.new(*base.synthetic('a'))
        result = self.hard_search(corpus, ' '.join(['a'] * 32))
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_SYNTH'])

    def test_duplicate_query_tokens_refuse_33_occurrences(self):
        corpus = self.new(*base.synthetic('a'))
        self.refused(corpus, base.search_request(
            'query', query=' '.join(['a'] * 33), mode='fts5'),
            'REFUSED_FTS_TOKEN_BOUND')

    def test_ascii_raw_run_at_8192_bytes_is_accepted(self):
        run = b'x' * 8192
        self.assertEqual(len(run), 8192)
        corpus = self.new(*base.synthetic(run + b' marker'))
        result = self.hard_search(corpus, 'marker')
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_SYNTH'])

    def test_ascii_raw_run_above_guard_refuses_fts_retains_literal(self):
        run = b'x' * 8193
        self.assertEqual(len(run), 8193)
        corpus = self.new(*base.synthetic(run + b' marker'))
        self.refused(corpus, base.search_request('query', query='marker', mode='fts5'),
                     'REFUSED_FTS_TOKEN_BOUND')
        literal = self.ok(corpus, base.search_request('query', query='marker'))
        self.assertEqual(literal['root_units'], ['U_SYNTH'])
        self.assertEqual(base64.b64decode(literal['units'][0]['bytes_base64'],
                                         validate=True), run + b' marker')

    def test_fold_inflation_run_at_raw_guard_is_accepted(self):
        run = ('\u023a' * 4096).encode('utf-8')
        self.assertEqual(len(run), 8192)
        corpus = self.new(*base.synthetic(run + b' marker'))
        result = self.hard_search(corpus, 'marker')
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_SYNTH'])
        page = self.ok(corpus, base.request('page', source='S_SYNTH', offset=0))
        self.assertEqual(base64.b64decode(page['bytes_base64'], validate=True),
                         run[:4096])

    def test_fold_inflation_above_guard_refuses_fts_retains_literal(self):
        run = ('\u023a' * 4096).encode('utf-8') + b'x'
        self.assertEqual(len(run), 8193)
        corpus = self.new(*base.synthetic(run + b' marker'))
        self.refused(corpus, base.search_request('query', query='marker', mode='fts5'),
                     'REFUSED_FTS_TOKEN_BOUND')
        literal = self.ok(corpus, base.search_request('query', query='marker'))
        self.assertEqual(literal['root_units'], ['U_SYNTH'])
        self.assertEqual(base64.b64decode(literal['units'][0]['bytes_base64'],
                                         validate=True), run + b' marker')


if __name__ == '__main__':
    unittest.main(verbosity=2)
