#!/usr/bin/env python3
"""Portable registry gate plus explicitly requested pinned-native qualification.

CI runs every portable test without a local artifact or skipped gate. Supplying
--native-payload and its held SHA adds the actual-payload archive qualification;
it never replaces portable results or claims acceptance by a derived runtime.
No native or candidate code executes in either lane.
"""

import argparse
import copy
import hashlib
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_plan as plans
import transport_package as packages
from transport_archive import read_archive
from transport_meaning import check_meaning
from transport_semantics import dictionary_pair
from transport_schema import operator_dictionary

NATIVE_PAYLOAD = None
NATIVE_PAYLOAD_SHA256 = None


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def unique(pairs):
    if len(pairs) > 256 or len(dict(pairs)) != len(pairs):
        raise ValueError('duplicate or excessive fields')
    return dict(pairs)


class RegistryBlocks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.current, self.blocks = None, {'dictionary': {}, 'unit': {}}
        self.table = None

    def handle_starttag(self, tag, attrs):
        if self.table is not None:
            self.symbol_start(tag, attrs)
            return
        if tag == 'table' and any(key == 'data-transport-symbol-dictionary' for key, _ in attrs):
            self.begin_symbols(attrs)
            return
        if tag != 'pre':
            return
        selected = [(key, value) for key, value in attrs if key.startswith('data-transport-')]
        if not selected:
            return
        if self.current is not None or len(selected) != 1 or len(attrs) != 1:
            raise ValueError('nested or ambiguous marked block')
        key, value = selected[0]
        kinds = {'data-transport-dictionary-sha256': 'dictionary', 'data-transport-unit': 'unit'}
        if key not in kinds or type(value) is not str:
            raise ValueError('unknown readable block')
        self.current = [kinds[key], value, []]

    def handle_data(self, data):
        if self.table is not None:
            self.symbol_data(data)
            return
        if self.current is not None:
            self.current[2].append(data)
            if sum(len(part.encode('utf-8')) for part in self.current[2]) > 65536:
                raise ValueError('marked block byte bound')

    def handle_endtag(self, tag):
        if self.table is not None:
            self.symbol_end(tag)
            return
        if tag != 'pre' or self.current is None:
            return
        kind, key, parts = self.current
        bucket = self.blocks[kind]
        if key in bucket or len(bucket) >= (32 if kind == 'dictionary' else 16):
            raise ValueError('duplicate or excessive marked records')
        bucket[key] = ''.join(parts).encode('utf-8')
        self.current = None

    def begin_symbols(self, attrs):
        expected = {'data-transport-symbol-dictionary', 'data-dictionary-schema',
                    'data-dictionary-id', 'data-dictionary-version'}
        values = dict(attrs)
        if self.current is not None or len(values) != len(attrs) or set(values) != expected or not all(type(value) is str for value in values.values()):
            raise ValueError('unknown symbol table metadata shape')
        if values['data-dictionary-schema'] != 'transport/dictionary/1' or values['data-dictionary-version'] != '1':
            raise ValueError('unknown symbol table schema or version')
        if re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,47}', values['data-dictionary-id']) is None:
            raise ValueError('invalid symbol dictionary id')
        if re.fullmatch('[0-9a-f]{64}', values['data-transport-symbol-dictionary']) is None:
            raise ValueError('invalid symbol dictionary digest')
        self.table = dict(metadata=values, state='header-row', entries={}, chunks=[])

    def symbol_start(self, tag, attrs):
        transitions = {'header-row': ('tr', 'header-first-open'),
            'header-first-open': ('th', 'header-first-text'), 'header-second-open': ('th', 'header-second-text'),
            'row-or-end': ('tr', 'symbol-open'), 'symbol-open': ('td', 'symbol-text'),
            'literal-open': ('td', 'pre-open'), 'pre-open': ('pre', 'literal-text')}
        state = self.table['state']
        if attrs or state not in transitions or transitions[state][0] != tag:
            raise ValueError('unknown symbol table element shape')
        self.table['state'] = transitions[state][1]
        self.table['chunks'] = []

    def symbol_data(self, data):
        if self.table['state'] in ('header-first-text', 'header-second-text', 'symbol-text', 'literal-text'):
            self.table['chunks'].append(data)
            if sum(len(chunk.encode('utf-8')) for chunk in self.table['chunks']) > 65536:
                raise ValueError('symbol cell byte bound')
        elif data.strip():
            raise ValueError('unexpected symbol table text')

    def symbol_end(self, tag):
        state = self.table['state']
        text = ''.join(self.table['chunks'])
        if state in ('header-first-text', 'header-second-text') and tag == 'th':
            expected = 'Symbol' if state == 'header-first-text' else 'Exact source literal (canonical JSON string)'
            if text != expected:
                raise ValueError('unknown symbol table heading')
            self.table['state'] = 'header-second-open' if state == 'header-first-text' else 'header-row-end'
        elif state == 'header-row-end' and tag == 'tr':
            self.table['state'] = 'row-or-end'
        elif state == 'symbol-text' and tag == 'td':
            if re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,47}', text) is None:
                raise ValueError('invalid symbol row name')
            self.table.update(symbol=text, state='literal-open')
        elif state == 'literal-text' and tag == 'pre':
            value = json.loads(text)
            if type(value) is not str or encoded(value) != text.encode('utf-8') or not 1 <= len(value.encode('utf-8')) <= 4096:
                raise ValueError('noncanonical or oversized symbol literal')
            self.table.update(literal=value, state='literal-cell-end')
        elif state == 'literal-cell-end' and tag == 'td':
            self.table['state'] = 'row-end'
        elif state == 'row-end' and tag == 'tr':
            entries, symbol = self.table['entries'], self.table['symbol']
            if symbol in entries or len(entries) >= 64:
                raise ValueError('duplicate or excessive symbol rows')
            entries[symbol] = self.table['literal']
            self.table['state'] = 'row-or-end'
        elif state == 'row-or-end' and tag == 'table':
            self.finish_symbols()
        else:
            raise ValueError('unknown or truncated symbol table structure')
        if self.table is not None:
            self.table['chunks'] = []

    def finish_symbols(self):
        metadata, entries = self.table['metadata'], self.table['entries']
        digest = metadata['data-transport-symbol-dictionary']
        if not entries or digest in self.blocks['dictionary'] or len(self.blocks['dictionary']) >= 32:
            raise ValueError('empty, duplicate or excessive symbol dictionary')
        value = dict(schema=metadata['data-dictionary-schema'], id=metadata['data-dictionary-id'],
                     version=metadata['data-dictionary-version'], role='symbols', entries=entries)
        self.blocks['dictionary'][digest] = encoded(value)
        self.table = None

    def handle_comment(self, data):
        if self.table is not None:
            raise ValueError('comments are not symbol table structure')


def recover(rendered):
    if type(rendered) is not bytes or len(rendered) > 131072:
        raise ValueError('readable input bound')
    parser = RegistryBlocks()
    parser.feed(rendered.decode('utf-8'))
    parser.close()
    if parser.current is not None or parser.table is not None:
        raise ValueError('unfinished marked block')
    dictionaries, restored, used = {}, {}, set()
    for digest, raw in parser.blocks['dictionary'].items():
        value = json.loads(raw, object_pairs_hook=unique)
        if re.fullmatch('[0-9a-f]{64}', digest) is None or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('dictionary digest differs')
        if encoded(value) != raw or set(value) != {'schema', 'id', 'version', 'role', 'entries'}:
            raise ValueError('dictionary canonical form or fields differ')
        dictionaries[digest] = value
    for name, raw in parser.blocks['unit'].items():
        value = json.loads(raw, object_pairs_hook=unique)
        if encoded(value) != raw or value['id'] != name:
            raise ValueError('unit canonical form or identity differs')
        references = value['dictionaries']
        if type(references) is not list or len(references) != 2:
            raise ValueError('unit dictionary count')
        roles = []
        for reference in references:
            digest = reference['sha256']
            if set(reference) != {'id', 'version', 'role', 'sha256', 'content'} or reference['content'] is not None:
                raise ValueError('reference fields or embedded content differs')
            if digest not in dictionaries:
                raise ValueError('missing dictionary')
            content = dictionaries[digest]
            expected = {key: content[key] for key in ('id', 'version', 'role')}
            if reference != dict(expected, sha256=digest, content=None):
                raise ValueError('reference identity differs')
            roles.append(content['role'])
            reference['content'] = copy.deepcopy(content)
            used.add(digest)
        if sorted(roles) != ['operators', 'symbols']:
            raise ValueError('dictionary roles differ')
        restored[name] = encoded(value)
    if not restored or used != set(dictionaries):
        raise ValueError('unused registry or missing units')
    return restored, parser.blocks


def marked(kind, name, raw):
    attribute = 'data-transport-dictionary-sha256' if kind == 'dictionary' else 'data-transport-unit'
    return ('<pre ' + attribute + '="' + name + '">'
            + html.escape(raw.decode('utf-8'), quote=False) + '</pre>').encode('utf-8')


def stored_plan():
    base = ROOT / 'examples/heldout-release-v1'
    source = json.loads((base / 'fixture.json').read_bytes())
    plan = json.loads((base / 'plan.json').read_bytes())
    data = {item['id']: item['text'].encode('utf-8') for item in source['sources']}
    units = []
    if len(plan['meaning_units']) != 13 or len(data) != 6:
        raise ValueError('held-out fixture shape changed')
    for unit in plan['meaning_units']:
        grammar, dictionaries, symbols = dictionary_pair(unit['plan'])
        meaning = unit['plan']['meaning']
        check_meaning(meaning, data[unit['source']], symbols['entries'])
        units.append({key: value for key, value in unit.items() if key != 'plan'} |
                     dict(grammar=grammar, dictionaries=dictionaries, meaning=meaning))
    return plan | {'meaning_units': units}


def symbol_table(rendered):
    found = re.search(rb'<table data-transport-symbol-dictionary="([0-9a-f]{64})"[^>]*>.*?</table>',
                      rendered, re.DOTALL)
    if found is None:
        raise ValueError('missing test symbol table')
    return found.group(1).decode('ascii'), found.group(0)


def native_payload():
    if NATIVE_PAYLOAD is None or NATIVE_PAYLOAD_SHA256 is None:
        raise ValueError('native qualification requires an explicit payload path and pin')
    if NATIVE_PAYLOAD.stat().st_size > 131072:
        raise ValueError('native payload read bound')
    raw = NATIVE_PAYLOAD.read_bytes()
    if hashlib.sha256(raw).hexdigest() != NATIVE_PAYLOAD_SHA256:
        raise ValueError('native payload pin differs')
    value = json.loads(raw, object_pairs_hook=unique)
    if set(value) != {'frames', 'plan', 'runtime'}:
        raise ValueError('native payload fields differ')
    fixture = json.loads((ROOT / 'examples/heldout-release-v1/fixture.json').read_bytes())
    sources = tuple(item['text'].encode('utf-8') for item in fixture['sources'])
    if len(value['frames']) != len(sources) or len(value['plan']['meaning_units']) != 13:
        raise ValueError('native payload fixture shape differs')
    for frame, source, metadata in zip(value['frames'], sources, fixture['sources'], strict=True):
        if frame['id'] != metadata['id'] or frame['bytes'] != len(source) or frame['sha256'] != hashlib.sha256(source).hexdigest():
            raise ValueError('native payload source identity differs')
    return value, sources


class LexiconRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = stored_plan()
        cls.units = cls.plan['meaning_units']
        cls.rendered = '\n'.join(plans.semantic_lines(cls.units)).encode('utf-8')

    def test_every_complete_unit_and_reference_reconstructs_exact_canonical_bytes(self):
        restored, blocks = recover(self.rendered)
        self.assertEqual(set(restored), {unit['id'] for unit in self.units})
        for original in self.units:
            raw = restored[original['id']]
            self.assertEqual(raw, encoded(original))
            reconstructed = json.loads(raw)
            self.assertEqual(encoded(reconstructed['dictionaries']), encoded(original['dictionaries']))
            for reference in original['dictionaries']:
                self.assertEqual(blocks['dictionary'][reference['sha256']], encoded(reference['content']))

    def test_registry_and_human_tables_appear_once_per_exact_dictionary(self):
        _, blocks = recover(self.rendered)
        unique_dictionaries = {item['sha256']: item['content'] for unit in self.units for item in unit['dictionaries']}
        self.assertEqual(set(blocks['dictionary']), set(unique_dictionaries))
        roles = [value['role'] for value in unique_dictionaries.values()]
        self.assertEqual(self.rendered.count(b'data-transport-symbol-dictionary="'), roles.count('symbols'))
        self.assertEqual(self.rendered.count(b'| Operator | Argument types | Result | Exact definition |'), roles.count('operators'))
        self.assertEqual(self.rendered, '\n'.join(plans.semantic_lines(self.units)).encode('utf-8'))
        self.assertLessEqual(len(plans.lexicon(self.plan)), plans.MAX_METADATA)

    def test_missing_tampered_and_conflicting_registry_refuse_reconstruction(self):
        _, blocks = recover(self.rendered)
        digest, raw = next((key, raw) for key, raw in blocks['dictionary'].items() if json.loads(raw)['role'] == 'operators')
        block = marked('dictionary', digest, raw)
        self.assertIn(block, self.rendered)
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(block, b'', 1))
        value = json.loads(raw)
        value['id'] += '-tampered'
        altered = marked('dictionary', digest, encoded(value))
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(block, altered, 1))
        new_digest = hashlib.sha256(encoded(value)).hexdigest()
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(block, marked('dictionary', new_digest, encoded(value)), 1))
        with self.assertRaises(ValueError):
            recover(self.rendered + altered)

    def test_reference_tampering_refuses_even_with_valid_registry(self):
        _, blocks = recover(self.rendered)
        name, raw = next(iter(blocks['unit'].items()))
        original = marked('unit', name, raw)
        value = json.loads(raw)
        value['dictionaries'][0]['id'] += '-tampered'
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(original, marked('unit', name, encoded(value)), 1))
        value = json.loads(raw)
        value['dictionaries'][0]['content'] = {}
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(original, marked('unit', name, encoded(value)), 1))

    def test_renderer_refuses_bad_references_and_unit_count_without_mutating_input(self):
        before = encoded(self.units)
        for invalid in ([], self.units + self.units):
            with self.assertRaises(ValueError):
                plans.semantic_lines(invalid)
        altered = copy.deepcopy(self.units)
        altered[0]['dictionaries'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            plans.semantic_lines(altered)
        self.assertEqual(encoded(self.units), before)

    def test_html_literals_and_non_ascii_round_trip_without_markup_execution(self):
        units = copy.deepcopy(self.units[:1])
        literal = '<script>not code</script> & "quoted" \u2028 end'
        dictionary = next(item for item in units[0]['dictionaries'] if item['role'] == 'symbols')
        symbol = next(iter(dictionary['content']['entries']))
        dictionary['content']['entries'][symbol] = literal
        dictionary['sha256'] = hashlib.sha256(encoded(dictionary['content'])).hexdigest()
        rendered = '\n'.join(plans.semantic_lines(units)).encode('utf-8')
        restored, _ = recover(rendered)
        self.assertEqual(restored[units[0]['id']], encoded(units[0]))
        self.assertNotIn(b'<script>', rendered)
        self.assertIn(b'&lt;script&gt;', rendered)

    def test_symbol_table_missing_tampered_conflicting_and_rekeyed_content_refuse(self):
        digest, table = symbol_table(self.rendered)
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(table, b'', 1))
        literal = re.search(rb'<pre>(.*?)</pre>', table, re.DOTALL).group(1)
        value = json.loads(html.unescape(literal.decode('utf-8')))
        changed_literal = html.escape(encoded(value + ' altered').decode('utf-8'), quote=False).encode('utf-8')
        altered = table.replace(literal, changed_literal, 1)
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(table, altered, 1))
        with self.assertRaises(ValueError):
            recover(self.rendered + altered)
        parser = RegistryBlocks()
        parser.feed(altered.decode('utf-8'))
        parser.close()
        new_digest = hashlib.sha256(parser.blocks['dictionary'][digest]).hexdigest().encode('ascii')
        with self.assertRaises(ValueError):
            recover(self.rendered.replace(table, altered.replace(digest.encode('ascii'), new_digest, 1), 1))

    def test_symbol_table_duplicate_truncated_unknown_shapes_refuse(self):
        _, table = symbol_table(self.rendered)
        row = re.search(rb'<tr><td>.*?</tr>', table, re.DOTALL).group(0)
        cases = [table.replace(b'</table>', row + b'</table>', 1),
                 table.replace(b'</table>', b'', 1), table.replace(b'<pre>', b'<pre><span>', 1),
                 table.replace(b'<table ', b'<table unknown="x" ', 1),
                 table.replace(b'data-dictionary-version="1"', b'data-dictionary-version="999"', 1),
                 table.replace(b'</pre></td>', b'</pre>', 1)]
        for altered in cases:
            with self.subTest(length=len(altered)), self.assertRaises(ValueError):
                recover(self.rendered.replace(table, altered, 1))

    def test_symbol_table_exactly_64_rows_pass_and_65_rows_refuse(self):
        content = dict(schema='transport/dictionary/1', id='boundary-symbols', version='1', role='symbols',
                       entries={f'SYMBOL_{index:02d}': 'literal' for index in range(64)})
        digest = hashlib.sha256(encoded(content)).hexdigest()
        table = '\n'.join(plans.symbol_dictionary_lines(digest, content)).encode('utf-8')
        parser = RegistryBlocks()
        parser.feed(table.decode('utf-8'))
        parser.close()
        self.assertIsNone(parser.table)
        self.assertEqual(parser.blocks['dictionary'][digest], encoded(content))
        overflow = table.replace(b'</table>', b'<tr><td>OVERFLOW</td><td><pre>"literal"</pre></td></tr></table>')
        with self.assertRaisesRegex(ValueError, 'excessive'):
            RegistryBlocks().feed(overflow.decode('utf-8'))
        content['entries']['OVERFLOW'] = 'literal'
        with self.assertRaises(ValueError):
            plans.symbol_dictionary_lines(digest, content)

    def test_operator_versions_and_same_symbol_ids_retain_distinct_digests(self):
        units = copy.deepcopy(self.units[:2])
        units[1]['grammar'] = 'transport/meaning/2'
        units[1]['meaning']['schema'] = 'transport/meaning/2'
        operators = next(item for item in units[1]['dictionaries'] if item['role'] == 'operators')
        operators['content'] = operator_dictionary('2')
        operators['version'] = '2'
        operators['sha256'] = hashlib.sha256(encoded(operators['content'])).hexdigest()
        rendered = '\n'.join(plans.semantic_lines(units)).encode('utf-8')
        restored, blocks = recover(rendered)
        for unit in units:
            self.assertEqual(restored[unit['id']], encoded(unit))
        self.assertEqual(len(blocks['dictionary']), 4)
        symbols = [json.loads(raw) for raw in blocks['dictionary'].values() if json.loads(raw)['role'] == 'symbols']
        self.assertEqual(symbols[0]['id'], symbols[1]['id'])
        self.assertNotEqual(encoded(symbols[0]), encoded(symbols[1]))

    def qualify_pinned_actual_native_payload_reconstructs_and_fits_complete_archive(self):
        payload, sources = native_payload()
        plan, frames = payload['plan'], payload['frames']
        before = encoded(plan)
        entries = packages.content_entries(plan, sources, frames)
        expected_codec = encoded(dict(schema='transport/codec/2', plan=plan, source_frames=frames))
        self.assertEqual(entries['codec.json'], expected_codec)
        restored, _ = recover(entries['README.md'])
        for unit in plan['meaning_units']:
            self.assertEqual(restored[unit['id']], encoded(unit))
        _, archive = packages.seal(entries, payload['runtime'], 'attached:meaning.zip', 131072)
        recovered = read_archive(archive)
        self.assertEqual(recovered['codec.json'], expected_codec)
        self.assertLessEqual(sum(len(raw) for raw in recovered.values()), 131072)
        self.assertLessEqual(len(archive), 131072)
        self.assertEqual(encoded(plan), before)
        print(json.dumps(dict(measurement='PINNED_NATIVE_PAYLOAD_LAYOUT_ONLY_NOT_RUNTIME_ACCEPTANCE',
            entries={name: len(raw) for name, raw in recovered.items()},
            total_entry_bytes=sum(len(raw) for raw in recovered.values()), archive_bytes=len(archive)), sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--native-payload', type=Path)
    parser.add_argument('--expect-native-payload-sha256')
    args, remaining = parser.parse_known_args()
    if (args.native_payload is None) != (args.expect_native_payload_sha256 is None):
        raise ValueError('native payload path and independent pin must be supplied together')
    NATIVE_PAYLOAD, NATIVE_PAYLOAD_SHA256 = args.native_payload, args.expect_native_payload_sha256
    if NATIVE_PAYLOAD is not None:
        LexiconRegistryTests.test_pinned_actual_native_payload_reconstructs_and_fits_complete_archive = (
            LexiconRegistryTests.qualify_pinned_actual_native_payload_reconstructs_and_fits_complete_archive)
    unittest.main(argv=[sys.argv[0], *remaining])
