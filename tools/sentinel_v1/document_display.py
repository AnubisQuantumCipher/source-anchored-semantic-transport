"""Source-anchored display artifacts and prospective shares; never a decoder/truth gate."""
import html
import re
from urllib.parse import urlsplit
import transport_document as transport
from transport_schema import operator_dictionary
from . import document_analysis, census, graph
from .common import (METADATA, canonical, digest, fields, hash_checked, held_record, identity,
                     integer, label, registry_snapshot, require)

PROFILE = 'sentinel/document-display/1'
TITLES = 'sentinel/document-title-anchors/1'
REFERENCE = 'sentinel/document-display-reference/1'
OUTPUT_CAP = 2097152
INPUT_CAP = 16777216
IMPORT_KEYS = ('request_raw', 'request_held', 'graph_raw', 'graph_held', 'registry',
               'registry_held', 'provenance_raw', 'provenance_held', 'import_raw', 'import_held')
NOTATION = {
    'DOC[title]': 'Existing transport display syntax; title is a JSON string, not executable code.',
    ':=': 'A display definition, not an assignment, permission or execution instruction.',
    'Σ{symbols}': 'Ordered list of display references; not arithmetic, entailment or proof of completeness.',
    '@ SOURCE': 'Source linkage notation; source authenticity and meaning are not established by display.',
    'STS1': 'Prospective carrier package identity. A preview is not a verified existing package share.',
    'PKG': 'Caller-declared retrieval hint only; no fetching, hosting, authentication or code selection.',
    'R / H / P / N': 'Region / exact heading quote / proposed proposition / other proposed node; '
                     'full entries are in the external lexicon, not a second codec grammar.'}


def reference_checked(raw, held, source_package):
    value = held_record(raw, held)
    fields(value, ('schema', 'kind', 'value', 'package_id'))
    require(value['schema'] == REFERENCE, 'display reference schema')
    text = value['value']; transport.text(text, 2048)
    require(all(not 128 <= ord(char) <= 159 for char in text), 'display reference C1 control')
    kind = value['kind']
    require(kind in ('PLACEHOLDER', 'LOCAL_ARTIFACT', 'HTTPS_URL'), 'unsupported reference kind')
    if kind == 'PLACEHOLDER':
        require(text.startswith('PLACEHOLDER:') and len(text) > len('PLACEHOLDER:'), 'explicit reference placeholder')
    elif kind == 'LOCAL_ARTIFACT':
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,2047}', text) is not None
                and '..' not in text.split('/') and len(text.split('/')) <= 16, 'relative local artifact reference')
    else:
        url = urlsplit(text)
        require(url.scheme == 'https' and bool(url.hostname) and url.username is None
                and url.password is None, 'HTTPS reference without credentials required')
        if url.port is not None: integer(url.port, 1, 65535)
    if value['package_id'] is not None:
        hash_checked(value['package_id'])
        require(value['package_id'] != source_package, 'new formula cannot reuse unverified source package identity')
    return value


def title_anchors(reading, index, index_held, raw, held):
    if raw is None or held is None:
        require(raw is None and held is None, 'partial title anchor reference')
        return []
    value = held_record(raw, held)
    fields(value, ('schema', 'index_sha256', 'titles'))
    require(value['schema'] == TITLES and value['index_sha256'] == index_held, 'title index binding')
    rows = value['titles']
    require(type(rows) is list and len(rows) <= 64, 'title anchor count')
    regions = {r['id']: r for r in index['regions']}; result, seen, region_titles, prior = [], set(), set(), 0
    for row in rows:
        fields(row, ('id', 'region_id', 'role', 'span', 'sha256'))
        name = label(row['id']); region = label(row['region_id'])
        require(name not in seen and region in regions, 'title anchor ID/region')
        require(row['role'] in ('REGION_TITLE', 'SOURCE_HEADING'), 'title anchor role')
        span = row['span']; require(type(span) is list and len(span) == 2, 'title anchor span')
        integer(span[0], regions[region]['start'], regions[region]['end'])
        integer(span[1], span[0] + 1, min(regions[region]['end'], span[0] + 255))
        require(span[0] >= prior, 'source title anchors overlap/reorder'); prior = span[1]
        quote = reading[span[0]:span[1]]
        require(digest(quote) == hash_checked(row['sha256']), 'source title quote changed')
        text = quote.decode('utf-8'); transport.text(text)
        require(all(not 128 <= ord(char) <= 159 for char in text), 'title anchor C1 control')
        if row['role'] == 'REGION_TITLE':
            require(region not in region_titles, 'duplicate region title'); region_titles.add(region)
        result.append(dict(row, text=text, title_status='EXACT_CALLER_SELECTED_SOURCE_QUOTE_NOT_VERIFIED_HEADING'))
        seen.add(name)
    return result


def imports_snapshot(supplied):
    require(type(supplied) is tuple and len(supplied) <= 64, 'candidate import tuple/count')
    result, total = [], 0
    for row in supplied:
        require(type(row) is dict and len(row) == len(IMPORT_KEYS), 'candidate import closed field count')
        fields(row, IMPORT_KEYS); item = dict(row)
        for name in ('request_raw', 'graph_raw', 'provenance_raw', 'import_raw'):
            require(type(item[name]) is bytes and len(item[name]) <= 65536, 'candidate immutable byte bound')
            total += len(item[name])
        require(total <= INPUT_CAP, 'candidate input aggregate bound before registry snapshot')
        require(type(item['registry']) is dict and len(item['registry']) <= 256, 'candidate registry bound')
        for raw in item['registry'].values():
            require(type(raw) is bytes and len(raw) <= METADATA, 'candidate registry immutable byte bound')
            total += len(raw); require(total <= INPUT_CAP, 'candidate input aggregate bound before snapshot')
        item['registry'] = registry_snapshot(item['registry'], item['registry_held'])
        result.append(item)
    require(total <= INPUT_CAP, 'candidate aggregate input bound')
    return result


def candidate_graphs(reading, binding_raw, index_raw, index_held, blocks, supplied):
    result, seen, nodes, edges, sequence = [], set(), 0, 0, 0
    for item in imports_snapshot(supplied):
        expected = document_analysis.import_candidate(item['request_raw'], item['request_held'],
            item['graph_raw'], item['graph_held'], reading, binding_raw, index_raw, index_held,
            blocks, item['registry'], item['registry_held'], item['provenance_raw'], item['provenance_held'])
        require(digest(item['import_raw']) == hash_checked(item['import_held'])
                and expected == item['import_raw'], 'candidate import receipt differs from replay')
        require(item['import_held'] not in seen, 'duplicate candidate import'); seen.add(item['import_held'])
        value = held_record(item['graph_raw'], item['graph_held']); receipt = held_record(expected, item['import_held'])
        nodes += len(value['nodes']); edges += len(value['edges'])
        require(nodes <= 256 and edges <= 512, 'complete display graph aggregate bound; no nodes dropped')
        symbols = {}
        for node in value['nodes']:
            sequence += 1; symbols[node['id']] = ('P' if node['kind'] == 'PROPOSITION' else 'N') + f'{sequence:03d}'
        result.append({'job_id': receipt['job_id'], 'graph_pin': identity(item['graph_raw']),
            'import_pin': identity(expected), 'observed_provenance': receipt['observed_provenance'],
            'status': 'PROPOSED_STRUCTURALLY_IMPORTED_NOT_TRUTH', 'symbols': symbols, 'graph': value})
    return result


def display_entries(index, titles, candidates):
    named = {r['region_id']: r for r in titles if r['role'] == 'REGION_TITLE'}
    entries, symbols = [], {}
    for position, region in enumerate(index['regions'], 1):
        symbol = f'R{position:03d}'; symbols[region['id']] = symbol
        anchor = named.get(region['id'])
        entries.append({'symbol': symbol, 'kind': 'SOURCE_REGION', 'id': region['id'],
            'label': anchor['text'] if anchor else region['id'], 'span': [region['start'], region['end']],
            'title_anchor': anchor, 'title_status': 'SOURCE_QUOTE' if anchor else 'TITLE_UNSUPPLIED',
            'context_regions': census.dependency_regions(region['id'], index['dependencies'], index['regions'])})
    for position, anchor in enumerate((r for r in titles if r['role'] == 'SOURCE_HEADING'), 1):
        entries.append({'symbol': f'H{position:03d}', 'kind': 'SOURCE_HEADING_QUOTE', 'id': anchor['id'],
            'label': anchor['text'], 'span': anchor['span'], 'parent_region': anchor['region_id'],
            'title_anchor': anchor, 'title_status': 'TITLE_SPAN_ONLY_NO_INFERRED_SECTION_BODY',
            'context_regions': census.dependency_regions(anchor['region_id'], index['dependencies'], index['regions'])})
    formula = [r['symbol'] for r in entries if r['span'][0] < r['span'][1]]
    for candidate in candidates:
        formula.extend(candidate['symbols'][n['id']] for n in candidate['graph']['nodes'] if n['kind'] == 'PROPOSITION')
    require(len(formula) <= 64, 'complete formula symbol bound; no source/idea symbols dropped')
    return entries, symbols, formula


def cell(value):
    text = html.escape(str(value), quote=False)
    result = []
    for char in text:
        if char in '|[]`*_\\{}()#+-.!:/~$' or ord(char) < 32 or 127 <= ord(char) <= 159:
            result.append('&#' + str(ord(char)) + ';')
        else: result.append(char)
    return ''.join(result)


def append(chunks, count, text):
    raw = text.encode('utf-8')
    require(count[0] + len(raw) <= METADATA, 'complete readable artifact bound; no truncation')
    chunks.append(raw); count[0] += len(raw)


def overview_text(index, entries, region_symbols, statuses, candidate_count):
    chunks, count = [], [0]
    append(chunks, count, '# Source-anchored whole-book overview\n\n'
        'Operational outline only. Main ideas are not inferred from headings. '
        'Truth, meaning completeness, OCR fidelity and context adequacy remain UNPROVEN.\n\n')
    append(chunks, count, 'Proposal imports: ' + str(candidate_count) +
        ' (PROPOSED, not truth); no imports means MODEL_ANALYSIS_UNPERFORMED.\n\n')
    append(chunks, count, '| Symbol | Source region / exact caller quote | Scope / status | Required declared contexts |\n'
        '|---|---|---|---|\n')
    for row in entries:
        context = ', '.join(region_symbols[r] + ' [' + r + ']' for r in row['context_regions']) or 'NONE_DECLARED_NOT_PROVED_SUFFICIENT'
        append(chunks, count, '| ' + ' | '.join(cell(x) for x in
            (row['symbol'], row['label'], row['title_status'], context)) + ' |\n')
    append(chunks, count, '\nParent and dependency groups (declared, not interpreted):\n')
    for region in index['regions']:
        append(chunks, count, '- ' + cell(region['id']) + ' parent: ' + cell(region['parent']) + '\n')
    for edge in index['dependencies']:
        append(chunks, count, '- ' + cell(edge['from']) + ' depends on ' + cell(edge['to']) + '\n')
    append(chunks, count, '\nProcessing/refusal status counts: ' + cell(statuses) +
        '. Opaque/unadmitted groups remain explicit in machine.json and lexicon; none were omitted.\n')
    return b''.join(chunks)


def lexicon_text(entries, candidates, groups):
    chunks, count = [], [0]
    append(chunks, count, '# Complete display symbol lexicon\n\n'
        'Source quotes are caller selections. Proposed concepts are not source truth. '
        'Formula symbols require this complete external lexicon; the short formula does not encode all relations.\n\n')
    for row in entries:
        append(chunks, count, '## ' + row['symbol'] + ': ' + cell(row['label']) + '\n\n'
            'Kind: ' + cell(row['kind']) + '; absolute span: ' + cell(row['span']) +
            '; title status: ' + cell(row['title_status']) + '; required contexts: ' + cell(row['context_regions']) + '.\n\n')
    for candidate in candidates:
        append(chunks, count, '\n## PROPOSED graph ' + cell(candidate['graph_pin']['sha256']) + '\n\n'
            'Job: ' + cell(candidate['job_id']) + '; provenance: ' + cell(candidate['observed_provenance']) + '.\n\n')
        for node in candidate['graph']['nodes']:
            append(chunks, count, '### ' + candidate['symbols'][node['id']] + ' — PROPOSED ' + cell(node['kind']) + '\n\n'
                + cell(node['text']) + '\n\nOrigin: ' + cell(node['origin']) +
                '; documentary state: ' + cell(node['documentary_state']) +
                '; exact declared evidence: ' + cell(node['evidence']) +
                '; external support/refutation record pins: ' + cell(node['support_records'] + node['refutation_records']) + '.\n\n')
        for edge in candidate['graph']['edges']:
            append(chunks, count, '- ' + candidate['symbols'][edge['from']] + ' ' + cell(edge['kind']) +
                ' ' + candidate['symbols'][edge['to']] + ' (DECLARED_PROPOSAL_RELATION).\n')
    append(chunks, count, '\n## Explicit non-admitted groups\n\n')
    for row in groups:
        if row['status'] != 'ADMITTED':
            append(chunks, count, '- ' + cell(row['id']) + ': ' + cell(row['status']) +
                '; complete absolute span ' + cell(row['span']) + '; paragraphs ' + cell(row['paragraph_ids']) + '.\n')
    return b''.join(chunks)


def operators_text(operators):
    chunks, count = [], [0]
    append(chunks, count, '# Exact operator and display definitions\n\n'
        'Display notation is not a decoder, executable instruction, truth or authorization. '
        'The inherited typed operator dictionary below is reproduced exactly as compatibility documentation; '
        'this renderer does not invent or apply a typed interpretation.\n\n')
    for name, definition in NOTATION.items():
        append(chunks, count, '- ' + cell(name) + ': ' + cell(definition) + '\n')
    append(chunks, count, '\n## Existing transport operator dictionary version 2\n\n')
    for name, row in operators['entries'].items():
        append(chunks, count, '- ' + cell(name) + ': args ' + cell(row['args']) + '; result ' + cell(row['result']) +
            '; definition: ' + cell(row['definition']) + '\n')
    append(chunks, count, '\n## Proposed graph relation endpoint sorts\n\n')
    for name, (left, right) in graph.EDGE_TYPES.items():
        append(chunks, count, '- ' + cell(name) + ': ' + cell(sorted(left)) + ' -> ' + cell(sorted(right)) +
            '. Declared typed relation only; no entailment or world-truth verdict.\n')
    return b''.join(chunks)


def formula_preview(index, titles, symbols, reference, budget, unit):
    integer(budget, 1, METADATA)
    require(unit in ('UNICODE_CODEPOINTS', 'UTF8_BYTES'), 'explicit share counting convention')
    root = index['regions'][0]['id']
    selected = [row['text'] for row in titles if row['role'] == 'REGION_TITLE' and row['region_id'] == root]
    title = selected[0] if selected else 'Whole-book source outline; main ideas UNPERFORMED'
    transport.text(title)
    formula = transport.formula_for(title, [{'id': name} for name in symbols])
    package = reference['package_id'] or '0' * 64
    share = transport.share_for(formula, package, reference['value'], None)
    amount = len(share) if unit == 'UTF8_BYTES' else len(share.decode('utf-8'))
    require(amount <= budget, 'complete share preview budget too small; no fields removed')
    return formula.encode('utf-8'), share, {'unit': unit, 'count': amount,
        'utf8_bytes': len(share), 'unicode_codepoints': len(share.decode('utf-8')),
        'platform_limit': 'NOT_CLAIMED', 'includes_complete_reference': True}


def render_document_display(reading, binding_raw, index_raw, index_held, blocks, reference_raw,
                            reference_held, budget, budget_unit='UNICODE_CODEPOINTS',
                            title_anchors_raw=None, title_anchors_held=None, candidate_imports=()):
    index, groups = document_analysis.document_checked(reading, binding_raw, index_raw, index_held, blocks)
    require(len(index['regions']) <= 64, 'complete displayed region bound; no regions dropped')
    reference = reference_checked(reference_raw, reference_held, index['binding']['source']['package_id'])
    titles = title_anchors(reading, index, index_held, title_anchors_raw, title_anchors_held)
    candidates = candidate_graphs(reading, binding_raw, index_raw, index_held, blocks, candidate_imports)
    entries, region_symbols, formula_symbols = display_entries(index, titles, candidates)
    formula, share, measured = formula_preview(index, titles, formula_symbols, reference, budget, budget_unit)
    operators = operator_dictionary('2'); statuses = {name: sum(row['status'] == name for row in groups)
        for name in ('ADMITTED', 'OPAQUE', 'PROMPT_BUDGET_UNADMITTED')}
    machine = {'schema': PROFILE, 'binding': index['binding'], 'index_pin': identity(index_raw),
        'regions': index['regions'], 'dependencies': index['dependencies'], 'entries': entries,
        'formula_symbols': formula_symbols, 'candidate_graphs': candidates, 'status_counts': statuses,
        'nonadmitted_groups': [row for row in groups if row['status'] != 'ADMITTED'],
        'reference': reference, 'share_status': 'SHARE_PREVIEW_NOT_VERIFIED_PACKAGE',
        'source_package_is_not_preview_carrier': True, 'share_measurement': measured,
        'formula_scope': 'SOURCE_OUTLINE_AND_PROPOSED_SYMBOLS_WITH_COMPLETE_EXTERNAL_LEXICON',
        'candidate_selection': 'CALLER_HELD_IMPORT_LIST_NOT_COMPLETENESS_OR_LATESTNESS',
        'hosting': 'LOCAL_UNHOSTED' if reference['kind'] == 'LOCAL_ARTIFACT' else 'NOT_VERIFIED',
        'model_analysis': 'UNPERFORMED' if not candidates else 'PROPOSED_IMPORTS_NOT_SEMANTIC_ACCEPTANCE',
        'operator_dictionary': operators, 'operator_dictionary_pin': identity(canonical(operators)),
        'document_processing': 'EMPTY_READING' if not groups else 'INCOMPLETE_OPAQUE_OR_UNADMITTED' if any(row['status'] != 'ADMITTED' for row in groups) else 'OPERATIONALLY_PLANNED_NOT_MODEL_ANALYZED',
        'required_context_scope': 'DECLARED_REGION_CLOSURES_ONLY_NOT_PROVED_SUFFICIENT', 'interpretation_entailment': 'UNPROVEN',
        'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN', 'ocr_accuracy': 'UNPROVEN',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}
    output = {'machine': canonical(machine), 'overview': overview_text(index, entries, region_symbols, statuses, len(candidates)),
        'lexicon': lexicon_text(entries, candidates, groups), 'operators': operators_text(operators),
        'formula': formula, 'share_preview': share}
    require(all(len(raw) <= METADATA for raw in output.values())
            and sum(map(len, output.values())) <= OUTPUT_CAP, 'complete display artifact aggregate bound')
    return output
