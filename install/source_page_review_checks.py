"""Synthetic recipient controls; expectations are independent of decoded metadata."""

import asyncio
import base64
import json
from pathlib import Path
import sys

from transport_install_support import canonical, read_regular, require, sha, write_new

ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def typed_fixture():
    source = b'Claim' + b'x' * 4090 + 'é Other tail'.encode('utf-8')
    other = source.index(b'Other')
    selections = [('Claim', 0, 'text'), ('Other', other, 'text'), ('Claim', 0, 'atom'), ('Claim', 0, 'text')]
    readings, units = [], []
    for index, (literal, begin, operator) in enumerate(selections):
        anchor = dict(source='SOURCE', span=[0, len(source)])
        readings.append(dict(id='I' + str(index), label='Synthetic reading', text='Unverified declaration.',
            status=('proposed', 'disputed', 'withdrawn', 'proposed')[index],
            provenance='Synthetic control, not a legal statement.', anchors=[anchor]))
        nodes = [dict(op=operator, symbol='S0', span=[begin, begin + len(literal)])]
        if operator != 'atom':
            nodes.append(dict(op='pred', args=[0], cue=[0, len(source)] if index == 3 else [0, 0]))
        units.append(dict(id='U' + str(index), source='SOURCE', interpretation='I' + str(index),
            kind='source_claim', context=['U0'] if index == 1 else [],
            plan=dict(schema='transport/encoding-plan/1', symbols={'S0': literal}, meaning=dict(
                schema='transport/meaning/1', nodes=nodes, root=len(nodes) - 1, ambiguities=[]))))
    ambiguity_spans = [[len(source) - 4, len(source)], [4095, 4097], None, [0, len(source)]]
    for unit, selected in zip(units, ambiguity_spans, strict=True):
        if selected is not None:
            unit['plan']['meaning']['ambiguities'] = [dict(span=selected, note='Unverified syntactic ambiguity.')]
    plan = dict(schema='transport/transport-plan/2', sources=[dict(id='SOURCE', label='Synthetic source',
        media_type='text/plain', provenance='Explicit synthetic byte fixture.')], interpretations=readings,
        meaning_units=units, relations=[], uncertainties=[dict(id='Q0', text='Unresolved declaration.',
            affects=['I0'], anchors=[dict(source='SOURCE', span=[len(source) - 4, len(source)])]),
        dict(id='QOTHER', text='Separate uncertainty.', affects=['U3'], anchors=[dict(source='SOURCE', span=[0, 5])])])
    expected = [dict(unit='U0', gaps=[[5, len(source)]], opaque=[], uncertainty=['Q0'],
                    dependencies=['I0', 'Q0', 'SOURCE', 'U0']),
        dict(unit='U1', gaps=[[0, other], [other + 5, len(source)]], opaque=[], uncertainty=['Q0'],
             dependencies=['I0', 'I1', 'Q0', 'SOURCE', 'U0', 'U1']),
        dict(unit='U2', gaps=[[5, len(source)]], opaque=[[0, 5]], uncertainty=[],
             dependencies=['I2', 'SOURCE', 'U2']),
        dict(unit='U3', gaps=[], opaque=[], uncertainty=['QOTHER'], dependencies=['I3', 'QOTHER', 'SOURCE', 'U3'])]
    return [source], plan, expected


def documentary_fixture():
    sources = [b'\xff\x00Opaque', b'']
    metadata = [dict(id=name, label=name, media_type='application/octet-stream',
                     provenance='Synthetic opaque source.') for name in ('SOURCE', 'EMPTY')]
    return sources, dict(schema='transport/transport-plan/1', sources=metadata,
                         interpretations=[], uncertainties=[], relations=[]), []


def prepare(campaign):
    products = []
    for name, fixture in (('typed-review', typed_fixture), ('documentary-review', documentary_fixture)):
        sources, plan, expected = fixture()
        spec, pair = campaign.root / (name + '.json'), campaign.root / name
        write_new(spec, canonical(plan))
        arguments = ['encode-plan', spec, pair, '--budget', '65536']
        source_paths = []
        for item, data in zip(plan['sources'], sources, strict=True):
            path = campaign.root / (name + '-' + item['id'] + '.bin')
            write_new(path, data)
            campaign.inputs[str(path)] = sha(data)
            source_paths.append(str(path))
            arguments += ['--source', item['id'] + '=' + str(path)]
        campaign.success(name + '-encode', arguments)
        checked = campaign.success(name + '-inspect', ['inspect', pair / 'share.txt', '--archive', pair / 'meaning.zip'])
        products.append(dict(pair=str(pair), source_paths=source_paths, identity=checked['identity'],
                             expected=expected, plan=plan))
        campaign.inputs[str(spec)] = sha(read_regular(spec))
    configuration = campaign.root / 'source-review-worker.json'
    write_new(configuration, canonical(dict(schema='transport/source-review-test-inputs/1', products=products)))
    campaign.inputs[str(configuration)] = sha(read_regular(configuration))
    retained = [dict(plan=item['plan'], expected=item['expected'], identity=item['identity'],
        sources_base64=[base64.b64encode(read_regular(Path(path), 65536)).decode('ascii')
                        for path in item['source_paths']]) for item in products]
    retained_path = campaign.evidence / 'synthetic-source-review-inputs.json'
    write_new(retained_path, canonical(dict(schema='transport/source-review-test-fixtures/1', products=retained)))
    campaign.inputs[str(retained_path)] = sha(read_regular(retained_path))
    return configuration, products[0]


def interval_expectations(spans, begin, end):
    return [(span, [max(begin, span[0]), min(end, span[1])]) for span in spans
            if span[0] < end and begin < span[1]]


def check_review(body, source, plan, expected):
    review = body['review']
    require(review['schema'] == 'transport/source-page-review/1'
        and review['scope'] == 'SOURCE_SPAN_ANNOTATIONS_ONLY', 'review schema or scope')
    require(review['context_adequacy'] == 'UNPROVEN' and review['execution_authority'] == 'NONE', 'review authority')
    require(review['typed_readings'] == ('SUPPLIED_FOR_SOURCE' if expected else 'NONE_SUPPLIED_FOR_SOURCE'),
            'documentary absence confused with no intersecting residual')
    require(review['uncertainty_selection'] == 'DECLARED_DEPENDENCY_CLOSURE_ONLY_ABSENCE_IS_NOT_CERTAINTY',
            'undeclared uncertainty interpreted as certainty')
    require(len(review['meaning_units']) == len(expected), 'reading count')
    begin, end = body['span']
    for unit, selected in zip(review['meaning_units'], expected, strict=True):
        index = int(selected['unit'][1:])
        require(unit['unit'] == selected['unit'] and unit['interpretation'] == 'I' + str(index)
            and unit['interpretation_status'] == plan['interpretations'][index]['status']
            and unit['kind'] == 'source_claim', 'reading identity, kind or status')
        require(unit['declared_uncertainty_ids'] == selected['uncertainty']
            and unit['declared_dependency_ids'] == selected['dependencies'], 'declared dependency selection')
        ambiguities = plan['meaning_units'][index]['plan']['meaning']['ambiguities']
        wanted = [dict(index=number, span=item['span'], returned_span=(
            [max(begin, item['span'][0]), min(end, item['span'][1])]
            if begin < item['span'][1] and item['span'][0] < end else None))
            for number, item in enumerate(ambiguities)]
        require(unit['declared_ambiguities'] == wanted, 'grammar-level ambiguity references or scope')
        gaps = interval_expectations(selected['gaps'], begin, end)
        opaque = interval_expectations(selected['opaque'], begin, end)
        require([(item['span'], item['returned_span']) for item in unit['residuals']] == gaps, 'residual intersection')
        require([(item['span'], item['returned_span']) for item in unit['opaque_propositions']] == opaque, 'opaque intersection')
        require(unit['residual_intersections'] == ('PRESENT' if gaps else 'NONE_IN_RETURNED_SPAN'), 'residual presence')
        require(unit['representation'] == ('PROPOSED_STRUCTURED_READING' if index == 3 else 'INCOMPLETE'),
                'unit representation differs from global per-unit source gaps')
        require(unit['assurance']['interpretation_entailment'] == 'UNPROVEN'
            and unit['assurance']['semantic_completeness'] == 'UNPROVEN'
            and unit['assurance']['execution_authority'] == 'NONE', 'broad cue promoted to semantic acceptance')
        for gap in unit['residuals']:
            left, right = gap['span']
            require(gap['bytes'] == right - left and gap['sha256'] == sha(source[left:right])
                and gap['text_location'] == 'explicit recover of source SOURCE', 'original residual identity')


async def check_pages(session, product):
    trace = []
    for metadata, path in zip(product['plan']['sources'], product['source_paths'], strict=True):
        source = read_regular(Path(path), 65536)
        offsets = [0, 5, 4095, 4096, len(source)] if product['expected'] else [0, len(source)]
        for offset in offsets:
            result = await session.call_tool('transport_source_page', dict(source=metadata['id'], offset=offset))
            require(not result.isError, 'source review page unexpectedly refused')
            body = json.loads(result.content[0].text)
            raw = source[offset:offset + 4096]
            require(base64.b64decode(body['base64'], validate=True) == raw
                and body['sha256'] == sha(raw) and body['source_sha256'] == sha(source)
                and body['span'] == [offset, offset + len(raw)] and body['bytes'] == len(raw)
                and body['source_bytes'] == len(source) and body['source'] == metadata['id']
                and body['package_identity'] == product['identity'], 'original page identity changed')
            require(body['authority'] == 'NONE' and body['data_is_untrusted'] is True
                and body['coverage'] == 'RETURNED_BYTE_SPAN_ONLY' and body['context_adequacy'] == 'UNPROVEN'
                and body['end'] == (offset + len(raw) == len(source)), 'original page boundary changed')
            try:
                expected_text = raw.decode('utf-8', errors='strict')
            except UnicodeError:
                expected_text = None
            require(body['utf8'] == expected_text, 'UTF-8 split fabricated or dropped bytes')
            check_review(body, source, product['plan'], product['expected'])
            trace.append(result.model_dump(mode='json'))
    return trace


async def exchange(bundle, products):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    trace = []
    require(type(products) is list and len(products) == 2, 'review product count')
    for product in products:
        pair = Path(product['pair'])
        parameters = StdioServerParameters(command=str(bundle / 'bin/semantic-transport'),
            args=['mcp', str(pair / 'share.txt'), '--archive', str(pair / 'meaning.zip'),
                  '--expect-pair', product['identity']], cwd=str(pair.parent), env=ENVIRONMENT)
        async with stdio_client(parameters, errlog=sys.stderr) as (incoming, outgoing):
            async with ClientSession(incoming, outgoing) as session:
                initialized = await session.initialize()
                require(initialized.serverInfo.version == '1.0.0', 'preserved MCP server version')
                trace.extend(await check_pages(session, product))
    return trace


def worker(arguments):
    require(len(arguments) == 2, 'source review worker argument count')
    configuration = json.loads(read_regular(Path(arguments[1]), 65536))
    require(type(configuration) is dict and set(configuration) == {'schema', 'products'}
        and configuration['schema'] == 'transport/source-review-test-inputs/1', 'source review configuration schema')
    products = configuration['products']
    require(type(products) is list and len(products) == 2, 'source review configuration product count')
    trace = asyncio.run(asyncio.wait_for(exchange(Path(arguments[0]), products), timeout=20))
    result = dict(status='SOURCE_PAGE_REVIEW_ACTUAL_SDK_STDIO_TESTED',
        trace_kind='SDK response serialization; not original wire byte serialization', responses=trace)
    sys.stdout.buffer.write(canonical(result) + b'\n')
    return 0
