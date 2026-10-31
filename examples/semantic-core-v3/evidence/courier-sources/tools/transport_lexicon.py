"""Bounded author-facing codebooks. Definitions are exact source quotations."""

import json
import hashlib
import re
from dataclasses import dataclass

from transport_formula import IDENT, check_symbols, parse_formula
from transport_requirement_language import HEADER as ANCHORED_HEADER, PROFILE, components
from transport_source_map import (HEADER as MAPPED_HEADER, PROFILE as MAPPED_PROFILE,
                            Origin, Passage, Support, add_passage, bind_mapping, passage,
                            parse_origin, parse_support)
from transport_wire import MAX_SOURCE, MAX_SYMBOLS, MAX_TOKEN, TransportError

HEADER = 'transport/readable-plan/1'
MAX_PLAN = 16_384
MAX_LINES = 128


@dataclass(frozen=True)
class Plan:
    symbols: tuple[tuple[str, str], ...]
    senses: tuple[tuple[str, str], ...]
    formula: str
    profile: str = 'documentary'
    source_id: str = ''
    bindings: tuple[tuple[str, int, int], ...] = ()
    supports: tuple[Support, ...] = ()
    contexts: tuple[Passage, ...] = ()
    origin: Origin | None = None


def unicode_text(data: bytes, cap: int) -> str:
    if not data or len(data) > cap:
        raise TransportError('empty input or text byte budget exceeded')
    try:
        return data.decode('utf-8')
    except UnicodeError as error:
        raise TransportError('readable Source-Anchored Semantic Transport requires UTF-8; use pack for arbitrary bytes') from error


def add_symbol(payload: str, symbols: dict[str, str]) -> None:
    parts = payload.split(' ', 1)
    if len(parts) != 2 or not IDENT.fullmatch(parts[0]):
        raise TransportError('symbol declaration requires NAME and a quoted source phrase')
    name, quoted = parts
    if name in symbols or len(symbols) == MAX_SYMBOLS or not quoted.startswith('"'):
        raise TransportError('duplicate symbol, symbol budget, or missing source quotation')
    try:
        value = json.loads(quoted)
        if not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= MAX_TOKEN:
            raise TransportError('symbol phrase must be nonempty and fit the native dictionary')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise TransportError('invalid or oversized symbol source quotation') from error
    symbols[name] = value


def add_operator(payload: str, senses: dict[str, str]) -> None:
    parts = payload.split(' ')
    if len(parts) != 2 or parts[0] in senses or len(senses) == 8:
        raise TransportError('duplicate or malformed operator declaration')
    senses[parts[0]] = parts[1]


def plan_header(lines: list[str]) -> tuple[list[str], str, str]:
    if lines[0] == HEADER:
        return lines[1:], 'documentary', ''
    profile = {ANCHORED_HEADER: PROFILE, MAPPED_HEADER: MAPPED_PROFILE}.get(lines[0])
    if profile is None or len(lines) < 4 or lines[1] != 'profile ' + profile:
        raise TransportError('missing or unknown readable codebook version or profile')
    if re.fullmatch(r'source [0-9a-f]{64}', lines[2]) is None:
        raise TransportError('anchored codebook requires an exact source identity')
    return lines[3:], profile, lines[2][len('source '):]


def add_bound_symbol(payload: str, symbols: dict, bindings: list) -> None:
    parts = payload.split(' ', 3)
    if len(parts) != 4 or any(re.fullmatch(r'(0|[1-9][0-9]{0,4})', item) is None
                              for item in parts[1:3]):
        raise TransportError('bound symbol needs NAME START END and exact source quotation')
    begin, end = int(parts[1]), int(parts[2])
    if not 0 <= begin < end <= MAX_SOURCE or end - begin > MAX_TOKEN:
        raise TransportError('invalid source span')
    add_symbol(parts[0] + ' ' + parts[3], symbols)
    bindings.append((parts[0], begin, end))


def parse_plan(data: bytes) -> Plan:
    text = unicode_text(data, MAX_PLAN)
    lines = text.split('\n')
    if len(lines) > MAX_LINES:
        raise TransportError('codebook line budget exceeded')
    lines = [line.removesuffix('\r') for line in lines]
    body, profile, source_id = plan_header(lines)
    symbols: dict[str, str] = {}
    senses: dict[str, str] = {}
    formula = ''
    bindings = []
    supports, contexts = [], []
    origin = None
    for line in body:
        if not line:
            continue
        if formula:
            raise TransportError('content after formula')
        if line.startswith('symbol '):
            if profile == 'documentary':
                add_symbol(line[7:], symbols)
            else:
                add_bound_symbol(line[7:], symbols, bindings)
        elif line.startswith('operator '):
            add_operator(line[9:], senses)
        elif profile == MAPPED_PROFILE and line.startswith('support '):
            add_passage(parse_support(line[8:]), supports)
        elif profile == MAPPED_PROFILE and line.startswith('context '):
            add_passage(passage(line[8:].split(' ', 3), 'context'), contexts)
        elif profile == MAPPED_PROFILE and line.startswith('origin ') and origin is None:
            origin = parse_origin(line[7:])
        elif line.startswith('formula '):
            formula = line[8:]
            if not formula:
                raise TransportError('empty formula declaration')
        else:
            raise TransportError('unknown readable codebook statement')
    nodes, _ = parse_formula(formula)
    check_symbols(nodes, symbols, senses)
    return Plan(tuple(symbols.items()), tuple(senses.items()), formula,
                profile, source_id, tuple(bindings), tuple(supports), tuple(contexts), origin)


def bind_occurrences(plan: Plan, source: bytes) -> None:
    if plan.source_id != hashlib.sha256(source).hexdigest():
        raise TransportError('codebook source identity mismatch')
    symbols = dict(plan.symbols)
    for name, begin, end in plan.bindings:
        if source[begin:end] != symbols[name].encode('utf-8'):
            raise TransportError('source occurrence mismatch: ' + name)


def bind_requirements(plan: Plan, source: bytes) -> None:
    symbols = dict(plan.symbols)
    expected_symbols, expected_bindings, expected_senses, expected_formula = components(source)
    actual_spans = {name: (begin, end) for name, begin, end in plan.bindings}
    expected_spans = {name: (begin, end) for name, begin, end in expected_bindings}
    if (symbols, actual_spans, dict(plan.senses)) != (
            dict(expected_symbols), expected_spans, dict(expected_senses)):
        raise TransportError('requirement roles or numerical association changed')
    if parse_formula(plan.formula) != parse_formula(expected_formula):
        raise TransportError('requirement formula changes source role, scope, or association')


def bind_source(plan: Plan, source: bytes) -> str:
    text = unicode_text(source, MAX_SOURCE)
    for symbol, phrase in plan.symbols:
        if phrase not in text:
            raise TransportError('source phrase or figure changed for symbol ' + symbol)
    if plan.profile in (PROFILE, MAPPED_PROFILE):
        bind_occurrences(plan, source)
    if plan.profile == PROFILE:
        bind_requirements(plan, source)
    elif plan.profile == MAPPED_PROFILE:
        if plan.origin is not None and plan.origin.end - plan.origin.begin != len(source):
            raise TransportError('origin interval length differs from the retained source')
        bind_mapping(source, plan.formula, plan.senses, plan.bindings, plan.supports, plan.contexts)
    return text


def phrase_chunks(text: str) -> list[str]:
    chunks, current = [], []
    size = 0
    for match in re.finditer(r'\S+\s*|\s+', text):
        word = match.group()
        width = len(word.encode('utf-8'))
        if width > MAX_TOKEN:
            raise TransportError('automatic draft cannot split an oversized word or figure')
        if size + width > MAX_TOKEN:
            chunks.append(''.join(current))
            current, size = [], 0
        current.append(word)
        size += width
        if word.rstrip().endswith(('.', '!', '?', ';')) or '\n' in word:
            chunks.append(''.join(current))
            current, size = [], 0
        if len(chunks) > MAX_SYMBOLS:
            raise TransportError('automatic draft needs too many phrases; supply a smaller codebook')
    if current:
        chunks.append(''.join(current))
    if len(chunks) > MAX_SYMBOLS:
        raise TransportError('automatic draft needs too many phrases; supply a smaller codebook')
    return chunks


def phrase_name(phrase: str, index: int) -> str:
    words = re.findall(r'[A-Za-z]+', phrase)
    label = '_'.join(words[:4]).upper()[:40] or 'TEXT'
    suffix = chr(ord('A') + index // 26) + chr(ord('A') + index % 26)
    return label + '_' + suffix


def draft_plan(source: bytes) -> bytes:
    text = unicode_text(source, MAX_SOURCE)
    phrases = phrase_chunks(text)
    lines, names = [HEADER], []
    for index, phrase in enumerate(phrases):
        name = phrase_name(phrase, index)
        names.append(name)
        lines.append('symbol ' + name + ' ' + json.dumps(phrase, ensure_ascii=False))
    lines.extend(('operator Σ integrate', 'formula Σ{' + '; '.join(names) + '}'))
    result = ('\n'.join(lines) + '\n').encode('utf-8')
    parse_plan(result)
    return result


def draft_source_map(source: bytes) -> bytes:
    text = unicode_text(source, MAX_SOURCE)
    lines = [MAPPED_HEADER, 'profile ' + MAPPED_PROFILE,
             'source ' + hashlib.sha256(source).hexdigest()]
    names, position = [], 0
    for index, phrase in enumerate(phrase_chunks(text)):
        name = phrase_name(phrase, index)
        end = position + len(phrase.encode('utf-8'))
        lines.append('symbol ' + name + ' ' + str(position) + ' ' + str(end) +
                     ' ' + json.dumps(phrase, ensure_ascii=False))
        names.append(name)
        position = end
    lines.extend(('operator Σ integrate', 'formula Σ{' + '; '.join(names) + '}'))
    result = ('\n'.join(lines) + '\n').encode('utf-8')
    bind_source(parse_plan(result), source)
    return result
