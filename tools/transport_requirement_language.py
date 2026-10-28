"""Source-bound readable requirements; a closed surface grammar, not English AI.

All role values and byte spans come from the retained source. Normative meaning,
event identity and compliance remain outside this tested syntactic profile.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass

from transport_wire import MAX_SOURCE, MAX_TOKEN, TransportError

HEADER = 'transport/readable-plan/2'
PROFILE = 'technical-requirements/1'
MAX_RECORDS = 8
MAX_LINES = 32
MAX_LINE_BYTES = 2048
IDENTIFIER = re.compile(rb'([A-Z][A-Z0-9_-]{0,63}): ')
MODAL = re.compile(rb' (shall not|shall|should|may) ')
DEADLINE = re.compile(rb'within (0|[1-9][0-9]{0,8})(\.[0-9]{1,9})? (ns|us|ms|s|min|h)')
RESERVED = re.compile(r'\b(?:when|shall|should|may|within|unless)\b', re.IGNORECASE)
ORDER = ('ID', 'WHEN', 'ACTOR', 'MODAL', 'ACTION', 'WITHIN', 'UNLESS')


@dataclass(frozen=True)
class Field:
    role: str
    begin: int
    end: int
    value: str


def field(role: str, data: bytes, begin: int, end: int, base: int) -> Field:
    if not 0 <= begin < end <= len(data) or end - begin > MAX_TOKEN:
        raise TransportError('requirement field is empty or exceeds its source-quote budget')
    value = data[begin:end].decode('utf-8')
    if value != value.strip() or any(unicodedata.category(c).startswith('C') for c in value):
        raise TransportError('requirement field contains padding or unsupported Unicode category C characters')
    return Field(role, base + begin, base + end, value)


def atom(value: str) -> None:
    if any(char in value for char in ',;:"()[]{}') or RESERVED.search(value):
        raise TransportError('ambiguous or reserved wording in a requirement role; use documentary profile')


def split_condition(data: bytes, start: int, end: int, base: int) -> tuple[int, list[Field]]:
    if not data.startswith(b'When ', start):
        return start, []
    comma = data.find(b', ', start, end)
    if comma < 0 or comma <= start + len(b'When '):
        raise TransportError('When clause requires a nonempty trigger and comma-space delimiter')
    item = field('WHEN', data, start, comma, base)
    atom(item.value[len('When '):])
    return comma + len(b', '), [item]


def split_exception(data: bytes, start: int, end: int, base: int) -> tuple[int, list[Field]]:
    mark = data.find(b', unless ', start, end)
    if mark < 0:
        return end, []
    item = field('UNLESS', data, mark + len(b', '), end, base)
    if item.value == 'unless ' or not item.value[len('unless '):]:
        raise TransportError('empty exception')
    atom(item.value[len('unless '):])
    return mark, [item]


def split_deadline(data: bytes, start: int, end: int, base: int) -> tuple[int, list[Field]]:
    mark = data.find(b' within ', start, end)
    if mark < 0:
        return end, []
    if DEADLINE.fullmatch(data[mark + 1:end]) is None:
        raise TransportError('unsupported or ambiguous deadline; preserve its spelling in documentary profile')
    item = field('WITHIN', data, mark + 1, end, base)
    return mark, [item]


def parse_requirement(data: bytes, base: int) -> tuple[Field, ...]:
    if not data.endswith(b'.') or len(data) > MAX_LINE_BYTES:
        raise TransportError('requirement needs a final period and a bounded physical line')
    identity = IDENTIFIER.match(data)
    if identity is None:
        raise TransportError('requirement needs an uppercase ID followed by colon-space')
    fields = [field('ID', data, identity.start(1), identity.end(1), base)]
    start, extra = split_condition(data, identity.end(), len(data) - 1, base)
    fields.extend(extra)
    modality = MODAL.search(data, start, len(data) - 1)
    if modality is None:
        raise TransportError('requirement needs an actor and shall/shall not/should/may')
    actor = field('ACTOR', data, start, modality.start(), base)
    atom(actor.value)
    fields.extend((actor, field('MODAL', data, modality.start(1), modality.end(1), base)))
    end, extra = split_exception(data, modality.end(), len(data) - 1, base)
    fields.extend(extra)
    end, extra = split_deadline(data, modality.end(), end, base)
    fields.extend(extra)
    action = field('ACTION', data, modality.end(), end, base)
    atom(action.value)
    fields.append(action)
    by_role = {item.role: item for item in fields}
    return tuple(by_role[role] for role in ORDER if role in by_role)


def parse_requirements(source: bytes) -> tuple[tuple[Field, ...], ...]:
    if not isinstance(source, bytes) or not 1 <= len(source) <= MAX_SOURCE:
        raise TransportError('requirement source byte budget exceeded')
    try:
        source.decode('utf-8')
    except UnicodeError as error:
        raise TransportError('requirements source must be UTF-8') from error
    lines = source.split(b'\n', MAX_LINES)
    if len(lines) > MAX_LINES:
        raise TransportError('requirement physical-line budget exceeded')
    records, identities = [], set()
    base = 0
    for index, raw in enumerate(lines):
        line = raw.removesuffix(b'\r') if index < len(lines) - 1 else raw
        if line:
            if len(records) == MAX_RECORDS:
                raise TransportError('requirement record budget exceeded')
            record = parse_requirement(line, base)
            if record[0].value in identities:
                raise TransportError('duplicate source requirement identity')
            identities.add(record[0].value)
            records.append(record)
        base += len(raw) + 1
    if not records:
        raise TransportError('requirement document has no requirements')
    return tuple(records)


def requirement_formula(prefix: str, fields: tuple[Field, ...]) -> str:
    roles = {item.role for item in fields}
    body = [prefix + role for role in ('ACTOR', 'MODAL', 'ACTION', 'WITHIN', 'UNLESS')
            if role in roles]
    scope = 'Σ{' + '; '.join(body) + '}'
    if 'WHEN' in roles:
        scope = '(' + prefix + 'WHEN → ' + scope + ')'
    return 'Σ{' + prefix + 'ID; ' + scope + '}'


def components(source: bytes) -> tuple:
    records = parse_requirements(source)
    symbols, bindings, formulas = [], [], []
    conditional = False
    for index, fields in enumerate(records):
        prefix = chr(ord('A') + index) + '_'
        for item in fields:
            name = prefix + item.role
            symbols.append((name, item.value))
            bindings.append((name, item.begin, item.end))
            conditional = conditional or item.role == 'WHEN'
        formulas.append(requirement_formula(prefix, fields))
    formula = formulas[0] if len(formulas) == 1 else 'Σ{' + '; '.join(formulas) + '}'
    senses = [('Σ', 'integrate')]
    if conditional:
        senses.append(('→', 'condition'))
    return tuple(symbols), tuple(bindings), tuple(senses), formula


def draft_requirements(source: bytes) -> bytes:
    symbols, bindings, senses, formula = components(source)
    lines = [HEADER, 'profile ' + PROFILE, 'source ' + hashlib.sha256(source).hexdigest()]
    for (name, phrase), (_, begin, end) in zip(symbols, bindings, strict=True):
        lines.append('symbol ' + name + ' ' + str(begin) + ' ' + str(end) +
                     ' ' + json.dumps(phrase, ensure_ascii=False))
    lines.extend('operator ' + glyph + ' ' + sense for glyph, sense in senses)
    lines.append('formula ' + formula)
    return ('\n'.join(lines) + '\n').encode('utf-8')
