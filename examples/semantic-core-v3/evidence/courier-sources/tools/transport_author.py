"""Bounded explicit plan authoring; no natural-language interpretation or authority."""

from transport_operators import GRAMMAR_V2, MAX_MENTIONS, PLAN_V2
from transport_meaning import check_meaning
from transport_schema import MAX_LITERAL, MAX_NODES, MAX_SYMBOLS, canonical, require
from transport_codec import source_text


class Plan:
    """Propose v2 structure with exact source quotations and explicit occurrence choices."""

    def __init__(self, source: bytes):
        source_text(source)
        self.source = source
        self.symbols = {}
        self.nodes = []
        self.ambiguities = []

    def interval(self, phrase: str, start: int | None = None) -> list[int]:
        require(type(phrase) is str, 'quotation must be text')
        raw = phrase.encode('utf-8')
        require(1 <= len(raw) <= MAX_LITERAL, 'quotation byte budget exceeded')
        if start is None:
            start = self.source.find(raw)
            require(start >= 0 and self.source.find(raw, start + 1) < 0,
                    'quotation absent or ambiguous; supply its exact byte offset')
        require(type(start) is int and 0 <= start < len(self.source), 'invalid quotation offset')
        require(self.source[start:start + len(raw)] == raw, 'quotation differs at specified offset')
        self.source[:start].decode('utf-8')
        return [start, start + len(raw)]

    def mention(self, phrase: str, start: int | None = None) -> dict:
        interval = self.interval(phrase, start)
        existing = next((name for name, value in self.symbols.items() if value == phrase), None)
        if existing is None:
            require(len(self.symbols) < MAX_SYMBOLS, 'author symbol budget exceeded')
            existing = 'S' + str(len(self.symbols))
            self.symbols[existing] = phrase
        return {'symbol': existing, 'span': interval}

    def node(self, value: dict) -> int:
        require(len(self.nodes) < MAX_NODES, 'author node budget exceeded')
        self.nodes.append(value)
        return len(self.nodes) - 1

    def quote(self, phrase: str, kind: str = 'term', start: int | None = None) -> int:
        require(kind in ('term', 'text', 'atom'), 'invalid quotation kind')
        return self.node(dict(self.mention(phrase, start), op=kind))

    def variable(self, name: str) -> int:
        return self.node({'op': 'var', 'name': name})

    def reference(self, name: str, mentions: list, relationship: str = 'document',
                  scope: int | None = None) -> int:
        require(type(mentions) is list and 1 <= len(mentions) <= MAX_MENTIONS,
                'author reference mention budget exceeded')
        return self.node({'op': 'reference', 'id': name, 'relationship': relationship,
                          'args': [] if scope is None else [scope], 'mentions': mentions})

    def relation(self, op: str, *args: int, cue: str = '', start: int | None = None) -> int:
        interval = self.interval(cue, start) if cue else [0, 0]
        value = {'op': op, 'args': list(args), 'cue': interval}
        if op == 'copy_unchanged':
            value['comparison'] = 'unspecified'
        return self.node(value)

    def predicate(self, verb: str, *args: int, start: int | None = None) -> int:
        return self.relation('pred', self.quote(verb, 'text', start), *args)

    def ambiguity(self, phrase: str, note: str, start: int | None = None) -> None:
        require(len(self.ambiguities) < 16, 'author ambiguity budget exceeded')
        self.ambiguities.append({'span': self.interval(phrase, start), 'note': note})

    def finish(self, root: int) -> bytes:
        meaning = {'schema': GRAMMAR_V2, 'nodes': self.nodes, 'root': root, 'ambiguities': self.ambiguities}
        check_meaning(meaning, self.source, self.symbols)
        return canonical({'schema': PLAN_V2, 'symbols': self.symbols, 'meaning': meaning})
