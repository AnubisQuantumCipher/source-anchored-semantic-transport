"""Readable Source-Anchored Semantic Transport expression trees. Documentary relations, never arithmetic.

All leaves are defined symbols. Binary relations require explicit parentheses;
there is no inferred precedence, execution, substitution, or recursive descent.
"""

import re
from dataclasses import dataclass

from transport_wire import TransportError

MAX_FORMULA = 4096
MAX_TOKENS = 1024
MAX_NODES = 512
MAX_GROUP = 64
IDENT = re.compile(r'[A-Za-z][A-Za-z_]{0,47}\Z')
TOKEN = re.compile(r'\|\||[A-Za-z][A-Za-z_]*|[Σ×÷+\-→=(){};]')
BINARY = frozenset(('×', '÷', '+', '-', '→', '||', '='))
DEFINITIONS = {
    ('Σ', 'integrate'): 'Integrate the listed elements as one ordered knowledge group; retain every element and its qualifications. This is not a numerical sum.',
    ('+', 'include'): 'Include the left and right elements together, in that order. No numerical addition or unstated interaction is asserted.',
    ('×', 'enhance'): 'The author proposes that the left and right elements enhance one another. No numerical multiplier or measured effect is implied.',
    ('÷', 'separate'): 'Separate the left element from the right element. This is not arithmetic division, logical negation, or refutation.',
    ('÷', 'refute'): 'The author presents the left element as a refutation of the right element. The notation does not verify the refutation.',
    ('÷', 'remove'): 'Remove the right element from the left element in the stated context. This is not numerical division.',
    ('-', 'exclude'): 'Exclude the right element from the left element in the stated context. This does not silently mean logical negation or subtraction.',
    ('→', 'condition'): 'The left element states a condition for the right element. This does not assert causation or a temporal ordering.',
    ('→', 'progress'): 'The author presents a directional progression from left to right. Causation and logical entailment are not implied.',
    ('→', 'cause'): 'The author asserts that the left element causes the right element. Causation requires evidence beyond this notation.',
    ('→', 'imply'): 'Within the declared interpretation, the left proposition implies the right proposition. This does not establish either proposition as true.',
    ('→', 'transform'): 'The author presents a transformation from the left element into the right element. No mechanism is supplied by the arrow alone.',
    ('||', 'parallel'): 'The left and right tracks occur in parallel in the declared context. Interaction or feedback must be separately stated.',
    ('=', 'identity'): 'The author asserts identity between the two descriptions in the declared context. This is not assignment, numerical evaluation, or a proof of identity.',
}


@dataclass(frozen=True)
class Expression:
    operator: str
    symbol: str
    children: tuple[int, ...]


def tokenize(formula: str) -> list[str]:
    if not formula or len(formula.encode('utf-8')) > MAX_FORMULA:
        raise TransportError('formula byte budget exceeded or formula empty')
    tokens: list[str] = []
    position = 0
    for _ in range(MAX_FORMULA):
        if position == len(formula):
            break
        if formula[position] in ' \t\r\n':
            position += 1
            continue
        match = TOKEN.match(formula, position)
        if match is None or len(tokens) == MAX_TOKENS:
            raise TransportError('unknown formula token or token budget exceeded')
        token = match.group()
        if token[0].isascii() and token[0].isalpha() and not IDENT.fullmatch(token):
            raise TransportError('symbol names require bounded ASCII letters and underscores')
        tokens.append(token)
        position = match.end()
    if position != len(formula):
        raise TransportError('formula scan budget exceeded')
    return tokens


def append_node(nodes: list[Expression], node: Expression) -> int:
    if len(nodes) == MAX_NODES:
        raise TransportError('formula node budget exceeded')
    nodes.append(node)
    return len(nodes) - 1


def begin_expression(token: str, tasks: list[str], values: list, nodes: list) -> None:
    if IDENT.fullmatch(token):
        values.append(append_node(nodes, Expression('', token, ())))
    elif token == '(':
        tasks.extend(('binary', ')', 'expression', 'operator', 'expression'))
    elif token == 'Σ':
        values.append(None)
        tasks.extend(('group', 'expression', '{'))
    else:
        raise TransportError('expected a symbol, parenthesized binary relation, or Σ group')


def reduce_binary(values: list, nodes: list[Expression]) -> None:
    if len(values) < 3:
        raise TransportError('incomplete binary relation')
    left, operator, right = values[-3:]
    if type(left) is not int or operator not in BINARY or type(right) is not int:
        raise TransportError('invalid binary relation')
    del values[-3:]
    values.append(append_node(nodes, Expression(operator, '', (left, right))))


def reduce_group(values: list, nodes: list[Expression]) -> None:
    children: list[int] = []
    for _ in range(MAX_GROUP + 1):
        if not values:
            raise TransportError('missing group boundary')
        value = values.pop()
        if value is None:
            if not children:
                raise TransportError('empty integration group')
            values.append(append_node(nodes, Expression('Σ', '', tuple(reversed(children)))))
            return
        if type(value) is not int or len(children) == MAX_GROUP:
            raise TransportError('invalid or oversized integration group')
        children.append(value)
    raise TransportError('group reduction budget exceeded')


def parse_formula(formula: str) -> tuple[tuple[Expression, ...], int]:
    tokens = tokenize(formula)
    tasks, values, nodes = ['expression'], [], []
    position = 0
    for _ in range(MAX_TOKENS * 4):
        if not tasks:
            break
        task = tasks.pop()
        if task == 'binary':
            reduce_binary(values, nodes)
            continue
        if position == len(tokens):
            raise TransportError('incomplete formula')
        token = tokens[position]
        position += 1
        if task == 'expression':
            begin_expression(token, tasks, values, nodes)
        elif task == 'operator' and token in BINARY:
            values.append(token)
        elif task == 'group' and token == ';':
            tasks.extend(('group', 'expression'))
        elif task == 'group' and token == '}':
            reduce_group(values, nodes)
        elif task not in ('{', ')') or token != task:
            raise TransportError('ambiguous or malformed formula; parenthesize each binary relation')
    if tasks or position != len(tokens) or len(values) != 1 or type(values[0]) is not int:
        raise TransportError('incomplete formula, trailing content, or parser budget exceeded')
    return tuple(nodes), values[0]


def selected_definitions(senses: dict[str, str]) -> dict[str, str]:
    if len(senses) > 8:
        raise TransportError('operator declaration budget exceeded')
    selected = {}
    for glyph, sense in senses.items():
        key = (glyph, sense)
        if key not in DEFINITIONS:
            raise TransportError('undefined operator meaning: ' + glyph + ' ' + sense)
        selected[glyph] = DEFINITIONS[key]
    return selected


def check_symbols(nodes: tuple[Expression, ...], symbols: dict, senses: dict) -> None:
    used_symbols = {node.symbol for node in nodes if node.symbol}
    used_operators = {node.operator for node in nodes if node.operator}
    if used_symbols != set(symbols):
        raise TransportError('undefined or unused lexicon symbol')
    if used_operators != set(senses):
        raise TransportError('undefined or unused operator meaning')
    selected_definitions(senses)
