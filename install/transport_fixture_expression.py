"""Bounded data-only patching and Boolean fixture interpretation.

This test adapter executes no supplied Python, imports or commands. Python's AST
parser and the trusted helper imports remain in the trusted computing base.
Passing controls is TESTED behavior, not formal proof or semantic preservation.
The caller holds the base digest and the function/domain specification externally.
"""

import ast
from dataclasses import dataclass
import io
import keyword
import tokenize

from transport_install_support import require, sha

MAX_BYTES = 4096
MAX_NODES = 512
MAX_DEPTH = 48
MAX_TOKENS = 1024
MAX_PARAMETERS = 16
MAX_NAME = 64
MIN_INTEGER = -1000000
MAX_INTEGER = 1000000


@dataclass(frozen=True, slots=True)
class Domain:
    kind: str
    lower: int = 0
    upper: int = 0


@dataclass(frozen=True, slots=True)
class Node:
    operation: str
    payload: object
    children: tuple
    kind: str


@dataclass(frozen=True, slots=True)
class Program:
    """Immutable in-process result; not an accepted serialized input format."""

    source_sha256: str
    parameters: tuple
    domains: tuple
    nodes: tuple
    root: int


def _utf8(raw, label):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, label + ': byte bound/type')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError(label + ': invalid UTF8') from error
    require('\0' not in text, label + ': NUL refused')
    return text


def apply_replacement(base, expected_sha256, before, after):
    """Apply exactly one UTF8 byte replacement; overlapping matches also refuse."""
    _utf8(base, 'base')
    require(type(expected_sha256) is str and len(expected_sha256) == 64
            and all(char in '0123456789abcdef' for char in expected_sha256),
            'held base digest format')
    require(sha(base) == expected_sha256, 'held base digest mismatch')
    _utf8(before, 'before')
    _utf8(after, 'after')
    require(bool(before), 'empty replacement site')
    offset = base.find(before)
    require(offset >= 0, 'replacement site absent')
    require(base.find(before, offset + 1) < 0, 'replacement site not unique')
    require(len(base) - len(before) + len(after) <= MAX_BYTES, 'result byte bound')
    result = base[:offset] + after + base[offset + len(before):]
    _utf8(result, 'result')
    receipt = dict(schema='transport/fixture-replacement/1', status='APPLIED',
                   base_sha256=expected_sha256, result_sha256=sha(result),
                   before_sha256=sha(before), after_sha256=sha(after),
                   base_bytes=len(base), result_bytes=len(result),
                   before_bytes=len(before), after_bytes=len(after),
                   replacement_count=1, byte_offset=offset,
                   scope='EXACT_BYTES_ONLY', execution_authority='NONE',
                   semantics='NOT_ASSESSED')
    return result, receipt


def _name(value):
    require(type(value) is str and 0 < len(value) <= MAX_NAME
            and value.isascii() and value.isidentifier()
            and not keyword.iskeyword(value), 'invalid fixed identifier')


def _domain(value):
    require(type(value) is dict and len(value) <= 3, 'domain object/type bound')
    require(type(value.get('type')) is str and value['type'] in ('boolean', 'integer'),
            'unsupported domain type')
    if value['type'] == 'boolean':
        require(set(value) == {'type'}, 'boolean domain keys')
        return Domain('boolean')
    require(set(value) == {'type', 'min', 'max'}, 'integer domain keys')
    low, high = value['min'], value['max']
    require(type(low) is int and type(high) is int
            and MIN_INTEGER <= low <= high <= MAX_INTEGER, 'integer domain bounds/type')
    return Domain('integer', low, high)


def _specification(function_name, parameter_names, domains):
    _name(function_name)
    require(type(parameter_names) in (list, tuple)
            and len(parameter_names) <= MAX_PARAMETERS, 'parameter list/type bound')
    for name in parameter_names:
        _name(name)
    require(len(set(parameter_names)) == len(parameter_names), 'duplicate parameters')
    require(type(domains) is dict and len(domains) == len(parameter_names)
            and all(type(name) is str for name in domains)
            and set(domains) == set(parameter_names), 'domain keys/type differ')
    return tuple(parameter_names), tuple(_domain(domains[name]) for name in parameter_names)


def _lexical_check(text):
    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    try:
        for _ in range(MAX_TOKENS):
            token = next(tokens)
            if token.type == tokenize.NAME:
                require(token.string.isascii() and len(token.string) <= MAX_NAME,
                        'non-ASCII or oversized identifier token')
            if token.type == tokenize.ENDMARKER:
                return
    except (tokenize.TokenError, IndentationError, StopIteration) as error:
        raise ValueError('malformed token stream') from error
    raise ValueError('token count bound')


def _bounded_tree(module):
    pending, visited = [(module, 1)], 0
    for _ in range(MAX_NODES):
        if not pending:
            return
        node, depth = pending.pop()
        require(depth <= MAX_DEPTH, 'AST depth bound')
        visited += 1
        children = ast.iter_child_nodes(node)
        for _ in range(MAX_NODES + 1):
            child = next(children, None)
            if child is None:
                break
            require(visited + len(pending) < MAX_NODES, 'AST node bound')
            pending.append((child, depth + 1))
    require(not pending, 'AST node bound')


def _function(module, function_name, parameters):
    require(type(module) is ast.Module and len(module.body) == 1
            and not module.type_ignores, 'single function module required')
    function = module.body[0]
    require(type(function) is ast.FunctionDef and function.name == function_name,
            'fixed ordinary function required')
    require(not function.decorator_list and function.returns is None
            and function.type_comment is None and not getattr(function, 'type_params', []),
            'decorator/annotation/type parameters refused')
    arguments = function.args
    require(not arguments.posonlyargs and not arguments.kwonlyargs
            and arguments.vararg is None and arguments.kwarg is None
            and not arguments.defaults and not arguments.kw_defaults, 'ordinary positional arguments required')
    require(tuple(item.arg for item in arguments.args) == parameters, 'fixed ordered arguments differ')
    require(all(item.annotation is None and item.type_comment is None for item in arguments.args),
            'argument annotations refused')
    require(len(function.body) == 1 and type(function.body[0]) is ast.Return
            and function.body[0].value is not None, 'single valued return required')
    return function.body[0].value


def _constant(value):
    require(type(value) in (bool, int), 'constant type refused')
    require(type(value) is bool or MIN_INTEGER <= value <= MAX_INTEGER, 'integer literal bound')
    return 'constant', value, ()


def _comparison(operator):
    if type(operator) is ast.Eq:
        return 'eq'
    if type(operator) is ast.NotEq:
        return 'ne'
    if type(operator) is ast.Lt:
        return 'lt'
    if type(operator) is ast.LtE:
        return 'le'
    if type(operator) is ast.Gt:
        return 'gt'
    if type(operator) is ast.GtE:
        return 'ge'
    raise ValueError('comparison operator refused')


def _shape(node):
    if type(node) is ast.Constant:
        return _constant(node.value)
    if type(node) is ast.Name:
        require(type(node.ctx) is ast.Load, 'name context refused')
        return 'name', node.id, ()
    if type(node) is ast.UnaryOp:
        if type(node.op) is ast.Not:
            return 'not', None, (node.operand,)
        require(type(node.op) in (ast.USub, ast.UAdd)
                and type(node.operand) is ast.Constant and type(node.operand.value) is int,
                'only directly signed integer literals permitted')
        value = node.operand.value
        return _constant(-value if type(node.op) is ast.USub else value)
    if type(node) is ast.BoolOp:
        require(type(node.op) in (ast.And, ast.Or) and 2 <= len(node.values) <= MAX_NODES,
                'Boolean operator/arity refused')
        return 'and' if type(node.op) is ast.And else 'or', None, tuple(node.values)
    if type(node) is ast.Compare:
        require(0 < len(node.ops) == len(node.comparators) < MAX_NODES, 'comparison arity refused')
        return 'compare', tuple(_comparison(op) for op in node.ops), (node.left, *node.comparators)
    raise ValueError('expression node refused: ' + type(node).__name__)


def _kind(operation, payload, child_kinds, kinds):
    if operation == 'name':
        require(payload in kinds, 'undeclared name')
        return kinds[payload]
    if operation == 'constant':
        return 'boolean' if type(payload) is bool else 'integer'
    if operation in ('not', 'and', 'or'):
        require(all(kind == 'boolean' for kind in child_kinds), 'Boolean operands required')
    else:
        require(operation == 'compare' and len(set(child_kinds)) == 1,
                'mixed comparison types refused')
    return 'boolean'


def _nodes(expression, parameters, domains):
    pending, shapes, indexes, nodes = [(expression, False)], {}, {}, []
    kinds = {name: domain.kind for name, domain in zip(parameters, domains)}
    for _ in range(MAX_NODES * 2):
        if not pending:
            require(nodes[-1].kind == 'boolean', 'Boolean return required')
            return tuple(nodes), len(nodes) - 1
        node, ready = pending.pop()
        if not ready:
            operation, payload, children = _shape(node)
            shapes[node] = operation, payload, children
            pending.append((node, True))
            pending.extend((child, False) for child in reversed(children))
            require(len(shapes) <= MAX_NODES and len(pending) <= MAX_NODES * 2, 'expression work bound')
        else:
            operation, payload, children = shapes[node]
            child_indexes = tuple(indexes[child] for child in children)
            kind = _kind(operation, payload, tuple(nodes[index].kind for index in child_indexes), kinds)
            indexes[node] = len(nodes)
            nodes.append(Node(operation, payload, child_indexes, kind))
    raise ValueError('expression step bound')


def parse_function(source, function_name, parameter_names, domains):
    """Parse and type-check; comments, parentheses and integer spellings are data.

    Identifiers are ASCII. Ordinary positional parameters only. Direct unary plus
    and minus are supported for integer literals; ordered Boolean comparisons are
    supported. Type comments and all other annotations are refused.
    """
    text = _utf8(source, 'source')
    parameters, ordered_domains = _specification(function_name, parameter_names, domains)
    _lexical_check(text)
    try:
        module = ast.parse(text, filename='<bounded-fixture>', mode='exec', type_comments=True)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError, Warning) as error:
        raise ValueError('AST parse refused') from error
    _bounded_tree(module)
    expression = _function(module, function_name, parameters)
    nodes, root = _nodes(expression, parameters, ordered_domains)
    return Program(sha(source), parameters, ordered_domains, nodes, root)


def _state(program, state):
    require(type(state) is dict and len(state) == len(program.parameters)
            and all(type(name) is str for name in state)
            and set(state) == set(program.parameters), 'state keys/type differ')
    for name, domain in zip(program.parameters, program.domains):
        value = state[name]
        if domain.kind == 'boolean':
            require(type(value) is bool, 'state Boolean type')
        else:
            require(type(value) is int and domain.lower <= value <= domain.upper,
                    'state integer type/domain bound')


def _compare(operator, left, right):
    if operator == 'eq':
        return left == right
    if operator == 'ne':
        return left != right
    if operator == 'lt':
        return left < right
    if operator == 'le':
        return left <= right
    if operator == 'gt':
        return left > right
    require(operator == 'ge', 'invalid internal comparison')
    return left >= right


def _value(node, values, state):
    if node.operation == 'constant':
        return node.payload
    if node.operation == 'name':
        return state[node.payload]
    operands = tuple(values[index] for index in node.children)
    if node.operation == 'not':
        return not operands[0]
    if node.operation == 'and':
        return all(operands)
    if node.operation == 'or':
        return any(operands)
    require(node.operation == 'compare', 'invalid internal operation')
    for index, operator in enumerate(node.payload):
        if not _compare(operator, operands[index], operands[index + 1]):
            return False
    return True


def evaluate(program, state):
    """Evaluate an in-process parse result against exactly the supplied state.

    Every accepted subexpression is pure and total for its checked domains.
    Visiting them in postorder has the same result as Python short-circuiting;
    no supplied callable, attribute, import, command or hidden binding is used.
    The program must be the unchanged object returned by parse_function.
    """
    require(type(program) is Program and 0 < len(program.nodes) <= MAX_NODES,
            'in-process parsed program required')
    _state(program, state)
    values = []
    for node in program.nodes:
        values.append(_value(node, values, state))
    result = values[program.root]
    require(type(result) is bool, 'internal non-Boolean result')
    return result
