"""Bounded QUORUM metadata input; shape success is not replay acceptance."""

from transport_schema import canonical, json_value
from transport_wire import TransportError

MAX_INPUT = 65536
MAX_DEPTH = 12
MAX_DIGITS = 20
MAX_VISITS = 65536


class InputError(Exception):
    """An explicit component refusal, never a partial replay result."""

    def __init__(self, code: str, stage: str = 'PREPARSE') -> None:
        super().__init__(code)
        self.code = code
        self.stage = stage


def _token(raw: bytes, start: int, end: int) -> None:
    if start == end:
        return
    size = end - start
    if raw[start] in b'-+.NI':
        raise InputError('INPUT_INTEGER_TOKEN')
    if 48 <= raw[start] <= 57:
        for index in range(start, end):
            if not 48 <= raw[index] <= 57:
                raise InputError('INPUT_INTEGER_TOKEN')
        if size > 1 and raw[start] == 48:
            raise InputError('INPUT_INTEGER_TOKEN')
        if size > MAX_DIGITS:
            raise InputError('INPUT_INTEGER_BOUND')
    elif size > 5 or raw[start:end] not in (b'null', b'true', b'false'):
        raise InputError('INPUT_JSON')


def _lexical(raw: bytes) -> None:
    quoted, escaped, depth, start = False, False, 0, 0
    for index, byte in enumerate(raw):
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
                start = index + 1
        elif byte in b' \t\r\n[]{}:,"':
            _token(raw, start, index)
            start = index + 1
            if byte == 34:
                quoted = True
            elif byte in b'[{':
                depth += 1
                if depth > MAX_DEPTH:
                    raise InputError('INPUT_DEPTH')
            elif byte in b']}':
                depth -= 1
                if depth < 0:
                    raise InputError('INPUT_JSON')
    if not quoted:
        _token(raw, start, len(raw))
    if quoted or depth != 0:
        raise InputError('INPUT_JSON')


def _scalars(value: object) -> None:
    # One iterator per active container; no attacker-sized pending work list.
    stack = [iter((value,))]
    for _ in range(MAX_VISITS):
        if not stack:
            return
        current = next(stack[-1], StopIteration)
        if current is StopIteration:
            stack.pop()
        elif type(current) is str:
            try:
                current.encode('utf-8')
            except UnicodeError as error:
                raise InputError('INPUT_ENCODING') from error
        elif type(current) is dict:
            stack.append(iter(current.items()))
        elif type(current) in (list, tuple):
            stack.append(iter(current))
        if len(stack) > 128:
            raise InputError('INPUT_WORK_BOUND')
    raise InputError('INPUT_WORK_BOUND')


def _read_value(raw: object) -> object:
    if type(raw) is not bytes:
        raise InputError('INPUT_TYPE')
    if not 0 < len(raw) <= MAX_INPUT:
        raise InputError('INPUT_BYTE_BOUND')
    try:
        raw.decode('utf-8')
    except UnicodeError as error:
        raise InputError('INPUT_ENCODING') from error
    if raw.startswith(b'\xef\xbb\xbf'):
        raise InputError('INPUT_ENCODING')
    _lexical(raw)
    try:
        value = json_value(raw, MAX_INPUT)
    except TransportError as error:
        raise InputError('INPUT_JSON') from error
    _scalars(value)
    return value


def _canonical_bytes(value: object, raw: bytes) -> None:
    if canonical(value) != raw:
        raise InputError('INPUT_NONCANONICAL', 'CANONICAL_BYTES')


def _error(error: InputError) -> dict[str, str]:
    return dict(status='error', stage=error.stage, error=error.code)


def check_canonical_value(raw: object) -> dict[str, str]:
    """Internal reader diagnostic; does not check the Body schema."""
    try:
        value = _read_value(raw)
        _canonical_bytes(value, raw)
    except InputError as error:
        return _error(error)
    return dict(status='ok', stage='CANONICAL_VALUE_ONLY')


def check_body_input(raw: object) -> dict[str, str]:
    """Validate metadata input only; no source, interpretation or authority claim."""
    from transport_quorum_shape import check_shape, load_schema
    try:
        schema = load_schema()
        value = _read_value(raw)
        check_shape(value, schema)
        _canonical_bytes(value, raw)
    except InputError as error:
        return _error(error)
    return dict(status='ok', stage='BODY_INPUT_SHAPE_ONLY')
