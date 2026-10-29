"""Versioned documentary norm/reference definitions. No runtime authority."""

GRAMMAR_V2 = 'transport/meaning/2'
PLAN_V2 = 'transport/encoding-plan/2'
MAX_MENTIONS = 8
EXTENSIONS = {
    'permission_after': (('prop', 'prop'), 'prop',
        'Declared permission for the first action subject to the necessary guard that the second has completed earlier. The guard alone is not declared sufficient for permission; no occurrence, approval, truth or execution authority is asserted.'),
    'must_before': (('prop', 'prop'), 'prop',
        'Declared obligation to perform the first action, with precedence before the second if that boundary occurs. No obligation or prediction that the boundary occurs; no deadline is inferred if it does not occur.'),
    'part_of': (('term', 'text'), 'term',
        'Named component of the first referenced entity, with exact field wording in the second operand. Ownership is declared, not observed; no storage layout is inferred.'),
    'value_of': (('term', 'text'), 'value',
        'Named value owned by the first referenced entity, with exact field wording in the second operand. Not an evaluated value, conversion, wire layout or authenticated observation.'),
    'copy_unchanged': (('term', 'value'), 'prop',
        'Declared copying into the first destination of the second identified source value without alteration. The source value retains its owner; no destination field or representation is invented. comparison=unspecified leaves the equality/representation domain unresolved, not bytewise verified.'),
}
REFERENCE_DEFINITION = {
    'args': ['optional-scope-var'], 'result': 'term',
    'definition': 'Exact source mentions declared to denote one reference group. id distinguishes groups. relationship=bound-variable denotes its single scope variable; dependent denotes one role within that scope, without asserting existence or uniqueness; document has no bound scope. Same spelling alone never merges groups. Alias interpretation is unproved.'}
