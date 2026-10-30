# QUORUM record input checks

This internal component reads bounded canonical metadata and checks the exact
versioned Body schema. It rejects malformed numbers, duplicate fields, unsafe
schema files, incompatible versions, excessive resources and unknown fields.
It retains Unicode spelling and distinguishes booleans from integers.

Run from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_input.py
python3 -I -S -B -Werror install/check_source.py
```

Add `--evidence /new/path/result.json` to retain every test outcome. The output
file must not exist. Runtime checks use the standard library and the pinned
local schema; they do not fetch definitions or execute imported content.

`transport_quorum_input.check_body_input(raw)` returns either a stage-specific
refusal or `BODY_INPUT_SHAPE_ONLY`. This success does not establish source
integrity, valid references, faithful interpretation, agreement, applicability
or authority. The component is not yet part of the installed decoder.

The raw oracle was written before implementation. The independent shape matrix
contains 207 frozen candidates and observations from `jsonschema` 4.26.0, used
only as a development oracle. CI replays those observations without installing
that package. Oversized inputs and non-integer numeric tokens are excluded from
the private shape comparison and must fail the public reader. Original and
transport development arms use identical annotations and checks; this measures
parity, not a workflow advantage.

Retained corrections matter: the original handwritten V13 expectation wrongly
allowed an extra field; the independent oracle rejected it. The first reader
review found a numeric error-order bug. Later review found a blocking FIFO read,
a missing byte-limit check for constant fields, late quota charging and an
omitted version-refusal rule. Their first outputs remain in the evidence. The
initial public-predicate expectation for V16 is retained, with an explicit
correction tied to the pre-existing protocol. No oracle was changed to accept
an input the contract rejects.

The formula and meaning transport contracts remain separate from these input
checks. Python runtime internals, complete replay, formal component proof and
external product validation remain outside this component's tested claim.
