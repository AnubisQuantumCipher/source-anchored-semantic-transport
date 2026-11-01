# Replay a source-bound assessment

QUORUM now has one complete replay path. A fresh process verifies the decoder and
checker inputs, recovers records from a meaning ZIP or an original-document
index, and recomputes the result. A supplied verdict cannot replace that work.

The result keeps the source quotations, declared structure, dependency paths,
context changes, reading counts, challenges and withdrawals together. In this
fixture, a changed context definition makes a claim need revalidation even
though its quoted source bytes have not changed. An illustrative supporting
reading remains a recorded reading; it does not establish truth or permission.

## Try the portable controls

From the repository root, with Python 3.14:

```sh
python3 -I -S -B -Werror install/test_quorum_replay.py
python3 -I -S -B -O -Werror install/test_quorum_replay.py
```

These commands compare complete results with the frozen literal expectations.
They use synthetic host observations and exercise the private core. The separate
[ZIP recipient preparation](PREPARATION.md) exercises the actual installed
decoder and public bootstrap. It requires the exact declared decoder bundle and
independently held identities; a fresh source build is not assumed compatible.

The [share text](recipient/share.txt), [meaning ZIP](recipient/meaning.zip), and
[readable lexicon](recipient/lexicon.md) are a matched development example.
The package reference is an attachment reference, not a public hosting URL.
This small mechanical fixture tests the replay plumbing; it is not a realistic
legal document or a polished example of the intended visible formula.

## Interface and validation order

`install/transport_quorum_bootstrap.py` is the public process entry point. It
accepts a closed invocation file and independently held invocation and entry
digests. It verifies the actual Python executable, checker files, installed
decoder, matching source inventory and installation snapshot before loading
product modules. Owned source bytes are compiled directly, so a stale bytecode
cache cannot substitute for the checked file.

The same internal replay core serves both input arms. Its phases are:

```text
PREPARSE → BOUNDS → SCHEMA → IDENTITY → REFERENCES → GRAPHS
         → RECOMPUTATION → IMPORT_COMPARISON → OUTPUT_BOUND
```

The [wire schema](../../tools/transport_quorum_body.schema.json) and
[protocol rules](../../tools/transport_quorum_protocol-rules.json) fix the record
types, operator meanings, ordering, limits and refusal behavior. The receiving
ZIP path obtains the Body and original bytes from the archive. It succeeds when
the corresponding evaluator-side source paths do not exist. Optional imported
results are compared with recomputation, never used as authority.

Successful replay writes the complete canonical result plus a newline to
stdout and a separate host qualification receipt to stderr. Replay refusals
return exit status 1; bootstrap refusals return 2. Required evidence is not
trimmed to fit an output limit. Imported content is data; the decoder does not
execute supplied code or fetch undeclared resources.

## Evidence and limitations

The [report](REPORT.md) separates actual CLI runs, instrumented process probes,
private helper checks and portable core tests. Original expected files and
failed observations remain available alongside explicitly justified corrections.
The original-document arm uses the same sources, annotations, checker and rules.
Matching results demonstrate parity on these development cases, not an advantage
over originals.

These are tested Python properties. The existing Ada/SPARK sources and proof
receipts are unchanged; their proofs do not extend to this orchestration layer.
Semantic entailment, complete capture, authentication and current authority
remain outside the checked claim. External human validation and a measured
continuation benefit remain pending.
