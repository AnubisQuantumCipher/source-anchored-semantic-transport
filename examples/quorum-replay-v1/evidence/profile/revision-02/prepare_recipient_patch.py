"""Narrow source-only receiving adapter repair; no candidate execution."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')
S=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/install/transport_quorum_bootstrap.py')
t=S.read_text();before=t.encode()
if hashlib.sha256(before).hexdigest()!='da3d7994a43a7eccc232594e864b4dd1c299b7d83f3deeabef7d0235bcc3c751':raise ValueError('sourcefreeze mismatch')
(P/'bootstrap-da3d-firstpair-qualified.py').write_bytes(before)
a=t.index('def _originals(');b=t.index('\n\ndef _original_index(',a)
t=t[:a]+'''def _originals(inv):
    result = []
    for row in inv['originals']:
        raw = _matches(_read(row['path'], CAP), row['key'], 'CHECKER_FILE_IDENTITY')
        result.append((row['alias'], dict(row['key']), raw))
    return tuple(result)


def _auxiliary(inv):
    row = inv['auxiliary']
    if row is None:
        return None
    raw = _matches(_read(row['path'], CAP), row['key'], 'CHECKER_FILE_IDENTITY')
    return row['alias'], dict(row['key']), raw, dict(row['held_key'])
'''+t[b:]
a=t.index('def _transport(');b=t.index('\n\ndef _arguments(',a)
t=t[:a]+'''def _transport(inv, package, allowed):
    share = _carrier(inv['share'], 131072)
    module = _load('transport_mcp', allowed)
    try:
        receiver = module.Receiver(share, package, inv['share']['identity'])
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
        raise HostError('CHECKER_FILE_IDENTITY') from error
    _audit(allowed)
    declarations = {row['alias']: row['key'] for row in inv['originals']}
    _need(len(declarations) == len(inv['originals']) and 'Q_RECORDS' not in declarations,
          'CHECKER_FILE_IDENTITY')
    actual = receiver.decoded['sources']
    expected_ids = sorted(list(declarations) + ['Q_RECORDS'], key=_canonical)
    _need(type(actual) is list and [row['id'] for row in actual] == expected_ids,
          'CHECKER_FILE_IDENTITY')
    _need(receiver.decoded['schema'] == 'transport/decoded/1', 'CHECKER_FILE_IDENTITY')
    for field in ('interpretations', 'uncertainties', 'relations'):
        _need(receiver.decoded[field] == [], 'CHECKER_FILE_IDENTITY')
    body, originals = None, []
    for row in actual:
        _need(row['label'] == 'Exact fixture ' + row['id']
              and row['media_type'] == 'application/octet-stream'
              and row['provenance'] == 'Manually supplied frozen original bytes; no semantic qualification.',
              'CHECKER_FILE_IDENTITY')
        raw = row['data']
        _need(type(raw) is bytes, 'CHECKER_FILE_IDENTITY')
        _matches(raw, row, 'CHECKER_FILE_IDENTITY')
        if row['id'] == 'Q_RECORDS':
            body = _matches(raw, inv['body'], 'CHECKER_FILE_IDENTITY')
        else:
            key = dict(declarations[row['id']])
            _matches(raw, key, 'CHECKER_FILE_IDENTITY')
            originals.append((row['id'], key, raw))
    _need(type(body) is bytes, 'CHECKER_FILE_IDENTITY')
    return body, tuple(originals)
'''+t[b:]
t=t.replace("    body = _carrier(inv['body'], 131072)\n    package = _carrier(inv['package'], 131072)\n    originals, auxiliary = _originals(inv, body)\n    if inv['arm'] == 'transport':\n        _transport(inv, package, body, originals, allowed)\n    else:\n        _original_index(package, body, originals)","    package = _carrier(inv['package'], 131072)\n    auxiliary = _auxiliary(inv)\n    if inv['arm'] == 'transport':\n        body, originals = _transport(inv, package, allowed)\n    else:\n        body = _carrier(inv['body'], 131072)\n        originals = _originals(inv)\n        _original_index(package, body, originals)")
after=t.encode();ast.parse(after)
(P/'bootstrap-recipient-candidate.py').write_bytes(after)
(P/'bootstrap-recipient.patch').write_text(''.join(difflib.unified_diff(before.decode().splitlines(True),t.splitlines(True),fromfile=str(S),tofile=str(S))))
def write(name,v):
 raw=json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode();(P/name).write_bytes(raw);return hashlib.sha256(raw).hexdigest()
c={'schema':'quorum/bootstrap-receiving-contract/1','owner_adoption':'Explicit root after retained da3d firstpair normal/-O exactPASS; no first newcode execution before source/map review and freeze03.','previous_source_sha256':hashlib.sha256(before).hexdigest(),'source_sha256':hashlib.sha256(after).hexdigest(),'boundary':'Transport reads actualBodyQ and mainoriginals solely from qualifiedReceiver ZIP source rows. Body.path/originals[].path remain wellformed required schema metadata but are explicitly ignored transport evaluatorreferences; nonexistent sidecars permitted. No separate mainoriginal files in freshrecipient demonstration. Actualchecker/qualifieddecoder/code-root setup remains independent prerequisite, not candidate original source data.','transport_reads':['Request actualcarrier','Envelope actualcarrier','ZIP actualcarrier','share actualcarrier','optional outerauxiliary actualcarrier','fixed hostqualification/schema/protocol/code files'], 'transport_integrity':'Exactly canonicalaliasorder includingQ, fixedfiniteemptyannotation plan; each actualrecovered rawbytes len/hash matches heldBody or explicit alias->complete SourceKey metadata. Logical source IDs never inferred from digest/alias. Only owneddecodedbytes passed to unchanged private replay; no candidateBody parse/semantic admission in adapter.','original_arm':'ActualBody+originals files and canonicalindex unchanged; originalbaseline hasnoZIPpreparation/decode. Optionalauxiliary remains separatelyheld file outsidemainRequest closure.','same_expected_semantics':'All15 priorClaim/impact/reading/refusal expected values unchanged. Only newchecker/descriptor/Request codeidentity pins mechanically rebound; perarm normalization stilltop-level Request only.','source_only':True}
print('contract',write('bootstrap-receiving-contract.json',c))
base=json.loads((P/'literal-controls'/'F02_TRANSPORT_ACCEPT'/'expected.json').read_bytes())
controls={'schema':'quorum/bootstrap-sidecar-absence-manual-oracle/1','source_sha256':hashlib.sha256(after).hexdigest(),'before_first_new_execution':True,'cases':[{'id':'A01_TRANSPORT_NO_MAIN_SIDECARS','base':'F02_TRANSPORT_ACCEPT','mutation':'Set invocation.body.path and every invocation.originals[].path to distinct wellformed absolute nonexistent paths; keepallotheractualcarrierpins/bodykey/sourcekeys/ZIP/share/Request/Envelope unchanged. Harness independentlyassertspathexistencefalse. Rebindonlyinvocationheldhash andpermittednewchecker/Request codepins.','expected_exit':0,'expected_stdout':base,'expected_stderr':'Exact actual frozen transport qualified modulemap+hostsuccess receipt withmechanicalcodeidentity pins; no ordinarysidecar path contributes.','io_rule':'No attempted read of ordinary Body/original path; actualdecoded ZIP bytes supplyallmaininputs.'},{'id':'A02_ORIGINAL_MISSING_BODY','base':'F01_ORIGINAL_ACCEPT','mutation':'Set invocation.body.path to wellformed absent absolutepath, retain actualfilepin expectedBodybytes; rebindinvocationheldhash only.','expected_exit':2,'expected_stdout':{'schema':'quorum/bootstrap-refusal/1','status':'REFUSED_HOST_PRECONDITION','authority':'NONE','reason':'CHECKER_FILE_IDENTITY'},'expected_stderr_hex':''},{'id':'A03_ORIGINAL_MISSING_ONE_SOURCE','base':'F01_ORIGINAL_ACCEPT','mutation':'Set first invocation.originals[].path to wellformed absent absolutepath, retain fullheldSourceKey; rebindinvocationheldhash only.','expected_exit':2,'expected_stdout':{'schema':'quorum/bootstrap-refusal/1','status':'REFUSED_HOST_PRECONDITION','authority':'NONE','reason':'CHECKER_FILE_IDENTITY'},'expected_stderr_hex':''}], 'no_outcome_derivation':'Complete expected accepted semantic object copied from previouslymanual F02; no newcode imported or executed.'}
print('absenceoracle',write('bootstrap-sidecar-absence-oracle.json',controls))
S.write_bytes(after)
print('source',len(after),hashlib.sha256(after).hexdigest())
