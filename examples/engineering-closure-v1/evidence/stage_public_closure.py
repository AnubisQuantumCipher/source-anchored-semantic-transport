"""Copy selected immutable observations; no builds, execution or old receipt edits."""
import hashlib
import json
from pathlib import Path
import stat

P = Path('/dev/shm/semantic-transport-proof-closure-20261029')
W = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
OUT = W / 'examples/engineering-closure-v1'


def need(value, message):
    if not value:
        raise ValueError(message)


def raw(path):
    need(stat.S_ISREG(path.lstat().st_mode), 'regular evidence input required')
    with path.open('rb') as stream:
        data = stream.read(1048577)
    need(len(data) <= 1048576, 'evidence input bound')
    return data


def put(name, data):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(data) == len(data), 'short evidence copy')


def copy_inputs():
    chosen = [(f, 'evidence/' + f.name) for f in sorted(P.iterdir())
              if f.is_file() and f.suffix in ('.json', '.py', '.stdout', '.stderr')
              and f.name != 'storage-preflight.json']
    nested = ('install-current/first-build/receipt.json',
              'install-current/second-build/receipt.json',
              'install-current/paired-comparison.json',
              'install-current/regression/receipt.json',
              'install-current/regression/regression.stdout',
              'install-current/regression/regression.stderr',
              'install-current/product/receipt.json',
              'install-current/portable/receipt.json',
              'bound-native-integration/receipt.json',
              'bound-test-receipts/receipt.json', 'current-export/receipt.json')
    chosen.extend((P / name, 'evidence/' + name) for name in nested)
    for stem in ('test_handoff_prepare', 'test_handoff_reader', 'test_evidence_finish'):
        for suffix in ('.json', '.stdout', '.stderr', '/receipt.json'):
            name = 'current-handoff/' + stem + suffix
            chosen.append((P / name, 'evidence/' + name))
    for label, name in (('core', 'source/obj/gnatprove/gnatprove.out'),
                        ('evaluation', 'source/evaluation/obj/gnatprove/gnatprove.out'),
                        ('bound', 'source/evaluation/bound_proof_obj/gnatprove/gnatprove.out')):
        chosen.append((P / name, 'evidence/proofs/' + label + '.out'))
    for name in ('native-proof-scope-review-20261029.json',
                 'native-closure-review-20261029.json',
                 'native-handoff-closure-review-20261029.json',
                 'native-handoff-closure-review-inventory-addendum-20261029.json',
                 'inherited-test-closure-20261029.json'):
        chosen.append((Path('/dev/shm') / name, 'evidence/reviews/' + name))
    chosen.append((W / 'install/SOURCE.json', 'evidence/current-SOURCE.json'))
    for label in ('first', 'second'):
        for name in ('INSTALL.json', 'RUNTIME.json'):
            chosen.append((P / 'install-current' / (label + '-bundle') / name,
                           'evidence/install-current/' + label + '-' + name))
    need(len(chosen) <= 256, 'evidence count bound')
    return chosen


def bundle_inventory(root):
    result, pending = {}, [root]
    for unused in range(8):
        if not pending:
            break
        for path in sorted(pending.pop().iterdir()):
            info = path.lstat()
            entry = {'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISDIR(info.st_mode):
                entry['kind'] = 'directory'
                pending.append(path)
            else:
                need(stat.S_ISREG(info.st_mode), 'unsafe bundle member')
                with path.open('rb') as stream:
                    data = stream.read(4194305)
                need(len(data) <= 4194304, 'bundle member byte bound')
                entry.update(kind='file', bytes=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
            result[path.relative_to(root).as_posix()] = entry
            need(len(result) <= 128 and len(pending) <= 8, 'bundle inventory bound')
    need(not pending, 'bundle traversal bound')
    return result


def main():
    need(not OUT.exists(), 'create-only evidence directory')
    chosen = copy_inputs()
    need(all(path.is_file() for path, unused in chosen), 'missing evidence input')
    total = 0
    for path, name in chosen:
        data = raw(path)
        total += len(data)
        need(total <= 8388608, 'selected evidence aggregate bound')
        put(name, data)
    review = json.loads(raw(Path('/dev/shm/native-closure-review-20261029.json')))
    for label in ('first', 'second'):
        observed = bundle_inventory(P / 'install-current' / (label + '-bundle'))
        need(observed == review['paired_complete_inventory'], 'bundle changed')
        put('evidence/install-current/' + label + '-bundle-inventory.json',
            (json.dumps(observed, sort_keys=True, indent=2) + '\n').encode())
    caches = {}
    for name in ('attempt-01-proof-state.tar.gz', 'attempt-02-proof-state.tar.gz'):
        path = P / name
        need(path.stat().st_size <= 16777216, 'partial state bound')
        caches[name] = {'bytes': path.stat().st_size,
                       'sha256': hashlib.file_digest(path.open('rb'), 'sha256').hexdigest(),
                       'availability': 'PINNED_LOCAL_ONLY; not needed for receipt checking'}
    put('evidence/partial-proof-state-pins.json',
        (json.dumps(caches, sort_keys=True, indent=2) + '\n').encode())
    expected = {'schema': 'transport/engineering-closure-contract/1',
        'proofs': [], 'suite_counts': {'product': 9, 'bound-native-integration': 22,
          'bound-test-receipts': 13, 'test_handoff_prepare': 13,
          'test_handoff_reader': 13, 'test_evidence_finish': 14},
        'negative_controls': ['changed_source', 'missing_log', 'changed_stream',
          'incomplete_proof_units', 'unproved_check', 'swallowed_suite_failure',
          'skipped_suite', 'changed_installation'],
        'scope': 'Receipt checks retained observations; does not rerun proof or tests.'}
    for item, label, stem, project in zip(review['proofs'], ('core','evaluation','bound'),
          ('core-proof-03','evaluation-proof-03','bound-proof'),
          ('transport.gpr','evaluation/transport_eval.gpr','evaluation/transport_bound_eval_proof.gpr')):
        expected['proofs'].append({'label': label, 'stem': stem, 'project': project,
          'unit_rows': item['unit_rows'], 'total_row': item['total_row']})
    put('contract.json', (json.dumps(expected, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'files':len(chosen), 'bytes':total}))


if __name__ == '__main__':
    main()
