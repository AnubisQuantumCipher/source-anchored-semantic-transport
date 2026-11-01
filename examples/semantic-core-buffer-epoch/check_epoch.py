"""Seal the listed warning repairs. The v3 receipt stays frozen."""

import hashlib
import json
from pathlib import Path
import stat

FROZEN_RECEIPT = '54c2b2a67acfbda9c6629b6b298d0dca111b1ec384abccca0ab18cfb0180a9a1'
MANIFEST_SHA256 = '9f31e742bf689a65ace792a250622aa2dac74802bf2e8255f4e67489945e40fd'
PATHS = ('src/transport_buffers.adb', 'src/transport_buffers.ads',
         'src/transport_graph_parse.adb', 'src/transport_graphs.adb',
         'src/transport_graphs.ads', 'src/transport_paths.adb',
         'src/transport_paths.ads',
         'src/transport_temporal_format.adb', 'src/transport_temporal_format.ads',
         'src/transport_temporal_parse.adb')
REPLACEMENTS = {
    'src/transport_buffers.adb': (
        (b'Pos := Start + Size + 1;', b'Pos := (Start + Size) + 1;'),),
    'src/transport_buffers.ads': (
        (b"Pos = Pos'Old + Item.Size + 1", b"Pos = (Pos'Old + Item.Size) + 1"),),
    'src/transport_graph_parse.adb': (
        (b'Size > Length + 1 - Pos', b'Size > (Length + 1) - Pos'),
        (b'Wire (Pos + J - 1)', b'Wire ((Pos + J) - 1)'),
        (b'Length /= Pos - 1 + Raw_Count', b'Length /= (Pos - 1) + Raw_Count'),),
    'src/transport_graphs.adb': (
        (b'Original.Data (Left.First + J - 1)', b'Original.Data ((Left.First + J) - 1)'),
        (b'Candidate.Data (Right.First + J - 1)', b'Candidate.Data ((Right.First + J) - 1)'),),
    'src/transport_graphs.ads': (
        (b'G.Nodes (I).Size <= G.Used + 1 - G.Nodes (I).First',
         b'G.Nodes (I).Size <= (G.Used + 1) - G.Nodes (I).First'),
        (b'Original.Data (Original.Nodes (I).First + J - 1)',
         b'Original.Data ((Original.Nodes (I).First + J) - 1)'),
        (b'Candidate.Data (Candidate.Nodes (Map (I)).First + J - 1)',
         b'Candidate.Data ((Candidate.Nodes (Map (I)).First + J) - 1)'),),
    'src/transport_paths.adb': (
        (b'      Result (0) := G.Root;\n',
         b'      Result := [Result with delta 0 => G.Root];\n'),
        (b'         Result (I) := Advance (G, Result (I - 1), Choices (I));\n',
         b'         Result := [Result with delta I =>\n'
         b'           Advance (G, Result (I - 1), Choices (I))];\n'),),
    'src/transport_paths.ads': (
        (b'Left.Data (Left.Nodes (Left_At).First + J - 1)',
         b'Left.Data ((Left.Nodes (Left_At).First + J) - 1)'),
        (b'Right.Data (Right.Nodes (Right_At).First + J - 1)',
         b'Right.Data ((Right.Nodes (Right_At).First + J) - 1)'),),
    'src/transport_temporal_format.adb': (
        (b'return Tick (Wire (4 * Index + 1)) * 16_777_216 +\n'
         b'        Tick (Wire (4 * Index + 2)) * 65_536 +\n'
         b'        Tick (Wire (4 * Index + 3)) * 256 + Tick (Wire (4 * Index + 4));',
         b'return ((Tick (Wire (4 * Index + 1)) * 16_777_216 +\n'
         b'        Tick (Wire (4 * Index + 2)) * 65_536) +\n'
         b'        Tick (Wire (4 * Index + 3)) * 256) + Tick (Wire (4 * Index + 4));'),
        (b'   function Projection (Wire : Wire_Buffer; Count : Field_Count) return Fields is\n'
         b'      Result : Fields := [others => 0];\n'
         b'   begin\n'
         b'      for I in 1 .. Count loop\n'
         b'         Result (I) := Value (Wire, I);\n'
         b'         pragma Loop_Invariant\n'
         b'           (for all J in 1 .. I => Result (J) = Value (Wire, J));\n'
         b'         pragma Loop_Invariant (for all J in I + 1 .. Max_Fields => Result (J) = 0);\n'
         b'      end loop;\n'
         b'      return Result;\n'
         b'   end Projection;\n',
         b'   function Projection (Wire : Wire_Buffer; Count : Field_Count) return Fields is\n'
         b'     ([for I in Field_Index => (if I <= Count then Value (Wire, I) else 0)]);\n'),),
    'src/transport_temporal_format.ads': (
        (b'Tick (Wire (4 * Index + 1)) * 16_777_216 +\n'
         b'       Tick (Wire (4 * Index + 2)) * 65_536 +\n'
         b'       Tick (Wire (4 * Index + 3)) * 256 + Tick (Wire (4 * Index + 4));',
         b'((Tick (Wire (4 * Index + 1)) * 16_777_216 +\n'
         b'         Tick (Wire (4 * Index + 2)) * 65_536) +\n'
         b'        Tick (Wire (4 * Index + 3)) * 256) + Tick (Wire (4 * Index + 4));'),),
    'src/transport_temporal_parse.adb': (
        (b'Tick (Wire (Pos)) * 16_777_216 + Tick (Wire (Pos + 1)) * 65_536 +\n'
         b'       Tick (Wire (Pos + 2)) * 256 + Tick (Wire (Pos + 3))',
         b'((Tick (Wire (Pos)) * 16_777_216 + Tick (Wire (Pos + 1)) * 65_536) +\n'
         b'        Tick (Wire (Pos + 2)) * 256) + Tick (Wire (Pos + 3))'),
        (b'return Tick (Wire (Pos)) * 16_777_216 +\n'
         b'        Tick (Wire (Pos + 1)) * 65_536 +\n'
         b'        Tick (Wire (Pos + 2)) * 256 + Tick (Wire (Pos + 3));',
         b'return ((Tick (Wire (Pos)) * 16_777_216 +\n'
         b'        Tick (Wire (Pos + 1)) * 65_536) +\n'
         b'        Tick (Wire (Pos + 2)) * 256) + Tick (Wire (Pos + 3));'),
        (b'      for I in 1 .. Used loop\n'
         b'         Values (I) := Word (Wire, 4 * I + 1);\n'
         b'         pragma Loop_Invariant\n'
         b'           (for all J in 1 .. I => Values (J) = Word (Wire, 4 * J + 1));\n'
         b'         pragma Loop_Invariant (for all J in I + 1 .. Max_Fields => Values (J) = 0);\n'
         b'      end loop;\n',
         b'      Values := [for I in Field_Index =>\n'
         b'        (if I <= Used then Word (Wire, 4 * I + 1) else 0)];\n'),),
}
EPOCH = 'examples/semantic-core-buffer-epoch'
CAP = 1048576
EXPECTED = {
    EPOCH + '/check_epoch.py',
    EPOCH + '/manifest.json',
    EPOCH + '/test_epoch.py',
    EPOCH + '/historical/src/transport_buffers.adb',
    EPOCH + '/historical/src/transport_buffers.ads',
    EPOCH + '/historical/src/transport_graph_parse.adb',
    EPOCH + '/historical/src/transport_graphs.adb',
    EPOCH + '/historical/src/transport_graphs.ads',
    EPOCH + '/historical/src/transport_paths.adb',
    EPOCH + '/historical/src/transport_paths.ads',
    EPOCH + '/historical/src/transport_temporal_format.adb',
    EPOCH + '/historical/src/transport_temporal_format.ads',
    EPOCH + '/historical/src/transport_temporal_parse.adb',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def read_file(root, name):
    path = Path(name)
    require(not path.is_absolute() and path.parts and
            all(part not in ('.', '..') for part in path.parts), 'unsafe epoch path')
    target = root
    for part in path.parts:
        target = target / part
        require(not target.is_symlink(), 'epoch symlink refused')
    info = target.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= CAP, 'epoch file cap/type')
    raw = target.read_bytes()
    require(len(raw) == info.st_size, 'epoch file changed')
    return raw


def files_under(root):
    base = root / EPOCH
    pending, found = [base], set()
    for _unused in range(32):
        if not pending:
            return found
        current = pending.pop()
        require(current.is_dir() and not current.is_symlink(), 'epoch directory')
        for child in current.iterdir():
            require(not child.is_symlink(), 'epoch symlink refused')
            if child.is_dir():
                pending.append(child)
            else:
                require(child.is_file(), 'epoch entry')
                found.add(child.relative_to(root).as_posix())
                require(len(found) <= 16, 'epoch file cap')
    require(not pending, 'epoch walk cap')
    return found


def receipt_rows(receipt):
    require(type(receipt) is dict and type(receipt.get('source_files')) is list,
            'receipt rows')
    rows = {}
    for item in receipt['source_files']:
        require(type(item) is dict and item.get('path') not in rows, 'receipt row')
        if item.get('path') in PATHS:
            rows[item['path']] = item
    require(set(rows) == set(PATHS), 'buffer rows missing from sealed receipt')
    return rows


def derived(root, receipt):
    rows = receipt_rows(receipt)
    files = {}
    for name in PATHS:
        historical = read_file(root, EPOCH + '/historical/' + name)
        current = read_file(root, name)
        edited = historical
        for old, new in REPLACEMENTS[name]:
            require(edited.count(old) == 1, 'parenthesis site missing: ' + name)
            edited = edited.replace(old, new, 1)
        require(edited == current, 'source edit is not the listed parentheses: ' + name)
        historical_pin = pin(historical)
        require(rows[name]['bytes'] == historical_pin['bytes'] and
                rows[name]['sha256'] == historical_pin['sha256'],
                'historical bytes differ from sealed receipt: ' + name)
        files[name] = {'current': pin(current), 'historical': historical_pin}
    return {'files': files, 'frozen_receipt_sha256': FROZEN_RECEIPT,
            'schema': 'sast/semantic-core-buffer-epoch/1'}


def verify(root, receipt):
    require(files_under(root) == EXPECTED, 'buffer epoch roster')
    raw = read_file(root, EPOCH + '/manifest.json')
    require(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256, 'buffer epoch manifest pin')
    parsed = json.loads(raw)
    body = canonical(derived(root, receipt))
    require(raw == body == canonical(parsed), 'buffer epoch manifest differs from sources')
    return {'manifest_sha256': MANIFEST_SHA256, 'status': 'BUFFER_EPOCH_CHECKED'}
