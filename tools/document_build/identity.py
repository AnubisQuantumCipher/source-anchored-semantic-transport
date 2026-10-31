"""Recheck only the declared roster; hostile-host/TOCTOU attestation is absent."""
import hashlib
import json
from pathlib import Path
from .common import need


def selected_roster(config):
    roster = {}
    for label, cap in (('tool_pins', 8), ('runtime_pins', 8),
                       ('compiler_runtime_pins', 4096), ('system_runtime_pins', 64)):
        pins = config[label]
        need(isinstance(pins, dict) and len(pins) <= cap, 'declared pin roster bound')
        for name, pin in pins.items():
            path = pin['path']
            need(isinstance(path, str) and len(path) <= 4096, 'declared resource path bound')
            need(path not in roster or roster[path] == pin, 'conflicting resource pins')
            roster[path] = pin
    return roster


def verify_roster(config):
    # Imports here avoid a launcher/namespace initialization cycle.
    from .launcher import pin_regular
    pins = selected_roster(config)
    checked = {}
    for name, expected in pins.items():
        actual = pin_regular(Path(name))
        need(actual == expected, 'declared tool/runtime identity changed: ' + name)
        checked[name] = actual
    raw = json.dumps(checked, sort_keys=True, separators=(',', ':')).encode()
    return {'status': 'CHECKED', 'files': len(checked), 'roster_sha256': hashlib.sha256(raw).hexdigest(),
            'scope': 'exact previously declared tool/compiler/runtime/system-library roster',
            'assumption': 'hostile host and concurrent writes outside namespace are not attested; TOCTOU remains UNPROVEN'}
