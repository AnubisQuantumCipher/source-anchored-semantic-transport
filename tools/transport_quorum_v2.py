"""Local informational threshold CLI; no network, model execution or authority."""

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from transport_quorum_v2_input import Refusal, canonical, read_regular
from transport_quorum_v2_policy import NAMES, evaluate


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in NAMES:
        parser.add_argument('--' + name, required=True)
    for name in NAMES[:3]:
        parser.add_argument('--expect-' + name + '-sha256', required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    try:
        raws = tuple(read_regular(getattr(args, name)) for name in NAMES)
        held = {name: getattr(args, 'expect_' + name + '_sha256') for name in NAMES[:3]}
        result = evaluate(raws, held)
    except (OSError, Refusal) as error:
        result = dict(schema='quorum/threshold-refusal/2', status='REFUSED',
                      code=str(error) if isinstance(error, Refusal) else 'FILE_IO', authority='NONE')
    sys.stdout.buffer.write(canonical(result) + b'\n')
    return 2 if result['status'] == 'REFUSED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
