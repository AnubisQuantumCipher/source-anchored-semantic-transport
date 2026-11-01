"""Create and check private receiving-run directories, without model dispatch."""
import argparse
import json
from pathlib import Path
import resource
import signal
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import private_staging

LAYOUT = ('receivers/original/input', 'receivers/transport/input/content',
          'preflight', 'runs', 'evaluation', 'captures')


def prepare_layout(anchor):
    paths = {}
    for relative in LAYOUT:
        paths[relative] = str(private_staging.chain(anchor, relative))
    for relative in LAYOUT:
        private_staging.chain(anchor, relative, create=False)
    return {'schema': 'transport/private-receiving-layout/1', 'status': 'PRIVATE_PARENTS_READY',
            'root': str(anchor), 'paths': paths, 'mode': '0700', 'authority': 'NONE',
            'source_content': 'NOT_STAGED', 'models': 'NOT_DISPATCHED',
            'scope': 'Current-EUID private anchor and descendants only; no same-UID race exclusion.'}


def timed_out(unused_signal, unused_frame):
    raise ValueError('STAGING_WALL_LIMIT')


def main():
    for kind, bound in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_FSIZE, 4194304)):
        resource.setrlimit(kind, (bound, bound))
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(30)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = prepare_layout(args.root)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({'status': 'STAGING_REFUSED', 'reason': str(error)[:256],
                          'authority': 'NONE', 'partial_directories_may_exist': True}))
        return 1
    print(json.dumps(value, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
