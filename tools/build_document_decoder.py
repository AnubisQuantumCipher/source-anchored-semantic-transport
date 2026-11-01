#!/usr/bin/env python3
"""Bounded developer build and ledger proof; existing Linux/GNAT required."""
from pathlib import Path
import subprocess
import sys

# Explicit sibling code, including when invoked with Python isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from document_build.launcher import main


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print('BUILD_REFUSED: ' + str(error)[:4096], file=sys.stderr)
        sys.exit(2)
