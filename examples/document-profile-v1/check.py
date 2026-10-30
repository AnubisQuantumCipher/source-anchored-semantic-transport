"""Check retained source/report identities; this does not rerun GNATprove."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, cap=131072):
    need(not path.is_symlink() and path.is_file(), "regular input required")
    need(path.stat().st_size <= cap, "input byte bound")
    return path.read_bytes()


def main():
    receipt = json.loads(read(HERE / "receipt.json"))
    need(len(receipt["sources"]) == 8 and len(receipt["reports"]) == 2, "fixed roster")
    for name, expected in receipt["sources"].items():
        need(hashlib.sha256(read(ROOT / name)).hexdigest() == expected, "source mismatch: " + name)
    for name, expected in receipt["reports"].items():
        raw = read(HERE / name)
        need({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == expected, "report mismatch")
        rows = re.findall(r"^Total\s+(.+)$", raw.decode("ascii"), re.M)
        need(len(rows) == 1, "one total required")
        actual = re.sub(r"\([^)]*\)", "", rows[0]).split()
        wanted = ["16", "10", "6", ".", "."] if name.startswith("ledger") else ["56", "10", "46", ".", "."]
        need(actual == wanted, "proof totals differ")
    print("CHECKED retained source/report bytes; proof scopes remain separate")


if __name__ == "__main__":
    main()
