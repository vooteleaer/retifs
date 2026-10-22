"""Verifies test-vectors/words-v1.json (ADR-0020, fingerprint words) with
hashlib and the BIP-39 English list only.

    python crates/retifs-core/test-vectors/verify_words.py
"""

import hashlib
import json
import sys
from pathlib import Path

here = Path(__file__).parent
WORDS = (here.parent / "src" / "bip39-english.txt").read_text().split()
assert len(WORDS) == 2048
assert hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest() == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def fingerprint(key, n=6):
    bits = int.from_bytes(hashlib.sha256(key).digest(), "big")
    return [WORDS[(bits >> (256 - 11 * (i + 1))) & 0x7FF] for i in range(n)]


def main():
    cases = json.loads((here / "words-v1.json").read_text())["cases"]
    failed = 0
    for c in cases:
        got = fingerprint(bytes.fromhex(c["key"]))
        ok = got == c["words"]
        failed += not ok
        print("ok  " if ok else "FAIL", " ".join(got))
    print(f"{len(cases) - failed}/{len(cases)} fingerprint cases match")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
