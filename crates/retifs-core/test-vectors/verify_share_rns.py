"""Verifies test-vectors/share-v1.json (ADR-0021, share copies' record IDs)
with Python RNS's HKDF and hashlib only.

    python crates/retifs-core/test-vectors/verify_share_rns.py
"""

import hashlib
import json
import sys
from pathlib import Path

from RNS.Cryptography.HKDF import hkdf


def ns_id(writer):
    return hashlib.sha256(b"retifs/v1/ns" + writer).digest()[:16]


def share_record(source, share_ns_id):
    return hkdf(16, source, b"retifs/v1/share-record", share_ns_id)


def main():
    vectors = json.loads((Path(__file__).parent / "share-v1.json").read_text())
    failed = 0
    for c in vectors["cases"]:
        writer = bytes.fromhex(c["share_writer"])
        nid = ns_id(writer)
        got = share_record(bytes.fromhex(c["source_record"]), nid)
        ok = nid.hex() == c["share_ns_id"] and got.hex() == c["share_record"]
        failed += not ok
        print(("ok  " if ok else "FAIL"), c["source_record"][:8], "->", got.hex())
    print(f"{len(vectors['cases']) - failed}/{len(vectors['cases'])} share cases match")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
