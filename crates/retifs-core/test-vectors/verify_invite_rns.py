"""Verifies test-vectors/invite-v1.json (ADR-0020, invitations) with Python
RNS's umsgpack and HMAC, hashlib and base64 only.

    python crates/retifs-core/test-vectors/verify_invite_rns.py
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack
from RNS.Cryptography import HMAC


def encode(f):
    limits = {}
    if f["keys"]:
        limits["keys"] = f["keys"]
    if f["until"] is not None:
        limits["until"] = f["until"]
    inv = {"expires": f["expires"], "limits": limits, "node": bytes.fromhex(f["node"]), "ns": bytes.fromhex(f["ns"])}
    if f["q"] is not None:
        inv["q"] = f["q"]
    inv["rights"] = ["grant", "write"] if f["grant"] else ["write"]
    inv["secret"] = bytes.fromhex(f["secret"])
    return umsgpack.packb(inv)


def main():
    vectors = json.loads((Path(__file__).parent / "invite-v1.json").read_text())
    failed = 0
    for c in vectors["cases"]:
        f = c["fields"]
        enc = encode(f)
        secret = bytes.fromhex(f["secret"])
        ident = hashlib.sha256(b"retifs/v1/invite" + secret).digest()
        text = base64.b32encode(enc).decode().lower().rstrip("=")
        r = c["redeem"]
        msg = bytes.fromhex(r["link_id"]) + bytes.fromhex(r["writer"]) + bytes.fromhex(r["node"])
        proof = HMAC.new(secret, msg, hashlib.sha256).digest()
        request = ident + bytes.fromhex(r["writer"]) + bytes.fromhex(r["node"]) + proof
        checks = {
            "encoding": enc.hex() == c["encoded"],
            "text": text == c["text"],
            "id": ident.hex() == c["id"],
            "redemption": request.hex() == r["request"],
        }
        bad = [k for k, ok in checks.items() if not ok]
        failed += bool(bad)
        print("ok  " if not bad else "FAIL", c["id"][:8], ", ".join(bad))
    print(f"{len(vectors['cases']) - failed}/{len(vectors['cases'])} invitation cases match")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
