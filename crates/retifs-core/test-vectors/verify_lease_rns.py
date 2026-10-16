#!/usr/bin/env python3
"""Cross-checks lease-v1.json against the Python reference RNS.

Rebuilds the lease, renewal and receipt from the vector inputs using only RNS's
own primitives (hkdf, HMAC, Ed25519, Identity, Destination) and compares them
byte for byte (Ed25519 signatures are deterministic). Stamps are checked with
LXMF's own LXStamper.

    python verify_lease_rns.py [lease-v1.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import RNS
from RNS.Cryptography import HMAC
from RNS.Cryptography.HKDF import hkdf
from RNS.Cryptography import Ed25519PrivateKey, Ed25519PublicKey


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("lease-v1.json")
    v = json.loads(path.read_text())
    h = bytes.fromhex
    checks = {}

    lease_id = h(v["lease_id"])
    seed = hkdf(32, h(v["namespace_key"]), b"retifs/v1/lease-key", lease_id)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    signer = key.public_key().public_bytes()
    checks["lease_key"] = signer.hex() == v["lease_signer"]

    entries = b""
    for c in v["chunks"]:
        ct = h(c["ciphertext"])
        cid = b"\x01" + hashlib.sha256(ct).digest()
        token = hkdf(32, h(c["seed"]), b"retifs/v1/serve", b"")
        checks[f"cid {c['cid'][:10]}"] = cid.hex() == c["cid"]
        checks[f"token {c['cid'][:10]}"] = token.hex() == c["chunk_token"]
        proof = HMAC.new(h(c["prove_nonce"]), b"retifs/v1/prove" + ct).digest()[:16]
        checks[f"prove {c['cid'][:10]}"] = proof.hex() == c["prove"]
        entries += cid + token

    body = (b"\x01" + lease_id + signer + struct.pack(">Q", v["expires"]) + bytes([v["generations"]])
            + struct.pack(">H", len(v["chunks"])) + entries)
    lease = body + key.sign(b"retifs/v1/lease" + body)
    checks["lease"] = lease.hex() == v["lease"]
    checks["lease_digest"] = hashlib.sha256(body).hexdigest() == v["lease_digest"]
    vec_lease = h(v["lease"])
    Ed25519PublicKey.from_public_bytes(signer).verify(vec_lease[-64:], b"retifs/v1/lease" + vec_lease[:-64])
    checks["lease_verify"] = True

    ren_fields = b"\x01" + lease_id + struct.pack(">Q", v["renewal_expires"])
    renewal = ren_fields + key.sign(b"retifs/v1/renew" + ren_fields)
    checks["renewal"] = renewal.hex() == v["renewal"]

    holder = RNS.Identity.from_bytes(h(v["holder_identity_secret"]))
    pub = holder.get_public_key()
    dest = RNS.Destination.hash(holder, "retifs", "node")
    checks["holder_destination"] = dest.hex() == v["holder_node_destination"]
    fields = b"\x01" + lease_id + hashlib.sha256(body).digest() + struct.pack(">Q", v["expires"]) + pub
    receipt = fields + holder.sign(b"retifs/v1/receipt" + fields)
    checks["receipt"] = receipt.hex() == v["receipt"]
    vec_receipt = h(v["receipt"])
    checks["receipt_validate"] = holder.validate(vec_receipt[-64:], b"retifs/v1/receipt" + vec_receipt[:-64])

    # Stamps: LXMF's own construction (LXStamper), over "retifs/v1/stamp" || SHA-256(lease body).
    from LXMF import LXStamper
    material = b"retifs/v1/stamp" + hashlib.sha256(body).digest()
    checks["stamp_material"] = material.hex() == v["stamp_material"]
    wb = LXStamper.stamp_workblock(material)
    checks["stamp_workblock"] = hashlib.sha256(wb).hexdigest() == v["stamp_workblock_sha256"]
    stamp = h(v["stamp"])
    checks["stamp_value"] = LXStamper.stamp_value(wb, stamp) == v["stamp_value"] >= v["stamp_cost"]
    checks["stamp_valid_lxmf"] = LXStamper.stamp_valid(stamp, v["stamp_cost"], wb)

    failures = 0
    for name, ok in checks.items():
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"{len(checks) - failures}/{len(checks)} lease checks verified against RNS")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
