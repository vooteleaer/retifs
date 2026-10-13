#!/usr/bin/env python3
"""Cross-checks chunk-v1.json against the Python reference RNS.

Re-implements ADR-0008 using only RNS's own primitives (hkdf, HMAC,
AES_256_CBC, PKCS7), compares every field with the Rust-generated vectors,
and decrypts every vector with RNS Token.

    python verify_rns.py [chunk-v1.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from RNS.Cryptography import HMAC, PKCS7
from RNS.Cryptography.AES import AES_256_CBC
from RNS.Cryptography.HKDF import hkdf
from RNS.Cryptography.Token import Token


def convergence_secret(scheme, given):
    t = scheme["type"]
    if t == "public":
        return hashlib.sha256(b"retifs/v1/public").digest()
    if t == "restricted":
        name, channel = bytes.fromhex(scheme["name"]), bytes.fromhex(scheme["channel"])
        info = struct.pack(">H", len(name)) + name + struct.pack(">H", len(channel)) + channel
        return hkdf(32, bytes.fromhex(scheme["publisher_secret"]), b"retifs/v1/restricted", info)
    if t == "personal":
        return given  # random by definition
    raise ValueError(t)


def seal(secret, data, cls):
    frame = struct.pack(">I", len(data)) + data
    frame += b"\x00" * (cls - 64 - len(frame))
    seed = HMAC.new(secret, frame).digest()
    okm = hkdf(80, seed, b"retifs/v1/chunk", b"")
    sign, enc, iv = okm[:32], okm[32:64], okm[64:80]
    signed = iv + AES_256_CBC.encrypt(PKCS7.pad(frame), enc, iv)
    chunk = signed + HMAC.new(sign, signed).digest()
    return frame, seed, okm, chunk


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("chunk-v1.json")
    doc = json.loads(path.read_text())
    failures = 0
    for c in doc["cases"]:
        given = bytes.fromhex(c["convergence_secret"])
        secret = convergence_secret(c["scheme"], given)
        data = bytes.fromhex(c["data"])
        frame, seed, okm, chunk = seal(secret, data, c["class"])
        vec_ct = bytes.fromhex(c["ciphertext"])
        checks = {
            "secret": secret == given,
            "class": len(chunk) == c["class"] == len(vec_ct),
            "seed": seed.hex() == c["seed"],
            "ciphertext": chunk == vec_ct,
            "cid": ("01" + hashlib.sha256(vec_ct).hexdigest()) == c["cid"],
            "rns_token_decrypt": Token(okm[:64]).decrypt(vec_ct) == frame,
        }
        ok = all(checks.values())
        failures += not ok
        bad = ", ".join(k for k, v in checks.items() if not v)
        print(f"{'ok  ' if ok else 'FAIL'} {c['name']:<28} class {c['class']:>6}  {bad}")
    print(f"{len(doc['cases']) - failures}/{len(doc['cases'])} vectors verified against RNS")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
