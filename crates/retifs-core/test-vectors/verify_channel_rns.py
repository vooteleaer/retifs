#!/usr/bin/env python3
"""Cross-checks channel-v1.json against the Python reference RNS.

Decrypts the commit chunks with RNS Token, checks the commit and head
signatures with RNS's Ed25519, decrypts the head's commit seed with RNS Token,
and rebuilds the head byte for byte (Ed25519 is deterministic; the vector
fixes the Token IV).

    python verify_channel_rns.py [channel-v1.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from RNS.Cryptography import Ed25519PrivateKey, Ed25519PublicKey, HMAC, PKCS7
from RNS.Cryptography.AES import AES_256_CBC
from RNS.Cryptography.HKDF import hkdf
from RNS.Cryptography.Token import Token


def record_secret(namespace_key, record_id):
    return hkdf(32, namespace_key, b"retifs/v1/record", record_id)


def open_chunk(seed, chunk):
    okm = hkdf(80, seed, b"retifs/v1/chunk", b"")
    frame = Token(okm[:64]).decrypt(chunk)
    (n,) = struct.unpack(">I", frame[1:5])
    assert frame[0] == 0, "commits are stored raw"
    return frame, frame[5:5 + n]


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("channel-v1.json")
    v = json.loads(path.read_text())
    h = bytes.fromhex
    checks = {}

    key = Ed25519PrivateKey.from_private_bytes(h(v["writer_seed"]))
    writer = key.public_key().public_bytes()
    read_key = h(v["read_key"])
    checks["writer"] = writer.hex() == v["writer"]
    ns_id = hashlib.sha256(b"retifs/v1/ns" + writer).digest()[:16]
    checks["ns_id"] = ns_id.hex() == v["ns_id"]
    checks["address"] = v["address"] == f"retifs-ch:1:{writer.hex()}:{read_key.hex()}"

    secret = record_secret(read_key, b"retifs/v1/commits")
    pub = Ed25519PublicKey.from_public_bytes(writer)
    prev = None
    for c in v["commits"]:
        chunk, seed = h(c["chunk"]), h(c["chunk_seed"])
        frame, body_and_sig = open_chunk(seed, chunk)
        checks[f"commit {c['seq']} cid"] = ("01" + hashlib.sha256(chunk).hexdigest()) == c["chunk_cid"]
        checks[f"commit {c['seq']} convergent seed"] = HMAC.new(secret, frame).digest() == seed
        checks[f"commit {c['seq']} plaintext"] = body_and_sig.hex() == c["body_and_sig"]
        body, sig = body_and_sig[:-64], body_and_sig[-64:]
        expect = (b"\x01" + ns_id + writer + struct.pack(">QQ", c["seq"], c["time_ms"])
                  + (b"\x00" if prev is None else b"\x01" + prev[0] + prev[1])
                  + h(c["root_cid"]) + h(c["root_seed"]) + struct.pack(">Q", c["root_size"]))
        checks[f"commit {c['seq']} layout"] = body == expect
        pub.verify(sig, b"retifs/v1/commit" + body)
        checks[f"commit {c['seq']} signature"] = sig == key.sign(b"retifs/v1/commit" + body)
        prev = (h(c["chunk_cid"]), seed)

    head = h(v["head"])
    head_key = hkdf(64, read_key, b"retifs/v1/head-seed", b"")
    last = v["commits"][-1]
    seed = Token(head_key).decrypt(head[1 + 16 + 32 + 16 + 33:1 + 16 + 32 + 16 + 33 + 96])
    checks["head commit seed (RNS Token)"] = seed.hex() == last["chunk_seed"]
    iv = h(v["head_iv"])
    ct = AES_256_CBC.encrypt(PKCS7.pad(seed), head_key[32:], iv)
    sealed = iv + ct + HMAC.new(head_key[:32], iv + ct).digest()
    fields = (b"\x01" + ns_id + writer + struct.pack(">QQ", last["seq"], 1_790_000_060)
              + h(last["chunk_cid"]) + sealed)
    rebuilt = fields + key.sign(b"retifs/v1/head" + fields)
    checks["head bytes"] = rebuilt == head
    pub.verify(head[-64:], b"retifs/v1/head" + head[:-64])
    checks["head signature"] = True
    checks["head length"] = len(head) == 258

    failures = 0
    for name, ok in checks.items():
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"{len(checks) - failures}/{len(checks)} channel checks verified against RNS")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
