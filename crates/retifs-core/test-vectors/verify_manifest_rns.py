#!/usr/bin/env python3
"""Cross-checks manifest-v1.json (ADR-0009, irreversible decision 11)
against the Python reference RNS.

For every case it opens each manifest node with RNS Token, parses it by the
layout alone, seals the data chunks again from the file's data and the leaf
spans, derives and seals the padding chunks from the padding rule, encodes
every node again and seals it, and compares every CID and seed with the
vector. Only RNS's own primitives (HKDF, HMAC, AES-256-CBC, PKCS7, Token).

    python verify_manifest_rns.py [manifest-v1.json]
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

CLASSES = [1 << n for n in range(9, 19)]
OVERHEAD, FRAME_HEADER, CID_LEN = 64, 5, 33
LEAF, INTERNAL, INLINE = 0, 1, 2


def secret_of(scheme):
    if scheme["type"] == "public":
        return hashlib.sha256(b"retifs/v1/public").digest()
    if scheme["type"] == "record":
        return hkdf(32, bytes.fromhex(scheme["namespace_key"]), b"retifs/v1/record", bytes.fromhex(scheme["record_id"]))
    raise ValueError(scheme["type"])


def seal(secret, data):
    """ADR-0008: the smallest class that fits; returns (cid, seed, chunk)."""
    cls = next(c for c in CLASSES if len(data) + FRAME_HEADER <= c - OVERHEAD)
    frame = bytes([0]) + struct.pack(">I", len(data)) + data
    frame += b"\x00" * (cls - OVERHEAD - len(frame))
    seed = HMAC.new(secret, frame).digest()
    okm = hkdf(80, seed, b"retifs/v1/chunk", b"")
    sign, enc, iv = okm[:32], okm[32:64], okm[64:80]
    signed = iv + AES_256_CBC.encrypt(PKCS7.pad(frame), enc, iv)
    chunk = signed + HMAC.new(sign, signed).digest()
    return b"\x01" + hashlib.sha256(chunk).digest(), seed, chunk


def open_node(cid, seed, chunk):
    assert cid == b"\x01" + hashlib.sha256(chunk).digest(), "CID is 0x01 || SHA-256(ciphertext)"
    frame = Token(hkdf(80, seed, b"retifs/v1/chunk", b"")[:64]).decrypt(chunk)
    assert frame[0] == 0, "manifest nodes are never compressed"
    (n,) = struct.unpack(">I", frame[1:5])
    assert frame[5 + n:] == b"\x00" * (len(frame) - 5 - n), "zero fill"
    return frame[5:5 + n]


def parse(node):
    version, kind, count = node[0], node[1], struct.unpack(">H", node[2:4])[0]
    assert version == 1, "node version"
    body = node[4:]
    if kind == INLINE:
        assert len(body) == count
        return kind, body
    width = CID_LEN + 32 + (4 if kind == LEAF else 8)
    assert kind in (LEAF, INTERNAL) and len(body) == count * width, "node length matches its count"
    entries = []
    for i in range(count):
        e = body[i * width:(i + 1) * width]
        span = struct.unpack(">I" if kind == LEAF else ">Q", e[65:])[0]
        entries.append((e[:33], e[33:65], span))
    return kind, entries


def encode(kind, entries):
    out = bytes([1, kind]) + struct.pack(">H", len(entries))
    for cid, seed, span in entries:
        out += cid + seed + struct.pack(">I" if kind == LEAF else ">Q", span)
    return out


def padme(n):
    if n < 2:
        return n
    e = n.bit_length() - 1
    s = e.bit_length()
    z = max(e - s, 0)
    mask = (1 << z) - 1
    return (n + mask) & ~mask


def padding_piece(secret, digest, index, length):
    key = HMAC.new(secret, b"retifs/v1/pad" + digest + struct.pack(">Q", index)).digest()
    out, block = b"", 0
    while len(out) < length:
        out += HMAC.new(key, struct.pack(">Q", block)).digest()
        block += 1
    return out[:length]


def data_of(spec):
    if "hex" in spec:
        return bytes.fromhex(spec["hex"])
    p = spec["pattern"]
    return bytes((i * 31 + p["salt"]) % 251 for i in range(p["len"]))


def check(doc, c):
    secret = secret_of(c["scheme"])
    assert secret.hex() == c["convergence_secret"], "convergence secret"
    data = data_of(c["data"])
    blobs = {bytes.fromhex(n["cid"].split(":")[-1] if ":" in n["cid"] else n["cid"]): bytes.fromhex(n["ciphertext"]) for n in c["nodes"]}
    f = c["file"]
    assert f["size"] == len(data), "file size"
    root_cid = bytes.fromhex(f["root"].split(":")[-1] if ":" in f["root"] else f["root"])
    leaves = []  # data and padding entries, in order
    nodes_seen = 0

    def walk(cid, seed, span, is_root):
        nonlocal nodes_seen
        node = open_node(cid, seed, blobs[cid])
        nodes_seen += 1
        kind, body = parse(node)
        # The node, encoded again and sealed again, is the same blob.
        again = body if kind == INLINE else None
        reenc = node if kind == INLINE else encode(kind, body)
        assert reenc == node, "canonical node encoding"
        rcid, rseed, _ = seal(secret, reenc)
        assert (rcid, rseed) == (cid, seed), "node sealed again gives its CID and seed"
        if kind == INLINE:
            assert is_root and len(again) <= doc["inline_max"] and again == data, "inline root holds the file"
            return
        total = sum(s for _, _, s in body)
        assert total == span or (is_root and total > span), "spans add up"
        for ecid, eseed, espan in body:
            if kind == LEAF:
                leaves.append((ecid, eseed, espan))
            else:
                walk(ecid, eseed, espan, False)

    walk(root_cid, bytes.fromhex(f["seed"]), f["size"], True)
    assert nodes_seen == len(blobs), "every listed node is in the tree"
    if not leaves:
        return
    # Real data chunks first: sealed again from the data at the leaf spans.
    off, real = 0, 0
    while off < len(data):
        ecid, eseed, espan = leaves[real]
        rcid, rseed, _ = seal(secret, data[off:off + espan])
        assert (rcid, rseed) == (ecid, eseed), f"data chunk {real}"
        off += espan
        real += 1
    assert off == len(data), "data chunks cover the file exactly"
    # Then the padding, by the rule.
    pads = leaves[real:]
    assert len(leaves) == (padme(real) if c["pad"] else real), "PADMÉ over the chunk count"
    digest = b"\x00" * 32 if c["stable_padding"] else hashlib.sha256(b"".join(e[0] for e in leaves[:real])).digest()
    for i, (ecid, eseed, espan) in enumerate(pads):
        piece = padding_piece(secret, digest, i, doc["max_piece"])
        rcid, rseed, _ = seal(secret, piece)
        assert (rcid, rseed, espan) == (ecid, eseed, len(piece)), f"padding chunk {i}"


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("manifest-v1.json")
    doc = json.loads(path.read_text())
    ok = 0
    for c in doc["cases"]:
        try:
            check(doc, c)
            ok += 1
        except AssertionError as e:
            print(f"FAIL {c['name']}: {e}")
    print(f"{ok}/{len(doc['cases'])} manifest cases verified against RNS")
    sys.exit(0 if ok == len(doc["cases"]) else 1)


if __name__ == "__main__":
    main()
