"""Verifies test-vectors/index-v1.json (ADR-0019, the blind index) with
Python RNS's primitives and umsgpack only:

- token key and search secret: RNS HKDF from the read key;
- tokens: RNS HMAC-SHA256 over umsgpack [key, value], truncated to 16 bytes;
- entries: one AES-256 block (RNS AES_256_CBC with a zero IV over one block);
- the index tree: rebuilt here (Prolly rules of ADR-0018 with 32-byte keys)
  and sealed with ADR-0008, giving the same root and node CIDs.

    python crates/retifs-core/test-vectors/verify_index_rns.py
"""

import hashlib
import json
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack
from RNS.Cryptography import HMAC, PKCS7
from RNS.Cryptography.AES import AES_256_CBC
from RNS.Cryptography.Ed25519 import Ed25519PrivateKey
from RNS.Cryptography.Token import Token
from RNS.Cryptography.HKDF import hkdf

from verify_prolly_rns import boundary, put, value

SETTINGS_TYPE = "retifs.index"


def keys_from(read_key):
    token_key = hkdf(32, read_key, b"retifs/v1/index-token", b"")
    search = hkdf(32, read_key, b"retifs/v1/index-search", b"")
    return token_key, search


def token(token_key, key, v):
    return HMAC.new(token_key, umsgpack.packb([key, v]), hashlib.sha256).digest()[:16]


def entry(token_key, t, record_id):
    k = hkdf(32, token_key, b"retifs/v1/index-entry", t)
    out = AES_256_CBC.encrypt(record_id, k, b"\x00" * 16)
    assert len(out) == 16
    return out


def declared(key, patterns):
    for p in patterns:
        if p.endswith(":*"):
            prefix = p[:-1]
            if key.startswith(prefix) and len(key) > len(prefix):
                return True
        elif p == key:
            return True
    return False


def declared_keys(records):
    out = set()
    for _, attrs in records:
        if not any(k == "type" and v == SETTINGS_TYPE for k, v in attrs):
            continue
        for k, v in attrs:
            if k != "keys":
                continue
            items = v if isinstance(v, list) else [v]
            out.update(i.strip() for i in items if isinstance(i, str) and i.strip())
    return sorted(out, key=lambda s: s.encode("utf-8"))


def split(fanout, max_node, level, items, size, key_len):
    nodes, cur, n = [], [], 0
    for k, v in items:
        n += size(v) + key_len
        cur.append((k, v))
        if boundary(fanout, level, k) or n >= max_node:
            nodes.append(cur)
            cur, n = [], 0
    if cur:
        nodes.append(cur)
    return nodes


def build(doc, secret, keys):
    """keys: sorted 32-byte tree keys, each mapping to nil."""
    fanout, max_node, store = doc["fanout"], doc["max_node"], {}
    level = []
    for node in split(fanout, max_node, 0, [(k, None) for k in keys], lambda _: 1, 32):
        leaf = umsgpack.packb({"entries": [[k, None] for k, _ in node], "level": 0})
        level.append((node[0][0], put(secret, leaf, store)))
    height = 0
    while len(level) > 1:
        height += 1
        nxt = []
        for node in split(fanout, max_node, height, level, lambda _: 32 + 65, 32):
            body = umsgpack.packb({"children": [[k, cid, seed] for k, (cid, seed) in node], "level": height})
            nxt.append((node[0][0], put(secret, body, store)))
        level = nxt
    return level[0][1], store


def main():
    here = Path(__file__).parent
    doc = json.loads((here / "index-v1.json").read_text(encoding="utf-8"))
    checks = []

    read_key = bytes.fromhex(doc["read_key"])
    token_key, search = keys_from(read_key)
    checks.append(("search secret", search.hex() == doc["search_secret"]))

    for c in doc["tokens"]:
        t = token(token_key, c["key"], value(c["value"]))
        e = entry(token_key, t, bytes.fromhex(c["record"]))
        checks.append((f"token and entry {c['key']}={c['value'].get('v')}", t.hex() == c["token"] and e.hex() == c["entry"]))

    ns = doc["namespace"]
    records = [(bytes.fromhex(i), [(k, value(v)) for k, v in attrs]) for i, attrs in ns["records"]]
    patterns = declared_keys(records)
    checks.append(("declared keys from the settings record", patterns == ns["declared"]))
    tree_keys = set()
    for rid, attrs in records:
        for k, v in attrs:
            if not declared(k, patterns):
                continue
            vals = v if isinstance(v, list) else ([] if v is None else [v])
            for x in vals:
                t = token(token_key, k, x)
                tree_keys.add(t + entry(token_key, t, rid))
    tree_keys = sorted(tree_keys)
    checks.append(("tree keys", len(tree_keys) == ns["tree_keys"] and hashlib.sha256(b"".join(tree_keys)).hexdigest() == ns["tree_keys_sha256"]))
    (cid, seed), store = build(doc, search, tree_keys)
    checks.append(("index root", cid.hex() == ns["root_cid"] and seed.hex() == ns["root_seed"]))
    checks.append(("index nodes", sorted(c.hex() for c in store) == ns["nodes"]))

    for l in doc["lookups"]:
        t = token(token_key, l["key"], value(l["value"]))
        entries = [k[16:] for k in tree_keys if k[:16] == t]
        ids = []
        for e in entries:
            k = hkdf(32, token_key, b"retifs/v1/index-entry", t)
            ids.append(AES_256_CBC.decrypt(e, k, b"\x00" * 16).hex())
        checks.append((f"lookup {l['key']}", t.hex() == l["token"] and [e.hex() for e in entries] == l["entries"] and sorted(ids) == l["records"]))

    # The index channel: writer from the derived seed, read key = search secret.
    ch = doc["channel"]
    writer = Ed25519PrivateKey.from_private_bytes(hkdf(32, read_key, b"retifs/v1/index-writer", b"")).public_key().public_bytes()
    ns_id = hashlib.sha256(b"retifs/v1/ns" + writer).digest()[:16]
    checks.append(("index channel writer and ns_id", writer.hex() == ch["writer"] and ns_id.hex() == ch["ns_id"]))
    checks.append(("index channel address (the search capability)", ch["address"] == f"retifs-ch:1:{writer.hex()}:{search.hex()}"))

    # The descriptor: index root, checkpoint sealed to members as an RNS Token, time.
    dd = doc["descriptor"]
    state_key = hkdf(64, token_key, b"retifs/v1/index-state", b"")
    cid_hex, seed_hex, size = dd["checkpoint"]
    pt = umsgpack.packb([bytes.fromhex(cid_hex), bytes.fromhex(seed_hex), size])
    iv = bytes.fromhex(dd["iv"])
    signed = iv + AES_256_CBC.encrypt(PKCS7.pad(pt), state_key[32:], iv)
    sealed = signed + HMAC.new(state_key[:32], signed, hashlib.sha256).digest()
    encoded = umsgpack.packb({"index": [cid, seed], "state": sealed, "time": dd["time_ms"]})
    checks.append(("descriptor encoding", encoded.hex() == dd["encoded"]))
    checks.append(("descriptor state opens with RNS Token", Token(state_key).decrypt(sealed) == pt))

    qp = doc["query_proof"]
    proof = HMAC.new(search, b"retifs/v1/index-query" + bytes.fromhex(qp["link_id"]), hashlib.sha256).digest()
    checks.append(("query proof", proof.hex() == qp["proof"]))

    ok = all(c for _, c in checks)
    for name, c in checks:
        print(("ok    " if c else "FAIL  ") + name)
    print(f"{sum(c for _, c in checks)}/{len(checks)} checks passed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
