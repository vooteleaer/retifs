#!/usr/bin/env python3
"""Cross-checks prolly-v1.json: re-encodes the stamped records with RNS's
umsgpack and rebuilds every Prolly tree independently (ADR-0018) — boundary
rule, size cut, node encoding, and sealing with RNS primitives (ADR-0008) —
comparing the root CID, root seed and the full set of node CIDs.

    python verify_prolly_rns.py [prolly-v1.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack

from verify_rns import seal

CLASSES = [1 << k for k in range(10, 19)]
LABEL = b"retifs/v1/prolly"


def value(t):
    k, v = t["t"], t.get("v")
    if k == "nil":
        return None
    if k in ("bool", "int", "str"):
        return v
    if k == "float":
        return float(v)
    if k == "bin":
        return bytes.fromhex(v)
    if k == "list":
        return [value(x) for x in v]
    raise ValueError(k)


def stamp(s):
    return [s[0], bytes.fromhex(s[1]), s[2], s[3]]


def stamped_record(r):
    blocks = None
    if r["blocks"] is not None:
        s, refs = r["blocks"]
        blocks = [stamp(s), [[bytes.fromhex(c), bytes.fromhex(sd), n] for c, sd, n in refs]]
    fields = {}
    for k, s, v in sorted(r["fields"], key=lambda f: f[0].encode("utf-8")):
        fields[k] = [stamp(s)] if v is None else [stamp(s), value(v)]
    return {
        "blocks": blocks,
        "deleted": None if r["deleted"] is None else stamp(r["deleted"]),
        "fields": fields,
        "live": None if r["live"] is None else stamp(r["live"]),
    }


def boundary(fanout, level, key):
    h = hashlib.sha256(LABEL + bytes([level]) + key).digest()
    return struct.unpack(">I", h[:4])[0] < (1 << 32) // fanout


def split(fanout, max_node, level, items, size):
    nodes, cur, n = [], [], 0
    for k, v in items:
        n += size(v) + 16
        cur.append((k, v))
        if boundary(fanout, level, k) or n >= max_node:
            nodes.append(cur)
            cur, n = [], 0
    if cur:
        nodes.append(cur)
    return nodes


def put(secret, data, store):
    cls = next(c for c in CLASSES if len(data) + 5 <= c - 64)
    _, seed, _, chunk = seal(secret, data, cls)
    cid = b"\x01" + hashlib.sha256(chunk).digest()
    store[cid] = chunk
    return cid, seed


def build(doc, secret, entries):
    """entries: sorted [(key, python value)]."""
    fanout, max_node, store = doc["fanout"], doc["max_node"], {}
    level = []
    for node in split(fanout, max_node, 0, entries, lambda v: len(umsgpack.packb(v))):
        leaf = umsgpack.packb({"entries": [[k, v] for k, v in node], "level": 0})
        level.append((node[0][0], put(secret, leaf, store)))
    height = 0
    while len(level) > 1:
        height += 1
        nxt = []
        for node in split(fanout, max_node, height, level, lambda _: 81):
            body = umsgpack.packb({"children": [[k, cid, seed] for k, (cid, seed) in node], "level": height})
            nxt.append((node[0][0], put(secret, body, store)))
        level = nxt
    return level[0][1], store


def key(i):
    return hashlib.sha256(struct.pack(">I", i) + bytes(12)).digest()[:16]


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("prolly-v1.json")
    doc = json.loads(path.read_text(encoding="utf-8"))
    secret = bytes.fromhex(doc["secret"])
    checks = {}
    srecs = []
    for r in doc["stamped_records"]:
        rec = stamped_record(r)
        checks[f"stamped record {r['id']} encoding"] = umsgpack.packb(rec).hex() == r["encoded"]
        srecs.append((bytes.fromhex(r["id"]), rec))
    for t in doc["trees"]:
        if t["kind"] == "small":
            entries = {key(i): f"value {i}" for i in range(t["count"])}
        else:
            entries = {key(i): bytes([i % 256]) * 4000 for i in range(t["count"])}
        if t["with_stamped"]:
            entries.update(srecs)
        if t["changed"] is not None:
            i, packed = t["changed"]
            entries[key(i)] = umsgpack.unpackb(bytes.fromhex(packed))
        (cid, seed), store = build(doc, secret, sorted(entries.items()))
        res = t["result"]
        checks[f"tree '{t['name']}' root cid"] = cid.hex() == res["root_cid"]
        checks[f"tree '{t['name']}' root seed"] = seed.hex() == res["root_seed"]
        checks[f"tree '{t['name']}' nodes ({len(store)})"] = sorted(c.hex() for c in store) == res["nodes"]
    trees = {t["name"]: set(t["result"]["nodes"]) for t in doc["trees"]}
    names = [t["name"] for t in doc["trees"]]
    new = len(trees[names[1]] - trees[names[0]])
    checks[f"one changed entry: {new} new nodes, rest shared"] = 1 <= new <= 4

    width = max(len(k) for k in checks)
    for k, ok in checks.items():
        print(f"{k:<{width}}  {'ok' if ok else 'FAIL'}")
    passed = sum(checks.values())
    print(f"{passed}/{len(checks)} passed")
    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
