#!/usr/bin/env python3
"""Cross-checks prolly-v1.json: re-encodes the stamped records with RNS's
umsgpack and rebuilds every Prolly tree independently (ADR-0018) — boundary
rule, size cut, node encoding, and sealing with RNS primitives (ADR-0008) —
comparing the root CID, root seed and the full set of node CIDs. For the
checkpoint, replays the chains independently into stamped records (last
writer wins per field, rights at each stamp), builds the state tree under
HKDF(read key, "retifs/v1/state") and re-encodes the checkpoint.

    python verify_prolly_rns.py [prolly-v1.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack
from RNS.Cryptography.HKDF import hkdf

from verify_ops_rns import allows, holds, limits_of, narrowed, op as ops_op
from verify_rns import seal

CLASSES = [1 << k for k in range(9, 19)]
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


CONTROL = ("grant", "revoke", "identity", "rekey")


def stamped_state(creator, chains):
    """Sequential replay in stamp order; the last applied operation per field wins."""
    events = []
    for writer, commits in chains.items():
        for c in commits:
            for i, o in enumerate(c["ops"]):
                events.append(((c["time_ms"], writer, c["seq"], i), ops_op(o)))
    events.sort(key=lambda e: e[0])
    rights = {creator: {"rights": {"grant", "write"}, "limits": (None, None)}}
    # Each writer's rights over time, for pruning: [(from stamp, rights or None)].
    timeline = {creator: [([0, bytes(32), 0, 0], {"grant", "write"})]}
    control, high, recs = [], None, {}
    for s, o in events:
        stamp = [s[0], s[1], s[2], s[3]]
        tag, w = o[0], s[1]
        if tag == "checkpoint":
            continue
        if tag in CONTROL:
            control.append([stamp, o])
            if tag in ("grant", "revoke") and holds(rights, w, "grant", s[0]) and o[1] != creator:
                if tag == "grant":
                    rights[o[1]] = {"rights": set(o[2]), "limits": narrowed(rights[w]["limits"], limits_of(o))}
                    timeline.setdefault(o[1], []).append((stamp, set(o[2])))
                else:
                    rights.pop(o[1], None)
                    timeline.setdefault(o[1], []).append((stamp, None))
            continue
        high = stamp
        if not allows(rights, w, o, s[0]):
            continue
        r = recs.setdefault(o[1], {"blocks": None, "deleted": None, "fields": {}, "live": None})
        if tag == "set":
            r["fields"][o[2]] = [stamp, o[3]]
            r["live"] = stamp
        elif tag == "unset":
            r["fields"][o[2]] = [stamp]
        elif tag == "blocks":
            r["blocks"] = [stamp, o[2]]
            r["live"] = stamp
        elif tag == "delete":
            r["deleted"] = stamp
    for r in recs.values():
        r["fields"] = {k: r["fields"][k] for k in sorted(r["fields"], key=lambda k: k.encode("utf-8"))}
    return control, high, recs, timeline


def prune(recs, timeline, frontier):
    """Drops dead records no writer can still precede (ADR-0018): a writer's
    next op is stamped above [time, writer, seq, 2^32-1] of its frontier, and
    it can write in each (from, until] it held write rights."""
    nxt = {w: [t, w, seq, 2**32 - 1] for w, seq, t, _ in frontier}
    intervals = []
    for w, tl in timeline.items():
        after = nxt.get(w, [0, w, 0, 0])
        for i, (frm, r) in enumerate(tl):
            if r is not None and "write" in r:
                intervals.append((after, frm, tl[i + 1][0] if i + 1 < len(tl) else None))
    for rid in list(recs):
        r = recs[rid]
        d = r["deleted"]
        if d is None or (r["live"] is not None and r["live"] > d):
            continue
        if not any(max(a, f) < (min(u, d) if u is not None else d) for a, f, u in intervals):
            del recs[rid]


def visible(recs):
    n = 0
    for r in recs.values():
        if r["live"] is not None and (r["deleted"] is None or r["live"] > r["deleted"]):
            n += 1
    return n


def check_checkpoint(doc, checks):
    v = doc["checkpoint"]
    creator = bytes.fromhex(v["creator"])
    chains = {bytes.fromhex(c["writer"]): c["commits"] for c in v["chains"]}
    control, high, recs, timeline = stamped_state(creator, chains)
    frontier = [[bytes.fromhex(w), s, t, bytes.fromhex(c)] for w, s, t, c in v["frontier"]]
    before = len(recs)
    prune(recs, timeline, frontier)
    checks[f"checkpoint prunes tombstones ({before - len(recs)} of {before})"] = before - len(recs) == v.get("pruned", 0)
    secret = hkdf(32, bytes.fromhex(v["read_key"]), b"retifs/v1/record", b"retifs/v1/state")
    (cid, seed), store = build(doc, secret, sorted(recs.items()))
    checks["checkpoint state root cid"] = cid.hex() == v["state_root_cid"]
    checks["checkpoint state root seed"] = seed.hex() == v["state_root_seed"]
    checks[f"checkpoint state nodes ({len(store)})"] = sorted(c.hex() for c in store) == v["state_nodes"]
    checks["checkpoint visible records"] = visible(recs) == v["visible_records"]
    cp = {
        "control": control,
        "frontier": frontier,
        "high": high,
        "retifs": "ns-checkpoint/1",
        "state": [cid, seed],
    }
    checks["checkpoint encoding"] = umsgpack.packb(cp).hex() == v["encoded"]


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
    check_checkpoint(doc, checks)
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
