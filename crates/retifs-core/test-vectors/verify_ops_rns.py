#!/usr/bin/env python3
"""Cross-checks ops-v1.json: re-encodes every operations file with RNS's
umsgpack and re-implements the merge (ADR-0017) independently, comparing the
merged namespace snapshot byte for byte.

    python verify_ops_rns.py [ops-v1.json]
"""
import json
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack

DAY_MS = 24 * 3600 * 1000


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


def sorted_map(d):
    return {k: d[k] for k in sorted(d, key=lambda k: k.encode("utf-8"))}


def op(o):
    h = bytes.fromhex
    tag = o[0]
    if tag == "set":
        return ["set", h(o[1]), o[2], value(o[3])]
    if tag == "unset":
        return ["unset", h(o[1]), o[2]]
    if tag == "blocks":
        return ["blocks", h(o[1]), [[h(c), h(s), n] for c, s, n in o[2]]]
    if tag == "delete":
        return ["delete", h(o[1])]
    if tag == "grant":
        return ["grant", h(o[1]), sorted(set(o[2]))]
    if tag == "revoke":
        return ["revoke", h(o[1])]
    raise ValueError(tag)


def merge(creator, chains, now):
    events = []
    for writer, commits in chains.items():
        last = 0
        for c in commits:
            if c["time_ms"] < last or c["time_ms"] > now + DAY_MS:
                continue
            last = c["time_ms"]
            for i, o in enumerate(c["ops"]):
                events.append((c["time_ms"], writer, i, op(o)))
    events.sort(key=lambda e: (e[0], e[1], e[2]))
    rights = {creator: {"grant", "write"}}
    records, ignored = {}, 0
    for _, w, _, o in events:
        tag = o[0]
        if tag in ("grant", "revoke"):
            if "grant" not in rights.get(w, ()):
                ignored += 1
            elif o[1] != creator:
                if tag == "grant":
                    rights[o[1]] = set(o[2])
                else:
                    rights.pop(o[1], None)
            continue
        if "write" not in rights.get(w, ()):
            ignored += 1
            continue
        rid = o[1]
        if tag == "set":
            records.setdefault(rid, {"attrs": {}, "blocks": []})["attrs"][o[2]] = o[3]
        elif tag == "unset":
            if rid in records:
                records[rid]["attrs"].pop(o[2], None)
        elif tag == "blocks":
            records.setdefault(rid, {"attrs": {}, "blocks": []})["blocks"] = o[2]
        elif tag == "delete":
            records.pop(rid, None)
    return records, rights, ignored


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("ops-v1.json")
    v = json.loads(path.read_text(encoding="utf-8"))
    checks = {}
    chains = {}
    for ch in v["chains"]:
        w = bytes.fromhex(ch["writer"])
        chains[w] = ch["commits"]
        for c in ch["commits"]:
            f = sorted_map({"ops": [op(o) for o in c["ops"]], "retifs": "ns-ops/1"})
            checks[f"ops file {ch['writer'][:4]}@{c['time_ms']}"] = umsgpack.packb(f).hex() == c["encoded"]
    records, rights, ignored = merge(bytes.fromhex(v["creator"]), chains, v["now_ms"])
    snap = sorted_map({
        "records": [
            sorted_map({"id": rid, "attrs": sorted_map(r["attrs"]), "blocks": r["blocks"]})
            for rid, r in sorted(records.items())
        ],
        "retifs": "ns-snapshot/1",
    })
    checks["merged snapshot"] = umsgpack.packb(snap).hex() == v["merged_snapshot"]
    checks["ignored operations"] = ignored == v["ignored_ops"]
    checks["writers after"] = sorted(k.hex() for k in rights) == v["writers_after"]
    failures = 0
    for name, ok in checks.items():
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"{len(checks) - failures}/{len(checks)} operation checks verified (umsgpack + independent merge)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
