#!/usr/bin/env python3
"""Cross-checks record-v1.json against RNS's own msgpack (RNS.vendor.umsgpack).

Rebuilds every value, record and the snapshot from the tagged JSON with
umsgpack, map keys sorted by their UTF-8 bytes, and compares byte for byte.

    python verify_record_rns.py [record-v1.json]
"""
import json
import sys
from pathlib import Path

import RNS.vendor.umsgpack as umsgpack


def value(t):
    kind, v = t["t"], t.get("v")
    if kind == "nil":
        return None
    if kind in ("bool", "int", "str"):
        return v
    if kind == "float":
        return float(v)
    if kind == "bin":
        return bytes.fromhex(v)
    if kind == "list":
        return [value(x) for x in v]
    raise ValueError(kind)


def sorted_map(d):
    return {k: d[k] for k in sorted(d, key=lambda k: k.encode("utf-8"))}


def record(r):
    attrs = sorted_map({k: value(v) for k, v in r["attrs"].items()})
    blocks = [[bytes.fromhex(c), bytes.fromhex(s), n] for c, s, n in r["blocks"]]
    return sorted_map({"id": bytes.fromhex(r["id"]), "attrs": attrs, "blocks": blocks})


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("record-v1.json")
    v = json.loads(path.read_text(encoding="utf-8"))
    checks = {}
    for i, case in enumerate(v["values"]):
        checks[f"value {i} {case['value']['t']}"] = umsgpack.packb(value(case["value"])).hex() == case["encoded"]
    for r in v["records"]:
        checks[f"record {r['id'][:4]}"] = umsgpack.packb(record(r)).hex() == r["encoded"]
    recs = sorted((record(r) for r in v["records"]), key=lambda r: r["id"])
    snap = sorted_map({"records": recs, "retifs": "ns-snapshot/1"})
    checks["snapshot"] = umsgpack.packb(snap).hex() == v["snapshot"]
    checks["snapshot unpacks"] = umsgpack.unpackb(bytes.fromhex(v["snapshot"]))["retifs"] == "ns-snapshot/1"

    failures = 0
    for name, ok in checks.items():
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"{len(checks) - failures}/{len(checks)} record checks verified against RNS umsgpack")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
