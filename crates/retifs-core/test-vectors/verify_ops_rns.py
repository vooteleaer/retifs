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
    if tag == "identity":
        return ["identity", h(o[1])]
    if tag == "rekey":
        return ["rekey", o[1], [[h(w), h(x)] for w, x in sorted(o[2])]]
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
    records, ignored, identities, rekeys = {}, 0, {}, []
    for t, w, _, o in events:
        tag = o[0]
        if tag == "identity":
            if o[1][32:] == w:
                identities[w] = o[1]
            else:
                ignored += 1
            continue
        if tag == "rekey":
            if "grant" in rights.get(w, ()):
                rekeys.append((o[1], t, w, o[2]))
            else:
                ignored += 1
            continue
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
    return records, rights, ignored, identities, rekeys


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
    records, rights, ignored, identities, rekeys = merge(bytes.fromhex(v["creator"]), chains, v["now_ms"])
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
    checks["identities after"] = sorted(k.hex() for k in identities) == v["identities_after"]
    checks["rekeys after"] = len(rekeys) == v["rekeys_after"]
    # The wrapped key opens with stock RNS Identity.decrypt.
    import RNS
    alice = RNS.Identity.from_bytes(bytes.fromhex(v["alice_identity_secret"]))
    wrapped = dict((w, x) for w, x in rekeys[-1][3])[alice.get_public_key()[32:]]
    checks["rekey unwraps with RNS Identity.decrypt"] = alice.decrypt(wrapped) == bytes.fromhex(v["rekey_new_key"])
    checks["identity is the RNS public key"] = identities[alice.get_public_key()[32:]] == alice.get_public_key()
    failures = 0
    for name, ok in checks.items():
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"{len(checks) - failures}/{len(checks)} operation checks verified (umsgpack + independent merge)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
