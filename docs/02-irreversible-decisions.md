# Irreversible decisions

These stay forever in every stored chunk and signature. Everything else can be fixed later: chunk size, pinning logic, cache, UI, client OS.

| # | Decision | Risk | Status |
|---|---|---|---|
| 1 | **CID format**: hash algorithm plus a version byte from the start | The IPFS CIDv0→v1 migration was painful for years | open |
| 2 | **Canonical serialization**: exactly what is signed (msgpack key order, integer encoding) | SSB signed a JS engine's JSON formatting, which made other implementations nearly impossible | open |
| 3 | **Nonces for deterministic crypto**: SIV-style, nonce derived from content | Same key and nonce with different content = silent catastrophe | open |
| 4 | **Capability semantics**: narrowing, chain validation, revocation | Confused deputy | open |
| 5 | **Namespace updates**: sequence numbers, rollback protection | Replaying an old signed root | open |
| 6 | **Lease format**: expiry and renewal signature, and it covers a chunk list, not a manifest | A manifest-based lease leaks structure | open |
| 7 | **Record ID vs content CID**: which attributes attach to which | Without the distinction, every change loses the tags | open |
| 8 | **Commit object format**: per-namespace vs independent sub-namespaces | Restructuring history later is impossible | open |
| 9 | **Chunk encryption construction**: per-chunk AEAD, padding size classes | Size leakage, no random access | open |
| 10 | **Blind index key derivation** | Index leakage, or keys that can't be rotated | open |

Each decision needs an ADR (`adr/`) and test vectors before any real data is stored with it. The crypto parts get an external review.
