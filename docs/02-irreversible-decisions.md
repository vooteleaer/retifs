# Irreversible decisions

These stay forever in every stored chunk and signature. Everything else can be fixed later: chunk size, pinning logic, cache, UI, client OS.

| # | Decision | Risk | Status |
|---|---|---|---|
| 1 | **CID format**: hash algorithm plus a version byte from the start | The IPFS CIDv0→v1 migration was painful for years | proposed ([ADR-0008](adr/0008-chunk-encryption-and-cid.md)) |
| 2 | **Canonical serialization**: exactly what is signed (msgpack key order, integer encoding) | SSB signed a JS engine's JSON formatting, which made other implementations nearly impossible | proposed: canonical msgpack profile ([ADR-0016](adr/0016-records-and-snapshots.md), vectors verified with RNS umsgpack) |
| 3 | **Nonces for deterministic crypto**: SIV-style, nonce derived from content | Same key and nonce with different content = silent catastrophe | proposed ([ADR-0008](adr/0008-chunk-encryption-and-cid.md)) |
| 4 | **Capability semantics**: narrowing, chain validation, revocation | Confused deputy | proposed: grant/revoke operations replayed in stamp order ([ADR-0017](adr/0017-multi-writer-namespaces.md)); filters and expiry open |
| 5 | **Namespace updates**: per-writer sequence numbers, rollback protection (multi-writer, [ADR-0006](adr/0006-versioning-and-sharing.md)) | Replaying an old signed root | proposed: signed heads ([ADR-0015](adr/0015-signed-channels.md), vectors verified against RNS) |
| 6 | **Lease format**: expiry and renewal signature, and it covers a chunk list, not a manifest; receipts and per-lease derived keys ([ADR-0010](adr/0010-continuous-seeking.md), [ADR-0011](adr/0011-redundancy-by-default.md)) | A manifest-based lease leaks structure | proposed (draft v1, vectors verified against RNS) |
| 7 | **Record ID vs content CID**: which attributes attach to which | Without the distinction, every change loses the tags | open |
| 8 | **Commit object format**: per-writer chains, one commit per modification, lazy content ([ADR-0006](adr/0006-versioning-and-sharing.md)) | Restructuring history later is impossible | proposed: commits carry operations, merged per field in stamp order ([ADR-0015](adr/0015-signed-channels.md), [ADR-0017](adr/0017-multi-writer-namespaces.md)) |
| 9 | **Chunk encryption construction**: per-chunk AEAD, padding size classes | Size leakage, no random access | proposed ([ADR-0008](adr/0008-chunk-encryption-and-cid.md)) |
| 10 | **Blind index key derivation** | Index leakage, or keys that can't be rotated | open |
| 11 | **Manifest node format**: fixed binary layout, sealed like chunks | Non-canonical encoding breaks convergence; format changes strand old trees | proposed ([ADR-0009](adr/0009-manifest-format.md)) |

Each decision needs an ADR (`adr/`) and test vectors before any real data is stored with it. The crypto parts get an external review.
