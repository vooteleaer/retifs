# ADR-0016: Records, canonical encoding and namespace snapshots

- **Status:** proposed
- **Date:** 2026-10-16
- **Irreversible:** yes, for the encoding (decision 2: canonical serialization) and the record and snapshot layouts. Vectors in `crates/retifs-core/test-vectors/record-v1.json`, verified against RNS's own msgpack (`RNS.vendor.umsgpack`).

## Context
Phase 2 makes records and attributes the main interface ([vision](../00-vision.md), BeFS heritage; [API §5–6](../07-api.md#5-records)). Everything signed or content-addressed needs one byte-exact encoding (decision 2), or signatures and CIDs differ between implementations (SSB's lesson). Channels ([ADR-0015](0015-signed-channels.md)) also need a version to be more than one file: a site or an app is a set of records with paths and content.

## Principles
Supports 6 (records and attributes first, the file tree is a view) and 1 (snapshots are ordinary encrypted files). Violates none.

## Options
1. **Canonical CBOR** (RFC 8949 deterministic): well specified, but foreign to the RNS ecosystem.
2. **Canonical msgpack** (chosen): what RNS and LXMF already use, with a strict profile. Python RNS ships `umsgpack`, which produces the same bytes when map keys are sorted, so interop needs no new library.
3. **A custom binary layout per object:** compact, but every new object needs its own spec.

## Decision

### Canonical msgpack profile
- Integers in their smallest form (fixint, then 8/16/32/64-bit); floats always 64-bit, never NaN.
- Strings UTF-8, bytes as `bin`, both with the smallest length prefix; arrays and maps likewise.
- Maps have string keys, sorted by their UTF-8 bytes, no duplicates.
- **Strict decoding:** input that doesn't re-encode to the same bytes is rejected.

### Records and snapshots (`retifs_core::record`, draft v1)
```text
record   = { "attrs": { key: value, … }, "blocks": [ [cid, seed, size], … ], "id": bin 16 }
snapshot = { "records": [ record, … sorted by id, unique ], "retifs": "ns-snapshot/1" }
value    = nil | bool | int (i64) | float (f64) | str | bin | [ value, … ]
```
- A record ID is 16 random bytes, stable across changes.
- Blocks are content as read-caps (`FileRef`); a record may have none.
- **A snapshot is one version of a small namespace**, stored as an ordinary file and published like any other (a channel's commit points to it). Large namespaces will use Prolly trees for indexes and diffs; snapshots stay as the simple form for sites and apps.

### Not decided here
- **Record vs content binding of attributes** (decision 7): all attributes in a snapshot bind to the record for now.
- **Signed attribute writes and per-writer commit chains for databases** ([ADR-0006](0006-versioning-and-sharing.md)): a snapshot is published by a channel's signed commit; per-modification commits inside a namespace come with Prolly trees.

## Impact on the threat model
See the [threat model](../04-threat-model.md). A snapshot is encrypted like any file; holders learn only its size class and chunk count (padded, [ADR-0009](0009-manifest-format.md)). Readers of a snapshot see all of it: share a filtered namespace to share less ([ADR-0006](0006-versioning-and-sharing.md)).

## Consequences
- Easier: one encoding for everything signed, checkable with stock RNS tools; sites and apps can be published as trees today.
- Harder: snapshots rewrite the whole namespace per version (fine for small ones; record-level dedup comes from the per-record secret of each block, not the snapshot itself).
