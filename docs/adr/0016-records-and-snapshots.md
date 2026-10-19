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

## Implementation status (2026-10-16)
- **Format:** `retifs_core::record`; vectors `record-v1.json`, verified byte for byte with RNS's umsgpack (26/26: integer and string boundaries, floats, bytes, nested lists, two records, a snapshot).
- **Local database** (`retifs-store`, `db.rs`): records per namespace, and an order-preserving index of every attribute value (ints and floats numerically, strings and bytes bytewise; list values per element). Queries are the AND of terms: `key=value`, `key>n`, `key>=n`, `key<n`, `key<=n` (the bound's type limits the range), `key^=prefix`, `has:key`.
- **API and CLI:** `retifs rec add NS KEY=VALUE… [--file PATH]` (the file becomes the record's content block, stored under its own record secret, needed and placed like any file; `name` and `size` are filled in), `rec set … [--unset KEY]`, `rec get`, `rec rm` (its content is forgotten unless another record uses it), `retifs query NS TERM…`.
- Live: records with and without content; queries by exact value, prefix, list element, numeric range combined with type, and `has:`; set and unset; delete.
- **Namespaces over channels:** `retifs channel publish-ns NAME NS` publishes a snapshot of the namespace as the channel's next version. A follower rebuilds it into a local namespace `ch-<ns_id>` (queryable like any other) and seeks every content block it references; the version counts as complete only when the snapshot and all blocks are local, then all are pinned and served on, and whatever only the previous version had is forgotten. Live: a two-page site published over a channel was complete at the follower 34 s later (queries and content matched); the publisher added a page, marked one as draft and republished, and the follower updated by itself (three pages; `draft=true` found the marked one).
- **NomadNet bridge (2026-10-19):** `retifsd --nomadnet NS [--nomadnet-name NAME]` runs a `nomadnetwork.node` destination (own identity, the name as announce app data, as NomadNet does) serving namespace NS, own or a followed channel's `ch-…`. A record with `path=/x.mu` (or `/page/x.mu`) is the page `/page/x.mu`, registered as a request path at run time (Prns `register_request_path`) and answered with the content as a msgpack `bin`, as NomadNet clients expect; without an `/index.mu` an index of the pages is generated as micron links. Paths follow the namespace (resynced every 15 s).
  - Live, with a Python RNS client speaking NomadNet's page protocol: the author's node served the generated index and a page; a follower of the site's channel served the same index and another page **with the author offline**. Before the follower had the site, it answered 13 index requests from elsewhere on the network (NomadNet clients or crawlers that heard its announce); it now says it is still fetching instead of serving an empty index.
  - Not yet: `/file/` downloads, NomadNet's `.allowed` access lists, form fields and dynamic pages.
- **Not yet:** per-modification signed commits inside a namespace; Prolly trees; content-bound attributes (decision 7).

