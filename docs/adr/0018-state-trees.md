# ADR-0018: Namespace state as a Prolly tree

- **Status:** proposed
- **Date:** 2026-10-19
- **Irreversible:** yes. Stamped records and tree nodes are stored as chunks and will be named by signed checkpoints (decision 2: canonical serialization; decision 8: commit content). Vectors in `crates/retifs-core/test-vectors/prolly-v1.json`, verified with RNS's umsgpack and RNS primitives.

## Context
[ADR-0017](0017-multi-writer-namespaces.md) merges namespaces by replaying every writer's operations. The merge is now a CRDT state (per-field stamps), so a node only applies new commits. But a node that restarts, or a member that joins, still has to fetch and replay every chain from the beginning. That costs time and, over slow links, transfer: the history of a busy namespace grows without bound while its current state doesn't.

What's needed is the state itself as content-addressed data:
- a member can fetch it instead of the history;
- two versions share everything that didn't change, so a node holding one fetches only the difference;
- holders stay blind, as with every other chunk.

## Principles
- Supports 2 (content addressing: the state is a CID, like everything else) and 4 (local-first: restart without the network).
- Supports the slow-link goal ([ADR-0013](0013-slow-links.md)): one changed record costs a few nodes, not the whole state.
- Violates none. Crypto is ADR-0008 sealing, nothing new.

## Options
1. **One snapshot file per version** (the ADR-0016 snapshot): simple, but every version is a whole new file. Chunk-level dedup helps only if the change doesn't shift chunk boundaries.
2. **A Merkle tree with fixed shape** (e.g. by key prefix): stable, but uneven. Record IDs are random, so it works, yet node sizes can't adapt to large values.
3. **A Prolly tree** (chosen): a B-tree whose node boundaries are chosen by hashing keys, as in Dolt and Noms. The shape depends only on the set of keys, so equal maps give equal trees, and a change touches one leaf and its path.

## Decision

### Stamped records
A tree entry is one record's CRDT state (ADR-0017 `State`), so merging can resume from it exactly:
```text
srec  = { "blocks": nil | [ stamp, [ [cid, seed, size], … ] ],
          "deleted": nil | stamp,
          "fields": { key: [ stamp ] | [ stamp, value ], … },
          "live": nil | stamp }                                       canonical msgpack (ADR-0016)
stamp = [ time_ms, writer (bin 32), seq, index ]
```
- `[stamp]` is an unset field; `[stamp, value]` is a set one.
- `live` is the latest `set` or `blocks`, and `deleted` is the latest `delete`.
- Tombstones are kept: a deleted record still has its stamps, so an older write arriving later can't revive it.

### Tree
A sorted map from record ID (16 bytes) to canonical msgpack bytes:
```text
leaf     = { "entries": [ [ id (bin 16), value (embedded msgpack) ], … ], "level": 0 }
internal = { "children": [ [ first id (bin 16), cid (bin 33), seed (bin 32) ], … ], "level": n }
```
- **Boundaries:** a node at level L ends after the entry (or child) with key k if `u32_be(SHA-256("retifs/v1/prolly" ‖ L ‖ k)[0..4]) < 2^32 / 32`, giving 32 entries per node on average.
  - A node also ends once its entries reach 64 KiB, counting each entry as its value's length plus 16 and each child as 81. This keeps a node within one chunk however large the values are.
- **Levels:** leaves are split into nodes, then the list of (first key, node) is split again with the next level's boundary, until one node remains. That node is the root. An empty map has no root.
- **Sealing:** every node is one chunk, sealed with ADR-0008 under one convergence secret per tree (the caller's). For namespaces this is meant to be `ConvergenceSecret::for_record(read key, "retifs/v1/state")`, fixed with checkpoints.
  - Unchanged nodes keep their CIDs across versions and are stored once. A different namespace or key gives different CIDs, so holders can't correlate.
- **Reading:** lookup descends by first key. A diff collects both trees' leaves and reads only the leaves the other tree doesn't share.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- Holders see sealed chunks of size classes, as before. The number of nodes and how they change between versions reveal roughly how many records a namespace has and how many change: about one leaf and its path per change. Snapshot files revealed the size too.
- Equal keys give equal shapes only under one secret. Across namespaces, CIDs differ.

## Consequences
- **Easier:**
  - A namespace version is a single (CID, seed).
  - A member fetches the state instead of the history.
  - Versions share nodes, and comparing them is cheap.
  - It is the base for signed checkpoints (next) and for fetching only part of a namespace later.
- **Harder:**
  - Tombstones are stored forever, as in every state CRDT. Pruning needs agreement that no older write can still arrive (a checkpoint every writer has passed).
  - The format is fixed by the vectors.

## Implementation status (2026-10-19)
- `retifs_core::prolly`: `build`, `get`, `read_all`, `diff`. Test: 3 000 entries; one changed value adds at most four nodes; the diff names exactly the changed key; equal entries give the same root; a deleted entry shows up in the diff.
- `retifs_core::ops::StampedRecord` (canonical encode and strict decode) and `State::stamped` / `State::with_stamped`.
  - Test: 300 random multi-writer histories. In each, the state is checkpointed into a tree halfway, restored from it, and the later commits are applied. The result equals replaying everything.
- Vectors `prolly-v1.json` (13/13 with `verify_prolly_rns.py`):
  - three stamped records re-encode byte for byte with RNS umsgpack;
  - three trees are rebuilt independently in Python, sealed with RNS primitives, and match root CID, root seed and every node CID. The trees are 2 003 small entries over three levels, the same with one entry changed (3 new nodes, the rest shared), and 60 entries of 4 000 bytes, where the size cut closes the leaves.
- **Not yet:** signed checkpoints, persisting the state across restarts, fetching a checkpoint when joining, pruning tombstones.
