# ADR-0018: Namespace state as a Prolly tree, and checkpoints

- **Status:** proposed
- **Date:** 2026-10-19
- **Irreversible:** yes. Stamped records, tree nodes and checkpoint files are stored as chunks, and checkpoints will be named in signed chains (decision 2: canonical serialization; decision 8: commit content). Vectors in `crates/retifs-core/test-vectors/prolly-v1.json`, verified with RNS's umsgpack and RNS primitives.

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
- **Sealing:** every node is one chunk, sealed with ADR-0008 under one convergence secret per tree. For a namespace that secret is `ConvergenceSecret::for_record(read key, "retifs/v1/state")`, i.e. `HKDF(salt "retifs/v1/record", ikm read key, info "retifs/v1/state")`.
  - Unchanged nodes keep their CIDs across versions and are stored once.
  - Every member holding the read key builds the same tree from the same state, so two members can compare states by root CID.
  - A different namespace or a rotated key gives different CIDs, so holders can't correlate.
- **Reading:** lookup descends by first key. A diff collects both trees' leaves and reads only the leaves the other tree doesn't share.

### Checkpoints
A checkpoint is the merged state at a point of every writer's chain, stored as an ordinary file (ADR-0009) sealed under the same state secret:
```text
checkpoint = { "control":  [ [ stamp, op ], … ],              every control operation seen, valid or not, by stamp
               "frontier": [ [ writer (bin 32), seq, time_ms, commit cid (bin 33) ], … ],   by writer
               "high":     nil | stamp,                       the highest stamp of any data operation seen
               "retifs":   "ns-checkpoint/1",
               "state":    nil | [ root cid (bin 33), root seed (bin 32) ] }   the tree of stamped records
```
- **A checkpoint is a cache.** It describes a deterministic function: the state after each writer's commits up to its frontier. Anyone holding the chains can check it by replaying them and comparing the root.
- **Resuming:** a node loads the state, walks each chain back only to its frontier commit, and applies the newer commits as usual.
- **Late control operations:** a grant or revoke changes the meaning of data operations stamped after it.
  - If a new control operation's stamp is above `high`, no data seen so far can be affected, so it is added in place. Arrivals in any order then still give the same state. This also spares the in-memory state most rebuilds.
  - If it is below `high`, the state is rebuilt from the whole chains: the history before the checkpoint is read again. The history is kept and placed (ADR-0017), so this is a slow path, not data loss.
  - Control operations are few, so the checkpoint carries all of them, and the rights timeline is re-evaluated whole.
- **Misdated commits** (dated before their predecessor, or more than a day ahead when the checkpoint was made) are settled as ignored once a frontier passes them.
- **Local checkpoints:** a node writes one after every 64 new commits it applies, plus on the first rebuild of an existing namespace. The previous checkpoint's chunks that the new one doesn't share become evictable.
- **Not decided yet:** how a checkpoint goes into a chain for new members, and whose checkpoints a member may trust without replaying.
  - Likely as an operation naming the checkpoint file, written by a member holding `grant`. Such a member can already revoke and rekey anyone, so trusting it adds no power.
  - Placing tree nodes on other nodes needs placement to know trees, not only manifests.

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
- `retifs_core::ops::StampedRecord` (canonical encode and strict decode), `State::stamped` / `State::restore`.
- `State` keeps every control operation and its `high` stamp. `add_control` / `apply_commits` add control operations in place when they're newer than all data, and report when a rebuild is needed.
- `retifs_core::checkpoint`: `Checkpoint` (canonical encode, strict decode: sorted control and frontier, no trailing bytes), `save`, `load`, `state_secret`.
  - Test: 1 500 random three-writer histories with grants, revokes, deletes and same-millisecond commits. The commits arrive in random interleavings, are applied incrementally (rebuilding only when told to), and are checkpointed, encoded, decoded and restored at a random point. After every commit the result equals the full replay.
- Daemon: local checkpoints (`ns_checkpoint` in the store), resume after a restart, and a full walk only when a rebuild or the history (`rec history`, `query --at`) needs it.
  - Live test: 150 records written, edited and deleted (two checkpoints written), then a restart. The daemon logged `resumed from checkpoint`; the same 148 records came back, with the edits and deletions; history and `--at` still showed the earliest versions.
- Vectors `prolly-v1.json` (18/18 with `verify_prolly_rns.py`):
  - three stamped records re-encode byte for byte with RNS umsgpack;
  - three trees are rebuilt independently in Python, sealed with RNS primitives, and match root CID, root seed and every node CID. The trees are 2 003 small entries over three levels, the same with one entry changed (3 new nodes, the rest shared), and 60 entries of 4 000 bytes, where the size cut closes the leaves;
  - a checkpoint of a three-writer history (grant, revoke, a write after the revoke, an ungranted writer, unset, delete, content). Python replays the chains into stamped records on its own, builds the state tree under the HKDF state secret, and matches the root and the checkpoint's bytes.
- **Not yet:** checkpoints in chains for new members, placing trees on other nodes, pruning tombstones.
