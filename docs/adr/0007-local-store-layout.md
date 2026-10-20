# ADR-0007: Local store layout (slabs on an ordinary filesystem)

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** no. The store is local and can be migrated. What's irreversible is the chunk/CID format, which is identical on disk and on the wire.

## Context
The local store ([ADR-0005](0005-local-store-offline.md)) holds:
- chunks (immutable ciphertext, addressed by CID, padded to fixed size classes);
- Prolly-tree nodes and commits, which are also immutable, encrypted and content-addressed;
- a small amount of mutable state: heads, per-writer sequence numbers, pins and tiers, leases, LRU, keep rules and wrapped keys.

The question is whether this needs its own on-disk format or block-device filesystem.

## Principles
Supports 1 (everything at rest is ciphertext), 4 (local-first: crash-safe local durability) and 7 (the local store is a blind store like any other). Violates none.

## Options
1. **One file per chunk** on the host FS (IPFS flatfs, git loose objects). Simple, but millions of small files make backup, `rsync` and fsck slow and waste inodes.
2. **Own block-device filesystem** (BFS-style). Full control, but it needs a kernel driver or raw I/O, fsck and recovery tooling. That's years of edge cases to beat ext4/F2FS by a small margin.
3. **Slab segments plus an embedded index on an ordinary filesystem.**

## Decision
Option 3.

```
~/.local/share/retifs/store/        (or /var/lib/retifs/store, system-wide)
  slabs/
    c16k/  seg-000001 …             one directory per size class (c512b for 512 B)
    c32k/  …                        each segment = N fixed-size slots
    c256k/ …
  index.redb                        CID → (class, segment, slot), tier, refs, leases
  state.redb                        heads, seqs, keep rules, LRU
  keys/                             wrapped keys (separate, YubiKey-wrappable)
```

- **Slabs per size class.** Padding means every chunk fits a fixed slot size, so a segment is an array of equal slots: `offset = slot × size`. Freed slots are reused directly, with no allocator and no fragmentation.
- **Index and state in [redb](https://github.com/cberner/redb)**: pure Rust, ACID, copy-on-write B-tree, no C dependency.
- **Tiers are metadata.** Pinned, cache and serving are index flags, so moving a chunk between tiers copies nothing.
- **Content first, then the reference.** Write the slot, `fsync`, then commit the index. After a crash, orphaned slots are free space.
- **Self-verifying.** Every read checks the CID. A corrupt chunk is dropped and fetched again from the network.
- **Keys are kept apart** from the ciphertext, so the store can be copied, backed up or shared without exposing anything.

## Impact on the threat model
A copied or stolen store is ciphertext plus an index of CIDs, size classes, tiers and lease times. That shows how much is kept locally and of what size, but not what it is. The keys directory is the sensitive part and is wrapped (YubiKey where available). See the [threat model](../04-threat-model.md).

## Consequences
- Easier:
  - Thousands of segment files instead of millions of chunks.
  - Trivial allocation.
  - **Export/sneakernet for free:** a set of segments plus an index is a self-verifying bundle.
  - A **system-wide shared store** across users ([ADR-0006](0006-versioning-and-sharing.md)).
  - A later move to a raw partition or zoned storage (SMR, ZNS) without changing anything above the store.
- Harder: slot reuse needs care so that a freed slot is never overwritten while a reader still holds it (epoch or refcount). Padding wastes space by design, which is the price of not leaking size.
