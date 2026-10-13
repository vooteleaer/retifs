# ADR-0009: Manifest format

- **Status:** proposed. This is a draft, and it depends on [ADR-0008](0008-chunk-encryption-and-cid.md).
- **Date:** 2026-10-13
- **Irreversible:** yes. Manifest nodes are stored forever, and their bytes determine their CIDs. This is decision 11, and it applies decision 2 (canonical serialization) to manifests.

## Context
A file is a sequence of encrypted chunks. Readers need random access: reading one byte of a 10 GB file should cost a few manifest nodes plus one chunk ([architecture](../01-architecture.md)). Storage nodes must not learn which chunks belong together. Public content should converge: independent writers of the same file must produce the same manifest, and so the same CID.

## Principles
Supports 2 (manifests are built from encrypted chunks), 7 (blind storage nodes) and 4 (random access works with only the needed chunks local). Violates none.

## Options
1. **msgpack or CBOR nodes:** flexible, but canonical encoding needs rules for key order, integer widths and so on. That's the SSB lesson.
2. **Flat chunk list:** simple, but reading one byte of a large file needs the whole list.
3. **A Merkle tree of fixed-layout binary nodes, sealed like chunks.**

## Decision
Option 3.

```text
node      = version (0x01) ‖ kind (0 = leaf, 1 = internal) ‖ u16_be count ‖ entries
leaf      = cid (33) ‖ seed (32) ‖ u32_be data length          69 bytes
internal  = cid (33) ‖ seed (32) ‖ u64_be span (bytes below)   73 bytes
```

- **Sealed like content.** Each node is sealed with the ADR-0008 construction and the **same convergence secret** as the file's content, so nodes and chunks are indistinguishable and public manifests converge.
- **Canonical by construction.** There are no optional fields, no maps, and one width per field. Equal trees give equal bytes.
- **The read capability** is `FileRef = (root cid, root seed, size)`. That's all a reader needs, and it reveals nothing beyond that one file.
- **Strict validation on read:** version, kind, `length = 4 + count × width`, a known CID version, child spans that sum to the parent's span, and chunk lengths that match their leaf entries.
- **Writer policy v1** (not format; readers accept any count): FastCDC chunks (4/16/60 KiB), then groups of up to **64** entries per node, bottom-up. A 64-entry internal node is 4 676 bytes and seals into the 8 KiB class. An empty file is a root leaf with 0 entries.

## Impact on the threat model
- Storage nodes see class-sized blobs only. Which blobs form a tree is hidden; only fetch timing remains, which is already listed in [threat model](../04-threat-model.md) "Known leaks".
- A holder of a `FileRef` can read exactly that file, including its chunk seeds. That's the intended read-cap semantics (Tahoe-LAFS style).

## Consequences
- Easier: random access with `depth + 1` fetches. Partial fetch for streaming and FUSE. Public dedup extends to whole files.
- Harder:
  - **Every file costs at least one extra blob** (the root node), even when it's tiny.
  - Changing the fanout policy later breaks convergence with old public uploads; content stays readable, only dedup suffers.
  - Open: an optional whole-file plaintext hash in the root, for integrity across re-chunking and for lookups.

## Test coverage
The `retifs-core` tests cover:
- round trips from 0 bytes to 3 MB;
- 50 random range reads;
- a deep tree with fanout 2;
- a one-byte read touching only one root-to-leaf path;
- convergence of public files across independent writers;
- detection of missing and tampered chunks and of inconsistent spans;
- all stored blobs being class-sized.

Still missing: cross-implementation manifest vectors.
