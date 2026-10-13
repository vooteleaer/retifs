# Architecture

## Three primitives

1. **Encrypted chunks**: content (from IPFS).
2. **Prolly-tree database**: attributes, indexes, queries (from BeFS).
3. **Signed chain of roots**: history, namespaces, permissions (from RNS identity).

Files, folders, albums, packages, versions and branches are all combinations of these.

## 1. Content: encrypted chunks

- Chunking: content-defined chunking (FastCDC). Target size is ~16–32 KB for LoRa and ~256 KB on fast links.
- **Each chunk is encrypted separately** with its own key/nonce and MAC. A chunk can be verified and decrypted on arrival, independently of the others, which enables random access and streaming.
- **The CID is computed over the ciphertext**, so pinning nodes verify integrity without the key. The hash of the content itself lives in the encrypted manifest.
- Chunks are padded to fixed size classes so the type doesn't leak through the size.
- **Manifest** = Merkle tree mapping byte range → chunk CID. Large files get a tree, so reading one byte of a 10 GB file costs a couple of manifest nodes and one chunk.

### Key schemes (always encrypted; the key choice determines the dedup scope)

| Content | Key | Dedup |
|---|---|---|
| Public (packages, public documents) | convergent: `HKDF(hash(chunk))` | network-wide |
| Restricted (internal packages, group content) | `HKDF(publisher_secret, "retifs.pkg" ‖ name ‖ channel)` | across versions of a line |
| Personal | random | none |

- `publisher_secret` is a separate 256-bit secret, **not** the RNS identity private key.
- With deterministic keys, the construction is SIV-style, with the nonce derived from the content. See [irreversible decisions](02-irreversible-decisions.md).
- The content key is wrapped for the reader the way an RNS SINGLE packet does it: ephemeral X25519 → ECDH → HKDF → Token (AES + HMAC-SHA256). Ratchet keys are used where possible (forward secrecy).
- Groups use a shared group key, wrapped separately for each member, and the key is rotated when a member is removed.

## 2. Database: records and attributes

- **Record** = stable random ID + attributes + 0..N blocks (CIDs). An image in several resolutions is one record with several blocks. A contact may have no block at all.
- **File identity ≠ version.** Mutable attributes (album, tags, path) attach to the record ID. Content-derived ones (EXIF, duration, dimensions) attach to the CID.
- **Attribute record:** `(record_id, identity, key, value, seq)`, signed. CRDT: LWW per (identity, key). File content versions are multi-value, so conflicts are visible.
- **Indexes:** Prolly trees (content-addressed B-trees). The same content gives the same root, and sync transfers only the branches that differ.
- **Blind index:** index key = `HMAC(group_key, "key=value")`. A remote node can only do exact matches. Range and prefix queries run locally after sync.
- **Query language:** minimal (=, range, prefix, AND/OR), BeFS-style. Geo as geohash prefix.
- **Live query:** subscription over a Link. The node sends only the new CID and the changed attributes.
- **A folder is a query.** An album is `album = "Prangli 2026"`.
- **POSIX view:** `path` is an attribute. Rename = attribute change, and a folder = prefix query. `path` isn't unique, so a conflict is presented as `plan (2).txt`.

## 3. History, namespaces, permissions

- **Database root CID = snapshot.** A version is a root.
- **Commit:** `{parents[], db_root, author, time, message, signature}`, encrypted. A branch is a reference to the latest commit. Two heads = conflict, and a merge commit resolves it.
- Changing several records under one root is an atomic commit.
- History queries are ordinary queries against an older root.
- Sub-namespaces are versioned independently (photo collection ≠ system configuration).
- **Granularity:** Time Machine style (all commits for an hour, hourly for a day, daily for a month...). Unique chunks of squashed commits expire through the lease.
- **Namespace** = destination (`retifs.ns.<name>` + identity), addressed like an RNS destination hash. Updates carry a sequence number (rollback protection) and propagate via announce.
- **Capabilities** (UCAN-like): `{issuer, audience, resource, action, expiry, proof}`, content-addressed. Delegation chain where each link may only narrow. Read permission = key, and write permission = signature.
- **Revocation:** short expiry times plus signed revocation records. Revoking read access = key rotation.

## Write path

1. The application writes to a local overlay (POSIX).
2. On close/fsync (with a delay), the commit runs chunking → encryption → CIDs. Unchanged chunks stay the same.
3. **Content first, then the reference:** chunks go to pinning nodes (with a lease), and only then the signed manifest and root.
4. Confirmation: "only here" vs "N copies on the network" (signed receipts).
5. Databases and VM disks stay local and go to the network only as periodic snapshots.

## Read path

- FUSE: `read(offset, len)` fetches only the chunks it needs, with readahead on sequential reads.
- Many chunks in one Link request (`/get [cid1, cid2, ...]`), in parallel from several nodes.
- **Images:** several resolutions as separate CIDs. Progressive format (JPEG XL). Opening an album prefetches thumbnails.
- **Audio/video:** MP3 frames are independent, and MP4 uses faststart/fMP4. Chunk boundaries follow GOPs, and adaptive bitrate variants are separate CIDs. Over LoRa, Opus 6–12 kbps / Codec2.

## Garbage collection and lifetime

- Nodes are blind, so graph-based GC is impossible.
- **A pin is a lease:** a signed "keep these CIDs until X". If it isn't renewed, the chunks are deleted. The lease is expressed as a **list of chunks**, so structure doesn't leak.
- Cache (LRU) ≠ pin.
- **Local store:** metadata always fully local; content in pinned / cache / serving tiers, stored as ciphertext. `keep:<device>` tags and query-based keep rules pull chunks proactively for offline use. See [ADR-0005](adr/0005-local-store-offline.md).
- Renewal can be delegated to a pinning service via a capability.
- **Deletion = key destruction.**
- Archive nodes deliberately pin valuable public content (library).

## Packages (Haiku hpkg model)

- A package is a manifest/CID. It's mounted (packagefs/FUSE), not extracted.
- Activation = a signed CID list, so update and rollback are atomic.
- `.PackageInfo` provides/requires → attributes. A repo is the query `type=package AND publisher=<id>`.
- Two levels: system namespace and user namespace.
- Reproducible builds: several identities sign the same CID.
- Prototype: the real hpkg format plus a FUSE driver that reads from retifs.

## Client / OS

- **Native API:** `retifsd` (cache, database, crypto, Prns) is a local shared instance, like `rnsd`. Applications use `libretifs` over a Unix socket and work with records, attributes, queries and history directly, with no paths. Each app gets a narrowed capability. Local and remote use the same messages. See [ADR-0004](adr/0004-native-record-api.md).
- **OS integration:** the file tree is one client of the native API, exposed through thin frontends. Linux (libfuse) is the primary target, and Haiku (userlandfs, native attributes and queries) comes later. See [ADR-0002](adr/0002-os-integration.md).
- Thin client: a minimal local bootstrap, with applications and data on the network. **The local disk is a cache**, and a pinned set enables offline use.
- **Identity travels with you:** a YubiKey (device key, authorised by the root) plus a root identity kept offline. Login issues a short-lived session capability.
- USB stick layout: EFI (UKI) · bootstrap EROFS + dm-verity · F2FS cache with LUKS (bound to the YubiKey) · writable layer on tmpfs.
- Client: Linux first. Haiku later, as a UX demo (native BFS, Tracker and packagefs). Infrastructure: Alpine (pinning, transport and gateway nodes).
