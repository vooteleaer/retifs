# Prototype plan

Prototypes are throwaway. They're for learning, not for locking in the format. The specification comes after.

## Phase 0: reconnaissance
- [ ] Run rnfs on 2–3 mesh nodes (TCP + LoRa) and measure DHT, multi-source and upload_budget.
- [ ] Read the rnfs `specification.md`, Giampaolo's BFS book, the Tahoe-LAFS capability doc and the Dolt Prolly-tree articles.
- [ ] YubiKey: `ykman info` → firmware (5.7+ PIV Ed25519/X25519 vs OpenPGP).
- [ ] Prns ↔ Python RNS interop over TCP and LoRa: Link, Resource, announces ([ADR-0003](adr/0003-rust-and-prns.md)). TCP done, LoRa pending: [results](recon/prns-interop.md).

## Phase 1: content layer
- [x] `retifs-core` spike: FastCDC chunking, per-chunk encryption with size classes, CIDs, and test vectors verified against Python RNS ([ADR-0008](adr/0008-chunk-encryption-and-cid.md), proposed).
- [x] Manifests: Merkle tree of sealed nodes, `FileRef` read-cap, random-access reads ([ADR-0009](adr/0009-manifest-format.md), proposed).
- [x] `retifsd` + `retifs get` on Prns: `/retifs/get [cids]` from the slab store, batched breadth-first fetch by read-cap, verified across Windows/Linux/aarch64 and LAN/backbone ([first-transfer](recon/first-transfer.md)).
- [x] Transfer, continued: transport trait (client side), several links per peer, multi-source with retry, local-first cache ([first-transfer](recon/first-transfer.md)).
- [ ] Transfer, open: LAN throughput ceiling, occasional unsettled request with ≥4 links, pinning/leases, serving side behind the transport trait.
- [x] Local store: slab segments per size class + redb index, tier flags, slot reuse, CID-verified reads (`crates/retifs-store`, [ADR-0007](adr/0007-local-store-layout.md)).
- [ ] Local store, continued: LRU eviction of the cache tier, lease expiry for the serving tier, keep rules ([ADR-0005](adr/0005-local-store-offline.md)).
- [x] `libretifs` + local endpoint (Unix socket / Windows named pipe): `ping`, `put`, `get`, `status` via `retifsd` ([ADR-0004](adr/0004-native-record-api.md), implementation status).
- [ ] Local API, continued: records/attributes (`create`, `put_block`, `set`, `query`), streaming / fd passing, per-app capabilities, faster cache writes (batch per tree level, keep segment files open).
- [ ] Local HTTP gateway (a client of `libretifs`).
- [ ] Alpine: `/etc/apk/repositories` → gateway (apk knows nothing about RNS).

## Phase 1b: seeking, replication, redundancy, disk budget
- [ ] **Holder privacy first (RNS style):** anonymous requests with proof of access (serve token in the read-cap, `HMAC(token, link_id ‖ request)`); the cache tier is never served to others; explicit publish/seed for anonymous public serving ([ADR-0010](adr/0010-continuous-seeking.md), [threat model](04-threat-model.md#holder-privacy-tracking-and-honeypot-attacks)).
- [ ] Disk budget: store limit, free-space reserve, per-tier quotas, LRU eviction of the cache tier, space reclamation in slabs ([ADR-0012](adr/0012-disk-budget.md)).
- [ ] Want-list in the store (readable and blind wants); `/retifs/have`; event-driven seeker triggered by announces; partial `status`/`get` ([ADR-0010](adr/0010-continuous-seeking.md)).
- [ ] Holder map: per-chunk/per-group holders from receipts, `have` answers, hints and announces; source ranking, load spreading, failover, measured copy counts.
- [ ] Holder hints in read-caps; store generation counter in announces.
- [ ] Leases, `/retifs/put`, receipts (with test vectors: decision 6).
- [ ] Own-node pool on a LAN, replication target, repair, storage proofs ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [ ] Volunteer storage offers (`retifs.store`).
- [ ] Diffuse mode: anonymous push seeding, epidemic re-replication with jitter, cover holdings ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [ ] Decide full replicas vs erasure coding before accepting ADR-0008/0009.

## Phase 2: database
- [ ] Attribute records (signed), Prolly-tree index, local queries; `set` / `query` / `watch` / `transaction` / `at` in the API.
- [ ] `keep:<device>` tag and query-based keep rules (proactive pull).
- [ ] Blind index, remote `/query`, live query.
- [ ] Per-writer commit chains (one commit per modification), merge, history queries, per-record `versions`.

## Phase 3: identity and permissions
- [ ] Capability chains, group namespaces, filtered share namespaces, validate-on-read, key rotation on removal.
- [ ] YubiKey-backed Prns `IdentitySigner` (upstream: fallible `sign()`, X25519 exchange through a trait).
- [ ] Session capabilities; per-app capabilities on the local socket.

## Phase 4: Linux client
- [ ] Linux: libfuse frontend on `libretifs` (POSIX view, `user.retifs.*` xattrs, `.query/` dirs).
- [ ] apkovl in the user namespace.

## Phase 5: thin client
- [ ] USB stick: UKI + EROFS/dm-verity + LUKS/F2FS cache + YubiKey.
- [ ] Bootstrap → system manifest from the namespace → root.

## Later: Haiku client
- [ ] Build Prns on Haiku (Rust tier 3).
- [ ] userlandfs native frontend (attributes and live queries in Tracker).
- [ ] hpkg driver reading from retifs.

After each phase there is a usable system.
