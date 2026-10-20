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
- [ ] Transfer, open: LAN throughput ceiling, occasional unsettled request with ≥4 links, serving side behind the transport trait.
- [x] Local store: slab segments per size class + redb index, tier flags, slot reuse, CID-verified reads (`crates/retifs-store`, [ADR-0007](adr/0007-local-store-layout.md)).
- [x] Local store, continued: keep rules ([ADR-0005](adr/0005-local-store-offline.md)).
- [x] `libretifs` + local endpoint (Unix socket / Windows named pipe): `ping`, `put`, `get`, `status` via `retifsd` ([ADR-0004](adr/0004-native-record-api.md), implementation status).
- [x] Local API, continued: records and attributes, queries, history, `Watch`, transactions, range reads, write sessions (streamed into the store), per-app capabilities ([ADR-0004](adr/0004-native-record-api.md)).
- [ ] Local API, open: fd passing, faster cache writes (batch per tree level, keep segment files open).
- [x] Local HTTP gateway, `retifs-gateway` (a client of `libretifs`, the base for the browser extension): every namespace is a site at `http://<namespace>.localhost:8740/` with its own origin. It's read-only, has a content security policy that allows only its own origin, and refuses foreign `Host` headers (DNS rebinding). Range requests are answered from on-demand reads, so video seeks. It answers only its own user (connection owner from `/proc/net/tcp`, Linux) and refuses cross-site background requests.
- [ ] Gateway, continued: NomadNet pages fetched over RNS, so any NomadNet node can be browsed; micron rendered as HTML.
- [ ] Browser extension (later; Firefox first, Manifest V3): `web+retifs:` links and pasted addresses open through the gateway, micron rendered as HTML, a popup with node status and copies, "follow this site" and "save to retifs". Privileged actions go through a native-messaging host talking to the local API, never through the gateway.
- [ ] Alpine: `/etc/apk/repositories` → gateway (apk knows nothing about RNS).

## Phase 1b: seeking, replication, redundancy, disk budget
- [x] **Holder privacy first (RNS style):** anonymous requests with proof of access (serve token in the read-cap, `HMAC(token, link_id ‖ request)`); the cache tier is never served to others; explicit publish/seed for anonymous public serving ([ADR-0010](adr/0010-continuous-seeking.md), [threat model](04-threat-model.md#holder-privacy-tracking-and-honeypot-attacks)).
- [x] Disk budget: store limit, free-space reserve, hard and elastic tiers, LRU eviction of the cache tier, hole punching, background enforcement, rollback of failed writes ([ADR-0012](adr/0012-disk-budget.md), implementation status).
- [ ] Spare tier: fill free space with replicas by need score (rarest first), evicted first, idle bandwidth only.
- [x] Want-list in the store (readable wants); `/retifs/have`; event-driven seeker woken by announces; `retifs want`; partial `status` ([ADR-0010](adr/0010-continuous-seeking.md), implementation status).
- [x] Blind wants for leases (CID + access token, pulled by the holder).
- [x] Range reads of partially available files: only the chunks a range needs, fetched on demand ([ADR-0002](adr/0002-os-integration.md)).
- [x] Request privacy: per-chunk access proofs (no file token on the wire), one-item requests (`--private-requests`, `batch: 1`), PADMÉ padding with padding fetched like data, per-record personal secrets (versions dedup) ([ADR-0008](adr/0008-chunk-encryption-and-cid.md), [ADR-0010](adr/0010-continuous-seeking.md)).
- [ ] Request privacy, continued: sliced `have` per peer, decoy prefixes, several links with jitter.
- [ ] Holder map: per-chunk/per-group holders from receipts, `have` answers, hints and announces; source ranking, load spreading, failover, measured copy counts.
- [ ] Holder hints in read-caps; store generation counter in announces.
- [x] Leases, renewals, receipts, storage proofs; `retifsd --hold-for-others`, `retifs replicate`; vectors verified against RNS (decision 6, [ADR-0010](adr/0010-continuous-seeking.md)).
- [x] Placement follows need, first slice ([ADR-0014](adr/0014-placement-follows-need.md)): every node holds for others by default; storage nodes recognised from announces (hops); push after lease with `have` first; automatic leases to the nearest nodes by writers and readers until a loss target is met; holder reliability record; lazy repair.
- [x] Link cost: measured RTT and throughput per peer; placement ranks by estimated transfer time and never uses slow links; seeking over a slow link fetches only the manifest unless the rest fits a budget ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Ending need: `retifs forget` (leases run out, shared chunks kept) ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] One upkeep exchange per holder: bundled renewals and receipt requests, sampled storage proofs ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Stamps on lease offers (LXMF construction, verified with LXMF), holder-set cost, offerer limit ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Repair live across machines: a holder goes offline, a farther node is added, the holder returns and is renewed ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Trimming surplus copies with hysteresis; holders whose lease ran out are forgotten, not re-offered ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Mixed leases: per-holder packing sorted by CID, stale leases repacked at renewal ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Signed channels: commits, heads, `/retifs/head`, follow with automatic updates, followers mirror ([ADR-0015](adr/0015-signed-channels.md)).
- [ ] Placement, continued: offer in announces (needs announce app data from Prns), merging small leases per holder at renewal.
- [ ] Own-node pool on a LAN, replication target, repair, storage proofs ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [ ] Volunteer storage offers (`retifs.store`).
- [ ] Diffuse mode: anonymous push seeding, epidemic re-replication with jitter, cover holdings ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [x] Format additions: compression flag in the chunk frame (opt-in zstd) and inline tiny files in manifests (node kind 2); vectors regenerated and verified against RNS.
- [ ] Decide before accepting ADR-0008/0009: full replicas vs erasure coding.
- [ ] Slow links: per-interface priority and airtime budget; no bulk/spare/diffusion over LoRa ([ADR-0013](adr/0013-slow-links.md)); LoRa measurements once a second RNode is available.

## Phase 2: database
- [x] Records, canonical encoding and snapshots; local attribute index and BeFS-style queries; `rec add/set/get/rm`, `query` ([ADR-0016](adr/0016-records-and-snapshots.md)).
- [x] Namespaces published over channels: snapshot versions, followers rebuild them and fetch their content ([ADR-0016](adr/0016-records-and-snapshots.md)).
- [x] NomadNet bridge: any node holding a site namespace (author or follower) serves it as a NomadNet node ([ADR-0016](adr/0016-records-and-snapshots.md)).
- [x] Every modification is a version (single writer): a signed commit per change in the namespace's own channel; `rec history`, `query --at` ([ADR-0006](adr/0006-versioning-and-sharing.md)).
- [x] Multi-writer namespaces: operations per commit, merge per field in stamp order, grants and revokes, join and sync between members ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [x] Read-key rotation on revoke: identities, rekey wrapped with RNS Identity.encrypt, crossing rotations via per-key heads ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [x] Namespace state as a Prolly tree; checkpoints: local resume, named in chains, new members start from a grant holder's checkpoint, history fetched on demand, `ns verify` ([ADR-0018](adr/0018-state-trees.md)).
- [x] Multi-writer, continued: hybrid logical clock for commit times, grants limited by attribute key and expiry and narrowed on delegation, `watch` (long poll per namespace), transactions, `query --at` ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [ ] Multi-writer, open: grants filtered by record content, pruning tombstones.
- [x] `keep:<device>` tag and query-based keep rules (proactive pull), keep mode per namespace, `user.retifs.local` ([ADR-0005](adr/0005-local-store-offline.md)).
- [x] Remote queries to own nodes over a Link, full query language: `--via NODE`, devices admitted with app-style scopes ([ADR-0019](adr/0019-remote-query-and-blind-index.md)).
- [ ] Blind index for search nodes without the read key: declared keys, exact match, vectors against RNS ([ADR-0019](adr/0019-remote-query-and-blind-index.md)); remote live query.
- [x] Per-writer commit chains (one commit per modification), merge, history queries, per-record `versions` ([ADR-0017](adr/0017-multi-writer-namespaces.md)).

## Phase 3: identity and permissions
- [x] Group namespaces, validate-on-read (every reader checks grants on merge), key rotation on removal, limited grants narrowed on delegation ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [ ] Capability chains between people beyond grants, filtered share namespaces.
- [ ] YubiKey-backed Prns `IdentitySigner` (upstream: fallible `sign()`, X25519 exchange through a trait).
- [x] Per-app capabilities on the local socket: an app socket with tokens scoped to namespaces and read/write, pinned to the executable on Linux ([ADR-0004](adr/0004-native-record-api.md)).
- [ ] Session capabilities; app scopes as capability chains (record filters, keys).

## Phase 4: Linux client
- [x] Linux: FUSE frontend on `libretifs`: `retifs-mount` (POSIX view of a namespace, `user.retifs.*` xattrs, `.query/` dirs, saves keep the record) ([ADR-0002](adr/0002-os-integration.md)).
- [x] Reads on demand: only the byte ranges read, fetched from peers within a wait, never hanging (offline semantics, [ADR-0002](adr/0002-os-integration.md)).
- [x] Writes without whole-file buffering: write sessions spooled in the daemon, streamed into the store ([ADR-0002](adr/0002-os-integration.md)).
- [x] Packaging, first step: systemd user units for retifsd, retifs-mount@<namespace> and retifs-gateway (`packaging/systemd`), and "Try it" in the README.
- [ ] Linux, continued: FUSE passthrough, several namespaces in one mount, distribution packages (.deb, apk).
- [ ] apkovl in the user namespace.

## Phase 5: thin client
- [ ] USB stick: UKI + EROFS/dm-verity + LUKS/F2FS cache + YubiKey.
- [ ] Bootstrap → system manifest from the namespace → root.

## Later: Haiku client
- [ ] Build Prns on Haiku (Rust tier 3).
- [ ] userlandfs native frontend (attributes and live queries in Tracker).
- [ ] hpkg driver reading from retifs.

After each phase there is a usable system.
