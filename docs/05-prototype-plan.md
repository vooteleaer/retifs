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
- [x] fd passing on Unix: `put` hands the daemon the open file ([ADR-0004](adr/0004-native-record-api.md)).
- [x] Handles on Windows: `put` hands the daemon the open file (`PutHandle`); the daemon duplicates it from the process on the other end of the owner's pipe, so only the client's own handles can be named ([ADR-0004](adr/0004-native-record-api.md)).
- [ ] Local API, open: faster cache writes (batch per tree level, keep segment files open).
- [x] Local HTTP gateway, `retifs-gateway` (a client of `libretifs`, the base for the browser extension): every namespace is a site at `http://<namespace>.localhost:8740/` with its own origin. It's read-only, has a content security policy that allows only its own origin, and refuses foreign `Host` headers (DNS rebinding). Range requests are answered from on-demand reads, so video seeks; bodies stream in 1 MiB pieces, so a large file is never held whole. It answers only its own user (connection owner from `/proc/net/tcp` on Linux, the owning process's user SID on Windows) and refuses cross-site background requests.
- [x] Gateway, continued: any NomadNet node browsed at `http://nn-<address>.localhost:8740/`, its own origin: pages and files fetched by retifsd over Reticulum (`NomadNetPage`, also `retifs nomadnet NODE [PATH]`), micron rendered as HTML (headings, dividers, styles, colours, alignment, links within and across nodes with their variables; input fields shown read-only).
- [ ] Gateway: NomadNet forms (fields sent with a link), identifying to nodes that ask for it.
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
- [x] Request privacy, continued: private rounds ask each peer about a random slice (≤ 16) with decoy prefixes, requests spaced by random pauses ([ADR-0010](adr/0010-continuous-seeking.md)).
- [ ] Request privacy: private requests spread over several links per peer.
- [x] Where a library's copies are, said in the library: a `retifs.holders` record per writing node, so every member reads files placed by a node that's away; readers keeping content are peers too (`/retifs/reader`) ([ADR-0035](adr/0035-holders-in-the-library.md)).
- [x] Holder map, first slice: per-file holders from receipts and `have` answers, in memory and bounded; sources ranked (holds, holds some, unknown, holds none, just failed; then by link), reads spread over up to three holders, instant failover, copies seen in `retifs status` ([ADR-0010](adr/0010-continuous-seeking.md)).
- [ ] Holder map, continued: per-chunk holders, holders learned from own nodes (gossip, opt-in).
- [x] Holder hints in read-caps (`…@<node>,<node>`): `get` and `want` ask them, `put --hint` adds this node ([ADR-0010](adr/0010-continuous-seeking.md)).
- [ ] Store generation counter, to proven or own peers only (not in public announces; size and privacy open, [open questions](06-open-questions.md)).
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
- [x] Copies by policy: at least three of every needed file, a library's own number (`retifs ns copies NS N`), one copy at another site, trimming never takes the last copy at another site; `retifs nodes` lists the storage nodes placement knows ([ADR-0011](adr/0011-redundancy-by-default.md), [ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Announce app data (Prns 0.3.8): a `retifs.node` announce states its interval (a node missing 5 gets no new leases) and whether it holds for others ([ADR-0014](adr/0014-placement-follows-need.md)).
- [x] Placement, continued: the offer in announces (`room`, a power of two; placement skips nodes without room for a lease), small leases per holder merged at renewal ([ADR-0014](adr/0014-placement-follows-need.md)).
- [ ] Own-node pool on a LAN, replication target, repair, storage proofs ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [ ] Volunteer storage offers (`retifs.store`).
- [ ] Diffuse mode: anonymous push seeding, epidemic re-replication with jitter, cover holdings ([ADR-0011](adr/0011-redundancy-by-default.md)).
- [x] Format additions: compression flag in the chunk frame (opt-in zstd) and inline tiny files in manifests (node kind 2); vectors regenerated and verified against RNS.
- [x] Decide before accepting ADR-0008/0009: full replicas now, erasure coding later below chunks; a 512 B smallest class ([format decisions](08-open-format-decisions.md)).
- [ ] External review of the irreversible formats (ADR-0008/0009 first; also 0010's leases, 0015–0019, decisions 12 and 13), then accept them. The reviewer's starting point: [external review](09-external-review.md).
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
- [x] Pruning tombstones in checkpoints: dead records no writer can still precede, by each writer's frontier and write intervals ([ADR-0018](adr/0018-state-trees.md)).
- [x] Grants filtered by record content: decided against (order-dependent); separate namespaces per contributor, and queries across namespaces (`query NS1,NS2 …`) ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [x] `keep:<device>` tag and query-based keep rules (proactive pull), keep mode per namespace, `user.retifs.local` ([ADR-0005](adr/0005-local-store-offline.md)).
- [x] Remote queries to own nodes over a Link, full query language: `--via NODE`, devices admitted with app-style scopes ([ADR-0019](adr/0019-remote-query-and-blind-index.md)).
- [x] Blind index for search nodes without the read key: declared keys, exact match, index channel derived from the read key, `/retifs/query` with proof, `query --search NODE`; vectors verified against RNS ([ADR-0019](adr/0019-remote-query-and-blind-index.md)).
- [x] Lazy members: `ns join --lazy` holds the checkpoint, the chains since and only the state paths it needs (changed records on sync, others on demand) ([ADR-0018](adr/0018-state-trees.md)).
- [x] Search, continued: one builder per index channel (the lowest-addressed writer's node that's around) ([ADR-0019](adr/0019-remote-query-and-blind-index.md)).
- [ ] Search: remote live queries beyond `Watch`.
- [x] Maps, places and addresses as public libraries: vector tiles, places by cell, a gazetteer searched through the blind index, no internet service ([ADR-0027](adr/0027-places.md), [ADR-0028](adr/0028-maps-over-retifs.md)).
- [x] Per-writer commit chains (one commit per modification), merge, history queries, per-record `versions` ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [x] Leaving a library: hidden at once, its data goes in the background; one made here only with `--mine`. Deleting a library on every member's node: `ns delete NS --yes`, a `retifs.deleted` record counted only from a writer holding `grant`, 30 days' grace ([ADR-0034](adr/0034-deleting-a-library.md)).

## Phase 3: identity and permissions
- [x] Group namespaces, validate-on-read (every reader checks grants on merge), key rotation on removal, limited grants narrowed on delegation ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- [ ] Capability chains between people beyond grants.
- [x] Public libraries announced (`retifs.library`, app data with name, about, address, what it holds by type, area, format), heard into a local list and joined from it; members' node addresses in the namespace so every member syncs with every member ([ADR-0022](adr/0022-public-namespaces-discovery.md), [ADR-0029](adr/0029-announced-public-libraries.md)).
- [x] Compatibility rules for every app: versioned network and library formats, must-ignore and must-keep, unknown shown ([ADR-0030](adr/0030-data-outlives-apps.md)).
- [x] Every node size-limited; storage-less nodes with only a keyring on disk, their own libraries fetched back from their holders after a restart ([ADR-0031](adr/0031-storage-less-nodes.md)).
- [x] Shares: a selection (records, a folder, a query) as its own namespace kept up to date by the owner's nodes, content by reference, attributes optionally left out; started from Explorer's context menu ([ADR-0021](adr/0021-shares.md)).
- [x] Shares: location (`geo`) left out by default, `--keep geo` to share it ([ADR-0021](adr/0021-shares.md)).
- [ ] Shares, continued: write-back from members, resharing; Nautilus and Dolphin menus.
- [x] Sharing: `retifs:` links and QR codes, one-use invitations (`/retifs/invite`), contacts as petnames in `me`, fingerprint words ([ADR-0020](adr/0020-sharing-names-invitations.md)).
- [x] Readers as members: invitations to read (`invite create NS --read`), readers listed in `ns info`, rekeys wrapped to every member ([ADR-0017](adr/0017-multi-writer-namespaces.md), [ADR-0020](adr/0020-sharing-names-invitations.md)).
- [ ] Sharing, continued: profiles (`/retifs/profile`), sending links over LXMF.
- [ ] YubiKey-backed Prns `IdentitySigner` (upstream: fallible `sign()`, X25519 exchange through a trait).
- [ ] Recovery kit: 24 words for a recovery identity that can bring the user's libraries back (proposed, nothing built; [ADR-0033](adr/0033-recovery.md)).
- [x] Per-app capabilities on the local socket: an app socket with tokens scoped to namespaces and read/write, pinned to the executable on Linux ([ADR-0004](adr/0004-native-record-api.md)).
- [ ] Session capabilities; app scopes as capability chains (record filters, keys).

## Phase 4: Linux client
- [x] Linux: FUSE frontend on `libretifs`: `retifs-mount` (POSIX view of a namespace, `user.retifs.*` xattrs, `.query/` dirs, saves keep the record) ([ADR-0002](adr/0002-os-integration.md)).
- [x] Reads on demand: only the byte ranges read, fetched from peers within a wait, never hanging (offline semantics, [ADR-0002](adr/0002-os-integration.md)).
- [x] Writes without whole-file buffering: write sessions spooled in the daemon, streamed into the store ([ADR-0002](adr/0002-os-integration.md)).
- [x] `retifs mount NS [DIR]`, `retifs mount`, `retifs unmount NS`: one command for the file tree on Linux (FUSE) and Windows (Cloud Files) ([ADR-0002](adr/0002-os-integration.md)).
- [x] Albums in the file views (`retifs-tree`): a file whose `album` names albums is also under `/Albums/<album>/`; deleting it there takes it out of the album ([ADR-0002](adr/0002-os-integration.md), [ADR-0026](adr/0026-photos-thumbnails-albums.md)).
- [x] Packaging, first step: systemd user units for retifsd, retifs-mount@<namespace> and retifs-gateway (`packaging/systemd`), and "Try it" in the README.
- [x] Debian packages (`packaging/deb`, amd64 and arm64): retifsd and the tools as user services; Reticulum (Prns or another shared instance) installed apart.
- [x] retifsd mounts every library itself in `~/retifs` ([ADR-0035](adr/0035-holders-in-the-library.md)); a `.deb` for glibc 2.31 (Debian 11, Ubuntu 20.04 and 22.04, elementary OS 6 and 7); the apps also as Flatpaks; packages don't bring prnsd ([getting started](getting-started.md)).
- [x] Every install joins the library `retifs-installers`, where new versions of retifs and the apps arrive.
- [ ] Linux, continued: FUSE passthrough, several namespaces in one mount, an Alpine package (apk).
- [ ] apkovl in the user namespace.

## Later: user clients (Android, Linux, Haiku, Windows)
- [x] First clients: the desktop utility (`retifs-desktop`: libraries, invitations and links, members, leaving and deleting, announced public libraries) on Linux and Windows; the Android app (`retifs-android`: retifsd on the phone, apps asking it for libraries). Code in their own repositories ([getting started](getting-started.md)).
- [ ] Clients, continued: an app in the spirit of the Nextcloud mobile and desktop clients: browse records, search (local, own node, blind index), import and export files, keep rules per device, search capabilities. Haiku (Tracker already shows attributes).
- [x] Attributes from what's in files, for every file that enters: `retifs-extractd` (EXIF, audio tags, document properties, types; [ADR-0023](adr/0023-attribute-extraction.md)).
- [x] Conventions, first: keys per media type from the extractor (time ISO 8601, `geo` as [lat, lon]; [ADR-0023](adr/0023-attribute-extraction.md)), a record's type is a MIME type ([ADR-0025](adr/0025-types-are-mime-types.md)), block roles and thumbnails, albums, favourites ([ADR-0026](adr/0026-photos-thumbnails-albums.md)), people and events ([ADR-0024](adr/0024-people-and-events.md)), places ([ADR-0027](adr/0027-places.md)).
- [x] Haiku's media attributes (`Audio:Artist`, `Media:Width`, …) as views of the extractor's keys in `retifs-haikufs` ([ADR-0023](adr/0023-attribute-extraction.md)).
- [ ] Conventions, continued: content-bound attributes (decision 7; the `extracted` marker stands in), video frames as thumbnails.
- [ ] Apps on those records, iterated one at a time (each in its own repository):
  - [x] photos, first: phone backup with thumbnails, favourites, albums (also moved between libraries), on Android, Linux and Haiku;
  - [x] map ([ADR-0028](adr/0028-maps-over-retifs.md)), contacts and calendars ([ADR-0024](adr/0024-people-and-events.md)): the map from public libraries, an address book in `me`, a calendar per library holding events;
  - [ ] photos, continued: timeline from range queries, shared albums as shares in the app, faces computed on own devices (`retifs-facesd`, [ADR-0026](adr/0026-photos-thumbnails-albums.md));
  - [ ] contacts and calendars as Android system sync adapters;
  - [ ] music player: library from audio tags, playback over range reads, offline by keep rules per device, playlists as records holding queries.

## Windows client
- [x] Cloud Files provider (`retifs-cloudfiles`): a namespace as a sync root, placeholders hydrated on demand, remote changes followed, keep tags as "Always keep on this device" / "Free up space" ([ADR-0002](adr/0002-os-integration.md)).
- [x] Local changes as writes: new and edited files and folders, deletes (and the Recycle Bin), renames, saves that rename aside.
- [x] Holding up in Explorer: `cloud-filter` vendored and patched (a failed read reports its range, no panic on failure), placeholders filled folders first, reads waiting for content that keeps arriving (up to 10 min), Explorer told when a folder's entries change.
- [x] Installer: `retifs-setup.exe`, per user (`packaging/windows`).
- [x] Share with retifs… in Explorer's context menu ([ADR-0021](adr/0021-shares.md)): a classic verb ("Show more options" on Windows 11), the recipient's command on the clipboard.
- [x] Setup brings Photos and Map where their repositories have a Windows front end; `retifs:` links open the utility.
- [ ] In Windows 11's top-level menu (a packaged `IExplorerCommand`), a share dialog (in the desktop utility); attributes as properties and columns.

## Phase 5: thin client
- [ ] USB stick: UKI + EROFS/dm-verity + LUKS/F2FS cache + YubiKey.
- [ ] Bootstrap → system manifest from the namespace → root.

## Later: Haiku client
- [x] retifsd and the `retifs` CLI on Haiku (2026-10-30): built natively on a Haiku nightly with HaikuPorts' Rust, with one small Prns patch (TCP keepalive options); the node ran against a shared instance on another machine, heard and joined public libraries and held copies for others.
- [x] prnsd on Haiku (2026-10-30), from a Haiku branch of Prns kept for upstream: mDNS LAN discovery left out (Haiku has no `IP_PKTINFO`), `if-addrs` and `mio` patched (on Haiku an accepted socket does not inherit non-blocking mode), lifecycle locks through `flock`. A Haiku node runs on its own: prnsd connected to another node, retifsd on it, a public library heard, joined and searched.
- [ ] RNode over USB serial on Haiku; retifsd with the same `mio` fix (until mio has it).
- [x] Haiku packages (`prns`, `retifs`): retifsd mounts every library as a volume in `~/retifs` after Tracker and Deskbar are up; a left library's volume goes.
- [x] userlandfs native frontend (attributes and live queries in Tracker), 2026-10-31: `retifs-haikufs`, a userlandfs module with Haiku's kernel file system interface. A namespace mounts as a volume; directories, contents and each record's attributes as Haiku typed attributes (`BEOS:TYPE` from the record's MIME `type`), so Tracker shows them as columns. Queries in Haiku's query language (`query`, Tracker's Find), live ones included: the exact string parts go to retifs as terms (its index, a search node for a library held in part), the whole expression filters; `lsindex` lists the namespace's attributes. Writing (2026-11-01): new files, contents (through the daemon's write sessions, one version per close, `O_APPEND` too), directories, moves, deletes, size and time, and attributes written and removed, each one commit as in the FUSE mount; node monitors are told, so Tracker windows follow. Contacts (`application/x-person`, ADR-0025) carry Haiku People's `META:` attributes as views of their keys (`META:company` is `org`, `META:wphone` `phone:work`), so People opens, edits and makes retifs contacts. Tracker's own attributes (`_trk/…`) and any on a directory without a record stay with the mount.
- [ ] hpkg driver reading from retifs.

After each phase there is a usable system.
