# Prototype plan

Prototypes are throwaway. They're for learning, not for locking in the format. The specification comes after.

## Phase 0: reconnaissance
- [ ] Run rnfs on 2–3 mesh nodes (TCP + LoRa) and measure DHT, multi-source and upload_budget.
- [ ] Read the rnfs `specification.md`, Giampaolo's BFS book, the Tahoe-LAFS capability doc and the Dolt Prolly-tree articles.
- [ ] YubiKey: `ykman info` → firmware (5.7+ PIV Ed25519/X25519 vs OpenPGP).
- [ ] Prns ↔ Python RNS interop over TCP and LoRa: Link, Resource, announces ([ADR-0003](adr/0003-rust-and-prns.md)).

## Phase 1: content layer
- [ ] Rust daemon on Prns (behind our own transport trait): chunking, per-chunk encryption, manifest, `/get [cids]`, pinning.
- [ ] Local HTTP gateway.
- [ ] Alpine: `/etc/apk/repositories` → gateway (apk knows nothing about RNS).

## Phase 2: database
- [ ] Attribute records (signed), Prolly-tree index, local queries.
- [ ] Blind index, remote `/query`, live query.
- [ ] Commit chain, history queries.

## Phase 3: identity and permissions
- [ ] Capability chains, group keys.
- [ ] YubiKey-backed Prns `IdentitySigner` (upstream: fallible `sign()`, X25519 exchange through a trait).
- [ ] Session capabilities.

## Phase 4: Linux client
- [ ] Linux: libfuse frontend (POSIX view, `user.retifs.*` xattrs, `.query/` dirs).
- [ ] apkovl in the user namespace.

## Phase 5: thin client
- [ ] USB stick: UKI + EROFS/dm-verity + LUKS/F2FS cache + YubiKey.
- [ ] Bootstrap → system manifest from the namespace → root.

## Later: Haiku client
- [ ] Build Prns on Haiku (Rust tier 3).
- [ ] userlandfs native frontend (attributes and live queries in Tracker).
- [ ] hpkg driver reading from retifs.

After each phase there is a usable system.
