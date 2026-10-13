# ADR-0002: OS integration via FUSE + userlandfs

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** no

## Context
Applications must access retifs transparently, like any mounted filesystem, on Linux, the primary target. Haiku follows later. RNS runs in userspace, so the network part can't live in the kernel. The chunk cache, database, crypto and RNS link live in one userspace daemon. The question is how the OS sees it.

## Principles
Supports 4 (local-first: the mount reads from the local cache) and 6 (the file tree is a view generated from the database). Violates none.

## Options
1. **Loopback NFSv4.** The daemon serves NFS on localhost, and the OS uses its built-in client (Linux kernel, Haiku `nfs4`). One frontend for both OSes. But NFS has no attributes or queries, its offline semantics are poor (hung/timed-out mounts) and AUTH_SYS is weak against other local users.
2. **FUSE + userlandfs.** Thin native frontends per OS over one daemon core.
3. **Kernel drivers.** The kernel reads from the local cache and calls the daemon on a miss (Linux EROFS + cachefiles on-demand pattern). This gives native speed and lets you boot from it, but it's a lot of kernel code per OS for a first iteration.

## Decision
Option 2.

- **Daemon core** is reached only through the native record API ([ADR-0004](0004-native-record-api.md)). Frontends only translate `lookup / getattr / read / readdir / getxattr / setxattr` into it. Other frontends (NFS for LAN clients, a kernel driver for boot) can be added later without touching the core.
- **Linux:** libfuse.
  - Attributes appear as `user.retifs.*` xattrs.
  - Queries appear as virtual directories, e.g. `.query/album=Prangli 2026/`.
  - Cached reads use FUSE passthrough (kernel 6.9+).
- **Haiku (later):** userlandfs with the native Haiku FS interface. Attributes, indexes and live queries are native, so they work in Tracker and `query` like on BFS.

## Impact on the threat model
The mount exposes plaintext to processes in the user's session, and root on the client machine sees everything mounted. This matches the existing "foreign machine" row in the [threat model](../04-threat-model.md): exposure is limited to what the session capability allows, for the session's duration.

## Consequences
- Easier: no kernel code; Linux works in phase 4; the later Haiku frontend gets real attributes and queries.
- Harder: two frontends to maintain. Linux has no native queries, so the `.query/` convention is ours. Booting from retifs (phase 5) still needs a kernel-side path.
