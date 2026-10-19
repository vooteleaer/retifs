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

## Implementation status (2026-10-19)
`retifs-mount [--store DIR] NS MOUNTPOINT` (crate `retifs-fuse`, the `fuser` crate without libfuse) mounts one namespace. It is a client of the local API like any app: it holds no keys and no store. On other platforms it builds but refuses to mount.

**The view:**
- A record with a `path` attribute is the file at that path; its content block is the file's content.
- `type = directory` records give empty directories; other directories are implied by the paths below them.
- Records without a path are under `/.records/<id>`.
- Two records claiming one path: the later ID is shown as `name~<first 8 of its ID>`.

**Attributes as xattrs:**
- Every attribute is `user.retifs.<key>`, readable and writable.
- Text maps to typed values: numbers, `true`/`false` and `null` are typed, `0x…` is bytes, JSON strings and lists are themselves, anything else is a string. A string that would read back as another type is shown quoted.
- Writing `user.retifs.path` moves the file.

**Queries:**
- `/.query/<terms>/` is any name of comma-separated terms (as `retifs query` takes them), percent-decoded: `%2F` is `/`, `%2C` a comma inside a term.
- It lists the matching records as symlinks to their place in the tree, e.g. `.query/album=Prangli 2026/`, `.query/path^=%2Fphotos%2F,type=photo/`.

**Writes:**
- Content is buffered per open file and written back on flush or close as one new version, with `size` and `mtime` (O_TRUNC arrives with the open, so `echo > f` is one version). A write is one operation, a commit on the writer's chain.
- `RecordSet` in the local API now takes content too, so attributes and content change in one commit.
- Renaming a file over an existing one keeps the target record, with its ID, attributes and history: the target takes the new content, and the renamed record is deleted. That is how editors and `sed -i` save, and without it every save would make a new record and lose the file's tags.
- Directory renames move every record below; unlink and rmdir delete records.
- The tree is re-read from the daemon at most once a second, so other members' writes appear within that.

**Live test** (WSL2 Debian, kernel 6.18, against an offline Python RNS shared instance):
- read, create, write, append, truncate, a 3 MiB copy (hash matches);
- mkdir, rename into a directory, rmdir refusing a non-empty directory, unlink;
- xattrs set, read and removed, checked through the CLI;
- a query directory and a percent-encoded path-prefix query;
- `sed -i`: same record ID, attribute kept, one more version.

**Not yet:**
- **Contents in memory:** a file's whole content is held while it's open, and reads fetch the whole file. Range reads via the manifest's random access, and FUSE passthrough for cached reads, come later.
- **Offline reads:** a file whose content isn't local fails with `EIO`; see the [open questions](../06-open-questions.md).
- **Several renames are several commits:** a directory rename or a save is not yet one transaction.
- **Permissions:** the mounting user owns everything. Modes aren't stored.
- **Mounting as a normal user** needs `fusermount3` (the `fuse3` package); the test ran as root.
