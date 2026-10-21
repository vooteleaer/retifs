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
- **Windows (decided 2026-10-21): the Cloud Files API**, the sync-provider interface OneDrive and the Nextcloud desktop client use, rather than a virtual drive (WinFsp, which needs its own driver installed) or ProjFS (an optional Windows feature).
  - Each mounted namespace is a *sync root*: an ordinary NTFS folder (e.g. `%USERPROFILE%etifs\photos`) registered with Windows. Records with a `path` appear in it as placeholder files, with sizes and times but no content.
  - Opening a placeholder makes Windows ask the provider for its data, which it reads from the daemon on demand (`ReadRange`, as the FUSE mount's reads do).
  - Explorer's own commands map onto keep tags ([ADR-0005](0005-local-store-offline.md)): **Always keep on this device** sets `keep:<device>` (the content is pulled and pinned); **Free up space** clears it and turns the file back into a placeholder. Explorer shows each file's state with its own icons (in sync, available offline, online only).
  - Changes made in the folder (new files, edits, renames, deletes) go to the daemon as writes, write sessions and transactions, like the FUSE mount's. Remote changes update the placeholders, woken by `Watch`.
  - Attributes are shown where Windows has room for them (custom columns and properties are possible later); queries stay in apps and the desktop utility.
  - A provider program (`retifs-cloudfiles`, Rust over the Win32 `CfApi` bindings) runs alongside the daemon; the desktop utility turns it on and off per namespace.

## Impact on the threat model
The mount exposes plaintext to processes in the user's session, and root on the client machine sees everything mounted. This matches the existing "foreign machine" row in the [threat model](../04-threat-model.md): exposure is limited to what the session capability allows, for the session's duration.

## Consequences
- Easier: no kernel code; Linux works in phase 4; the later Haiku frontend gets real attributes and queries.
- Harder: three frontends to maintain (FUSE, userlandfs, Cloud Files). Linux has no native queries, so the `.query/` convention is ours. Booting from retifs (phase 5) still needs a kernel-side path.

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

**Reads on demand (2026-10-20):**
- A read asks the daemon for just that byte range (`ReadRange` in the local API; `retifs read CAP` on the command line). The daemon walks the manifest as far as it's held here (`manifest::missing_for_range`) and fetches the missing nodes and chunks the range covers, in rounds, from the namespace's peers and the file's hinted holders. Fetched chunks go to the cache tier.
  - Reading 100 KB at offset 20 MB of a 30 MB file fetched 10 of its 2,211 chunks.
  - Through the mount: reads at six offsets of a 20 MiB file match the source, and the whole file reads at about 240 MB/s when local.
- **Offline semantics (decided):** a read never hangs.
  - Content that's here is read whatever the network does.
  - Content that isn't: the read waits while a peer is reachable, up to `--wait` (default 30 s, a mount option), then fails with `EIO` and a message in the mount's log. With no peer known it fails at once.
  - Over a slow link (ADR-0013) a peer is used only if the transfer fits the slow-link budget.
  - Measured: with the only holder stopped, a read of a range not held failed after its 8 s wait; with no peer known, at once.
- A lookup that misses re-reads the namespace if its view is older than 100 ms, so a record made a moment ago by another program is found.

**Watching (2026-10-20):** the local API's `Watch { ns, since, timeout_ms }` is a long poll that answers as soon as the namespace's records change here, whether from a local write or other members' writes merged in. It returns a change count. The mount keeps one watch open on a thread of its own and re-reads the namespace only when told, at the latest every 30 s, instead of every second. Live: an attribute set through the CLI showed through the mount's xattrs within 2 s.

**Transactions (2026-10-20):** the local API's `Transaction { ns, steps }` applies creates, sets and deletes as one commit (one version), so other members see all of them or none. The single-record requests are one-step transactions. The mount uses them for directory renames (every record below in one commit) and for saves that rename over a file (the target's new content and the temporary record's deletion in one commit). Live: moving a directory of two files added exactly one version.

**Writes without buffering (2026-10-20):**
- The local API has write sessions: `WriteBegin`, `WriteAt`, `WriteRead`, `WriteTruncate`, then `WriteCommit` or `WriteAbort`. The daemon spools written ranges to a sparse file under the store and keeps the record's previous content for everything not written, so only what changed crosses the API.
- `WriteCommit` fetches any of the previous content it keeps that isn't here, then streams the result into the store with `manifest::write_reader`. That uses FastCDC over a stream and builds the same file (same root) as writing the bytes from memory, so dedup across versions is unchanged.
- The mount writes through a session per open file. A save that renames over a file now gives the target the source's content by reference (`TxStep::Set` with `blocks`), without copying it.
- Live (WSL2): a 200 MiB file written through the mount in 4.4 s, with the mount's peak memory at 3 MiB and the daemon's at 50 MiB. Overwriting 1 MiB in its middle in place matches the same change made locally.

**Not yet:**
- FUSE passthrough for cached reads.
- **Permissions:** the mounting user owns everything. Modes aren't stored.
- **Mounting as a normal user** needs `fusermount3` (the `fuse3` package); the test ran as root.
