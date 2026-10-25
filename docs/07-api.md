# Native API (draft)

> **Status: draft v0, unstable.** This describes the intended shape of the native record API ([ADR-0004](adr/0004-native-record-api.md)). It is ahead of the code in places and behind it in others; the table below says what exists. Parts that touch [irreversible decisions](02-irreversible-decisions.md) are marked **⚠ irreversible**: their final form needs an ADR and test vectors.

## What exists (2026-10-20)
The implemented local API is the `Request`/`Response` enums in `crates/libretifs` (msgpack frames over a Unix socket or named pipe). It is flatter than this draft: plain requests instead of handles and streams.

| Section | Implemented as | Differences from the draft |
|---|---|---|
| §3 Connection and access | owner socket `retifs.sock`; app socket `apps.sock` with `Hello { token }`, `AppAdd/List/Remove` | apps get a namespace list and read/write, not per-key scopes; the token is pinned to the executable on Linux |
| §4 Namespaces | `Namespaces`, `NsInfo`, `NsAddress`, `NsJoin`, `NsKeep`, `NsCheckpoint`, `NsVerify` | namespaces are created on first write (or by `NsAddress`); `NsInfo` on an unknown name is an error |
| §5–6 Records, attributes | `RecordCreate`, `RecordSet`, `RecordGet`, `RecordDelete` | |
| §7 Blocks | `ReadRange` (fetches missing chunks within a wait), `WriteBegin/At/Read/Truncate/Commit/Abort` | content is one `content` block per record; write sessions instead of `put_block` |
| §8 Queries | `Query` with the CLI's terms, optionally `at` a version; `SearchQuery` through a search node's blind index; `NsSearch` publishes the index | remote queries without the read key are exact matches on declared keys ([ADR-0019](adr/0019-remote-query-and-blind-index.md)) |
| §9 Live queries | `Watch { ns, since, timeout_ms }`: a long poll per namespace | no per-query events; clients re-query |
| §10 Transactions, history | `Transaction` (create, set, delete steps, one commit), `RecordHistory`, `Query { at }` | |
| §11 Availability | `Status`, `Want`, `NsKeep`, keep rules as records | a miss waits up to the client's wait, then fails (`EIO` in the mount), not `Unavailable` at once |
| §12 Sharing | `NsGrant` (rights, `keys`, `until`), `NsRevoke`, channels (`ChannelCreate`, `Follow`, …), shares (`ShareCreate`, `ShareDelete`), invitations (`InviteCreate`, `InviteList`, `InviteCancel`, `InviteAccept`, [ADR-0020](adr/0020-sharing-names-invitations.md)) | a filtered share is a namespace filled by the owner's nodes, not a projection with re-wrapped keys ([ADR-0021](adr/0021-shares.md)) |
| §14 Wire protocol | the same requests over an RNS Link (`/retifs/api`) for the user's own devices; `/retifs/query` for search nodes ([ADR-0019](adr/0019-remote-query-and-blind-index.md)) | own nodes get the full API; search nodes only blind index lookups |
| §15 C ABI | not yet | |
| §16 POSIX mapping | `retifs-mount` ([ADR-0002](adr/0002-os-integration.md)) | |

Not yet: fd passing, the C ABI, per-query live events.

Large content: one message is at most 256 MiB (`MAX_FRAME`), and through another node (`--via`) a request is one RNS Resource, at most 1 MiB with its envelope. Clients move large files through write sessions and range reads in pieces: the CLI's `rec add/set --file` above 4 MiB (1 MiB pieces, 512 KiB `--via`) and `retifs read` (4 MiB pieces, 512 KiB `--via`); the mounts always do.

## Contents
1. [Overview](#1-overview)
2. [Core types](#2-core-types)
3. [Connection and access](#3-connection-and-access)
4. [Namespaces](#4-namespaces)
5. [Records](#5-records)
6. [Attributes](#6-attributes)
7. [Blocks (content)](#7-blocks-content)
8. [Queries](#8-queries)
9. [Live queries](#9-live-queries)
10. [Transactions and history](#10-transactions-and-history)
11. [Availability and offline](#11-availability-and-offline)
12. [Sharing and capabilities](#12-sharing-and-capabilities)
13. [Errors](#13-errors)
14. [Wire protocol](#14-wire-protocol)
15. [C ABI](#15-c-abi)
16. [POSIX mapping (FUSE)](#16-posix-mapping-fuse)
17. [Examples](#17-examples)
18. [Open points](#18-open-points)

---

## 1. Overview

```
 app ──libretifs──┐
 app ──libretifs──┤  Unix socket            ┌── Prns ── network
 FUSE frontend ───┼──────────────► retifsd ─┤
 HTTP gateway ────┘  ($XDG_RUNTIME_DIR/     └── local store (ciphertext)
                      retifs.sock)
 remote app ──libretifs── RNS Link ──► retifsd (on another machine)
```

- **`retifsd`** is the shared instance. It owns keys, the local store, the database and the network. Applications never touch keys or ciphertext.
- **`libretifs`** is the client library: a Rust crate (async, runtime-agnostic) plus a C ABI (§15). Other language bindings are generated from the C ABI later.
- **Same protocol locally and remotely** (§14). Over the Unix socket, bulk data travels as file descriptors. Over an RNS Link, it travels as Resources.
- **No paths.** The API works with records, attributes, blocks, queries and history. `path` is just an attribute (§6.3).

All calls below are shown as Rust signatures. The C ABI mirrors them one to one.

## 2. Core types

| Type | Form | Notes |
|---|---|---|
| `RecordId` | 16 random bytes | Stable for the record's whole life. Shown as base32. |
| `Cid` | version byte + hash of the ciphertext | **⚠ irreversible** (decision 1). Content-addressed and verifiable without the key. |
| `RootId` | `Cid` of a database root | A snapshot of a namespace (§10). |
| `CommitId` | `Cid` of a commit object | **⚠ irreversible** format (decision 8). |
| `NsAddr` | 16-byte RNS destination hash | `retifs.ns.<name>` + owner identity. |
| `Identity` | RNS identity hash (16 bytes) | A person, device or app identity. |
| `Device` | short name, e.g. `laptop` | Bound to a device identity. Used in `keep:<device>`. |
| `Key` | UTF-8 string, max 255 bytes | Attribute key (§6.3). |
| `Value` | tagged union, below | |
| `Capability` | content-addressed token | UCAN-like (§12). **⚠ irreversible** semantics (decision 4). |

```rust
enum Value {
    Str(String),          // UTF-8
    Int(i64),
    Float(f64),           // NaN not allowed
    Bool(bool),
    Time(i64),            // milliseconds since Unix epoch, UTC
    Bytes(Vec<u8>),       // max 4 KiB; larger data belongs in a block
    Ref(RecordId),        // link to another record
    Geo(String),          // geohash
}
```

Values compare within their own type only. A query comparing `Int` with `Str` matches nothing. It doesn't coerce.

## 3. Connection and access

```rust
let rt = Retifs::connect().await?;                 // local socket
let rt = Retifs::connect_remote(dest, cap).await?; // over an RNS Link
```

- If `retifsd` isn't running, `connect` fails with `DaemonUnavailable`. An app never becomes the instance itself.
- The daemon identifies the connecting process (`SO_PEERCRED`, plus sandbox identity where available). An unknown app starts with **no access**.

```rust
let grant = rt.request_access(&[
    Scope::new(ns, Action::Read  | Action::Write, "type = \"image\""),
    Scope::new(ns, Action::Read, "type = \"album\""),
], "Import photos from camera").await?;
```

- The daemon asks the user through its own agent UI. That flow is outside this API.
- Returns `Grant { capability, scopes }`. The granted scopes may be narrower than requested.
- Grants persist per app identity until revoked or expired. `rt.access()` lists the current scopes.

| Action | Allows |
|---|---|
| `Read` | query, get attributes, read blocks |
| `Write` | create records, set attributes, put blocks |
| `Delete` | tombstone records |
| `History` | `at()`, `log()` |
| `Share` | issue capabilities to others (§12), narrowed from its own |
| `Keep` | change `keep:` tags and keep rules |

A scope's filter is a query (§8). The app sees and changes only records matching it, and writes that would take a record outside its scope fail with `OutOfScope`.

## 4. Namespaces

A namespace is an independently versioned database: the photo collection and the system configuration are separate.

```rust
rt.namespaces().await?                        -> Vec<NsInfo>
rt.namespace(addr_or_petname).await?          -> Ns
rt.create_namespace("photos", NsOptions{..}).await? -> Ns
```

`NsInfo { addr, petname, owner, role, head: CommitId, synced: SyncState }`

- Petnames are local labels. Resolving `community/…`-style community names is an open question.
- The namespace update format with sequence numbers and rollback protection is **⚠ irreversible** (decision 5).

All following calls are made on an `Ns` handle (or on a transaction, §10).

## 5. Records

A record = stable ID + attributes + 0..N blocks.

```rust
ns.create(attrs: &[(Key, Value)]).await?   -> RecordId
ns.get(id).await?                          -> Record
ns.get_many(&[id]).await?                  -> Vec<Record>
ns.delete(id).await?                       // tombstone
ns.shred(id, Confirm::Irreversible).await? // destroy content keys
```

```rust
struct Record {
    id: RecordId,
    attrs: Vec<Attr>,          // §6
    blocks: Vec<BlockRef>,     // §7
    created: Time,
    modified: Time,
    tombstoned: bool,
}
```

- **`delete`** writes a tombstone. The record disappears from queries but remains readable in history (`at()`).
- **`shred`** destroys the content keys of the record's blocks wherever this daemon holds them (crypto-shredding). The content becomes unreadable in every root, including history. Content shared under a convergent key can't be shredded and returns `NotShreddable`.

## 6. Attributes

### 6.1 Calls

```rust
ns.set(id, key, value).await?
ns.set_many(id, &[(Key, Value)]).await?
ns.unset(id, key).await?
ns.attr(id, key).await?        -> Option<Attr>     // resolved view
ns.attr_all(id, key).await?    -> Vec<Attr>        // every author's value
```

```rust
struct Attr {
    key: Key,
    value: Value,
    author: Identity,
    seq: u64,
    binds_to: Binding,   // Record or Content(Cid)
}
```

### 6.2 Semantics

- Each attribute write is a signed record `(record_id, identity, key, value, seq)`. The serialization is **⚠ irreversible** (decision 2).
- **CRDT:** last-writer-wins per `(identity, key)`. Different authors' values coexist. `attr()` returns the newest by default, and `attr_all()` returns all of them.
- **Record vs content binding** (**⚠ irreversible**, decision 7):
  - Mutable, user-given attributes (`name`, `album`, `tags`, `path`) bind to the **record** and survive content changes.
  - Content-derived attributes (`width`, `duration`, `exif.*`, `mime`) bind to the **block's CID** and are recomputed for new content.
  - The daemon decides the binding from the key's convention (§6.3). Apps can't override it.

### 6.3 Key conventions

The schema is a convention, not enforced. Keys are lowercase, `.` separates groups, and `:` separates a qualifier.

| Key | Type | Binding | Meaning |
|---|---|---|---|
| `type` | Str | record | what the record is, a MIME type: `image/jpeg`, `application/x-person`, `text/calendar`, `inode/directory` ([ADR-0025](adr/0025-types-are-mime-types.md)) |
| `name` | Str | record | human title |
| `path` | Str | record | POSIX view only (§16); not unique |
| `tags` | Str | record | multi-valued via `tags:<tag> = true` |
| `album` | Str | record | |
| `mime` | Str | content | |
| `size` | Int | content | plaintext bytes |
| `width`, `height`, `duration` | Int | content | |
| `exif.*` | any | content | `exif.lens`, `exif.exposure`, `exif.fnumber`, `exif.iso`, `exif.focal`, `exif.orientation`, `exif.software` |
| `geo`, `geo:<label>` | Geo | content for photos, record otherwise | `[lat, lon]` (floats): where the record is ([ADR-0027](adr/0027-places.md)) |
| `taken`, `camera` | Str | content | ISO 8601 as recorded; make and model |
| `audio.*` | Str/Int | content | `title`, `artist`, `album`, `track`, `year`, `genre` (not `album`: that's the user's) |
| `doc.*` | Str/Int | content | `title`, `author`, `pages` |
| `extracted` | Str | record | which content the content keys were taken from ([ADR-0023](adr/0023-attribute-extraction.md)) |
| `type=application/x-person`, `type=text/calendar` | — | record | people and events: [ADR-0024](adr/0024-people-and-events.md) |
| `keep` / `keep:<device>` | Bool | record | availability (§11) |
| `retifs.*` | — | — | reserved for the daemon |

Apps may add their own keys, preferably prefixed (`com.example.rating`).

## 7. Blocks (content)

A block is one piece of content attached to a record with a **role**: `original`, `thumb:256`, `variant:720p`, `subtitle:et`, ... A record has at most one block per role.

```rust
ns.put_block(id, role, source: impl AsyncRead).await? -> Cid
ns.put_block_fd(id, role, fd).await?                  -> Cid   // zero-copy
ns.remove_block(id, role).await?
ns.blocks(id).await?                                  -> Vec<BlockRef>
ns.read(cid, range: Range<u64>).await?                -> Bytes
ns.open(cid).await?                                   -> BlockReader // AsyncRead + Seek, fd-backed locally
```

`BlockRef { role, cid, size, local: Presence }`

- `put_block` chunks, encrypts and stores locally, then queues upload. It returns once the block is durable **locally**. Network replication is reported through `status()` (§11).
- Replacing a role's block creates a new content version. Concurrent replacements from different authors are kept as multiple values (conflicts are visible, as with files).
- `read`/`open` fetch only the chunks covering the range. When a chunk is neither local nor fetchable, you get `Unavailable` (§11).
- Chunking, padding and the per-chunk encryption construction are **⚠ irreversible** (decisions 3, 9) and invisible to apps.

## 8. Queries

```rust
ns.query(expr, opts).await?   -> Cursor<RecordId>
ns.count(expr).await?         -> u64
```

`QueryOpts { order_by: Option<(Key, Asc|Desc)>, limit: Option<u32>, fetch: Fetch::Ids | Fetch::Attrs(&[Key]) }`

Queries always run against the local database (metadata is always local, [ADR-0005](adr/0005-local-store-offline.md)), so they never block on the network.

### 8.1 Grammar

```ebnf
expr     = term { "OR" term } ;
term     = factor { "AND" factor } ;
factor   = "NOT" factor | "(" expr ")" | cond ;
cond     = key op value
         | key "IN" value ".." value      (* inclusive range *)
         | key "^=" string                (* prefix *)
         | "HAS" key ;                    (* attribute exists *)
op       = "=" | "!=" | "<" | "<=" | ">" | ">=" ;
value    = string | int | float | bool | time | ref ;
time     = iso8601 | reltime ;            (* 2026-10-13, -30d, -2h *)
ref      = "@" base32-record-id ;
```

Examples:

```
type = "image" AND album = "Prangli 2026"
type = "document" AND modified > -30d
geo ^= "ud9w"                              -- geohash prefix: Tallinn area
path ^= "/home/projects/"                  -- a "folder"
HAS tags:urgent AND NOT type = "email"
```

- The language is deliberately minimal (BeFS-style): no joins, no aggregation beyond `count`.
- Indexes are created on demand per key. Querying an unindexed key works, with a scan, and the daemon may index it afterwards.
- **Remote queries** (against a node that isn't ours) support only exact `=` matches through the blind index (decision 10). The API returns `RemoteOpUnsupported` for anything else.

## 9. Live queries

```rust
let mut w = ns.watch(expr, WatchOpts { initial: true }).await?;
while let Some(ev) = w.next().await {
    match ev? {
        Event::Added(id)                  => ..., // now matches
        Event::Changed(id, keys)          => ..., // still matches; these keys changed
        Event::Removed(id)                => ..., // no longer matches, or tombstoned
        Event::ContentChanged(id, role, cid) => ...,
        Event::Synced(head)               => ..., // a remote change has been merged
    }
}
```

- With `initial: true`, the stream starts with `Added` for every current match, then switches to changes.
- Events are coalesced. A slow consumer gets the latest state, not every intermediate step.
- Remote watch (over a Link) sends only new CIDs and changed attributes.

## 10. Transactions and history

### 10.1 Transactions

```rust
let commit = ns.transaction(|tx| async move {
    let a = tx.create(&[("type", "album".into()), ("name", "Prangli 2026".into())]).await?;
    tx.set(photo, "album", "Prangli 2026".into()).await?;
    Ok(())
}, "Create album").await?;   // -> CommitId
```

- **Every modification is a version** ([ADR-0006](adr/0006-versioning-and-sharing.md)): each call outside a transaction is its own signed commit, and the daemon never batches separate modifications.
- A transaction is atomic: everything lands in one root, or nothing does.

### 10.2 History

```rust
ns.head().await?                   -> CommitId
ns.log(from, limit).await?         -> Vec<Commit>
ns.at(root_or_commit).await?       -> NsView     // read-only Ns: get, query, read
ns.diff(a, b).await?               -> Vec<Change>
ns.heads().await?                  -> Vec<CommitId>   // >1 = unresolved conflict
ns.merge(&[CommitId], resolver).await? -> CommitId

// per record
ns.versions(id).await?             -> Vec<Version>  // { commit, time, author, changed: keys/roles }
ns.get_at(id, commit).await?       -> Record
ns.restore(id, commit).await?      -> CommitId      // a new version with the old state
```

`Commit { id, parents, root, author, seq, time, message }`

- Each writer (person or device) has its own append-only chain with its own `seq`. The namespace state is the merge of all writers' heads, computed by every reader, and writes without a valid capability are ignored on merge.
- Two heads mean two devices or people changed things concurrently. Attributes merge automatically (CRDT). Concurrent content versions stay multi-valued until resolved, and `merge` records the resolution.
- `at()` gives the whole API, read-only, against an old snapshot. History queries are ordinary queries.
- **Retention:** every version is kept by default. `ns.set_retention(policy)` lets a namespace opt into thinning, which drops only old *content*, never commits.
- Commits and metadata sync promptly, while the content of intermediate versions may upload lazily (shown as `OnlyHere` in `status()`).

## 11. Availability and offline

```rust
ns.status(id).await?        -> Availability
ns.fetch(id, roles).await?  -> FetchHandle   // progress stream
ns.keep(id, device: Option<Device>, on: bool).await?
ns.keep_rules().await?      -> Vec<KeepRule>
ns.add_keep_rule(device, expr).await? -> RecordId
ns.store_usage().await?     -> StoreUsage
```

```rust
struct Availability {
    blocks: Vec<(Role, Presence)>,   // Local | Partial(f32) | Remote | Unreachable
    kept_on: Vec<Device>,
    replicas: Replication,           // OnlyHere | Network { copies: u32, receipts }
}
```

- `keep(id, Some("laptop"), true)` sets `keep:laptop = true` and pulls the chunks proactively ([ADR-0005](adr/0005-local-store-offline.md)). `None` means all the user's devices.
- Keep rules are records (`type = "retifs.keep-rule"`) holding a query, so they sync like everything else.
- `store_usage()` reports the pinned/cache/serving tiers, and pinned sets that don't fit.
- **Misses:** `read`/`open` return `Unavailable { fetch_queued: bool }` instead of hanging.

## 12. Sharing and capabilities

```rust
rt.create_group("family", &[alice, bob]).await? -> Ns   // group namespace, all members write
ns.create_share(filter, Share {..}).await?     -> (Ns, Capability) // filtered read-only share namespace
ns.add_member(identity, actions, filter).await?

ns.share(Share {
    audience: Identity,
    filter: "album = \"Prangli 2026\"",
    actions: Action::Read,
    expiry: Time,
}).await?                         -> Capability

ns.publish(id).await?             -> ReadCap      // record + key, as one shareable reference
rt.accept(capability).await?      -> Ns           // mount someone else's grant
ns.revoke(capability_id).await?
ns.members().await?               -> Vec<Member>  // groups
ns.remove_member(identity).await? // rotates the group key
```

- **A share is a namespace** ([ADR-0006](adr/0006-versioning-and-sharing.md)). A group namespace has one group key wrapped for each member. A filtered share is a projection namespace with its own key: only per-block keys are re-wrapped, and no content is copied.
- A capability is `{issuer, audience, resource, action, expiry, proof}`, content-addressed. Each delegation can only narrow, and the daemon rejects any wider grant with `CannotWiden`. **⚠ irreversible** semantics (decision 4).
- Read permission = key, and write permission = signature.
- Revoking read access rotates keys, so the revoked party keeps what they already received but nothing new.
- `publish` returns a Tahoe-style read-cap (CID + key). Anyone holding it can read that record version.

## 13. Errors

```rust
enum Error {
    DaemonUnavailable,
    AccessDenied { needed: Action },
    OutOfScope,                     // write would leave the app's scope
    NotFound,
    Tombstoned,
    Unavailable { fetch_queued: bool },
    Conflict { heads: Vec<CommitId> },
    InvalidQuery { at: usize, msg: String },
    InvalidValue,
    CannotWiden,
    NotShreddable,
    RemoteOpUnsupported,
    StoreFull,
    Expired,                        // capability or grant
    Transport(String),
    Internal(String),
}
```

Every error is returned. Nothing panics across the API boundary.

## 14. Wire protocol

Applications use `libretifs` and never speak the protocol directly. It's documented here so frontends in other languages and remote use are possible.

- **Framing (local):** length-prefixed messages over a `SOCK_SEQPACKET` Unix socket. Bulk data is passed as file descriptors (`SCM_RIGHTS`: memfd for writes, pipe or memfd for reads).
- **Framing (remote):** RNS Link requests to `/retifs/v0/<op>`. Bulk data travels as RNS Resources.
- **Envelope:** `{v: 0, id: u32, op: str, args: map}` → `{id, ok: map}` | `{id, err: {code, detail}}`. Streams (`watch`, cursors, fetch progress) send multiple replies with the same `id` and end with `{id, end: true}`.
- **Encoding:** msgpack. These messages are transient, so the encoding isn't irreversible. Anything the daemon *signs or stores* (attribute records, commits, capabilities) uses the canonical serialization of decision 2.
- **Versioning:** `v` is the protocol version. The daemon answers `hello` with the versions it supports.

## 15. C ABI

Opaque handles, status codes, caller-provided buffers, and callbacks for streams.

```c
typedef struct retifs retifs_t;
typedef struct retifs_ns retifs_ns_t;
typedef int32_t retifs_status;   /* 0 = OK, negative = error code from §13 */

retifs_status retifs_connect(retifs_t **out);
void          retifs_close(retifs_t *rt);

retifs_status retifs_ns_open(retifs_t *rt, const char *name, retifs_ns_t **out);
retifs_status retifs_create(retifs_ns_t *ns, const retifs_attr *attrs, size_t n,
                            retifs_record_id *out);
retifs_status retifs_set(retifs_ns_t *ns, const retifs_record_id *id,
                         const char *key, const retifs_value *value);
retifs_status retifs_put_block_fd(retifs_ns_t *ns, const retifs_record_id *id,
                                  const char *role, int fd, retifs_cid *out);
retifs_status retifs_open_block(retifs_ns_t *ns, const retifs_cid *cid, int *fd_out);
retifs_status retifs_query(retifs_ns_t *ns, const char *expr,
                           retifs_cursor **out);
retifs_status retifs_watch(retifs_ns_t *ns, const char *expr,
                           retifs_event_cb cb, void *user, retifs_watch **out);
const char   *retifs_strerror(retifs_status s);
```

The full header is generated from the Rust crate (cbindgen).

## 16. POSIX mapping (FUSE)

The FUSE frontend ([ADR-0002](adr/0002-os-integration.md)) is an ordinary client of this API, with a broad grant.

| POSIX | API |
|---|---|
| `lookup` / `readdir` of `/a/b/` | `query("path ^= \"/a/b/\"")`, one level deep |
| `open` + `read` | `blocks(id)` → `open(cid)` of role `original` |
| `create` + `write` + `close`/`fsync` | `create` with `path`, then `put_block(original)` on close |
| `rename` | `set(id, "path", new)` |
| `unlink` | `delete(id)` |
| `mkdir` | nothing stored; a directory exists while something has that path prefix (an empty dir is a hidden `type = "dir"` record) |
| `getxattr user.retifs.<key>` | `attr(id, key)` |
| `setxattr user.retifs.<key>` | `set(id, key, value)` |
| `getxattr user.retifs.local` | `status(id)` |
| `ls /mnt/retifs/.query/<expr>/` | `query(expr)` as a virtual directory |
| duplicate `path` | shown as `plan (2).txt` |
| `read` of an unavailable block | blocks up to a timeout if there's a route, else `EIO` |

## 17. Examples

### Import a photo

```rust
let rt = Retifs::connect().await?;
let ns = rt.namespace("photos").await?;

let id = ns.create(&[
    ("type".into(), "image".into()),
    ("name".into(), "Sunset at the harbour".into()),
    ("album".into(), "Prangli 2026".into()),
]).await?;
ns.put_block_fd(id, "original", file.as_raw_fd()).await?;
ns.put_block(id, "thumb:256", thumbnail.as_slice()).await?;
// width, height, exif.*, geo are filled in by retifs-extractd (ADR-0023)
```

### Show an album and keep it updated

```rust
let mut w = ns.watch(r#"type = "image" AND album = "Prangli 2026""#,
                     WatchOpts { initial: true }).await?;
while let Some(ev) = w.next().await {
    match ev? {
        Event::Added(id) => ui.add(id, ns.read_role(id, "thumb:256").await?),
        Event::Removed(id) => ui.remove(id),
        _ => {}
    }
}
```

### Keep an album on the laptop

```rust
ns.add_keep_rule(Some("laptop".into()), r#"album = "Prangli 2026""#).await?;
```

### Share an album read-only for a month

```rust
let cap = ns.share(Share {
    audience: friend,
    filter: r#"album = "Prangli 2026""#.into(),
    actions: Action::Read,
    expiry: now() + days(30),
}).await?;
// send `cap` to the friend, e.g. over LXMF
```

### Look at last week's version

```rust
let old = ns.at(ns.log(None, 200).await?.iter()
    .find(|c| c.time < now() - days(7)).unwrap().id).await?;
let docs = old.query(r#"type = "document""#, Default::default()).await?;
```

## 18. Open points

- App identity on Linux without a sandbox (see [open questions](06-open-questions.md)).
- Multi-valued attributes: is `tags:<tag> = true` enough, or do we need a real set type?
- ~~Daemon-side metadata extraction: which formats, and does it run sandboxed?~~ A separate daemon, an app with a key limit ([ADR-0023](adr/0023-attribute-extraction.md)).
- Pagination and consistency of cursors across commits (snapshot the root per cursor?).
- Partial namespace sync for small devices.
- Language bindings beyond Rust/C: which first?
