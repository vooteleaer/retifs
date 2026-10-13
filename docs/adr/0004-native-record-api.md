# ADR-0004: Native record API via a local shared instance

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** no

## Context
The file tree is a compatibility view ([vision](../00-vision.md), principle 6), but until now FUSE ([ADR-0002](0002-os-integration.md)) was the only way for applications to reach retifs. Paths and folders then become the de facto API, which is exactly the legacy we want to leave behind. A mount also exposes everything to every process the user runs.

RNS shows a model that works: `rnsd` owns the interfaces, and applications attach to it as a *shared instance* over a local socket.

## Principles
Supports 2 (the API is the three primitives), 5 (attributes and queries, not a relational engine), 6 (the file tree is just one client) and 4 (local-first: the API works offline against the local daemon). Violates none.

## Options
1. **FUSE only.** Simple, but paths stay the real interface, and there's no per-app access control.
2. **D-Bus service.** Native to the Linux desktop, but a poor fit for bulk data, desktop-only, and with no remote story.
3. **Own shared-instance API** over a local socket, using the same messages as the remote protocol.

## Decision
Option 3.

- **`retifsd`** owns the cache, keys, database and Prns. Applications use **`libretifs`** (a Rust crate with a C ABI), which connects to a Unix socket (`$XDG_RUNTIME_DIR/retifs.sock`). The daemon is required: an application never becomes the instance itself, so there is one owner of keys and cache.
- **API = the three primitives, no paths:**

  | Call | Meaning |
  |---|---|
  | `create(attrs)` → record_id | new record, no name or location needed |
  | `set(record, key, value)` | attribute (signed and synced underneath) |
  | `put_block(record, stream)` → CID / `read(cid, range)` | content |
  | `query(expr)` → cursor | `type=image AND album="Prangli 2026"` |
  | `watch(expr)` → stream | live query |
  | `transaction { … }` → commit | atomic change across records |
  | `at(root)` | the same API against history |
  | `status(record)` | "only here" vs "N copies on the network" |

- `path` is an optional attribute that only legacy software sets.
- **Per-app capabilities.** The daemon identifies the connecting process (`SO_PEERCRED`) and gives each application a narrowed capability, e.g. "read/write `type=image` in namespace `photos`". These are the same UCAN-style chains used between people.
- **One protocol, two transports.** Local API messages are the same requests as the remote protocol (`/get`, `/query`, live query over a Link). Locally they travel over the Unix socket. Remotely they travel over an RNS Link, so a thin client can use a daemon on another machine through the same library.
- **Bulk data** is passed as file descriptors (memfd/pipe) over the socket, not copied through messages.
- **FUSE is a client of this API.** The FUSE frontend from ADR-0002 is built on `libretifs`, not beside it.

The full draft API is in [07-api.md](../07-api.md).

## Impact on the threat model
- Improvement: an application no longer automatically sees everything the user owns. It gets only what its capability allows. A FUSE mount still exposes whatever it mounts, so mounting is a deliberate, broad grant.
- New surface: the local socket and the per-process identification. The socket must be private to the user, and capabilities bind to the process, not just the UID.

See the [threat model](../04-threat-model.md).

## Consequences
- Easier: applications work with records, queries and history directly. Local and remote access look the same. FUSE shrinks to a translation layer.
- Harder: applications must be written for the API to benefit. Identifying apps reliably per process on Linux is imperfect without a sandbox (Flatpak/portal identity helps). Language bindings beyond Rust/C come later.
