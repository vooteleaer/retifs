# ADR-0021: Shares: a selection of records as its own namespace

- **Status:** accepted (prototype), 2026-10-29
- **Date:** 2026-10-21
- **Irreversible:** partly. A share is an ordinary namespace ([ADR-0017](0017-multi-writer-namespaces.md)); what's new is how a node keeps it filled. The copies' derived record IDs are [irreversible decision 12](../02-irreversible-decisions.md) (owner nodes must derive the same ones), with vectors verified with RNS (`verify_share_rns.py`).

## Context
A namespace has one read key: whoever has its address reads all of it. People rarely want that. They share an album, a folder, a few files, not their whole photo library. Grants can't be limited to some records ([ADR-0017](0017-multi-writer-namespaces.md), decided 2026-10-20: it would make merging depend on arrival order), and a query in a link is a view, not a limit ([ADR-0020](0020-sharing-names-invitations.md)).

## Principles
- Supports "from location to identity": you share *these* with *Mom*, not a folder on a server.
- No new crypto, no re-encryption: a share points at the same content.
- Uses the existing pieces: namespaces, grants and key rotation, `Watch`, invitations.

## Decision
**A share is its own namespace, filled from a source namespace by a selection, and kept up to date by the owner's node.**

- **Selection**, one of:
  - records by ID (the files picked);
  - a folder: `path^=/Pictures/Prangli/`;
  - a query: `album="Prangli 2026"` (an album is a query).
- **What's copied:** each selected record's attributes and its content references. The content isn't copied or re-encrypted: a read-cap carries its own seed, so the share's members can read and fetch exactly that content, and nothing else in the source. A share may leave attributes out (e.g. `geo`, `exif:gps*`, so photos are shared without where they were taken).
- **Kept up to date:** the owner's node watches the source (`Watch`) and writes the differences into the share: records that start matching appear, changed ones change, records that stop matching are deleted from the share (not from the source). Any of the owner's nodes holding both namespaces may do this; equal writes merge to the same state.
- **Members:** invited like any namespace ([ADR-0020](0020-sharing-names-invitations.md)), read-only by default. With write, a member's additions to a shared folder or album can flow back into the source (open: below).
- **Ending a share:** revoking a member rotates the share's read key ([ADR-0017](0017-multi-writer-namespaces.md)); deleting the share stops its updates. What a member already read stays readable to it, as for any namespace.
- **Where it starts:**
  - the file manager's context menu: **Share with retifs…** on files or a folder (Explorer through the Cloud Files provider, [ADR-0002](0002-os-integration.md); Nautilus and Dolphin on Linux);
  - the desktop utility and apps (an album's Share button).

  A small dialog asks who (contacts, or a QR code or link), read or write, how long, and which attributes to leave out.

### Format (decided 2026-10-21)
- **The definition** is a record in the source namespace: `type = "retifs.share"`, `name`, `share` (the share namespace's address), the selection as `select` (query terms, comma-separated, as keep rules write them) or `ids` (a list of record IDs), and `omit` (a list of attribute keys; `exif:gps*` is a prefix). Every node holding the source sees the source's shares and can keep them filled; members of the share see nothing of it. The user chose this over a setting on one device, so a share keeps updating while any of the owner's nodes runs.
- **A copy's record ID** is derived, so every owner node writes the same records and equal writes merge to one state:
  ```text
  share_id = HKDF-SHA256(ikm = source record ID, salt = "retifs/v1/share-record", info = ns_id of the share)[0..16]
  ns_id    = SHA-256("retifs/v1/ns" ‖ the share's writer key)[0..16]   (ADR-0015)
  ```
  Both inputs are fixed for the share's life (`ns_id` doesn't change when the read key rotates). A member can't find the source ID (128 random bits) from it, and two shares of one source give the same record unrelated IDs. Vectors: `test-vectors/share-v1.json`, verified with Python RNS's HKDF (`verify_share_rns.py`).
- **A copy** holds the source record's attributes but the omitted ones and the owner's keep tags (`keep`, `keep:<device>`: what the owner's devices hold says nothing about the members'), and the same content references. The share namespace is the owner nodes' to fill: records in it that no selected source record maps to are deleted on the next update.

## Implementation status (2026-10-21)
- Local API: `ShareCreate { source, name, terms | ids, omit }` makes the share namespace, writes the definition into the source and fills the share; `ShareDelete { source, id }` deletes the definition, so updates stop (the share namespace and what members hold stay). CLI: `retifs share create NAME --from NS [TERM]... [--id ID]... [--omit KEY]...`, `share list NS`, `share rm NS ID`.
- The daemon keeps shares filled: when a namespace's records change here (a local write or other members' merged in), every share defined in it is brought up to date in one commit, and all of them once a minute. A node that doesn't hold the share namespace, or may not write to it yet, skips it.
- **Explorer (2026-10-21):** the Cloud Files provider adds **Share with retifs…** to the context menu of files and folders in its folder (a registry verb under the user's classes, limited to the folder with `AppliesTo`; Windows 11 shows it under "Show more options"; removed with `--unregister`). A folder is shared as `path^=<its path>/`, a file by its record ID, under a name made from the folder's or file's name. The share's link ([ADR-0020](0020-sharing-names-invitations.md), for `retifs open`) goes on the clipboard and a message box says what was shared. The dialog asking who, for how long and what to leave out comes with the desktop utility. Live: 10 checks (the verb registered and removed, a folder and a file shared, a second share of one file named apart, a path outside the folder refused).
- Members join a share like any namespace (its address, `ns join`) and read its records and content; they get no grant, so they only read. Invitations (ADR-0020) to a share work as to any namespace (`invite create`, by the share's local name); write-back is later.
- Live (two nodes, 2026-10-21, 16 checks): a two-record selection by album with `geo` and `exif:gps*` left out; IDs unlike the source's; keep tags not copied; content by reference; the member reads the records and their content but nothing else of the source; a new matching record, a change, a record that stops matching (it stays in the source) and a deleted source record all reach the member; `share rm` stops updates.

## Impact on the threat model
- A member learns the shared records and their content, not the source namespace, its other records, or its address.
- Content read-caps given out can't be taken back: after a revoke, the member can still read the content it was given, as with any revoke. New and changed records after the rotation are not readable to it.
- Holders see a share's chunks as the same chunks as the source's (no re-encryption), so a holder that knows both CIDs learns that the share's content is also in the source. Holders don't learn which namespaces chunks belong to without the read-caps.

## Decided (2026-11-11, owner)
- **Write-back, by the owner's rule:** a member the owner gave write in a share may add records to it; the owner's node copies those additions into the source, where the share's selection says (a folder share: into that folder; an album share: into that album). The share stays a namespace of its own and the owner's node decides what crosses. Members' changes and deletions don't touch the owner's records in the source. Not built yet.
- **Resharing, like any library:** a member may make a share of a share (kept current by their node), and may pass the link on, as with any library: a read link is a key and can't be held back. The original owner sees nothing of it, as with a letter forwarded. Nothing to build beyond what shares already do; apps may offer it.
- **Linux file managers (2026-11-11):** `retifs share path PATH...` does what Explorer's verb does for files, or one folder, in a library mounted from this store: finds the library and the records (a folder by its path prefix), makes the share, prints the link and puts it on the clipboard (`wl-copy`, `xclip` or `xsel`). retifsd puts "Share with retifs" in Nautilus's scripts folder and a "Share with retifs…" service menu in Dolphin's, in the user's own folders, when those file managers are installed (`packaging/linux`). Live (WSL, FUSE): one file, a folder of two, and a file outside any library (refused).
- ~~Default attribute filters per content type (location in photos).~~ Built (2026-11-11) as one default for every share: `geo` is left out unless the share keeps it (`--keep geo`, `ShareCreate { keep }`); Explorer's menu and the apps get the default too. Other keys only on request (`--omit exif.*`).
