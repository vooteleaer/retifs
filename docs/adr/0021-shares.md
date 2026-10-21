# ADR-0021: Shares: a selection of records as its own namespace

- **Status:** proposed (draft)
- **Date:** 2026-10-21
- **Irreversible:** no. A share is an ordinary namespace ([ADR-0017](0017-multi-writer-namespaces.md)); what's new is how a node keeps it filled.

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

## Impact on the threat model
- A member learns the shared records and their content, not the source namespace, its other records, or its address.
- Content read-caps given out can't be taken back: after a revoke, the member can still read the content it was given, as with any revoke. New and changed records after the rotation are not readable to it.
- Holders see a share's chunks as the same chunks as the source's (no re-encryption), so a holder that knows both CIDs learns that the share's content is also in the source. Holders don't learn which namespaces chunks belong to without the read-caps.

## Open
- Write-back: whether members' additions to a share flow into the source namespace, and how (an import rule on the owner's node).
- Shares of shares (resharing) and how the original owner sees them.
- Default attribute filters per content type (location in photos).
