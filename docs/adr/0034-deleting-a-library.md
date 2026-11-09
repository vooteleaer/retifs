# ADR-0034: Deleting a library everywhere

- **Status:** accepted (prototype), 2026-11-09
- **Date:** 2026-11-09
- **Irreversible:** partly. A record type every daemon reads (`retifs.deleted`) and the rule that only a writer holding `grant` makes it count. No new crypto, no format change in commits or operations.

## Context
Leaving a library (`ns leave`) drops it from one device; other members keep it, and so do the holders this device leased content to until their leases run out. The user asked (2026-11-09) for a way to delete a library from all their machines at once. A library made on a device could also not be left from the apps at all (the menu hid it); that's fixed alongside: leaving one's own is allowed with a warning (`NsLeave { mine }`).

## Principles
- **No central server:** a deletion travels like any write: as a commit every member merges.
- **Always encrypted:** nothing about the deletion is in the clear; holders see chunks stop being renewed.
- **From location to identity:** who may delete is a right in the library (grant), not a device.

## Options
1. **Each device leaves by hand.** Works today; doesn't reach the devices one forgets, nor other people's.
2. **Revoke everyone and rotate the key.** Stops new reads, but every member keeps what it had, and the library still shows on their devices.
3. **Delete every record and say so in the library.** Chosen: every member's daemon sees it in the next merge and lets the library go.

## Decision
- **Who:** a member holding `grant` (in the apps: one who may invite). Others are refused and may leave.
- **What is written**, in one commit: a delete of every record, and a new record `type = "retifs.deleted"`, `by = <this node's retifs.node address>`.
- **What counts:** a member's daemon takes a library as deleted when a live record's `type` is `retifs.deleted` **and** that field was set by a writer holding `grant` at its stamp (`State::set_by_granter`). A writer with only `write` can't delete a library by writing that record (tested live: two daemons, the write-only member's own record ignored by both).
- **What a member's daemon does** (`library_deleted`):
  - hides the library at once (the apps, the mounts and the Explorer provider no longer list it) and stops announcing it;
  - lets its content go: the files only it used become evictable, and leases on them aren't renewed, so holders release them when the leases run out (ADR-0011, ADR-0014);
  - keeps its commits (small) for a **grace of 30 days**, still syncing and serving them, so a member that was away hears of the deletion from any other; then leaves it (`leave_now`).
  - Persisted in the store's `deleted` file (`name<TAB>since_ms`), so a restart carries on.
- **Interfaces:** `NsDelete { ns }` in the local API; `retifs ns delete NS --yes`; "Delete everywhere…" in the desktop apps (Windows: asked twice; Android: the library's name typed; GTK and Haiku: a warning alert).

## Impact on the threat model
- What a member already copied out of the library (a file saved elsewhere, a screenshot) stays theirs. A deletion doesn't reach a device that never comes back online, nor one whose daemon is older than this ADR; their copies stay readable to them, as after any revoke.
- A member holding `grant` can now delete a shared library for everyone. That was already within its power in effect (it could revoke everyone and delete every record); the apps now say so ("Delete everywhere…" only for those who may invite).
- A dishonest granter who was later revoked can't delete with a stamp after the revoke: rights are evaluated at the stamp, as for every write (ADR-0017).

## Consequences
- One action instead of leaving on every device, and other people's devices follow.
- A library deleted by mistake is gone: within the grace, its commits are still on the members' nodes, but no tool brings it back (a later "undelete" could write a newer delete-the-deletion record; not built).
- Members on an older daemon don't follow; they still see an empty library (every record deleted).

## Implementation status (2026-11-09)
- `retifs_core::ops::State::set_by_granter`, with a unit test (a write-only member's record doesn't count, a revoked granter's doesn't, a granter's does).
- retifsd: `NsDelete`, `library_deleted`, `leave_deleted` (every 30 s), the `deleted` file; `forget_files_of` split out of `leave_now`.
- Live on one machine with two daemons on the local Prns: the write-only member's `ns delete` refused; the granter's deletion leaves one record (`retifs.deleted`); the other member hid the library within seconds and logged its 30-day grace; a write-only member's own `retifs.deleted` record didn't count on its own node.
