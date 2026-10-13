# ADR-0005: Local store and offline semantics

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** no

## Context
Local-first ([vision](../00-vision.md), principle 4) means reads must work offline for the data the user needs. The open question was what `read()` does when a chunk isn't local and there's no network: block, error, or make sure it never happens.

## Principles
Supports 4 (local-first), 1 (data at rest stays encrypted) and 7 (the local store is just another blind store). Violates none.

## Options
1. **Pure LRU cache.** Simple, but offline availability is luck.
2. **Explicit pin lists** (CIDs/files). Precise, but breaks as soon as new content arrives.
3. **Metadata always local, content pinned by tag and query, misses explicit.**

## Decision
Option 3.

- **Metadata is always local.** The database for the user's namespaces (indexes, attributes, commits) is synced in full. Queries, `watch` and history always work offline, and the daemon always knows whether a block is present.
- **Content tiers** in one store:

  | Tier | What | Evicted? |
  |---|---|---|
  | **Pinned** | records tagged or matched for this device, plus own unsynced writes | never |
  | **Cache** | recently read blocks (LRU) | yes, under space pressure |
  | **Serving** | chunks held for others under a lease | when the lease expires |

- **The keep tag:** `keep:<device> = true` on a record means "always have this locally on that device". The daemon pulls missing chunks proactively, keeps them current on new versions, and never evicts them.
  - The tag is an ordinary synced attribute, so you can mark something for the laptop from the phone.
  - Without a device name, `keep = true` means all of the user's devices.
- **Keep rules:** for whole categories, a rule record holds a query, e.g. `keep:laptop` ← `album="Prangli 2026"` or `type=document AND modified > -30d`. New matching records are pinned automatically. The tag is just the simplest rule.
- **Ciphertext at rest.** Chunks are stored exactly as they travel, keyed by CID, and decrypted in memory on read. A stolen disk is noise even without LUKS, the store can serve other nodes directly, and dedup is natural.
- **Misses are explicit:**
  - Native API ([ADR-0004](0004-native-record-api.md)): an `Unavailable { fetch: queued }` result, and `status()` lets apps check beforehand.
  - FUSE: with a route, block up to a configurable timeout; with no route, fail immediately. Presence is visible as the xattr `user.retifs.local`.
- **Writes never miss.** They land in the pinned tier immediately and show "only here" until pinning nodes confirm with signed receipts.

## Impact on the threat model
Ciphertext at rest means a stolen device without its key reveals only chunk counts and sizes. `keep:<device>` tags reveal device names and usage patterns to anyone who can read the namespace's attributes. That's acceptable, since they're encrypted like all attributes. See the [threat model](../04-threat-model.md).

## Consequences
- Easier: offline behaviour is predictable and user-controlled. Queries never block on the network. One store format for own data and served data.
- Harder: full metadata sync costs space on small devices (a later option: partial namespaces). Every read pays one decryption pass. Pinned sets can exceed disk space, so the daemon must report this rather than silently dropping pins.
