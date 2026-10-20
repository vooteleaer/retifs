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

## Implementation status (2026-10-20)
- **Device name:** `retifsd --device NAME`, by default the host name in lower case.
- **Keep tags:** a record is kept on this device if its `keep` or `keep:<device>` attribute is `true`.
- **Keep rules:** records with `type = "keep-rule"`, a `query` of comma-separated terms (the syntax `retifs query` takes, e.g. `album=Prangli 2026, type=photo`), and an optional `device`. Without `device` the rule applies to every device. A rule that doesn't parse is ignored.
- **Keep mode per namespace on each node:** `retifs ns keep NS all|rules`.
  - `all` is the default and today's behaviour: a member pulls all content.
  - `rules` pulls only tagged and matching records, for devices that can't hold everything.
  - `ns info` shows the mode, the device name and how many files were pulled because they're kept.
- **After every sync and every local write:**
  - Content of kept records that isn't here is sought in the background.
  - Content that is here, for example read on demand into the cache tier, is pinned.
  - Files pulled because they were kept, and kept no longer (the tag removed, the rule deleted, or replaced by a new version), are released: their leases end, and their chunks become evictable unless another needed file shares them.
  - Content this node wrote is never released by keep.
- **FUSE:** the computed xattr `user.retifs.local` is `yes`, `no` or `partial (n/m chunks)`.
- **Misses:** reads of content that isn't kept are fetched on demand (ADR-0002, offline semantics).
- **Live test**, two daemons; B is device `laptop` in `rules` mode. A wrote four photos (two in album Prangli), a rule for `laptop` (album Prangli) and a rule for `phone`.
  - B pulled exactly the two Prangli photos, and ignored the `phone` rule.
  - Tagging a third photo `keep:laptop` pulled it, complete and readable offline.
  - Deleting the `laptop` rule released the two Prangli photos and kept the tagged one.
- **Not yet:**
  - Relative dates in rules (`modified > -30d`).
  - Reporting pinned sets that don't fit the disk budget.
  - Content pulled before this change (by the old "fetch everything" sync) isn't tracked as kept, so switching such a namespace to `rules` doesn't release it.

