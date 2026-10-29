# ADR-0012: Disk budget and eviction

- **Status:** accepted (prototype), 2026-10-29; the spare tier and the signed release are not built yet (see Review)
- **Date:** 2026-10-14
- **Irreversible:** no

## Context
The store will hold three kinds of data with very different value: your own data (pinned), copies of what you read (cache), and data you keep for others (leases: own-node pool replicas and volunteer storage, [ADR-0011](0011-redundancy-by-default.md)). Without limits, seeking and replication ([ADR-0010](0010-continuous-seeking.md)) will happily fill the disk. A full disk breaks the OS and the user's other programs, and in retifs it would also break the promises behind leases.

Two prototype facts matter:
- Slab files only grow: removing a chunk frees its slot for reuse, but the disk space isn't returned ([ADR-0007](0007-local-store-layout.md)).
- The store doesn't yet track usage per tier.

## Principles
Supports 4 (local-first: own writes keep working as long as possible) and 8 (redundancy: lease promises are kept or explicitly released, never silently broken). Violates none.

## Decision

### Two global limits
- **Store limit:** the maximum the hard tiers (pinned and leased) may occupy. Default: **50 % of the volume**, adjustable. Elastic tiers may use more, down to the reserve.
- **Free-space reserve:** retifs never takes the volume below it. Default: **the larger of 10 % of the volume and 5 GiB**.

The effective limit is whichever is reached first. Both are checked against real free space (statvfs / GetDiskFreeSpaceEx), so other programs filling the disk shrink retifs's room too.

### Tiers: hard and elastic
Empty disk is wasted disk, but retifs must hand space back immediately. That's the OS page-cache model: use what's free, give it back when anyone needs it.

| Tier | Promise | Budget | Under pressure |
|---|---|---|---|
| **Pinned** (own data) | yes | within the store limit | never evicted; new writes refused at the hard limit |
| **Leased** (own-node pool, volunteer leases) | yes, with receipts | within the store limit; volunteer leases capped (e.g. `--volunteer 500G`) | refuse new leases; existing ones run to expiry |
| **Cache** (your own reads) | no | up to 20 % of the store limit by default | evict LRU |
| **Spare** (others' replicas, no lease) | **no** | **all free space above the reserve** (device-dependent default) | **evicted first, lowest need first** |

- **Hard tiers** (pinned, leased) are bounded by the store limit.
- **Elastic tiers** (cache, spare) use what's left down to the reserve and shrink automatically when other programs fill the disk.

### Spare tier: filling free space by need
- Chunks with no promise attached, held because the network needs them. They count as **probable** copies in the holder map ([ADR-0010](0010-continuous-seeking.md)), never as confirmed ones, so evicting them breaks no promise. Owner redundancy relies on leases and receipts ([ADR-0011](0011-redundancy-by-default.md)).
- **Need score**, from the holder map:
  - **rarity** (few known copies, highest weight; "rarest first");
  - **recent demand**;
  - **priority by who asked** (own pool, then friends and groups, then strangers);
  - **within the spread policy** (otherwise not taken);
  - **age**.
- **Swap:** a candidate chunk is taken only if it outscores the lowest-scored spare chunk held, which is then evicted.
- **Device defaults:**
  - servers and NAS (mains power, fast links): spare on;
  - laptops and phones (battery, metered or slow links): off or small.
- **Filling** uses idle bandwidth only, at low priority, never over LoRa.
- **Privacy bonus:** spare chunks are unrequested holdings, which gives the deniability of diffuse mode ([ADR-0011](0011-redundancy-by-default.md)).

### Eviction and refusal order under pressure
1. Evict **spare** (lowest need first).
2. Evict **cache** (least recently used first; never chunks a running read needs).
3. Drop chunks of **expired leases**.
4. **Refuse new leases** and stop renewing volunteer leases (they expire normally).
5. **Refuse new pinned writes** with a clear error ("disk budget reached").
6. **Never** silently drop pinned data or chunks of an active lease. If an operator really has to shrink a lease (`retifs release`), the holder sends a signed release to the owner, so the owner's repair recruits elsewhere ([ADR-0011](0011-redundancy-by-default.md)).

### Admission
Before accepting a lease, the daemon checks its budget for that tier, including space already promised but not yet fetched. Seeking never pulls blind chunks beyond accepted leases.

### Reclaiming space in slabs
Freed slots are reused first. To return space to the OS, the store either:
- punches holes in freed slots (Linux `fallocate(PUNCH_HOLE)`, Windows sparse files with `FSCTL_SET_ZERO_DATA`), or
- compacts mostly-empty segments by moving live slots and deleting the segment.

Hole punching comes first; compaction comes later.

### Visibility
`retifs status` and `ping` show usage per tier, the limits, the reserve, and what is being refused or evicted. Under-replication caused by full disks is reported as such.

### Configuration
Flags or config: `--max-store`, `--min-free`, `--cache-max`, `--volunteer`, `--spare on|off|SIZE`. Later these become records in the node's own namespace, so they can be managed remotely.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Storage exhaustion by others:** promised volunteer storage is capped, and quotas apply per lease signer (ADR-0011). The spare tier can't exhaust anything, because it only uses free space above the reserve and yields first.
- **Timing and usage leak:** what a node evicts or refuses can hint at its usage. That's minor and accepted.

## Consequences
- Easier: retifs is safe to run on a laptop next to other programs, and a NAS can dedicate most of its disk deliberately.
- Harder:
  - Accounting per tier, including promised-but-not-fetched space.
  - LRU tracking for the cache.
  - Hole punching is platform-specific.
  - A full disk can stop own writes, by design, rather than corrupting anything.

## Implementation status (2026-10-14)
In `retifs-store` and `retifsd`:
- **Tiers:** a new `SPARE` flag; each chunk's effective tier is pinned > leased > cache > spare. Usage per tier is kept in the index, in the same transactions as the data.
- **Limits:** a store limit for hard tiers, a free-space reserve (real volume figures via `fs4`), and a cache cap. Defaults as above; flags `--max-store`, `--min-free`, `--cache-max`.
- **Admission:**
  - A new chunk first reuses a freed slot of its class.
  - Otherwise it may evict spare, then cache (spare only for spare), preferring its own class so a slot frees up.
  - Hard tiers are never evicted; a write beyond the budget fails with "disk budget reached".
  - A failed own write rolls back the chunks it newly added (`TrackedPinned`), so half a file doesn't eat the budget.
- **LRU:** accesses are tracked in memory and written to the index lazily (non-durable).
- **Space back to the OS:** removed slots are hole-punched (Linux `fallocate(PUNCH_HOLE)`, Windows sparse files with `FSCTL_SET_ZERO_DATA`) and reused. Verified on Linux (2026-10-15) with a test that checks allocated blocks, not just zeroes: on tmpfs 32 removed 4 KiB slots give back exactly 32 blocks; on ext4 (also under overlayfs) 31, because the holes split the file into more extents than fit in the inode and ext4 spends one block on the extent tree. Plain `fallocate -p` behaves the same, so it's the filesystem, not the store.
- **Background:** `enforce()` every 30 s trims the cache to its cap and restores the reserve when other programs fill the volume.
- **Visibility:** `retifs ping` shows usage per tier, the limits and the volume.
- **Tests:** usage accounting, cache LRU at its cap, eviction order under disk pressure (pinned never dropped), store limit for hard tiers only, `enforce` after others fill the disk, and holes (freed slot reads as zeros, neighbours intact). Plus a live daemon check: a put over the limit is refused and leaves nothing behind.
- **Not yet:**
  - The spare tier has no producer yet (need score, filling).
  - Volunteer lease quotas.
  - Eviction scans the whole index, which is fine for a prototype; an access-ordered index comes later.
  - Segment compaction.

## Review (2026-10-29)
Built and in use on the testbed: the store limit and free-space reserve, hard and elastic tiers, eviction in the order above, refusing leases past the hold limit, refusing pinned writes with "disk budget reached", compaction (`retifsd --compact`), and short of room releasing own files with enough confirmed copies elsewhere to the cache ([ADR-0031](0031-storage-less-nodes.md)).

Not built yet:
- **Filling the spare tier:** the tier exists as a flag in the store, but nothing fills it by need score.
- **The signed release** (`retifs release`) a holder sends its owner when an operator shrinks a lease.
