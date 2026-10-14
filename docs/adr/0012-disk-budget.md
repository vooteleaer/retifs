# ADR-0012: Disk budget and eviction

- **Status:** proposed
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
- **Store limit:** the maximum the store may occupy. Default: **50 % of the volume**, adjustable.
- **Free-space reserve:** retifs never takes the volume below it. Default: **the larger of 10 % of the volume and 5 GiB**.

The effective limit is whichever is reached first. Both are checked against real free space (statvfs / GetDiskFreeSpaceEx), so other programs filling the disk shrink retifs's room too.

### Per-tier budgets inside the store limit
| Tier | Default budget | When full |
|---|---|---|
| **Pinned** (own data) | no separate cap; uses the store limit | refuse new writes with a clear error, after evicting all cache |
| **Leases: own-node pool** | no separate cap (it's your data on another box) | refuse new leases, report under-replicated |
| **Leases: volunteer storage** | **0, opt-in**; e.g. `--volunteer 500G` | refuse new leases; existing ones run until expiry |
| **Cache** | the rest, up to 20 % of the store limit by default | evict (LRU) |

### Eviction and refusal order under pressure
1. Evict **cache** (least recently used first; never chunks a running read needs).
2. Drop chunks of **expired leases**.
3. **Refuse new leases** and stop renewing volunteer leases (they expire normally).
4. **Refuse new pinned writes** with a clear error ("disk budget reached").
5. **Never** silently drop pinned data or chunks of an active lease. If an operator really has to shrink a lease (`retifs release`), the holder sends a signed release to the owner, so the owner's repair recruits elsewhere ([ADR-0011](0011-redundancy-by-default.md)).

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
Flags or config: `--max-store`, `--min-free`, `--cache-max`, `--volunteer`. Later these become records in the node's own namespace, so they can be managed remotely.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Storage exhaustion by others:** volunteer storage is opt-in and hard-capped, and quotas apply per lease signer (ADR-0011). Leases for blind chunks can't exceed the budget.
- **Timing and usage leak:** what a node evicts or refuses can hint at its usage. That's minor and accepted.

## Consequences
- Easier: retifs is safe to run on a laptop next to other programs, and a NAS can dedicate most of its disk deliberately.
- Harder:
  - Accounting per tier, including promised-but-not-fetched space.
  - LRU tracking for the cache.
  - Hole punching is platform-specific.
  - A full disk can stop own writes, by design, rather than corrupting anything.
