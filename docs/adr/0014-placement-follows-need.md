# ADR-0014: Placement follows need

- **Status:** proposed
- **Date:** 2026-10-15
- **Irreversible:** no. It reuses the lease format (decision 6) unchanged. It refines [ADR-0011](0011-redundancy-by-default.md) (who recruits holders, how many copies) and [ADR-0013](0013-slow-links.md) (what crosses LoRa).

## Context
The first lease slice ([ADR-0010](0010-continuous-seeking.md)) keeps a file on nodes the user names (`retifs replicate --to`). It should be automatic, like LXMF propagation nodes: storage nodes announce themselves, and everyone uses them without configuration.

Two things shape how:
- **Keeping data where nobody needs it is pointless.** A copy is worth something only if someone who needs the data can reach it cheaply. Placement should follow the people who use the data, not a fixed policy.
- **Traffic is the real cost, not disk.** In peer-to-peer storage, the bandwidth needed to maintain copies under churn limits the system long before disk does (Blake & Rodrigues, 2003). 100 GB kept in 3 copies on holders that live about 30 days needs about 10 GB a day of repair traffic; on holders that live about a year, about 0.8 GB a day. Copies placed near nobody spend that traffic for nothing.

## Principles
Supports 8 (redundant by default), 4 (local-first: data sits close to who uses it), 7 (holders are blind) and 1 (ciphertext only). Violates none.

## Options
1. **Fixed replication target set by the owner** (ADR-0011 as written): simple, but copies land where nobody reads, and the count ignores both holder reliability and use.
2. **Owner places copies near readers:** the owner would have to learn where its readers are, which breaks reader anonymity.
3. **Whoever needs the data places copies near itself** (chosen).

## Decision

### Every node is a storage node by default
- `retifsd` holds data for others within its disk budget ([ADR-0012](0012-disk-budget.md)); `--hold-for-others 0` opts out. Unused disk is worth more holding someone's data than empty.
- It announces a `retifs.store` destination (separate from `retifs.node`) whose app data carries a coarse offer: free capacity bucket, maximum lease term, and later a stamp cost and a failure-domain hint. Announces follow the announce economy of ADR-0013.
- Each node keeps a list of storage nodes it has heard: destination, hops and interface from the path table, offer, last heard.

### Whoever needs the data issues the leases
- A lease lists CIDs and access tokens only, and anyone with the read-cap can derive them. So **any reader can sign leases**, with its own per-lease keys, to storage nodes near itself. The owner is just the first reader.
- The owner never learns where readers are, and holders never learn who signed (per-lease keys, anonymous links).
- **Need means renewing.** A copy lives while someone who needs the data renews its lease. When nobody needs it any more, the leases expire and the holders drop it: garbage collection with no extra machinery.
- **Sharing is a need.** Receiving a read-cap starts seeking at once (within the link budgets below), so data is near the recipient before it's opened.
- Several readers near one holder lease the same chunks to it: refcounts, not new transfers. The number of distinct leases per chunk is a free popularity signal.

### Closest first, by hops and link cost
- Candidates are ranked by hops from the RNS path table, adjusted for the path's link type and measured rate. One LoRa hop costs more than several TCP hops.
- A reader keeps copies with its nearest storage nodes, usually on its own LAN. Data therefore ends up near each place it's used, and the extra traffic is one short hop beyond the read itself.

### Copy count is dynamic, not a constant
- Each needer keeps enough copies near itself to survive losing a device, given how reliable its nearby holders have actually been (receipts on time, proofs passed, absences). Reliable always-on neighbours give one or two; flaky ones, more.
- A file used in three places has copies in three places. That is more durable than a fixed number placed near nobody.

### Keeping traffic down
- **Lazy repair (Carbonite, Chun et al. 2006):** a holder that is only away still has the data. It's replaced only after a long absence, and a copy that comes back counts again instead of being thrown away.
- **Prefer holders that stay:** placement weighs uptime history.
- **Never send what's there:** ask with `have` before pushing; versions and convergent public data then cost only new chunks.
- **Push after the lease is accepted** (`/retifs/put`), so a laptop can put a file and go offline. Pushing also hides the leaser: the holder doesn't learn which node it came from. Pulling stays as a fallback.
- **Bundle control traffic:** renewals, receipts and proofs travel in one session per holder. Later, leases mix chunks of several files, which also hides file boundaries from holders.
- **Traffic budget per node,** like LXMF propagation nodes' transfer limits: repair and placement use idle capacity first.

### Slow links: carry what's needed, if it fits
Data someone needs beyond a slow link has to cross it, once, and then stays on the far side. Size decides whether that makes sense: LoRa moves about 0.5 MB per hour within the duty cycle, so 1 GB would take about 2 000 hours.
- **Cost check first:** estimated transfer time = size ÷ the path's bottleneck rate, compared with the interface's airtime budget.
- **Fits:** messages, notes, metadata, small files, the range actually being read. These cross right away, and land on the far side.
- **Doesn't fit:** the want waits for a fast path (the device comes home, a neighbour's link comes up, an export bundle on removable media). The user sees why, e.g. "1 GB, about 80 days over LoRa: queued for a faster link".
- **Parts still help:** manifests, thumbnails, low-resolution variants and single ranges can cross so a large file is usable before it's complete.
- **Never speculative:** placement for durability, spare filling and diffusion never cross slow links; an explicit fetch can be forced, within the budget.

## Open
- **Failure domains:** the nearest nodes are usually in the same building, on the same power and uplink. Whether data only one site needs should also keep one copy further away is open.
- **Erasure coding** with the owner's local full copy (cheap repair, half the upload of full replicas; Rodrigues & Liskov 2005) is the leading candidate for the replicas-vs-erasure-coding decision that blocks ADR-0008/0009. It needs its own ADR.
- **Stamps** (proof of work, as in LXMF) against lease spam; per-signer quotas don't work with per-lease keys.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Locality leaks interest:** holders are chosen nearest first, so a holder can infer that someone a few hops away needs these chunks. For personal and record data the CIDs mean nothing to it; for public convergent data it can compute CIDs of known files and learn that a known file is read nearby. Mitigations: the lease signer and link initiator stay anonymous; mixing chunks of several files per lease; spare copies that aren't driven by need make holding less telling.
- **Every node holds others' data by default:** it stores only ciphertext under leases; the cache (own reading) is still never served.

## Consequences
- Easier: no configuration; data follows its users; unused data cleans itself up; traffic is spent where reads happen; slow links stay usable.
- Harder:
  - Readers sign and renew leases too, so every daemon runs lease upkeep.
  - Ranking needs link-rate estimates per path, not just hops.
  - Popular data may end up with many copies (one set per site that uses it). That is the intended trade.
