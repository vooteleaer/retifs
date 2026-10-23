# ADR-0011: Redundancy by default

- **Status:** proposed
- **Date:** 2026-10-14
- **Irreversible:** partly. Erasure-coded shares would be a format of their own; decided (2026-10-20) to start with full replicas and add shares later as a layer below chunks, so this no longer blocks [ADR-0008](0008-chunk-encryption-and-cid.md) and [ADR-0009](0009-manifest-format.md).

> **Refined by [ADR-0014](0014-placement-follows-need.md):** every node holds for others by default; whoever needs the data (not only the owner) issues leases to the nearest storage nodes; the copy count follows need and holder reliability instead of a fixed target.

## Context
With wants alone ([ADR-0010](0010-continuous-seeking.md)), replication is demand-driven: popular data spreads, and data nobody else reads stays on one node. For your own data, that's the wrong default. retifs should be usable as a self-healing store for servers and NAS-like setups (a few nodes on a LAN acting as a redundant pool), as well as across sites and mesh links. That makes redundancy a core property ([vision](../00-vision.md), principle 8), not an add-on.

## Principles
Supports 8 (redundant by default), 7 (holders are blind), 4 (local-first: writes succeed locally first, replication follows) and 1 (all replicas are ciphertext). Violates none.

## Decision

### Replication target as policy
- Every piece of own data has a target, set per namespace, keep rule or tag. Example: "all my storage nodes, at least 2 copies, one in another failure domain".
- **Default greater than 1.** If the target can't be met (e.g. one node only), writes still succeed locally and `status` says **under-replicated** clearly.
- `status` shows the real state: only here, N/M replicas, or complete.

### Three sources of holders (one mechanism: leases, ADR-0010)
| Source | Initiator | Example |
|---|---|---|
| Demand | someone wants the data | a friend opens a shared album |
| Owner policy | the owner's daemon recruits holders | own NAS pool, plus 1 offsite |
| Volunteer supply | a storage node seeks work | a community or library node with spare disk |

- **Own-node pool:** devices authorised by the same root identity recognise each other. On a LAN they find each other via AutoInterface and replicate with zero configuration. Adding a box means it fills up and starts repairing.
- **Recruitment:** the owner's daemon issues leases to candidates (own nodes first, then configured peers, then volunteers if policy allows) until the target is met.
- **Volunteer storage:**
  - Nodes with spare capacity announce a `retifs.store` destination with an offer: free capacity, maximum lease length, failure domain, and policy (anyone or friends only).
  - Owners with under-replicated data say so in their announce (e.g. "need replicas: ~2 GB").
  - A volunteer asks for a lease offer; the owner signs one if the volunteer fits its policy, and the volunteer pulls. **Without a signed lease nobody stores your data**, which keeps GC and accounting clean.

### Diffusion and source anonymity ("diffuse" mode)
Wide, fast replication also protects privacy: when many nodes hold a chunk, holding it says nothing about who wrote or read it.
- **Push seeding hides the origin (an RNS property):**
  - RNS packets carry no source address, and a link's destination doesn't learn who opened it.
  - Pulling exposes the source: holders ask the origin's `retifs.node` destination. So in diffuse mode the origin **opens anonymous links and pushes** chunks to a few randomly chosen first holders (own pool or volunteers), and never serves that content as a destination itself.
- **Epidemic diffusion:** holders replicate further under their own volunteer policy, with random delays, so copies quickly outnumber any set an observer could watch.
- **Holding stops implying interest:** nodes in a diffusion pool hold chunks they never asked for (cover holdings). That makes honeypot probes uninformative: a chunk found on a node may have arrived by diffusion.
- **Timing defences:** jitter, batching several releases together, and mixing with other replication traffic, against first-appearance analysis.
- **Per content class:** private (own pool only), shared (group), diffused (wide, source-anonymous).
- **Limits:**
  - Small networks give a small crowd.
  - The early spread can still hint at the source (rumour-source-detection results), which jitter and batching reduce but don't eliminate.
  - A global passive observer is out of scope, as for RNS.
  - Diffusion costs bandwidth and disk, so it suits fast links and volunteers, not LoRa.
  - The cache is still never served: diffusion protects what's published or held for others, not reading history.

### Spread policy: how far data travels
Two independent limits, set per content class:
- **Replication generations (spread budget):**
  - The origin's push is generation 1. Each re-replication passes the data on with the budget decremented, and at 0 nobody passes it further.
  - Against position leaks (Freenet's hops-to-live lesson), the origin **picks a random starting budget** from a range, and at the top of the range the counter is decremented **only with some probability**. A first-generation holder therefore can't tell it's first.
- **Network radius (RNS hops, from the path table):**
  - `max_hops` keeps copies within a local mesh or community.
  - `min_hops` makes an offsite copy at least N hops away, a cheap proxy for another failure domain.
- **Link type:** bulk replication never crosses LoRa interfaces, even within the radius. Wants, leases and receipts may.

| Class | Generations | Radius | Example |
|---|---|---|---|
| private | 1 (own pool only) | own nodes | personal photos |
| local | 2–3 | ≤ 3 hops, no LoRa bulk | village mesh notices |
| offsite backup | 1 | ≥ 3 hops | NAS plus remote copy |
| diffused | random 4–7 | unlimited (fast links) | published document, source-anonymous |

A small radius means a smaller crowd (less source anonymity) but less exposure and bandwidth. That's a per-content choice. The spread budget travels with the lease, so its encoding is part of the lease format (decision 6).

### Soft volunteering: the spare tier
Besides promised volunteering (leases with receipts), nodes fill otherwise empty disk with **spare** replicas: no promise, evicted first, chosen by need (rarest first). They raise real redundancy across the network without anyone having to ask, and count as probable copies, not confirmed ones. See [ADR-0012](0012-disk-budget.md).

### Repair
A holder that stops renewing receipts, fails proofs, or is gone too long is replaced: a new lease goes elsewhere. Repair runs continuously as part of the seeker loop, not as a separate tool.

### Proof of storage
A receipt is a promise. Before handing out a lease, the owner precomputes a few challenges for random chunks, e.g. `HMAC(nonce, chunk)` using only RNS primitives. Later it asks the holder to answer them, which needs neither a download nor a local copy. A failed proof counts as a lost replica.

### Placement
- **Failure domains:** nodes advertise a coarse failure-domain hint (site, power or network domain, link type), and recruitment spreads across domains.
- **Link-aware:** bulk replication uses fast links. LoRa-only nodes aren't recruited as bulk holders; LoRa carries wants, leases, receipts and small repairs.
- **Opt-out:** small devices (Pi, phone) may opt out of holding others' data and are still protected themselves.

### Full replicas vs erasure coding (decided 2026-10-20)
- **Full replicas** are simple and fit the current format. 3 copies cost 3× and survive 2 losses.
- **Erasure coding** (Tahoe-LAFS style, k-of-n) costs less per unit of protection: 4-of-6 costs 1.5× and survives 2 losses; 3-of-10 costs 3.3× and survives 7.
- **Decided:** full replicas now; erasure coding later as a separate layer below chunks (share maps: a chunk group = n shares, any k rebuild it, each chunk still checked against its CID), with its own ADR. Chunks and manifests don't change for it, so nothing has to be reserved in ADR-0008/0009. Replicas suit slow links: one holder is enough to read, where shares need k ([options](../08-open-format-decisions.md)).

### Who holds copies (confirmed 2026-10-23)
Any retifs node may hold the encrypted chunks; the nearest and fastest are preferred (ADR-0014). What a file holds, its name, path and other attributes, are readable only by the club's members (the namespace's read key): a holder sees ciphertext and chunk CIDs, not which namespace, record or file they belong to. Storage nodes not heard announcing for a week are dropped from the candidates (gone test nodes had piled up, each costing a 20 s link attempt).

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Holders** see ciphertext, chunk grouping per lease, lease timing and the owner key that signed. Mitigations: **per-lease derived signing keys** (unlinkable to the owner's identity and to each other), split leases, cover chunks.
- **Malicious or lazy volunteers** (Sybil) are limited by proofs of storage, spreading over failure domains and many holders, and stamps (as in LXMF) that make spamming offers or lease requests costly.
- **Storage exhaustion attacks** on volunteers are limited by quotas per lease signer and stamp cost.

## Consequences
- Easier: losing a device doesn't lose data. A NAS pool works out of the box. Community storage is possible without trusting holders.
- Harder:
  - Disk and bandwidth multiply by the replication factor.
  - Proofs, repair and placement add state and background traffic.
  - Lease grouping leaks which chunks belong together.
  - Incentives beyond reciprocity remain open ("pinning economics").

## Implementation status (2026-10-15)
- Leases, renewals, receipts and storage proofs exist as a first slice ([ADR-0010](0010-continuous-seeking.md), "Leases and receipts"): `retifs replicate CAP --to NODE…` keeps a file on chosen nodes, and `status` reports confirmed copies.
- Per-lease derived signing keys are implemented; spread budget (generations) is in the format, set to 0 (don't pass on) for now.
- Not yet: replication targets as policy, own-node pool discovery, automatic recruitment and repair to a target, failure domains, volunteer offers (`retifs.store`), diffuse mode, the spare tier, and the full-replicas-vs-erasure-coding decision.
