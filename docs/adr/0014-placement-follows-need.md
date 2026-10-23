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
- **Erasure coding** with the owner's local full copy (cheap repair, half the upload of full replicas; Rodrigues & Liskov 2005) is the leading candidate for the erasure-coding layer that comes after full replicas (decided 2026-10-20, [ADR-0011](0011-redundancy-by-default.md)). It needs its own ADR.
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

## Implementation status (2026-10-15)
- **Every node holds for others by default,** up to its store limit (`--hold-for-others SIZE` caps it, `0` opts out).
- **Storage nodes are recognised without announce data:** Prns passes announce events with hops but not app data, so `retifsd` looks up the announced identity and checks that it hashes to `retifs.node`. The offer in the announce (capacity, term) waits for app data access; a full node answers a lease with "no room" instead, and is avoided for an hour.
- **Announce app data (2026-10-23):** since Prns 0.3.8 passes app data on, a `retifs.node` announce states how often the node announces (`{"announce_s": N, "v": 1}`, ADR-0011); a node that missed 5 of them gets no new leases. The capacity offer could now go in the same map.
- **Need:** a file is needed by the node that wrote it and by every node whose want for it completed.
- **Dynamic copy count:** each copy has a loss estimate. The local copy counts 0.1 if pinned, 0.5 if only cached; a holder counts `(failures + 1) / (contacts + 10)` from its upkeep record (new holders 0.1; 100 good contacts bring it under 0.01), and 1 once its receipt ran out or a storage proof failed. Placement adds the nearest storage nodes (fewest hops, then most recently heard) until the product is below `--loss-target` (default 0.001): two new holders at first, fewer as they prove reliable. An unreachable holder only worsens its record (lazy repair); its copy counts again when it answers.
- **A floor of copies (2026-10-23):** whatever the estimate says, placement keeps at least `--min-copies` copies of each needed file, this node's own included (default 3: two elsewhere), and trimming never goes below it. Estimates are only as good as the records behind them, which a new network doesn't have; a floor is easy to reason about and is what Ceph, HDFS and most clouds keep. More copies add little once repair is quick: what loses data is every copy going before repair notices. Where copies are matters more than how many (copies in one room fail together): see sites below. When too few storage nodes are reachable, placement does what it can and says so.
- **Proven holders first (2026-10-23):** candidates that kept data for this node before are asked first, by their record, then the rest by hops and recency; a pass tries at most 12 links. A node hears many storage nodes that are gone (test nodes, a crowded network), and each failed link costs 20 s. `retifs nodes` shows what placement knows of each: hops, when heard, link, record, and whether it's avoided for now.
- **Push:** after a lease is accepted, the leaser asks `have` and sends only missing chunks with `/retifs/put` (16 per request). Placement leases name no source, so holders don't learn where data came from; a holder that reports progress short of complete gets the rest pushed during upkeep.
- **`have` answers only for chunks present:** leased chunks are in the serving index before they arrive, so a bare token match isn't enough.
- **Live, four daemons on one machine:** A wrote 2 MB and, with no configuration, leased it to the two nearest nodes and pushed 148 chunks to each; the estimate went 0.1 → 0.01 → 0.001 and placement stopped; both holders returned receipts and passed proofs. D then sought the file with its read-cap; once complete it placed copies near itself, and its lease to a node already holding A's copy pushed **0 of 148 chunks**. An unreachable node (flaky Prns path requests) was skipped and avoided for 10 minutes. The cause was found afterwards: Prns `request_path` never settles for a destination whose route is already known ([prns-path-replay](../recon/prns-path-replay.md)); with the workaround (check the route table first), a rerun reached every node and placed in 13.5 s instead of 44.5 s.
- **Across machines (2026-10-15):** this machine (Windows), cafa-cloud (x86-64 Linux, 1 hop over TCP) and rtr-4 (aarch64 Pi, 5 hops through public gateways). The writer heard both storage nodes within 46 s and placed a 512 KB file nearest first: cafa-cloud got all 37 chunks, then rtr-4; both returned receipts and passed proofs within 47 s. The push to rtr-4 timed out after 16 chunks (one 256 KiB request over 5 public hops); upkeep pushed the missing 21. Pushes now halve their batch on a timeout and resend.
- **Bugs found there:** rtr-4's `/tmp` is a 1 GB tmpfs below the free-space reserve, yet it accepted a lease it couldn't store, and the writer kept counting "had 0, pushed 0" as a good contact. The hold limit is now always capped by the actual room, and a holder that takes none of the pushed chunks counts as a failed contact.
- **Link cost (2026-10-15):** a client of the shared instance can't see the interfaces behind it, so paths are measured: the link setup RTT (`establish_link_with_rtt`) and a moving average of real transfer throughput (pushes, seek rounds; transfers under 4 KiB are ignored). Until something was transferred, an RTT of 1.5 s or more counts as LoRa class (~150 B/s), anything else as 50 KB/s; a measured rate under 2 KiB/s is slow.
  - **Placement** links to the nearest eight candidates, skips slow ones (and avoids them for 6 h), and ranks the rest by estimated transfer time, then hops.
  - **Seeking** over a slow peer fetches everything only if the rest fits `--slow-link-budget` (default 10 min); otherwise only manifest nodes, and `status` says "rest waits for a faster path (about N over the slow link)". A faster holder completes it.
  - Live, five daemons (one treated as behind LoRa with the testing flag `--treat-as-slow`): placement skipped the slow node and used the next two; a reader whose only source was slow fetched the manifest (total known, 0/144 data chunks) and reported about 3 h; given a fast holder it completed.
- **Ending need (2026-10-16):** `retifs forget CAP` drops the file from the needed and wanted lists and drops this node's leases for it, so they're no longer renewed and holders release the chunks when the leases run out (no new message; the lease format is unchanged). Local own copies become evictable (pinned → cache, no longer served), except chunks another needed file shares; chunks held for others are untouched. Live, three daemons, 2-minute term: a one-byte-edited second version of a 2 MB record was placed by pushing 3 of 148 chunks per holder; forgetting the first version made 3 chunks evictable and kept 148 shared ones; when the term ran out, both holders dropped the old lease (151 → 148 chunks) while the second version's leases were renewed.
- **One exchange per holder (2026-10-16):** upkeep groups leases by holder: renewals go in bundles of up to 64 (each still the signed 89-byte renewal, so the lease format is unchanged), receipts are asked for up to 64 leases at once, and storage proofs are sampled, one random lease per holder every 10 minutes, since reliability is tracked per holder. Live: five files leased to two holders were renewed with one request per holder ("renewed 5 lease(s) in one request"), with 10 receipts and 2 proofs.
- **Stamps (2026-10-16):** lease offers carry a proof of work, LXMF's construction (`retifs_core::stamp`): a workblock of 3 000 HKDF rounds over `"retifs/v1/stamp" ‖ SHA-256(lease body)`, and a 32-byte stamp whose SHA-256 with the workblock has at least *cost* leading zero bits. Only RNS primitives; vectors in `lease-v1.json` are checked with LXMF's own `stamp_workblock`, `stamp_value` and `stamp_valid`. Holders ask `--stamp-cost` bits (default 20) of every offer and answer an offer without a valid stamp with "stamp required, cost N"; offerers remember each holder's cost, pay up to `--max-stamp-cost` (default 24) and treat dearer holders as full. Renewals are free.
  - **Calibration:** the workblock is a fixed prefix, so a solver hashes it once and reuses the hash state: each try costs one small hash, not 768 KB (true of LXMF stamps as well). Measured on a desktop: 20 bits about 0.1 s, 22 bits about 1.7 s, 24 bits about 2.9 s per lease of up to 16 MB; expect several times that on a Pi. At 20 bits, filling a holder with 50 GB of junk leases costs roughly 3 200 stamps, minutes of one desktop core: a deterrent together with hold limits, not a wall.
  - Live: holders asking 20 bits were paid (0.06 s and 0.51 s per lease) and accepted; a holder asking 28 bits was skipped by placement and refused for an explicit `replicate`.
- **Repair across machines (2026-10-16):** owner on this machine (10-minute lease term), holders C1 and C2 on cafa-cloud (1 hop) and R on rtr-4 (4–5 hops through public gateways). The file went to C1 and C2 within 2 s of the put. C2 was stopped; its first storage proof timed out, the failed contact raised its loss estimate, and placement added R (all 41 chunks pushed over 4 hops, receipt, proof passed) about 100 s later; the estimate fell to 1.4e-4. C2 was restarted with the same identity; it passed its proof and was renewed at half-term with C1, all in one exchange per holder. All three copies stayed confirmed.
  - Observed: with a young record, one failed contact is enough to add a copy (adding is cheap, and nothing is dropped). When the absent holder returns, the file has more copies than the target needs; trimming surplus copies (stop renewing the least reliable holder once the target holds without it, with hysteresis against churn) is not implemented yet.
- **Trimming and lapsed holders (2026-10-16):**
  - **Surplus:** when the estimate meets the target, placement stops renewing one holder if the estimate without it is at most half the target (hysteresis: adding happens above the target) and every holder is confirmed (never during a placement). The worst record goes first; on a tie, the farthest. Its leases run out at the holder like `forget`'s.
  - **Lapsed:** a lease that ran out unrenewed (one minute of grace) means the holder dropped the copy; placement forgets that holder for the file instead of re-offering to it later. A first test showed why: a holder that came back after expiry got the whole file pushed again and was trimmed right after.
  - Live, four daemons, 4-minute term, target 0.02: the file went to one holder; it was stopped; repair added a second (≈ 2 min); the first came back within its lease and was renewed; 30 s later it was trimmed (its record had a failed proof; estimate without it 9.1e-3); its lease ran out and it released the chunks. Two pushes in total.
- **Mixed leases (2026-10-16):** one placement pass plans per holder: each file picks the holders it lacks from one ranking of candidates, then every chunk bound for a holder goes out together, deduplicated and packed into leases of up to 1024 chunks **sorted by CID**, so a holder sees neither file boundaries nor chunk order. Each own lease records the files it serves. When a file stops being kept under a lease (forgotten, trimmed, lapsed), the lease turns stale and is **repacked** at its next renewal: a new lease over only the chunks still needed (the holder has them, nothing is pushed), while the old one runs out.
  - Live: three files written together went to one holder as one mixed lease (91 chunks, one stamp, one receipt). Forgetting the middle file made the lease stale; at half-term it was repacked into a 60-chunk lease (0 pushed), and when the old lease ran out the holder went from 91 to 60 chunks. The other two files stayed confirmed.
  - Files written at different times still get separate leases (each placement pass packs what it has); renewal-time repacking could also merge small leases per holder.
- **Not yet:** the offer in announces (would let offerers see the cost up front), merging small leases per holder at renewal.

