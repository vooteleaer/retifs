# ADR-0010: Continuous seeking and replication

- **Status:** proposed
- **Date:** 2026-10-14
- **Irreversible:** partly. The lease and receipt formats are decision 6 and need test vectors; the seeking behaviour itself is not.

## Context
A node starts with no links, so it has no data from others. Holders appear and disappear: an announce makes some chunks reachable, but not necessarily all. Links may be intermittent or LoRa-only. The first prototype (`retifs get --from NODE`) treats a missing path as an error after 60 s and forgets the request. That suits a LAN, not a mesh.

Data also has to move the other way: local-only data must reach other nodes even if nobody is actively reading it (see [ADR-0011](0011-redundancy-by-default.md)).

## Principles
Supports 4 (local-first: the network is for syncing, missing data is a normal state), 7 (holders stay blind: they need CIDs, not seeds) and 8 (redundancy). Violates none.

## Options
1. **Request/response only** (the current prototype): simple, but fails whenever the peer isn't reachable right now.
2. **A global DHT of who holds what:** the IPFS approach, which is expensive over radio. Discovery is still an open question; see [open questions](../06-open-questions.md).
3. **A persistent, chunk-level want-list with an event-driven seeker**, used for both fetching and replication.

## Decision
Option 3.

### Wants
- The daemon keeps a persistent **want-list** at chunk granularity: `CID → (seed if known, span, reason, added, per-peer ask history)`.
  - **Readable wants** carry a seed: our own files, read-caps we were given.
  - **Blind wants** carry only a CID: chunks we agreed to keep for someone else under a lease.
- **Sources of wants:**
  - `get` and read-caps;
  - keep tags and rules ([ADR-0005](0005-local-store-offline.md));
  - leases accepted from others;
  - redundancy repair ([ADR-0011](0011-redundancy-by-default.md)).
- **Tree expansion:** when a manifest node arrives, its children become wants. Nodes come before leaves.
- **Partial availability is normal.** `status` reports progress (e.g. 412/711 local). Reads of local ranges succeed; missing ranges fail fast with "unavailable, still seeking".

### Seeker
- **Triggers:** an announce from a candidate peer, a new want, or a slow periodic tick as a fallback.
- **Links:** one or a few links per reachable peer, kept open while useful.
- **Before fetching, ask what the peer has:** `/retifs/have` sends 8-byte CID prefixes (about 50 per packet, below the MDU, so they pipeline; see [first-transfer](../recon/first-transfer.md)) and returns a bitmap. Then `/retifs/get` fetches what's held. Multi-source fills different gaps from different peers.
- **Change detection:** nodes include a small **store generation** counter in their `retifs.node` announce. A peer is asked again only if its generation changed since the last ask, or after a long back-off.
- **Candidates:**
  - by default, read-cap holder hints, configured peers and our own nodes;
  - every `retifs.node` heard, as an opt-in, because asking reveals interest in CIDs.

### Holder map
There may be hundreds of copies of a chunk online. The daemon keeps a living **holder map** of who has what, not just a list of what's missing.
- **Sources, by strength:**
  - signed receipts (a promise to keep until T);
  - `/retifs/have` answers (good but going stale);
  - holder hints in read-caps;
  - announce summaries (store generation, possibly a Bloom filter of held chunks);
  - gossip from own nodes (opt-in).
- **Uses:**
  - **Pick the best source:** hops, RTT, link MTU, measured throughput, failure rate; LoRa last for bulk.
  - **Spread load:** across many holders, filling different gaps from different nodes.
  - **Instant failover:** the next holder is already known.
  - **Measured redundancy:** confirmed copies (receipts) and probable copies (sightings), which repair acts on ([ADR-0011](0011-redundancy-by-default.md)).
- **Bounded:**
  - **Per chunk:** the best few holders (e.g. 8) plus a count of others seen.
  - **Grouped:** holders recorded per lease or per manifest subtree where possible, since holders usually have whole groups.
  - **Aged:** entries decay and are refreshed when a holder's store generation changes.
- **Stale entries are harmless:** every chunk is verified against its CID on arrival, so a wrong holder only costs one wasted request.
- **Privacy:** the map is local. Sharing it reveals who holds what, so gossip is opt-in and limited to own nodes by default.

### Holder hints
A read-cap may carry hints: `retifs:1:<root>:<seed>:<size>@<node>,<node>`. Hints say where to ask; integrity always comes from the CID.

### Replication: push the want, pull the data
- **Lease:** a signed "keep these CIDs until T" from an owner (or a key the owner delegated). It lists chunks, never manifests ([irreversible decision 6](../02-irreversible-decisions.md)). A node that accepts a lease adds blind wants, and its seeker pulls the chunks from the owner or from anyone who has them.
- **Optional push:** `/retifs/put` lets an owner send leased chunks directly before going offline, within the receiver's quota and capability.
- **Receipt:** a signed "I hold all chunks of lease L until T" from the holder. The owner's `status` shows "only here", "N of M holders" or "N copies".
- **Content first, then reference:** a new commit or manifest root is announced only once its chunks have at least one receipt.

### Endpoints
| Endpoint | Request | Response |
|---|---|---|
| `/retifs/have` | CID prefixes | bitmap |
| `/retifs/get` | CIDs | ciphertexts (existing) |
| `/retifs/put` | lease id + ciphertexts | per-chunk accept/reject |
| `/retifs/lease` | signed lease | accept (with quota) or reject |
| `/retifs/receipt` | lease id | signed receipt, or progress |

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- Asking reveals interest in CIDs; prefixes leak slightly less. Asking only trusted candidates by default limits it.
- A lease reveals which chunks belong together to the holder (not content or structure). Mitigations: split leases, cover chunks, per-lease derived signing keys ([ADR-0011](0011-redundancy-by-default.md)).
- A malicious holder can withhold data. Multi-source, proofs and repair (ADR-0011) limit the damage.

## Consequences
- Easier: works on intermittent and LoRa links, partial data is usable, and fetching and replication share one mechanism.
- Harder:
  - Persistent state per want and per peer.
  - Announce payload changes (generation counter).
  - Lease and receipt formats must be fixed carefully (decision 6).
