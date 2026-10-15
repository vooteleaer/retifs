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
  - store generation counters (from authorized peers only; **no public Bloom filters of holdings**, see below);
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

### Who may ask: RNS style (anonymous by default)
As in RNS, where a NomadNet page or LXMF delivery doesn't learn who's asking unless the requester chooses to `identify`, **access is proven by knowing a secret, not by revealing who you are.** Answering `have`/`get` reveals holdings, so an attacker who knows CIDs (honeypot chunks, or CIDs computed from a known public file) must not be able to probe ([threat model](../04-threat-model.md#holder-privacy-tracking-and-honeypot-attacks)).
- **Fetchers are anonymous by default:** ephemeral links, no `identify`.
- **Proof of access, per chunk (revised 2026-10-15):** each item in a request carries its own proof, `HMAC(chunk_token, label ‖ link_id ‖ cid or prefix)`, where `chunk_token = HKDF(chunk seed)`. The requester knows each seed from the manifest, so no token has to be shared. There is **no file-level token on the wire**, so a holder can't link items of one file by token. The link ID is a free, replay-proof nonce, so there's no extra round trip. The holder verifies each proof and learns nothing about the requester. Without a valid proof an item gets "don't have", indistinguishable in content and timing. (The first slice used one serve token per file; that linked every request for a file and was replaced.)
- **Identity only where policy needs it:** own nodes, quotas and volunteer-storage accounting use RNS `identify`, like restricted NomadNet pages. Ordinary reading never does.
- **Publishing is deliberate:** content explicitly **published or seeded** is served to anonymous requesters without proof, like hosting a micron page. Being seen holding it reveals nothing private.
- **The cache tier is never served** (with or without proof) except to own nodes. A honeypot creator knows the seed and the token, but still can't see reading history.
- **No public holdings summaries** in announces. Generation counters go to proven or own peers only.
- **Rate limits and stamps** for non-own requesters.
- **Option (later):** per-file serving destinations derived from the read-cap, so only cap holders can even find where a file is served.

### Request-pattern leaks (2026-10-15)
What a holder holds reveals little: chunks are equal-sized blobs with no visible grouping. What it is **asked** reveals more:
- **Grouping by token:** removed by per-chunk proofs (above).
- **Grouping by request:** a batched request shows that its items belong together. Requests can carry a single item (one packet each: `get` 49 B, `have` 24 B), so a peer can't group by request either. `retifsd --private-requests` seeks one item per request; the fetcher's `batch: 1` does the same. On own nodes and LANs, batching stays the default for speed.
- **Telling a peer the size:** a `have` over all wanted chunks tells even a one-chunk holder the file's chunk count. Mitigations, not yet implemented: ask each peer about a slice; add decoy prefixes.
- **Padding:** readers fetch padding chunks like real ones, so the number of requests matches the padded size (ADR-0008/0009).
- **Residual:** requests on one link are visibly one session, and bursts are visible in timing. Spreading requests over several links with jitter reduces this; a global passive observer is out of scope, as for RNS.

### Holder hints
A read-cap may carry hints: `retifs:1:<root>:<seed>:<size>@<node>,<node>`. Hints say where to ask; integrity always comes from the CID. The read-cap also carries the file's serve token (format to be fixed together with the lease format, decision 6).

### Replication: push the want, pull the data
- **Lease:** a signed "keep these CIDs until T" from an owner (or a key the owner delegated). It lists chunks, never manifests ([irreversible decision 6](../02-irreversible-decisions.md)). A node that accepts a lease adds blind wants, and its seeker pulls the chunks from the owner or from anyone who has them.
- **Optional push:** `/retifs/put` lets an owner send leased chunks directly before going offline, within the receiver's quota and capability.
- **Receipt:** a signed "I hold all chunks of lease L until T" from the holder. The owner's `status` shows "only here", "N of M holders" or "N copies".
- **Content first, then reference:** a new commit or manifest root is announced only once its chunks have at least one receipt.

### Endpoints
| Endpoint | Request | Response |
|---|---|---|
| `/retifs/have` | items of CID prefix (8) ‖ proof (16), ≤ 16 | bitmap |
| `/retifs/get` | items of CID (33) ‖ proof (16), ≤ 64 | ciphertexts |
| `/retifs/put` | lease id + ciphertexts | per-chunk accept/reject |
| `/retifs/lease` | signed lease | accept (with quota) or reject |
| `/retifs/receipt` | lease id | signed receipt, or progress |

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Answering reveals holdings (tracking/honeypot attack).** Mitigated by anonymous proof of access (serve tokens), a never-served cache, deliberate publishing and no public summaries (see "Who may ask").
- Asking reveals interest in CIDs; prefixes leak slightly less. Asking only trusted candidates by default limits it.
- A lease reveals which chunks belong together to the holder (not content or structure). Mitigations: split leases, cover chunks, per-lease derived signing keys ([ADR-0011](0011-redundancy-by-default.md)).
- A malicious holder can withhold data. Multi-source, proofs and repair (ADR-0011) limit the damage.

## Consequences
- Easier: works on intermittent and LoRa links, partial data is usable, and fetching and replication share one mechanism.
- Harder:
  - Persistent state per want and per peer.
  - Announce payload changes (generation counter).
  - Lease and receipt formats must be fixed carefully (decision 6).

## Implementation status (2026-10-14)
- **"Who may ask", first slice:**
  - Serve token derived from the read-cap (`retifs_core::access`): `token = HKDF(root seed, "retifs/v1/serve")`, `proof = HMAC(token, "retifs/v1/get" ‖ link_id ‖ CIDs)[0..16]`.
  - `/retifs/get` v1 request: `token_id ‖ proof ‖ CIDs`.
  - `retifsd` keeps a serving index (token, CID) for its own writes, plus published CIDs under an all-zero id. Fetched and cached chunks are never in it.
  - Covered by unit tests, in-memory fetch tests (wrong token: nothing served), and a three-daemon run on one machine (owner serves, forged read-cap and cache-only holder get nothing).
- **Want-list and seeker, first slice:**
  - `retifs-store` keeps wanted files, wants per chunk (seed and span, so nodes expand into children), and hints per (file, peer) with back-off from 30 s to 30 min. An announce resets that peer's back-off.
  - `/retifs/have`: token id, proof, and up to 48 CID prefixes of 8 bytes (fits one packet), answered with a bitmap from the serving index only (cache stays invisible).
  - `retifs_net::seek::seek_round`: `have`, then `get` for what's held.
  - `retifsd` runs a seeker woken by new wants, announces of hinted peers, and a 30 s tick. It completes from local chunks first, then asks peers, storing arrivals in the cache tier and expanding nodes into new wants.
  - `retifs want CAP --from NODE` queues a file; `status` shows "seeking (N holders known)".
- **Tests:** in-memory, two peers each holding half fill a file together and a prober learns nothing from `have` or `get`. Live, B wanted a 3 MB file while its only holder A was offline; 6 s after A came back and announced, B had all 211 chunks, with no manual retry, and the hash matched.
- **Not yet:**
  - A holder map beyond per-file hints (ranking per chunk, learning holders from others).
  - Candidates other than hints (own-node pool, opt-in announced nodes).
  - Leases and receipts.
  - Rate limits and stamps.

