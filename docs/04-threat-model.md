# Threat model (draft)

Every crypto decision is checked against this.

## Adversaries

| Adversary | Sees / gets | Must not get |
|---|---|---|
| **Pinning node** | encrypted chunks, their (padded) size, request timing | content, structure (which chunks belong together), attributes, who the owner is |
| **Foreign machine** (thin client) | what the session capability allows, during the session | root or device key; any rights after the session ends |
| **Local application** | what its per-app capability allows (an app-socket token scoped to namespaces and read/write, pinned to its executable on Linux) | the rest of the user's data; a FUSE mount and the gateway are deliberate broad grants |
| **Network observer** | RNS traffic patterns | content, CIDs (the Link is encrypted) |
| **Malicious co-author** (in a group) | everything they were granted; reading the whole namespace (limits restrict writes, not reads) | un-narrowed rights (limits only narrow on delegation), writes outside its keys or after its expiry, forging others' signatures, rewriting history |
| **Former member** | what they already received | new content after key rotation |
| **Search node** (given a namespace's search capability) | the index: how many records share each opaque value of a declared key, which tokens members ask for and when, how posting lists change between versions | attribute names or values, record contents, the checkpoint, tokens it wasn't sent, which entries in different lists are one record ([ADR-0019](adr/0019-remote-query-and-blind-index.md)) |
| **Sybil / spammer** | cheap identities | unlimited storage, announces, attributes (stamps, quotas) |
| **Prober / tracker** (knows CIDs: created honeypot chunks, or computed them from a known public file) | whether *it* can fetch a chunk from nodes that serve it | which nodes hold, or read, a given chunk; what any node has in its cache |
| **Lost/stolen YubiKey, stick or disk** | nothing (the local store is ciphertext; without the key it's noise) | the identity; the device key is revoked by the root |

## Known leaks
- Chunk count and size class, request timing.
- Public content under a convergent key: anyone can compute the CIDs of a known file. That the file exists somewhere is accepted, since the content is public. **Who holds it is not**: see "Holder privacy" below.
- Lease renewal timing (mitigation: delegated renewal).
- **Lease grouping:** holders see which chunks a lease lists. Leases pack chunks of several files sorted by CID, so they show neither file boundaries nor chunk order; what remains is that chunks leased together were placed together ([ADR-0014](adr/0014-placement-follows-need.md)).
- **Revoked members:** a revoke rotates the namespace's read key, wrapped to each remaining writer's RNS identity; later versions are unreadable to the revoked member, history it had stays readable ([ADR-0017](adr/0017-multi-writer-namespaces.md)).
- **Junk leases:** per-lease signing keys rule out quotas per owner, so lease offers carry a proof-of-work stamp (LXMF construction, holder-set cost, [ADR-0014](adr/0014-placement-follows-need.md)); together with each holder's hold limit this makes filling nodes with junk costly, not impossible.
- **Request patterns:** requests on one link are visibly one session, and bursts are visible in timing. Token linking is removed (per-chunk proofs), request grouping is avoidable (one item per request), and padding hides file size to a PADMÉ bucket; what remains is link/timing correlation ([ADR-0010](adr/0010-continuous-seeking.md)).
- **File size** to a PADMÉ bucket (O(log log n) bits), not exactly ([ADR-0008](adr/0008-chunk-encryption-and-cid.md)).
- **Local gateway:** `retifs-gateway` serves every namespace read-only on `127.0.0.1:8740` to the user it runs as. It refuses other users: on Linux by the connection's owner in `/proc/net/tcp{,6}`, on Windows by the owning process's user SID; that user's own processes could read the daemon's socket anyway. Requests other websites make in the background (`Sec-Fetch-Site: cross-site`, not a navigation) are refused before any lookup, so a page can't probe which namespaces and files exist or make the node fetch content; links to a site still open. The `Host` check stops DNS rebinding and each namespace is its own origin. On Windows the TCP table names the connection's process, whose token must carry the same user SID; a process of another user can't even be opened, so it is refused.
- **Own devices over a Link:** a node asking another with `--via` identifies to it, so that node (the user's own) learns which node asks and when; an observer sees only an encrypted link. An admitted device keeps its scope (namespaces, read/write) until it's removed, so a lost device should be removed on the others ([ADR-0019](adr/0019-remote-query-and-blind-index.md)).
- **Checkpoints:** a new member trusts the state a grant holder's checkpoint gives it. A dishonest holder (or one revoked after making it) can hand out a false state until `ns verify` replays the history against it ([ADR-0018](adr/0018-state-trees.md)).
- **Commit clocks:** a member can date commits up to a day ahead and win conflicts within that window ([ADR-0017](adr/0017-multi-writer-namespaces.md)).

## Holder privacy (tracking and honeypot attacks)
An attacker who knows CIDs (because it created distinctive chunks and got people to fetch them, or computed them from a known public file) could ask nodes "do you have these?" and learn who read what. Rules:
1. **Anonymous by default, access by possession (RNS style).** Requesters don't identify; each item proves knowledge of that chunk's seed (`HMAC(chunk_token, link_id ‖ cid)`), so nothing links items of one file by token. Without a valid proof the response is indistinguishable from "don't have", in content and timing. Identity (`identify`) is used only where policy needs it: own nodes, quotas, volunteer accounting. Explicitly published or seeded content is served to anyone, like a micron page.
2. **The cache is never served to others.** Cached chunks are the user's reading history; only the user's own nodes may see them. Serving public content to strangers ("seeding") is an explicit opt-in per content class, never a side effect of reading.
3. **Proofs stop CID-only probing.** Parties who only saw CIDs (pinning nodes, observers) can't produce proofs. A honeypot creator can (it knows the token), so rule 2 protects reading history.
4. **No public summaries of holdings.** Announces carry no Bloom filters of held chunks. Store generation counters go only to authorized peers.
5. **Holding doesn't imply reading.** Pool and volunteer nodes hold leased chunks they never chose to read. In diffuse mode, nodes also hold unrequested chunks (cover holdings), and the origin seeds by pushing over anonymous links instead of serving, so it's hidden among many holders ([ADR-0011](adr/0011-redundancy-by-default.md)). Limits: small networks, early-spread timing analysis, global passive observers.
6. **Linkability.** A long-lived `retifs.node` destination makes a node trackable. Use per-group or per-namespace serving destinations and ephemeral identities for fetching where possible.
7. **Probing is expensive.** Rate limits and stamps on `/have` and `/get` from non-own peers.

**Prototype status (2026-10-14):** rules 1–3 are implemented. `/retifs/get` requests carry a token id and an anonymous proof bound to the link; `retifsd` serves only chunks registered under that token (its own writes) or published (`retifs put --publish`), and never fetched or cached chunks. Refusals look like "don't have", with the same lookups on every path. Tested across three daemons: a forged read-cap that knows the root CID gets nothing, and a node holding a file only in its cache refuses even a correct read-cap. Rate limits, stamps and per-group destinations are not done yet.

## Open
- Compromised bootstrap (needs Secure Boot / measured boot).
- Metadata timing analysis of live queries.
- Sybil attacks on the DHT/discovery (rnfs uses node age).
- Cover holdings and diffusion: disk and bandwidth cost vs privacy gain; how much jitter and batching are needed against source detection in early spread.
- Timing side channels in "don't have" responses (lookup vs no lookup).
