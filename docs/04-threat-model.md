# Threat model (draft)

Every crypto decision is checked against this.

## Adversaries

| Adversary | Sees / gets | Must not get |
|---|---|---|
| **Pinning node** | encrypted chunks, their (padded) size, request timing | content, structure (which chunks belong together), attributes, who the owner is |
| **Foreign machine** (thin client) | what the session capability allows, during the session | root or device key; any rights after the session ends |
| **Local application** | what its per-app capability allows | the rest of the user's data; a FUSE mount is a deliberate broad grant |
| **Network observer** | RNS traffic patterns | content, CIDs (the Link is encrypted) |
| **Malicious co-author** (in a group) | everything they were granted | un-narrowed rights, forging others' signatures, rewriting history |
| **Former member** | what they already received | new content after key rotation |
| **Sybil / spammer** | cheap identities | unlimited storage, announces, attributes (stamps, quotas) |
| **Prober / tracker** (knows CIDs: created honeypot chunks, or computed them from a known public file) | whether *it* can fetch a chunk from nodes that serve it | which nodes hold, or read, a given chunk; what any node has in its cache |
| **Lost/stolen YubiKey, stick or disk** | nothing (the local store is ciphertext; without the key it's noise) | the identity; the device key is revoked by the root |

## Known leaks
- Chunk count and size class, request timing.
- Public content under a convergent key: anyone can compute the CIDs of a known file. That the file exists somewhere is accepted, since the content is public. **Who holds it is not**: see "Holder privacy" below.
- Lease renewal timing (mitigation: delegated renewal).

## Holder privacy (tracking and honeypot attacks)
An attacker who knows CIDs (because it created distinctive chunks and got people to fetch them, or computed them from a known public file) could ask nodes "do you have these?" and learn who read what. Rules:
1. **Anonymous by default, access by possession (RNS style).** Requesters don't identify; they prove knowledge of a per-file or per-lease serve token from the read-cap (`HMAC(token, link_id ‖ request)`). Without a valid proof the response is indistinguishable from "don't have", in content and timing. Identity (`identify`) is used only where policy needs it: own nodes, quotas, volunteer accounting. Explicitly published or seeded content is served to anyone, like a micron page.
2. **The cache is never served to others.** Cached chunks are the user's reading history; only the user's own nodes may see them. Serving public content to strangers ("seeding") is an explicit opt-in per content class, never a side effect of reading.
3. **Proofs stop CID-only probing.** Parties who only saw CIDs (pinning nodes, observers) can't produce proofs. A honeypot creator can (it knows the token), so rule 2 protects reading history.
4. **No public summaries of holdings.** Announces carry no Bloom filters of held chunks. Store generation counters go only to authorized peers.
5. **Holding doesn't imply reading.** Pool and volunteer nodes hold leased chunks they never chose to read. In diffuse mode, nodes also hold unrequested chunks (cover holdings), and the origin seeds by pushing over anonymous links instead of serving, so it's hidden among many holders ([ADR-0011](adr/0011-redundancy-by-default.md)). Limits: small networks, early-spread timing analysis, global passive observers.
6. **Linkability.** A long-lived `retifs.node` destination makes a node trackable. Use per-group or per-namespace serving destinations and ephemeral identities for fetching where possible.
7. **Probing is expensive.** Rate limits and stamps on `/have` and `/get` from non-own peers.

**Prototype status (2026-10-14):** `retifsd` still answers `/retifs/get` for anyone (`AllowAll`) without proofs, and doesn't separate the cache tier. Fixing that comes before any non-test use.

## Open
- Compromised bootstrap (needs Secure Boot / measured boot).
- Metadata timing analysis of live queries.
- Sybil attacks on the DHT/discovery (rnfs uses node age).
- Cover holdings and diffusion: disk and bandwidth cost vs privacy gain; how much jitter and batching are needed against source detection in early spread.
- Timing side channels in "don't have" responses (lookup vs no lookup).
