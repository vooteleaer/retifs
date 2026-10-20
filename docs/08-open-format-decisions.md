# Format decisions before ADR-0008/0009

**Both decided on 2026-10-20: option A each** (replicas now, erasure coding later below chunks; a 512 B class). The options are kept here as the record.

Two choices were left before [ADR-0008](adr/0008-chunk-encryption-and-cid.md) (chunk encryption, CIDs) and [ADR-0009](adr/0009-manifest-format.md) (manifests) can be accepted. Both are fixed for good once real data is stored. The rest of their earlier open points are decided: PADMÉ over the chunk count (final-chunk padding) and one secret per record (personal scheme). Separately, an external review of the construction and its KDF labels is still needed. That is an action, not a choice.

## 1. Full replicas vs erasure coding

**Today:** placement ([ADR-0014](adr/0014-placement-follows-need.md)) keeps whole copies of chunks on holders; a lease lists chunks; repair copies a chunk to a new holder.

**Erasure coding** (k-of-n, Tahoe-LAFS style) protects more per byte: 4-of-6 costs 1.5× and survives 2 losses, where full replicas surviving 2 losses cost 3×.

| | Full replicas | Erasure coding |
|---|---|---|
| Storage per unit of protection | high (3× to survive 2 losses) | low (1.5× for 4-of-6) |
| Reading | one holder is enough | needs k holders; k round trips over LoRa |
| Repair | copy one chunk | fetch k shares, decode, re-encode |
| Holders | hold ciphertext chunks | hold shares (linear combinations of ciphertext; still noise to them) |
| Slow links | fine | worse: reads fan out to k nodes |

**The key point for the format:** shares don't have to change chunks or manifests. They can be a layer *below* chunks: a *share map* says "chunk group G = shares S1…Sn, any k rebuild it". A reader that gets a group back checks every chunk against its CID as usual. Chunks stay the unit of addressing, manifests stay as they are, and leases list share CIDs instead of chunk CIDs (a share is a fixed-size blob, so it fits the size classes).

**Options:**
- **A. Full replicas now; erasure coding later as a separate layer below chunks** (share maps, its own ADR and vectors when needed). This needs nothing reserved in ADR-0008/0009, so they can be accepted after review.
- **B. Erasure coding now:** design share maps and the share format before accepting ADR-0008/0009. It costs a lot of work before any use, and LoRa reads get worse.
- **C. Full replicas only, for good:** simplest, but volunteer and pool storage then cost the most.

**Recommendation: A.** Replicas suit the slow links retifs is built for, and the layering keeps erasure coding open without blocking the chunk format.

## 2. Smallest size class: 1 KiB or 512 B

**Today:** classes run 1 KiB … 256 KiB, and every chunk is padded to one ([ADR-0008](adr/0008-chunk-encryption-and-cid.md)). Since multi-writer namespaces, every modification is two small chunks: a commit (268 B) and an operations file (48–389 B in the vectors). Each is padded to 1 KiB, so **a write costs 2 KiB** on the wire for under 700 B of content.

Over LoRa (SF7, 125 kHz, about 5 kbit/s raw, 10 % airtime limit) that's roughly 4 s of airtime per write at 1 KiB, or 2 s with a 512 B class. A 512 B class carries up to 443 B of payload, which fits a commit and most operations files.

| | 1 KiB smallest (today) | 512 B smallest | 256 B smallest |
|---|---|---|---|
| Cost of one write | 2 KiB | 1 KiB (usually) | 1 KiB (a commit doesn't fit in 256 B with the overhead) |
| Size leak of small chunks | to 1 KiB | to 512 B: one more class, so small objects are told apart a little better | more classes still |
| Slab store | as is | one more slab size | two more |

**Options:**
- **A. Add a 512 B class.** Halves the cost of small writes and commits on slow links; one more class reveals a bit more about small objects.
- **B. Keep 1 KiB.** Simplest; small writes stay 2 KiB.
- **C. Keep 1 KiB but pack** a commit and its operations into one chunk. A format change in [ADR-0017](adr/0017-multi-writer-namespaces.md) instead of ADR-0008. It saves the same bytes for writes but not for other small objects (heads are already 258 B and not chunks).

**Recommendation: A**, measured first on LoRa once a radio link works again (the LoRa test is parked). The class list goes into every chunk's size, so it must be settled before ADR-0008 is accepted.
