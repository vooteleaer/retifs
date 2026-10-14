# ADR-0013: Slow links (LoRa)

- **Status:** proposed
- **Date:** 2026-10-14
- **Irreversible:** partly. Inline tiny files (manifest format, [ADR-0009](0009-manifest-format.md)) and a compression flag in the chunk frame ([ADR-0008](0008-chunk-encryption-and-cid.md)) are format decisions; both are now in the draft format (2026-10-14). The rest is policy.

## Context
On LoRa (e.g. SF7, 125 kHz, EU 869.5 MHz with a 10 % duty cycle), a node gets a few kbps on air and, within the duty cycle, on the order of **0.5 MB per hour** at best. Link MTU is small (~4 KB negotiated over mixed paths, ~500 B packets on the radio), RTTs are seconds, and announces cost shared airtime. One 16 KiB chunk is about 40 RNS packets and roughly a minute of airtime. Seeking, replication, spare filling and diffusion ([ADR-0010](0010-continuous-seeking.md)–[ADR-0012](0012-disk-budget.md)) would swamp such links if left unchecked.

## Principles
Supports 4 (local-first: the network is for syncing, and slow links sync what matters first) and the vision's "same dataset from LoRa to fibre". Violates none.

## Decision

### Control plane over LoRa, bulk only on explicit request
- **Over LoRa by default:** wants, `have` queries, leases, receipts, commits and small manifest nodes.
- **Bulk chunks:** only for explicit user fetches of specific data, within an airtime budget.
- **Never over LoRa:** spare filling, diffusion, redundancy replication.

### Airtime-aware, prioritised sending per interface
Priority order:
1. interactive reads;
2. own small data;
3. metadata;
4. bulk.

Respect RNS airtime limits and announce-rate targets, and never saturate a shared channel.

### Inline tiny files (format: added)
Files of at most 951 bytes are stored inside the root manifest node (node kind 2, [ADR-0009](0009-manifest-format.md)), so reading one is one fetch of one 1 KiB blob instead of two (root node, then chunk). A 1 KiB blob still needs a small Resource on LoRa (about 3 packets), since 1 KiB plus Token overhead exceeds one link packet.

### Compression before encryption (format: added)
- **Why:** ciphertext doesn't compress, so RNS Resource compression gains nothing for retifs chunks. Text and metadata compress 3–5×.
- **What:** the chunk frame has an encoding byte (0 raw, 1 zstd) inside the encrypted frame ([ADR-0008](0008-chunk-encryption-and-cid.md)). Writers opt in per file (`retifs put --compress`); manifest nodes are never compressed.
- **Risk:** compressed size can leak content (CRIME-style) when attacker-controlled data is mixed with secrets in one chunk. For whole files that's minor, and the padding classes hide most of the size. Mixed-content chunks can opt out.
- **Measured:** a repetitive 16 000-byte text chunk shrank from the 16 KiB class to at most 2 KiB; a 500 KB log file took under a quarter of the uncompressed storage (tests in `retifs-core`).

### Link-adaptive content
- Prefer thumbnails and low-resolution variants (separate blocks per resolution, progressive JPEG XL), and Opus 6–12 kbps or Codec2 for audio ([architecture](../01-architecture.md)).
- The fetcher picks variants by the link's measured capacity.

### Store-and-forward
- The want-list waits for a fast link when bulk would otherwise cross LoRa.
- Large data can travel as export bundles on removable media ([ADR-0007](0007-local-store-layout.md)).

### Announce economy
- retifs-level announces (store generation) are rate-limited and not sent over LoRa by default; peers use path requests on demand.
- Links are kept alive only while useful, since keepalives cost airtime.

### Smaller chunks for LoRa-native content (policy)
Messages, notes and sensor data created on LoRa nodes may use a smaller chunker policy (2–4 KiB classes). The chunker is policy, not format ([ADR-0008](0008-chunk-encryption-and-cid.md)), so it can be set per content class.

## Impact on the threat model
- Compression and size: see above.
- Fewer announces over LoRa also means less metadata on a channel that's easy to monitor.

See the [threat model](../04-threat-model.md).

## Consequences
- Easier: LoRa nodes stay useful for messages, notes, metadata and selected files without starving the channel.
- Harder:
  - Per-interface scheduling and airtime accounting.
  - Two format additions to settle before ADR-0008/0009.
  - Real numbers are pending a LoRa test with a second RNode.
