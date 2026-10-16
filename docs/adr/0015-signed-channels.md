# ADR-0015: Signed channels: commits, heads and followers

- **Status:** proposed
- **Date:** 2026-10-16
- **Irreversible:** yes. The commit (decision 8) and head (decision 5) formats are stored and signed; test vectors in `crates/retifs-core/test-vectors/channel-v1.json`, verified against Python RNS.

## Context
Several uses need the same thing: a publisher updates something, and everyone who follows it gets the new version automatically.
- **Sites** (NomadNet pages, HTML): readers should see the latest version, served from wherever copies are, even when the author is offline.
- **An app store** in the spirit of Haiku's hpkg: when the author publishes, every machine using the app updates.
- **Namespaces** in general ([ADR-0006](0006-versioning-and-sharing.md)): every modification is a version in a per-writer chain.

A channel is the single-writer case of ADR-0006's per-writer chains, so its formats must already work for several writers.

## Principles
Supports 2 (the signed chain of roots is a primitive), 1 (commits are ordinary encrypted chunks; holders stay blind), 4 (followers read locally; the network brings updates) and "from trust to crypto" (every follower verifies signatures and sequence numbers). Violates none.

## Options
1. **Mutable pointer by name lookup (IPNS/DNS style):** needs a resolver and a lookup network.
2. **Signed head + chain of commits, held and passed on by followers** (chosen): anyone can verify a head without reading content; followers pass heads and commits on, so the publisher needn't be online.

## Decision

### Formats (draft v1, `retifs_core::channel`)
```text
address  = "retifs-ch:1:" ‖ hex(writer Ed25519 public key) ‖ ":" ‖ hex(read key)
ns_id    = SHA-256("retifs/v1/ns" ‖ writer)[0..16]

commit   = 0x01 ‖ ns_id ‖ writer ‖ seq (u64) ‖ time (u64, unix ms)
           ‖ has_prev (u8) [‖ prev commit cid ‖ prev commit seed] ‖ root cid ‖ root seed ‖ root size (u64)
           ‖ Ed25519(writer, "retifs/v1/commit" ‖ all before)
           sealed as an ordinary chunk; convergence secret = for_record(read key, "retifs/v1/commits")

head     = 0x01 ‖ ns_id ‖ writer ‖ seq (u64) ‖ time (u64, unix s) ‖ commit cid
           ‖ RNS Token(HKDF(read key, "retifs/v1/head-seed", 64), commit seed)   (96)
           ‖ Ed25519(writer, "retifs/v1/head" ‖ all before)                     258 B in total
```
- **Holders and relays stay blind:** a commit is a chunk like any other. A head shows the namespace, the writer key, the sequence number, a time and a commit CID; the commit's seed is encrypted to readers.
- **Rollback protection (decision 5):** anyone can verify a head and keep the highest `seq` per writer, without the read key; a follower never goes back.
- **Freeze protection:** `time` lets a follower distrust a head that hasn't moved for longer than a channel promises (policy, later).
- **History:** each commit links the previous one (CID and seed), so a follower can walk back through every version ([ADR-0006](0006-versioning-and-sharing.md): every modification is a version).
- **Several writers later:** commits and heads already name their writer and carry its own `seq`. A namespace with several writers keeps one chain per writer and merges them (ADR-0006); its `ns_id` then comes from the namespace's creation, and writers are admitted by capabilities (decision 4, open). Here one writer = one channel.

### Behaviour
- **Publishing:** the writer stores the new tree (one record per channel, so versions dedup), seals a commit with `seq + 1` linking the last one, and signs a head. Its own data is placed like any other needed file ([ADR-0014](0014-placement-follows-need.md)).
- **Following:** `retifs follow ADDRESS --from NODE` keeps the channel. The follower asks its hints for the head (`/retifs/head`, ns_id → latest head known) every 30 s and when they announce. A valid, newer head brings the commit, then the new tree is sought; once complete it becomes needed here (so it's placed near the follower), and the previous version is forgotten.
- **Followers pass it on:** a follower keeps the commit chunk and serves it to anyone proving its seed (other followers), and answers head requests for channels it follows. The publisher can go offline once followers have the latest version.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- **Head requests reveal interest** in a namespace to the node asked. Asking only hints (by default the publisher and own nodes) limits it, as for seeking.
- **A stolen writer key** can publish anything to every follower. Mitigations later: key rotation via a signed successor, thresholds (k of n writers), and follower policy (install automatically, notify only, or pin), as in TUF.
- **Withholding (freeze):** a node can serve an old but valid head. Followers keep asking other hints; `time` allows a staleness policy.

## Consequences
- Easier: sites and app updates without a server or a name system; followers keep content alive and nearby; history is a walkable chain.
- Harder: polling for heads costs a small request per channel per hint every 30 s (announce-driven updates need announce app data from Prns); key rotation and thresholds are still to design.

## Implementation status (2026-10-16)
- **Formats:** `retifs_core::channel` (`ChannelKey`, `ChannelAddr`, `Commit`, `Head`); vectors in `channel-v1.json`, verified by `verify_channel_rns.py` with RNS's HKDF, Ed25519 and Token (17/17: commit chunks decrypt, convergent seeds, layouts, signatures, the head's encrypted seed, the head byte for byte).
- **Store:** own channels (keys, last commit, latest head) and follows (address, highest verified `seq`, current and previous version, hints, latest head).
- **Network:** `/retifs/head` (ns_id → latest head known, own or followed).
- **CLI:** `retifs channel create NAME`, `retifs channel publish NAME FILE`, `retifs follow ADDRESS --from NODE`, `retifs channels`.
- **Followers serve:** once a version is complete, a follower pins it and serves it (and the commit, and the head) to anyone proving the chunks' seeds, i.e. other readers. Following a channel thus mirrors it. The trade-off: other readers can see that this node follows the channel; that is the same exposure as holding published data.
- **Live, three daemons:** P created a channel and published a 300 KB version; F1 followed it (hint P) and had it 32 s later. P published version 2 (one byte changed); F1 updated by itself within a minute and forgot version 1 (its chunks shared with version 2 stayed). With P offline, F2 followed with **only F1** as hint and got head, commit and content from F1 (hash matched version 2).
- **Not yet:** announce-driven updates (polling every 30 s for now), staleness policy from `time`, walking history (`versions`), writer key rotation and thresholds, multi-writer namespaces, trees beyond snapshots (a version is one file, or a namespace snapshot with content blocks, [ADR-0016](0016-records-and-snapshots.md)).

