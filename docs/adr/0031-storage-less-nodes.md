# ADR-0031: Every node is size-limited; storage-less is the end of the scale

- **Status:** accepted (prototype)
- **Date:** 2026-10-28
- **Irreversible:** no. A node mode; no format changes.

## Context
A thin client (a phone, a small device, a borrowed machine) should be a retifs node like any other: its own identity, its own libraries, joining and leaving, announces heard. It differs only in where data is kept: not on the device. The other way, using another of one's own nodes as if it were this one (`--via`, ADR-0019), is a different thing: the device then has no libraries of its own, only the other node's.

## Principles
- Holders and readers are separate (vision; any node may hold ciphertext): a library is read by whoever has its key, and its data may be held anywhere.
- Local-first where there is local storage; where there isn't, the network is the storage, and the device shows what it can reach.

## Decision
**Every node is size-limited**; some have more room than others (a server, a PC, a Pi on an SD card, a phone, a device with none). One rule covers them all:
- A node keeps its own files pinned, and they count towards their copies, while it has room.
- **Short of room** (its own and others' data at nine tenths of its store limit or more, ADR-0007's budget): an own file that has enough confirmed copies elsewhere, its own copy not counted, is kept here only as cache, and so evicted when room is needed. What it holds for others stays as promised.
- **A storage-less node** is the end of the scale, as if always short of room.

`retifsd --no-storage [--cache-max SIZE]`: a node that keeps no data of its own on the device.
- **Kept on the device:** the identity, library keys, the list of libraries and settings, and the record index of what has been fetched (metadata, small). Keys never leave the device.
- **Joined libraries are held lazily** (ADR-0018): records come from checkpoints and the network as they're needed. Libraries created here keep their record index (metadata), not their content.
- **Content** is read from holders on the network and kept only in the cache tier, up to `--cache-max` (default 128 MB), evicted least recently used.
- **Writes** go to other nodes. A file written here is pinned only until placement has enough copies elsewhere: for this node, its own copy doesn't count towards the number of copies or the loss estimate (ADR-0014). Once enough copies elsewhere hold it, its own copy moves to the cache tier. Until then (offline, say) it stays pinned and the write is not yet safe, which the node says.
- **It holds nothing for others** (`hold: false` in its announce): no one offers it copies.
- **It keeps nothing by rules:** keep rules and "keep all" pull nothing here.

## Impact on the threat model
- The device holds keys and little else: losing it loses no data, and it reveals less (no content at rest beyond the cache).
- Its data is on other nodes, as ciphertext; their holders learn sizes and access patterns as with any holder.
- A device that writes while offline holds that write alone until it's placed: as with any node, but it can't keep the copy for long.

## Consequences
- A thin client is a full node; no separate client protocol.
- Without the network it shows only its cache. Pinning an area or a library for offline use needs storage, so it isn't for storage-less nodes.
- Over slow links (LoRa) every read is a fetch; apps should ask for less (lower map zoom first).
