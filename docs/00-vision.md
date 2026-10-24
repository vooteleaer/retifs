# Vision

## Paradigm shift

- **From location to identity**: data isn't "on server X". It's "mine", wherever it physically lives.
- **From files to records**: data and its meaning, not names and folders.
- **From hierarchy to queries**: structure isn't where you put something. It's what you ask of it.
- **From trust to crypto**: you don't have to believe the server behaves.
- **From network dependence to independence**: the network is a means of syncing, not a prerequisite (local-first).
- **From machine to person**: the computer is hardware, and you are your key.

## Parallel with Reticulum

| Reticulum | This project |
|---|---|
| No IP addresses, only identities | No file paths, only records and namespaces |
| No central address allocation | No central server or owner |
| Works over any medium | Storage over any node, disk, stick |
| Crypto by default | Crypto by default, with no unencrypted mode |
| 300 bit/s to gigabit | Same dataset from LoRa to fibre |
| Needs no infrastructure | Works offline, syncs when it can |

## Principles

1. **Always encrypted.** There is no unencrypted mode. "Public" content is encrypted, and the key is shared along with the reference.
2. **Three primitives:** encrypted chunks, a Prolly-tree database, and a signed chain of roots. Everything else is a combination of these.
3. **Only RNS crypto primitives.** No new crypto is invented.
4. **Local-first.** Writes are local and immediate, and the network is for syncing.
5. **The BeOS way, not the WinFS way.** Free-form key-value attributes, schema as convention, opaque blocks. No relational engine on every file's path.
6. **The file tree is a compatibility view,** not the primary interface.
7. **Storage nodes are blind.** They hold hash-addressed noise and know nothing of its structure.
8. **Redundant by default.** Every piece of your own data has a replication target from the moment it's written. "Only here" is a visible, temporary state, not a setting. Your own nodes pool and repair automatically, and others can volunteer storage ([ADR-0011](adr/0011-redundancy-by-default.md), proposed).
9. **Data is universal; each app shows its part.** Records belong to no app and a library has no kind: a contact, an event or a photo is the same record to every app, its `type` a MIME type ([ADR-0025](adr/0025-types-are-mime-types.md)). Each app shows the records it's made to show and leaves the rest alone (keeping keys it doesn't know); Find, like Haiku's Tracker, sees everything. Records refer to each other by ID across libraries, so a person ties their photos and events together ([ADR-0024](adr/0024-people-and-events.md)). Apps are the main interface, each organising its part by its own logic.

## Non-goals

- Not compatible with IPFS.
- No unencrypted storage.
- Not a relational database: no joins, no enforced schemas.
- No guaranteed deletion across the network. Deletion means destroying the key (crypto-shredding).
- Does not replace global DNS with one global namespace.

## Why not X?

- **Why not just IPFS?** It has no encryption by default and no attributes or queries. Its DHT is expensive over radio, and libp2p isn't RNS.
- **Why not rnfs?** It's a good IPFS port to RNS, but it's public by default and uses plaintext CIDs, which conflicts with principle 1 at the format level. We learn from it rather than build directly on it.
- **Why not git?** We take its history model, but git has no distributed storage, queries or crypto.
- **Why not NFS/Samba/Nextcloud?** They have a server in the middle and are location-based and trust-based.
- **Why not RAID, Ceph or MinIO?** They're bound to one location or cluster, don't encrypt at the storage layer, and assume a fast, always-on LAN. retifs redundancy works across sites and links, and holders only ever see ciphertext.
- **Why not an SQL database?** WinFS tried. See [prior art](03-prior-art.md).
