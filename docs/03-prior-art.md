# Prior art and lessons

## BeOS / BFS: worked
- Attributes inside the file system, with indexes as B+ trees in the same FS and no SQL engine.
- Only selected attributes were indexed, so writes stayed fast.
- A simple query language, plus live queries through file system notifications.
- The OS's own applications (BeMail, People) used it from day one, so there was no chicken-and-egg problem.
- Weaknesses: a new index didn't cover old files. Attributes were lost when copying, zipping or emailing. Everything was local.
- Reading: Dominic Giampaolo, *Practical File System Design with the Be File System* (1999, free).

## WinFS (Microsoft, 2003–2006): failed
- An SQL Server engine on top of NTFS made it slow.
- Rigid universal schemas meant the world didn't fit.
- It was all-or-nothing, so applications didn't adopt it.
- The Longhorn reset happened, and Windows Search delivered 80% of the value more cheaply.
- **Lesson:** a lightweight KV store and schema as convention. Old applications work immediately through the file view. The killer feature must be something search can't give you.

## IPFS
- Good: CID, Merkle DAG, Bitswap, pinning.
- Missing: crypto by default, attributes, indexes, queries. In IPLD you can walk paths, not search.
- IPNS over the DHT is slow. Databases came from third parties (OrbitDB, Ceramic, ThreadDB), which fragmented the ecosystem.

## rnfs (github.com/afit21/rnfs, v0.1.0, MIT, Python)
- An IPFS port to RNS with very thorough documentation and packaging. It's young (1 star, 10 commits).
- 64 KiB chunks (FastCDC optional), a Kademlia DHT for provider records only, and Sybil protection by node age.
- Names = announce + signed record, held by keepers. Pubsub left out.
- LoRa settings: upload_budget, serve/no_serve_interfaces, quiet_hours. Remote pinning with quotas. Export/import for sneakernet.
- **Difference:** public by default. "Sealing" is per file. It doesn't hide size or recipients, and it doesn't prove who sealed. No attributes, queries, history, capabilities or FUSE.
- **Use for us:** test it on a real mesh, read `specification.md` (especially Appendix A), borrow transport/DHT ideas. Don't build directly on top of it.

## Others
- **Tahoe-LAFS**: capabilities (read-cap = CID + key), very well thought through.
- **Dolt**: a versioned DB on Prolly trees, with diff and merge solved.
- **Pijul**: patch-based, with mathematically more correct merges.
- **Irmin**: a git-like store with type-specific merge functions.
- **Perkeep, Hypercore**: a personal content-addressed store, and append-only logs.
- **Secure Scuttlebutt**: a cautionary tale about serialization.
- **Plan 9, CernVM-FS, OSTree/composefs, Nix**: a network file system for everything, a lazy content-addressed software tree, an atomic rootfs.
- **Haiku hpkg/packagefs, Tiny Core tcz**: mountable packages.
- **UCAN**: capability chains.
