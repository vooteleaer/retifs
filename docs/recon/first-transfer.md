# Recon: first retifs file transfers between machines (phase 1)

`retifsd` imports a file into its slab store and serves chunks at `/retifs/get`. `retifs get READ-CAP --from NODE` attaches to the local `prnsd`, finds a path, opens one Link, walks the manifest breadth-first with batched requests, verifies every chunk (CID + HMAC) and writes the plaintext. Both are in `crates/retifs-node`, built on `retifs-net` and Prns 0.3.7 ([prns-embedding](prns-embedding.md)).

## Results (2026-10-14)

Every transfer was verified by SHA-256 of the output against the original.

### Same machine (both processes attached to the local prnsd), 10 MiB, 711 chunks, 1 in flight
| Batch (CIDs/request) | Requests | Time | Throughput |
|---|---|---|---|
| 8 | 92 | 1.46 s | 58 Mbps |
| 16 | 47 | 0.50 s | 167 Mbps |
| 32 | 25 | 0.36 s | 233 Mbps |
| 64 | 14 | 0.30 s | 280 Mbps |

### LAN, 1 hop (testbed server ← dev machine over TCP), 10 MiB
| Batch | Time | Throughput |
|---|---|---|
| 8 | 2.98 s | 28 Mbps |
| 16 | 1.93 s | 44 Mbps |
| 32 | 1.68 s | 50 Mbps |
| 64 | 1.44 s | 58 Mbps |

Path found in 9 ms and Link set up in 2 ms. For comparison, `prnsd cp` moved one 64 MiB Resource over the same link at about 212 Mbps ([prns-interop](prns-interop.md)), so per-request overhead dominates here.

### Public backbone, 5 hops (Raspberry Pi ← dev machine), 1 MiB, batch 64
| Path request | Link setup | Fetch | Throughput |
|---|---|---|---|
| 20 ms (cached) | 391 ms | 16.2 s (4 requests) | 0.52 Mbps |

That's on par with the best Python pattern on a similar path (0.55 Mbps, [chunk-fetch](chunk-fetch.md)). Only 1 MiB was sent, so as not to load community gateways.

## Findings
- **The full stack works end to end** across Windows x86_64, Linux x86_64 (with `prnsd` in Docker over TCP) and Linux aarch64 (Raspberry Pi with native `prnsd` over the abstract socket).
- **Several Resource responses in flight on one Prns Link can stall forever.** With 4 in flight, 3 of 45 batches never settled; 1 in flight always completed. Hence `FetchOpts::default()` uses 1 in flight plus a 60 s per-request timeout. This is a candidate upstream issue for Prns. **Workaround to try:** several Links per peer, one request in flight on each.
- **Bigger batches win everywhere measured.** The default is now 32, and 64 is the protocol maximum (`MAX_BATCH`, up to ~1 MiB per response).
- **Socket naming:** Prns prefixes the abstract socket name with `rns/`, so the transport's `socket_path` is the instance name (`default`), not `rns/default`.
- **Containerised prnsd:** a `prnsd` configured with a TCP shared instance has no abstract socket, so `attach()` tries the abstract socket first and then TCP.
- **Store access:** the slab store's redb index is opened exclusively, so files are imported by `retifsd --put` at startup until the local API ([ADR-0004](../adr/0004-native-record-api.md)) exists.

## Next
- Several Links per peer (parallelism without the in-flight stall), then retest the LAN at batch 64.
- Report the stall upstream with a minimal reproduction.
- Fetch from several peers (multi-source), and cache fetched chunks in the local slab store.
