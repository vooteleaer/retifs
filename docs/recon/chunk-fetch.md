# Recon: fetching many small chunks over RNS (phase 0)

How should retifs request chunks: one per request, or batched (`/get [cid1…cidN]`)? Measured with [`recon/chunk_bench.py`](../../recon/chunk_bench.py), a throwaway benchmark using the Python RNS API (Link + request handler; responses larger than the link MDU travel as Resources). Every chunk is verified byte for byte.

Both ends are Python RNS clients attached to `prnsd` 0.3.7 shared instances, so the path is Python → Prns → … → Prns → Python.

## Patterns
- **A**: new Link per chunk
- **B**: one Link, one request per chunk
- **C**: one Link, batched requests (one response carries N chunks)
- **D**: one Link, pipelined single-chunk requests (N in flight)

## Results (2026-10-13)

### LAN, 1 hop (testbed server → dev machine), RTT a few ms

| Pattern | 64 × 32 KiB | 128 × 16 KiB |
|---|---|---|
| A new Link per chunk | 22.1 ms/chunk · 11.8 Mbps | 25.0 ms/chunk · 5.2 Mbps |
| B request per chunk | 7.7 ms/chunk · 34.0 Mbps | 7.6 ms/chunk · 17.3 Mbps |
| C batch 8 | 7.1 ms/chunk · 36.9 Mbps | 4.7 ms/chunk · 27.9 Mbps |
| C batch 32 | 6.6 ms/chunk · 39.4 Mbps | 3.3 ms/chunk · 39.3 Mbps |
| C batch 64 / 128 (all) | 6.2 ms/chunk · 42.1 Mbps | 3.0 ms/chunk · 44.0 Mbps |

- Link setup: median 12 ms.
- Each request costs about 7.6 ms regardless of chunk size, so small chunks need batching most.
- About 44 Mbps is the Python client and server ceiling. `prnsd cp` reached over 200 Mbps on the same link ([prns-interop](prns-interop.md)).

### Public backbone, 4 hops (Raspberry Pi → dev machine), RTT 0.8–1 s, link MTU 4.1 KB

| Pattern | 16 × 32 KiB | per chunk | Mbps |
|---|---|---|---|
| A new Link per chunk | 34.9 s | 2182 ms | 0.12 |
| B request per chunk | 29.5 s | 1841 ms | 0.14 |
| C batch 4 | 11.6 s | 726 ms | 0.36 |
| C batch 16 | 7.6 s | 478 ms | 0.55 |

- Link setup: median 486 ms.
- Batching is **4.6× faster** than a Link per chunk and **3.9×** faster than a request per chunk.
- Kept small (about 2.5 MB in total) so as not to load volunteer-run community gateways.

### Pipelining (second run, same day)

**LAN, 1 hop, 128 × 16 KiB** (negotiated link MTU 262 KB):

| Pattern | ms/chunk | Mbps |
|---|---|---|
| B request per chunk | 8.3 | 15.8 |
| C one batch of 128 | 2.9 | 45.7 |
| D 4 in flight | 4.1 | 32.2 |
| D 16 in flight | 1.3 | 100.9 |
| D 64 in flight | 1.2 | **111.1** |

On the LAN, pipelining beats batching by 2.4×. With a 262 KB link MTU, each 16 KiB response fits in a single packet, so no Resource transfer is involved. A batch, by contrast, is one large Resource that the Python implementation serializes, advertises and reassembles.

**Public backbone, 4 hops, 16 × 32 KiB** (negotiated link MTU 4.1 KB, so every response is a Resource):

| Pattern | ms/chunk | Mbps |
|---|---|---|
| B request per chunk | 519 | 0.51 |
| C one batch of 16 | **175** | **1.50** |
| D 4 in flight | 385 | 0.68 |
| D 16 in flight | — | — |

- D-16 is inconclusive. The run stalled, and a rerun couldn't establish a Link: the server accepted it, but the proof never got back over the public path. We stopped rather than keep loading community gateways.
- Path quality varies a lot. B took 519 ms/chunk here, against 1841 ms an hour earlier on the same endpoints.

## Conclusions for retifs
1. **Never one round trip per chunk.** The two remedies win in different regimes:
   - **Large-MTU, low-latency links (LAN/TCP):** pipelined small requests, where each response fits in a packet, won (111 vs 46 Mbps).
   - **Small-MTU, high-latency paths (backbone, and LoRa):** batched `/get [cid…]` won (1.50 vs 0.68 Mbps), since every response is a Resource there anyway.
   - So the retifs fetcher should do **both**: several batches in flight, with batch size chosen from the link MTU and RTT. A batch should fill roughly one Resource's worth on small-MTU paths and stay within one packet on large-MTU links.
2. **Keep Links open** per peer and reuse them. Opening a Link costs about one RTT plus processing (12 ms on the LAN, about 0.5 s over the backbone).
3. **Size batches by path:** larger batches on high-RTT paths. Batch size could adapt to the measured RTT, e.g. aiming for a target response size per round trip.
4. The **link MTU** that RNS negotiates per Link matters as much as RTT. The fetcher should read it from the Link and adapt.
5. Python is the bottleneck at LAN speed, which supports implementing retifs in Rust ([ADR-0003](../adr/0003-rust-and-prns.md)).

## Interop note: RPC key for clients in their own config dir
A Python client attached to `prnsd` from its own minimal config directory needs the daemon's `rpc_key` (`full_hash(transport identity private key)`). Without it, shared-instance RPC fails with "digest sent was rejected", and Links fail too, because the client can't get the first-hop timeout. On the testbed container it worked without the key; the reason is still unknown.

## Still to test
- [x] Pipelined requests (N in flight on one Link). Backbone D-16 inconclusive because of the public path.
- [ ] Pipelining plus batching combined (several batches in flight), on a stable high-latency path of our own, not public gateways.
- [ ] LoRa (needs a second RNode).
- [ ] The same patterns with a Rust client on Prns directly.
