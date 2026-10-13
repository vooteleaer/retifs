# Recon: fetching many small chunks over RNS (phase 0)

How should retifs request chunks: one per request, or batched (`/get [cid1…cidN]`)? Measured with [`recon/chunk_bench.py`](../../recon/chunk_bench.py), a throwaway benchmark using the Python RNS API (Link + request handler; responses larger than the link MDU travel as Resources). Every chunk is verified byte for byte.

Both ends are Python RNS clients attached to `prnsd` 0.3.7 shared instances, so the path is Python → Prns → … → Prns → Python.

## Patterns
- **A**: new Link per chunk
- **B**: one Link, one request per chunk
- **C**: one Link, batched requests (one response carries N chunks)

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

## Conclusions for retifs
1. **Batch requests: `/get [cid…]` with many CIDs per request.** On high-latency paths, round trips dominate everything. The design in [01-architecture](../01-architecture.md) is confirmed.
2. **Keep Links open** per peer and reuse them. Opening a Link costs about one RTT plus processing (12 ms on the LAN, about 0.5 s over the backbone).
3. **Size batches by path:** larger batches on high-RTT paths. Batch size could adapt to the measured RTT, e.g. aiming for a target response size per round trip.
4. **Pipelining** (several requests in flight on one Link) isn't measured yet. It may reach batch-level throughput while keeping per-chunk responses.
5. Python is the bottleneck at LAN speed, which supports implementing retifs in Rust ([ADR-0003](../adr/0003-rust-and-prns.md)).

## Interop note: RPC key for clients in their own config dir
A Python client attached to `prnsd` from its own minimal config directory needs the daemon's `rpc_key` (`full_hash(transport identity private key)`). Without it, shared-instance RPC fails with "digest sent was rejected", and Links fail too, because the client can't get the first-hop timeout. On the testbed container it worked without the key; the reason is still unknown.

## Still to test
- [ ] Pipelined requests (N in flight on one Link).
- [ ] LoRa (needs a second RNode).
- [ ] The same patterns with a Rust client on Prns directly.
