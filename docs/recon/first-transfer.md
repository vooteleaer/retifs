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

## Second round: transport trait, multiple links, multi-source, cache

The fetcher now goes through a `Transport` trait (ADR-0003, client side). It spreads batches over several links (to one or more peers) via a shared work queue, retries missing or failed batches on links not yet tried, reads chunks already held in the local store, and keeps fetched chunks in the store's cache tier. It's covered by tests over an in-memory network: latency, a peer missing half the chunks, a peer failing every request, a peer returning corrupt data, and a warm cache.

**Same machine, 10 MiB, batch 64, 1 in flight per link:**

| Links | Time | Throughput |
|---|---|---|
| 1 | 0.30 s | 280 Mbps |
| 4 | 0.19 s | 438 Mbps |
| 8 | 0.21 s | 393 Mbps |

**LAN, 1 hop, 10 MiB, batch 64:**

| Links | Time | Throughput | Note |
|---|---|---|---|
| 1 | 1.53 s | 55 Mbps | |
| 2 | 1.50 s | 56 Mbps | no gain |
| 4 | 15.2 s | — | one request never settled; retried after the 15 s timeout |
| 8 | 15.2 s | — | same |
| 4 (separate run, `--cache`) | 1.08 s | 78 Mbps | no stall this time |
| 4, warm cache | 0.46 s | — | all 724 chunks from the local store, **0 network bytes** |

Every output was verified by SHA-256.

- Across the real link, throughput stays at about 55 Mbps however many links are used, against ~212 Mbps for one large `prnsd cp` Resource on the same link. The bottleneck isn't link count. Candidates: Resource windowing per ~1 MiB response, or the TCP interface or `prnsd` relaying many medium Resources.
- With 4 or more links, an occasional request never settles. The retry path recovers, but costs the timeout. This isn't isolated yet, and differs from the stall below (one request per link, small request bodies).

## Root cause of the in-flight stall (isolated)
`crates/retifs-net/examples/inflight_stall.rs` reproduces it locally with two nodes attached to `prnsd`. **Concurrent requests on one Prns 0.3.7 Link stall when the request body is larger than the link MDU (~431 B), so the request itself is sent as a Resource.** Only 1 of K requests settles; the rest never do. Response size doesn't matter. Small request bodies (≤ 400 B) pipeline fine, and so do concurrent requests on separate links.

| Request body | 4 concurrent on 1 link |
|---|---|
| 1, 300, 400 B | 4/4 settled |
| 450, 600, 1056 B | 1/4 settled, the rest timed out at 20 s |

A blocking handler (5 or 20 ms) does not trigger it. Consequences for retifs:
- Batches of up to 12 CIDs (396 B) may be pipelined on one link.
- Larger batches use one request in flight per link (the default).

Reported upstream as [KenAKAFrosty/Prns#286](https://github.com/KenAKAFrosty/Prns/issues/286) ([text](prns-issue-286.md)).

## Findings
- **The full stack works end to end** across Windows x86_64, Linux x86_64 (with `prnsd` in Docker over TCP) and Linux aarch64 (Raspberry Pi with native `prnsd` over the abstract socket).
- **Several requests in flight on one Prns Link can stall forever.** With 4 in flight, 3 of 45 batches never settled; 1 in flight always completed. The root cause is isolated in the section above: it's about request size, not responses. `FetchOpts::default()` uses 1 in flight per link plus a 60 s per-request timeout with retry on other links.
- **Bigger batches win everywhere measured.** The default is now 32, and 64 is the protocol maximum (`MAX_BATCH`, up to ~1 MiB per response).
- **Socket naming:** Prns prefixes the abstract socket name with `rns/`, so the transport's `socket_path` is the instance name (`default`), not `rns/default`.
- **Containerised prnsd:** a `prnsd` configured with a TCP shared instance has no abstract socket, so `attach()` tries the abstract socket first and then TCP.
- **Store access:** the slab store's redb index is opened exclusively, so files are imported by `retifsd --put` at startup until the local API ([ADR-0004](../adr/0004-native-record-api.md)) exists.

## Next
- Find the LAN ceiling (~55 Mbps vs ~212 Mbps for `prnsd cp`), e.g. by comparing one large response with many 1 MiB responses on one link.
- Isolate the occasional unsettled request with 4 or more links.
- Follow [Prns#286](https://github.com/KenAKAFrosty/Prns/issues/286) (request-size stall); re-enable pipelining for large batches once fixed.
- Test multi-source on the testbed with two real `retifsd` nodes holding different parts of a file.
