# Upstream issue for Prns

> Posted 2026-10-14 as [KenAKAFrosty/Prns#286](https://github.com/KenAKAFrosty/Prns/issues/286). The text below is what was submitted.

**Title:** Concurrent requests on one Link stall when the request body exceeds the link MDU (0.3.7)

**Summary**
With `personal-rns` 0.3.7, issuing several `PrnsNodeHandle::request` calls concurrently on the same `LinkId` works when each request body fits in a single packet. When the body is larger than the link MDU (about 431 bytes here), so the request itself is sent as a Resource, only one of the concurrent requests settles. The others never complete; we observed no error and no settlement within 20 s. The same requests spread over separate Links all settle. Response size doesn't matter (256 KiB responses work fine when the request bodies are small).

**Reproduction** (two nodes in one process, both attached as shared-instance clients to a local `prnsd` 0.3.7 on Windows 11; the server endpoint responds with 256 KiB):

| Request body | 2 concurrent on 1 link | 4 concurrent on 1 link | 8 concurrent on 1 link | 8 concurrent on 8 links |
|---|---|---|---|---|
| 1 B | 2/2 | 4/4 | 8/8 | 8/8 |
| 400 B | 2/2 | 4/4 | 8/8 | 8/8 |
| 450 B | 1/2 | 1/4 | 1/8 | 8/8 |
| 1056 B | 1/2 | 1/4 | 1/8 | 8/8 |

Source: `crates/retifs-net/examples/inflight_stall.rs` in https://github.com/vooteleaer/retifs (MIT). Run with `cargo run --release -p retifs-net --example inflight_stall 0 1056`. A handler that blocks its thread for 5–20 ms does not change the outcome.

**Expected**
Concurrent requests with Resource-sized bodies on one Link should either queue and settle in turn (as the Python reference allows one outgoing Resource at a time per link, queuing the rest), or fail with an error, rather than never settling.

**Environment:** personal-rns 0.3.7 (crates.io), prnsd 0.3.7, Windows 11 x64, Rust 1.99.
