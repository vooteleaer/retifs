# Recon: embedding Prns in retifs (phase 1, step 1)

Can retifs use Prns as a Rust library ([ADR-0003](../adr/0003-rust-and-prns.md)) rather than only as a daemon? Checked with [`crates/retifs-net/examples/join_smoke.rs`](../../crates/retifs-net/examples/join_smoke.rs).

## Answer: yes

- **Crate:** `personal-rns = "=0.3.7"` from crates.io, the same release as the `prnsd` on our nodes. It has features `tokio-host`, `tcp` and `shared-instance`, and is licensed MIT OR Apache-2.0.
- **Attach to the running daemon as a client:** `connect_existing_shared_instance(handle, SharedInstanceClientIntent { bus_port: 37428, transport, policy })`. It needs **only the bus port**: no RPC key and no transport identity (unlike the Python client in [chunk-fetch](chunk-fetch.md), which needed `rpc_key` for RPC calls). The transport is TCP on Windows and the abstract Unix socket `rns/default` on Linux.
- **Serve requests:** implement `RequestEndpoint` (an async `handle(context)`). Handlers get `context.state`, i.e. the node's `app_state`, which is where the slab store goes.
- **Large replies:** plain `context.respond(bytes)` switches to a Resource transfer automatically. Replies of 16 / 64 / 256 KiB were all verified.
- **Client side:** `establish_link(dest)` then `request(link, endpoint, data)`, which returns `(response, rtt)`.

## Measured (local, both nodes attached to the same prnsd, release build)

| Step | Time |
|---|---|
| Announce heard via prnsd | immediate (0 hops) |
| Link established | 1.9 ms |
| `get` 1 × 16 KiB | 3.8 ms |
| `get` 4 × 16 KiB | 9.5 ms |
| `get` 16 × 16 KiB (256 KiB) | 40 ms ≈ 52 Mbps |

That's already above the Python client's LAN peak (44–111 Mbps across patterns) through the same daemon kind, before any pipelining.

## Gotchas
- **Use crates.io, not git.** The Prns GitHub repo contains benchmark files with paths longer than the Windows limit, so a cargo git checkout fails on Windows. The local repo HEAD is also ahead of 0.3.7: the recipe gained `remote_control`, and endpoints gained a generic host parameter. Pin `=0.3.7` and follow its own examples.
- **Stack size on Windows.** Prns node futures overflow the default 1 MB main-thread stack. Run the runtime on a thread with a larger stack (64 MB here, plus 16 MB for worker threads). Linux's 8 MB default may be enough, but don't rely on it.
- **0.3.7 has no `respond_resource`.** It isn't needed, since `respond` already handles it. There's also a hidden `respond_open_bytes(File, len)` that streams from an open file, which might let `/get` serve slab slots without copying.

## Next
- `retifs-net`: a transport trait (announce, link, request, serve) with a Prns implementation behind it.
- `retifsd`: serve `/get [cid…]` from the slab store via `app_state`.
- `retifs get`: fetch a `FileRef` with batches in flight, per [chunk-fetch](chunk-fetch.md).
