# Prns: path requests for known routes never settle

> Found 2026-10-15 while testing automatic placement ([ADR-0014](../adr/0014-placement-follows-need.md)). Workaround in `retifs-net` (`PrnsTransport::ensure_path`); posted 2026-10-15 as [KenAKAFrosty/Prns#287](https://github.com/KenAKAFrosty/Prns/issues/287); the text is below.

## Symptom
Between daemons attached to one local `prnsd`, `ensure_path` regularly failed with "no path within 20s", even though the peer was up and had announced. In placement runs, one of three peers was unreachable in almost every run; seeking and lease pulls lost 15–150 s to it.

## Cause
In Prns 0.3.7, `PrnsNodeHandle::request_path` always sends a path request and settles only when an announce for the destination is **accepted** into the route table (`apply_announce_ingest` → `pop_settled_path_request`, `prns-core` `engine/node_ingress/announce_completion.rs`).

When the requester already has a route, the answer to its path request is usually the shared instance's cached copy of the announce it already knows. `determine_acceptance` (`routing/announce/acceptance.rs`) rejects that as `KnownRouteReplay` (or `KnownRouteNoNewerEvidence`), the ingest is `Ignored`, and the pending request is never settled. It times out after `PATH_REQUEST_TIMEOUT_MS` (15 s) unless the destination happens to announce again in that window.

Python RNS doesn't hit this: `Transport.request_path` doesn't settle anything, and callers poll `Transport.has_path()`, which is true at once for a known route.

## Reproduction
`crates/retifs-net/examples/path_replay.rs` (three nodes in one process, all clients of a local `prnsd` 0.3.7 on Windows 11):

| Case | Result |
|---|---|
| A heard the server's announce, then calls `request_path` | `Failed(Timeout)` after 15.0 s |
| B attached after the announce (no route), calls `request_path` | found after 0.0 s |
| A calls `establish_link` over its known route, no path request | link up after 0.00 s |
| A calls `request_path`; the server re-announces 2 s later | found after 2.0 s |

## Workaround (retifs)
`ensure_path` checks the route table first (`NodeIntrospection::route`) and requests a path only when there is none, like `has_path` in Python. If a link over a known route fails, `retifsd` requests a fresh path and retries once. The four-daemon placement test went from one unreachable peer per run to none; placing 2 MB on the nearest nodes took 13.5 s instead of 44.5 s, and a reader's seek plus placement 7 s instead of 56 s.

## Upstream issue (as posted)

**Title:** `request_path` never settles for a destination whose route is already known (0.3.7)

**Summary**
`PrnsNodeHandle::request_path(dest)` settles only when an announce for `dest` is accepted into the route table. If the node already has a route to `dest`, the path response it receives (typically the shared instance's cached copy of the same announce) is rejected by `determine_acceptance` as `KnownRouteReplay`, the ingest is ignored, and the request times out after 15 s, unless `dest` happens to announce again within that window.

**Reproduction** (three nodes in one process, clients of a local `prnsd` 0.3.7, Windows 11): the server announces once; client A hears it (route known), then `request_path` → `Failed(Timeout)` after 15.0 s. Client B attaches afterwards (no route) and gets `found` in 0.0 s from the same shared instance. `establish_link` from A over the known route works immediately. A pending request settles when the server announces again. Source: `crates/retifs-net/examples/path_replay.rs` in https://github.com/vooteleaer/retifs (MIT), `cargo run --release -p retifs-net --example path_replay`.

**Expected**
Either settle at once when a usable route exists (callers in the Python reference check `Transport.has_path()` before requesting), or settle a pending request when a path response for the destination arrives even if the announce itself adds no new route evidence.

**Environment:** personal-rns 0.3.7 (crates.io), prnsd 0.3.7, Windows 11 x64, Rust 1.99.
