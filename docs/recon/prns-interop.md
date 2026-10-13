# Recon: Prns interop (phase 0)

Checks whether [Prns](https://github.com/KenAKAFrosty/Prns) works as retifs's transport ([ADR-0003](../adr/0003-rust-and-prns.md)): wire compatibility with the Python reference RNS, plus Link and Resource transfers, which retifs needs for `/get [cids]`.

## Setup

| Node | Software | Role |
|---|---|---|
| Dev machine (Windows 11) | `prnsd` 0.3.7 as the shared instance; Python RNS 1.4.2 tools attach to it | sender/receiver |
| Testbed server (Linux, Docker) | `prnsd` 0.3.7 (`-hw` image) | sender |

The two are linked by a TCP interface (full mode) over the LAN. Test data was random files of 1 MiB and 64 MiB, verified by SHA-256 after each transfer.

## Results (2026-10-13)

### Shared instance and tooling
| Check | Result |
|---|---|
| Python RNS client attaches to the `prnsd` shared instance | ✅ |
| `rnpath -t` (path table via shared-instance RPC) | ✅ full table, paths of 0–46 hops |
| A Python app (MeshChatX/LXMF) announcing through `prnsd` | ✅ seen at 0 hops via `LocalInterface` |
| Python `rnstatus` | ⚠️ exits 0 with no output. Use `prnsd status` instead; this is a tooling gap, not a wire issue. |

### Prns → Prns over TCP (testbed → dev machine, `prnsd cp`)
| File | Time | Effective | Hash |
|---|---|---|---|
| 1 MiB | 0.62 s | ~13 Mbps (dominated by Link setup) | ✅ |
| 64 MiB | 2.53 s | ~212 Mbps (peak shown: 274 Mbps) | ✅ |

### Python RNS → Prns (Python `rncp` → `prnsd cp` listener, same machine)
| File | Time* | Reported rate | Hash |
|---|---|---|---|
| 1 MiB | 2.14 s | — | ✅ |
| 64 MiB | 5.21 s | ~182 Mbps | ✅ |

\* Includes Python interpreter startup. Both ends attach to the same `prnsd`, so this tests Link and Resource protocol compatibility between the implementations, not a network path.

## Findings
- **The Link and Resource protocols interoperate** between Python RNS and Prns. Prns `cp` is `rncp`-compatible: same options, and it uses `.rncp.*.staging` files.
- **Throughput on TCP is far above what retifs needs** for chunk transfer. The ~0.5 s Link setup dominates small transfers, so retifs should batch many CIDs into one Link (`/get [cid1, cid2, …]`), as planned.
- **Bug: `prnsd cp -l` panics in the testbed container.** The message is `recipe destination is valid and fits the store: ServesEmptyEndpointSet` (`prns-runtime/core/src/runtime/node/assembly.rs:689`). The same 0.3.7 listens fine on Windows, so the cause is likely the `-hw` build or its config. To report upstream.
- **Minor:** an empty `.rncp.*.staging` file is left behind after a transfer.

## Still to test
- [ ] Python → Prns across the network (Python node on a separate machine).
- [ ] Multi-hop: through a Prns transport node.
- [ ] LoRa (Hopspot / RNode): Link setup time and Resource throughput.
- [ ] Ratchets: announce with ratchets, send from the other implementation.
- [ ] Many small Resources (16–32 KiB, the retifs chunk size) on one Link vs one Resource per Link.
