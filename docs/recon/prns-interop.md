# Recon: Prns interop (phase 0)

Checks whether [Prns](https://github.com/KenAKAFrosty/Prns) works as retifs's transport ([ADR-0003](../adr/0003-rust-and-prns.md)): wire compatibility with the Python reference RNS, plus Link and Resource transfers, which retifs needs for `/get [cids]`.

## Setup

| Node | Software | Role |
|---|---|---|
| Dev machine (Windows 11) | `prnsd` 0.3.7 as the shared instance; Python RNS 1.4.2 tools attach to it | sender/receiver |
| Testbed server (Linux, Docker) | `prnsd` 0.3.7 (`-hw` image) | sender |
| Raspberry Pi (aarch64, Debian 13) | **Python `rnsd`** 1.5.2 at test time, with public backbone auto-connects; switched to `prnsd` afterwards (see below) | Python reference sender |

The dev machine and the testbed server are linked by a TCP interface (full mode) over the LAN. The Pi reaches them only through public backbone gateways. Test data was random files of 1 MiB and 64 MiB, verified by SHA-256 after each transfer.

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

### Python RNS → Prns across the internet (Raspberry Pi → dev machine)
The Pi and the dev machine have no direct link. Python `rnpath` found the Prns listener **5 hops away via a public backbone gateway** (Australia), so the route crosses third-party transport nodes as well as both implementations.

| File | Rate | Hash |
|---|---|---|
| 1 MiB | ~725 kbps (about 12 s) | ✅ |

Only 1 MiB was sent, so as not to load volunteer-run community nodes with 64 MiB. The sender reports "complete" a moment before the receiver has written and renamed the file, which is expected and not a bug.

### Tooling across implementations
| Tool | Against | Result |
|---|---|---|
| Python `rnstatus` | `prnsd` | ⚠️ no output |
| `prnsd status` | Python `rnsd` | ⚠️ `could not read the reply for shared-instance RPC … unexpected end of file` |

The shared-instance RPC (interface stats) isn't compatible in either direction. Path table queries (`rnpath -t`) do work. Use each implementation's own status tool.

### Switching a Python node to Prns (Raspberry Pi)
The Pi's existing Python RNS config (AutoInterface, BackboneInterface listener, I2PInterface, RNodeInterface on a RAK4631, interface discovery with auto-connect) was used unchanged by `prnsd` 0.3.7:
- `prnsd interfaces validate` accepted the config. The only warnings were ineffective discovery and location settings.
- The same transport identity and storage were reused.
- After starting `prnsd`: **LoRa RNode up and passing traffic**, backbone listener bound, discovered gateways auto-connected again.
- AutoInterface and I2P show **Down** under Prns. Still to investigate.

### Prns ↔ Prns between all three nodes (after the switch)
All three nodes run Prns. The Pi has no direct link to the others, so paths go through public backbone gateways. 1 MiB per transfer.

| From → to | Mode | Path | Time | Hash |
|---|---|---|---|---|
| Testbed → Pi | push | 4 hops | 6.9 s (incl. path discovery) | ✅ |
| Dev machine → Pi | push | 4 hops (via testbed, then backbone) | 5.9 s | ✅ |
| Pi → dev machine | push | 4 hops | 6.5 s | ✅ |
| Pi → testbed | **fetch** (`cp -f` from a `-F -j` listener) | 4 hops | 11.3 s | ✅ |

- Fetch mode is the closer model for retifs `/get`: the holder serves, and the requester pulls. It also works around the container's listen panic.
- Throughput on these paths is about 1–1.3 Mbps, limited by the public gateways' advertised 5 Mbps rate and shared load.
- `prnsd cp -l` works on the Pi (native Linux aarch64), which confirms that the listen panic is specific to the testbed container or its `-hw` build.
- A received file with a duplicate name is saved as `name.1`. An empty `.rncp.*.staging` file is left behind in every case.
- Not yet tested: whether the `-j` jail refuses paths outside the jail (`../`, absolute paths). This is relevant to retifs's own `/get` handler.

## Findings
- **The Link and Resource protocols interoperate** between Python RNS and Prns. Prns `cp` is `rncp`-compatible: same options, and it uses `.rncp.*.staging` files.
- **Mixed multi-hop paths work:** Python sender → third-party transport nodes → Prns receiver over 5 hops, with the Link, Resource and hash all intact.
- **Throughput on TCP is far above what retifs needs** for chunk transfer. The ~0.5 s Link setup dominates small transfers, so retifs should batch many CIDs into one Link (`/get [cid1, cid2, …]`), as planned.
- **Bug: `prnsd cp -l` panics in the testbed container.** The message is `recipe destination is valid and fits the store: ServesEmptyEndpointSet` (`prns-runtime/core/src/runtime/node/assembly.rs:689`). The same 0.3.7 listens fine on Windows, so the cause is likely the `-hw` build or its config. To report upstream.
- **Minor:** an empty `.rncp.*.staging` file is left behind after a transfer.

## Still to test
- [x] Python → Prns across the network (5 hops, public backbone).
- [ ] Multi-hop through a *Prns* transport node (the path above went through Python/third-party nodes).
- [ ] Prns → Python direction across machines.
- [x] Prns ↔ Prns across machines, push and fetch.
- [ ] Fetch jail: refusal of paths outside `-j`.
- [ ] LoRa (Hopspot / RNode): Link setup time and Resource throughput.
- [ ] Ratchets: announce with ratchets, send from the other implementation.
- [x] Many small chunks per Link vs a Link per chunk: see [chunk-fetch](chunk-fetch.md).
- [ ] LoRa: parked until a second RNode is available (the Pi has one).
