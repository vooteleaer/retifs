# ADR-0003: Rust as the primary language, Prns for transport

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** no

## Context
The format-defining code (chunk encryption, CIDs, canonical serialization, Prolly trees, blind index) is tied to the [irreversible decisions](../02-irreversible-decisions.md). It should be written once, in the language it will live in, and not prototyped in Python and rewritten later with subtle differences. The daemon has to run on Alpine nodes, on Linux clients (Haiku later), and eventually inside the thin client's boot image (phase 5), where a Python runtime is a burden.

The reference RNS is Python. [Prns](https://github.com/KenAKAFrosty/Prns) is a Rust implementation of RNS:
- It's a drop-in `rnsd` replacement (`prnsd`), with interop benchmarks against stock RNS 1.4/1.5 in both directions.
- It implements Identity, Destination, announce, Link, Resource and ratchets, over TCP, serial and LoRa interfaces.
- Its core is `no_std` and licensed Apache-2.0/MIT.
- Its `IdentitySigner` trait exposes operations, not secrets.

## Principles
Supports 3 (only RNS crypto primitives: Prns uses the same primitives, and interop is tested against the reference) and 4 (local-first: one native daemon, no runtime dependencies). Violates none.

## Options
1. **Python throughout** on reference RNS: fastest to prototype, but a rewrite later, and a poor fit for boot images and small nodes.
2. **Rust core + Python daemon** (PyO3): the core is right from day one, but there are two languages and a bridge.
3. **Rust throughout, with Prns for transport.**

## Decision
Option 3.

- All retifs code is Rust: core, daemon, and FUSE/userlandfs frontends ([ADR-0002](0002-os-integration.md)).
- Transport is Prns, used **only through our own thin transport trait** (announce, link, request, resource, signer). This keeps a fork or a swap to another RNS implementation possible.
- Python RNS is kept as a **test oracle**: interop tests and cross-checking test vectors for RNS-compatible pieces (key wrapping, signatures).
- Prototypes are still throwaway; only the language changes.

## Impact on the threat model
- Fewer runtimes in the trusted base.
- Prns becomes part of the trusted code. Its crypto must stay byte-compatible with reference RNS, which the interop tests verify.
- YubiKey integration (phase 3) needs two upstream changes:
  - `IdentitySigner::sign()` must be able to fail (hardware key removed, PIN timeout).
  - X25519 exchange must go through a trait, not raw secrets held in memory.

See the [threat model](../04-threat-model.md).

## Consequences
- Easier: one language, single static binaries (musl), embedded and WASM targets come for free, no rewrite between prototype and implementation.
- Harder: slower early prototyping than Python. Prns has a single dominant maintainer (bus factor). Rust on Haiku is tier 3. That's accepted: Linux is the primary target, and Haiku's Rust support is expected to improve before the Haiku client.
