# Upstream issue for Prns: announce app_data

> Posted 2026-10-21 as [KenAKAFrosty/Prns#306](https://github.com/KenAKAFrosty/Prns/issues/306). The text below is what was submitted.

**Title:** Expose announce app_data to applications (AnnounceHeard event and DestinationIdentitySnapshot)

**Summary**
In `personal-rns` 0.3.7 an application can't read the app_data of announces it hears. Prns has it: `AnnounceObservation` carries `app_data` (prns-core, `routing/announce/mod.rs`), and each known destination's app_data is retained in `DestinationIdentity` (like Python RNS's `Identity.recall_app_data`). But both public paths drop it:

- `PrnsEvent::Diagnostic(Diagnostic::AnnounceHeard { destination, hops, source_interface })` is built from the observation in `prns-runtime/src/runtime/event.rs` (around line 258) without `app_data`.
- `DestinationIdentitySnapshot` (from `destination_identity(DestinationIdentityQuery::…)`) has `destination`, `identity` and `public`, but no `app_data`.

**Parity with Python RNS**
The event's own doc comment calls it "RNS 1.4.2's announce-handler `received_announce` callback as data", and in Python that callback is `received_announce(destination_hash, announced_identity, app_data)`; `RNS.Identity.recall_app_data(destination_hash)` returns the last app_data heard for a destination. So this looks like a gap rather than a deliberate difference: the wire format and Prns' internal state already have the data, only the public API leaves it out. (Python handlers can also set an `aspect_filter`; that one is easy to do on the application side.)

**Why it matters**
Many Reticulum applications discover each other through announce app_data: NomadNet node names, LXMF display names and stamp costs, relay-chat hub names. An application built on Prns can announce with app_data (that works) but can't read what others announce, so it can't show a directory of nodes the way Python RNS applications do with an announce handler or `Identity.recall_app_data`.

We're building a distributed data system on Prns (retifs) and want to discover public datasets through ordinary announces (an aspect and a short msgpack app_data), so that every RNS node and tool handles them like any other application's announces.

**Suggested change** (either would do; both would match Python RNS):
1. Add `app_data: Vec<u8>` (owned, at most one announce's worth) to `Diagnostic::AnnounceHeard`, so an announce handler gets it as Python's `received_announce(destination_hash, announced_identity, app_data)` does.
2. Add `app_data: Vec<u8>` to `DestinationIdentitySnapshot`, the equivalent of `Identity.recall_app_data(destination_hash)`.

Happy to send a PR for either if you'd like.

**Versions:** personal-rns 0.3.7 (prns-core, prns-runtime, prns-runtime-tokio 0.3.7).
