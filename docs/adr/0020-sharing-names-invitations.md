# ADR-0020: Sharing, names and invitations

- **Status:** proposed (draft)
- **Date:** 2026-10-20
- **Irreversible:** no. Invitations are a protocol message; the grant they lead to is the existing operation ([ADR-0017](0017-multi-writer-namespaces.md)). The link format (`retifs:`) should stay stable once printed on QR codes.

## Context
Sharing works, but by hand: a namespace address is about 140 characters (`retifs-ch:1:<writer>:<read key>`), a node is a 32-digit hash, and giving someone write access is a round trip. They join and send back their writer key, then the creator grants it. People won't do that for a family calendar or a shared album. They need names they recognise, a way to pass an address without typing it, and a share that takes one step.

## Principles
- Supports "from location to identity" and "from machine to person": you share with *Mom*, not with a hash.
- No global names (non-goal: no global DNS). Names are either self-chosen hints or the user's own names for others (petnames). Zooko's triangle: secure and memorable, not global.
- Crypto: HMAC-SHA256 and random secrets only; the grant is the existing operation.

## Options
1. **Global names** (a registry, or first come first served on announces): memorable and global, but either central or squattable. Rejected.
2. **Self-chosen display names only** (like an LXMF profile name): easy, but anyone can claim any name, so a name can't decide access.
3. **Petnames, with display names as hints** (chosen): the user's own name for each contact is the authority. A display name only suggests one when adding.

## Decision

### Names
- **Display name:** every node may publish a profile (`/retifs/profile`: display name, optionally per namespace). Prns doesn't pass announce app data on, so it's fetched, not announced. Apps always show it with a short fingerprint, and never use it to decide anything.
- **Petnames:** adding someone creates a contact record in the user's own namespace (`type=contact`, `name=Mom`, `retifs:node`, `retifs:writer`, `lxmf`). The record is the address book: "share with Mom" looks it up. It syncs like any record, so every device of the user knows Mom.
- **Fingerprint words:** a key's fingerprint can be shown as a few words from a fixed list (`SHA-256(key)`, 11 bits per word). Both sides compare them when it matters (adding a contact in person, a first grant).

### Links and QR codes
Apps share different things: an album, a photo, a playlist, a calendar, a store. So one link envelope carries many kinds, and every retifs app can tell what a code is, whichever app made it:
```text
retifs:<kind>/<what>[?view=<hint>&name=<label>&…]

kind    what                                      e.g.
node    a node address                            add a contact
ns      a namespace address (read)                a shared calendar, read-only
invite  an invitation (see below)                 join and write
rec     namespace address + record ID             one record, through the namespace
query   namespace address + query terms           an album (album=Prangli), a smart playlist
ch      a channel address                         follow a store or a site
cap     a read-cap (+ attributes)                 one file, nothing else
```
- **`view`** hints which app opens it (`photos`, `music`, `calendar`, `store`). Without one, the record type decides, the way Android routes intents to apps.
- **Unknown kinds and parameters** are shown for what they are (with a generic action: open in the gateway, save the file), never an error. New kinds can be added without breaking printed codes.
- **QR** is the main in-person channel: shown on one screen, scanned by the other. A namespace address or an invitation is a few hundred characters, well within an easily scanned code.
- Over a distance the same link goes in an LXMF message (end-to-end encrypted to the recipient, who is often already an LXMF contact), so sharing reuses Reticulum messaging and needs no new channel.
- **Sharing one record** without the rest of its namespace: a `cap` link (its content and attributes, no access to anything else; can't be revoked) or a small share namespace holding just that record (revocable, updatable). Which one an app offers is open.

### Invitations: one-step sharing
```text
invitation = { "ns": namespace address, "node": creator's node, "secret": 32 random bytes,
               "rights": [...], "limits": { "keys"?, "until"? }, "expires": time }   canonical msgpack, base32 in the link
```
1. The creator's node makes the invitation and keeps `H(secret)` with the rights, limits and expiry, as pending.
2. The invitation travels as a link (QR, LXMF, …).
3. The recipient's node joins the namespace (it can read from then on: the address carries the read key) and asks the creator's node (`/retifs/invite`, over a Link): `H(secret) ‖ writer key ‖ HMAC(secret, link id ‖ writer key)`.
4. The creator's node checks that the invitation is pending, unexpired and the proof good. It then writes the grant (`Op::Grant` or `Op::GrantLimited`) for that writer key and marks the invitation spent. If the creator is offline, the recipient's node asks again on its next sync.

- **One use:** the first redemption spends it. A copy of the QR code redeemed later gets nothing beyond what the address already gives (reading).
- **Bound to the link:** the proof can't be replayed on another link, and it names the writer key, so a relay can't swap in its own.
- **Read-only shares** need no invitation: `retifs:ns/…` is enough.

## Impact on the threat model
- **Anyone who sees an invitation can read the namespace** (it carries the read key, as an address does). Only the write grant is single-use. Show QR codes in person, and treat a leaked one like a leaked address: revoke and rotate.
- **Display names are claims:** a node can call itself anything. Petnames and fingerprint words are what to rely on.
- **A pending invitation** is a standing offer until it expires or is spent. Short expiry by default (e.g. a day).

## Consequences
- Easier: "share with Mom" in one step; QR in person; LXMF at a distance; one address book across devices.
- Harder: the creator's node must be reachable once to redeem a write invitation; contact records need the conventions (with images and audio).

## Open
- The word list for fingerprints (an existing one, e.g. the PGP word list or BIP-39 English, or our own).
- One-record sharing: `cap` links, share namespaces, or both.
- Whether a profile is per node or per person (a person has several nodes; a profile record in their namespace could list them).
