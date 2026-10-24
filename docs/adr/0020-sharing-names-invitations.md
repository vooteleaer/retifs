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
retifs:<kind>/<what>[?q=<query>&view=<hint>&name=<label>&…]

kind    what                                      e.g.
node    a node address                            add a contact
ns      a namespace address (read) + query        a calendar; an album (q=album=Prangli); one record (q=@<id>)
invite  an invitation (see below) + query         join and write, opening on a view
ch      a channel address                         follow a store or a site
cap     a read-cap (+ attributes)                 one file, nothing else
```
- **`q`** is a query in the CLI's terms (URL-encoded): what the recipient's app opens on. An album, a playlist, one record and a whole namespace are all a namespace plus a query (or none).
- **A query is a view, not a limit.** The address carries the read key, so whoever has the link can read the whole namespace. Sharing only an album means the album is its own namespace: a share ([ADR-0021](0021-shares.md)). Apps must say so ("this shares your whole Photos library") rather than let a query look like a limit.
- **`view`** hints which app opens it (`photos`, `music`, `calendar`, `store`). Without one, the record type decides, the way Android routes intents to apps.
- **Unknown kinds and parameters** are shown for what they are (with a generic action: open in the gateway, save the file), never an error. New kinds can be added without breaking printed codes.
- **QR** is the main in-person channel: shown on one screen, scanned by the other. A namespace address or an invitation is a few hundred characters, well within an easily scanned code.
- Over a distance the same link goes in an LXMF message (end-to-end encrypted to the recipient, who is often already an LXMF contact), so sharing reuses Reticulum messaging and needs no new channel.
- **Sharing one record** without the rest of its namespace: a `cap` link (its content and attributes, no access to anything else; can't be revoked) or a small share namespace holding just that record (revocable, updatable). Which one an app offers is open.

### Invitations: one-step sharing
```text
invitation = { "ns": namespace address, "node": creator's node, "secret": 32 random bytes,
               "rights": [...], "limits": { "keys"?, "until"? }, "expires": time, "q"?: query }   canonical msgpack, base32 in the link
```
1. The creator's node makes the invitation and keeps `H(secret)` with the rights, limits and expiry, as pending.
2. The invitation travels as a link (QR, LXMF, …).
3. The recipient's node joins the namespace (it can read from then on: the address carries the read key) and asks the creator's node (`/retifs/invite`, over a Link): `H(secret) ‖ writer key ‖ HMAC(secret, link id ‖ writer key)`.
4. The creator's node checks that the invitation is pending, unexpired and the proof good. It then writes the grant (`Op::Grant` or `Op::GrantLimited`) for that writer key and marks the invitation spent. If the creator is offline, the recipient's node asks again on its next sync.

- **One use:** the first redemption spends it. A copy of the QR code redeemed later gets nothing beyond what the address already gives (reading).
- **Bound to the link:** the proof can't be replayed on another link, and it names the writer key, so a relay can't swap in its own.
- **Read-only shares** need no invitation: `retifs:ns/…` is enough.

## Implementation status (2026-10-21)
- **Links:** `libretifs::link` parses and writes the envelope (percent-encoded; unknown kinds and parameters kept). For `ns`, `<what>` is the address without its `retifs-ch:` prefix (`1:<writer>:<read key>`), and **`from`** (repeatable) names nodes to fetch from, since a joining node needs a peer before it has any.
- `retifs ns link NS [--name LABEL] [--q TERMS]` prints a namespace's link (with this node as `from`, and a reminder that the link reads the whole namespace); `retifs open LINK [--as NAME]` joins it under its `name` (made into a local name) and says what `q` opens on; `ns join NAME LINK` takes a link where it took an address. `share create` and Explorer's **Share with retifs…** give the share's link.
- A namespace link is about 200 characters (two 64-digit hex keys, a node, a label): a QR code of version 10 or so.
- **Invitations** (2026-10-21), as decided above, with these details:
  - The encoding is canonical msgpack `{expires, limits {keys?, until?}, node, ns (writer ‖ read key, bin 64), q?, rights, secret}`, base32 (RFC 4648, lowercase, no padding) in `retifs:invite/<base32>?name=<label>`: about 330 characters.
  - `id = SHA-256("retifs/v1/invite" ‖ secret)`. The redemption over a Link to `/retifs/invite` is `id ‖ writer key ‖ node ‖ HMAC-SHA256(secret, link id ‖ writer key ‖ node)`: the member's node is in it too (and in the proof), so the creator knows whom to sync with. The answer is a status byte and a message.
  - The creator spends the invitation before writing the grant (two redemptions at once can't both win) and puts it back if the write fails.
  - The recipient joins first (reading at once), then redeems; if the creator's node can't be reached, it keeps the invitation and tries every 30 s until it expires. After a redemption it syncs once, so the answer already says it may write.
  - Vectors: `test-vectors/invite-v1.json`, verified with Python RNS's umsgpack and HMAC (`verify_invite_rns.py`).
- CLI: `retifs invite create NS [--grant] [--keys K1,K2] [--until DATE] [--expires 1d] [--q TERMS] [--name LABEL]` prints the link; `invite list NS`, `invite cancel NS ID`; `retifs open LINK` accepts it.
- Live (four nodes, 2026-10-21, 14 checks): the first opener writes at once and its writes reach the creator; a second use, an expired and a withdrawn invitation are refused and grant nothing; a key-limited invitation grants limited write; with the creator stopped, the recipient joins, reads, and gets its grant once the creator is back.
- **QR (2026-10-22):** `--qr` on `ns link`, `invite create` and `share create` draws the link as a QR code in the terminal (error correction L, light modules drawn, for dark terminals). An invitation is a version 13 code.
- **Fingerprint words (decided 2026-10-22: BIP-39 English):** consecutive 11-bit groups of SHA-256(key), most significant bit first, as words from the BIP-39 English list (the file, SHA-256 `2f5eed53…dbda`, is in `retifs-core`); six words (66 bits) by default. Vectors: `test-vectors/words-v1.json` (`verify_words.py`).
- **Contacts (decided 2026-10-22: in the user's own namespace `me`):** a contact is a record `type=contact` (now `application/x-person`, [ADR-0025](0025-types-are-mime-types.md)), `name` (the petname), `retifs:node` in `me`, which the user's devices share like any namespace (and which will hold saved queries and other personal settings).
  - `retifs me` shows this node and its words; `retifs me link [--name LABEL] [--qr]` gives a `retifs:node/<node>?name=<label>` link; `retifs open` on one adds the contact (the label as its name, or `--as NAME`) and shows its words to compare with the other side's `retifs me`.
  - `retifs contact add NAME NODE|LINK`, `contact list` (with words), `contact rm NAME`. Adding a known node again renames it; a name already used for another node is refused.
  - A contact's name works where a node goes (`--from Mom`).
  - Live (two nodes, 11 checks).
- **Saved queries (2026-10-23)** live in `me` too: `type=retifs.query`, `name`, `query` (terms as `retifs query` takes them, comma-separated) and `scope`, the namespaces it looks in by their creators' keys (stable, the same on every device whatever each calls them; empty: all). `retifs query NS[,NS]|'*' TERM... --save NAME`, `retifs saved` (list), `saved run NAME [--watch]` (live: runs again when one of its namespaces changes), `saved rm NAME`. They're what the desktop utility's Find saves; being `retifs.*` records without a path, they aren't files in the mounts. Live (two devices, 9 checks): a query saved on one ran on the other through `me`, finding its namespace under another local name and saying which wasn't there.
- Not yet: display names published by nodes (`/retifs/profile`), writer keys in contacts, sending links over LXMF.

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
