# ADR-0029: Announced public libraries

- **Status:** proposed
- **Date:** 2026-10-28
- **Irreversible:** no while proposed. Once nodes and apps rely on it, the announce's app data is a network format: versioned (`v`), and changes need a new version.

## Context
A public library (a map, a country's places, a site, later an app store) is published as a channel ([ADR-0015](0015-signed-channels.md), [ADR-0016](0016-records-and-snapshots.md)). To join one now, someone has to pass its link along. Reticulum apps solve finding things differently: nodes **announce** what they offer, and apps show what they have heard. Sideband and MeshChat have an "Announces" view, and NomadNet lists the nodes it heard. Maps over retifs ([ADR-0028](0028-maps-over-retifs.md)) need the same thing, so that a map for an area can be found without the internet or a directory server.

## Principles
- No central directory: what's on offer is heard on the network, as Reticulum does it.
- Only public things are announced. A private library is never announced.
- The user decides what to join; an announce is a suggestion, not a subscription.

## Decision
- **Announcing is the publisher's choice, per library:** `retifs channel announce NAME on|off`, and a switch in the apps beside a public library. Off by default.
- **A Reticulum destination per announced library**, aspect `retifs.library`, announced by the node that publishes it, at the node's announce interval and when the library gets a new version.
- **App data** (the same compact map as the node announce, ADR-0014):
  - `v` = 1;
  - `name` (≤ 32 bytes) and `about` (≤ 80 bytes), as the publisher wrote them;
  - `ch` (64 bytes): the channel's writer key and read key, so the library can be followed directly. It's public: the read key of a public library is meant to be known;
  - `has`: what it holds, as the MIME types of its records with a count each, e.g. tileset 1, `application/x-vnd.retifs.place` 38822. Apps use this to show only what they can use (vision 9);
  - `bounds` (optional): west, south, east, north, for libraries tied to an area (maps, places);
  - `seq`: the channel's latest version, so a listener can see it's alive and current.
  - `fmt`: the library's format version (channel and records), so a node knows before joining whether it can read it.
  - The whole app data stays under about 300 bytes, inside one announce.
- **Listening:** every node keeps the library announces it hears (latest per destination, with the time heard and hop count), and answers `retifs heard` / the local API `HeardLibraries`.
- **In the apps, an "Announces" view as in LXMF apps:** public libraries heard, newest first, with name, about, what they hold, hops and when. Each has a **Join** button (follows the channel lazily, ADR-0028). Each app shows the ones it can use: the map app the ones with tilesets or places in view, the desktop utility all of them.
- **When it isn't compatible**, the general rules of [ADR-0030](0030-data-outlives-apps.md) apply: nothing breaks, and nothing is joined that can't be used. For announced libraries they mean:
  1. **A newer announce** (`v` this node doesn't know): kept and listed as "needs a newer retifs", with only the fields it can read. Never parsed by guessing.
  2. **A newer library format** (the channel and record formats, decision 2, carry their version; the announce repeats it as `fmt`): listed, but **Join** is off with "needs a newer retifs". Following it would fetch data the node can't read.
  3. **Content no app here understands** (types in `has` that no installed app shows, say a music library on a device with only the map): each app lists only what it can use (vision 9). The desktop utility lists everything and says which of it nothing here opens. It can still be joined, to hold and pass on.
  4. **Content an app half understands** (a map whose `format` or style the renderer can't draw, e.g. raster-only, or a style schema it doesn't know): the tileset record says what it is (`format`, `schema`, ADR-0028). The map app offers only maps it can draw, and says why it skips another ("this map needs raster support").
  5. **Wrong for this device** (too big for the free space, or outside any area the user looks at): offered with its size, never joined without asking. Joining is lazy anyway (ADR-0028).
- **The map app** can offer a heard map for the area on screen when it has none ("Eesti map heard from 2 nodes. Add?").

## Impact on the threat model
- **Anyone can announce anything:** a name and description are claims. The channel signature makes the content the writer's, but not the writer who they say they are. Apps show the announcing node and the writer key, and a library joined once is recognised by its writer key afterwards.
- **Spam and flooding** are limited as Reticulum limits announces (rate limits per interface). A node keeps a bounded number of heard libraries and drops the oldest.
- **Privacy:** announcing tells the network that this node publishes this library. Following one reveals nothing to the announcer: the data comes from whichever holder is nearest.

## Consequences
- Maps, places and other public data can be found without passing links and without the internet.
- A new node format to implement in retifsd, plus the "Announces" view in the desktop utility and the map app.
- Test vectors for the app data once accepted.
