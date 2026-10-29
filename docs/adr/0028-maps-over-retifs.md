# ADR-0028: Maps over retifs: tiles and address search as public libraries

- **Status:** accepted (prototype), 2026-10-29
- **Date:** 2026-10-28
- **Irreversible:** no. Attribute conventions and a dataset layout.

## Context
The map app ([ADR-0027](0027-places.md)) takes its tiles from OpenStreetMap's tile servers and looks addresses up in Nominatim. Both are ordinary internet services. retifs must work without the ordinary internet (vision: the network is a means of syncing, not a prerequisite), over Reticulum alone, offline, and on networks that are only LoRa or a mesh. A map that goes blank and a search that fails there don't meet that.

OpenStreetMap's data is open (ODbL), but its tile servers' usage policy forbids bulk downloading. So the tiles have to be **made from the data**, not copied from the servers.

## Principles
- Local-first and network-independent: what the user needs to see a map and find an address is data in retifs, not a service somewhere else.
- Data, not services: a dataset any node can hold and serve, rather than a server everyone must reach.
- Any node may hold ciphertext and serve it (holders are never restricted).

## Decision
- **A map lives in a public library**, published as a channel ([ADR-0016](0016-records-and-snapshots.md)). Its publisher builds it from an OpenStreetMap extract (for example Geofabrik's Estonia), and republishes it when the extract is updated.
- **Tiles:**
  - One record per tile, holding the tile as its content block.
  - Attributes: `path = /tiles/<z>/<x>/<y>.<ext>`, `tile:z`, `tile:x`, `tile:y`.
  - `type`: vector tiles (`application/vnd.mapbox-vector-tile`) are preferred, since they are small, styled on the device and need one set for every zoom. Raster (`image/png`) is allowed.
  - Because tiles are files with paths, the gateway already serves them at `http://<library>.localhost:8740/tiles/{z}/{x}/{y}.pbf`. Any map widget that takes a URL template (libshumate, MapLibre, Leaflet) uses them unchanged.
- **The tileset** is one record: `type = application/x-vnd.retifs.tileset`, with:
  - `name`, `bounds`, `minzoom`, `maxzoom`, `format`;
  - `attribution` ("© OpenStreetMap contributors"), `license` (ODbL), `source` and `source_date`;
  - a style (MapLibre style JSON) as a content block.
- **A library has no kind** (vision 9): the same library may hold a map, its places, its addresses and anything else (a region's whole package, as OsmAnd's region files are), or only some of them, next to other data. Apps find what they use by type, never by what a library is called or meant for.
- **Many maps, the user's choice:**
  - A map app finds maps in every library the user has joined, by their tileset records. It isn't tied to one map or one publisher.
  - The user adds a map as they add any public library, from its link. Examples are another country, a topographic or nautical map, a cycling map, a historical map, or a community's own map.
  - Maps covering different areas are used side by side, each where it covers. Where several cover the same area, the user picks the base map. Transparent ones (`overlay = true`, for example hiking trails) are drawn on top.
- **Places from public libraries:**
  - Any record with `geo` ([ADR-0027](0027-places.md)) in a joined public library is a place the map can show, for example shelters and campsites, a town's events, or charging points.
  - Each such library is a layer of its own that the user can turn on and off.
  - The user can copy a place into their own library, to keep it or add notes, as with any record.
  - These are ordinary libraries, so the same data serves a map app, a list, or anything else (vision 9).
  - A place library may be searched too: its places carry `find` terms (the beginnings of their name's words, and the whole words of what they are and their address) and its index declares `find`. The map's search then finds "kumu" or "cafe tartu" as it finds addresses. One's own things (photos, contacts, events, saved places) are matched by name on the device, first.
- **Address search (a gazetteer):** address libraries, one per region, built from OpenStreetMap (`osm-addresses.py`).
  - Not a record per house (a country has hundreds of thousands): a record `type = application/x-vnd.retifs.address` per street and per settlement. `kind` (`street`, `settlement`), `name`, `in` (the settlement a street is in), `geo` (the middle of its houses), `count`, and `houses`: each house's number (or, in the countryside, its name) with its coordinates, as `label|lat|lon;…`. A street with more than 300 houses is split into parts (`part`), so a record stays a few KB.
  - `find`: the search terms, a list. The beginnings (from 2 letters) of each word of the name and of the settlement, and the whole words of house names. Words are folded: lower case, no diacritics, letters and digits of any script.
  - The library declares `find` and `type` as its index keys, so a device that holds it lazily searches it through a search node's blind index ([ADR-0019](0019-remote-query-and-blind-index.md)), exact terms only: each typed word is one term (`find="raek"`), all must match, and a word starting with a digit is a house number, looked for in the matching records' `houses` on the device. Holding the library whole, the device searches it locally.
  - The map app searches as the user types, every joined library at once. No internet service is asked, not even as a fallback.
- **Following lazily:**
  - A device joins a map library lazily, fetching what it reads rather than the whole world.
  - It pins the areas the user marks (home country, a trip) for offline use.
  - Tiles it has read are cached like any other block, and served on to others.
- **A map from the start.** The map app comes with the address of a default public map library (the retifs project's, built from OpenStreetMap) and follows it lazily on first start, so there is a map without any setup. It is an ordinary followed library: the user can remove it, or add others next to it.
- **No internet tiles.** Tiles come only from map libraries. Without one, the map is blank, places still show on it, and the app suggests joining a map library.
- **No internet address search.** The opt-in Nominatim search that stood in for the gazetteer is gone.

## Impact on the threat model
- A map library is public: nothing in it is secret.
- Fetching a tile tells the holder it is fetched from which tile is wanted, as OpenStreetMap's servers learn now. Pinning an area or fetching a whole block of tiles reveals less.
- Address search on a device holding the library reveals nothing. Through a search node, the node sees the terms' tokens. An address library is public, so its read key is too: the search node can compute tokens for guessed words and so learn what is searched for. The records fetched afterwards tell their holders the same. A device that wants its searches to itself holds the library whole (a few tens of MB a country).
- The publisher's identity signs every version, so tiles and addresses can't be altered on the way. A wrong map is the publisher's error, not an attacker's.

## Consequences
- Maps and address search work offline and over Reticulum alone, from any node holding the library.
- Someone has to build and publish map libraries (a tool: OSM extract → tiles and gazetteer → library). One publisher per region is enough, since anyone can follow it.
- Size: a country's vector tiles are tens to a few hundred MB, and its addresses a few tens of MB. That is fine for a PC or a server and too much for a phone's whole-country pin, so pinning is per area.
- Lazy following with partial pinning must work well for libraries of hundreds of thousands of records (a test case for the store and placement).
- **The whole world** is the same done per region: a map library and an address library per country or smaller (OpenStreetMap's regional extracts), built by the same tools and announced. A device joins the regions it needs, lazily; the map app draws and searches every joined one. Address formats differ by country (OSM's `addr:*` tagging, scripts), so the builder folds any script and takes what each region tags.

## Review (2026-10-29)
Built: map libraries of vector tiles drawn by the map app, several maps side by side, places from joined libraries as layers (by cell when held lazily, with detail by zoom), the gazetteer and place search through the blind index, no internet tiles or search. Published on the testbed: `eesti-kaart`, `eesti-kohad`, `eesti-aadressid`.

Not built, or done differently:
- **A map from the start:** instead of a built-in address, a map library is joined from the libraries heard on the network ([ADR-0029](0029-announced-public-libraries.md)). A default address may still come with the app once the project publishes one.
- **Pinning an area for offline use** (keep rules by area).
- **Regions beyond Estonia** (the whole world, per region).
