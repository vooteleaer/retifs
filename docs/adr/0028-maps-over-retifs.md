# ADR-0028: Maps over retifs: tiles and address search as public libraries

- **Status:** proposed
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
- **A map is a public library**, published as a channel ([ADR-0016](0016-records-and-snapshots.md)). Its publisher builds it from an OpenStreetMap extract (for example Geofabrik's Estonia), and republishes it when the extract is updated.
- **Tiles:**
  - One record per tile, holding the tile as its content block.
  - Attributes: `path = /tiles/<z>/<x>/<y>.<ext>`, `tile:z`, `tile:x`, `tile:y`.
  - `type`: vector tiles (`application/vnd.mapbox-vector-tile`) are preferred, since they are small, styled on the device and need one set for every zoom. Raster (`image/png`) is allowed.
  - Because tiles are files with paths, the gateway already serves them at `http://<library>.localhost:8740/tiles/{z}/{x}/{y}.pbf`. Any map widget that takes a URL template (libshumate, MapLibre, Leaflet) uses them unchanged.
- **The tileset** is one record: `type = application/x-vnd.retifs.tileset`, with:
  - `name`, `bounds`, `minzoom`, `maxzoom`, `format`;
  - `attribution` ("© OpenStreetMap contributors"), `license` (ODbL), `source` and `source_date`;
  - a style (MapLibre style JSON) as a content block.
- **Address search (a gazetteer):**
  - Records `type = application/x-vnd.retifs.address` for settlements, streets and addresses: `name`, `geo`, `in` (the enclosing place's name, for example "Viimsi vald, Harju maakond"), `kind` (city, village, street, house) and `housenumber` where it has one.
  - Packed into one block per area, so a device fetches the areas it needs and searches them locally, offline.
  - Search happens on the device. The question doesn't leave it.
- **Following lazily:**
  - A device joins a map library lazily, fetching what it reads rather than the whole world.
  - It pins the areas the user marks (home country, a trip) for offline use.
  - Tiles it has read are cached like any other block, and served on to others.
- **The internet services stay only as fallbacks.** OpenStreetMap's tiles and Nominatim (ADR-0027) are used only where no map library covers the area, and only while the user leaves them on. They are to go once map libraries cover what users need.

## Impact on the threat model
- A map library is public: nothing in it is secret.
- Fetching a tile tells the holder it is fetched from which tile is wanted, as OpenStreetMap's servers learn now. Pinning an area or fetching a whole block of tiles reveals less.
- Address search on the device reveals nothing. Fetching a gazetteer area reveals only the area.
- The publisher's identity signs every version, so tiles and addresses can't be altered on the way. A wrong map is the publisher's error, not an attacker's.

## Consequences
- Maps and address search work offline and over Reticulum alone, from any node holding the library.
- Someone has to build and publish map libraries (a tool: OSM extract → tiles and gazetteer → library). One publisher per region is enough, since anyone can follow it.
- Size: a country's vector tiles are tens to a few hundred MB, and its addresses a few tens of MB. That is fine for a PC or a server and too much for a phone's whole-country pin, so pinning is per area.
- Lazy following with partial pinning must work well for libraries of hundreds of thousands of records (a test case for the store and placement).
