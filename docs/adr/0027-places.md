# ADR-0027: Places: where a record is

- **Status:** accepted (prototype)
- **Date:** 2026-10-25
- **Irreversible:** no. An attribute convention.

## Context
A map app (its own repository, like the others) shows every record that has a place: photos where they were taken, contacts where they live, events where they happen, later people's positions from LXMF telemetry. It owns none of them (vision 9). Photos already carry `geo` from their EXIF (ADR-0023); contacts and events have a place only as text (`address`, `location`).

## Principles
- Data is universal, each app shows its part: one convention any app reads.
- Local-first and private: an address isn't sent anywhere to be turned into coordinates unless the user says so.

## Decision
- **`geo = [lat, lon]`** (two floats, WGS 84 degrees) on any record: where it is or was. A photo: where it was taken (from EXIF, content-derived). An event: where it happens. Anything else: where it belongs.
- **`geo:<label>`** where a record has several places, matching its labelled addresses: a contact's `geo:home` beside `address:home`, `geo:work` beside `address:work`.
- `alt` (metres) where known.
- **A saved place** is a record of its own: `type = application/x-vnd.retifs.place`, `name`, `geo`, and `address` and `note` where given. It lives in whichever library the user saves it to, and is shared with it like anything else.
- **Coordinates for an address come from the user:** the map app lets them place a contact or an event on the map, and writes `geo`. They may also **look an address up** in OpenStreetMap's Nominatim, but only after turning that on (once per device, asked the first time). Only the typed search text is sent, only when the user presses Enter (no search-as-you-type), at most once a second, with the app named in the User-Agent, as Nominatim's usage policy asks. The search result is only a suggestion: the user picks it, and `geo` is written as for a click.
- **Map tiles** come only from map libraries in retifs, never from the internet ([ADR-0028](0028-maps-over-retifs.md)). Address search is to move there too. The online search above is an opt-in stopgap until it does.
- **Later: positions** reported over LXMF (Sideband's telemetry: place, altitude, speed, bearing, accuracy, time) become records of their own, `type = application/x-vnd.retifs.position` with `person:<contact id>`, `geo`, `at` and the rest, so the map shows where people were and are. That needs an LXMF receiver in Rust first.

## Impact on the threat model
A place says where someone lives or was. It's as private as the library it's in; a share can leave it out (`--omit geo,geo:*`, ADR-0021), and public libraries should. Tiles come from map libraries; the node a tile is fetched from learns which tile is wanted (ADR-0028). An address search tells Nominatim the searched text and the device's IP address, which is why it is off until turned on; a later lookup over Reticulum (a node serving an OSM extract) would keep it inside the network.

## Consequences
- Any app can show where things are; Find can ask `has:geo`.
- Contacts and events get places by hand, or by a search the user turned on.
- Saved places are ordinary records: favourites, a meeting point, a summer house, findable with `type=application/x-vnd.retifs.place`.
