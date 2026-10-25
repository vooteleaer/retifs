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
- **Coordinates for an address come from the user:** the map app lets them place a contact or an event on the map once, and writes `geo`. Looking an address up in an online service (OpenStreetMap's Nominatim) may come later, only when the user turns it on, since it sends the address out.
- **Map tiles** come from OpenStreetMap and are cached locally. Later they could be shared as a public channel in retifs, so maps work offline and over Reticulum.
- **Later: positions** reported over LXMF (Sideband's telemetry: place, altitude, speed, bearing, accuracy, time) become records of their own, `type = application/x-vnd.retifs.position` with `person:<contact id>`, `geo`, `at` and the rest, so the map shows where people were and are. That needs an LXMF receiver in Rust first.

## Impact on the threat model
A place says where someone lives or was. It's as private as the library it's in; a share can leave it out (`--omit geo,geo:*`, ADR-0021), and public libraries should. Tiles are fetched from OpenStreetMap's servers, which learn which area is being looked at (not what's in it); offline tiles remove that.

## Consequences
- Any app can show where things are; Find can ask `has:geo`.
- Contacts and events get places once, by hand, until a lookup is turned on.
