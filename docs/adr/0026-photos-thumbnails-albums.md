# ADR-0026: Photos: thumbnails, albums, favourites, faces

- **Status:** accepted (prototype)
- **Date:** 2026-10-25
- **Irreversible:** no. Attribute conventions on top of the record format; the format itself doesn't change.

## Context
A photo app in the spirit of Immich (its own repository, like the contacts and calendar apps): a timeline of every photo by date, albums, people, favourites, a viewer. Every device shows a grid of thousands of photos, so it needs small images it can get quickly, not the 4 MB originals. And albums are more than a word on a photo: a photo is in several, an album has a name, a cover and a description, and gets shared.

The API draft (§7) gave each content block a role (`original`, `thumb:256`). The record format (decision 2, [ADR-0016](0016-records-and-snapshots.md)) has an ordered list of blocks and no roles, and changing that is a format change.

## Principles
- Data is universal, each app shows its part (vision 9): thumbnails and albums are for any app that shows photos, not one app's cache.
- Records refer to each other by ID ([ADR-0024](0024-people-and-events.md)).
- The format doesn't change for a convention.

## Decision

### Block roles are attributes
- `blocks[0]` is the record's content (the original), as always.
- Other blocks are named by attributes: `block:<role> = <index>` into the list, e.g. `block:thumb = 1`, `block:preview = 2`.
- When the content is replaced, the record's blocks become the new content alone: the role attributes point past the list and mean nothing, and whatever made them makes them again (the extractor's `extracted` marker changes, [ADR-0023](0023-attribute-extraction.md)).
- Writing blocks needs `@content` in an app's key limit (ADR-0023), and storing them first (`Put`) is allowed to such an app.

### Thumbnails
Made by the attribute producer (`retifs-extractd`, ADR-0023) for images:

| Role | Size | Use |
|---|---|---|
| `block:thumb` | longest side 320 px, JPEG | grids, lists |
| `block:preview` | longest side 1600 px, JPEG | the viewer, before (or instead of) the original |

Turned the way the EXIF orientation says, so every app can show them as they are. Each is an encrypted block like any other, synced and placed with the record, so a phone shows a grid without fetching originals. Video frames come later.

### Albums are records
- An album: `type = application/x-vnd.retifs.album`, `name`, `note`, `cover` (a photo's record ID).
- A photo is in an album by reference: `album:<album id> = <album name>` (a hint). In several albums: several keys. Renaming an album touches no photo.
- An album's photos: `has:album:<id>`, in any library. Sharing an album is a share of that query ([ADR-0021](0021-shares.md)), kept up to date as photos are added.
- A plain `album = "Prangli 2026"` (from before) is still shown as an album by name.

### Favourites and people
- `favorite = true` marks a favourite.
- People on a photo: `person:<contact id>` (ADR-0024), tagged in the viewer.

### Faces (later): their own daemon
Face detection is a separate daemon (`retifs-facesd`), apart from the extractor: it carries machine-learning models and wants more CPU or a GPU, so it runs where there's power (a home server), and only if wanted. It's an app with a key limit: it writes face regions and embeddings (`face:*`) and proposals (`person?:<contact id>`), never `person:` itself. The photo app shows proposals; the user's confirmation makes them `person:`.

## Impact on the threat model
Thumbnails are as private as the originals (same library, same keys). An album's share shows only that album's photos. Face embeddings identify people: they stay in the library, encrypted like everything else, and are never sent anywhere to be matched.

## Consequences
- Any app, or Find, can show a photo small without the original.
- Albums can be shared, renamed and given covers without touching their photos.
- The extractor reads whole images to make thumbnails (it read only their heads before); it does so once per content.
