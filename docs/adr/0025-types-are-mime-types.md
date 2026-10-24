# ADR-0025: A record's type is a MIME type

- **Status:** accepted (prototype)
- **Date:** 2026-10-24
- **Irreversible:** no. It's a convention ([API §6.3](../07-api.md)), but every app reads it, so it should settle early: now, while the records out there are test records.

## Context
Data in retifs is universal: every app reads the same records, and each shows what it's made to show (a calendar its events, the contacts app its people, Find and the desktop utility everything; [ADR-0024](0024-people-and-events.md)). What a record is says its `type`. Until now that was a short word of our own: `contact`, `event`, `image`, `directory`. Files also had `mime`, their content's type (ADR-0023), so a photo had `type=image` and `mime=image/jpeg`.

BeOS did this with MIME types: every file had `BEOS:TYPE`. A person in People was a file with no content and type `application/x-person`, all of it attributes, and Tracker opened each file in the app registered for its type. Haiku still works that way.

## Principles
- Records, not files; one convention, many apps.
- Works with what exists: Haiku, freedesktop, iCalendar and vCard already name these kinds.

## Decision
`type` is a MIME type.

| Record | `type` |
|---|---|
| a file | its content's type: `image/jpeg`, `application/pdf`, `audio/mpeg` (the extractor sets it when there's none, ADR-0023) |
| a person (contact) | `application/x-person` (Haiku People's) |
| an event | `text/calendar` (iCalendar's media type; the record holds attributes, not iCalendar text) |
| a directory of the file-tree view | `inode/directory` (freedesktop's) |
| an app's own kind | a type of its own, `application/x-vnd.<app>` style, as Haiku names them |
| retifs' own records (saved queries, shares, placement, keep rules) | stay `retifs.*`: they aren't the user's content |

- `mime` stays: it's what the content is, bound to the content and taken from it again when it changes. `type` is what the record is. They're the same for a plain file and differ when a record of one kind carries content of another (a contact's photo, an event's attachment).
- Queries by family work as text: `type^=image/` is every picture, `type^=audio/` every recording.
- An app or the system picks what opens a record by its `type`, as Tracker does; the `view` hint of a link (ADR-0020) stays for links, which name a library, not a record.
- The old names (`contact`, `event`, `directory`) are still read, for the records made before; new records get the MIME type. `libretifs::types` holds the names and the old ones.

## Impact on the threat model
None.

## Consequences
- Haiku's Tracker and People can read retifs contacts as they are, once the Haiku frontend maps `type` to `BEOS:TYPE`.
- Bridges and other systems recognise the kinds without a table of ours.
- Types are longer to type in a query than `type=contact`; Find and apps hide that.
