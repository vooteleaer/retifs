# ADR-0030: Data outlives apps: compatibility rules for every app

- **Status:** proposed
- **Date:** 2026-10-28
- **Irreversible:** no. It's a rule for apps and conventions, but every app and node is to follow it, so it should settle before there are many.

## Context
Records belong to no app (vision 9). One record is read by several apps (a contact by Contacts, Calendar, Photos and the map), on several devices, by other people (shares, public libraries), for longer than any app version lasts. So data constantly meets apps that are older than it, newer than it, or don't know it at all. Some examples:
- a contact written by a newer Contacts app with a field the old one doesn't know;
- a public map in a format this renderer can't draw;
- an announced library of music on a device without a music player;
- a library written by a newer retifs.

What happens then can't be left to each app. The rules have to be the same everywhere.

## Principles
- Data is universal, each app shows its part (vision 9).
- Nothing is lost because an app doesn't understand it.
- An app never misreads: when it can't tell what something means, it treats it as unknown.

## Decision
**Three layers, each with its own version:**
1. **Network formats** (announces, request/response messages) carry `v`. A node that doesn't know a `v` keeps what it heard, shows it as "needs a newer retifs", and never parses it by guessing.
2. **The library format** (channels, commits, records, decision 2) is versioned. A node never joins or writes into a library whose format it can't read; it says so instead. A public library's announce repeats the version (`fmt`, ADR-0029), so this is known before joining.
3. **Conventions** (record types and their attributes) are named by MIME types (ADR-0025) and change as below.

**How a convention changes:**
- **Additively by default:** a type grows by adding attributes. Old records stay valid and old apps keep working.
- **Must-ignore:** an app reading a record ignores attributes it doesn't know.
- **Must-keep:** an app writing a record changes only the keys it means to change, and never rewrites a whole record from its own model. That way a newer app's attributes survive an older app's edit. The local API already works this way: `RecordSet` sets and unsets the keys given. A copy or a share carries every attribute, except what a share is told to leave out (ADR-0021).
- **A breaking change gets a new name:** a different meaning goes under a new attribute name, or under a new type or a MIME parameter (`application/x-vnd.retifs.tileset; schema=…`). An old reader then sees something unknown instead of misreading it. The old form keeps being read, as old type names are now (`libretifs::types::LEGACY`).

**How apps meet data:**
- **Apps say what they handle:** the types they read and the ones they write, known to the system as Haiku's file types and freedesktop's MIME associations are. Then the system knows when nothing on a device opens something, and can later suggest an app (an app store is a public library too, ADR-0029).
- **Unknown is shown, not hidden or dropped:** the generic views (the desktop utility, Find, the file-tree view) show any record's attributes and content. Nothing is deleted, trimmed or left unsynced because no app knows it. A device may hold and pass on what nothing on it opens.
- **Half understood: use what you can and say what you skip.** For example a contact field the app doesn't know is shown as plain text, and a map in a format the renderer can't draw is listed with the reason.
- **Too big or unfit for this device:** it's offered with its size and never fetched in full without asking. Joining is lazy (ADR-0028).

These rules apply everywhere data crosses apps: records, shares, public libraries and their announces (ADR-0029), bridges to other systems, and apps on Linux, Windows, Haiku and later Android.

## Impact on the threat model
Must-keep means a record can carry attributes the editing app never shows. The user doesn't see everything an app passes on. The generic views show all of it, and a share's omit list (ADR-0021) still decides what leaves.

## Consequences
- Apps can be updated at different times on different devices, and other people's apps can work on shared records, without breaking or losing data.
- Each convention ADR (people, events, photos, places, maps) is read as additive. Breaking it needs a new name, which its ADR records.
- Apps need a declaration of the types they handle. The format for that is to be decided (with the per-app capabilities of ADR-0004 or an app manifest).
- Test: an older app editing a record with unknown attributes keeps them (a test per app core).
