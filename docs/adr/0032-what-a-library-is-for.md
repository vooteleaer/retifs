# ADR-0032: What a library is for: a hint, not a kind

- **Status:** proposed
- **Date:** 2026-11-04
- **Irreversible:** no. One more convention record (like `retifs.placement` and `retifs.calendar`); nothing reads it but the apps that show libraries.

## Context
[ADR-0024](0024-people-and-events.md) says a library has no kind: each app shows the libraries holding records it understands (the contacts app `me` and those with contacts, a calendar those with events or a `retifs.calendar` record). That works for a library with something in it. A new, empty one shows nowhere: on Android, where each library holding contacts is an address book of the system's Contacts, there's no address book to make its first contact in, and a calendar app has the same problem with events (the `retifs.calendar` record was its way out).

The user's choice (2026-11-04): when making a library, say what it's for (contacts, calendar, photos, files, or several); saying nothing makes it a generic one.

## Principles
- Records and libraries, not files and folders: a library is a set of records, whatever they are. A purpose doesn't limit what goes in it.
- One convention for every front end (the utilities, the apps, Android's sync adapters), kept in the library itself, so every member and device sees the same.

## Options
1. **Keep no purpose; show a library once it holds a record of the kind.** The empty library is shown nowhere (the problem above).
2. **A purpose per app** (`retifs.calendar`, `retifs.contacts`, ...). One record type per app, and the utility can't say in one place what a library is for.
3. **One record that says what the library is for, as hints.** Apps show libraries hinted for them as well as those holding their records.

## Decision
Option 3. A library may hold one record `type = retifs.library` with `for`, a list of what it's for:
- `contacts`, `calendar`, `photos`, `files`; other apps may add their own words (a map app `places`). Unknown words are kept, not removed.
- No record, or an empty `for`: a **generic** library.
- It's a hint: an app shows a library hinted for it, or holding records it understands, as before. Nothing refuses a record because of the library's purpose.
- Being `retifs.*`, it isn't a file in the mounts (ADR-0002). It's written like any record, by a member who may write; a reader sees it. Two members making one at once: an app reads the union of their `for`, and the next write keeps one record.
- `retifs.calendar` (ADR-0024) still makes a library a calendar, with its colour.

The utilities ask for it when a library is made (none ticked: generic) and change it from the library's menu; their library list shows it.

## Impact on the threat model
None beyond any record: members already see the library's records; a purpose says no more than its records do. It isn't announced (ADR-0029 says what a public library holds from its records).

## Consequences
- An empty library shows where it's meant to: an Android address book (writable if this device may write the library) or a calendar, ready for its first record.
- One more record in each library made with a purpose.
- The utilities and apps on every platform read it; until one does, it shows a library as before (by its records).
