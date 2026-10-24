# ADR-0024: People and events (contacts and calendars)

- **Status:** accepted (prototype)
- **Date:** 2026-10-24
- **Irreversible:** no. These are attribute conventions ([API §6.3](../07-api.md)). Apps and bridges read them, so changes need care, but nothing in the formats depends on them.

## Context
The first user apps are a contacts app and a calendar (separate repositories, like the desktop utility). Others will read the same records: the desktop utility's Find, a CardDAV/CalDAV bridge for existing apps (Thunderbird, DAVx5, phones), Haiku's Tracker. So the records need one convention, written down here rather than in either app.

Contacts already exist: [ADR-0020](0020-sharing-names-invitations.md) keeps the people a user knows as `type=contact` records in their own namespace `me` (`name`, `retifs:node`, `retifs:writer`, `lxmf`), so "share with Mom" finds Mom. The address book is those records, with more about each person.

## Principles
- Records, not files: a person or an event is a record with attributes, findable by any of them, synced and versioned like any other.
- Local-first and encrypted: an address book or a calendar is a library like any other. A shared one is a club's library (a family calendar), with members, invitations and read-only members as usual.
- One convention, many apps: whatever writes a contact, any app reads it.

## Decision

### People: `type=contact`
In `me` (the user's own address book) or in any library (a club's shared one).

| Key | Value | vCard |
|---|---|---|
| `name` | Str: how the user calls them (the petname, ADR-0020) | `FN` |
| `given`, `family` | Str | `N` |
| `org`, `role` | Str | `ORG`, `TITLE` |
| `email`, `email:<label>` | Str: the main address, and labelled others (`email:work`, `email:home`) | `EMAIL;TYPE=` |
| `phone`, `phone:<label>` | Str (`phone:mobile`, `phone:work`) | `TEL;TYPE=` |
| `address`, `address:<label>` | Str: one postal address, lines separated by `\n` | `ADR` (as label) |
| `birthday` | Str: `YYYY-MM-DD`, or `--MM-DD` without the year | `BDAY` |
| `url` | Str | `URL` |
| `photo` | Str: a photo record's ID (references below) | `PHOTO` (by value, for a bridge) |
| `note` | Str | `NOTE` |
| `retifs:node`, `retifs:writer`, `lxmf` | as in ADR-0020 | (`X-`) |

A profile picture is a reference to a photo record (`photo`, below). Labels are lowercase words. The qualifier form (`key:label`, as `tags:<tag>`, §6.3) keeps every value its own attribute, so `has:phone:mobile` and `email:work=…` work in queries and in Find.

### Events: `type=event`
In any library: each library holding events is a calendar (`Family`, `Work`, a club's).

| Key | Value | iCalendar |
|---|---|---|
| `title` | Str | `SUMMARY` |
| `start` | Str: `YYYY-MM-DDTHH:MM` (local time), or `YYYY-MM-DD` for an all-day event | `DTSTART` |
| `end` | Str, same form; exclusive for all-day events (a one-day event ends the next day); absent: an hour, or one day | `DTEND` |
| `tz` | Str: an IANA zone (`Europe/Tallinn`); absent: floating (the same local time anywhere) | `TZID` |
| `location`, `note` | Str | `LOCATION`, `DESCRIPTION` |
| `rrule` | Str: an RFC 5545 rule (`FREQ=WEEKLY;BYDAY=MO`) | `RRULE` |
| `attendee:<contact id>` | Str: their name, a hint (references below); `attendee:<label>` with an address for someone not in contacts | `ATTENDEE` |
| `uid` | Str: an iCalendar UID, kept for bridges | `UID` |

Times are strings in ISO 8601 order so they sort and compare as text: `start^=2026-10` finds October, `start>=2026-10-24` everything from that day.

### References between records
Records point at each other by record ID: IDs are 128 random bits, unique across libraries, so a reference needs no namespace and finds the record wherever the reader has it. The key names the role, qualified by the ID; the value is a readable hint (a name), never needed to follow it.

| On | Key | Means |
|---|---|---|
| a photo (or any record) | `person:<contact id>` | this person is in it (tagged by hand, or proposed by face detection and confirmed) |
| an event | `attendee:<contact id>` | this person is at it |
| a contact | `photo` = `<photo record id>` | their profile picture is that photo (its content, not a copy) |

So "photos of Mom" is `has:person:<id>` in any library, in Find and in any app; the contacts app lists a person's photos and events, and offers any of those photos as their picture; the calendar shows attendees as contacts. A reference to a record the reader can't see (another club's) just doesn't resolve: the hint is all they get, so a hint carries no more than the referring record's members should see.

### Birthdays
A calendar shows the birthdays of the contacts it can see (`type=contact has:birthday` in `me` and the libraries it shows) as all-day yearly events, without copying them into event records. The contact stays the one place a birthday is kept.

### Settings
A library's display settings for a calendar (`color`) are a record `type=retifs.calendar` in it, shared by its members like `retifs.placement` (ADR-0014). Being `retifs.*`, it isn't a file in the mounts.

## Impact on the threat model
Nothing new: an address book or a calendar is as private as the library it's in. A shared calendar shows its events to its members, attendees included, so a private event belongs in a private library.

## Consequences
- Contacts made for sharing (ADR-0020) and contacts in the address book are the same records: adding a phone number to "Mom" adds it where "share with Mom" looks.
- A CardDAV/CalDAV bridge can map these both ways; the keys follow vCard and iCalendar closely.
- Recurrence follows RFC 5545 rules; the prototype calendar shows weekly, monthly and yearly ones.
