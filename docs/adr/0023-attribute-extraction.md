# ADR-0023: Attributes from what's in files (`retifs-extractd`)

- **Status:** accepted (prototype)
- **Date:** 2026-10-23
- **Irreversible:** no. The keys are conventions ([API §6.3](../07-api.md)); the record-vs-content binding of decision 7 stays open (below).

## Context
Records and queries are only as good as their attributes. A photo copied in through a mount or Explorer arrives with a `path` and a `size`, and nothing about what it shows, when, or with which camera. On BeOS, files got their attributes as they arrived: the type was sniffed from the bytes, and translators and apps filled in what they knew (`Audio:Artist`, `Media:Width`). Find and Tracker then worked on all of it. retifs should do the same for every file that enters, by any route (CLI, FUSE, Windows Cloud Files, `--via`, apps), and for every suitable format, not just photos.

[API §6.3](../07-api.md) already names the keys (`mime`, `width`, `duration`, `exif.*`, `geo`), and §18 left open where extraction runs and whether it's sandboxed. Parsers of media formats are the classic attack surface, and in a club the files come from other people.

## Principles
- Records and queries, not a file tree: attributes are what makes a library searchable (vision).
- Local-first and end-to-end encrypted: extraction needs plaintext, so it runs on the user's own node, and what it writes is encrypted like any attribute.
- Small trusted core: `retifsd` doesn't parse media.
- No new crypto, no format change.

## Options
1. **In `retifsd`**, on every content write. One place sees everything, but every parser runs inside the process that holds all the keys.
2. **A separate daemon on the local API**, an app like any other, that watches libraries for new content. Parsers are outside the daemon; it needs nothing new from the API.
3. **Each app extracts** what it imports. Files entering through a mount or Explorer get nothing, and every app repeats the work.

## Decision
Option 2: `retifs-extractd` (crate `retifs-extract`), the attribute producer for files entering retifs.

- **How it finds work.** For each library it may see (all but `me`), it compares the change count (`Watch` with no wait) with the last one it saw, and on a change looks at the records with content (`has:size`). A record is done when its `extracted` attribute equals a short hash of its content's read-cap (the cap itself is a key and stays out of attributes). New content has a new cap, so it's described again.
- **What it reads.** Content comes through `ReadRange` a piece at a time (256 KiB), as the extractors ask for it: the head of a file to tell its type, a photo's EXIF block, a zip's directory and one part of it, an MP4's boxes. A lazy library fetches only those pieces. Content that can't be reached (not here, holders offline) is left for a later look, not marked.
- **What it writes.** Only what changed, with `RecordSet`, in one commit per record. Keys an earlier content had and the new one hasn't are unset. `type` is set only when the record has none: to the content's MIME type ([ADR-0025](0025-types-are-mime-types.md)). Other keys, such as `album`, `path` and `name`, aren't touched.
- **Formats** (built in, Rust):

  | Kind | Formats | Keys |
  |---|---|---|
  | all | by magic bytes; text by name (md, csv, json, code, …) | `mime`, and `type` when the record has none (the same MIME type, ADR-0025) |
  | image | JPEG, PNG, GIF, WebP, HEIF/AVIF, TIFF, … | `width`, `height`, `taken` (ISO 8601, local time as recorded), `camera` (make and model), `geo` ([lat, lon]), `exif.lens`, `exif.exposure`, `exif.fnumber`, `exif.iso`, `exif.focal`, `exif.orientation`, `exif.software` |
  | audio | MP3, FLAC, Ogg, Opus, M4A, WAV, AIFF, … | `duration` (s), `audio.title`, `audio.artist`, `audio.album`, `audio.track`, `audio.year`, `audio.genre` |
  | video | MP4/MOV | `duration` (s) |
  | document | PDF, Office Open XML, OpenDocument, EPUB | `doc.title`, `doc.author`, `doc.pages` |
  | text | Markdown | `doc.title` (the first `# ` heading) |

  `audio.album` is not `album`: `album` is the user's own grouping (a photo album), and the recording's album is a fact of the file. Haiku's `Audio:Artist`, `Media:Width` and so on map one to one when the Haiku frontend comes.
- **One node is enough.** Any node of the user's with the library can run it, typically the always-on one. With `--via NODE` it describes another node's libraries, reading only the parts of files it needs over the network (tested 2026-10-23: 207 photos copied into a mount on Windows and stored on another node, all described within a couple of minutes; 168 with `geo`, 185 with `camera`). The attributes reach the others as they sync, so phones don't parse anything. Two running at once write the same values; nothing breaks.
- **Its permissions: an app with a key limit.** It runs with a token: `retifs app add extract --ns photos,notes --write --keys mime,width,height,taken,camera,geo,duration,exif.*,audio.*,doc.*,type,extracted`. The new `--keys` limits an app's writes to those attribute keys (`prefix*` for a family; `@content`, `@delete` and `@create` name content, deleting and new records). It's checked on the local API, for every set, unset, content write and transaction step. It's a local limit, not a grant: an app's writes are signed with its node's writer key ([ADR-0004](0004-native-record-api.md)), so in the namespace's history extracted values look like that node's own. Without a token it runs as the owner and sees every library.
- **Sandboxing.** The parsers run in their own process, which holds no keys and can only reach the local API with its token. On Linux its systemd unit takes the network and most of the file system away. Later, extractors in other languages (BeOS's translators) can be separate executables that read bytes on stdin and write attributes on stdout, under the same daemon.
- **Decision 7 (record vs content binding) stays open.** As [ADR-0016](0016-records-and-snapshots.md) says, every attribute binds to the record for now. The `extracted` marker gives the behaviour content binding is meant to give: when content changes, its derived attributes are taken from the new content, and the user's own attributes stay.

## Impact on the threat model
- A malicious file (from a club member, or a download) can target a parser. It runs outside `retifsd`, as an app limited to some libraries and some keys. The worst a compromised extractor can do is read those libraries' content and write wrong values to the extracted keys there. It can't touch grants, other keys or other libraries, or delete anything.
- Attributes can reveal more than people expect. A photo's `geo` and `camera` are now attributes that anyone who can read the library sees. A share can leave them out (`--omit geo,exif.*`, [ADR-0021](0021-shares.md)), and public libraries should. The desktop utility should say so when sharing.

## Consequences
- Files that come in through any route become findable by what they are: `has:camera`, `type=audio audio.artist=Bach`, `doc.author=…`.
- `retifsd` stays free of media parsers, and the extractor can be updated, sandboxed or switched off on its own.
- The key limit on apps is useful beyond this: a tagging app that may only write `tags:*`, a rating app only `com.example.rating`.
- Extracted values are written as the node's writer, not a distinct "extractor" identity. Telling them apart in history needs the marker and the key family, not the signature.
- Tested 2026-10-23 on Windows with the user's own files (copied into a test store; the originals were only read): four phone photos with EXIF (`camera` "Xiaomi M2101K6G", `taken`, exposure, ISO), three screenshots, an MP4, a Markdown note and a PDF. 15 checks:
  - the key limit refuses a narrower app;
  - a second run writes nothing;
  - new content is described again, and what it lacks is unset;
  - `album` and `type` set by the user stay.
