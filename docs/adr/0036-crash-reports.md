# ADR-0036: Crash and trouble reports in a library

- **Status:** proposed, 2026-11-13
- **Date:** 2026-11-13
- **Irreversible:** no. Reports are ordinary records with a path; one new local API request (`CrashReport`). No new crypto, no format change.

## Context
On 2026-11-12, retifs crashed twice in 30 seconds on a tablet while Music played in the background, and Prns stopped connecting on a phone and a tablet. By the next morning nothing was left to look at. Android's log had rotated, one phone had rebooted, and the adb capture had stopped hours before. A desktop's journal had kept a panic, but only on that machine. The user's devices are many (phones, a tablet, laptops, the NAS, the test nodes), and seeing what happened means reaching each one, often by hand. The user suggested a library that every device logs into (2026-11-13).

## Principles
- **Always encrypted:** the reports are in a library, readable only by its members. Logs carry library and file names. Nothing goes to an outside service.
- **No central server:** each device writes its own reports, and the library carries them to the user's other devices.
- **Records, not files:** each report is a record with attributes (`kind`, `source`, `device`, `node`, `version`, `mtime`), so `retifs query retifs-crashlogs device=tablet kind=panic` finds them. The file view shows them as `/<device>/<time>-<kind>-<source>.txt`.
- **Long work informs:** a node off the network for minutes says so, rather than looking fine.

## Options
1. **Logs stay on each device, fetched on demand** (adb, ssh). This is the way things worked before, and it lost the evidence.
2. **A log server.** Rejected: it's a central server, and logs would leave the user's encryption.
3. **A library that devices write their reports into, once they've joined it.** Chosen.

## Decision
- **Where:** a library named by the node setting `crash_library`, by default `retifs-crashlogs`.
  - A node writes there only once it has joined that library with a write grant. It never makes the library itself. Until then, and while it can't write, its reports wait locally.
  - `crash_library = ""` keeps them local only.
  - Joining the library is the opt-in.
- **What retifsd keeps:** its stdout and stderr go through a pipe. They are passed on as before (the journal, logcat, the console), and the last 400 lines are kept in memory and in `<store>/crash/log`. When that file passes 1 MB, it becomes `log.prev` and a new one starts.
- **What's reported, each as a text file in `<store>/crash/pending/`** (at most 100 waiting):
  - `panic`: from the panic hook, with a backtrace and the last output lines. At most 10 per run.
  - `unclean_stop`: the previous run left `<store>/crash/running` behind. It was killed, ran out of memory, or crashed outside Rust. The report carries the end of its log. A run that panicked and reported that isn't reported again.
  - `no_network`: the Reticulum shared instance has been unreachable for 5 minutes, once per outage.
  - `user`: `retifs report [TEXT]`, with the daemon's last output.
  - From apps, through the local API's `CrashReport { kind, source, text }`. Any app may send one. The daemon adds its own last output.
- **Delivery:** a worker writes each pending report into the library as one record, then removes the file.
  - It runs 30 s after start, every 10 minutes, and when a new report arrives.
  - It keeps each node's newest 50 reports in the library and deletes older ones.
- **Android apps** (Music, Map, Photos, the retifs app) share one `CrashReports.kt`:
  - An uncaught Kotlin exception and a panic in the app's Rust core are written to the app's own files at once, because the process is ending.
  - At the next start, the app reads what Android recorded about its past exits (`ApplicationExitInfo`, Android 11+): native crashes, ANRs with their trace, initialisation failures, and being killed for memory or by a signal while in use (importance perceptible or higher).
  - It then sends everything waiting to retifsd with `CrashReport`.

## Impact on the threat model
- The reports hold the device's name, its node address, library names and record paths from the log. They're encrypted like any library content and readable only by the crash library's members. The user should give that library only to their own devices.
- A malicious local app could fill a node's pending reports. This is bounded: 256 KiB per report, 100 waiting, 50 per node in the library.
- No new network surface: reports travel as library content.

## Consequences
- What went wrong on any device can be read from any other device, after the fact, without adb or ssh.
- Prns's own logs aren't covered. On Android, they're another app's private files. Prns can report the same way later, as a separate change in Prns.
- Every write path is a record write, so a node with a broken store can't report through the library. Its reports stay in `crash/pending/` and its log in `crash/log`, readable on the device.
