# ADR-0035: Where a library's copies are, said in the library

- **Status:** accepted (prototype), 2026-11-09
- **Date:** 2026-11-09
- **Irreversible:** partly. A record type every daemon reads (`retifs.holders`); no new crypto, no format change in commits, operations or leases.

## Context
A node that writes a file leases copies of it to other nodes (ADR-0011, ADR-0014): it alone knows who holds them, from its own leases. When it reads one of its files and the members are away, it asks those holders. Another member doesn't know them: it seeks content only from the library's members (and the nodes a link or an earlier fetch named). So a photo the Windows node backed up to three holders couldn't be read on the phone while the Windows node was off, though all three holders had every chunk. The user asked (2026-11-09) whether a node that only holds encrypted chunks is used at all.

## Principles
- **Storage nodes are blind:** holders still see only chunks; who holds a library's copies is said inside the library, encrypted, to its members only.
- **Redundant by default:** copies are useful to every member, not only to the node that placed them; that's also what recovery (ADR-0033) needs.
- **No central server:** nothing asks a directory; the library says where its copies are.

## Options
1. **Ask the nearest storage nodes when no member answers.** Simple, but blind asking is slow, and it tells nodes that aren't involved what a member looks for (holder privacy, threat model).
2. **The holders as attributes on each record.** Exact, but every lease change would rewrite records, and the holders are per node, not per file.
3. **One record per writing node per library naming its holders.** Chosen.

## Decision
- Each node that may write to a library keeps one record in it: `type = "retifs.holders"`, `node` (its `retifs.node` address, hex), `holders` (a list of the addresses of the nodes it leased any of the library's files to).
- It's brought up to date every 10 minutes (and a minute after the daemon starts), written only when the set changed.
- A member's node seeking or reading the library's content asks the library's members first, then the holders all members' records name (its own node left out). A holder without the chunk answers "don't have" at once; with it, it serves the chunk to whoever proves the chunk's seed (holder privacy rule 1), which only members can.
- Like every `retifs.*` record, it isn't a file in the file views.

## Impact on the threat model
- Members learn which nodes hold copies of the library: they could already ask those nodes for the chunks; holders learn nothing new.
- A member that isn't trusted to know the holders shouldn't be a member: the record is as visible as the library's records.

## Consequences
- A member reads files placed by a node that's away, from the nodes that hold them.
- Recovery (ADR-0033) finds a lost device's copies by the same records.
- A library with many writers has as many records; they're small (a list of 16-byte addresses each).

## Implementation status (2026-11-09)
- retifsd: `holders_keeper`, `update_holders`, `ns_holders`; reads (`ensure_local`) and keep-driven seeking (`apply_keep`) ask the holders after the members.
