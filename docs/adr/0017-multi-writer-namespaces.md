# ADR-0017: Multi-writer namespaces: operation chains, merge and grants

- **Status:** proposed
- **Date:** 2026-10-19
- **Irreversible:** yes. The operations file (decision 8: commit content), the merge rule, and grants (decision 4: capability semantics) are stored and signed. Vectors in `crates/retifs-core/test-vectors/ops-v1.json`, verified with RNS's umsgpack.

## Context
[ADR-0006](0006-versioning-and-sharing.md) decided that several people write the same namespace without a server: each writer has its own append-only chain, and every reader merges the writers' heads. Single-writer namespaces already commit every change ([ADR-0015](0015-signed-channels.md), [ADR-0016](0016-records-and-snapshots.md)), but as whole snapshots, which can't be merged per attribute: a reader can't tell who changed what, or when.

## Principles
Supports "from trust to crypto" (permissions are enforced by every reader's validation), 4 (offline writes, merged later) and 2 (the signed chain is the primitive). Violates none.

## Options
1. **Snapshots per writer, merged by record:** coarse; concurrent edits to different attributes of one record lose one side.
2. **Operations per commit, merged per attribute** (chosen): small commits, a well-understood CRDT (last writer wins per field), and history is the operations themselves.
3. **A shared head with locking:** needs coordination; impossible offline (rejected in ADR-0006).

## Decision

### Commits carry operations
A namespace commit's tree (`root` in the commit, ADR-0015) is an **operations file**, stored as an ordinary file:
```text
ops file = { "ops": [ op, … ], "retifs": "ns-ops/1" }                          canonical msgpack (ADR-0016)
op       = [ "set", id (bin 16), key (str), value ]
         | [ "unset", id, key ]
         | [ "blocks", id, [ [cid, seed, size], … ] ]                           the record's content
         | [ "delete", id ]
         | [ "grant", writer (bin 32, Ed25519), [ right, … ] ]                  rights: "write", "grant"
         | [ "revoke", writer ]
```
One commit is one modification (or one transaction): its operations take effect together.

### Stamps and merge
- Every operation is stamped `(commit time_ms, writer key, index in its commit)`, ordered in that order. A writer's commits have increasing time; a reader ignores commits dated before their predecessor or more than a day ahead of its own clock.
- **Last writer wins per field:** an attribute is the value (or absence, after `unset`) of the operation with the highest stamp for that `(record, key)`; a record's content is the latest `blocks`.
- **Deletion:** a record is visible if its latest `set` or `blocks` is newer than its latest `delete`.
- Every reader replays the operations of all writers' chains it holds and reaches the same state from the same operations, in any order of arrival.

### Who may write (decision 4)
- The namespace's **creator** (whose key gives `ns_id`, ADR-0015) holds `write` and `grant`.
- A `grant` or `revoke` counts only if its writer held `grant` at its stamp; a write counts only if its writer held `write` at its stamp. Membership is replayed in stamp order like everything else.
- Commits and heads keep their format; verification changes: a writer need not be the creator, but its operations count only as far as the grants allow. A follower of a single-writer channel still accepts only the creator.

### Joining and syncing
- A member's daemon makes a writer key for the namespace and shows it; the creator (or anyone holding `grant`) grants it. The member writes its own chain with the namespace's `ns_id`.
- Members follow every writer's chain: `/retifs/head` with `ns_id ‖ writer` (48 bytes) asks for that writer's head; with `ns_id` alone it still means the creator's.
- The writers are known from the grants, so a member learns new writers by merging.

### Left open (known limits)
- **Clocks:** stamps use writers' clocks; a writer with a wrong clock wins or loses conflicts unfairly. Hybrid logical clocks could replace wall time later; the stamp is per commit, so this is contained.
- **Revocation and keys:** the read key is shared; revoking a writer stops its later writes from counting but doesn't rotate the key (ADR-0006's rotation comes later). Writes made concurrently with a revocation count by stamp.
- **Concurrent content:** ADR-0006 wants concurrent content versions kept until a merge commit; here the latest `blocks` wins for now.
- **Filtered capabilities** (e.g. write only `type = document`) and expiry.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- A member can write within its rights; others' chains are signed, so it can't change them. A member with `grant` can admit others.
- A revoked member keeps what it could read and, until key rotation, can still read new versions.
- Clock games: future-dated commits are ignored beyond a day; within that window a member can win conflicts.

## Consequences
- Easier: offline co-editing without a server; tiny commits; history is the list of operations.
- Harder: readers replay all chains (checkpoints later); clocks matter for conflicts; key rotation still to do.

## Implementation status (2026-10-19)
- **Slice 1, format and merge:** `retifs_core::ops` (operations, canonical encoding, `merge`). Vectors `ops-v1.json`: every operations file re-encodes byte for byte with RNS's umsgpack, and an independent Python merge (`verify_ops_rns.py`) gives the same merged snapshot, ignored-operation count and final writer set (8/8). Unit tests: last writer wins per field regardless of arrival order; writes and grants count only with rights at their stamp (before a grant, after a revoke, an ungranted writer, a write-only writer granting); deletes, revival, commits dated before their predecessor or more than a day ahead.
- `retifs_core::channel`: commits and heads must belong to the namespace but may be signed by any writer (`ChannelKey::member` writes under another's `ns_id`); single-writer followers still require the creator. Channel vectors unchanged.
- **Slice 2, local namespaces on operations:** every `rec add/set/rm` commits an operations file to this node's writer chain (`ns:<name>`, separate from snapshot channels such as `channel publish-ns`), and the local view is rebuilt by merging every writer chain held. Namespace identity (creator, read key), member channels and other writers' heads are kept in the store. `rec history` and `query --at` replay the merge up to a version (other writers' operations up to its time). A change now costs two chunks (operations file and commit) regardless of the namespace's size; every operations file stays needed and placed, since together they are the history.
- **Next:** slice 3, join, grant and sync between daemons.

