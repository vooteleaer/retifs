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
         | [ "grant", writer, [ right, … ], limits ]                           a limited grant (below)
         | [ "revoke", writer ]
         | [ "checkpoint", [cid, seed, size] ]                                   names a checkpoint file (ADR-0018); changes nothing
```
One commit is one modification (or one transaction): its operations take effect together.

### Stamps and merge
- Every operation is stamped `(commit time_ms, writer key, commit seq, index in its commit)`, ordered in that order. (The commit's sequence number orders two commits a writer makes in the same millisecond; the first draft left that to sort stability.) A writer's commits have increasing time; a reader ignores commits dated before their predecessor or more than a day ahead of its own clock.
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
- **Clocks:** stamps use writers' clocks, so a writer with a wrong clock wins or loses conflicts unfairly. The stamp is per commit, so this is contained.
  - Since 2026-10-19 writers use a hybrid logical clock: a commit's time is the later of the wall clock and 1 ms after the newest commit already merged. Readers are unchanged.
  - This matters beyond fairness. Without it, a member whose clock is behind its granter's stamps its first writes before its own grant, and everyone ignores them. The live test that found this had a server clock 21 s ahead of a Raspberry Pi's.
  - A clock far ahead still pulls everyone forward, bounded by the one-day limit.
- **Revocation and keys:** the read key is shared; revoking a writer stops its later writes from counting but doesn't rotate the key (ADR-0006's rotation comes later). Writes made concurrently with a revocation count by stamp.
- **Concurrent content:** ADR-0006 wants concurrent content versions kept until a merge commit; here the latest `blocks` wins for now.
- **Filtering by record content** (e.g. write only `type = document`). The limits below are by attribute key and time only. Content filters would make whether a write counts depend on the record's state at its stamp, so late writes would force rebuilds as late revokes do.

## Impact on the threat model
See the [threat model](../04-threat-model.md).
- A member can write within its rights; others' chains are signed, so it can't change them. A member with `grant` can admit others.
- A revoked member keeps what it could read. The revoke rotates the read key, so versions written after a writer has seen the revoke are unreadable to it.
- Clock games: future-dated commits are ignored beyond a day; within that window a member can win conflicts.

## Consequences
- Easier: offline co-editing without a server; tiny commits; history is the list of operations.
- Harder: readers replay all chains, until they start from a checkpoint ([ADR-0018](0018-state-trees.md)); clocks matter for conflicts (a hybrid logical clock keeps one writer's commits ordered); a revoke has to rotate the read key.

## Implementation status (2026-10-19)
- **Slice 1, format and merge:** `retifs_core::ops` (operations, canonical encoding, `merge`). Vectors `ops-v1.json`: every operations file re-encodes byte for byte with RNS's umsgpack, and an independent Python merge (`verify_ops_rns.py`) gives the same merged snapshot, ignored-operation count and final writer set (8/8). Unit tests: last writer wins per field regardless of arrival order; writes and grants count only with rights at their stamp (before a grant, after a revoke, an ungranted writer, a write-only writer granting); deletes, revival, commits dated before their predecessor or more than a day ahead.
- `retifs_core::channel`: commits and heads must belong to the namespace but may be signed by any writer (`ChannelKey::member` writes under another's `ns_id`); single-writer followers still require the creator. Channel vectors unchanged.
- **Slice 2, local namespaces on operations:** every `rec add/set/rm` commits an operations file to this node's writer chain (`ns:<name>`, separate from snapshot channels such as `channel publish-ns`), and the local view is rebuilt by merging every writer chain held. Namespace identity (creator, read key), member channels and other writers' heads are kept in the store. `rec history` and `query --at` replay the merge up to a version (other writers' operations up to its time). A change now costs two chunks (operations file and commit) regardless of the namespace's size; every operations file stays needed and placed, since together they are the history.
- **Slice 3, join, grant and sync:** `retifs ns address NS` gives the namespace's address; `retifs ns join NAME ADDRESS --from NODE` makes this node a member with a new writer key (writing under the namespace's `ns_id`); `retifs ns grant NS KEY [--grant] [--from NODE]` and `ns revoke` write grant and revoke operations; `retifs ns info NS` shows the merged writers and rights. Every 30 s (and on join or grant) each member asks its peers for every known writer's head (`/retifs/head` with `ns_id ‖ writer`; writers come from the merged grants, the creator and heads already held), fetches missing commits and operations files back to what it has (pinned and served on, so members sync from each other), merges, and seeks record content it doesn't hold.
  - Live, two daemons: B joined A's namespace and was granted; B synced the record, its attributes and its content (hash matched). Concurrent edits of one record (A: `color`, `title`; B a second later: `rating`, `title`) converged to the same state on both: B's later title won and both other fields survived. After A revoked B, B's next write was ignored on both sides, B's own included once it had A's revoke.
- **Key rotation on revoke (2026-10-19):** writers are RNS-style identities (X25519 ‖ Ed25519; the Ed25519 half is the writer key) and announce their public identity with `[identity, pub]` in their first commit (counted only for the signer's own key). `retifs ns revoke` commits `revoke` and `[rekey, epoch, [[writer, wrapped], …]]` together under the old key: a new read key wrapped to every remaining writer with RNS's own `Identity.encrypt` construction (`retifs_core::keywrap`; vectors unwrap with stock RNS `Identity.decrypt`), counted only from a writer holding `grant`. Later commits and heads use the new key. Members unwrap rekeys addressed to them when merging, keep every key (oldest first) and try them newest first.
- **Member nodes (2026-10-23, [ADR-0022](0022-public-namespaces-discovery.md)):** `[node, bin 16]` is the signer's `retifs.node` address, a control operation like `identity`. It counts for the signer only, and a writer's latest one stands. A namespace's first commit carries it next to `identity`; a member writes it once it may write (and again if its node changed). Vectors: `ops-v1.json` has one per chain and `nodes_after`, checked by `verify_ops_rns.py`.
  - **Crossing a rotation:** the rekey sits in the last commit under the old key, and the writer's latest head may already be under the new one. Writers (and members, for heads they fetch) keep each writer's latest head per key; `/retifs/head` with `ns_id ‖ writer ‖ key id` (`SHA-256("retifs/v1/key-id" ‖ key)[0..16]`) returns it, and a member that can't open the latest head asks for the last one under each key it holds, reaches the rekey, and syncs again at once.
  - Live, three daemons: A revoked C, then wrote; B couldn't open A's latest head, fell back to A's last head under the old key (3 commits including the rekey), took the new key and then fetched the newer version. A and B converged (B's post-rotation write reached A); C could read neither A's nor B's new versions and kept the old state.
  - A revoked member still reads everything it had, and the rekey commit itself (learning only that it was revoked).
- **Cost of a write stays flat (2026-10-19):** a write used to walk every writer's whole chain from the store and rewrite the whole view: per write 68 ms at 100 records, 123 ms at 500 (O(history)). The daemon now caches, per namespace, the walked chains (a new walk reads back only to the last cached commit; chains are append-only) and the merged view (only changed records are written). Measured: 60–77 ms per write from the first to the 2 000th record (2 000 writes in 127 s, mostly the CLI call, signing and fsync); a range query over 2 000 records takes 19 ms. The merge itself still replays all operations, in memory.
- **Merge as a CRDT (2026-10-19):** `retifs_core::ops::State` keeps every field with the stamp that set it, and each record's latest write and latest delete; a data operation applies if it is newer, so operations apply one at a time in any order. Control operations (grant, revoke, identity, rekey) form a timeline evaluated as a whole, giving each writer's rights at any stamp. A property test checks the state against the sequential `merge` on 2 000 random cases (three writers, grants and revokes, deletes, same-millisecond commits), applied both in stamp order and shuffled; it found the same-millisecond ambiguity, fixed by putting `seq` in the stamp. The daemon now applies only new commits to the cached state, and rebuilds only when a new commit changes rights or is misdated. History, `--at`, multi-writer convergence and key rotation tests give the same results.
- **Interrupted fetches (2026-10-19)**, found by the overnight soak test with two mounts (cafa-cloud and a Raspberry Pi, about 5 hops apart over public gateways):
  - A chain fetch that timed out part-way left the newest commits held without the older ones. The next walk stopped at the first held commit, so the missing ones were never fetched.
  - The merge then applied the commits after the gap and moved that writer's mark past it, and a checkpoint written then made the loss permanent.
  - Now:
    - A fetch trusts only the head it last fetched completely and walks through other held commits.
    - A local walk that stops at a missing commit isn't cached, and that writer's later commits wait until the gap is filled.
    - A rebuild leaves gapped writers out, and no checkpoint is written while a gap exists.
  - Restarted with the fix on the affected stores, both nodes fetched the missing commits and converged within a minute.
- **Limited grants (2026-10-20; decision 4: narrowing and expiry).**
  - Format: `limits = { "keys": [ key, … ], "until": time_ms }`, either or both. Keys are sorted and unique, and the map is canonical. An unlimited grant keeps the three-element form, so earlier data and vectors are unchanged.
  - A limited writer's data operation counts only if it touches an allowed key and is stamped before `until`. `Set` and `Unset` name the attribute; `@content` allows `blocks`; `@delete` allows `delete`.
  - **Expiry** ends every right of the grant, `grant` included: an expired granter's grants, revokes and rekeys don't count either.
  - **Narrowing:** a grant counts only as far as the granter's own grant reaches. Keys are intersected and the earlier `until` wins, so delegation can't widen access. The creator is never limited.
  - Everything is evaluated at each operation's stamp, so the merge stays order-independent (the property tests include limited grants).
  - Vectors: `ops-v1.json` has a key-limited, expiring grant (14/14, with an independent Python merge that includes narrowing). `prolly-v1.json`'s stamped replay uses the same rules (18/18).
  - Daemon and CLI: `retifs ns grant NS KEY --keys rating,@content --until 2026-12-31` (or `+30d`, or milliseconds), and `ns info` shows each writer's limits.
  - Live, two daemons: B, granted only `rating` for one minute, set `rating` and `title`. Only `rating` counted, on both nodes. After the minute, B's next `rating` was ignored everywhere, and `ns info` marks the grant expired.
- **Filtering grants by record content:** **decided (2026-10-20): no record filters in grants.** A filter on a record's content would depend on the record's state at the time of the write, so an older operation arriving late could change which later writes count. Data operations would no longer apply in any order, and every late arrival would need a rebuild. Contributors who should touch only some records get their own namespace (or a shared one), and queries combine namespaces (`retifs query photos-alice,photos-bob album=Prangli`).
- **Not yet:** keeping concurrent content versions side by side, announcing new writers without a known peer.

