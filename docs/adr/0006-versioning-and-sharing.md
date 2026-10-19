# ADR-0006: Every modification is a version; sharing via multi-writer namespaces

- **Status:** accepted
- **Date:** 2026-10-13
- **Irreversible:** yes. This shapes decisions 5 (namespace updates) and 8 (commit format) in [irreversible decisions](../02-irreversible-decisions.md).

## Context
Two questions share one answer, the commit model:
1. **Versioning.** Should every modification be a version, or may the daemon batch and thin history?
2. **Sharing.** How do several people read and write the same data without a server?

The earlier design assumed one writer per namespace and allowed batching and Time Machine-style thinning. Both assumptions would be baked into the commit format if not decided now.

## Principles
Supports 2 (the signed chain of roots is a primitive), 4 (local-first: every write is a local, immediate version), "from trust to crypto" (permissions enforced by every reader's validation, not a server) and 7 (storage nodes stay blind). Violates none.

## Options
1. **Single writer per namespace, batched commits.** Simple, but loses versions, and sharing needs a central writer.
2. **Shared head with locking.** Needs coordination, which is impossible offline.
3. **Per-writer append-only chains, merged by every reader; one commit per modification.**

## Decision
Option 3.

### Versioning
- **Every modification creates a version**, a signed commit:

  | Change | Version boundary |
  |---|---|
  | API call (`set`, `put_block`, `delete`, ...) | each call |
  | `transaction { … }` | the whole transaction |
  | FUSE file write | `close` / `fsync` (one save), not each `write()` |

- **No silent batching.** The daemon never merges separate modifications into one commit.
- **Retention is separate from versioning.** The default is to keep every version forever. A namespace may opt into a thinning policy, which may only drop old *content*; commits themselves are never removed. Shredding ([API §5](../07-api.md#5-records)) remains the only way to make old content unreadable.
- **Cheap by construction.** An attribute change is a small commit plus a few Prolly-tree nodes. A content change stores only changed chunks.
- **Lazy content upload.** Commits and metadata sync promptly. Content of intermediate versions may stay "only here" on the authoring device and upload when bandwidth allows (important on LoRa). Sync ships many commits at once via Prolly diffs.
- **Per-record history** in the API: `versions(id)`, `get_at(id, commit)`, `restore(id, commit)`.

### Multi-writer namespaces
- **Each writer has its own append-only commit chain** in the namespace, with its own sequence number (rollback protection per writer).
- **The namespace state is the merge of all writers' heads**, computed by every reader:
  - Attributes merge automatically (LWW per `(identity, key)`).
  - Concurrent content versions stay multi-valued until a merge commit resolves them.
- **Validate-on-read.** Every write carries its author's signature and capability chain. Each member's daemon validates on merge and ignores invalid writes. There is no central enforcer.
- **Roles are capabilities.** For example, an admin holds `Share` and can grant narrower capabilities, and a member may hold `Write` only on `type = "document"`.

### Sharing
- **A share is a namespace.**
  - **Group namespace:** one group key, wrapped separately for each member (X25519 → HKDF → Token). All members may write within their capabilities.
  - **Share namespace** (filtered, read-only): the owner's daemon maintains a projection of a query (e.g. `album = "Prangli 2026"`) with its own key and index. Only per-block keys are re-wrapped, so no content is copied or re-encrypted. While the capability is valid, the share stays live.
- A filter given together with the full namespace key would be a promise, not crypto. That's why filtered shares get their own namespace and key.
- **Removing a member** rotates the group key and re-wraps it for the remaining members. The removed member keeps what they had, gets nothing new, and their later writes fail validation.
- **Membership changes are commits** and are ordered causally: a write counts if its author's capability was valid in the history that write had seen. The exact rule for writes made concurrently with a removal is an open question.

### Several users on one machine
Each Linux user runs their own `retifsd` (own keys, socket and capabilities). The chunk store may be shared system-wide, since it holds only ciphertext. That gives one blind store with dedup across users.

## Impact on the threat model
See the [threat model](../04-threat-model.md).

- **Malicious co-author:** can write only within their capability. Writes outside it are rejected by every reader. They can't rewrite others' chains, since those are signed and append-only.
- **Removed member:** can't read anything after key rotation. Writes after removal are rejected, except during the race window above.
- **Full history:** more past data stays readable to anyone who ever had the key for it. Shred and key rotation are the tools against that.

## Consequences
- Easier: complete history by default, offline multi-user writing, no server, one model for personal, group and shared data.
- Harder:
  - Storage grows with history (mitigated by dedup and opt-in thinning).
  - Every reader validates capability chains on merge (CPU cost).
  - The removal race needs a careful rule.
  - Decisions 5 and 8 must be specified multi-writer from the start.

## Implementation status (2026-10-19)
- **Every modification is a version, single writer:** each local namespace is its writer's channel ([ADR-0015](0015-signed-channels.md)), created on first write. Every `rec add`, `set` and `rm` writes a namespace snapshot ([ADR-0016](0016-records-and-snapshots.md)) and a signed commit linking the previous one; there is no batching. The snapshot is sorted by record ID and chunked by content, so a change rewrites a chunk or two: in a 41-record namespace, one attribute change stored 3 new chunks (snapshot and commit).
- **History:** `retifs rec history NS ID` walks the commit chain and shows the versions where a record changed; `retifs query NS --at VERSION …` queries the namespace as it was (the same terms, matched in memory against that version's snapshot).
- **Retention:** every version is kept locally; only the latest is placed on other nodes (older ones are unneeded there but stay pinned here).
- **Sharing:** a namespace's channel address shares it read-only; followers get its latest version. Followed namespaces (`ch-…`) are read-only.
- **Not yet:** several writers per namespace (per-writer chains merged by every reader, LWW per author and key, capabilities), transactions over several records, per-record history beyond what local snapshots hold, thinning policies.

