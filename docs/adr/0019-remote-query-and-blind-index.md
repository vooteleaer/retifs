# ADR-0019: Remote queries and the blind index

- **Status:** proposed (core and vectors done; open points below)
- **Date:** 2026-10-20
- **Irreversible:** partly. Remote queries to one's own nodes are protocol only. The blind index is [irreversible decision 10](../02-irreversible-decisions.md): its key derivation, token and entry formats end up in stored chunks and in capabilities handed to other nodes, Vectors in `crates/retifs-core/test-vectors/index-v1.json`, verified with RNS's HKDF, HMAC, AES and umsgpack (`verify_index_rns.py`).

## Context
Queries run only against a node's own copy of a namespace ([ADR-0016](0016-records-and-snapshots.md), [ADR-0018](0018-state-trees.md)). A device that hasn't synced a namespace (a phone, a thin client, a node behind LoRa) can't ask "photos in album Prangli" without first fetching the whole state.

There are two kinds of node to ask:
- **Own nodes** hold the read key: the home server, the laptop. They can answer any query on plaintext.
- **Nodes without the read key**: a pool or volunteer node, a friend's server holding the namespace's chunks. They are blind by principle 7 and can answer nothing today.

## Principles
- Supports 4 (local-first: a small device can work with a large namespace) and "from hierarchy to queries" (queries reach data that isn't here).
- Principle 7 (storage nodes are blind) is the constraint. A node that answers exact-match queries learns more than one that only holds chunks (see the threat model below). So searching is a **separate capability** a node must be given; plain holders learn nothing new.
- Crypto: HMAC-SHA256, HKDF-SHA256, AES-256 and ADR-0008 sealing only. No new construction.

## Options
1. **Own nodes only.** Remote query over a Link to a node with the read key, the full query language, no format change. Doesn't help with nodes that lack the key.
2. **Blind index (exact match).** Writers publish an index of `HMAC(key, attribute=value)` tokens; a node given the search capability looks tokens up without learning attributes. The classic searchable-encryption trade-off: equality and frequency leak, ranges don't work.
3. **ORAM / PIR.** Hides access patterns too, but costs orders of magnitude more transfer. Wrong for LoRa and for a prototype.
4. **Order-preserving or order-revealing tokens** for range queries: leak the order of all values, which for dates and sizes is most of the information. Rejected.

## Decision
Both 1 and 2, as separate layers.

### 1. Remote queries to own nodes
- The local API's requests also run over an RNS Link ([ADR-0004](0004-native-record-api.md): one protocol, two transports). The caller identifies (`identify`) and must be one of the user's own devices, with an app-style scope (namespaces, read/write) like the app socket.
- Answers are what a local query answers, as of the remote node's state; the answer says which state (frontier time).
- No format change; it can be built and changed freely.

### 2. The blind index
**Keys,** derived from the namespace's read key (rotated with it on revoke, [ADR-0017](0017-multi-writer-namespaces.md)):
```text
token key    = HKDF-SHA256(ikm = read key, salt = "retifs/v1/index-token",  info = "", L = 32)   members only
search secret = HKDF-SHA256(ikm = read key, salt = "retifs/v1/index-search", info = "", L = 32)   given to search nodes
```
The two are separate on purpose: a search node holds the search secret, which opens the index's tree nodes, but **not** the token key, so it can't compute the token for a guessed value (`album=Prangli 2026`) and test it. It only sees tokens that members send.

**Tokens and entries:**
```text
token = HMAC-SHA256(token key, canonical msgpack [key, value])[0..16]
K_t   = HKDF-SHA256(ikm = token key, salt = "retifs/v1/index-entry", info = token, L = 32)
entry = AES-256(K_t, record id)                                    one block, 16 bytes
```
- Values are matched exactly as stored: `Int 5` and `Str "5"` differ, case matters.
- An entry is the record ID under a key bound to the token. The same record under two tokens gives unrelated entries, so a search node can't intersect posting lists or follow one record across attributes; the member intersects after decrypting.
- Entries are deterministic, so every member builds the same index from the same state.

**What is indexed** (decided 2026-10-20): only keys the namespace declares searchable, in an index-settings record (`type = "retifs.index"`, e.g. `keys = ["type", "album", "tags:*"]`) that syncs like any record. Nothing is indexed until a key is declared, so a search node learns frequencies only of what the user chose to make searchable.

**The index** is a Prolly tree ([ADR-0018](0018-state-trees.md)) keyed by `token ‖ entry` (32 bytes) with empty values, sealed under the search secret as a convergence secret. A lookup is a scan of the keys that start with a token. Unchanged parts keep their CIDs across versions.

**Publishing:** the index describes one checkpoint ([ADR-0018](0018-state-trees.md)). Whoever makes a checkpoint also builds its index and publishes `{index root, checkpoint time}` in a signed channel ([ADR-0015](0015-signed-channels.md)) whose commits are sealed under the search secret, so search nodes can follow it without the read key.

**Search capability** = `{namespace, search secret, index channel address}`. Given to a node like a lease: it adds no right to read records.

**Query flow** (`/retifs/query`, exact `=` terms joined by AND):
1. The member computes each term's token and sends the tokens.
2. The search node returns, per token, the entries in its latest index and that index's checkpoint time.
3. The member decrypts the entries, intersects, and reads the matching records from the state tree named in the checkpoint (fetching the few nodes on the path), which also proves each result is real.
4. Everything else in the query language (ranges, prefixes, `NOT`, `HAS`) is filtered on the member after that, or needs an own node (layer 1).

## Impact on the threat model
A search node, beyond what a holder sees:
- **Frequency:** how many records share each (opaque) attribute value; the total number of indexed values.
- **Access pattern:** which tokens are asked, how often, by which link; which tokens' posting lists change between index versions (and so when records gained a value).
- **Not:** attribute names or values, record contents, which entries in different posting lists are the same record, or tokens it wasn't sent.
- **Completeness:** it can drop results. Results it returns are checked against the state tree, so it can't invent them. A member wanting completeness asks several search nodes or syncs.
- **Revoked members** keep the token key of the index they had; the rotation that follows a revoke changes both keys and the index is rebuilt.

## Open points (decide before vectors)
1. **Padding posting lists** (to powers of two, with dummy entries) to blur frequencies: costs size, helps most against small counts.
2. **Who builds the index** in a multi-writer namespace: every checkpoint maker, or one designated device.
3. **Coarse range buckets** declared per key (`modified` by month, `geo` as geohash prefixes up to a precision) as ordinary tokens: exact matches on buckets give range-like queries at the price of leaking the bucket's frequency.

## Implementation status (2026-10-20)
**Layer 1, remote queries to own nodes:**
- `retifs app add NAME --ns NS[,NS] [--write] --device NODE` admits another of the user's nodes (by the address `retifs ping` shows) with the same scope as an app token, and no token.
- `/retifs/api` on `retifs.node` takes msgpack local API requests. The requester must `identify` on the link; its identity hash gives its `retifs.node` address, which must be an admitted device. Requests are checked with the app socket's rules, then answered from a separate task (a request may wait on the network). Over a Link, a range read returns at most 1 MiB and a watch waits at most 45 s.
- The local API gained `Remote { node, req }` (owner only, one hop), and the CLI `--via NODE`: any command runs against the other node, carried by the local daemon, which identifies once per link.
- Live, two daemons on one machine: B queried A's namespace in 17–19 ms per request with nothing synced, read a record's history, and wrote with a read-write scope. A node that wasn't admitted, a removed device, another namespace, writing with a read-only scope and granting were all refused.

**Layer 2, the blind index (core):** `retifs_core::index` derives the keys, computes tokens and entries, builds the index tree and looks tokens up. The Prolly tree takes keys of any fixed length now (state trees keep 16-byte keys; their vectors are byte-identical). A list value is indexed per element. Vectors cover tokens over every value type, a 401-record namespace (416 tree keys, 17 nodes) and lookups.

**Layer 2 in the daemon:**
- A namespace declares searchable keys with a record `type=retifs.index keys=album[,…]`. Nothing is indexed until then.
- Whenever a node's checkpoint changes (and on `retifs ns search NS`, which also prints the capability), it builds the index of the declared keys and publishes a descriptor on the namespace's index channel. The index nodes are pinned and served like any own chunk.
- A search node is given the capability (the index channel's address) and follows it like any channel (`retifs follow CAPABILITY --from NODE`). It fetches the index tree the latest descriptor names and serves it on.
- `/retifs/query` takes `index channel ns_id ‖ proof ‖ tokens` and answers the entries per token, the descriptor's time and its sealed checkpoint reference. A node that holds no such index, or gets a bad proof, gives the same empty answer.
- `retifs query NS KEY=VALUE… --search NODE`: the member sends tokens for the terms on declared keys (all `=` terms if it holds no settings), opens and intersects the entries, then checks every term, the others included, on the records it holds. Matches it doesn't hold are listed by ID.
- Live, three daemons on one machine (60 records, `album` declared): the member found the 6 matching records through the search node in 19–36 ms. Results were exact-match only. A node without the capability, and a query for another namespace, got "no index here". The search node held no records of the namespace, and its logs named no album or title.

**Not yet:** fetching unresolved matches' records from the state the descriptor names (a member that holds no state; tied to fetching part of a namespace, ADR-0018); several builders publishing to one index channel (their sequence numbers can collide); releasing index nodes of replaced versions on the search node; remote live queries beyond `Watch`; a cross-machine measurement over slow links.

## Consequences
- Easier: a phone or LoRa node can query a namespace it doesn't hold; search can be delegated to always-on nodes without giving them the read key.
- Harder: every checkpoint costs an index build; search nodes are a new, weaker kind of blind; one more key pair rotates on revoke.
