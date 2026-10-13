# ADR-0001: Everything is always encrypted

- **Status:** accepted
- **Date:** 2026-10-08
- **Irreversible:** yes

## Context
In a distributed network, chunks can sit in anyone's cache, and read access can't be enforced by policy.

## Decision
There is no unencrypted mode. All chunks, manifests, attributes and indexes are encrypted. "Public" means the key is shared along with the reference (the Tahoe-LAFS read-cap model) or derived from the content (convergent). The CID is computed over the ciphertext.

## Consequences
- One code path, and it's impossible to leave something public by accident.
- Storage nodes are blind, so GC is lease-based, not graph-based.
- Deletion = key destruction.
- Cross-user dedup works only for public content under a convergent key.
- Remote queries work only through exact matches on the blind index.
