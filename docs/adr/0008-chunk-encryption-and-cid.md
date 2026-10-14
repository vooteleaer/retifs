# ADR-0008: Chunk encryption, padding and CID format

- **Status:** proposed. This is a draft and needs an external crypto review before any real data is stored with it.
- **Date:** 2026-10-13
- **Irreversible:** yes. It settles decisions 1 (CID format), 3 (deterministic nonces) and 9 (per-chunk encryption, padding) in [irreversible decisions](../02-irreversible-decisions.md).

## Context
Every chunk is encrypted on its own ([ADR-0001](0001-always-encrypted.md)). The architecture names three key schemes: public (convergent, network-wide dedup), restricted (dedup within a publisher's line) and personal (random, no dedup). Deterministic schemes need a nonce that never repeats for different content under the same key ("silent catastrophe", decision 3). Sizes must not leak the content type (padding classes). Storage nodes must verify integrity without keys, and must not learn structure.

Constraint: only RNS primitives (Ed25519, X25519, HKDF-SHA256, HMAC-SHA256, Token = AES-256-CBC + HMAC-SHA256). No new crypto.

## Principles
Supports 1 (always encrypted), 3 (only RNS primitives) and 7 (blind storage nodes). Violates none.

## Options
1. **RNS Token with a random IV**: what RNS does today. Not deterministic, so no dedup at all.
2. **A separate deterministic AEAD (AES-SIV, AES-GCM-SIV):** a new primitive that isn't in RNS.
3. **RNS Token with keys and IV derived from a keyed hash of the content.** This is SIV-style, since the IV comes from the plaintext, and it uses only HMAC-SHA256, HKDF and the Token format.

## Decision
Option 3. Version 1 of the construction:

### Size classes and framing
- The **ciphertext size** is one of `2^k` bytes, `k = 10..18` (1 KiB … 256 KiB). These are also the slab sizes of the local store ([ADR-0007](0007-local-store-layout.md)).
- `frame = u32_be(len(data)) ‖ data ‖ 0x00 … ` with zero fill to `class − 64` bytes, using the smallest class that fits. The maximum data per chunk is 262 076 bytes.
- The Token then adds IV (16), a full PKCS7 block (16, since `class − 64` is a multiple of 16) and the HMAC (32), so `len(ciphertext) = class` exactly.

### Keys and IV
```
seed     = HMAC-SHA256(convergence_secret, frame)                  32 bytes
okm      = HKDF-SHA256(ikm = seed, salt = "retifs/v1/chunk", info = "", L = 80)
sign_key = okm[0:32]     enc_key = okm[32:64]     iv = okm[64:80]
chunk    = iv ‖ AES-256-CBC(enc_key, iv, PKCS7(frame)) ‖ HMAC-SHA256(sign_key, iv ‖ ct)
```
This is exactly an RNS Token with key `okm[0:64]` and a derived IV. RNS's `Token(okm[0:64]).decrypt(chunk)` returns `frame`.

### Convergence secret per scheme
| Scheme | `convergence_secret` | Dedup |
|---|---|---|
| Public | `SHA-256("retifs/v1/public")`, a fixed constant | network-wide |
| Restricted | `HKDF(ikm = publisher_secret, salt = "retifs/v1/restricted", info = u16_be(len(name)) ‖ name ‖ u16_be(len(channel)) ‖ channel, L = 32)` | within one publisher line |
| Personal | 32 random bytes per namespace or file | none, or within the file |

- `publisher_secret` is a separate 256-bit secret, never the RNS identity key.
- **The reader needs only `seed`** (32 bytes) per chunk. The manifest stores `(cid, seed)`, and a read-cap for the content is the manifest's own `(cid, seed)`.

### Chunker (writer policy v1, not format)
FastCDC 2020 with **min 8 KiB, avg 12 KiB, max 16 KiB − 68 bytes**. Every content chunk except a file's last seals into exactly the **16 KiB class**:
- about 10 % padding overhead;
- chunk sizes reveal nothing about content;
- the size suits LoRa.

Chosen on 2026-10-14 from the measurements below. Readers don't depend on it; changing it later only affects dedup with older uploads.

### CID
`cid = 0x01 ‖ SHA-256(chunk)`: 33 bytes, computed over the ciphertext.
- The version byte is there from the start (lesson from IPFS CIDv0→v1).
- **No type byte.** Chunks, manifest nodes, Prolly nodes and commits look the same to storage nodes, so structure doesn't leak.

### Opening
Check that the size is a class, that `SHA-256(chunk)` matches the CID, then the HMAC (constant-time), then decrypt, unpad, and check the length field and zero fill.

## Why the nonce is safe
Key and IV are both derived from `seed`, which is a PRF (HMAC) of the full frame under the secret. Two different frames under the same secret give independent seeds, so a (key, IV) pair never repeats with different plaintext, except with HMAC-collision probability. The same frame under the same secret gives the same ciphertext, which is intended (dedup). Different secrets never produce related keys.

## Impact on the threat model
- **Storage nodes** see only class-sized ciphertext and its CID: no type, no exact size, no structure. They verify integrity without keys.
- **Known leak, accepted for public content:** anyone can compute the public seed for a known file and test whether its chunks exist (confirmation attack). This is already listed in [threat model](../04-threat-model.md) under "Known leaks". Restricted and personal content are immune, since outsiders lack the secret.
- **Equality leak:** within one secret, identical chunks have identical CIDs (dedup), so a holder of many CIDs learns which chunks repeat. This is accepted for restricted content, and avoided for personal content by using a fresh secret.
- **Padding:** size leaks only to the class, i.e. within a factor of 2. Chunk count still leaks the approximate file size.

## Test vectors
`crates/retifs-core/test-vectors/chunk-v1.json` is generated by the Rust implementation. `verify_rns.py` re-implements the construction with RNS's own HKDF, HMAC, AES-256-CBC and PKCS7, checks every field, and decrypts every vector with RNS `Token`.

## Consequences
- Easier: one code path for all schemes. Every chunk is an ordinary RNS Token, so other RNS implementations can open it. The class sizes are the slab sizes.
- Harder:
  - CBC + HMAC costs more than an AEAD and can't be parallelised for encryption.
  - Padding wastes up to half the class for small chunks (the price of not leaking size).
  - The chunker must keep chunks within a class (writer policy above).
- **Measured padding overhead (2026-10-14):** a 3 MB file with the current chunker (FastCDC 4/16/60 KiB) took **4.48 MB** in the slab store, i.e. **49 % overhead**. Chunks just above a power of two land in the next class, and FastCDC spreads sizes across class boundaries.
- **The overhead doesn't shrink for large files.** Chunk size is independent of file size: 1 MB to 1.8 GB files (random, DLLs, zip, mp4) all measured 46–49 %, with about 60 % of chunks landing in the 32 KiB class. Measured with `examples/padding_stats.rs`.
- **Aligning the chunker to one class** (100 MB random data; the dedup column is new data after 10 inserts of 100 B into a 20 MB file):

  | FastCDC min/avg/max | Avg chunk | Padding overhead | Forced cuts at max | New data after edits |
  |---|---|---|---|---|
  | 4 / 16 / 60 KiB (current) | 19.4 KiB | 49.3 % | 0.2 % | 1.50 % |
  | 8 / 10 / 16 KiB−68 | 12.6 KiB | 27.1 % | 19 % | 0.92 % |
  | 8 / 12 / 16 KiB−68 | 14.5 KiB | 10.3 % | 54 % | 1.73 % |
  | 10 / 12 / 16 KiB−68 | 14.8 KiB | 7.9 % | 57 % | — |
  | 12 / 14 / 16 KiB−68 | 15.6 KiB | 2.8 % | 73 % | 2.26 % |
  | 16 / 24 / 32 KiB−68 | 29.0 KiB | 10.3 % | 53 % | 2.90 % |

  FastCDC resynchronises at the next natural cut, so even with many forced cuts, dedup after edits stays close to the current config.

- **Before acceptance:**
  - an external review of the construction and the KDF labels;
  - a decision on whether 1 KiB as the smallest class is right for LoRa;
  - ~~reducing the padding overhead~~: **resolved** by aligning the chunker to the 16 KiB class (8/12/16 KiB−68). Measured 10 % overhead, with 100 % of non-final chunks in the 16 KiB class.
