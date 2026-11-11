# ADR-0033: Recovery: a key kept offline, and a keyring

- **Status:** accepted as the direction (owner, 2026-11-11; nothing built). The words and derivation are irreversible: vectors and the external review before the first kit.
- **Date:** 2026-11-09
- **Irreversible:** yes. The derivation of the recovery identity from its words, the words themselves (printed on paper), and the keyring's records and address derivation. Needs test vectors verified with RNS before anyone writes a recovery kit down.

## Context
The user asked (2026-11-09): what happens when one of my devices is destroyed, and how do I get my data back?

- **One device lost:** the others still hold every library's address and their own writer keys, and the content is kept by them and by holders (ADR-0011, ADR-0014). The lost device is revoked on another (`ns revoke`, which rotates the read key, ADR-0017), and a new one joins by invitation (ADR-0020). This works today.
- **The only device holding `grant` lost:** nobody can admit or revoke anyone in that library again. Its other members still read and write. On 2026-11-09 most of the user's libraries had exactly one grant holder (`photos`: the Windows node only; `pere üritused`, `eesti-*`, `cafa-tech`, `testing-stuff`: one node each); only `retifs-installers` had three.
- **Every device holding the keys lost** (a fire, a theft of everything at home): holders keep only ciphertext and no keys, by design (ADR-0001). The data is gone.

The [threat model](../04-threat-model.md) already speaks of a device key "revoked by the root", but there is no root and no recovery. This ADR proposes one.

## Principles
- **No central server:** recovery doesn't depend on any service being there, ours or anyone's. Nothing is escrowed.
- **Always encrypted:** holders still see only ciphertext; the recovery key is one more member, not a back door.
- **Only RNS primitives:** an RNS identity (X25519 and Ed25519), HKDF-SHA256, Token. No password hashing: a recovery key is random, never a passphrase.
- **From location to identity:** what's recovered is the user's set of libraries, wherever they are kept.
- **Offline works:** a recovery kit is paper (or a YubiKey), and recovery needs only one reachable node that keeps the keyring.

## Options
1. **Nothing new; grant a second device everywhere.** It covers losing one device and costs nothing, but not losing all of them. Do it anyway (below).
2. **A recovery identity on paper, a member of every library, and a keyring.** Chosen (proposed).
3. **Escrow the keys with a friend's node, encrypted to them.** That's option 2 with the paper given to someone, and it trusts their node to stay. A later variation (k of n, below).
4. **Derive every key from one seed** (a wallet's HD scheme). Libraries made by others, and keys rotated on revoke, can't be derived. Rejected.

## Decision (proposed)
**A recovery kit is one RNS identity kept offline. It's a writer with `write` and `grant` in every library of the user's, and it reads the keyring: a library listing every other library's address.**

### The recovery identity
- 32 random bytes, the seed, shown once as **24 words** from the same BIP-39 English list as the fingerprint words (decision 13). The words carry a checksum (BIP-39's), so a mistyped word is caught.
- The identity is derived: `x25519_private = HKDF-SHA256(ikm = seed, salt = "retifs/v1/recovery", info = "x25519")[0..32]`, `ed25519_seed = HKDF-SHA256(ikm = seed, salt = "retifs/v1/recovery", info = "ed25519")[0..32]`, the same `X25519 ‖ Ed25519` identity as every writer (ADR-0017).
- **Decided (2026-11-11):** the 24 words are always there; the same identity may also be put on a YubiKey (the two keys derived from the words, imported into the card's OpenPGP slots: signature Ed25519, decryption X25519; [recon](../recon/yubikey.md)). Not a YubiKey alone: a lost key would lose the recovery.

### A member of every library
- When the user makes a recovery kit, each of the user's devices that holds `grant` grants the recovery identity `write` and `grant` in each library it may (an ordinary grant, ADR-0017). A new library made afterwards grants it at once. Libraries where no device of the user's holds `grant` are listed as not recoverable.
- Being a writer, it's sent every rekey (a revoke wraps the new read key to each remaining writer), so it keeps reading after revocations, without being online.
- It never writes in normal use. It's online only during a recovery.

### The keyring
- A library whose creator key is the recovery identity's Ed25519 key, so its `ns_id` (ADR-0015) follows from the words. Its first read key is derived the same way (`info = "keyring-read"`); later ones come by rekey like any library's.
- Each of the user's devices is granted `write` in it, and the daemon keeps it current: a record per library (`type = "retifs.library"`, `name`, `address`), written on join, create and leave. The user's nodes keep it all, and it is leased to holders like everything else (it's small).

### Recovering
1. Install retifs on a new device and choose **Recover from a recovery kit**; type the 24 words (or scan them, or use the YubiKey).
2. The device derives the identity and the keyring's `ns_id` and asks the nodes it can reach for the keyring's heads. Which nodes: those a fresh node can find for a namespace (members' node addresses in its commits, ADR-0022; announced libraries, ADR-0029). **Decided (2026-11-11): the keyring announces itself.** A node keeping the keyring announces a `retifs.keyring` destination whose app data is a tag, `HMAC-SHA256(locator, its retifs.node address)[0..16]`, with the locator key derived from the words. A fresh device knows the locator from the words and checks each announce it hears; nobody else can tell the tag from noise, and two nodes' tags can't be linked (one tag shared by all the user's nodes would tie them together in public). The nodes need only the locator, not the recovery identity: it's kept in the keyring for them. The kit names no nodes.
3. With the keyring read, the device joins every library listed (as itself: a new writer key, granted by the recovery identity), then seeks the content (ADR-0010).
4. The lost devices are revoked, with the recovery identity, in every library. Each revoke rotates the read key.

### Today, before any of this is built
Every library should have a second grant holder on another device: `retifs ns grant NS <writer> --grant` on the device that holds `grant`. This covers losing any one device.

## Impact on the threat model
- **The recovery words are the whole account.** Whoever reads them can join, read and write every library, and revoke the user's devices. They must be kept like a wallet's seed: offline, on paper or a YubiKey, never photographed into a library.
- A holder learns nothing new: the recovery identity is one more writer key among a library's members, and the keyring is ciphertext like every library.
- Members of a shared library see one more writer with `grant` (the recovery key). The family sees that "Vootele's recovery key" may admit people. That's the intended reading of `grant`.
- Losing the paper but not the devices: make a new kit, then revoke the old identity everywhere (rotating every read key).

## Consequences
- Losing every device is no longer losing everything, provided the words are kept and one node still keeps the keyring and the content.
- One more thing to do once: write the words down. The desktop app and the Android app say how many libraries the kit covers, and which can't be covered.
- The words and the derivation can't change once printed: vectors (seed → words → identity, keyring `ns_id`, the first read key), verified with RNS and a BIP-39 implementation, are needed before the first kit.

## Open
- k-of-n recovery with friends (split the seed among people the user trusts); Shamir's scheme is new crypto here and needs its own ADR.
- Whether the recovery identity should also be the "root" the threat model mentions (one key that can revoke a device from every library at once).

## Implementation status (2026-11-11)
- **Derivation, fixed:** `retifs_core::recovery`. The words are BIP-39 English over the 32-byte seed and its checksum byte (not BIP-39's PBKDF2 seed: the seed itself is the key material); `k(info) = HKDF-SHA256(ikm = seed, salt = "retifs/v1/recovery", info)`; identity secret `k("x25519") ‖ k("ed25519")`; keyring writer its Ed25519 public key, `ns_id` as for any library; first read key `k("keyring-read")`; locator `k("keyring-locator")`. Words are read case-insensitively; a wrong count, an unknown word (by position) and a failed checksum are told apart.
- **Vectors:** `test-vectors/recovery-v1.json` (6 seeds; `--example gen_recovery_vectors`), verified by `verify_recovery_rns.py`: Python RNS makes the identity from the secret and gives the same public key and hash; the words are read the BIP-39 way apart from the Rust code; the all-zero and all-`ff` seeds give BIP-39's own test vectors ("abandon … art", "zoo … vote").
- **Not built yet:** making a kit (granting the identity in every library, its `Identity` operation, the keyring library kept by the daemon), the keyring's announce, recovering on a fresh device, revoking lost devices, putting the identity on a YubiKey.
