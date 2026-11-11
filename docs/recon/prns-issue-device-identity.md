# Prns issue: identities whose secret stays on a device

Posted 2026-11-11 as [KenAKAFrosty/Prns#330](https://github.com/KenAKAFrosty/Prns/issues/330), as below. Written against `main` at 04ecaef60 (0.3.8-hotfix.1 plus four commits; the parts named here are the same in both).

---

**Title:** Identity custody on a device: signing and key agreement through the owed-work seam

### What I'd like to do

Run a node whose destination identity lives on a hardware token (an OpenPGP card such as a YubiKey 5), so its secret keys never exist in process memory. The token does the identity's two secret operations itself: Ed25519 signatures and X25519 agreement. Everything else (HKDF, Token, hashing, links' ephemeral keys) stays in software, unchanged.

### Evidence that a token can be an RNS identity

On a YubiKey 5 NFC (firmware 5.4.3), the OpenPGP application's signature slot holds an Ed25519 key and its decryption slot an X25519 (cv25519) key, both generated on the card. Their public keys, laid out as RNS does (X25519 ‖ Ed25519), make an ordinary RNS identity:

- Python RNS 1.6.0 `Identity.validate` accepts the card's signatures (PSO:COMPUTE DIGITAL SIGNATURE, pure Ed25519 over the message) for 32- and 400-byte messages.
- A token RNS's `Identity.encrypt` made for the identity opens with the card's X25519 agreement (PSO:DECIPHER with the token's ephemeral key) followed by RNS's own HKDF and Token. No byte-order conversion is needed.
- Measured on Windows over PC/SC, 20 runs each, medians: sign 32 B 100 ms, sign 400 B 171 ms, agree 82 ms (spread under 5 ms).

So the latency is that of a slow signer, not a blocking network call.

### The seam that already exists

Every identity signature is already owed work: the engine hands out `AnnounceSignOwed`, `LinkProofSignOwed`, `IdentifySignOwed`, `ProofSignOwed`, `LinkReceiptSignOwed`, `ChannelAckSignOwed` and `TunnelSynthesizeSignOwed`, a host completes them (the tokio runtime's crypto pool, inline work on embassy and wasm) and resumes the engine with the completion. Identity decryption is owed the same way (`DecryptOwed`, `RatchetDecryptOwed`). Each owed job carries a copy of the secret (`signing_secret: Ed25519SecretKey`, `encryption_secret: X25519SecretKey`), cloned from the held identity.

A device fits there: the job would name the key instead of carrying it, and the host completes it by asking the device.

### A possible shape

Names are placeholders; API design is yours to steer.

```rust
/// Who performs an identity's secret operations.
pub enum IdentityCustody {
    /// The secret keys, held in memory as today.
    InMemory(PrivateIdentityMaterial),
    /// Only the public keys are known here; a device signs and agrees.
    Device(DeviceIdentity),
}

pub struct DeviceIdentity {
    public: PublicIdentityMaterial,
    key: DeviceKeyId,
}

/// What an owed signing job carries instead of `signing_secret`.
pub enum OwedSigningKey {
    InMemory(Ed25519SecretKey),
    Device(DeviceKeyId),
}

/// Host side (std runtimes): performs a device identity's operations.
pub trait IdentityDevice: Send + Sync {
    fn sign(&self, key: &DeviceKeyId, message: &[u8]) -> Result<Ed25519Signature, IdentityDeviceError>;
    fn agree(&self, key: &DeviceKeyId, peer: &X25519PublicKey) -> Result<X25519SharedSecret, IdentityDeviceError>;
}

pub enum IdentityDeviceError {
    Absent,
    AuthenticationRequired,
    Refused,
    Transport,
}
```

- `PreConfiguredDestination::Single` would take an `IdentityCustody` (or a sibling variant), so a destination is declared with its custody up front, and holding a device identity without a registered `IdentityDevice` fails at registration rather than at the first signature.
- Each `…SignOwed` and `DecryptOwed` carries the key as an enum instead of a secret; in-memory jobs complete exactly as today.
- A device failure completes the job as failed, and the engine treats it as it would a dropped send: no announce goes out this round, a link proof isn't sent (the initiator times out), an identify returns an error to its caller, an incoming single-destination packet stays undecrypted. Nothing else changes state.
- Runtimes without a device registered (embassy, wasm) reject device custody at registration.

### Not in scope

- Ratchets: a device identity would announce without them at first (`RatchetPolicy::NoRatchets`), since ratchet secrets are in-memory keys anyway.
- PIN entry and token discovery: those belong to the host application, behind `IdentityDevice`.
- Any wire or format change: none. Peers see an ordinary identity.

### Questions

1. Is the owed-work seam the place you'd want this, or would you rather see custody in `HeldIdentityTable`?
2. Is a failed completion per job type acceptable, or should failure be one shared shape the engine handles once?
3. Would you take this upstream in principle? If so, I'd send it in small steps: the owed jobs carrying `OwedSigningKey` (no behavior change), then device custody in the tokio runtime, then decryption.
