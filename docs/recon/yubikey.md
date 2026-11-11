# Recon: YubiKey as a retifs node's identity (2026-11-11)

Phase 0 asked which way a YubiKey can hold an RNS identity: an RNS identity is an X25519 key (key exchange) and an Ed25519 key (signatures), so the key must do both on the device.

## The key at hand
`ykman info` (yubikey-manager 5, read only):

- YubiKey 5 NFC, firmware **5.4.3**, USB-A; OTP, FIDO, CCID enabled.
- **PIV:** version 5.4.3. Ed25519 and X25519 in PIV came with firmware **5.7**, so not on this key. Slot 9A holds a P-256 key (in use).
- **OpenPGP:** version 3.4, algorithm attributes changeable, key import allowed. All three slots hold **NIST P-256** keys (signature: ECDSA, decryption: ECDH, authentication: ECDSA), in use.

## What it means
- **PIV route (5.7+):** not possible on this key. A newer YubiKey 5 (firmware 5.7 or later) can keep Ed25519 and X25519 in PIV slots, next to whatever else PIV holds.
- **OpenPGP route (5.2.3+):** possible on this key. OpenPGP cards on firmware 5.2.3+ do Ed25519 signatures (PSO:COMPUTE DIGITAL SIGNATURE over the message, EdDSA) and X25519 key agreement (cv25519, PSO:DECIPHER returns the shared secret). Together that is an RNS identity: signing slot Ed25519, decryption slot cv25519.
  - It would **replace the P-256 keys now in those slots**. Keys made on the card can't be copied out, so whatever uses them now (a GnuPG identity, SSH via the authentication key) would lose them for good, unless they were imported from a backup.
  - P-256 keys can't stand in: RNS fixes the curves.
- **In Prns (upstream):** an identity whose secret stays on a device needs a fallible `sign()` (a card can be pulled out, a PIN refused) and X25519 agreement through a trait instead of a key in memory. Neither exists in Prns 0.3.8; the plan has them as the next step, to be proposed upstream.

## Next
1. A decision: a key for retifs alone (a second YubiKey, or one with firmware 5.7+ for PIV), or this key's OpenPGP slots given up for it.
2. Prns: the `IdentitySigner` trait (fallible signing, agreement on the device), with a software implementation first and the card one behind it.
