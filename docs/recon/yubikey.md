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

## The card as an RNS identity, tried (2026-11-11)
The owner gave this key's OpenPGP application to retifs (its keys weren't in use). Firmware can't be updated on any YubiKey, so PIV stays without 25519 here.

- `ykman openpgp reset` (OpenPGP only; PIV, FIDO, OTP and OATH untouched), then on the card: signature slot set to Ed25519 and decryption slot to X25519 (cv25519), each key generated on the card ([card_identity_rns.py](yubikey/card_identity_rns.py), with `--generate`; without it, it only checks).
- The public keys make an RNS identity as RNS lays it out (X25519 public ‖ Ed25519 public): identity hash `12e9125e209f8c0f67acc1fe70b9e4f1`, `retifs.node` destination `258d3c394d3376c4662048ca83bd2f2d`.
- **Signatures:** the card signs the message itself (pure Ed25519, PSO:COMPUTE DIGITAL SIGNATURE); Python RNS's `Identity.validate` accepts them for 32- and 400-byte messages (an RNS packet's worth).
- **Key agreement:** Python RNS encrypted a token to the identity; the card's ECDH with the token's ephemeral key (PSO:DECIPHER), then RNS's own HKDF and Token, opened it. No byte-order conversion: the card's X25519 keys are as RFC 7748 and RNS have them.
- The PINs are the defaults after the reset (PIN 123456, admin PIN 12345678): change them (`ykman openpgp access change-pin`, `change-admin-pin`) before the key holds anything that matters. The PIN is asked once per session for signing ("Require PIN for signature: Once"); decryption needs it per session too.

So this YubiKey can be a retifs node's identity, with the secret never leaving the card, using only RNS's primitives.

## Next
1. Prns: the `IdentitySigner` trait (fallible signing, agreement on the device), with a software implementation first and the card one behind it.
2. retifs: the card's two operations over PC/SC (the `pcsc` crate: SELECT OpenPGP, VERIFY, PSO:CDS, PSO:DECIPHER) behind that trait, the PIN asked by the desktop utility.
