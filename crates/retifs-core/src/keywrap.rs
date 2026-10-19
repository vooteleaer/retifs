//! Encrypting a small secret to an RNS identity: exactly RNS's
//! `Identity.encrypt` / `Identity.decrypt`, so stock Python RNS can unwrap it.
//!
//! ```text
//! identity   = X25519 secret (32) ‖ Ed25519 seed (32);   public = X25519 public ‖ Ed25519 public
//! wrapped    = ephemeral X25519 public (32) ‖ Token(key, secret)
//! key        = HKDF-SHA256(ikm = X25519(ephemeral, recipient X25519 public),
//!                          salt = SHA-256(recipient public)[0..16], info = "", L = 64)
//! Token      = iv (16) ‖ AES-256-CBC(PKCS7) ‖ HMAC-SHA256(key[0..32], iv ‖ ciphertext);  AES key = key[32..64]
//! ```
//! Used to hand a namespace's new read key to its remaining members when one
//! is revoked (ADR-0017).

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use curve25519_dalek::MontgomeryPoint;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// An identity's public key (X25519 ‖ Ed25519) from its secret.
pub fn public(identity: &[u8; 64]) -> [u8; 64] {
    crate::lease::identity_public(identity)
}

/// RNS identity hash: SHA-256(public key)[0..16].
pub fn identity_hash(public: &[u8; 64]) -> [u8; 16] {
    Sha256::digest(public)[..16].try_into().unwrap()
}

fn token_key(shared: &[u8; 32], recipient: &[u8; 64]) -> [u8; 64] {
    let mut key = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&identity_hash(recipient)), shared)
        .expand(&[], &mut key)
        .expect("64 bytes is a valid HKDF output length");
    key
}

/// Encrypts `secret` to `recipient` (public, 64 bytes). `ephemeral` and `iv`
/// must be fresh randomness (tests pass fixed ones).
pub fn wrap(recipient: &[u8; 64], secret: &[u8], ephemeral: [u8; 32], iv: [u8; 16]) -> Vec<u8> {
    let eph_public = MontgomeryPoint::mul_base_clamped(ephemeral).to_bytes();
    let peer = MontgomeryPoint(recipient[..32].try_into().unwrap());
    let shared = peer.mul_clamped(ephemeral).to_bytes();
    let key = token_key(&shared, recipient);
    let ct = cbc::Encryptor::<Aes256>::new(key[32..].into(), (&iv).into()).encrypt_padded_vec_mut::<Pkcs7>(secret);
    let signed = [iv.as_slice(), &ct].concat();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32]).expect("HMAC takes any key length");
    mac.update(&signed);
    [eph_public.as_slice(), &signed, &mac.finalize().into_bytes()].concat()
}

/// Decrypts what [`wrap`] made for this identity (secret, 64 bytes).
pub fn unwrap(identity: &[u8; 64], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 32 + 16 + 16 + 32 {
        return None;
    }
    let (eph, token) = wrapped.split_at(32);
    let shared = MontgomeryPoint(eph.try_into().unwrap()).mul_clamped(identity[..32].try_into().unwrap()).to_bytes();
    let key = token_key(&shared, &public(identity));
    let (signed, tag) = token.split_at(token.len() - 32);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32]).expect("HMAC takes any key length");
    mac.update(signed);
    mac.verify_slice(tag).ok()?;
    let (iv, ct) = signed.split_at(16);
    cbc::Decryptor::<Aes256>::new(key[32..].into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ct).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_keys_open_only_for_their_recipient() {
        let alice = [7u8; 64];
        let bob = [9u8; 64];
        let w = wrap(&public(&alice), &[42; 32], [3; 32], [4; 16]);
        assert_eq!(unwrap(&alice, &w).unwrap(), vec![42; 32]);
        assert_eq!(unwrap(&bob, &w), None);
        let mut bad = w.clone();
        bad[40] ^= 1;
        assert_eq!(unwrap(&alice, &bad), None);
    }
}
