//! The recovery kit (ADR-0033): one secret, shown once as 24 words, from
//! which a recovery identity and the user's keyring follow.
//!
//! ```text
//! seed       32 random bytes
//! words      BIP-39 English: seed ‖ SHA-256(seed)[0] in 11-bit groups, 24 words
//!            (the BIP-39 entropy and checksum; not BIP-39's PBKDF2 seed)
//! k(info)    HKDF-SHA256(ikm = seed, salt = "retifs/v1/recovery", info)[0..32]
//! identity   X25519 private = k("x25519") ‖ Ed25519 seed = k("ed25519"): an RNS identity
//! keyring    the library whose creator is the identity (writer = its Ed25519 public key,
//!            ns_id = SHA-256("retifs/v1/ns" ‖ writer)[0..16]), first read key k("keyring-read")
//! locator    k("keyring-locator"); a node keeping the keyring announces `retifs.keyring`
//!            with app data HMAC-SHA256(locator, its retifs.node address)[0..16]
//! ```
//!
//! The words and every derivation here are irreversible once a kit is
//! printed: vectors in `test-vectors/recovery-v1.json`, checked with Python
//! RNS and a separate BIP-39 reading.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::channel::{self, NsId};

const SALT: &[u8] = b"retifs/v1/recovery";
const LIST: &str = include_str!("bip39-english.txt");

/// Words in a recovery kit.
pub const WORDS: usize = 24;

/// The secret behind a recovery kit.
pub struct RecoverySeed([u8; 32]);

/// Why words don't make a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordsError {
    /// Not 24 words.
    Count(usize),
    /// A word not on the list (its position, from 1).
    Unknown(usize),
    /// The checksum doesn't hold: a word is wrong or two are swapped.
    Checksum,
}

impl std::fmt::Display for WordsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WordsError::Count(n) => write!(f, "a recovery kit has {WORDS} words, not {n}"),
            WordsError::Unknown(i) => write!(f, "word {i} isn't one of the kit's words"),
            WordsError::Checksum => write!(f, "these words don't check out: one is wrong, or two are swapped"),
        }
    }
}

impl std::error::Error for WordsError {}

fn list() -> Vec<&'static str> {
    LIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect()
}

impl RecoverySeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        RecoverySeed(bytes)
    }

    /// A new seed from the OS's randomness.
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS entropy");
        RecoverySeed(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 24 words.
    pub fn words(&self) -> Vec<&'static str> {
        let words = list();
        let mut bits = self.0.to_vec();
        bits.push(Sha256::digest(self.0)[0]);
        (0..WORDS)
            .map(|i| {
                let index = (0..11).fold(0usize, |acc, b| {
                    let bit = i * 11 + b;
                    (acc << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1) as usize
                });
                words[index]
            })
            .collect()
    }

    /// The seed the words stand for (case and surrounding spaces don't matter).
    pub fn from_words(text: &[&str]) -> Result<Self, WordsError> {
        if text.len() != WORDS {
            return Err(WordsError::Count(text.len()));
        }
        let words = list();
        let mut bits = [0u8; 33];
        for (i, w) in text.iter().enumerate() {
            let w = w.trim().to_lowercase();
            let index = words.iter().position(|x| *x == w).ok_or(WordsError::Unknown(i + 1))?;
            for b in 0..11 {
                if (index >> (10 - b)) & 1 == 1 {
                    let bit = i * 11 + b;
                    bits[bit / 8] |= 1 << (7 - bit % 8);
                }
            }
        }
        let seed: [u8; 32] = bits[..32].try_into().expect("32 bytes");
        if Sha256::digest(seed)[0] != bits[32] {
            return Err(WordsError::Checksum);
        }
        Ok(RecoverySeed(seed))
    }

    fn key(&self, info: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(SALT), &self.0).expand(info.as_bytes(), &mut out).expect("32 bytes is a valid HKDF output length");
        out
    }

    /// The recovery identity's secret as RNS keeps one: X25519 private ‖ Ed25519 seed.
    pub fn identity_secret(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.key("x25519"));
        out[32..].copy_from_slice(&self.key("ed25519"));
        out
    }

    /// The identity's writer key in libraries: its Ed25519 public key.
    pub fn writer(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.key("ed25519")).verifying_key().to_bytes()
    }

    /// The identity's public key as RNS lays it out: X25519 public ‖ Ed25519 public.
    pub fn identity_public(&self) -> [u8; 64] {
        let x = curve25519_dalek::MontgomeryPoint::mul_base_clamped(self.key("x25519")).to_bytes();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&x);
        out[32..].copy_from_slice(&self.writer());
        out
    }

    /// The RNS identity hash: SHA-256 of the public key, first 16 bytes.
    pub fn identity_hash(&self) -> [u8; 16] {
        Sha256::digest(self.identity_public())[..16].try_into().expect("16 bytes")
    }

    /// The keyring library's ns_id.
    pub fn keyring_ns_id(&self) -> NsId {
        channel::ns_id(&self.writer())
    }

    /// The keyring library's first read key.
    pub fn keyring_read_key(&self) -> [u8; 32] {
        self.key("keyring-read")
    }

    /// The key behind the keyring's announce tags.
    pub fn locator(&self) -> Locator {
        Locator(self.key("keyring-locator"))
    }
}

/// The key that tells a node keeping the keyring by its announce.
#[derive(Clone)]
pub struct Locator(pub [u8; 32]);

impl Locator {
    /// The tag `node` (its retifs.node address) announces: unrelated across nodes to anyone without the key.
    pub fn tag(&self, node: &[u8; 16]) -> [u8; 16] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("any key length");
        mac.update(node);
        mac.finalize().into_bytes()[..16].try_into().expect("16 bytes")
    }

    /// Whether `tag` is `node`'s.
    pub fn is_tag(&self, node: &[u8; 16], tag: &[u8]) -> bool {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("any key length");
        mac.update(node);
        mac.verify_truncated_left(tag).is_ok() && tag.len() == 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip_and_catch_mistakes() {
        let seed = RecoverySeed::from_bytes([7; 32]);
        let words = seed.words();
        assert_eq!(words.len(), 24);
        assert_eq!(RecoverySeed::from_words(&words).unwrap().as_bytes(), seed.as_bytes());
        // BIP-39's own test vector: 32 zero bytes are "abandon" × 23, "art".
        let zero = RecoverySeed::from_bytes([0; 32]).words();
        assert_eq!(zero[..23], ["abandon"; 23]);
        assert_eq!(zero[23], "art");
        let mut wrong = words.clone();
        wrong.swap(3, 4);
        assert!(wrong == words || RecoverySeed::from_words(&wrong).is_err_and(|e| e == WordsError::Checksum));
        let mut typo: Vec<&str> = words.clone();
        typo[5] = "notaword";
        assert_eq!(RecoverySeed::from_words(&typo).err(), Some(WordsError::Unknown(6)));
        assert_eq!(RecoverySeed::from_words(&words[..23]).err(), Some(WordsError::Count(23)));
        let upper: Vec<String> = words.iter().map(|w| format!(" {} ", w.to_uppercase())).collect();
        assert!(RecoverySeed::from_words(&upper.iter().map(String::as_str).collect::<Vec<_>>()).is_ok());
    }

    #[test]
    fn derived_keys_differ_and_tags_are_per_node() {
        let seed = RecoverySeed::from_bytes([9; 32]);
        let s = seed.identity_secret();
        assert_ne!(s[..32], s[32..]);
        assert_ne!(seed.keyring_read_key(), seed.locator().0);
        let l = seed.locator();
        let (a, b) = ([1u8; 16], [2u8; 16]);
        assert_ne!(l.tag(&a), l.tag(&b));
        assert!(l.is_tag(&a, &l.tag(&a)) && !l.is_tag(&b, &l.tag(&a)));
    }
}
