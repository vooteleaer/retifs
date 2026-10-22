//! Fingerprint words (ADR-0020): a key shown as a few words people can
//! read to each other when it matters (adding a contact in person, a first
//! grant). Words from the BIP-39 English list (2048 words, 11 bits each);
//! the bits are the first of SHA-256(key).

use sha2::{Digest, Sha256};

/// The BIP-39 English word list (SHA-256 of the file:
/// 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
const LIST: &str = include_str!("bip39-english.txt");

/// How many words a fingerprint has by default: 66 bits.
pub const DEFAULT_WORDS: usize = 6;

fn list() -> Vec<&'static str> {
    LIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect()
}

/// `n` words (at most 23) for `key`: word i is bits 11·i … 11·i+10 of
/// SHA-256(key), most significant bit first.
pub fn fingerprint(key: &[u8], n: usize) -> Vec<&'static str> {
    let words = list();
    let digest = Sha256::digest(key);
    (0..n.min(23))
        .map(|i| {
            let index = (0..11).fold(0usize, |acc, b| {
                let bit = i * 11 + b;
                (acc << 1) | ((digest[bit / 8] >> (7 - bit % 8)) & 1) as usize
            });
            words[index]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_bip39_english() {
        let words = list();
        assert_eq!(words.len(), 2048);
        assert_eq!((words[0], words[2047]), ("abandon", "zoo"));
        let file: String = words.iter().map(|w| format!("{w}\n")).collect();
        assert_eq!(hex::encode(Sha256::digest(file.as_bytes())), "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
    }

    #[test]
    fn fingerprints_take_11_bits_per_word() {
        // SHA-256("") = e3b0c442…: 11100011101 → 1821, 10000110001 → 1073, …
        let words = list();
        let f = fingerprint(b"", 2);
        assert_eq!(f, [words[0b11100011101], words[0b10000110001]]);
        assert_eq!(fingerprint(b"key", DEFAULT_WORDS).len(), 6);
        assert_ne!(fingerprint(b"key", 6), fingerprint(b"kez", 6));
    }
}
