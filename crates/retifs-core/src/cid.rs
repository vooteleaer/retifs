//! Content identifiers: `0x01 ‖ SHA-256(ciphertext)` (ADR-0008).
//!
//! No type byte: chunks, manifest nodes, Prolly nodes and commits are
//! indistinguishable to storage nodes.

use std::fmt;

use sha2::{Digest, Sha256};

pub const CID_VERSION: u8 = 0x01;
pub const CID_LEN: usize = 33;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid([u8; CID_LEN]);

impl Cid {
    /// CID of a ciphertext.
    pub fn of(ciphertext: &[u8]) -> Self {
        let mut out = [0u8; CID_LEN];
        out[0] = CID_VERSION;
        out[1..].copy_from_slice(&Sha256::digest(ciphertext));
        Cid(out)
    }

    pub fn from_bytes(bytes: [u8; CID_LEN]) -> Option<Self> {
        (bytes[0] == CID_VERSION).then_some(Cid(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; CID_LEN] {
        &self.0
    }

    /// True if `ciphertext` hashes to this CID. Needs no key.
    pub fn verify(&self, ciphertext: &[u8]) -> bool {
        *self == Cid::of(ciphertext)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({self})")
    }
}
