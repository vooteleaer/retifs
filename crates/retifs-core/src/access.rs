//! Access by possession, per chunk (ADR-0010, "who may ask"): requesters stay
//! anonymous and prove they know each chunk's seed, RNS style.
//!
//! ```text
//! chunk_token = HKDF-SHA256(ikm = chunk seed, salt = "retifs/v1/serve", info = "", L = 32)
//! get proof   = HMAC-SHA256(chunk_token, "retifs/v1/get"  ‖ link_nonce ‖ cid)[0..16]
//! have proof  = HMAC-SHA256(chunk_token, "retifs/v1/have" ‖ link_nonce ‖ prefix)[0..16]
//! ```
//! - The seed comes from the manifest, so anyone who can read a file can prove
//!   access to each of its chunks, and nothing extra has to be shared.
//! - There is no file-level token on the wire: requests for two chunks of one
//!   file look like requests for chunks of two unrelated files.
//! - The link nonce (the RNS link ID) binds a proof to one link, so it can't
//!   be replayed elsewhere. A holder never learns who asks.
//! - Published content, and chunks held for others without their seeds, are
//!   served without a proof ([`NO_PROOF`]).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{chunk::Seed, cid::Cid};

pub const PROOF_LEN: usize = 16;

/// Proof placeholder for published / blind requests.
pub const NO_PROOF: [u8; PROOF_LEN] = [0; PROOF_LEN];

const SERVE_SALT: &[u8] = b"retifs/v1/serve";
const GET_LABEL: &[u8] = b"retifs/v1/get";
const HAVE_LABEL: &[u8] = b"retifs/v1/have";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChunkToken(pub [u8; 32]);

impl std::fmt::Debug for ChunkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChunkToken(…)")
    }
}

impl ChunkToken {
    /// The access token of a chunk, derived from its seed.
    pub fn for_seed(seed: &Seed) -> Self {
        let mut token = [0u8; 32];
        Hkdf::<Sha256>::new(Some(SERVE_SALT), &seed.0)
            .expand(&[], &mut token)
            .expect("32 bytes is a valid HKDF output length");
        ChunkToken(token)
    }

    pub fn get_proof(&self, link_nonce: &[u8], cid: &Cid) -> [u8; PROOF_LEN] {
        finish(self.mac(GET_LABEL, link_nonce, cid.as_bytes()))
    }

    /// Constant-time check of a truncated `get` proof.
    pub fn verify_get(&self, link_nonce: &[u8], cid: &Cid, proof: &[u8; PROOF_LEN]) -> bool {
        self.mac(GET_LABEL, link_nonce, cid.as_bytes()).verify_truncated_left(proof).is_ok()
    }

    /// `have` proofs use their own label, so they can never be replayed as `get` proofs.
    pub fn have_proof(&self, link_nonce: &[u8], prefix: &[u8]) -> [u8; PROOF_LEN] {
        finish(self.mac(HAVE_LABEL, link_nonce, prefix))
    }

    pub fn verify_have(&self, link_nonce: &[u8], prefix: &[u8], proof: &[u8; PROOF_LEN]) -> bool {
        self.mac(HAVE_LABEL, link_nonce, prefix).verify_truncated_left(proof).is_ok()
    }

    fn mac(&self, label: &[u8], link_nonce: &[u8], item: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(label);
        mac.update(link_nonce);
        mac.update(item);
        mac
    }
}

fn finish(mac: Hmac<Sha256>) -> [u8; PROOF_LEN] {
    mac.finalize().into_bytes()[..PROOF_LEN].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_bind_seed_link_and_item() {
        let t = ChunkToken::for_seed(&Seed([1; 32]));
        let (a, b) = (Cid::of(b"a"), Cid::of(b"b"));
        let p = t.get_proof(b"link-1", &a);
        assert!(t.verify_get(b"link-1", &a, &p));
        assert!(!t.verify_get(b"link-2", &a, &p), "replay on another link");
        assert!(!t.verify_get(b"link-1", &b, &p), "another chunk");
        assert!(!ChunkToken::for_seed(&Seed([2; 32])).verify_get(b"link-1", &a, &p), "without the seed");

        let hp = t.have_proof(b"link-1", &a.as_bytes()[..8]);
        assert!(t.verify_have(b"link-1", &a.as_bytes()[..8], &hp));
        assert!(!t.verify_get(b"link-1", &a, &hp), "a have proof is not a get proof");
    }
}
