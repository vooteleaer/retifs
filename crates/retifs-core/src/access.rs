//! Access by possession (ADR-0010, "who may ask"): requesters stay anonymous
//! and prove they hold a file's read-cap, RNS style.
//!
//! ```text
//! token     = HKDF-SHA256(ikm = root seed, salt = "retifs/v1/serve", info = "", L = 32)
//! token_id  = SHA-256(token)[0..16]
//! proof     = HMAC-SHA256(token, "retifs/v1/get" ‖ link_nonce ‖ cid ‖ cid ‖ …)[0..16]
//! have      = HMAC-SHA256(token, "retifs/v1/have" ‖ link_nonce ‖ prefix ‖ prefix ‖ …)[0..16]
//! ```
//! The token is derived from the read-cap, so anyone who can read a file can
//! prove it, and nothing extra has to be shared. The link nonce (the RNS link
//! ID) binds a proof to one link, so it can't be replayed elsewhere. A holder
//! learns which file is asked for, never who asks.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{cid::Cid, manifest::FileRef};

pub const TOKEN_ID_LEN: usize = 16;
pub const PROOF_LEN: usize = 16;

/// The token id under which deliberately published content is served without a proof.
pub const PUBLIC_ID: [u8; TOKEN_ID_LEN] = [0; TOKEN_ID_LEN];

const SERVE_SALT: &[u8] = b"retifs/v1/serve";
const PROOF_LABEL: &[u8] = b"retifs/v1/get";
const HAVE_LABEL: &[u8] = b"retifs/v1/have";

#[derive(Clone, PartialEq, Eq)]
pub struct ServeToken(pub [u8; 32]);

impl std::fmt::Debug for ServeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServeToken({}…)", hex::encode(self.id()))
    }
}

impl ServeToken {
    /// The serve token of a file, derived from its read-cap.
    pub fn for_file(file: &FileRef) -> Self {
        let mut token = [0u8; 32];
        Hkdf::<Sha256>::new(Some(SERVE_SALT), &file.seed.0)
            .expand(&[], &mut token)
            .expect("32 bytes is a valid HKDF output length");
        ServeToken(token)
    }

    pub fn id(&self) -> [u8; TOKEN_ID_LEN] {
        Sha256::digest(self.0)[..TOKEN_ID_LEN].try_into().unwrap()
    }

    pub fn proof(&self, link_nonce: &[u8], cids: &[Cid]) -> [u8; PROOF_LEN] {
        finish(self.mac(PROOF_LABEL, link_nonce, cids.iter().map(|c| c.as_bytes().as_slice())))
    }

    /// Constant-time check of a truncated proof.
    pub fn verify(&self, link_nonce: &[u8], cids: &[Cid], proof: &[u8; PROOF_LEN]) -> bool {
        self.mac(PROOF_LABEL, link_nonce, cids.iter().map(|c| c.as_bytes().as_slice()))
            .verify_truncated_left(proof)
            .is_ok()
    }

    /// Proof for a `have` request over CID prefixes (a different label, so a
    /// `have` proof can never be replayed as a `get` proof).
    pub fn have_proof(&self, link_nonce: &[u8], prefixes: &[&[u8]]) -> [u8; PROOF_LEN] {
        finish(self.mac(HAVE_LABEL, link_nonce, prefixes.iter().copied()))
    }

    pub fn verify_have(&self, link_nonce: &[u8], prefixes: &[&[u8]], proof: &[u8; PROOF_LEN]) -> bool {
        self.mac(HAVE_LABEL, link_nonce, prefixes.iter().copied()).verify_truncated_left(proof).is_ok()
    }

    fn mac<'a>(&self, label: &[u8], link_nonce: &[u8], items: impl Iterator<Item = &'a [u8]>) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(label);
        mac.update(link_nonce);
        for item in items {
            mac.update(item);
        }
        mac
    }
}

fn finish(mac: Hmac<Sha256>) -> [u8; PROOF_LEN] {
    mac.finalize().into_bytes()[..PROOF_LEN].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Seed;

    fn file(seed: u8) -> FileRef {
        FileRef { root: Cid::of(&[seed]), seed: Seed([seed; 32]), size: 1 }
    }

    #[test]
    fn proofs_bind_token_link_and_cids() {
        let t = ServeToken::for_file(&file(1));
        let cids = [Cid::of(b"a"), Cid::of(b"b")];
        let p = t.proof(b"link-1", &cids);
        assert!(t.verify(b"link-1", &cids, &p));
        assert!(!t.verify(b"link-2", &cids, &p), "replay on another link");
        assert!(!t.verify(b"link-1", &cids[..1], &p), "different CIDs");
        assert!(!ServeToken::for_file(&file(2)).verify(b"link-1", &cids, &p), "another file's token");
        assert_ne!(t.id(), PUBLIC_ID);

        let prefixes: Vec<&[u8]> = cids.iter().map(|c| &c.as_bytes()[..8]).collect();
        let hp = t.have_proof(b"link-1", &prefixes);
        assert!(t.verify_have(b"link-1", &prefixes, &hp));
        assert!(!t.verify(b"link-1", &cids, &hp), "a have proof is not a get proof");
    }
}
