//! Access by possession (ADR-0010, "who may ask"): requesters stay anonymous
//! and prove they hold a file's read-cap, RNS style.
//!
//! ```text
//! token     = HKDF-SHA256(ikm = root seed, salt = "retifs/v1/serve", info = "", L = 32)
//! token_id  = SHA-256(token)[0..16]
//! proof     = HMAC-SHA256(token, "retifs/v1/get" ‖ link_nonce ‖ cid ‖ cid ‖ …)[0..16]
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
        self.mac(link_nonce, cids).finalize().into_bytes()[..PROOF_LEN].try_into().unwrap()
    }

    /// Constant-time check of a truncated proof.
    pub fn verify(&self, link_nonce: &[u8], cids: &[Cid], proof: &[u8; PROOF_LEN]) -> bool {
        self.mac(link_nonce, cids).verify_truncated_left(proof).is_ok()
    }

    fn mac(&self, link_nonce: &[u8], cids: &[Cid]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(PROOF_LABEL);
        mac.update(link_nonce);
        for cid in cids {
            mac.update(cid.as_bytes());
        }
        mac
    }
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
    }
}
