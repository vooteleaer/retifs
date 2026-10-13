//! Convergence secrets: the only difference between the key schemes (ADR-0008).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const PUBLIC_LABEL: &[u8] = b"retifs/v1/public";
const RESTRICTED_SALT: &[u8] = b"retifs/v1/restricted";

/// Keys the per-chunk seed: `seed = HMAC-SHA256(secret, frame)`.
#[derive(Clone, PartialEq, Eq)]
pub struct ConvergenceSecret([u8; 32]);

impl ConvergenceSecret {
    /// Public content: a fixed, publicly known secret, giving network-wide dedup.
    pub fn public() -> Self {
        ConvergenceSecret(Sha256::digest(PUBLIC_LABEL).into())
    }

    /// Restricted content: dedup within one publisher line.
    /// `publisher_secret` is a dedicated secret, never an RNS identity key.
    pub fn restricted(publisher_secret: &[u8; 32], name: &[u8], channel: &[u8]) -> Self {
        let mut info = Vec::with_capacity(4 + name.len() + channel.len());
        info.extend_from_slice(&len_u16(name).to_be_bytes());
        info.extend_from_slice(name);
        info.extend_from_slice(&len_u16(channel).to_be_bytes());
        info.extend_from_slice(channel);
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(RESTRICTED_SALT), publisher_secret)
            .expand(&info, &mut out)
            .expect("32 bytes is a valid HKDF output length");
        ConvergenceSecret(out)
    }

    /// Personal content: a random secret per namespace or file, so no dedup.
    pub fn personal(random: [u8; 32]) -> Self {
        ConvergenceSecret(random)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn len_u16(field: &[u8]) -> u16 {
    u16::try_from(field.len()).expect("name and channel are at most 65535 bytes")
}
