//! Leases, renewals, receipts and storage proofs (ADR-0010/0011,
//! irreversible decision 6). Draft v1.
//!
//! ```text
//! lease    = body ‖ sig(64)
//! body     = 0x01 ‖ lease_id (16) ‖ signer (32) ‖ expires (u64 BE, unix s) ‖ generations (u8)
//!            ‖ count (u16 BE) ‖ (cid (33) ‖ chunk_token (32)) × count
//! sig      = Ed25519(signer, "retifs/v1/lease" ‖ body)
//!
//! renewal  = 0x01 ‖ lease_id (16) ‖ expires (u64 BE) ‖ sig(64)            89 B, one packet
//! sig      = Ed25519(signer, "retifs/v1/renew" ‖ 0x01 ‖ lease_id ‖ expires)
//!
//! receipt  = 0x01 ‖ lease_id (16) ‖ SHA-256(lease body) ‖ holds_until (u64 BE)
//!            ‖ holder RNS public key (64: X25519 ‖ Ed25519) ‖ sig(64)
//! sig      = Ed25519(holder identity, "retifs/v1/receipt" ‖ all fields before sig)
//!
//! storage proof answer = HMAC-SHA256(nonce, "retifs/v1/prove" ‖ ciphertext)[0..16]
//! ```
//! - A lease lists chunks, never manifests: the holder learns which chunks
//!   belong together, not the structure or content.
//! - Each entry carries the chunk's access token (`ChunkToken`, one-way from
//!   its seed): the holder can verify requesters' proofs and prove access
//!   itself when pulling, without ever being able to decrypt.
//! - The signer is a **per-lease key** derived from the owner's namespace key
//!   and the lease ID ([`LeaseKey::derive`]): leases are unlinkable to the
//!   owner's identity and to each other, and only the owner can renew.
//! - A renewal only moves the expiry, so keeping data alive over LoRa costs
//!   one packet per lease.
//! - A receipt is signed with the holder's RNS identity and bound to the
//!   exact lease body; the owner checks that the key belongs to the node it
//!   leased to ([`node_destination`]).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{access::ChunkToken, cid::CID_LEN, Cid};

pub const VERSION: u8 = 1;
pub const ID_LEN: usize = 16;
pub const ENTRY_LEN: usize = CID_LEN + 32;
/// At most this many chunks per lease (~66 KB); larger sets are split.
pub const MAX_CHUNKS: usize = 1024;
pub const RENEWAL_LEN: usize = 1 + ID_LEN + 8 + 64;
pub const RECEIPT_LEN: usize = 1 + ID_LEN + 32 + 8 + 64 + 64;
pub const PROVE_LEN: usize = 16;

const HEADER_LEN: usize = 1 + ID_LEN + 32 + 8 + 1 + 2;
const KEY_SALT: &[u8] = b"retifs/v1/lease-key";
const LEASE_LABEL: &[u8] = b"retifs/v1/lease";
const RENEW_LABEL: &[u8] = b"retifs/v1/renew";
const RECEIPT_LABEL: &[u8] = b"retifs/v1/receipt";
const PROVE_LABEL: &[u8] = b"retifs/v1/prove";

pub type LeaseId = [u8; ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    Malformed(&'static str),
    BadSignature,
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::Malformed(m) => write!(f, "malformed: {m}"),
            LeaseError::BadSignature => f.write_str("bad signature"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// The owner's signing key for one lease.
pub struct LeaseKey(SigningKey);

impl LeaseKey {
    /// `Ed25519 seed = HKDF-SHA256(ikm = namespace key, salt = "retifs/v1/lease-key", info = lease_id, L = 32)`.
    /// The owner can always re-derive it to renew; nobody else can link it to
    /// the owner or to other leases.
    pub fn derive(namespace_key: &[u8; 32], id: &LeaseId) -> Self {
        let mut seed = [0u8; 32];
        Hkdf::<Sha256>::new(Some(KEY_SALT), namespace_key)
            .expand(id, &mut seed)
            .expect("32 bytes is a valid HKDF output length");
        LeaseKey(SigningKey::from_bytes(&seed))
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

/// A signed lease: "keep these chunks until `expires`".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub id: LeaseId,
    pub signer: [u8; 32],
    /// Unix seconds.
    pub expires: u64,
    /// Spread budget (ADR-0011): 0 = don't pass on.
    pub generations: u8,
    pub entries: Vec<(Cid, ChunkToken)>,
    pub signature: [u8; 64],
}

impl Lease {
    pub fn sign(key: &LeaseKey, id: LeaseId, expires: u64, generations: u8, entries: Vec<(Cid, ChunkToken)>) -> Self {
        assert!(!entries.is_empty() && entries.len() <= MAX_CHUNKS, "1..=MAX_CHUNKS entries");
        let mut lease = Lease { id, signer: key.public(), expires, generations, entries, signature: [0; 64] };
        lease.signature = key.0.sign(&[LEASE_LABEL, &lease.body()].concat()).to_bytes();
        lease
    }

    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN + self.entries.len() * ENTRY_LEN);
        b.push(VERSION);
        b.extend_from_slice(&self.id);
        b.extend_from_slice(&self.signer);
        b.extend_from_slice(&self.expires.to_be_bytes());
        b.push(self.generations);
        b.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for (cid, token) in &self.entries {
            b.extend_from_slice(cid.as_bytes());
            b.extend_from_slice(&token.0);
        }
        b
    }

    /// What a receipt binds to.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.body()).into()
    }

    pub fn encode(&self) -> Vec<u8> {
        [self.body().as_slice(), &self.signature].concat()
    }

    /// Parses and verifies a lease. Returns it and the bytes after it.
    pub fn decode(bytes: &[u8]) -> Result<(Lease, &[u8]), LeaseError> {
        if bytes.len() < HEADER_LEN + 64 || bytes[0] != VERSION {
            return Err(LeaseError::Malformed("lease header"));
        }
        let count = u16::from_be_bytes([bytes[HEADER_LEN - 2], bytes[HEADER_LEN - 1]]) as usize;
        if count == 0 || count > MAX_CHUNKS {
            return Err(LeaseError::Malformed("lease needs 1..=1024 chunks"));
        }
        let body_len = HEADER_LEN + count * ENTRY_LEN;
        if bytes.len() < body_len + 64 {
            return Err(LeaseError::Malformed("truncated lease"));
        }
        let (body, rest) = bytes.split_at(body_len);
        let (sig, rest) = rest.split_at(64);
        let entries = body[HEADER_LEN..]
            .as_chunks::<ENTRY_LEN>()
            .0
            .iter()
            .map(|e| {
                let cid = Cid::from_bytes(e[..CID_LEN].try_into().unwrap()).ok_or(LeaseError::Malformed("CID version"))?;
                Ok((cid, ChunkToken(e[CID_LEN..].try_into().unwrap())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lease = Lease {
            id: body[1..17].try_into().unwrap(),
            signer: body[17..49].try_into().unwrap(),
            expires: u64::from_be_bytes(body[49..57].try_into().unwrap()),
            generations: body[57],
            entries,
            signature: sig.try_into().unwrap(),
        };
        verify(&lease.signer, &[LEASE_LABEL, body].concat(), &lease.signature)?;
        Ok((lease, rest))
    }
}

/// Moves a lease's expiry. Verified against the signer stored with the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Renewal {
    pub id: LeaseId,
    pub expires: u64,
    pub signature: [u8; 64],
}

impl Renewal {
    pub fn sign(key: &LeaseKey, id: LeaseId, expires: u64) -> Self {
        let signature = key.0.sign(&Self::message(&id, expires)).to_bytes();
        Renewal { id, expires, signature }
    }

    fn message(id: &LeaseId, expires: u64) -> Vec<u8> {
        [RENEW_LABEL, &[VERSION], id, &expires.to_be_bytes()].concat()
    }

    pub fn encode(&self) -> [u8; RENEWAL_LEN] {
        let mut b = [0u8; RENEWAL_LEN];
        b[0] = VERSION;
        b[1..17].copy_from_slice(&self.id);
        b[17..25].copy_from_slice(&self.expires.to_be_bytes());
        b[25..].copy_from_slice(&self.signature);
        b
    }

    /// Parses a renewal (not yet verified: the signer is in the stored lease).
    pub fn decode(b: &[u8]) -> Result<Renewal, LeaseError> {
        if b.len() != RENEWAL_LEN || b[0] != VERSION {
            return Err(LeaseError::Malformed("renewal"));
        }
        Ok(Renewal {
            id: b[1..17].try_into().unwrap(),
            expires: u64::from_be_bytes(b[17..25].try_into().unwrap()),
            signature: b[25..].try_into().unwrap(),
        })
    }

    pub fn verify(&self, signer: &[u8; 32]) -> Result<(), LeaseError> {
        verify(signer, &Self::message(&self.id, self.expires), &self.signature)
    }
}

/// "I hold every chunk of lease `lease_id` until `holds_until`", signed by the holder node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub lease_id: LeaseId,
    pub lease_digest: [u8; 32],
    pub holds_until: u64,
    /// The holder's RNS identity public key: X25519 (32) ‖ Ed25519 (32).
    pub holder: [u8; 64],
    pub signature: [u8; 64],
}

impl Receipt {
    /// `identity` is the holder's RNS identity secret: X25519 (32) ‖ Ed25519 seed (32).
    pub fn sign(identity: &[u8; 64], lease: &Lease, holds_until: u64) -> Self {
        let key = SigningKey::from_bytes(identity[32..].try_into().unwrap());
        let holder = identity_public(identity);
        let mut r = Receipt { lease_id: lease.id, lease_digest: lease.digest(), holds_until, holder, signature: [0; 64] };
        r.signature = key.sign(&[RECEIPT_LABEL, &r.encode()[..RECEIPT_LEN - 64]].concat()).to_bytes();
        r
    }

    pub fn encode(&self) -> [u8; RECEIPT_LEN] {
        let mut b = [0u8; RECEIPT_LEN];
        b[0] = VERSION;
        b[1..17].copy_from_slice(&self.lease_id);
        b[17..49].copy_from_slice(&self.lease_digest);
        b[49..57].copy_from_slice(&self.holds_until.to_be_bytes());
        b[57..121].copy_from_slice(&self.holder);
        b[121..].copy_from_slice(&self.signature);
        b
    }

    /// Parses and verifies the signature (not yet who signed: see [`node_destination`]).
    pub fn decode(b: &[u8]) -> Result<Receipt, LeaseError> {
        if b.len() != RECEIPT_LEN || b[0] != VERSION {
            return Err(LeaseError::Malformed("receipt"));
        }
        let r = Receipt {
            lease_id: b[1..17].try_into().unwrap(),
            lease_digest: b[17..49].try_into().unwrap(),
            holds_until: u64::from_be_bytes(b[49..57].try_into().unwrap()),
            holder: b[57..121].try_into().unwrap(),
            signature: b[121..].try_into().unwrap(),
        };
        verify(r.holder[32..].try_into().unwrap(), &[RECEIPT_LABEL, &b[..RECEIPT_LEN - 64]].concat(), &r.signature)?;
        Ok(r)
    }
}

/// An RNS identity's public key (X25519 ‖ Ed25519) from its secret (X25519 ‖ Ed25519 seed).
pub fn identity_public(secret: &[u8; 64]) -> [u8; 64] {
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&x25519_public(secret[..32].try_into().unwrap()));
    public[32..].copy_from_slice(&SigningKey::from_bytes(secret[32..].try_into().unwrap()).verifying_key().to_bytes());
    public
}

/// The RNS destination hash of `retifs.node` for an identity public key
/// (X25519 ‖ Ed25519): `SHA-256(SHA-256("retifs.node")[0..10] ‖ SHA-256(key)[0..16])[0..16]`.
pub fn node_destination(public_key: &[u8; 64]) -> [u8; 16] {
    node_destination_of(Sha256::digest(public_key)[..16].try_into().unwrap())
}

/// The `retifs.node` address of the identity with this (truncated) hash: who
/// an identified link's requester is, in the form `retifs ping` shows.
pub fn node_destination_of(identity_hash: &[u8; 16]) -> [u8; 16] {
    let name_hash = &Sha256::digest(b"retifs.node")[..10];
    Sha256::digest([name_hash, identity_hash.as_slice()].concat())[..16].try_into().unwrap()
}

/// Storage proof answer for one chunk: needs the ciphertext itself, so a
/// holder can't answer from memory of earlier challenges (fresh nonce).
pub fn prove(nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; PROVE_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(nonce).expect("HMAC takes any key length");
    mac.update(PROVE_LABEL);
    mac.update(ciphertext);
    mac.finalize().into_bytes()[..PROVE_LEN].try_into().unwrap()
}

fn verify(signer: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), LeaseError> {
    let key = VerifyingKey::from_bytes(signer).map_err(|_| LeaseError::BadSignature)?;
    key.verify(message, &Signature::from_bytes(sig)).map_err(|_| LeaseError::BadSignature)
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(n: u8) -> Vec<(Cid, ChunkToken)> {
        (0..n).map(|i| (Cid::of(&[i]), ChunkToken([i; 32]))).collect()
    }

    #[test]
    fn lease_roundtrip_and_tamper() {
        let key = LeaseKey::derive(&[7; 32], &[1; 16]);
        let lease = Lease::sign(&key, [1; 16], 1_800_000_000, 2, entries(3));
        let mut wire = lease.encode();
        wire.extend_from_slice(b"tail");
        let (back, rest) = Lease::decode(&wire).unwrap();
        assert_eq!(back, lease);
        assert_eq!(rest, b"tail");
        for i in [1, 20, 50, 57, 70, wire.len() - 10] {
            let mut bad = wire.clone();
            bad[i] ^= 1;
            assert!(Lease::decode(&bad).is_err(), "byte {i}");
        }
        assert_ne!(LeaseKey::derive(&[7; 32], &[2; 16]).public(), key.public(), "per-lease keys");
    }

    #[test]
    fn renewal_needs_the_lease_key() {
        let key = LeaseKey::derive(&[7; 32], &[1; 16]);
        let r = Renewal::decode(&Renewal::sign(&key, [1; 16], 99).encode()).unwrap();
        assert!(r.verify(&key.public()).is_ok());
        assert!(r.verify(&LeaseKey::derive(&[8; 32], &[1; 16]).public()).is_err());
        let mut other = r;
        other.expires = 100;
        assert!(other.verify(&key.public()).is_err());
    }

    #[test]
    fn receipt_binds_lease_and_holder() {
        let lease = Lease::sign(&LeaseKey::derive(&[7; 32], &[1; 16]), [1; 16], 99, 0, entries(2));
        let r = Receipt::sign(&[5; 64], &lease, 99);
        let back = Receipt::decode(&r.encode()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.lease_digest, lease.digest());
        let mut bad = r.encode();
        bad[50] ^= 1;
        assert!(Receipt::decode(&bad).is_err());
    }
}
