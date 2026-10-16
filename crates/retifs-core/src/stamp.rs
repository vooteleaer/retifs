//! Proof-of-work stamps for lease offers (ADR-0014), LXMF's construction:
//!
//! ```text
//! workblock = ‖ for n in 0..3000: HKDF-SHA256(ikm = material, salt = SHA-256(material ‖ msgpack(n)), info = "", L = 256)
//! value     = leading zero bits of SHA-256(workblock ‖ stamp)          stamp: 32 bytes
//! material  = "retifs/v1/stamp" ‖ SHA-256(lease body)
//! ```
//! A stamp is valid for one lease and costs about 2^cost hashes of the
//! 768 KB workblock to find, nothing to keep. Holders set the cost they ask of
//! strangers; it makes filling a node with junk leases expensive, since per-lease
//! signing keys rule out quotas per owner. Only RNS primitives (HKDF, SHA-256).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::lease::Lease;

pub const STAMP_LEN: usize = 32;
/// As LXMF's `WORKBLOCK_EXPAND_ROUNDS`.
pub const WORKBLOCK_ROUNDS: u32 = 3000;
const LABEL: &[u8] = b"retifs/v1/stamp";

pub type Stamp = [u8; STAMP_LEN];

/// The material a lease's stamp is computed over.
pub fn lease_material(lease: &Lease) -> Vec<u8> {
    [LABEL, &lease.digest()].concat()
}

/// LXMF's `stamp_workblock(material)`.
pub fn workblock(material: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WORKBLOCK_ROUNDS as usize * 256);
    let mut block = [0u8; 256];
    for n in 0..WORKBLOCK_ROUNDS {
        let salt = Sha256::digest([material, &msgpack_uint(n)].concat());
        Hkdf::<Sha256>::new(Some(&salt), material)
            .expand(&[], &mut block)
            .expect("256 bytes is a valid HKDF output length");
        out.extend_from_slice(&block);
    }
    out
}

/// LXMF's `stamp_value`: leading zero bits of SHA-256(workblock ‖ stamp).
pub fn value(workblock: &[u8], stamp: &Stamp) -> u32 {
    let mut h = Sha256::new();
    h.update(workblock);
    h.update(stamp);
    let digest = h.finalize();
    let mut zeros = 0;
    for b in digest {
        zeros += b.leading_zeros();
        if b != 0 {
            break;
        }
    }
    zeros
}

pub fn valid(workblock: &[u8], stamp: &Stamp, cost: u8) -> bool {
    value(workblock, stamp) >= cost as u32
}

/// Finds a stamp worth at least `cost` (about 2^cost tries). Deterministic:
/// candidates are SHA-256(material ‖ counter).
pub fn generate(material: &[u8], cost: u8) -> Stamp {
    let wb = workblock(material);
    // The workblock prefix is the same for every try: hash it once.
    let mut prefix = Sha256::new();
    prefix.update(&wb);
    for counter in 0u64.. {
        let stamp: Stamp = Sha256::digest([material, &counter.to_be_bytes()].concat()).into();
        let mut h = prefix.clone();
        h.update(stamp);
        let digest = h.finalize();
        let zeros = digest.iter().position(|&b| b != 0).map_or(256, |i| i as u32 * 8 + digest[i].leading_zeros());
        if zeros >= cost as u32 {
            return stamp;
        }
    }
    unreachable!("the counter space is never exhausted")
}

/// msgpack encoding of a non-negative integer, as Python's `msgpack.packb(n)`.
fn msgpack_uint(n: u32) -> Vec<u8> {
    match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0xcc, n as u8],
        0x100..=0xffff => [&[0xcd][..], &(n as u16).to_be_bytes()].concat(),
        _ => [&[0xce][..], &n.to_be_bytes()].concat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_stamps_are_valid_for_their_material_only() {
        let (a, b) = (b"retifs/v1/stamp lease a".to_vec(), b"retifs/v1/stamp lease b".to_vec());
        let stamp = generate(&a, 8);
        assert!(valid(&workblock(&a), &stamp, 8));
        assert!(!valid(&workblock(&b), &stamp, 8), "not for another lease");
        assert_eq!(workblock(&a).len(), 3000 * 256);
        assert_eq!(msgpack_uint(127), vec![127]);
        assert_eq!(msgpack_uint(200), vec![0xcc, 200]);
        assert_eq!(msgpack_uint(2999), vec![0xcd, 0x0b, 0xb7]);
    }
}
