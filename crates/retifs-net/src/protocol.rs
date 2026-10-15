//! `/retifs/get` and `/retifs/have` wire formats (draft v2).
//!
//! ```text
//! get request   = item × n          item = cid (33) ‖ proof (16)      1..=MAX_BATCH items
//! get response  = entry × n         entry = 0x00 ‖ u32_be len ‖ ciphertext   (served)
//!                                         | 0x01                              (not served)
//! have request  = item × n          item = cid prefix (8) ‖ proof (16)  1..=MAX_HAVE items
//! have response = bitmap (n bits)
//! ```
//! Every item carries its own proof of access, derived from that chunk's seed
//! (retifs_core::access). There is no file-level token on the wire, so items
//! of one file can't be linked by token, and one-item requests (one packet)
//! are possible for privacy-sensitive fetching. Published / blind requests use
//! a zero proof. Ciphertext only: a server never sees seeds, and clients verify
//! every chunk against its CID and HMAC before use.

use std::fmt;

use retifs_core::{access::PROOF_LEN, cid::CID_LEN, Cid};

pub const GET_ENDPOINT: &str = "/retifs/get";
pub const MAX_BATCH: usize = 64;
pub const GET_ITEM: usize = CID_LEN + PROOF_LEN;

pub const HAVE_ENDPOINT: &str = "/retifs/have";
pub const HAVE_PREFIX: usize = 8;
pub const HAVE_ITEM: usize = HAVE_PREFIX + PROOF_LEN;
/// 16 items = 384 B: a `have` request fits one link packet, so `have`
/// requests can be pipelined on one link (docs/recon/first-transfer.md).
pub const MAX_HAVE: usize = 16;

const FOUND: u8 = 0;
const MISSING: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub &'static str);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol: {}", self.0)
    }
}

impl std::error::Error for ProtocolError {}

pub type Proof = [u8; PROOF_LEN];

pub fn encode_request(items: &[(Cid, Proof)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() * GET_ITEM);
    for (cid, proof) in items {
        out.extend_from_slice(cid.as_bytes());
        out.extend_from_slice(proof);
    }
    out
}

pub fn decode_request(bytes: &[u8]) -> Result<Vec<(Cid, Proof)>, ProtocolError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(GET_ITEM) || bytes.len() / GET_ITEM > MAX_BATCH {
        return Err(ProtocolError("get request needs 1..=64 items of cid ‖ proof"));
    }
    bytes
        .as_chunks::<GET_ITEM>()
        .0
        .iter()
        .map(|raw| {
            let cid = Cid::from_bytes(raw[..CID_LEN].try_into().unwrap()).ok_or(ProtocolError("unknown CID version"))?;
            Ok((cid, raw[CID_LEN..].try_into().unwrap()))
        })
        .collect()
}

pub fn encode_response(items: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.iter().map(|i| 5 + i.as_ref().map_or(0, Vec::len)).sum());
    for item in items {
        match item {
            Some(ct) => {
                out.push(FOUND);
                out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
                out.extend_from_slice(ct);
            }
            None => out.push(MISSING),
        }
    }
    out
}

pub fn decode_response(mut bytes: &[u8], expected: usize) -> Result<Vec<Option<Vec<u8>>>, ProtocolError> {
    let mut items = Vec::with_capacity(expected);
    while !bytes.is_empty() {
        let (tag, rest) = bytes.split_first().unwrap();
        match *tag {
            MISSING => {
                items.push(None);
                bytes = rest;
            }
            FOUND => {
                let (len, rest) = rest.split_first_chunk::<4>().ok_or(ProtocolError("truncated length"))?;
                let len = u32::from_be_bytes(*len) as usize;
                if rest.len() < len {
                    return Err(ProtocolError("truncated chunk"));
                }
                items.push(Some(rest[..len].to_vec()));
                bytes = &rest[len..];
            }
            _ => return Err(ProtocolError("unknown item tag")),
        }
    }
    if items.len() != expected {
        return Err(ProtocolError("response item count differs from request"));
    }
    Ok(items)
}

pub fn encode_have(items: &[([u8; HAVE_PREFIX], Proof)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() * HAVE_ITEM);
    for (prefix, proof) in items {
        out.extend_from_slice(prefix);
        out.extend_from_slice(proof);
    }
    out
}

pub fn decode_have(bytes: &[u8]) -> Result<Vec<([u8; HAVE_PREFIX], Proof)>, ProtocolError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(HAVE_ITEM) || bytes.len() / HAVE_ITEM > MAX_HAVE {
        return Err(ProtocolError("have request needs 1..=16 items of prefix ‖ proof"));
    }
    Ok(bytes
        .as_chunks::<HAVE_ITEM>()
        .0
        .iter()
        .map(|raw| (raw[..HAVE_PREFIX].try_into().unwrap(), raw[HAVE_PREFIX..].try_into().unwrap()))
        .collect())
}

pub fn encode_bitmap(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 0x80 >> (i % 8);
        }
    }
    out
}

pub fn decode_bitmap(bytes: &[u8], n: usize) -> Result<Vec<bool>, ProtocolError> {
    if bytes.len() != n.div_ceil(8) {
        return Err(ProtocolError("bitmap length differs from request"));
    }
    Ok((0..n).map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let items: Vec<(Cid, Proof)> = (0..5u8).map(|i| (Cid::of(&[i]), [i; PROOF_LEN])).collect();
        assert_eq!(decode_request(&encode_request(&items)).unwrap(), items);
        assert_eq!(encode_request(&items[..1]).len(), 49, "a one-chunk request fits one packet");
        assert!(decode_request(&encode_request(&vec![(Cid::of(b"x"), [0; PROOF_LEN]); MAX_BATCH + 1])).is_err());
        assert!(decode_request(&[0; 48]).is_err());

        let resp = vec![Some(vec![1, 2, 3]), None, Some(vec![]), Some(vec![9; 1000])];
        assert_eq!(decode_response(&encode_response(&resp), 4).unwrap(), resp);
        assert!(decode_response(&encode_response(&resp), 3).is_err());

        let have = vec![([1u8; HAVE_PREFIX], [2u8; PROOF_LEN]), ([3; HAVE_PREFIX], [4; PROOF_LEN])];
        assert_eq!(decode_have(&encode_have(&have)).unwrap(), have);
        assert!(encode_have(&vec![have[0]; MAX_HAVE]).len() <= 400, "a full have request fits one packet");
        let bits = vec![true, false, true, true, false, false, false, false, true];
        assert_eq!(decode_bitmap(&encode_bitmap(&bits), bits.len()).unwrap(), bits);
    }
}
