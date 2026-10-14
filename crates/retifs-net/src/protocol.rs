//! `/retifs/get` wire format (draft v1).
//!
//! ```text
//! request   = token_id (16) ‖ proof (16) ‖ cid ‖ cid ‖ …   1..=MAX_BATCH CIDs, 33 bytes each
//!             token_id/proof: retifs_core::access (anonymous proof of possession);
//!             token_id = PUBLIC_ID and a zero proof ask for published content only
//! response  = item ‖ item ‖ …                one per requested CID, same order
//! item      = 0x00 ‖ u32_be len ‖ ciphertext  (found)
//!           | 0x01                             (not held by this node)
//! ```
//! Ciphertext only: the server never sees seeds, and the client verifies every
//! chunk against its CID and HMAC before use.

use std::fmt;

use retifs_core::{
    access::{PROOF_LEN, TOKEN_ID_LEN},
    cid::CID_LEN,
    Cid,
};

pub const GET_ENDPOINT: &str = "/retifs/get";
pub const MAX_BATCH: usize = 64;

/// `/retifs/have`: token_id (16) ‖ proof (16) ‖ CID prefix (8) × n  →  bitmap (n bits).
/// 48 prefixes keep the request (416 B) within one link packet, so `have`
/// requests can be pipelined on one link (see docs/recon/first-transfer.md).
pub const HAVE_ENDPOINT: &str = "/retifs/have";
pub const HAVE_PREFIX: usize = 8;
pub const MAX_HAVE: usize = 48;

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

/// A decoded `/retifs/get` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRequest {
    pub token_id: [u8; TOKEN_ID_LEN],
    pub proof: [u8; PROOF_LEN],
    pub cids: Vec<Cid>,
}

pub fn encode_request(token_id: &[u8; TOKEN_ID_LEN], proof: &[u8; PROOF_LEN], cids: &[Cid]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOKEN_ID_LEN + PROOF_LEN + cids.len() * CID_LEN);
    out.extend_from_slice(token_id);
    out.extend_from_slice(proof);
    for c in cids {
        out.extend_from_slice(c.as_bytes());
    }
    out
}

pub fn decode_request(bytes: &[u8]) -> Result<GetRequest, ProtocolError> {
    let (head, bytes) = bytes
        .split_first_chunk::<{ TOKEN_ID_LEN + PROOF_LEN }>()
        .ok_or(ProtocolError("request shorter than its header"))?;
    let token_id: [u8; TOKEN_ID_LEN] = head[..TOKEN_ID_LEN].try_into().unwrap();
    let proof: [u8; PROOF_LEN] = head[TOKEN_ID_LEN..].try_into().unwrap();
    let cids = decode_cids(bytes)?;
    Ok(GetRequest { token_id, proof, cids })
}

fn decode_cids(bytes: &[u8]) -> Result<Vec<Cid>, ProtocolError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(CID_LEN) {
        return Err(ProtocolError("request is not a whole number of CIDs"));
    }
    if bytes.len() / CID_LEN > MAX_BATCH {
        return Err(ProtocolError("too many CIDs in one request"));
    }
    bytes
        .as_chunks::<CID_LEN>()
        .0
        .iter()
        .map(|raw| Cid::from_bytes(*raw).ok_or(ProtocolError("unknown CID version")))
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

/// A decoded `/retifs/have` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaveRequest {
    pub token_id: [u8; TOKEN_ID_LEN],
    pub proof: [u8; PROOF_LEN],
    pub prefixes: Vec<[u8; HAVE_PREFIX]>,
}

pub fn encode_have(token_id: &[u8; TOKEN_ID_LEN], proof: &[u8; PROOF_LEN], prefixes: &[[u8; HAVE_PREFIX]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOKEN_ID_LEN + PROOF_LEN + prefixes.len() * HAVE_PREFIX);
    out.extend_from_slice(token_id);
    out.extend_from_slice(proof);
    for p in prefixes {
        out.extend_from_slice(p);
    }
    out
}

pub fn decode_have(bytes: &[u8]) -> Result<HaveRequest, ProtocolError> {
    let (head, body) = bytes
        .split_first_chunk::<{ TOKEN_ID_LEN + PROOF_LEN }>()
        .ok_or(ProtocolError("have request shorter than its header"))?;
    if body.is_empty() || !body.len().is_multiple_of(HAVE_PREFIX) || body.len() / HAVE_PREFIX > MAX_HAVE {
        return Err(ProtocolError("have request needs 1..=48 prefixes"));
    }
    Ok(HaveRequest {
        token_id: head[..TOKEN_ID_LEN].try_into().unwrap(),
        proof: head[TOKEN_ID_LEN..].try_into().unwrap(),
        prefixes: body.as_chunks::<HAVE_PREFIX>().0.to_vec(),
    })
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
        let cids: Vec<Cid> = (0..5u8).map(|i| Cid::of(&[i])).collect();
        let req = decode_request(&encode_request(&[7; 16], &[8; 16], &cids)).unwrap();
        assert_eq!(req, GetRequest { token_id: [7; 16], proof: [8; 16], cids: cids.clone() });
        let items = vec![Some(vec![1, 2, 3]), None, Some(vec![]), Some(vec![9; 1000])];
        assert_eq!(decode_response(&encode_response(&items), 4).unwrap(), items);
        assert!(decode_response(&encode_response(&items), 3).is_err());
        assert!(decode_request(&[0; 32]).is_err(), "header only, no CIDs");
        assert!(decode_request(&encode_request(&[0; 16], &[0; 16], &vec![Cid::of(b"x"); MAX_BATCH + 1])).is_err());

        let prefixes = [[1u8; HAVE_PREFIX], [2; HAVE_PREFIX]];
        let have = encode_have(&[3; 16], &[4; 16], &prefixes);
        assert!(have.len() <= 32 + MAX_HAVE * HAVE_PREFIX);
        assert_eq!(decode_have(&have).unwrap(), HaveRequest { token_id: [3; 16], proof: [4; 16], prefixes: prefixes.to_vec() });
        let bits = vec![true, false, true, true, false, false, false, false, true];
        assert_eq!(decode_bitmap(&encode_bitmap(&bits), bits.len()).unwrap(), bits);
    }
}
