//! `/retifs/get` wire format (draft v0).
//!
//! ```text
//! request   = cid ‖ cid ‖ …                  1..=MAX_BATCH CIDs, 33 bytes each
//! response  = item ‖ item ‖ …                one per requested CID, same order
//! item      = 0x00 ‖ u32_be len ‖ ciphertext  (found)
//!           | 0x01                             (not held by this node)
//! ```
//! Ciphertext only: the server never sees seeds, and the client verifies every
//! chunk against its CID and HMAC before use.

use std::fmt;

use retifs_core::{Cid, cid::CID_LEN};

pub const GET_ENDPOINT: &str = "/retifs/get";
pub const MAX_BATCH: usize = 64;

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

pub fn encode_request(cids: &[Cid]) -> Vec<u8> {
    cids.iter().flat_map(|c| c.as_bytes().iter().copied()).collect()
}

pub fn decode_request(bytes: &[u8]) -> Result<Vec<Cid>, ProtocolError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cids: Vec<Cid> = (0..5u8).map(|i| Cid::of(&[i])).collect();
        assert_eq!(decode_request(&encode_request(&cids)).unwrap(), cids);
        let items = vec![Some(vec![1, 2, 3]), None, Some(vec![]), Some(vec![9; 1000])];
        assert_eq!(decode_response(&encode_response(&items), 4).unwrap(), items);
        assert!(decode_response(&encode_response(&items), 3).is_err());
        assert!(decode_request(&[0; 32]).is_err());
        assert!(decode_request(&encode_request(&vec![Cid::of(b"x"); MAX_BATCH + 1])).is_err());
    }
}
