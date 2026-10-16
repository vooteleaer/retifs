//! `/retifs/get` and `/retifs/have` wire formats (draft v2).
//!
//! ```text
//! get request   = item × n          item = cid (33) ‖ proof (16)      1..=MAX_BATCH items
//! get response  = entry × n         entry = 0x00 ‖ u32_be len ‖ ciphertext   (served)
//!                                         | 0x01                              (not served)
//! have request  = item × n          item = cid prefix (8) ‖ proof (16)  1..=MAX_HAVE items
//! have response = bitmap (n bits)
//!
//! lease request    = 0x01 ‖ lease ‖ n (u8) ‖ source node (16) × n [‖ stamp (32)]   offer a lease (sources: where to pull)
//!                  | 0x02 ‖ renewal (89)                             move its expiry
//!                  | 0x03 ‖ n (u16) ‖ renewal (89) × n               1..=MAX_BUNDLE renewals at once
//! lease response   = status (u8) per offer or renewal: 0 accepted, 1 no room, 2 invalid or conflicting, 3 unknown lease,
//!                    or for an offer 4 ‖ cost (u8): a stamp worth `cost` bits is required (retifs_core::stamp)
//! receipt request  = lease_id (16) × n                                1..=MAX_BUNDLE leases
//! receipt response = reply × n: 0x00 ‖ receipt (185) | 0x01 ‖ held (u16) ‖ total (u16) | 0x02 (unknown lease)
//!
//! Bundles keep upkeep at one exchange per holder, however many leases it keeps.
//! prove request    = lease_id (16) ‖ nonce (16) ‖ index (u16) × n      1..=MAX_PROVE indices
//! prove response   = (0x00 ‖ answer (16) | 0x01) × n
//! put request      = lease_id (16) ‖ (u32_be len ‖ ciphertext) × n     1..=MAX_PUT chunks of that lease
//! put response     = bitmap (n bits): stored
//! ```
//! Lease formats: retifs_core::lease (decision 6).
//! Every item carries its own proof of access, derived from that chunk's seed
//! (retifs_core::access). There is no file-level token on the wire, so items
//! of one file can't be linked by token, and one-item requests (one packet)
//! are possible for privacy-sensitive fetching. Published / blind requests use
//! a zero proof. Ciphertext only: a server never sees seeds, and clients verify
//! every chunk against its CID and HMAC before use.

use std::fmt;

use retifs_core::{
    access::PROOF_LEN,
    cid::CID_LEN,
    lease::{Lease, LeaseId, Receipt, Renewal, PROVE_LEN, RECEIPT_LEN, RENEWAL_LEN},
    stamp::{Stamp, STAMP_LEN},
    Cid,
};

pub const GET_ENDPOINT: &str = "/retifs/get";
pub const MAX_BATCH: usize = 64;
pub const GET_ITEM: usize = CID_LEN + PROOF_LEN;

pub const HAVE_ENDPOINT: &str = "/retifs/have";
pub const HAVE_PREFIX: usize = 8;
pub const HAVE_ITEM: usize = HAVE_PREFIX + PROOF_LEN;
/// 16 items = 384 B: a `have` request fits one link packet, so `have`
/// requests can be pipelined on one link (docs/recon/first-transfer.md).
pub const MAX_HAVE: usize = 16;

pub const LEASE_ENDPOINT: &str = "/retifs/lease";
pub const RECEIPT_ENDPOINT: &str = "/retifs/receipt";
pub const PROVE_ENDPOINT: &str = "/retifs/prove";
pub const MAX_PROVE: usize = 16;
pub const PUT_ENDPOINT: &str = "/retifs/put";
/// 16 chunks of up to 16 KiB: one resource of about 256 KiB.
pub const MAX_PUT: usize = 16;

/// Renewals or receipt requests per bundle.
pub const MAX_BUNDLE: usize = 64;

const OFFER: u8 = 1;
const RENEW: u8 = 2;
const RENEW_MANY: u8 = 3;

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

/// A `/retifs/lease` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRequest {
    Offer { lease: Lease, sources: Vec<[u8; 16]>, stamp: Option<Stamp> },
    Renew(Renewal),
    RenewMany(Vec<Renewal>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    Accepted,
    NoRoom,
    Invalid,
    Unknown,
    /// Offers to this holder need a stamp of at least this many bits.
    StampRequired(u8),
}

impl LeaseStatus {
    /// The one-byte form used in renewal bundles (StampRequired never occurs there).
    pub fn byte(self) -> u8 {
        match self {
            LeaseStatus::Accepted => 0,
            LeaseStatus::NoRoom => 1,
            LeaseStatus::Invalid | LeaseStatus::StampRequired(_) => 2,
            LeaseStatus::Unknown => 3,
        }
    }
}

pub fn encode_lease_status(s: LeaseStatus) -> Vec<u8> {
    match s {
        LeaseStatus::StampRequired(cost) => vec![4, cost],
        other => vec![other.byte()],
    }
}

pub fn encode_lease_request(req: &LeaseRequest) -> Vec<u8> {
    match req {
        LeaseRequest::Offer { lease, sources, stamp } => {
            let mut out = vec![OFFER];
            out.extend_from_slice(&lease.encode());
            out.push(sources.len() as u8);
            for s in sources {
                out.extend_from_slice(s);
            }
            if let Some(st) = stamp {
                out.extend_from_slice(st);
            }
            out
        }
        LeaseRequest::Renew(r) => [&[RENEW][..], &r.encode()].concat(),
        LeaseRequest::RenewMany(rs) => {
            let mut out = vec![RENEW_MANY];
            out.extend_from_slice(&(rs.len() as u16).to_be_bytes());
            for r in rs {
                out.extend_from_slice(&r.encode());
            }
            out
        }
    }
}

/// Parses and verifies (lease signature; a renewal is verified against the stored lease).
pub fn decode_lease_request(bytes: &[u8]) -> Result<LeaseRequest, ProtocolError> {
    match bytes.split_first() {
        Some((&OFFER, rest)) => {
            let (lease, rest) = Lease::decode(rest).map_err(|_| ProtocolError("invalid lease"))?;
            let (&n, rest) = rest.split_first().ok_or(ProtocolError("missing source count"))?;
            let n = n as usize * 16;
            let stamp = match rest.len().checked_sub(n) {
                Some(0) => None,
                Some(STAMP_LEN) => Some(rest[n..].try_into().unwrap()),
                _ => return Err(ProtocolError("source list length")),
            };
            let sources = rest[..n].as_chunks::<16>().0.to_vec();
            Ok(LeaseRequest::Offer { lease, sources, stamp })
        }
        Some((&RENEW, rest)) => Ok(LeaseRequest::Renew(Renewal::decode(rest).map_err(|_| ProtocolError("invalid renewal"))?)),
        Some((&RENEW_MANY, rest)) => {
            let (n, rest) = rest.split_first_chunk::<2>().ok_or(ProtocolError("missing renewal count"))?;
            let n = u16::from_be_bytes(*n) as usize;
            if n == 0 || n > MAX_BUNDLE || rest.len() != n * RENEWAL_LEN {
                return Err(ProtocolError("renewal bundle needs 1..=64 renewals"));
            }
            let rs = rest.chunks(RENEWAL_LEN).map(Renewal::decode).collect::<Result<_, _>>();
            Ok(LeaseRequest::RenewMany(rs.map_err(|_| ProtocolError("invalid renewal"))?))
        }
        _ => Err(ProtocolError("unknown lease request")),
    }
}

pub fn decode_lease_status(bytes: &[u8]) -> Result<LeaseStatus, ProtocolError> {
    match bytes {
        [b] => status(*b),
        [4, cost] => Ok(LeaseStatus::StampRequired(*cost)),
        _ => Err(ProtocolError("lease status")),
    }
}

/// One status per renewal of a bundle.
pub fn decode_lease_statuses(bytes: &[u8], expected: usize) -> Result<Vec<LeaseStatus>, ProtocolError> {
    if bytes.len() != expected {
        return Err(ProtocolError("status count differs from request"));
    }
    bytes.iter().map(|b| status(*b)).collect()
}

fn status(b: u8) -> Result<LeaseStatus, ProtocolError> {
    match b {
        0 => Ok(LeaseStatus::Accepted),
        1 => Ok(LeaseStatus::NoRoom),
        2 => Ok(LeaseStatus::Invalid),
        3 => Ok(LeaseStatus::Unknown),
        _ => Err(ProtocolError("lease status")),
    }
}

/// A holder's answer to `/retifs/receipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptReply {
    Receipt(Receipt),
    Progress { held: u16, total: u16 },
    Unknown,
}

pub fn encode_receipt_reply(r: &ReceiptReply) -> Vec<u8> {
    match r {
        ReceiptReply::Receipt(r) => [&[0u8][..], &r.encode()].concat(),
        ReceiptReply::Progress { held, total } => [&[1u8][..], &held.to_be_bytes(), &total.to_be_bytes()].concat(),
        ReceiptReply::Unknown => vec![2],
    }
}

/// Parses a receipt reply; a receipt's signature is verified, not yet its signer.
pub fn decode_receipt_reply(bytes: &[u8]) -> Result<ReceiptReply, ProtocolError> {
    match decode_receipt_replies(bytes, 1)?.pop() {
        Some(r) => Ok(r),
        None => Err(ProtocolError("receipt reply")),
    }
}

pub fn encode_receipt_replies(replies: &[ReceiptReply]) -> Vec<u8> {
    replies.iter().flat_map(encode_receipt_reply).collect()
}

/// Parses the replies to a bundled receipt request, one per lease asked about.
pub fn decode_receipt_replies(mut bytes: &[u8], expected: usize) -> Result<Vec<ReceiptReply>, ProtocolError> {
    let mut out = Vec::with_capacity(expected);
    while let Some((&tag, rest)) = bytes.split_first() {
        let (reply, rest) = match tag {
            0 if rest.len() >= RECEIPT_LEN => (
                ReceiptReply::Receipt(Receipt::decode(&rest[..RECEIPT_LEN]).map_err(|_| ProtocolError("invalid receipt"))?),
                &rest[RECEIPT_LEN..],
            ),
            1 if rest.len() >= 4 => (
                ReceiptReply::Progress {
                    held: u16::from_be_bytes([rest[0], rest[1]]),
                    total: u16::from_be_bytes([rest[2], rest[3]]),
                },
                &rest[4..],
            ),
            2 => (ReceiptReply::Unknown, rest),
            _ => return Err(ProtocolError("receipt reply")),
        };
        out.push(reply);
        bytes = rest;
    }
    if out.len() != expected {
        return Err(ProtocolError("receipt reply count differs from request"));
    }
    Ok(out)
}

pub fn encode_receipt_request(ids: &[LeaseId]) -> Vec<u8> {
    ids.concat()
}

pub fn decode_receipt_request(bytes: &[u8]) -> Result<Vec<LeaseId>, ProtocolError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) || bytes.len() / 16 > MAX_BUNDLE {
        return Err(ProtocolError("receipt request needs 1..=64 lease ids"));
    }
    Ok(bytes.as_chunks::<16>().0.to_vec())
}

pub fn encode_prove(id: &LeaseId, nonce: &[u8; 16], indices: &[u16]) -> Vec<u8> {
    let mut out = [id.as_slice(), nonce].concat();
    for i in indices {
        out.extend_from_slice(&i.to_be_bytes());
    }
    out
}

pub fn decode_prove(bytes: &[u8]) -> Result<(LeaseId, [u8; 16], Vec<u16>), ProtocolError> {
    let n = bytes.len().saturating_sub(32) / 2;
    if bytes.len() < 34 || !bytes.len().is_multiple_of(2) || n > MAX_PROVE {
        return Err(ProtocolError("prove request needs lease id, nonce and 1..=16 indices"));
    }
    let indices = bytes[32..].as_chunks::<2>().0.iter().map(|b| u16::from_be_bytes(*b)).collect();
    Ok((bytes[..16].try_into().unwrap(), bytes[16..32].try_into().unwrap(), indices))
}

pub fn encode_prove_reply(answers: &[Option<[u8; PROVE_LEN]>]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in answers {
        match a {
            Some(a) => {
                out.push(FOUND);
                out.extend_from_slice(a);
            }
            None => out.push(MISSING),
        }
    }
    out
}

pub fn decode_prove_reply(mut bytes: &[u8], expected: usize) -> Result<Vec<Option<[u8; PROVE_LEN]>>, ProtocolError> {
    let mut out = Vec::with_capacity(expected);
    while let Some((&tag, rest)) = bytes.split_first() {
        match tag {
            MISSING => {
                out.push(None);
                bytes = rest;
            }
            FOUND if rest.len() >= PROVE_LEN => {
                out.push(Some(rest[..PROVE_LEN].try_into().unwrap()));
                bytes = &rest[PROVE_LEN..];
            }
            _ => return Err(ProtocolError("prove reply")),
        }
    }
    if out.len() != expected {
        return Err(ProtocolError("prove reply count differs from request"));
    }
    Ok(out)
}

pub fn encode_put(id: &LeaseId, chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = id.to_vec();
    for ct in chunks {
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(ct);
    }
    out
}

pub fn decode_put(bytes: &[u8]) -> Result<(LeaseId, Vec<Vec<u8>>), ProtocolError> {
    let (id, mut rest) = bytes.split_first_chunk::<16>().ok_or(ProtocolError("put needs a lease id"))?;
    let mut chunks = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>().ok_or(ProtocolError("truncated length"))?;
        let len = u32::from_be_bytes(*len) as usize;
        if tail.len() < len || chunks.len() == MAX_PUT {
            return Err(ProtocolError("put needs 1..=16 whole chunks"));
        }
        chunks.push(tail[..len].to_vec());
        rest = &tail[len..];
    }
    if chunks.is_empty() {
        return Err(ProtocolError("put needs 1..=16 whole chunks"));
    }
    Ok((*id, chunks))
}

#[cfg(test)]
mod tests {
    #[test]
    fn lease_messages_roundtrip() {
        use super::*;
        use retifs_core::{lease::LeaseKey, ChunkToken};
        let key = LeaseKey::derive(&[1; 32], &[2; 16]);
        let lease = Lease::sign(&key, [2; 16], 99, 1, vec![(Cid::of(b"a"), ChunkToken([3; 32]))]);
        for req in [
            LeaseRequest::Offer { lease: lease.clone(), sources: vec![[4; 16], [5; 16]], stamp: None },
            LeaseRequest::Offer { lease: lease.clone(), sources: vec![[4; 16]], stamp: Some([6; 32]) },
            LeaseRequest::Offer { lease: lease.clone(), sources: vec![], stamp: Some([7; 32]) },
            LeaseRequest::Renew(Renewal::sign(&key, [2; 16], 100)),
        ] {
            assert_eq!(decode_lease_request(&encode_lease_request(&req)).unwrap(), req);
        }
        let mut forged = encode_lease_request(&LeaseRequest::Offer { lease, sources: vec![], stamp: None });
        forged[30] ^= 1;
        assert!(decode_lease_request(&forged).is_err());
        assert_eq!(encode_lease_request(&LeaseRequest::Renew(Renewal::sign(&key, [2; 16], 1))).len(), 90, "one packet");

        for r in [ReceiptReply::Progress { held: 3, total: 9 }, ReceiptReply::Unknown] {
            assert_eq!(decode_receipt_reply(&encode_receipt_reply(&r)).unwrap(), r);
        }
        let lease = Lease::sign(&key, [2; 16], 99, 1, vec![(Cid::of(b"a"), ChunkToken([3; 32]))]);
        let replies = vec![
            ReceiptReply::Unknown,
            ReceiptReply::Receipt(retifs_core::lease::Receipt::sign(&[5; 64], &lease, 99)),
            ReceiptReply::Progress { held: 1, total: 2 },
        ];
        assert_eq!(decode_receipt_replies(&encode_receipt_replies(&replies), 3).unwrap(), replies);
        assert!(decode_receipt_replies(&encode_receipt_replies(&replies), 2).is_err());
        let ids = vec![[1u8; 16], [2u8; 16]];
        assert_eq!(decode_receipt_request(&encode_receipt_request(&ids)).unwrap(), ids);
        let bundle = LeaseRequest::RenewMany((0..3).map(|i| Renewal::sign(&key, [2; 16], 100 + i)).collect());
        assert_eq!(decode_lease_request(&encode_lease_request(&bundle)).unwrap(), bundle);
        assert_eq!(decode_lease_status(&encode_lease_status(LeaseStatus::StampRequired(9))).unwrap(), LeaseStatus::StampRequired(9));
        assert_eq!(decode_lease_statuses(&[0, 3, 2], 3).unwrap(), vec![LeaseStatus::Accepted, LeaseStatus::Unknown, LeaseStatus::Invalid]);
        let (id, nonce, idx) = decode_prove(&encode_prove(&[1; 16], &[2; 16], &[0, 7, 65535])).unwrap();
        assert_eq!((id, nonce, idx), ([1; 16], [2; 16], vec![0, 7, 65535]));
        let answers = vec![Some([9; PROVE_LEN]), None];
        assert_eq!(decode_prove_reply(&encode_prove_reply(&answers), 2).unwrap(), answers);

        let chunks = vec![vec![1u8; 1024], vec![2u8; 4096]];
        assert_eq!(decode_put(&encode_put(&[7; 16], &chunks)).unwrap(), ([7; 16], chunks));
        assert!(decode_put(&[7; 16]).is_err(), "no chunks");
        assert!(decode_put(&encode_put(&[7; 16], &vec![vec![0u8; 8]; MAX_PUT + 1])).is_err());
    }

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
