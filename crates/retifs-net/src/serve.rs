//! The serving side of `have` and `get` (ADR-0010), apart from any
//! transport: a request's bytes and the link's nonce in, the answer's bytes
//! out. retifsd answers its Prns endpoints with these, and in-memory tests
//! answer with the very same code, so the rules are written once:
//!
//! - a chunk is answered for if it's published, or if the item's proof shows
//!   the asker knows the chunk's seed (its access token verifies the proof
//!   bound to this link);
//! - anything else gets the same answer as a chunk not held ("don't have"),
//!   so a refusal can't be told from absence;
//! - `have` answers only for chunks that are actually here (a leased chunk is
//!   in the serving index before it arrives).

use retifs_core::{ChunkToken, Cid};

use crate::protocol::{decode_have, decode_request, encode_bitmap, encode_response, HAVE_PREFIX};

/// What the serving side needs to know of what it holds.
pub trait Holdings {
    /// For each CID: its access token if this node serves it under one, and
    /// whether it's published (served to anyone). One call for all, so every
    /// item costs the same whatever the answer.
    fn serving_info(&self, cids: &[Cid]) -> Vec<(Option<ChunkToken>, bool)>;
    /// The served chunk whose CID starts with `prefix`: its CID, token and
    /// whether it's published.
    fn served_by_prefix(&self, prefix: &[u8; HAVE_PREFIX]) -> Option<(Cid, Option<ChunkToken>, bool)>;
    /// Whether the chunk's bytes are here.
    fn present(&self, cid: &Cid) -> bool;
    /// The chunk's ciphertext, if it's here.
    fn chunk(&self, cid: &Cid) -> Option<Vec<u8>>;
}

/// Why a request got no answer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeRejection {
    /// The request's bytes don't decode.
    Malformed,
}

/// Answers a `get`: the ciphertext of each item the asker may have, nothing for the rest.
pub fn answer_get(holdings: &impl Holdings, link_nonce: &[u8], request: &[u8]) -> Result<Vec<u8>, ServeRejection> {
    let items = decode_request(request).map_err(|_| ServeRejection::Malformed)?;
    let cids: Vec<Cid> = items.iter().map(|(c, _)| *c).collect();
    let info = holdings.serving_info(&cids);
    let out: Vec<Option<Vec<u8>>> = items
        .iter()
        .zip(info)
        .map(|((cid, proof), (token, published))| {
            let may = published || token.is_some_and(|t| t.verify_get(link_nonce, cid, proof));
            if may { holdings.chunk(cid) } else { None }
        })
        .collect();
    Ok(encode_response(&out))
}

/// Answers a `have`: one bit per item, set for a chunk here that the asker may have.
pub fn answer_have(holdings: &impl Holdings, link_nonce: &[u8], request: &[u8]) -> Result<Vec<u8>, ServeRejection> {
    let items = decode_have(request).map_err(|_| ServeRejection::Malformed)?;
    let bits: Vec<bool> = items
        .iter()
        .map(|(prefix, proof)| match holdings.served_by_prefix(prefix) {
            Some((cid, token, published)) => {
                (published || token.is_some_and(|t| t.verify_have(link_nonce, prefix, proof))) && holdings.present(&cid)
            }
            None => false,
        })
        .collect();
    Ok(encode_bitmap(&bits))
}
