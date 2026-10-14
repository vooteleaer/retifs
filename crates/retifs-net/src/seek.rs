//! One seeking round against one link (ADR-0010): ask what the peer has
//! (`/retifs/have`, CID prefixes, packet-sized), then fetch what it holds
//! (`/retifs/get`). Missing chunks are normal: they stay wanted and are
//! sought again from other peers or later.

use std::time::Duration;

use retifs_core::{open, Cid, Seed, ServeToken};

use crate::{
    protocol::{decode_bitmap, decode_response, encode_have, encode_request, GET_ENDPOINT, HAVE_ENDPOINT, HAVE_PREFIX, MAX_HAVE},
    transport::Transport,
};

/// CIDs per `get` in a seeking round.
pub const SEEK_GET_BATCH: usize = 32;

/// What a round brought: (index into the wanted list, ciphertext, plaintext).
#[derive(Debug, Default)]
pub struct SeekRound {
    pub got: Vec<(usize, Vec<u8>, Vec<u8>)>,
    /// How many of the wanted chunks the peer said it holds.
    pub held: usize,
    pub requests: usize,
}

/// Asks `link`'s peer for `wanted` (CID and seed of each): `have` first, then
/// `get` for what it holds. Every chunk is verified before it's returned.
pub async fn seek_round<T: Transport>(
    transport: &T,
    link: T::Link,
    token: &ServeToken,
    wanted: &[(Cid, Seed)],
    timeout: Duration,
) -> Result<SeekRound, String> {
    let nonce = transport.link_nonce(link);
    let mut round = SeekRound::default();

    let mut held = Vec::new();
    for (batch_no, batch) in wanted.chunks(MAX_HAVE).enumerate() {
        let prefixes: Vec<[u8; HAVE_PREFIX]> = batch.iter().map(|(c, _)| c.as_bytes()[..HAVE_PREFIX].try_into().unwrap()).collect();
        let refs: Vec<&[u8]> = prefixes.iter().map(|p| p.as_slice()).collect();
        let body = encode_have(&token.id(), &token.have_proof(&nonce, &refs), &prefixes);
        round.requests += 1;
        let resp = tokio::time::timeout(timeout, transport.request(link, HAVE_ENDPOINT, body))
            .await
            .map_err(|_| "have: timed out".to_string())??;
        let bits = decode_bitmap(&resp, batch.len()).map_err(|e| e.to_string())?;
        held.extend(bits.iter().enumerate().filter(|(_, h)| **h).map(|(i, _)| batch_no * MAX_HAVE + i));
    }
    round.held = held.len();

    for batch in held.chunks(SEEK_GET_BATCH) {
        let cids: Vec<Cid> = batch.iter().map(|&i| wanted[i].0).collect();
        let body = encode_request(&token.id(), &token.proof(&nonce, &cids), &cids);
        round.requests += 1;
        let resp = tokio::time::timeout(timeout, transport.request(link, GET_ENDPOINT, body))
            .await
            .map_err(|_| "get: timed out".to_string())??;
        let items = decode_response(&resp, cids.len()).map_err(|e| e.to_string())?;
        for (&i, item) in batch.iter().zip(items) {
            if let Some(ct) = item {
                let (cid, seed) = wanted[i];
                if let Ok(pt) = open(&cid, &seed, &ct) {
                    round.got.push((i, ct, pt));
                }
            }
        }
    }
    Ok(round)
}
