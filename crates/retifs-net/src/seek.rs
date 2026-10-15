//! One seeking round against one link (ADR-0010): ask what the peer has
//! (`/retifs/have`, CID prefixes, packet-sized), then fetch what it holds
//! (`/retifs/get`). Missing chunks are normal: they stay wanted and are
//! sought again from other peers or later.
//!
//! Every item carries a proof derived from that chunk's seed, so a peer can't
//! link the items to one file by token. With `per_item`, every request holds
//! a single item (one packet each): slower, but a peer also can't group items
//! by request.

use std::time::Duration;

use retifs_core::{open, ChunkToken, Cid, Seed};

use crate::{
    protocol::{decode_bitmap, decode_response, encode_have, encode_request, GET_ENDPOINT, HAVE_ENDPOINT, HAVE_PREFIX, MAX_HAVE},
    transport::Transport,
};

/// Items per `get` in a seeking round when batching.
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
/// `get` for what it holds. Every chunk is verified and opened before it's returned.
pub async fn seek_round<T: Transport>(
    transport: &T,
    link: T::Link,
    wanted: &[(Cid, Seed)],
    per_item: bool,
    timeout: Duration,
) -> Result<SeekRound, String> {
    let blind: Vec<(Cid, ChunkToken)> = wanted.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
    let pulled = pull_round(transport, link, &blind, per_item, timeout).await?;
    let mut round = SeekRound { held: pulled.held, requests: pulled.requests, got: Vec::new() };
    for (i, ct) in pulled.got {
        let (cid, seed) = wanted[i];
        if let Ok(pt) = open(&cid, &seed, &ct) {
            round.got.push((i, ct, pt));
        }
    }
    Ok(round)
}

/// What a blind round brought: (index into the wanted list, ciphertext).
#[derive(Debug, Default)]
pub struct PullRound {
    pub got: Vec<(usize, Vec<u8>)>,
    pub held: usize,
    pub requests: usize,
}

/// Like [`seek_round`], for chunks known only by CID and access token (held
/// for others under a lease): the proofs are the same, and chunks are
/// verified against their CID but can't be opened.
pub async fn pull_round<T: Transport>(
    transport: &T,
    link: T::Link,
    wanted: &[(Cid, ChunkToken)],
    per_item: bool,
    timeout: Duration,
) -> Result<PullRound, String> {
    let nonce = transport.link_nonce(link);
    let mut round = PullRound::default();
    let (have_batch, get_batch) = if per_item { (1, 1) } else { (MAX_HAVE, SEEK_GET_BATCH) };

    let indices: Vec<usize> = (0..wanted.len()).collect();
    let mut held = Vec::new();
    for batch in indices.chunks(have_batch) {
        let items: Vec<([u8; HAVE_PREFIX], [u8; 16])> = batch
            .iter()
            .map(|&i| {
                let prefix: [u8; HAVE_PREFIX] = wanted[i].0.as_bytes()[..HAVE_PREFIX].try_into().unwrap();
                (prefix, wanted[i].1.have_proof(&nonce, &prefix))
            })
            .collect();
        round.requests += 1;
        let resp = tokio::time::timeout(timeout, transport.request(link, HAVE_ENDPOINT, encode_have(&items)))
            .await
            .map_err(|_| "have: timed out".to_string())??;
        let bits = decode_bitmap(&resp, batch.len()).map_err(|e| e.to_string())?;
        held.extend(batch.iter().zip(bits).filter(|(_, h)| *h).map(|(&i, _)| i));
    }
    round.held = held.len();

    for batch in held.chunks(get_batch) {
        let items: Vec<(Cid, [u8; 16])> = batch.iter().map(|&i| (wanted[i].0, wanted[i].1.get_proof(&nonce, &wanted[i].0))).collect();
        round.requests += 1;
        let resp = tokio::time::timeout(timeout, transport.request(link, GET_ENDPOINT, encode_request(&items)))
            .await
            .map_err(|_| "get: timed out".to_string())??;
        let got = decode_response(&resp, items.len()).map_err(|e| e.to_string())?;
        for (&i, item) in batch.iter().zip(got) {
            if let Some(ct) = item
                && wanted[i].0.verify(&ct)
            {
                round.got.push((i, ct));
            }
        }
    }
    Ok(round)
}
