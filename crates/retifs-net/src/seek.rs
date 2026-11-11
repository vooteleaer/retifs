//! One seeking round against one link (ADR-0010): ask what the peer has
//! (`/retifs/have`, CID prefixes, packet-sized), then fetch what it holds
//! (`/retifs/get`). Missing chunks are normal: they stay wanted and are
//! sought again from other peers or later.
//!
//! Every item carries a proof derived from that chunk's seed, so a peer can't
//! link the items to one file by token. With `per_item` (private requests,
//! ADR-0010's request-pattern leaks), every request holds a single item (one
//! packet each), so a peer can't group items by request either; a round asks
//! a peer about a random slice of at most [`PRIVATE_SLICE`] wanted chunks, so
//! it doesn't learn how many a file has; decoy prefixes are mixed in (about
//! one for every [`DECOY_EVERY`] real ones), which it answers "don't have" like
//! any chunk it lacks; and requests are spaced by a random pause of up to
//! [`JITTER_MAX_MS`], so their timing says less.

use std::time::Duration;

use retifs_core::{open, ChunkToken, Cid, Seed};

use crate::{
    protocol::{decode_bitmap, decode_response, encode_have, encode_request, GET_ENDPOINT, HAVE_ENDPOINT, HAVE_PREFIX, MAX_HAVE},
    transport::Transport,
};

/// Items per `get` in a seeking round when batching.
pub const SEEK_GET_BATCH: usize = 32;
/// Wanted chunks a private round asks one peer about at most.
pub const PRIVATE_SLICE: usize = 16;
/// A private round adds one decoy `have` for about this many real ones.
pub const DECOY_EVERY: usize = 4;
/// The longest random pause between a private round's requests.
pub const JITTER_MAX_MS: u64 = 300;

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS entropy");
    u64::from_le_bytes(b)
}

/// A random order of `0..n` (Fisher–Yates).
fn shuffled(n: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        v.swap(i, (random_u64() % (i as u64 + 1)) as usize);
    }
    v
}

/// What a private round asks `have` about: a random slice of the wanted
/// chunks (`Some(index)`) with decoys (`None`) mixed in, in random order.
fn private_plan(wanted: usize) -> Vec<Option<usize>> {
    let real: Vec<usize> = shuffled(wanted).into_iter().take(PRIVATE_SLICE).collect();
    let decoys = real.len().div_ceil(DECOY_EVERY);
    let mut items: Vec<Option<usize>> = real.into_iter().map(Some).chain(std::iter::repeat_n(None, decoys)).collect();
    let order = shuffled(items.len());
    let mut out = Vec::with_capacity(items.len());
    for i in order {
        out.push(items[i].take());
    }
    out
}

async fn jitter() {
    tokio::time::sleep(Duration::from_millis(random_u64() % (JITTER_MAX_MS + 1))).await;
}

/// What a round brought: (index into the wanted list, ciphertext, plaintext).
#[derive(Debug, Default)]
pub struct SeekRound {
    pub got: Vec<(usize, Vec<u8>, Vec<u8>)>,
    /// How many of the wanted chunks the peer said it holds.
    pub held: usize,
    /// How many of the wanted chunks were asked about (a private round asks a slice).
    pub asked: usize,
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
    let mut round = SeekRound { held: pulled.held, asked: pulled.asked, requests: pulled.requests, got: Vec::new() };
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
    /// How many of the wanted chunks were asked about (a private round asks a slice).
    pub asked: usize,
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

    let plan: Vec<Option<usize>> = if per_item { private_plan(wanted.len()) } else { (0..wanted.len()).map(Some).collect() };
    let mut held = Vec::new();
    for batch in plan.chunks(have_batch) {
        let items: Vec<([u8; HAVE_PREFIX], [u8; 16])> = batch
            .iter()
            .map(|item| match item {
                Some(i) => {
                    let prefix: [u8; HAVE_PREFIX] = wanted[*i].0.as_bytes()[..HAVE_PREFIX].try_into().unwrap();
                    (prefix, wanted[*i].1.have_proof(&nonce, &prefix))
                }
                // A decoy: a random prefix (like a hash's) and a random proof.
                None => {
                    let mut decoy = [0u8; HAVE_PREFIX + 16];
                    getrandom::fill(&mut decoy).expect("OS entropy");
                    (decoy[..HAVE_PREFIX].try_into().unwrap(), decoy[HAVE_PREFIX..].try_into().unwrap())
                }
            })
            .collect();
        if per_item && round.requests > 0 {
            jitter().await;
        }
        round.requests += 1;
        let resp = tokio::time::timeout(timeout, transport.request(link, HAVE_ENDPOINT, encode_have(&items)))
            .await
            .map_err(|_| "have: timed out".to_string())??;
        let bits = decode_bitmap(&resp, batch.len()).map_err(|e| e.to_string())?;
        held.extend(batch.iter().zip(bits).filter_map(|(i, h)| i.filter(|_| h)));
    }
    round.held = held.len();
    round.asked = plan.iter().filter(|i| i.is_some()).count();

    for batch in held.chunks(get_batch) {
        if per_item {
            jitter().await;
        }
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
