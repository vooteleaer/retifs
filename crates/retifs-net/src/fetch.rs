//! Fetching a whole file by read-cap: breadth-first over the manifest tree,
//! batched `/retifs/get` requests with several in flight (see
//! docs/recon/chunk-fetch.md: batching wins on high-latency paths, pipelining
//! on fast links, so do both).

use std::{fmt, sync::Arc, time::Duration};

use personal_rns::prelude::*;
use personal_rns::routing::links::LinkId;
use retifs_core::{
    open,
    manifest::{decode_node, NodeEntry},
    Cid, FileRef, ManifestError,
};
use tokio::{sync::Semaphore, task::JoinSet};

use crate::protocol::{decode_response, encode_request, GET_ENDPOINT, MAX_BATCH};

#[derive(Debug, Clone, Copy)]
pub struct FetchOpts {
    /// CIDs per request.
    pub batch: usize,
    /// Requests in flight at once on the link.
    ///
    /// Default 1: with Prns 0.3.7, several Resource-sized responses in flight on
    /// one Link can stall forever (seen 2026-10-14: 3 of 45 batches never
    /// settled with 4 in flight; 1 in flight completed every time).
    pub inflight: usize,
    /// Give up on a request after this long instead of waiting forever.
    pub timeout: Duration,
}

impl Default for FetchOpts {
    fn default() -> Self {
        FetchOpts { batch: 32, inflight: 1, timeout: Duration::from_secs(60) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FetchStats {
    pub requests: usize,
    pub chunks: usize,
    pub ciphertext_bytes: u64,
    pub tree_levels: usize,
}

#[derive(Debug)]
pub enum FetchError {
    Transport(String),
    Protocol(String),
    Missing(Cid),
    Corrupt(Cid, String),
    Manifest(ManifestError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Transport(e) => write!(f, "transport: {e}"),
            FetchError::Protocol(e) => write!(f, "{e}"),
            FetchError::Missing(c) => write!(f, "peer doesn't hold chunk {c}"),
            FetchError::Corrupt(c, e) => write!(f, "chunk {c} failed verification: {e}"),
            FetchError::Manifest(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Fetches and verifies the whole file behind `file` from the peer on `link`.
pub async fn fetch_file(
    handle: &PrnsNodeHandle,
    link: LinkId,
    file: &FileRef,
    opts: FetchOpts,
) -> Result<(Vec<u8>, FetchStats), FetchError> {
    let mut stats = FetchStats::default();
    let mut level = vec![NodeEntry { cid: file.root, seed: file.seed, span: file.size }];

    // Walk the manifest one level at a time; every level is one batched round.
    let chunks = loop {
        stats.tree_levels += 1;
        let opened = fetch_many(handle, link, &level, opts, &mut stats).await?;
        let mut next = Vec::new();
        let mut leaves = None;
        for (entry, plaintext) in level.iter().zip(opened) {
            let node = decode_node(&plaintext, entry.span).map_err(FetchError::Manifest)?;
            match (leaves, node.leaf) {
                (None, leaf) => leaves = Some(leaf),
                (Some(l), leaf) if l != leaf => {
                    return Err(FetchError::Manifest(ManifestError::Malformed("mixed node kinds on one level")));
                }
                _ => {}
            }
            next.extend(node.entries);
        }
        if leaves == Some(true) {
            break next;
        }
        level = next;
    };

    let data = fetch_many(handle, link, &chunks, opts, &mut stats).await?;
    let mut out = Vec::with_capacity(file.size as usize);
    for (entry, piece) in chunks.iter().zip(data) {
        if piece.len() as u64 != entry.span {
            return Err(FetchError::Manifest(ManifestError::Malformed("chunk length differs from its entry")));
        }
        out.extend_from_slice(&piece);
    }
    stats.chunks += chunks.len();
    Ok((out, stats))
}

/// Fetches, verifies and opens `entries` in order, `opts.inflight` batches at a time.
async fn fetch_many(
    handle: &PrnsNodeHandle,
    link: LinkId,
    entries: &[NodeEntry],
    opts: FetchOpts,
    stats: &mut FetchStats,
) -> Result<Vec<Vec<u8>>, FetchError> {
    let batch = opts.batch.clamp(1, MAX_BATCH);
    let permits = Arc::new(Semaphore::new(opts.inflight.max(1)));
    let mut tasks = JoinSet::new();
    for (index, group) in entries.chunks(batch).enumerate() {
        let group = group.to_vec();
        let handle = handle.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            let cids: Vec<Cid> = group.iter().map(|e| e.cid).collect();
            let body = encode_request(&cids);
            let request = handle.request(link, RequestEndpointId::of(GET_ENDPOINT), &body);
            let (response, _rtt) = tokio::time::timeout(opts.timeout, request)
                .await
                .map_err(|_| FetchError::Transport(format!("request for batch {index} timed out")))?
                .map_err(|e| FetchError::Transport(format!("{e:?}")))?;
            let items = decode_response(response.as_slice(), cids.len())
                .map_err(|e| FetchError::Protocol(e.to_string()))?;
            let mut bytes = 0u64;
            let mut opened = Vec::with_capacity(group.len());
            for (entry, item) in group.iter().zip(items) {
                let ct = item.ok_or(FetchError::Missing(entry.cid))?;
                bytes += ct.len() as u64;
                opened.push(open(&entry.cid, &entry.seed, &ct).map_err(|e| FetchError::Corrupt(entry.cid, e.to_string()))?);
            }
            Ok::<_, FetchError>((index, opened, bytes))
        });
    }

    let total = entries.len().div_ceil(batch);
    let mut results: Vec<Option<Vec<Vec<u8>>>> = vec![None; total];
    while let Some(joined) = tasks.join_next().await {
        let (index, opened, bytes) = joined.map_err(|e| FetchError::Transport(e.to_string()))??;
        stats.requests += 1;
        stats.ciphertext_bytes += bytes;
        results[index] = Some(opened);
        if std::env::var_os("RETIFS_DEBUG").is_some() {
            eprintln!("  batch {index} done ({} of {total})", results.iter().filter(|r| r.is_some()).count());
        }
    }
    Ok(results.into_iter().flat_map(|r| r.expect("every batch completed")).collect())
}
