//! Fetching a whole file by read-cap.
//!
//! - **Local first:** chunks already in the local store are not fetched.
//! - **Breadth-first** over the manifest tree; each level is one parallel round.
//! - **Batched** `/retifs/get` requests, spread over **several links**, which
//!   may go to the same peer (parallelism) or different peers (multi-source).
//! - A chunk a peer lacks, or a batch whose request fails, is retried on a
//!   link not yet tried for it. A fetch fails only when every link has failed
//!   to deliver a valid copy.
//!
//! See docs/recon/chunk-fetch.md and first-transfer.md for the measurements
//! behind batching and the one-request-per-link default.

use std::{
    collections::VecDeque,
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use retifs_core::{
    manifest::{decode_node, decode_root, NodeEntry},
    open, ChunkToken, Cid, FileRef, ManifestError, Store,
};
use tokio::{sync::Notify, task::JoinSet};

use crate::{
    protocol::{decode_response, encode_request, GET_ENDPOINT, MAX_BATCH},
    transport::Transport,
};

#[derive(Debug, Clone, Copy)]
pub struct FetchOpts {
    /// Chunks per request. 1 = one chunk per request (one packet each): a peer
    /// then can't group chunks by request either (privacy mode, ADR-0010).
    pub batch: usize,
    /// Requests in flight per link.
    ///
    /// Default 1: with Prns 0.3.7, several Resource-sized responses in flight on
    /// one Link can stall (docs/recon/first-transfer.md). Use more links instead.
    pub inflight_per_link: usize,
    /// Give up on a request after this long; the batch is retried elsewhere.
    pub timeout: Duration,
}

impl Default for FetchOpts {
    fn default() -> Self {
        FetchOpts { batch: 32, inflight_per_link: 1, timeout: Duration::from_secs(60) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FetchStats {
    pub chunks: usize,
    pub tree_levels: usize,
    pub requests: usize,
    pub retries: usize,
    pub network_bytes: u64,
    pub cache_hits: usize,
}

#[derive(Debug)]
pub enum FetchError {
    TooManyLinks,
    /// No link delivered a valid copy (missing everywhere, corrupt, or all requests failed).
    Unavailable { cid: Cid, last_error: String },
    Manifest(ManifestError),
    Cache(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::TooManyLinks => f.write_str("at most 64 links"),
            FetchError::Unavailable { cid, last_error } => write!(f, "no peer delivered chunk {cid} ({last_error})"),
            FetchError::Manifest(e) => write!(f, "{e}"),
            FetchError::Cache(e) => write!(f, "local store: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// A store that holds nothing, for fetching without a local cache.
pub struct NoCache;

impl Store for NoCache {
    type Error = std::convert::Infallible;
    fn put(&mut self, _cid: Cid, _ciphertext: Vec<u8>) -> Result<(), Self::Error> {
        Ok(())
    }
    fn get(&self, _cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }
}

/// Fetches and verifies the whole file behind `file`. With no `links`, only
/// the local store is used.
pub async fn fetch_file<T: Transport>(
    transport: &T,
    links: &[T::Link],
    file: &FileRef,
    opts: FetchOpts,
    cache: &mut impl Store,
) -> Result<(Vec<u8>, FetchStats), FetchError> {
    if links.len() > 64 {
        return Err(FetchError::TooManyLinks);
    }
    let mut stats = FetchStats::default();
    let mut level = vec![NodeEntry { cid: file.root, seed: file.seed, span: file.size }];

    let chunks = loop {
        stats.tree_levels += 1;
        let opened = fetch_level(transport, links, &level, opts, cache, &mut stats).await?;
        let mut next = Vec::new();
        let mut leaves = None;
        for (entry, plaintext) in level.iter().zip(opened) {
            let node = if stats.tree_levels == 1 {
                decode_root(&plaintext, entry.span) // a padded tree may cover more than the file
            } else {
                decode_node(&plaintext, entry.span)
            }
            .map_err(FetchError::Manifest)?;
            if let Some(data) = node.inline {
                // A tiny file lives entirely in its root node (ADR-0013).
                if stats.tree_levels != 1 || level.len() != 1 {
                    return Err(FetchError::Manifest(ManifestError::Malformed("inline node outside the root")));
                }
                return Ok((data, stats));
            }
            if leaves.is_some_and(|l| l != node.leaf) {
                return Err(FetchError::Manifest(ManifestError::Malformed("mixed node kinds on one level")));
            }
            leaves = Some(node.leaf);
            next.extend(node.entries);
        }
        if leaves == Some(true) {
            break next;
        }
        level = next;
    };

    // Padding chunks are fetched like real ones, so request volume matches the
    // padded size and reveals only the PADMÉ bucket (ADR-0008).
    let data = fetch_level(transport, links, &chunks, opts, cache, &mut stats).await?;
    let mut out = Vec::with_capacity(file.size as usize);
    for (entry, piece) in chunks.iter().zip(data) {
        if piece.len() as u64 != entry.span {
            return Err(FetchError::Manifest(ManifestError::Malformed("chunk length differs from its entry")));
        }
        out.extend_from_slice(&piece);
    }
    out.truncate(file.size as usize);
    stats.chunks += chunks.len();
    Ok((out, stats))
}

/// Opens `entries` in order: from the local store where possible, the rest over the network.
async fn fetch_level<T: Transport>(
    transport: &T,
    links: &[T::Link],
    entries: &[NodeEntry],
    opts: FetchOpts,
    cache: &mut impl Store,
    stats: &mut FetchStats,
) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut opened: Vec<Option<Vec<u8>>> = vec![None; entries.len()];
    let mut needed = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let local = cache.get(&e.cid).map_err(|err| FetchError::Cache(err.to_string()))?;
        match local.and_then(|ct| open(&e.cid, &e.seed, &ct).ok()) {
            Some(pt) => {
                opened[i] = Some(pt);
                stats.cache_hits += 1;
            }
            None => needed.push(*e),
        }
    }

    if !needed.is_empty() {
        let mut fetched = fetch_remote(transport, links, needed, opts, stats).await?.into_iter();
        for (slot, e) in opened.iter_mut().zip(entries) {
            if slot.is_none() {
                let (ct, pt) = fetched.next().expect("one result per needed entry");
                cache.put(e.cid, ct).map_err(|err| FetchError::Cache(err.to_string()))?;
                *slot = Some(pt);
            }
        }
    }
    Ok(opened.into_iter().map(|o| o.expect("every entry opened")).collect())
}

/// A fetched chunk: (ciphertext for the local store, opened plaintext).
type Fetched = (Vec<u8>, Vec<u8>);

struct Job {
    indices: Vec<usize>,
    /// Bit i set: link i already failed to deliver these.
    tried: u64,
    last_error: String,
}

struct Shared {
    entries: Vec<NodeEntry>,
    queue: Mutex<VecDeque<Job>>,
    results: Mutex<Vec<Option<Fetched>>>,
    failure: Mutex<Option<FetchError>>,
    done: AtomicUsize,
    requests: AtomicUsize,
    retries: AtomicUsize,
    bytes: AtomicU64,
    wake: Notify,
}

impl Shared {
    fn finished(&self) -> bool {
        self.failure.lock().unwrap().is_some() || self.done.load(Ordering::Acquire) == self.entries.len()
    }

    fn fail(&self, error: FetchError) {
        self.failure.lock().unwrap().get_or_insert(error);
        self.wake.notify_waiters();
    }

    /// Requeues `indices` for other links, or fails if every link has tried them.
    fn retry(&self, indices: Vec<usize>, tried: u64, all: u64, last_error: String) {
        if tried == all {
            let cid = self.entries[indices[0]].cid;
            self.fail(FetchError::Unavailable { cid, last_error });
        } else {
            self.retries.fetch_add(1, Ordering::Relaxed);
            self.queue.lock().unwrap().push_back(Job { indices, tried, last_error });
            self.wake.notify_waiters();
        }
    }
}

/// Fetches `entries` over all links; returns (ciphertext, plaintext) in order.
async fn fetch_remote<T: Transport>(
    transport: &T,
    links: &[T::Link],
    entries: Vec<NodeEntry>,
    opts: FetchOpts,
    stats: &mut FetchStats,
) -> Result<Vec<Fetched>, FetchError> {
    if links.is_empty() {
        return Err(FetchError::Unavailable { cid: entries[0].cid, last_error: "not held locally and no peers given".into() });
    }
    let batch = opts.batch.clamp(1, MAX_BATCH);
    let n = entries.len();
    let queue = (0..n)
        .collect::<Vec<_>>()
        .chunks(batch)
        .map(|c| Job { indices: c.to_vec(), tried: 0, last_error: String::new() })
        .collect();
    let shared = Arc::new(Shared {
        entries,
        queue: Mutex::new(queue),
        results: Mutex::new(vec![None; n]),
        failure: Mutex::new(None),
        done: AtomicUsize::new(0),
        requests: AtomicUsize::new(0),
        retries: AtomicUsize::new(0),
        bytes: AtomicU64::new(0),
        wake: Notify::new(),
    });
    let all: u64 = if links.len() == 64 { u64::MAX } else { (1u64 << links.len()) - 1 };

    let mut workers = JoinSet::new();
    for (me, &link) in links.iter().enumerate() {
        for _ in 0..opts.inflight_per_link.max(1) {
            workers.spawn(worker(transport.clone(), link, me, all, shared.clone(), opts.timeout));
        }
    }
    while workers.join_next().await.is_some() {}

    stats.requests += shared.requests.load(Ordering::Relaxed);
    stats.retries += shared.retries.load(Ordering::Relaxed);
    stats.network_bytes += shared.bytes.load(Ordering::Relaxed);
    if let Some(e) = shared.failure.lock().unwrap().take() {
        return Err(e);
    }
    let results = std::mem::take(&mut *shared.results.lock().unwrap());
    Ok(results.into_iter().map(|r| r.expect("every entry fetched")).collect())
}

async fn worker<T: Transport>(
    transport: T,
    link: T::Link,
    me: usize,
    all: u64,
    shared: Arc<Shared>,
    timeout: Duration,
) {
    let bit = 1u64 << me;
    let nonce = transport.link_nonce(link);
    loop {
        if shared.finished() {
            return;
        }
        let job = {
            let mut q = shared.queue.lock().unwrap();
            q.iter().position(|j| j.tried & bit == 0).and_then(|p| q.remove(p))
        };
        let Some(job) = job else {
            // Nothing this link may take right now; wait for requeues or completion.
            let _ = tokio::time::timeout(Duration::from_millis(50), shared.wake.notified()).await;
            continue;
        };

        let cids: Vec<Cid> = job.indices.iter().map(|&i| shared.entries[i].cid).collect();
        shared.requests.fetch_add(1, Ordering::Relaxed);
        // Each item proves access with its own chunk's seed: no file token on the wire.
        let items: Vec<(Cid, [u8; 16])> = job
            .indices
            .iter()
            .map(|&i| {
                let e = shared.entries[i];
                (e.cid, ChunkToken::for_seed(&e.seed).get_proof(&nonce, &e.cid))
            })
            .collect();
        let body = encode_request(&items);
        let response = tokio::time::timeout(timeout, transport.request(link, GET_ENDPOINT, body)).await;
        let tried = job.tried | bit;
        let items = match response {
            Err(_) => Err(format!("request timed out after {timeout:?}")),
            Ok(Err(e)) => Err(e),
            Ok(Ok(body)) => decode_response(&body, cids.len()).map_err(|e| e.to_string()),
        };
        let items = match items {
            Ok(items) => items,
            Err(e) => {
                shared.retry(job.indices, tried, all, e);
                continue;
            }
        };

        let mut missing = Vec::new();
        let mut last_error = job.last_error;
        for (&i, item) in job.indices.iter().zip(items) {
            let entry = shared.entries[i];
            let Some(ct) = item else {
                missing.push(i);
                last_error = "not held by any peer tried".into();
                continue;
            };
            shared.bytes.fetch_add(ct.len() as u64, Ordering::Relaxed);
            match open(&entry.cid, &entry.seed, &ct) {
                Ok(pt) => {
                    shared.results.lock().unwrap()[i] = Some((ct, pt));
                    shared.done.fetch_add(1, Ordering::AcqRel);
                }
                Err(e) => {
                    missing.push(i);
                    last_error = format!("corrupt copy: {e}");
                }
            }
        }
        if missing.is_empty() {
            shared.wake.notify_waiters();
        } else {
            shared.retry(missing, tried, all, last_error);
        }
    }
}
