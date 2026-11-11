//! Fetcher tests over an in-memory "network": peers with latency, peers that
//! lack chunks, peers that fail every request, peers that return corrupt data.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use retifs_core::{manifest, ChunkToken, Cid, ConvergenceSecret, FileRef, Store};
use retifs_net::{
    fetch::{fetch_file, FetchError, FetchOpts, NoCache},
    protocol::HAVE_ENDPOINT,
    seek::seek_round,
    serve,
    transport::Transport,
};

#[derive(Default, Clone)]
struct MemStore(HashMap<Cid, Vec<u8>>);

impl Store for MemStore {
    type Error = std::convert::Infallible;
    fn put(&mut self, cid: Cid, ct: Vec<u8>) -> Result<(), Self::Error> {
        self.0.insert(cid, ct);
        Ok(())
    }
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(cid).cloned())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    Good,
    FailAll,
    Corrupt,
}

struct Peer {
    chunks: HashMap<Cid, Vec<u8>>,
    behaviour: Behaviour,
    delay: Duration,
    requests: AtomicUsize,
    /// If set, serve only items carrying a valid proof for their chunk's token.
    tokens: Option<HashMap<Cid, ChunkToken>>,
}

#[derive(Clone)]
struct MemTransport(Arc<Vec<Peer>>);

impl Transport for MemTransport {
    type Peer = usize;
    type Link = usize;

    #[allow(clippy::manual_async_fn)] // the trait requires a `Send` future
    fn connect(&self, peer: usize) -> impl Future<Output = Result<usize, String>> + Send {
        async move { Ok(peer) }
    }

    fn link_nonce(&self, link: usize) -> Vec<u8> {
        format!("link-{link}").into_bytes()
    }

    fn request(&self, link: usize, endpoint: &'static str, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        let peers = self.0.clone();
        async move {
            let peer = &peers[link];
            peer.requests.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(peer.delay).await;
            if peer.behaviour == Behaviour::FailAll {
                return Err("link broke".into());
            }
            // The daemon's own serving code (retifs_net::serve), over this peer's chunks.
            let nonce = format!("link-{link}").into_bytes();
            let answer = if endpoint == HAVE_ENDPOINT { serve::answer_have(peer, &nonce, &body) } else { serve::answer_get(peer, &nonce, &body) };
            answer.map_err(|e| format!("{e:?}"))
        }
    }
}

/// A test peer's chunks as the serving side sees them: with `tokens`, each
/// chunk is served under its token; without, every chunk is published.
impl serve::Holdings for Peer {
    fn serving_info(&self, cids: &[Cid]) -> Vec<(Option<ChunkToken>, bool)> {
        cids.iter()
            .map(|c| match (&self.tokens, self.chunks.contains_key(c)) {
                (_, false) => (None, false),
                (None, true) => (None, true),
                (Some(t), true) => (t.get(c).cloned(), false),
            })
            .collect()
    }

    fn served_by_prefix(&self, prefix: &[u8; retifs_net::protocol::HAVE_PREFIX]) -> Option<(Cid, Option<ChunkToken>, bool)> {
        let cid = *self.chunks.keys().find(|c| &c.as_bytes()[..prefix.len()] == prefix)?;
        Some(match &self.tokens {
            None => (cid, None, true),
            Some(t) => (cid, t.get(&cid).cloned(), false),
        })
    }

    fn present(&self, cid: &Cid) -> bool {
        self.chunks.contains_key(cid)
    }

    fn chunk(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.chunks.get(cid).cloned().map(|mut ct| {
            if self.behaviour == Behaviour::Corrupt {
                ct[20] ^= 1;
            }
            ct
        })
    }
}

fn noise(len: usize, mut s: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

fn file(len: usize) -> (Vec<u8>, FileRef, MemStore) {
    let data = noise(len, len as u64 + 3);
    let mut store = MemStore::default();
    let f = manifest::write(&mut store, &ConvergenceSecret::personal([7; 32]), &data).unwrap();
    (data, f, store)
}

/// The access tokens an owner registers for every blob of a file.
fn tokens_for(data: &[u8]) -> HashMap<Cid, ChunkToken> {
    let mut scratch = MemStore::default();
    let (_, blobs) =
        manifest::write_tracked(&mut scratch, &ConvergenceSecret::personal([7; 32]), data, Default::default()).unwrap();
    blobs.into_iter().map(|(c, s)| (c, ChunkToken::for_seed(&s))).collect()
}

fn peer(chunks: HashMap<Cid, Vec<u8>>, behaviour: Behaviour, delay_ms: u64) -> Peer {
    Peer { chunks, behaviour, delay: Duration::from_millis(delay_ms), requests: AtomicUsize::new(0), tokens: None }
}

fn opts() -> FetchOpts {
    FetchOpts { batch: 16, inflight_per_link: 1, timeout: Duration::from_secs(5) }
}

#[tokio::test]
async fn single_link_roundtrip() {
    let (data, f, store) = file(2_000_000);
    let net = MemTransport(Arc::new(vec![peer(store.0, Behaviour::Good, 1)]));
    let (out, stats) = fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data);
    assert_eq!(stats.retries, 0);
    assert!(stats.tree_levels >= 2);
}

/// On a high-latency path, links multiply throughput (decryption is not the bottleneck).
/// Runs on paused (virtual) time so only link latency is measured, not CPU load from
/// other tests running in parallel.
#[tokio::test(start_paused = true)]
async fn more_links_are_faster() {
    let (data, f, store) = file(2_000_000);
    let net = MemTransport(Arc::new((0..4).map(|_| peer(store.0.clone(), Behaviour::Good, 80)).collect()));

    let t = tokio::time::Instant::now();
    fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap();
    let one = t.elapsed();

    let t = tokio::time::Instant::now();
    let (out, _) = fetch_file(&net, &[0, 1, 2, 3], &f, opts(), &mut NoCache).await.unwrap();
    let four = t.elapsed();
    assert_eq!(out, data);
    assert!(four * 2 < one, "4 links {four:?} vs 1 link {one:?}");
}

#[tokio::test]
async fn multi_source_fills_gaps() {
    let (data, f, store) = file(1_500_000);
    // Peer A has only every other chunk, plus all manifest nodes; peer B has everything.
    let leaves: Vec<Cid> = store.0.keys().copied().collect();
    let half: HashMap<Cid, Vec<u8>> = leaves.iter().enumerate()
        .filter(|(i, _)| i % 2 == 0).map(|(_, c)| (*c, store.0[c].clone())).collect();
    let net = MemTransport(Arc::new(vec![peer(half, Behaviour::Good, 1), peer(store.0.clone(), Behaviour::Good, 1)]));
    let (out, stats) = fetch_file(&net, &[0, 1], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data);
    assert!(stats.retries > 0);
}

#[tokio::test]
async fn failing_and_corrupt_peers_are_routed_around() {
    let (data, f, store) = file(800_000);
    let net = MemTransport(Arc::new(vec![
        peer(store.0.clone(), Behaviour::FailAll, 1),
        peer(store.0.clone(), Behaviour::Corrupt, 1),
        peer(store.0.clone(), Behaviour::Good, 1),
    ]));
    let (out, stats) = fetch_file(&net, &[0, 1, 2], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data);
    assert!(stats.retries > 0);
}

#[tokio::test]
async fn unavailable_everywhere_is_an_error() {
    let (_, f, mut store) = file(300_000);
    let victim = *store.0.keys().find(|c| **c != f.root).unwrap();
    store.0.remove(&victim);
    let net = MemTransport(Arc::new(vec![peer(store.0.clone(), Behaviour::Good, 1), peer(store.0, Behaviour::Corrupt, 1)]));
    let err = fetch_file(&net, &[0, 1], &f, opts(), &mut NoCache).await.unwrap_err();
    assert!(matches!(err, FetchError::Unavailable { .. }), "{err}");
}

#[tokio::test]
async fn local_cache_is_used_first_and_filled() {
    let (data, f, store) = file(1_000_000);
    let net = MemTransport(Arc::new(vec![peer(store.0, Behaviour::Good, 1)]));
    let mut cache = MemStore::default();

    let (_, cold) = fetch_file(&net, &[0], &f, opts(), &mut cache).await.unwrap();
    assert_eq!(cold.cache_hits, 0);
    let sent = net.0[0].requests.load(Ordering::Relaxed);

    let (out, warm) = fetch_file(&net, &[0], &f, opts(), &mut cache).await.unwrap();
    assert_eq!(out, data);
    assert_eq!(warm.requests, 0, "everything came from the local store");
    assert_eq!(net.0[0].requests.load(Ordering::Relaxed), sent);
    assert!(warm.cache_hits > 0);
}

#[tokio::test]
async fn peers_serve_only_with_a_valid_proof() {
    let (data, f, store) = file(300_000);
    let mut strict = peer(store.0.clone(), Behaviour::Good, 1);
    strict.tokens = Some(tokens_for(&data));
    let net = MemTransport(Arc::new(vec![strict]));
    let (out, _) = fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data, "the read-cap holder proves each chunk and is served");

    // A forged read-cap (right root CID, wrong seed) yields wrong per-chunk proofs.
    let mut strict = peer(store.0, Behaviour::Good, 1);
    strict.tokens = Some(tokens_for(&data));
    let net = MemTransport(Arc::new(vec![strict]));
    let forged = FileRef { seed: retifs_core::Seed([0xEE; 32]), ..f };
    let err = fetch_file(&net, &[0], &forged, opts(), &mut NoCache).await.unwrap_err();
    assert!(matches!(err, FetchError::Unavailable { .. }), "without the seed, a node looks like it has nothing: {err}");
}

#[tokio::test]
async fn padding_is_fetched_and_stripped() {
    let (data, f, store) = file(1_100_000);
    let net = MemTransport(Arc::new(vec![peer(store.0.clone(), Behaviour::Good, 1)]));
    let (out, stats) = fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data, "exactly the file, no padding bytes");
    let data_blobs = store.0.values().filter(|c| c.len() == 16_384).count();
    assert_eq!(stats.chunks, data_blobs, "padding chunks were requested like real ones");
}

#[tokio::test]
async fn one_chunk_per_request_works() {
    let (data, f, store) = file(400_000);
    let net = MemTransport(Arc::new(vec![peer(store.0, Behaviour::Good, 1)]));
    let (out, stats) = fetch_file(&net, &[0], &f, FetchOpts { batch: 1, ..opts() }, &mut NoCache).await.unwrap();
    assert_eq!(out, data);
    assert_eq!(stats.requests, stats.chunks + 1, "one request per blob: every chunk plus the root node");
}

/// The (CID, seed) of every data chunk of a small file (its root is a leaf).
fn leaves(f: &FileRef, store: &MemStore) -> Vec<(Cid, retifs_core::Seed)> {
    let root = retifs_core::open(&f.root, &f.seed, &store.0[&f.root]).unwrap();
    let node = retifs_core::manifest::decode_root(&root, f.size).unwrap();
    assert!(node.leaf);
    node.entries.iter().map(|e| (e.cid, e.seed)).collect()
}

#[tokio::test(start_paused = true)]
async fn seeking_rounds_fill_gaps_from_whichever_peer_has_them() {
    let (data, f, store) = file(400_000);
    let want = leaves(&f, &store);
    let n = want.len();
    // Peer 0 holds the first half of the data chunks, peer 1 the second half.
    let half = |range: std::ops::Range<usize>| -> HashMap<Cid, Vec<u8>> {
        want[range].iter().map(|(c, _)| (*c, store.0[c].clone())).collect()
    };
    let mut p0 = peer(half(0..n / 2), Behaviour::Good, 1);
    let mut p1 = peer(half(n / 2..n), Behaviour::Good, 1);
    p0.tokens = Some(tokens_for(&data));
    p1.tokens = Some(tokens_for(&data));
    let net = MemTransport(Arc::new(vec![p0, p1]));
    let t = Duration::from_secs(5);

    let r0 = seek_round(&net, 0, &want, false, t).await.unwrap();
    assert_eq!((r0.held, r0.got.len()), (n / 2, n / 2));
    let mut by_cid: HashMap<Cid, Vec<u8>> = HashMap::new();
    for (i, _, pt) in &r0.got {
        by_cid.insert(want[*i].0, pt.clone());
    }
    // Private rounds: one item per request, a slice of the wants each time,
    // decoys mixed in. The second peer fills the rest over a few rounds.
    let mut rounds = 0;
    loop {
        let still: Vec<_> = want.iter().filter(|(c, _)| !by_cid.contains_key(c)).copied().collect();
        if still.is_empty() {
            break;
        }
        let r = seek_round(&net, 1, &still, true, t).await.unwrap();
        assert!(r.asked <= retifs_net::seek::PRIVATE_SLICE && r.asked == still.len().min(retifs_net::seek::PRIVATE_SLICE));
        let decoys = r.asked.div_ceil(retifs_net::seek::DECOY_EVERY);
        assert_eq!(r.requests, r.asked + decoys + r.held, "one have per item and decoy, one get per held item");
        assert_eq!(r.held, r.got.len());
        for (i, _, pt) in &r.got {
            by_cid.insert(still[*i].0, pt.clone());
        }
        rounds += 1;
        assert!(rounds < 100);
    }
    assert_eq!(rounds, (n - n / 2).div_ceil(retifs_net::seek::PRIVATE_SLICE));
    let joined: Vec<u8> = want.iter().flat_map(|(c, _)| by_cid[c].clone()).collect();
    assert_eq!(&joined[..data.len()], &data[..], "data, then padding");
}

#[tokio::test]
async fn have_reveals_nothing_without_the_read_cap() {
    let (data, f, store) = file(300_000);
    let want = leaves(&f, &store);
    let mut p = peer(store.0.clone(), Behaviour::Good, 1);
    p.tokens = Some(tokens_for(&data));
    let net = MemTransport(Arc::new(vec![p]));
    // A prober knows the CIDs but not the seeds.
    let probe: Vec<_> = want.iter().map(|(c, _)| (*c, retifs_core::Seed([0x42; 32]))).collect();
    let r = seek_round(&net, 0, &probe, false, Duration::from_secs(5)).await.unwrap();
    assert_eq!((r.held, r.got.len()), (0, 0), "a prober learns nothing from have or get");
}

