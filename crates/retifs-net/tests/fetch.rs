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

use retifs_core::{manifest, Cid, ConvergenceSecret, FileRef, ServeToken, Store};
use retifs_net::{
    fetch::{fetch_file, FetchError, FetchOpts, NoCache},
    protocol::{decode_request, encode_response},
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
    /// If set, serve only to requests carrying a valid proof for this token.
    token: Option<ServeToken>,
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

    fn request(&self, link: usize, _endpoint: &'static str, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        let peers = self.0.clone();
        async move {
            let peer = &peers[link];
            peer.requests.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(peer.delay).await;
            if peer.behaviour == Behaviour::FailAll {
                return Err("link broke".into());
            }
            let req = decode_request(&body).map_err(|e| e.to_string())?;
            let authorized = match &peer.token {
                None => true,
                Some(t) => req.token_id == t.id() && t.verify(format!("link-{link}").as_bytes(), &req.cids, &req.proof),
            };
            if !authorized {
                return Ok(encode_response(&vec![None; req.cids.len()]));
            }
            let items: Vec<Option<Vec<u8>>> = req.cids
                .iter()
                .map(|c| {
                    peer.chunks.get(c).cloned().map(|mut ct| {
                        if peer.behaviour == Behaviour::Corrupt {
                            ct[20] ^= 1;
                        }
                        ct
                    })
                })
                .collect();
            Ok(encode_response(&items))
        }
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

fn peer(chunks: HashMap<Cid, Vec<u8>>, behaviour: Behaviour, delay_ms: u64) -> Peer {
    Peer { chunks, behaviour, delay: Duration::from_millis(delay_ms), requests: AtomicUsize::new(0), token: None }
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
    let right = ServeToken::for_file(&f);
    let wrong = ServeToken::for_file(&FileRef { seed: retifs_core::Seed([0xEE; 32]), ..f });

    let mut strict = peer(store.0.clone(), Behaviour::Good, 1);
    strict.token = Some(right);
    let net = MemTransport(Arc::new(vec![strict]));
    let (out, _) = fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap();
    assert_eq!(out, data, "the read-cap holder proves possession and is served");

    let mut other = peer(store.0, Behaviour::Good, 1);
    other.token = Some(wrong);
    let net = MemTransport(Arc::new(vec![other]));
    let err = fetch_file(&net, &[0], &f, opts(), &mut NoCache).await.unwrap_err();
    assert!(matches!(err, FetchError::Unavailable { .. }), "a node serving another file's token looks like it has nothing: {err}");
}
