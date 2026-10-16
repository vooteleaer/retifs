//! retifsd (prototype): the retifs shared instance.
//!
//!     retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE]
//!             [--private-requests] [--hold-for-others SIZE] [--lease-term DURATION] [--loss-target P]
//!             [--public] [--put FILE]...
//!
//! SIZE: bytes, or with a K/M/G/T suffix (powers of 1024). Defaults (ADR-0012):
//! store limit 50 % of the volume, reserve max(10 %, 5 GiB), cache 20 % of the limit.
//! `--hold-for-others`: hold leased data for others up to SIZE (default: up to the
//! store limit; 0 opts out). Every node is a storage node by default (ADR-0014).
//! `--slow-link-budget`: the most a file may take over a slow link (LoRa class) before
//! only its manifest is fetched and the rest waits for a faster path (default 10m).
//! `--treat-as-slow NODE`: testing only; plan as if NODE were behind LoRa.
//! `--stamp-cost`: proof of work (bits, LXMF stamps) asked of every lease offer to this
//! node (default 20 bits: about 0.1 s per lease on a desktop, a few seconds on a Pi;
//! 0: none). `--max-stamp-cost`: the most this node pays when offering leases (default 24).
//! A solver reuses the hash state after the workblock, so each try costs one small hash.
//! `--loss-target`: keep adding nearby holders for each needed file until the
//! estimated chance of losing every copy is below P (default 0.001).
//! `--lease-term`: how long leases this node gives out run before renewal is
//! due (seconds, or with an s/m/h/d suffix; default 30d). They're renewed at half-term.
//!
//! - Owns the slab store (default: libretifs::default_store_dir()).
//! - Attaches to the local prnsd as a shared-instance client and serves chunks
//!   to other nodes at `/retifs/get`.
//! - Serves the local API (ADR-0004) to apps via libretifs: put, get, status.
//!
//! `--put` imports files at startup (kept for scripting); normally use
//! `retifs put` while the daemon runs.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libretifs::{read_frame, write_frame, Envelope, GetStats, Request, Response, Status, PROTOCOL_VERSION};
use personal_rns::prelude::*;
use retifs_core::{
    lease::{self, node_destination, Lease, LeaseId, LeaseKey, Receipt, Renewal},
    stamp,
    manifest::{self, decode_node, decode_root, NodeEntry},
    open, ChunkToken, Cid, ConvergenceSecret, FileRef,
};
use personal_rns::node_introspection::DestinationIdentityQuery;
use personal_rns::routing::links::LinkId;
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{self, attach, block_on, destination, destination_hex, load_or_create_identity, parse_destination},
    protocol::{
        decode_have, decode_lease_request, decode_lease_status, decode_lease_statuses, decode_prove, decode_prove_reply,
        decode_receipt_replies, decode_receipt_request, encode_receipt_replies, encode_receipt_request, MAX_BUNDLE,
        decode_request, encode_bitmap, encode_lease_request, encode_prove, encode_prove_reply,
        encode_lease_status, encode_response, LeaseRequest, LeaseStatus, ReceiptReply, GET_ENDPOINT, HAVE_ENDPOINT, LEASE_ENDPOINT,
        PROVE_ENDPOINT, RECEIPT_ENDPOINT, decode_bitmap, decode_put, encode_have, encode_put, HAVE_PREFIX, MAX_HAVE,
        MAX_PUT, PUT_ENDPOINT,
    },
    seek::{pull_round, seek_round},
    transport::{PrnsTransport, Transport},
};
use retifs_store::{tier, Accept, OwnLease, PeerId, ProofState, Want};
use tokio::sync::{mpsc, Notify};
use retifs_store::{CacheTier, SlabStore};
use tokio::io::{AsyncRead, AsyncWrite};

/// What the request endpoints share (the Prns node's app state).
struct Shared {
    store: Arc<SlabStore>,
    /// The node's RNS identity secret (X25519 ‖ Ed25519): signs receipts.
    identity: [u8; 64],
    /// Bytes of leased chunks this node keeps for others (0: refuse leases;
    /// None: up to the store limit, the default, ADR-0014).
    hold_limit: Option<u64>,
    /// Wakes the lease puller (a lease was accepted).
    pull_wake: Notify,
    /// Bits of proof of work asked of every lease offer (0: none).
    stamp_cost: u8,
}

struct Get;
impl RequestEndpoint<Arc<Shared>> for Get {
    const ENDPOINT_ID: &'static str = GET_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    /// Anonymous requesters prove, per item, that they know the chunk's seed;
    /// published chunks need no proof. Anything else gets the same answer as
    /// "don't have" (holder privacy, ADR-0010). Fetched/cached chunks are never
    /// in the serving index, so they're never served.
    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok(items) = decode_request(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = &context.state.store;
        let nonce = context.respond_token().link_id.as_bytes().to_vec();
        // One lookup for all items; same work on every path, so a refusal
        // doesn't stand out by timing.
        let cids: Vec<_> = items.iter().map(|(c, _)| *c).collect();
        let info = store.serving_info(&cids).unwrap_or_else(|_| vec![(None, false); cids.len()]);
        let out: Vec<Option<Vec<u8>>> = items
            .iter()
            .zip(info)
            .map(|((cid, proof), (token, published))| {
                let ok = published || token.is_some_and(|t| t.verify_get(&nonce, cid, proof));
                if ok { store.fetch(cid).ok().flatten() } else { None }
            })
            .collect();
        context.respond(encode_response(&out))
    }
}

/// `/retifs/have`: which of these CID prefixes do you serve under this token?
/// Same rules as `get`: proof of possession, or published; cache is invisible.
struct Have;
impl RequestEndpoint<Arc<Shared>> for Have {
    const ENDPOINT_ID: &'static str = HAVE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok(items) = decode_have(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = &context.state.store;
        let nonce = context.respond_token().link_id.as_bytes().to_vec();
        let bits: Vec<bool> = items
            .iter()
            .map(|(prefix, proof)| match store.served_by_prefix(prefix) {
                // Leased chunks are in the serving index before they arrive: answer only for what's here.
                Ok(Some((cid, token, published))) => {
                    (published || token.is_some_and(|t| t.verify_have(&nonce, prefix, proof)))
                        && store.tier(&cid).ok().flatten().is_some()
                }
                _ => false,
            })
            .collect();
        context.respond(encode_bitmap(&bits))
    }
}

/// `/retifs/lease`: offers of leases (keep these chunks for me) and renewals.
/// The offer itself is anonymous; what limits it is the hold limit (ADR-0011).
struct LeaseEndpoint;
impl RequestEndpoint<Arc<Shared>> for LeaseEndpoint {
    const ENDPOINT_ID: &'static str = LEASE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let s = context.state.clone();
        let renew = |r: &Renewal| match s.store.held_lease(&r.id) {
            Ok(Some(_)) if s.store.renew_lease(r).unwrap_or(false) => LeaseStatus::Accepted,
            Ok(Some(_)) => LeaseStatus::Invalid,
            _ => LeaseStatus::Unknown,
        };
        let status = match decode_lease_request(context.data) {
            Ok(LeaseRequest::RenewMany(rs)) => return context.respond(rs.iter().map(|r| renew(r).byte()).collect::<Vec<u8>>()),
            Err(_) => LeaseStatus::Invalid,
            Ok(LeaseRequest::Offer { lease, .. }) if lease.expires <= now_s() => LeaseStatus::Invalid,
            // Proof of work against junk leases (ADR-0014), checked before anything is stored.
            Ok(LeaseRequest::Offer { lease, stamp, .. })
                if s.stamp_cost > 0
                    && !stamp.is_some_and(|st| stamp::valid(&stamp::workblock(&stamp::lease_material(&lease)), &st, s.stamp_cost)) =>
            {
                LeaseStatus::StampRequired(s.stamp_cost)
            }
            Ok(LeaseRequest::Offer { lease, sources, .. }) => match s.store.accept_lease(&lease, &sources, s.hold_limit()) {
                Ok(Accept::Accepted) => {
                    println!("lease {}: keeping {} chunk(s) for someone until {}", hex(&lease.id), lease.entries.len(), lease.expires);
                    s.pull_wake.notify_one();
                    LeaseStatus::Accepted
                }
                Ok(Accept::NoRoom) => LeaseStatus::NoRoom,
                Ok(Accept::Conflict) | Err(_) => LeaseStatus::Invalid,
            },
            Ok(LeaseRequest::Renew(r)) => renew(&r),
        };
        context.respond(encode_lease_status(status))
    }
}

/// `/retifs/receipt`: per lease asked about (up to 64 at once), a signed
/// receipt once every chunk is held, else progress.
struct ReceiptEndpoint;
impl RequestEndpoint<Arc<Shared>> for ReceiptEndpoint {
    const ENDPOINT_ID: &'static str = RECEIPT_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok(ids) = decode_receipt_request(context.data) else {
            return Err(Decline::Ignore);
        };
        let s = context.state.clone();
        let replies: Vec<ReceiptReply> = ids
            .iter()
            .map(|id| match s.store.held_lease(id) {
                Ok(Some(h)) if h.held == h.lease.entries.len() => ReceiptReply::Receipt(Receipt::sign(&s.identity, &h.lease, h.expires)),
                Ok(Some(h)) => ReceiptReply::Progress { held: h.held as u16, total: h.lease.entries.len() as u16 },
                _ => ReceiptReply::Unknown,
            })
            .collect();
        context.respond(encode_receipt_replies(&replies))
    }
}

/// `/retifs/prove`: storage proofs for chunks of a held lease (fresh nonce each time).
struct ProveEndpoint;
impl RequestEndpoint<Arc<Shared>> for ProveEndpoint {
    const ENDPOINT_ID: &'static str = PROVE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok((id, nonce, indices)) = decode_prove(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = &context.state.store;
        let answers: Vec<_> = indices
            .iter()
            .map(|&i| store.lease_chunk(&id, i as usize).ok().flatten().map(|ct| lease::prove(&nonce, &ct)))
            .collect();
        context.respond(encode_prove_reply(&answers))
    }
}

/// `/retifs/put`: chunks pushed by whoever holds a lease here (ADR-0014). Only
/// chunks that lease lists are stored; the pusher stays anonymous.
struct PutEndpoint;
impl RequestEndpoint<Arc<Shared>> for PutEndpoint {
    const ENDPOINT_ID: &'static str = PUT_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok((id, chunks)) = decode_put(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = &context.state.store;
        let stored: Vec<bool> = chunks
            .iter()
            .map(|ct| {
                let cid = Cid::of(ct);
                store.lease_covers(&id, &cid).unwrap_or(false) && store.lease_arrived(&cid, ct).unwrap_or(false)
            })
            .collect();
        context.respond(encode_bitmap(&stored))
    }
}

impl Shared {
    /// What's already held for others plus what still fits (within the store
    /// limit and above the free-space reserve), capped by `--hold-for-others`:
    /// a lease the disk can't take is never accepted.
    fn hold_limit(&self) -> u64 {
        let (Ok(u), Ok(l)) = (self.store.usage(), self.store.limits()) else { return 0 };
        let fits = u.leased + l.room().min(l.hard_max.saturating_sub(u.hard()));
        self.hold_limit.map_or(fits, |cap| cap.min(fits))
    }
}

struct Args {
    store: PathBuf,
    public: bool,
    put: Vec<PathBuf>,
    budget: retifs_store::Budget,
    private_requests: bool,
    hold_limit: Option<u64>,
    lease_term: u64,
    loss_target: f64,
    slow_budget: u64,
    treat_as_slow: Vec<PeerId>,
    stamp_cost: u8,
    max_stamp_cost: u8,
}

fn duration_secs(s: &str) -> u64 {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    num.parse::<u64>().unwrap_or_else(|_| panic!("bad duration {s}")) * mult
}

fn size(s: &str) -> u64 {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1 << 20),
        Some('G') => (&s[..s.len() - 1], 1 << 30),
        Some('T') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    let n: f64 = num.parse().unwrap_or_else(|_| panic!("bad size {s}"));
    (n * mult as f64) as u64
}

fn args() -> Args {
    let mut a = Args {
        store: libretifs::default_store_dir(),
        public: false,
        put: Vec::new(),
        budget: Default::default(),
        private_requests: false,
        hold_limit: None,
        lease_term: 30 * 86_400,
        loss_target: 1e-3,
        slow_budget: 600,
        treat_as_slow: Vec::new(),
        stamp_cost: 20,
        max_stamp_cost: 24,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => a.store = it.next().expect("--store DIR").into(),
            "--put" => a.put.push(it.next().expect("--put FILE").into()),
            "--public" => a.public = true,
            "--max-store" => a.budget.max_store = Some(size(&it.next().expect("--max-store SIZE"))),
            "--min-free" => a.budget.min_free = Some(size(&it.next().expect("--min-free SIZE"))),
            "--cache-max" => a.budget.cache_max = Some(size(&it.next().expect("--cache-max SIZE"))),
            "--private-requests" => a.private_requests = true,
            "--hold-for-others" => a.hold_limit = Some(size(&it.next().expect("--hold-for-others SIZE"))),
            "--slow-link-budget" => a.slow_budget = duration_secs(&it.next().expect("--slow-link-budget DURATION")),
            "--treat-as-slow" => a.treat_as_slow.push(*parse_destination(&it.next().expect("--treat-as-slow NODE")).expect("node hash").as_bytes()),
            "--stamp-cost" => a.stamp_cost = it.next().and_then(|v| v.parse().ok()).expect("--stamp-cost BITS"),
            "--max-stamp-cost" => a.max_stamp_cost = it.next().and_then(|v| v.parse().ok()).expect("--max-stamp-cost BITS"),
            "--loss-target" => a.loss_target = it.next().and_then(|v| v.parse().ok()).expect("--loss-target P (e.g. 0.001)"),
            "--lease-term" => a.lease_term = duration_secs(&it.next().expect("--lease-term DURATION")).max(60),
            "-h" | "--help" => {
                println!(
                    "retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE] [--private-requests]
                             [--hold-for-others SIZE] [--lease-term DURATION] [--loss-target P] [--slow-link-budget DURATION]\n        \
                     [--stamp-cost BITS] [--max-stamp-cost BITS] [--public] [--put FILE]..."
                );
                std::process::exit(0);
            }
            other => panic!("unknown argument {other}"),
        }
    }
    a
}

/// Public: convergent. With a record: one secret per record from the store's
/// namespace key (versions dedup, records don't share CIDs). Otherwise a fresh
/// random secret (a one-off file).
fn secret(store: &SlabStore, public: bool, record: Option<&str>) -> ConvergenceSecret {
    if public {
        return ConvergenceSecret::public();
    }
    match record {
        Some(r) => ConvergenceSecret::for_record(&namespace_key(store), r.as_bytes()),
        None => {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).expect("OS entropy");
            ConvergenceSecret::personal(random)
        }
    }
}

/// The store's namespace key (created on first use). Prototype stand-in for
/// real namespaces (phase 2): one personal namespace per store.
fn namespace_key(store: &SlabStore) -> [u8; 32] {
    let path = store.root().join("namespace_key");
    if let Some(k) = std::fs::read(&path).ok().and_then(|b| b.try_into().ok()) {
        return k;
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("OS entropy");
    std::fs::write(&path, k).expect("write namespace key");
    k
}

fn main() {
    let args = args();
    std::fs::create_dir_all(&args.store).expect("create store dir");
    let store = match SlabStore::open(&args.store) {
        Ok(s) => {
            s.set_budget(args.budget.clone());
            s
        }
        Err(retifs_store::StoreError::Db(e)) if matches!(*e, redb::Error::DatabaseAlreadyOpen) => {
            eprintln!("retifsd: another retifsd is already using {}", args.store.display());
            std::process::exit(1);
        }
        Err(e) => panic!("open slab store {}: {e}", args.store.display()),
    };
    for path in &args.put {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let record = std::path::absolute(path).unwrap_or_else(|_| path.clone()).to_string_lossy().into_owned();
        let file = store_file(&store, &data, args.public, false, Some(&record), manifest::WriteOpts::default()).expect("store file");
        store.need_file(&file).expect("record need");
        println!("put {}  {}", path.display(), file);
    }
    let identity = load_or_create_identity(&args.store.join("node_identity")).expect("node identity");
    let endpoint = libretifs::endpoint(&args.store);
    let store = Arc::new(store);
    block_on(move || serve(store, identity, endpoint, args));
}

struct Daemon {
    store: Arc<SlabStore>,
    transport: PrnsTransport,
    node_hex: String,
    /// Wakes the seeker (new want).
    wake: Arc<Notify>,
    /// Open links the seeker reuses, per peer.
    links: Mutex<HashMap<PeerId, LinkId>>,
    /// One item per `have`/`get` request when seeking: slower, but a peer
    /// can't group chunks by request (ADR-0010, request-pattern leaks).
    private_requests: bool,
    node_id: PeerId,
    /// Derives per-lease signing keys (prototype: one namespace per store).
    namespace_key: [u8; 32],
    lease_term: u64,
    /// Wakes lease upkeep (receipts, renewals, proofs, placement) after new leases or needs.
    upkeep_wake: Notify,
    loss_target: f64,
    slow_budget: u64,
    treat_as_slow: Vec<PeerId>,
    /// Files whose rest waits for a faster path, with the estimate over the slow link.
    deferred: Mutex<HashMap<Cid, u64>>,
    /// Stamp cost each holder asked for, so later offers carry a stamp at once.
    stamp_costs: Mutex<HashMap<PeerId, u8>>,
    max_stamp_cost: u8,
}

impl Daemon {
    /// A link to `peer`, reusing an open one.
    async fn link_to(&self, peer: &PeerId) -> Result<LinkId, String> {
        if let Some(l) = self.links.lock().unwrap().get(peer).copied() {
            return Ok(l);
        }
        let dest = parse_destination(&hex(peer)).expect("peer id");
        let mut t = self.transport.clone();
        t.path_timeout = Duration::from_secs(20);
        t.ensure_path(dest).await?;
        let (link, rtt) = match t.link_with_rtt(dest).await {
            Ok(l) => l,
            // The known route may be stale: ask for a fresh path and try once more.
            Err(_) => {
                t.request_path(dest).await?;
                t.link_with_rtt(dest).await?
            }
        };
        let _ = self.store.record_rtt(peer, rtt);
        self.links.lock().unwrap().insert(*peer, link);
        Ok(link)
    }

    /// What this node knows of the path to `peer` (measured; see LinkQuality).
    fn quality(&self, peer: &PeerId) -> retifs_store::LinkQuality {
        let mut q = self.store.link_quality(peer).unwrap_or_default();
        if self.treat_as_slow.contains(peer) {
            q.rtt_ms = q.rtt_ms.max(retifs_store::SLOW_RTT_MS * 2);
            q.rate_bps = retifs_store::SLOW_DEFAULT_RATE as u32;
        }
        q
    }

    fn drop_link(&self, peer: &PeerId) {
        self.links.lock().unwrap().remove(peer);
    }

    async fn ask(&self, link: LinkId, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, String> {
        tokio::time::timeout(Duration::from_secs(60), self.transport.request(link, endpoint, body))
            .await
            .map_err(|_| format!("{endpoint}: timed out"))?
    }

    fn sign_lease(&self, id: LeaseId, expires: u64, entries: Vec<(Cid, ChunkToken)>) -> Lease {
        // Generations 0: holders keep the data but don't pass it on (own-pool class, ADR-0011).
        Lease::sign(&LeaseKey::derive(&self.namespace_key, &id), id, expires, 0, entries)
    }
}

async fn serve(store: Arc<SlabStore>, identity: node::IdentitySecret, endpoint: String, args: Args) {
    let identity_bytes: [u8; 64] = identity[..].try_into().expect("RNS identity secrets are 64 bytes");
    let dest = destination(identity, true);
    let dest_hash = dest.destination_hash().expect("valid destination");
    // Receipts are signed with the node identity and checked against the node's
    // address, so the identity layout must be RNS's (X25519 ‖ Ed25519).
    if node_destination(&lease::identity_public(&identity_bytes)) != *dest_hash.as_bytes() {
        eprintln!("warning: node identity layout differs from RNS; receipts from this node won't verify");
    }
    let shared = Arc::new(Shared {
        store: store.clone(),
        identity: identity_bytes,
        hold_limit: args.hold_limit,
        pull_wake: Notify::new(),
        stamp_cost: args.stamp_cost,
    });
    let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<(PeerId, u8)>();
    let (seek_tx, seek_rx) = mpsc::unbounded_channel::<PeerId>();
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [dest],
        app_state: shared.clone(),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get, Have, LeaseEndpoint, ReceiptEndpoint, ProveEndpoint, PutEndpoint],
        on_event: move |event, _state| {
            if let PrnsEvent::Diagnostic(Diagnostic::AnnounceHeard { destination, hops, .. }) = event {
                let _ = heard_tx.send((*destination.as_bytes(), hops));
            }
        },
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    let handle = node.handle();
    let of = attach(&handle).await.unwrap_or_else(|e| panic!("{e}"));
    let daemon = Arc::new(Daemon {
        store: store.clone(),
        transport: PrnsTransport::new(handle.clone()),
        node_hex: destination_hex(&dest_hash),
        wake: Arc::new(Notify::new()),
        links: Mutex::new(HashMap::new()),
        private_requests: args.private_requests,
        node_id: *dest_hash.as_bytes(),
        namespace_key: namespace_key(&store),
        lease_term: args.lease_term,
        upkeep_wake: Notify::new(),
        loss_target: args.loss_target,
        slow_budget: args.slow_budget,
        treat_as_slow: args.treat_as_slow.clone(),
        deferred: Mutex::new(HashMap::new()),
        stamp_costs: Mutex::new(HashMap::new()),
        max_stamp_cost: args.max_stamp_cost,
    });
    println!("attached to shared instance {of}");
    println!("serving {} chunks as retifs.node <{}>", store.len().unwrap_or(0), daemon.node_hex);
    println!("local API at {endpoint}");

    match args.hold_limit {
        Some(0) => println!("not holding data for others"),
        Some(n) => println!("holding up to {n} bytes for others"),
        None => println!("holding data for others up to the store limit"),
    }

    tokio::spawn(local_api(endpoint, daemon.clone()));
    tokio::spawn(lease_puller(daemon.clone(), shared.clone()));
    tokio::spawn(lease_upkeep(daemon.clone()));
    let watcher = daemon.clone();
    tokio::spawn(async move {
        // Every retifs node is a storage node (ADR-0014). Prns doesn't pass
        // announce app data on, so recognise retifs.node by its identity.
        let mut not_retifs = std::collections::HashSet::new();
        while let Some((peer, hops)) = heard_rx.recv().await {
            let _ = seek_tx.send(peer);
            if peer == watcher.node_id || not_retifs.contains(&peer) {
                continue;
            }
            let dest = parse_destination(&hex(&peer)).expect("destination hash");
            match watcher.transport.handle.destination_identity(DestinationIdentityQuery::Destination(dest)).await {
                Some(id) if node_destination(id.public.as_bytes()) == peer => {
                    let known = watcher.store.storage_nodes().map(|n| n.iter().any(|n| n.peer == peer)).unwrap_or(true);
                    if watcher.store.heard_storage_node(&peer, hops, now_ms()).is_ok() && !known {
                        println!("storage node <{}> heard, {hops} hop(s) away", hex(&peer));
                        watcher.upkeep_wake.notify_one();
                    }
                }
                Some(_) => {
                    not_retifs.insert(peer);
                }
                None => {}
            }
        }
    });
    tokio::spawn(seeker(daemon, seek_rx));

    // Keep within the disk budget even when other programs fill the volume (ADR-0012).
    let budget_store = store.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let s = budget_store.clone();
            match tokio::task::spawn_blocking(move || s.enforce()).await {
                Ok(Ok(freed)) if freed > 0 => println!("disk budget: evicted {freed} bytes of cache/spare"),
                Ok(Err(e)) => eprintln!("disk budget: {e}"),
                _ => {}
            }
        }
    });

    let announcer = handle.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let cmd = PrnsCommand::AnnounceNow(AnnounceNow {
                destination: dest_hash,
                target: AnnounceTarget::AllInterfaces,
                app_data: AnnounceAppData::Registered,
            });
            if announcer.issue(cmd).is_none() {
                return;
            }
        }
    });

    if let Err(e) = node.run().await {
        eprintln!("node stopped: {e}");
    }
}

#[cfg(not(windows))]
async fn local_api(endpoint: String, daemon: Arc<Daemon>) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(&endpoint); // stale socket from a previous run
    let listener = tokio::net::UnixListener::bind(&endpoint).unwrap_or_else(|e| panic!("bind {endpoint}: {e}"));
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600)).expect("socket permissions");
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(connection(stream, daemon.clone()));
            }
            Err(e) => eprintln!("local API accept: {e}"),
        }
    }
}

#[cfg(windows)]
async fn local_api(endpoint: String, daemon: Arc<Daemon>) {
    use tokio::net::windows::named_pipe::ServerOptions;
    // first_pipe_instance: fail if another daemon already owns this store's pipe.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&endpoint)
        .unwrap_or_else(|e| panic!("create {endpoint}: {e} (is another retifsd running on this store?)"));
    loop {
        if let Err(e) = server.connect().await {
            eprintln!("local API connect: {e}");
            continue;
        }
        let connected = server;
        server = ServerOptions::new().create(&endpoint).expect("next pipe instance");
        tokio::spawn(connection(connected, daemon.clone()));
    }
}

async fn connection(mut stream: impl AsyncRead + AsyncWrite + Unpin, daemon: Arc<Daemon>) {
    loop {
        let req: Envelope<Request> = match read_frame(&mut stream).await {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                eprintln!("local API read: {e}");
                return;
            }
        };
        let msg = handle(&daemon, req.msg).await.unwrap_or_else(|message| Response::Error { message });
        if let Err(e) = write_frame(&mut stream, &Envelope { v: PROTOCOL_VERSION, id: req.id, msg }).await {
            eprintln!("local API write: {e}");
            return;
        }
    }
}

async fn handle(d: &Daemon, req: Request) -> Result<Response, String> {
    match req {
        Request::Ping => {
            let u = d.store.usage().map_err(|e| e.to_string())?;
            let l = d.store.limits().map_err(|e| e.to_string())?;
            Ok(Response::Pong {
                node: d.node_hex.clone(),
                chunks: d.store.len().map_err(|e| e.to_string())?,
                usage: Some(libretifs::StoreUsage {
                    pinned: u.pinned,
                    leased: u.leased,
                    cache: u.cache,
                    spare: u.spare,
                    store_limit: l.hard_max,
                    reserve: l.reserve,
                    cache_max: l.cache_max,
                    disk_total: l.disk_total,
                    disk_available: l.disk_available,
                }),
            })
        }

        Request::Put { data, public, compress, publish, record } => {
            let store = d.store.clone();
            let opts = manifest::WriteOpts {
                compression: if compress { retifs_core::Compression::Zstd } else { retifs_core::Compression::Off },
                ..Default::default()
            };
            let file = tokio::task::spawn_blocking(move || store_file(&store, &data, public, publish, record.as_deref(), opts))
                .await
                .map_err(|e| e.to_string())??;
            d.store.need_file(&file).map_err(|e| e.to_string())?;
            d.upkeep_wake.notify_one();
            Ok(Response::Put { cap: file.to_string() })
        }

        Request::Get { cap, from, links_per_node, batch } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let t0 = Instant::now();
            let mut links = Vec::new();
            for hex in &from {
                let peer = parse_destination(hex).ok_or_else(|| format!("bad node hash {hex}"))?;
                if let Err(e) = d.transport.ensure_path(peer).await {
                    eprintln!("path to {hex}: {e}");
                    continue;
                }
                for _ in 0..links_per_node.max(1) {
                    match d.transport.link(peer).await {
                        Ok(link) => links.push(link),
                        Err(e) => eprintln!("link to {hex}: {e}"),
                    }
                }
            }
            let connect_millis = t0.elapsed().as_millis() as u64;
            let t1 = Instant::now();
            if !from.is_empty() && links.is_empty() {
                return Err("could not link to any of the given nodes".into());
            }
            let opts = FetchOpts { batch: if batch == 0 { FetchOpts::default().batch } else { batch }, ..Default::default() };
            let (data, s) = fetch_file(&d.transport, &links, &cap, opts, &mut CacheTier(&d.store))
                .await
                .map_err(|e| e.to_string())?;
            let stats = GetStats {
                chunks: s.chunks,
                from_local: s.cache_hits,
                requests: s.requests,
                retries: s.retries,
                network_bytes: s.network_bytes,
                links: links.len(),
                connect_millis,
                millis: t1.elapsed().as_millis() as u64,
            };
            Ok(Response::Get { data, stats })
        }

        Request::Status { cap } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::Replicate { cap, to } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let chunks = file_chunks(&d.store, &cap)?;
            // The holders pull from this node with the chunks' tokens.
            d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
            for h in &to {
                let peer = *parse_destination(h).ok_or_else(|| format!("bad node hash {h}"))?.as_bytes();
                // Also name this node as a source, so the holder can pull what a push missed.
                let roots: HashMap<Cid, Vec<Cid>> = chunks.iter().map(|(c, _)| (*c, vec![cap.root])).collect();
                match lease_to(d, &peer, &sorted(&chunks), &roots, &[d.node_id]).await.map_err(|e| format!("{h}: {e}"))? {
                    true => println!("replicate: leased {} chunk(s) of {} to <{h}>", chunks.len(), cap.root),
                    false => return Err(format!("{h} refused the lease: NoRoom")),
                }
            }
            d.upkeep_wake.notify_one();
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::Forget { cap } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            // Chunks other needed files still use stay (versions share most of theirs).
            let mut keep = std::collections::HashSet::new();
            for other in d.store.needed_files().map_err(|e| e.to_string())? {
                if other.root != cap.root {
                    keep.extend(file_chunks(&d.store, &other).unwrap_or_default().into_iter().map(|(c, _)| c));
                }
            }
            let all: Vec<Cid> = file_chunks(&d.store, &cap).unwrap_or_default().into_iter().map(|(c, _)| c).collect();
            let shared = all.iter().filter(|c| keep.contains(c)).count();
            let mine: Vec<Cid> = all.into_iter().filter(|c| !keep.contains(c)).collect();
            let leases = d.store.forget_file(&cap.root).map_err(|e| e.to_string())?;
            let released = d.store.release_chunks(&mine).map_err(|e| e.to_string())?;
            d.deferred.lock().unwrap().remove(&cap.root);
            println!(
                "forget {}: {leases} lease(s) no longer serve it, {released} chunk(s) evictable, {shared} kept (other needed files use them)",
                cap.root
            );
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::Want { cap, from } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let peers: Vec<PeerId> = from
                .iter()
                .map(|h| parse_destination(h).map(|d| *d.as_bytes()).ok_or_else(|| format!("bad node hash {h}")))
                .collect::<Result<_, _>>()?;
            d.store.want_file(&cap, &peers).map_err(|e| e.to_string())?;
            d.wake.notify_one();
            Ok(Response::Status(full_status(d, &cap)))
        }
    }
}

/// Writes `data` as pinned own data and registers it for serving: to holders
/// of its read-cap (serve token), and to anyone if `publish`.
fn store_file(
    store: &SlabStore,
    data: &[u8],
    public: bool,
    publish: bool,
    record: Option<&str>,
    opts: manifest::WriteOpts,
) -> Result<FileRef, String> {
    let secret = secret(store, public, record);
    // A per-record secret belongs to one record: padding may then be stable
    // across its versions (ADR-0009), so an edit doesn't re-store all padding.
    let opts = manifest::WriteOpts { stable_padding: record.is_some() && !public, ..opts };
    let mut pinned = retifs_store::TrackedPinned::new(store);
    let (file, blobs) = match manifest::write_tracked(&mut pinned, &secret, data, opts) {
        Ok(written) => written,
        Err(e) => {
            // Don't leave half a file pinned (and eating the budget).
            let _ = pinned.roll_back();
            return Err(e.to_string());
        }
    };
    let tokens: Vec<_> = blobs.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
    store.register_serving(&tokens).map_err(|e| e.to_string())?;
    if publish {
        store.publish(&blobs.iter().map(|(c, _)| *c).collect::<Vec<_>>()).map_err(|e| e.to_string())?;
    }
    Ok(file)
}

fn full_status(d: &Daemon, cap: &FileRef) -> Status {
    let store = &d.store;
    let mut s = local_status(store, cap);
    s.slow_link_wait_secs = d.deferred.lock().unwrap().get(&cap.root).copied();
    s.seeking = store.is_wanted(&cap.root).unwrap_or(false);
    s.holders_known = store.hints(&cap.root).map(|h| h.len()).unwrap_or(0);
    let own = store.own_leases().unwrap_or_default();
    s.leased_to = own.iter().filter(|o| o.roots.contains(&cap.root)).map(|o| o.holder).collect::<std::collections::BTreeSet<_>>().len();
    s.replicas = store.confirmed_holders(&cap.root, now_s()).map(|h| h.len()).unwrap_or(0);
    s
}

fn now_s() -> u64 {
    now_ms() / 1000
}

/// Every chunk of a file (manifest nodes, data and padding) with its access
/// token, from the local store: what a lease for the whole file lists.
fn file_chunks(store: &SlabStore, file: &FileRef) -> Result<Vec<(Cid, ChunkToken)>, String> {
    let mut out = Vec::new();
    let mut level = vec![NodeEntry { cid: file.root, seed: file.seed, span: file.size }];
    while !level.is_empty() {
        let mut next = Vec::new();
        for e in level {
            out.push((e.cid, ChunkToken::for_seed(&e.seed)));
            let ct = store
                .fetch(&e.cid)
                .map_err(|e| e.to_string())?
                .ok_or("not all of the file is local; get it first")?;
            let pt = open(&e.cid, &e.seed, &ct).map_err(|e| e.to_string())?;
            let node = if e.cid == file.root { decode_root(&pt, e.span) } else { decode_node(&pt, e.span) }
                .map_err(|e| e.to_string())?;
            if node.leaf {
                out.extend(node.entries.iter().map(|c| (c.cid, ChunkToken::for_seed(&c.seed))));
            } else {
                next.extend(node.entries);
            }
        }
        level = next;
    }
    Ok(out)
}

// ------------------------------------------------------------------ leases

/// Holder side: pulls missing chunks of accepted leases from their sources,
/// and drops expired leases. Woken by new leases, else every 30 s.
async fn lease_puller(d: Arc<Daemon>, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = shared.pull_wake.notified() => {}
            _ = tick.tick() => {}
        }
        match d.store.expire_leases(now_s()) {
            Ok(n) if n > 0 => println!("leases: {n} expired, their chunks released"),
            Err(e) => eprintln!("leases: {e}"),
            _ => {}
        }
        if let Err(e) = pull_pass(&d).await {
            eprintln!("lease puller: {e}");
        }
    }
}

async fn pull_pass(d: &Daemon) -> Result<(), String> {
    for (held, missing) in d.store.lease_wants().map_err(|e| e.to_string())? {
        let total = held.lease.entries.len();
        let mut have = total - missing.len();
        for src in &held.sources {
            let link = match d.link_to(src).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("lease {}: source <{}> unreachable: {e}", hex(&held.lease.id), hex(src));
                    continue;
                }
            };
            let round = match pull_round(&d.transport, link, &missing, d.private_requests, Duration::from_secs(60)).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("lease {}: <{}>: {e}", hex(&held.lease.id), hex(src));
                    d.drop_link(src);
                    continue;
                }
            };
            for (i, ct) in round.got {
                if d.store.lease_arrived(&missing[i].0, &ct).map_err(|e| e.to_string())? {
                    have += 1;
                }
            }
            if have == total {
                println!("lease {}: holding all {total} chunk(s)", hex(&held.lease.id));
                break;
            }
        }
    }
    Ok(())
}

/// How often the owner checks each holder still has the data.
const PROOF_INTERVAL: Duration = Duration::from_secs(600);

/// Owner side: collects receipts, renews leases at half-term, and checks
/// storage proofs. Woken after new leases, else every 30 s.
async fn lease_upkeep(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    let mut proved: HashMap<PeerId, Instant> = HashMap::new();
    loop {
        tokio::select! {
            _ = d.upkeep_wake.notified() => {}
            _ = tick.tick() => {}
        }
        let Ok(leases) = d.store.own_leases() else { continue };
        let mut by_holder: std::collections::BTreeMap<PeerId, Vec<OwnLease>> = Default::default();
        for o in leases {
            by_holder.entry(o.holder).or_default().push(o);
        }
        // One exchange per holder however many leases it keeps (ADR-0014).
        for (holder, mut leases) in by_holder {
            match upkeep_holder(&d, &holder, &mut leases, &mut proved).await {
                Ok(Some(ok)) => {
                    let _ = d.store.holder_result(&holder, ok, now_ms());
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("upkeep <{}>: {e}", hex(&holder));
                    let _ = d.store.holder_result(&holder, false, now_ms());
                    d.drop_link(&holder);
                }
            }
        }
        if let Err(e) = place_all(&d).await {
            eprintln!("placement: {e}");
        }
    }
}

/// Estimated chance of losing every copy of `file` (ADR-0014): the local copy
/// times each holder's loss estimate from its record. A holder whose receipt
/// ran out counts as lost; one that is only unreachable just gets a worse
/// record (lazy repair: it may come back with the data).
/// Returns (local copy's estimate, holders, product of all).
fn loss_now(d: &Daemon, file: &FileRef) -> (f64, Vec<retifs_store::HolderView>, f64) {
    let pinned = d.store.tier(&file.root).ok().flatten().is_some_and(|f| f & tier::PINNED != 0);
    let local = if pinned { 0.1 } else { 0.5 };
    let now = now_s();
    let hops: HashMap<PeerId, u8> =
        d.store.storage_nodes().unwrap_or_default().into_iter().map(|n| (n.peer, n.hops)).collect();
    let mut by_holder: std::collections::BTreeMap<PeerId, retifs_store::HolderView> = Default::default();
    for o in d.store.own_leases_for(&file.root).unwrap_or_default() {
        let lapsed = o.receipt_until > 0 && o.receipt_until < now;
        let p = if lapsed || o.proof == ProofState::Failed {
            1.0
        } else {
            d.store.holder_stats(&o.holder).map(|s| s.loss()).unwrap_or(1.0)
        };
        let v = by_holder.entry(o.holder).or_insert(retifs_store::HolderView {
            peer: o.holder,
            loss: 0.0,
            hops: hops.get(&o.holder).copied().unwrap_or(0),
            confirmed: true,
        });
        // A holder is as good as its worst lease for this file.
        v.loss = v.loss.max(p);
        v.confirmed &= o.receipt_until >= now && !lapsed;
    }
    let holders: Vec<_> = by_holder.into_values().collect();
    let risk = local * holders.iter().map(|h| h.loss).product::<f64>();
    (local, holders, risk)
}

/// Whether a loss estimate meets the target. A relative tolerance keeps
/// rounding (0.1 × 0.1 × 0.1 = 0.0010000000000000002) from costing an extra copy.
fn met(risk: f64, target: f64) -> bool {
    risk <= target * (1.0 + 1e-9)
}

/// Keeps every needed file at or below the loss target (ADR-0014), in one
/// planned pass: each file picks the holders it lacks from one ranking of
/// candidates, then everything bound for a holder goes out together, packed
/// into mixed leases sorted by CID, so a holder sees neither file boundaries
/// nor chunk order. Data goes by push, so readers' copies (cache, never
/// served) can be placed too, and holders don't learn who sent it.
async fn place_all(d: &Daemon) -> Result<(), String> {
    let mut plan: std::collections::BTreeMap<PeerId, Vec<FileRef>> = Default::default();
    let mut ranked: Option<Vec<(f64, retifs_store::StorageNode)>> = None;
    for file in d.store.needed_files().map_err(|e| e.to_string())? {
        let Some((mut risk, holders)) = review(d, &file)? else { continue };
        if ranked.is_none() {
            ranked = Some(rank_candidates(d).await?);
        }
        for (_, n) in ranked.as_deref().unwrap_or_default() {
            if met(risk, d.loss_target) {
                break;
            }
            if holders.contains(&n.peer) {
                continue;
            }
            plan.entry(n.peer).or_default().push(file);
            risk *= d.store.holder_stats(&n.peer).map(|s| s.loss()).unwrap_or(1.0);
        }
    }
    for (peer, files) in plan {
        // Union of the files' chunks: shared chunks (versions) are listed once.
        let mut roots: HashMap<Cid, Vec<Cid>> = HashMap::new();
        let mut chunks: Vec<(Cid, ChunkToken)> = Vec::new();
        for f in &files {
            for (cid, token) in file_chunks(&d.store, f)? {
                let r = roots.entry(cid).or_default();
                if r.is_empty() {
                    chunks.push((cid, token));
                }
                r.push(f.root);
            }
        }
        let hops = d.store.storage_nodes().unwrap_or_default().iter().find(|n| n.peer == peer).map_or(0, |n| n.hops);
        match lease_to(d, &peer, &sorted(&chunks), &roots, &[]).await {
            Ok(true) => println!(
                "placement: {} file(s), {} chunk(s) kept at <{}> ({hops} hop(s)) in mixed lease(s)",
                files.len(),
                chunks.len(),
                hex(&peer)
            ),
            Ok(false) => d.store.avoid_storage_node(&peer, now_ms() + 3_600_000).map_err(|e| e.to_string())?,
            Err(e) => {
                eprintln!("placement: <{}>: {e}", hex(&peer));
                d.store.avoid_storage_node(&peer, now_ms() + 600_000).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Chunks in CID order: a lease then says nothing about file order or boundaries.
fn sorted(chunks: &[(Cid, ChunkToken)]) -> Vec<(Cid, ChunkToken)> {
    let mut v = chunks.to_vec();
    v.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    v.dedup_by(|a, b| a.0 == b.0);
    v
}

/// Brings one file's holders up to date: forgets holders whose lease ran
/// out, trims a surplus copy. Returns the loss estimate and current holders
/// if the file needs more.
fn review(d: &Daemon, file: &FileRef) -> Result<Option<(f64, std::collections::BTreeSet<PeerId>)>, String> {
    // A lease that ran out unrenewed means the holder dropped the copy: forget
    // that holder for this file instead of re-offering to it later (a minute of
    // grace for clocks). One that's only away but still within its lease counts
    // on, with a worse record (lazy repair).
    let now = now_s();
    let lapsed: std::collections::BTreeSet<PeerId> = d
        .store
        .own_leases_for(&file.root)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|o| o.expires + 60 < now)
        .map(|o| o.holder)
        .collect();
    for h in lapsed {
        d.store.drop_holder(&file.root, &h).map_err(|e| e.to_string())?;
        println!("placement: {}: lease at <{}> ran out unrenewed, its copy is gone", file.root, hex(&h));
    }
    let (local, views, risk) = loss_now(d, file);
    if met(risk, d.loss_target) {
        // Surplus after a repair (the absent holder came back): stop renewing
        // the worst copy once the target holds well without it.
        if let Some(drop) = retifs_store::surplus_holder(local, &views, d.loss_target) {
            let n = d.store.drop_holder(&file.root, &drop).map_err(|e| e.to_string())?;
            let without = local * views.iter().filter(|h| h.peer != drop).map(|h| h.loss).product::<f64>();
            println!(
                "placement: {} trimmed at <{}> ({n} lease(s) no longer serve it), loss estimate without it {without:.1e}",
                file.root,
                hex(&drop)
            );
        }
        return Ok(None);
    }
    Ok(Some((risk, views.iter().map(|h| h.peer).collect())))
}

/// The nearest few storage nodes by hops, measured by linking (RTT) and
/// earlier transfers, ranked by estimated transfer time. Placement is never
/// worth a slow link: copies for durability don't cross LoRa (ADR-0013/0014).
async fn rank_candidates(d: &Daemon) -> Result<Vec<(f64, retifs_store::StorageNode)>, String> {
    let mut candidates = Vec::new();
    for n in d.store.storage_nodes().map_err(|e| e.to_string())? {
        if candidates.len() == 8 {
            break;
        }
        if n.peer == d.node_id || n.avoid_until_ms > now_ms() {
            continue;
        }
        if let Err(e) = d.link_to(&n.peer).await {
            eprintln!("placement: <{}>: {e}", hex(&n.peer));
            d.store.avoid_storage_node(&n.peer, now_ms() + 600_000).map_err(|e| e.to_string())?;
            continue;
        }
        let q = d.quality(&n.peer);
        if q.slow() {
            println!("placement: <{}> is behind a slow link ({} ms, ~{:.0} B/s): not placing there", hex(&n.peer), q.rtt_ms, q.rate());
            d.store.avoid_storage_node(&n.peer, now_ms() + 6 * 3_600_000).map_err(|e| e.to_string())?;
            continue;
        }
        candidates.push((q.transfer_secs(1 << 20), n));
    }
    candidates.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.hops.cmp(&b.1.hops)));
    Ok(candidates)
}

/// Offers a lease, with a stamp if the holder asks for one (or asked before).
/// A holder asking more than `--max-stamp-cost` is treated as having no room.
async fn offer(d: &Daemon, link: LinkId, peer: &PeerId, l: &Lease, sources: &[PeerId]) -> Result<LeaseStatus, String> {
    let mut cost = d.stamp_costs.lock().unwrap().get(peer).copied().unwrap_or(0);
    for _ in 0..2 {
        let stamp = if cost > 0 {
            let material = stamp::lease_material(l);
            let t0 = Instant::now();
            let st = tokio::task::spawn_blocking(move || stamp::generate(&material, cost)).await.map_err(|e| e.to_string())?;
            println!("lease {}: stamp of {cost} bits for <{}> in {:.2} s", hex(&l.id), hex(peer), t0.elapsed().as_secs_f64());
            Some(st)
        } else {
            None
        };
        let req = LeaseRequest::Offer { lease: l.clone(), sources: sources.to_vec(), stamp };
        match decode_lease_status(&d.ask(link, LEASE_ENDPOINT, encode_lease_request(&req)).await?).map_err(|e| e.to_string())? {
            LeaseStatus::StampRequired(c) if c > d.max_stamp_cost => {
                println!("lease {}: <{}> asks a stamp of {c} bits, more than {}: not offering there", hex(&l.id), hex(peer), d.max_stamp_cost);
                return Ok(LeaseStatus::NoRoom);
            }
            LeaseStatus::StampRequired(c) if c != cost => {
                d.stamp_costs.lock().unwrap().insert(*peer, c);
                cost = c;
            }
            other => return Ok(other),
        }
    }
    Err("holder keeps refusing the stamp".into())
}

/// Offers `peer` leases over `chunks` (≤ 1024 per lease, in the given order)
/// and pushes what it lacks. `roots` says which files each chunk belongs to,
/// so each lease records the files it serves. Ok(false): it has no room.
async fn lease_to(
    d: &Daemon,
    peer: &PeerId,
    chunks: &[(Cid, ChunkToken)],
    roots: &HashMap<Cid, Vec<Cid>>,
    sources: &[PeerId],
) -> Result<bool, String> {
    let link = d.link_to(peer).await?;
    for part in chunks.chunks(lease::MAX_CHUNKS) {
        let mut id = [0u8; lease::ID_LEN];
        getrandom::fill(&mut id).expect("OS entropy");
        let l = d.sign_lease(id, now_s() + d.lease_term, part.to_vec());
        let mut served: Vec<Cid> = part.iter().flat_map(|(c, _)| roots.get(c).cloned().unwrap_or_default()).collect();
        served.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        served.dedup();
        match offer(d, link, peer, &l, sources).await {
            Ok(LeaseStatus::Accepted) => {
                d.store.record_own_lease(&l, peer, &served).map_err(|e| e.to_string())?;
                match push(d, link, &l, Some(peer)).await {
                    Ok(sent) => println!("lease {}: pushed {sent} of {} chunk(s) to <{}>", hex(&l.id), l.entries.len(), hex(peer)),
                    Err(e) => {
                        d.drop_link(peer);
                        return Err(format!("push: {e}"));
                    }
                }
            }
            Ok(LeaseStatus::NoRoom) => return Ok(false),
            Ok(other) => return Err(format!("lease refused: {other:?}")),
            Err(e) => {
                d.drop_link(peer);
                return Err(e);
            }
        }
    }
    Ok(true)
}

/// Sends the holder the chunks of `l` it doesn't have yet (asks with `have`
/// first, so shared chunks and earlier versions never travel twice).
async fn push(d: &Daemon, link: LinkId, l: &Lease, peer: Option<&PeerId>) -> Result<usize, String> {
    let nonce = d.transport.link_nonce(link);
    let mut missing = Vec::new();
    for batch in l.entries.chunks(MAX_HAVE) {
        let items: Vec<([u8; HAVE_PREFIX], [u8; 16])> = batch
            .iter()
            .map(|(cid, token)| {
                let prefix: [u8; HAVE_PREFIX] = cid.as_bytes()[..HAVE_PREFIX].try_into().unwrap();
                (prefix, token.have_proof(&nonce, &prefix))
            })
            .collect();
        let bits = decode_bitmap(&d.ask(link, HAVE_ENDPOINT, encode_have(&items)).await?, batch.len()).map_err(|e| e.to_string())?;
        missing.extend(batch.iter().zip(bits).filter(|(_, held)| !held).map(|((cid, _), _)| *cid));
    }
    // Start with full batches; on a timeout (slow or long paths), halve the
    // batch and resend the same chunks, down to one chunk per request.
    let (mut sent, mut at, mut batch) = (0, 0, MAX_PUT);
    while at < missing.len() {
        let end = (at + batch).min(missing.len());
        let cts: Vec<Vec<u8>> = missing[at..end].iter().filter_map(|c| d.store.fetch(c).ok().flatten()).collect();
        if !cts.is_empty() {
            let t0 = Instant::now();
            match d.ask(link, PUT_ENDPOINT, encode_put(&l.id, &cts)).await {
                Ok(reply) => {
                    if let Some(peer) = peer {
                        let bytes = cts.iter().map(|c| c.len() as u64).sum();
                        let _ = d.store.record_transfer(peer, bytes, t0.elapsed().as_millis() as u64);
                    }
                    sent += decode_bitmap(&reply, cts.len()).map_err(|e| e.to_string())?.iter().filter(|&&b| b).count()
                }
                Err(e) if batch > 1 && (e.contains("Timeout") || e.contains("timed out")) => {
                    batch /= 2;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        at = end;
    }
    Ok(sent)
}

/// Renews, collects receipts and samples a storage proof for all leases one
/// holder keeps, in bundles. Ok(None): nothing was due; Ok(Some(ok)): the
/// holder was contacted, and whether it behaved.
async fn upkeep_holder(
    d: &Daemon,
    holder: &PeerId,
    leases: &mut [OwnLease],
    proved: &mut HashMap<PeerId, Instant>,
) -> Result<Option<bool>, String> {
    let now = now_s();
    let renew: Vec<usize> = (0..leases.len()).filter(|&i| leases[i].expires < now + d.lease_term / 2).collect();
    let proof_due = leases.iter().any(|o| o.receipt_until > 0) && proved.get(holder).is_none_or(|t| t.elapsed() > PROOF_INTERVAL);
    if renew.is_empty() && !proof_due && leases.iter().all(|o| o.receipt_until >= o.expires) {
        return Ok(None);
    }
    let link = d.link_to(holder).await?;
    let before: Vec<_> = leases.iter().map(|o| (o.expires, o.receipt_until, o.proof)).collect();
    let mut behaved = true;

    // Stale leases (a file they served is no longer kept here) are repacked
    // instead of renewed: a new lease with only the chunks still needed, which
    // the holder already has, while the old one runs out.
    let mut gone = std::collections::HashSet::new();
    let (stale, renew): (Vec<usize>, Vec<usize>) = renew.into_iter().partition(|&i| leases[i].stale);
    for i in stale {
        if repack(d, holder, &leases[i]).await? {
            gone.insert(i);
        }
    }

    // Renewals, up to 64 per request.
    for batch in renew.chunks(MAX_BUNDLE) {
        let expires = now + d.lease_term;
        let rs: Vec<Renewal> = batch
            .iter()
            .map(|&i| Renewal::sign(&LeaseKey::derive(&d.namespace_key, &leases[i].lease.id), leases[i].lease.id, expires))
            .collect();
        let reply = d.ask(link, LEASE_ENDPOINT, encode_lease_request(&LeaseRequest::RenewMany(rs))).await?;
        let statuses = decode_lease_statuses(&reply, batch.len()).map_err(|e| e.to_string())?;
        let mut renewed = 0;
        for (&i, status) in batch.iter().zip(statuses) {
            match status {
                LeaseStatus::Accepted => {
                    leases[i].expires = expires;
                    renewed += 1;
                }
                LeaseStatus::Unknown => reoffer(d, link, &mut leases[i], expires).await?,
                other => {
                    eprintln!("lease {}: renewal refused by <{}>: {other:?}", hex(&leases[i].lease.id), hex(holder));
                    behaved = false;
                }
            }
        }
        if renewed > 0 {
            println!("upkeep <{}>: renewed {renewed} lease(s) until {expires} in one request", hex(holder));
        }
    }

    // Receipts for leases not yet covered, up to 64 per request.
    let need: Vec<usize> = (0..leases.len()).filter(|&i| !gone.contains(&i) && leases[i].receipt_until < leases[i].expires).collect();
    for batch in need.chunks(MAX_BUNDLE) {
        let ids: Vec<LeaseId> = batch.iter().map(|&i| leases[i].lease.id).collect();
        let reply = d.ask(link, RECEIPT_ENDPOINT, encode_receipt_request(&ids)).await?;
        for (&i, r) in batch.iter().zip(decode_receipt_replies(&reply, ids.len()).map_err(|e| e.to_string())?) {
            let o = &mut leases[i];
            let id = o.lease.id;
            match r {
                ReceiptReply::Receipt(r) => {
                    if r.lease_id != id || r.lease_digest != o.lease.digest() || node_destination(&r.holder) != *holder {
                        eprintln!("lease {}: bad receipt from <{}>", hex(&id), hex(holder));
                        behaved = false;
                        continue;
                    }
                    o.receipt_until = r.holds_until.min(o.expires);
                    println!("lease {}: receipt from <{}>, held until {}", hex(&id), hex(holder), o.receipt_until);
                }
                ReceiptReply::Progress { held, total } => {
                    let sent = push(d, link, &o.lease, Some(holder)).await?;
                    println!("lease {}: <{}> had {held}/{total}, pushed {sent}", hex(&id), hex(holder));
                    if sent == 0 {
                        // It answers but takes nothing (full, or broken): its loss
                        // estimate should rise so placement looks elsewhere.
                        behaved = false;
                    }
                }
                ReceiptReply::Unknown => {
                    println!("lease {}: <{}> lost the lease, offering it again", hex(&id), hex(holder));
                    let expires = o.expires.max(now + d.lease_term / 2);
                    reoffer(d, link, o, expires).await?;
                }
            }
        }
    }

    // One storage proof per holder per interval, on a random lease with a receipt.
    let receipted: Vec<usize> = (0..leases.len()).filter(|&i| !gone.contains(&i) && leases[i].receipt_until > 0).collect();
    if proof_due && !receipted.is_empty() {
        let mut rnd = [0u8; 16 + 8 + 2];
        getrandom::fill(&mut rnd).expect("OS entropy");
        let o = &mut leases[receipted[u16::from_be_bytes([rnd[24], rnd[25]]) as usize % receipted.len()]];
        let n = o.lease.entries.len();
        let nonce: [u8; 16] = rnd[..16].try_into().unwrap();
        let indices: Vec<u16> = rnd[16..24].chunks(2).map(|b| (u16::from_be_bytes([b[0], b[1]]) as usize % n) as u16).collect();
        let mut expected = Vec::new();
        for &i in &indices {
            let ct = d.store.fetch(&o.lease.entries[i as usize].0).map_err(|e| e.to_string())?;
            expected.push(ct.map(|ct| lease::prove(&nonce, &ct)));
        }
        let reply = d.ask(link, PROVE_ENDPOINT, encode_prove(&o.lease.id, &nonce, &indices)).await?;
        let answers = decode_prove_reply(&reply, indices.len()).map_err(|e| e.to_string())?;
        // Only chunks this node still has can be checked.
        let checked: Vec<bool> = expected.iter().zip(&answers).filter_map(|(e, a)| e.map(|e| Some(e) == *a)).collect();
        if !checked.is_empty() {
            o.proof = if checked.iter().all(|&ok| ok) { ProofState::Passed } else { ProofState::Failed };
            behaved &= o.proof == ProofState::Passed;
            println!("lease {}: storage proof from <{}>: {:?} ({} chunk(s))", hex(&o.lease.id), hex(holder), o.proof, checked.len());
        }
        proved.insert(*holder, Instant::now());
    }

    for (i, (o, b)) in leases.iter().zip(before).enumerate() {
        if !gone.contains(&i) && (o.expires, o.receipt_until, o.proof) != b {
            d.store.update_own_lease(o).map_err(|e| e.to_string())?;
        }
    }
    Ok(Some(behaved))
}

/// Replaces a stale lease with one over only the chunks its remaining files
/// still need (the holder has them: nothing is pushed). The old lease isn't
/// renewed and runs out. Ok(true): the old lease is no longer tracked.
async fn repack(d: &Daemon, holder: &PeerId, o: &OwnLease) -> Result<bool, String> {
    let needed: HashMap<Cid, FileRef> =
        d.store.needed_files().map_err(|e| e.to_string())?.into_iter().map(|f| (f.root, f)).collect();
    let in_lease: std::collections::HashSet<Cid> = o.lease.entries.iter().map(|(c, _)| *c).collect();
    let mut roots: HashMap<Cid, Vec<Cid>> = HashMap::new();
    let mut keep = Vec::new();
    for root in &o.roots {
        let Some(f) = needed.get(root) else { continue };
        for (cid, token) in file_chunks(&d.store, f)? {
            if in_lease.contains(&cid) {
                let r = roots.entry(cid).or_default();
                if r.is_empty() {
                    keep.push((cid, token));
                }
                r.push(*root);
            }
        }
    }
    if keep.is_empty() || lease_to(d, holder, &sorted(&keep), &roots, &[]).await? {
        println!(
            "lease {}: repacked at <{}>: {} of {} chunk(s) still needed",
            hex(&o.lease.id),
            hex(holder),
            keep.len(),
            o.lease.entries.len()
        );
        d.store.remove_own_lease(&o.lease.id).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

/// The holder lost a lease (restart without it, expiry): offer it again under
/// the same ID, with a fresh expiry, and wait for a new receipt.
async fn reoffer(d: &Daemon, link: LinkId, o: &mut OwnLease, expires: u64) -> Result<(), String> {
    let l = d.sign_lease(o.lease.id, expires, o.lease.entries.clone());
    match offer(d, link, &o.holder, &l, &[d.node_id]).await? {
        LeaseStatus::Accepted => {
            o.lease = l;
            o.expires = expires;
            o.receipt_until = 0;
            Ok(())
        }
        other => Err(format!("re-offer refused: {other:?}")),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Continuous seeking (ADR-0010): woken by new wants, by announces of hinted
/// peers (which resets their back-off), and by a slow tick.
async fn seeker(d: Arc<Daemon>, mut heard: mpsc::UnboundedReceiver<PeerId>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = d.wake.notified() => {}
            Some(peer) = heard.recv() => {
                if !d.store.wake_peer(&peer).unwrap_or(false) {
                    continue; // not a peer we're waiting for
                }
            }
            _ = tick.tick() => {}
        }
        if let Err(e) = seek_pass(&d).await {
            eprintln!("seeker: {e}");
        }
    }
}

async fn seek_pass(d: &Daemon) -> Result<(), String> {
    let store = &d.store;
    for file in store.wanted_files().map_err(|e| e.to_string())? {
        let root = file.root;
        expand_local(store, &root)?;
        if store.wants(&root, 1).map_err(|e| e.to_string())?.is_empty() {
            store.finish_file(&root).map_err(|e| e.to_string())?;
            d.deferred.lock().unwrap().remove(&root);
            store.need_file(&file).map_err(|e| e.to_string())?;
            d.upkeep_wake.notify_one();
            println!("seeker: {root} complete");
            continue;
        }
        for hint in store.hints(&root).map_err(|e| e.to_string())? {
            if hint.next_try_ms > now_ms() {
                continue;
            }
            let peer_hex = hex(&hint.peer);
            let link = match d.link_to(&hint.peer).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("seeker: {peer_hex} unreachable: {e}");
                    store.hint_result(&root, &hint.peer, false, now_ms()).map_err(|e| e.to_string())?;
                    continue;
                }
            };
            // Over a slow link (LoRa class), fetch it all only if it fits the budget;
            // otherwise only manifest nodes (the file is browsable, small parts
            // cross), and the rest waits for a faster path (ADR-0014).
            let q = d.quality(&hint.peer);
            let local = local_status(store, &file).local_chunks as u64 * 16 * 1024;
            let est = q.transfer_secs(file.size.saturating_sub(local));
            let nodes_only = q.slow() && est > d.slow_budget as f64;
            if nodes_only {
                if d.deferred.lock().unwrap().insert(root, est as u64).is_none() {
                    println!("seeker: {root}: ~{est:.0} s over the slow link to <{peer_hex}>; fetching the manifest only, the rest waits for a faster path");
                }
            } else {
                d.deferred.lock().unwrap().remove(&root);
            }
            // Rounds until this peer has nothing more for us (nodes reveal more wants).
            let mut progressed = false;
            for _ in 0..64 {
                let mut wants = store.wants(&root, 512).map_err(|e| e.to_string())?;
                if nodes_only {
                    wants.retain(|w| w.node);
                }
                if wants.is_empty() {
                    break;
                }
                let t0 = Instant::now();
                let pairs: Vec<(retifs_core::Cid, retifs_core::Seed)> = wants.iter().map(|w| (w.cid, w.seed)).collect();
                let round = match seek_round(&d.transport, link, &pairs, d.private_requests, Duration::from_secs(60)).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("seeker: {peer_hex}: {e}");
                        d.drop_link(&hint.peer);
                        break;
                    }
                };
                let bytes: u64 = round.got.iter().map(|(_, ct, _)| ct.len() as u64).sum();
                let _ = store.record_transfer(&hint.peer, bytes, t0.elapsed().as_millis() as u64);
                if round.got.is_empty() {
                    break;
                }
                progressed = true;
                for (i, ct, pt) in round.got {
                    arrived(store, &root, &wants[i], &ct, &pt)?;
                }
            }
            store.hint_result(&root, &hint.peer, progressed, now_ms()).map_err(|e| e.to_string())?;
            expand_local(store, &root)?;
            if store.wants(&root, 1).map_err(|e| e.to_string())?.is_empty() {
                store.finish_file(&root).map_err(|e| e.to_string())?;
                d.deferred.lock().unwrap().remove(&root);
                store.need_file(&file).map_err(|e| e.to_string())?;
                d.upkeep_wake.notify_one();
                println!("seeker: {root} complete");
                break;
            }
        }
    }
    Ok(())
}

/// Stores an arrived chunk (cache tier: it's for reading, never served on)
/// and, for a manifest node, turns its children into wants.
fn arrived(store: &SlabStore, root: &retifs_core::Cid, want: &Want, ct: &[u8], pt: &[u8]) -> Result<(), String> {
    match store.insert(&want.cid, ct, tier::CACHE) {
        Ok(_) | Err(retifs_store::StoreError::Full(_)) => {}
        Err(e) => return Err(e.to_string()),
    }
    if want.node {
        let node = if want.cid == *root { decode_root(pt, want.span) } else { decode_node(pt, want.span) }
            .map_err(|e| e.to_string())?;
        let children: Vec<Want> = node
            .entries
            .iter()
            .filter(|c| store.tier(&c.cid).ok().flatten().is_none())
            .map(|c| Want { cid: c.cid, seed: c.seed, span: c.span, node: !node.leaf })
            .collect();
        store.add_wants(root, &children).map_err(|e| e.to_string())?;
    }
    store.satisfied(root, &want.cid).map_err(|e| e.to_string())
}

/// Satisfies wants whose chunks are already local (expanding local nodes).
fn expand_local(store: &SlabStore, root: &retifs_core::Cid) -> Result<(), String> {
    loop {
        let mut progressed = false;
        for want in store.wants(root, 4096).map_err(|e| e.to_string())? {
            if let Ok(Some(ct)) = store.fetch(&want.cid)
                && let Ok(pt) = open(&want.cid, &want.seed, &ct)
            {
                arrived(store, root, &want, &ct, &pt)?;
                progressed = true;
            }
        }
        if !progressed {
            return Ok(());
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Walks the manifest using only the local store.
fn local_status(store: &SlabStore, file: &FileRef) -> Status {
    let mut status = Status { size: file.size, total_chunks: Some(0), ..Default::default() };
    let mut level = vec![NodeEntry { cid: file.root, seed: file.seed, span: file.size }];
    while !level.is_empty() {
        let mut next = Vec::new();
        for e in level {
            let is_root = e.cid == file.root;
            let node = store
                .fetch(&e.cid)
                .ok()
                .flatten()
                .and_then(|ct| open(&e.cid, &e.seed, &ct).ok())
                .and_then(|pt| if is_root { decode_root(&pt, e.span) } else { decode_node(&pt, e.span) }.ok());
            match node {
                Some(n) if n.leaf => {
                    for c in &n.entries {
                        status.total_chunks = status.total_chunks.map(|t| t + 1);
                        if store.tier(&c.cid).ok().flatten().is_some() {
                            status.local_chunks += 1;
                        }
                    }
                }
                Some(n) => next.extend(n.entries),
                None => {
                    status.missing_nodes += 1;
                    status.total_chunks = None;
                }
            }
        }
        level = next;
    }
    status
}
