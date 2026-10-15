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
    manifest::{self, decode_node, decode_root, NodeEntry},
    open, ChunkToken, Cid, ConvergenceSecret, FileRef,
};
use personal_rns::node_introspection::DestinationIdentityQuery;
use personal_rns::routing::links::LinkId;
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{self, attach, block_on, destination, destination_hex, load_or_create_identity, parse_destination},
    protocol::{
        decode_have, decode_lease_request, decode_lease_status, decode_prove, decode_prove_reply, decode_receipt_reply,
        decode_request, encode_bitmap, encode_lease_request, encode_prove, encode_prove_reply, encode_receipt_reply,
        encode_response, LeaseRequest, LeaseStatus, ReceiptReply, GET_ENDPOINT, HAVE_ENDPOINT, LEASE_ENDPOINT,
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
        let status = match decode_lease_request(context.data) {
            Err(_) => LeaseStatus::Invalid,
            Ok(LeaseRequest::Offer { lease, .. }) if lease.expires <= now_s() => LeaseStatus::Invalid,
            Ok(LeaseRequest::Offer { lease, sources }) => match s.store.accept_lease(&lease, &sources, s.hold_limit()) {
                Ok(Accept::Accepted) => {
                    println!("lease {}: keeping {} chunk(s) for someone until {}", hex(&lease.id), lease.entries.len(), lease.expires);
                    s.pull_wake.notify_one();
                    LeaseStatus::Accepted
                }
                Ok(Accept::NoRoom) => LeaseStatus::NoRoom,
                Ok(Accept::Conflict) | Err(_) => LeaseStatus::Invalid,
            },
            Ok(LeaseRequest::Renew(r)) => match s.store.held_lease(&r.id) {
                Ok(Some(_)) if s.store.renew_lease(&r).unwrap_or(false) => LeaseStatus::Accepted,
                Ok(Some(_)) => LeaseStatus::Invalid,
                _ => LeaseStatus::Unknown,
            },
        };
        context.respond(vec![status as u8])
    }
}

/// `/retifs/receipt`: a signed receipt once every chunk of the lease is held, else progress.
struct ReceiptEndpoint;
impl RequestEndpoint<Arc<Shared>> for ReceiptEndpoint {
    const ENDPOINT_ID: &'static str = RECEIPT_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>) -> Result<(), Decline> {
        let Ok(id) = <LeaseId>::try_from(context.data) else {
            return Err(Decline::Ignore);
        };
        let s = context.state.clone();
        let reply = match s.store.held_lease(&id) {
            Ok(Some(h)) if h.held == h.lease.entries.len() => ReceiptReply::Receipt(Receipt::sign(&s.identity, &h.lease, h.expires)),
            Ok(Some(h)) => ReceiptReply::Progress { held: h.held as u16, total: h.lease.entries.len() as u16 },
            _ => ReceiptReply::Unknown,
        };
        context.respond(encode_receipt_reply(&reply))
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
    fn hold_limit(&self) -> u64 {
        self.hold_limit.unwrap_or_else(|| self.store.limits().map(|l| l.hard_max).unwrap_or(0))
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
            "--loss-target" => a.loss_target = it.next().and_then(|v| v.parse().ok()).expect("--loss-target P (e.g. 0.001)"),
            "--lease-term" => a.lease_term = duration_secs(&it.next().expect("--lease-term DURATION")).max(60),
            "-h" | "--help" => {
                println!(
                    "retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE] [--private-requests]
                             [--hold-for-others SIZE] [--lease-term DURATION] [--loss-target P] [--public] [--put FILE]..."
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
        let link = t.link(dest).await?;
        self.links.lock().unwrap().insert(*peer, link);
        Ok(link)
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
            Ok(Response::Status(full_status(&d.store, &cap)))
        }

        Request::Replicate { cap, to } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let chunks = file_chunks(&d.store, &cap)?;
            // The holders pull from this node with the chunks' tokens.
            d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
            for h in &to {
                let peer = *parse_destination(h).ok_or_else(|| format!("bad node hash {h}"))?.as_bytes();
                // Also name this node as a source, so the holder can pull what a push missed.
                match lease_to(d, &peer, &cap, &chunks, &[d.node_id]).await.map_err(|e| format!("{h}: {e}"))? {
                    true => println!("replicate: leased {} chunk(s) of {} to <{h}>", chunks.len(), cap.root),
                    false => return Err(format!("{h} refused the lease: NoRoom")),
                }
            }
            d.upkeep_wake.notify_one();
            Ok(Response::Status(full_status(&d.store, &cap)))
        }

        Request::Want { cap, from } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let peers: Vec<PeerId> = from
                .iter()
                .map(|h| parse_destination(h).map(|d| *d.as_bytes()).ok_or_else(|| format!("bad node hash {h}")))
                .collect::<Result<_, _>>()?;
            d.store.want_file(&cap, &peers).map_err(|e| e.to_string())?;
            d.wake.notify_one();
            Ok(Response::Status(full_status(&d.store, &cap)))
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

fn full_status(store: &SlabStore, cap: &FileRef) -> Status {
    let mut s = local_status(store, cap);
    s.seeking = store.is_wanted(&cap.root).unwrap_or(false);
    s.holders_known = store.hints(&cap.root).map(|h| h.len()).unwrap_or(0);
    let own = store.own_leases().unwrap_or_default();
    s.leased_to = own.iter().filter(|o| o.root == cap.root).map(|o| o.holder).collect::<std::collections::BTreeSet<_>>().len();
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
    let mut proved: HashMap<LeaseId, Instant> = HashMap::new();
    loop {
        tokio::select! {
            _ = d.upkeep_wake.notified() => {}
            _ = tick.tick() => {}
        }
        let Ok(leases) = d.store.own_leases() else { continue };
        for mut o in leases {
            match upkeep_one(&d, &mut o, &mut proved).await {
                Ok(true) => {
                    let _ = d.store.holder_result(&o.holder, o.proof != ProofState::Failed, now_ms());
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!("lease {} at <{}>: {e}", hex(&o.lease.id), hex(&o.holder));
                    let _ = d.store.holder_result(&o.holder, false, now_ms());
                    d.drop_link(&o.holder);
                }
            }
        }
        if let Ok(files) = d.store.needed_files() {
            for f in files {
                if let Err(e) = place(&d, &f).await {
                    eprintln!("placement {}: {e}", f.root);
                }
            }
        }
    }
}

/// Estimated chance of losing every copy of `file` (ADR-0014): the local copy
/// times each holder's loss estimate from its record. A holder whose receipt
/// ran out counts as lost; one that is only unreachable just gets a worse
/// record (lazy repair: it may come back with the data).
fn loss_now(d: &Daemon, file: &FileRef) -> (f64, std::collections::BTreeSet<PeerId>) {
    let pinned = d.store.tier(&file.root).ok().flatten().is_some_and(|f| f & tier::PINNED != 0);
    let mut risk = if pinned { 0.1 } else { 0.5 };
    let now = now_s();
    let mut worst: std::collections::BTreeMap<PeerId, f64> = Default::default();
    for o in d.store.own_leases().unwrap_or_default().into_iter().filter(|o| o.root == file.root) {
        let lapsed = o.receipt_until > 0 && o.receipt_until < now;
        let p = if lapsed || o.proof == ProofState::Failed {
            1.0
        } else {
            d.store.holder_stats(&o.holder).map(|s| s.loss()).unwrap_or(1.0)
        };
        let w = worst.entry(o.holder).or_insert(0.0);
        *w = w.max(p);
    }
    for p in worst.values() {
        risk *= p;
    }
    (risk, worst.into_keys().collect())
}

/// Adds the nearest storage nodes as holders of `file` until the loss estimate
/// is below the target. Data goes by push, so readers' copies (cache, never
/// served) can be placed too, and holders don't learn who sent it.
async fn place(d: &Daemon, file: &FileRef) -> Result<(), String> {
    let (mut risk, holders) = loss_now(d, file);
    if risk <= d.loss_target {
        return Ok(());
    }
    let chunks = file_chunks(&d.store, file)?;
    for n in d.store.storage_nodes().map_err(|e| e.to_string())? {
        if risk <= d.loss_target {
            break;
        }
        if n.peer == d.node_id || holders.contains(&n.peer) || n.avoid_until_ms > now_ms() {
            continue;
        }
        match lease_to(d, &n.peer, file, &chunks, &[]).await {
            Ok(true) => {
                risk *= d.store.holder_stats(&n.peer).map(|s| s.loss()).unwrap_or(1.0);
                println!("placement: {} kept at <{}> ({} hop(s)), loss estimate now {risk:.1e}", file.root, hex(&n.peer), n.hops);
            }
            Ok(false) => d.store.avoid_storage_node(&n.peer, now_ms() + 3_600_000).map_err(|e| e.to_string())?,
            Err(e) => {
                eprintln!("placement: <{}>: {e}", hex(&n.peer));
                d.store.avoid_storage_node(&n.peer, now_ms() + 600_000).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Offers `peer` leases over all of `chunks` and pushes what it lacks.
/// Ok(false): it has no room.
async fn lease_to(d: &Daemon, peer: &PeerId, file: &FileRef, chunks: &[(Cid, ChunkToken)], sources: &[PeerId]) -> Result<bool, String> {
    let link = d.link_to(peer).await?;
    for part in chunks.chunks(lease::MAX_CHUNKS) {
        let mut id = [0u8; lease::ID_LEN];
        getrandom::fill(&mut id).expect("OS entropy");
        let l = d.sign_lease(id, now_s() + d.lease_term, part.to_vec());
        let req = LeaseRequest::Offer { lease: l.clone(), sources: sources.to_vec() };
        let reply = d.ask(link, LEASE_ENDPOINT, encode_lease_request(&req)).await;
        match reply.and_then(|r| decode_lease_status(&r).map_err(|e| e.to_string())) {
            Ok(LeaseStatus::Accepted) => {
                d.store.record_own_lease(&l, peer, &file.root).map_err(|e| e.to_string())?;
                match push(d, link, &l).await {
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
async fn push(d: &Daemon, link: LinkId, l: &Lease) -> Result<usize, String> {
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
    let mut sent = 0;
    for batch in missing.chunks(MAX_PUT) {
        let cts: Vec<Vec<u8>> = batch.iter().filter_map(|c| d.store.fetch(c).ok().flatten()).collect();
        if cts.is_empty() {
            continue;
        }
        let bits = decode_bitmap(&d.ask(link, PUT_ENDPOINT, encode_put(&l.id, &cts)).await?, cts.len()).map_err(|e| e.to_string())?;
        sent += bits.iter().filter(|&&b| b).count();
    }
    Ok(sent)
}

/// Ok(true) if the holder was contacted (and answered).
async fn upkeep_one(d: &Daemon, o: &mut OwnLease, proved: &mut HashMap<LeaseId, Instant>) -> Result<bool, String> {
    let now = now_s();
    let id = o.lease.id;
    let due_proof = |o: &OwnLease, proved: &HashMap<LeaseId, Instant>| {
        o.receipt_until > 0 && proved.get(&id).is_none_or(|t| t.elapsed() > PROOF_INTERVAL)
    };
    let renew = o.expires < now + d.lease_term / 2;
    if !renew && o.receipt_until >= o.expires && !due_proof(o, proved) {
        return Ok(false);
    }
    let link = d.link_to(&o.holder).await?;
    let before = (o.expires, o.receipt_until, o.proof);

    if renew {
        let expires = now + d.lease_term;
        let r = Renewal::sign(&LeaseKey::derive(&d.namespace_key, &id), id, expires);
        let status = decode_lease_status(&d.ask(link, LEASE_ENDPOINT, encode_lease_request(&LeaseRequest::Renew(r))).await?)
            .map_err(|e| e.to_string())?;
        match status {
            LeaseStatus::Accepted => {
                o.expires = expires;
                println!("lease {}: renewed at <{}> until {expires}", hex(&id), hex(&o.holder));
            }
            LeaseStatus::Unknown => reoffer(d, link, o, expires).await?,
            other => return Err(format!("renewal refused: {other:?}")),
        }
    }

    if o.receipt_until < o.expires {
        let reply = decode_receipt_reply(&d.ask(link, RECEIPT_ENDPOINT, id.to_vec()).await?).map_err(|e| e.to_string())?;
        match reply {
            ReceiptReply::Receipt(r) => {
                if r.lease_id != id || r.lease_digest != o.lease.digest() {
                    return Err("receipt for another lease".into());
                }
                if node_destination(&r.holder) != o.holder {
                    return Err("receipt signed by another node".into());
                }
                o.receipt_until = r.holds_until.min(o.expires);
                println!("lease {}: receipt from <{}>, held until {}", hex(&id), hex(&o.holder), o.receipt_until);
            }
            ReceiptReply::Progress { held, total } => {
                let sent = push(d, link, &o.lease).await?;
                println!("lease {}: <{}> had {held}/{total}, pushed {sent}", hex(&id), hex(&o.holder));
            }
            ReceiptReply::Unknown => {
                println!("lease {}: <{}> lost the lease, offering it again", hex(&id), hex(&o.holder));
                let expires = o.expires.max(now + d.lease_term / 2);
                reoffer(d, link, o, expires).await?;
            }
        }
    }

    if due_proof(o, proved) {
        let n = o.lease.entries.len();
        let mut rnd = [0u8; 16 + 8];
        getrandom::fill(&mut rnd).expect("OS entropy");
        let nonce: [u8; 16] = rnd[..16].try_into().unwrap();
        let indices: Vec<u16> = rnd[16..].chunks(2).map(|b| (u16::from_be_bytes([b[0], b[1]]) as usize % n) as u16).collect();
        let mut expected = Vec::new();
        for &i in &indices {
            let ct = d.store.fetch(&o.lease.entries[i as usize].0).map_err(|e| e.to_string())?;
            expected.push(ct.map(|ct| lease::prove(&nonce, &ct)));
        }
        let reply = d.ask(link, PROVE_ENDPOINT, encode_prove(&id, &nonce, &indices)).await?;
        let answers = decode_prove_reply(&reply, indices.len()).map_err(|e| e.to_string())?;
        // Only chunks this node still has can be checked.
        let checked: Vec<bool> = expected.iter().zip(&answers).filter_map(|(e, a)| e.map(|e| Some(e) == *a)).collect();
        if !checked.is_empty() {
            o.proof = if checked.iter().all(|&ok| ok) { ProofState::Passed } else { ProofState::Failed };
            println!("lease {}: storage proof from <{}>: {:?} ({} chunk(s))", hex(&id), hex(&o.holder), o.proof, checked.len());
        }
        proved.insert(id, Instant::now());
    }

    if (o.expires, o.receipt_until, o.proof) != before {
        d.store.update_own_lease(o).map_err(|e| e.to_string())?;
    }
    Ok(true)
}

/// The holder lost a lease (restart without it, expiry): offer it again under
/// the same ID, with a fresh expiry, and wait for a new receipt.
async fn reoffer(d: &Daemon, link: LinkId, o: &mut OwnLease, expires: u64) -> Result<(), String> {
    let l = d.sign_lease(o.lease.id, expires, o.lease.entries.clone());
    let req = LeaseRequest::Offer { lease: l.clone(), sources: vec![d.node_id] };
    match decode_lease_status(&d.ask(link, LEASE_ENDPOINT, encode_lease_request(&req)).await?).map_err(|e| e.to_string())? {
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
            // Rounds until this peer has nothing more for us (nodes reveal more wants).
            let mut progressed = false;
            for _ in 0..64 {
                let wants = store.wants(&root, 512).map_err(|e| e.to_string())?;
                if wants.is_empty() {
                    break;
                }
                let pairs: Vec<(retifs_core::Cid, retifs_core::Seed)> = wants.iter().map(|w| (w.cid, w.seed)).collect();
                let round = match seek_round(&d.transport, link, &pairs, d.private_requests, Duration::from_secs(60)).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("seeker: {peer_hex}: {e}");
                        d.drop_link(&hint.peer);
                        break;
                    }
                };
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
