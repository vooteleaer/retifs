//! retifsd (prototype): the retifs shared instance.
//!
//!     retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE]
//!             [--private-requests] [--public] [--put FILE]...
//!
//! SIZE: bytes, or with a K/M/G/T suffix (powers of 1024). Defaults (ADR-0012):
//! store limit 50 % of the volume, reserve max(10 %, 5 GiB), cache 20 % of the limit.
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
    manifest::{self, decode_node, decode_root, NodeEntry},
    open, ChunkToken, ConvergenceSecret, FileRef,
};
use personal_rns::routing::links::LinkId;
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{self, attach, block_on, destination, destination_hex, load_or_create_identity, parse_destination},
    protocol::{decode_have, decode_request, encode_bitmap, encode_response, GET_ENDPOINT, HAVE_ENDPOINT},
    seek::seek_round,
    transport::PrnsTransport,
};
use retifs_store::{tier, PeerId, Want};
use tokio::sync::{mpsc, Notify};
use retifs_store::{CacheTier, SlabStore};
use tokio::io::{AsyncRead, AsyncWrite};

struct Get;
impl RequestEndpoint<Arc<SlabStore>> for Get {
    const ENDPOINT_ID: &'static str = GET_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    /// Anonymous requesters prove, per item, that they know the chunk's seed;
    /// published chunks need no proof. Anything else gets the same answer as
    /// "don't have" (holder privacy, ADR-0010). Fetched/cached chunks are never
    /// in the serving index, so they're never served.
    async fn handle(mut context: RequestContext<'_, Arc<SlabStore>>) -> Result<(), Decline> {
        let Ok(items) = decode_request(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = context.state;
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
impl RequestEndpoint<Arc<SlabStore>> for Have {
    const ENDPOINT_ID: &'static str = HAVE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<SlabStore>>) -> Result<(), Decline> {
        let Ok(items) = decode_have(context.data) else {
            return Err(Decline::Ignore);
        };
        let store = context.state;
        let nonce = context.respond_token().link_id.as_bytes().to_vec();
        let bits: Vec<bool> = items
            .iter()
            .map(|(prefix, proof)| match store.served_by_prefix(prefix) {
                Ok(Some((_, token, published))) => published || token.is_some_and(|t| t.verify_have(&nonce, prefix, proof)),
                _ => false,
            })
            .collect();
        context.respond(encode_bitmap(&bits))
    }
}

struct Args {
    store: PathBuf,
    public: bool,
    put: Vec<PathBuf>,
    budget: retifs_store::Budget,
    private_requests: bool,
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
            "-h" | "--help" => {
                println!("retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE] [--public] [--put FILE]...");
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
        println!("put {}  {}", path.display(), file);
    }
    let identity = load_or_create_identity(&args.store.join("node_identity")).expect("node identity");
    let endpoint = libretifs::endpoint(&args.store);
    let store = Arc::new(store);
    let private_requests = args.private_requests;
    block_on(move || serve(store, identity, endpoint, private_requests));
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
}

async fn serve(store: Arc<SlabStore>, identity: node::IdentitySecret, endpoint: String, private_requests: bool) {
    let dest = destination(identity, true);
    let dest_hash = dest.destination_hash().expect("valid destination");
    let (heard_tx, heard_rx) = mpsc::unbounded_channel::<PeerId>();
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [dest],
        app_state: store.clone(),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get, Have],
        on_event: move |event, _state| {
            if let PrnsEvent::Diagnostic(Diagnostic::AnnounceHeard { destination, .. }) = event {
                let _ = heard_tx.send(*destination.as_bytes());
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
        private_requests,
    });
    println!("attached to shared instance {of}");
    println!("serving {} chunks as retifs.node <{}>", store.len().unwrap_or(0), daemon.node_hex);
    println!("local API at {endpoint}");

    tokio::spawn(local_api(endpoint, daemon.clone()));
    tokio::spawn(seeker(daemon, heard_rx));

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
    s
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
    let mut transport = d.transport.clone();
    transport.path_timeout = Duration::from_secs(20);
    for file in store.wanted_files().map_err(|e| e.to_string())? {
        let root = file.root;
        expand_local(store, &root)?;
        if store.wants(&root, 1).map_err(|e| e.to_string())?.is_empty() {
            store.finish_file(&root).map_err(|e| e.to_string())?;
            println!("seeker: {root} complete");
            continue;
        }
        for hint in store.hints(&root).map_err(|e| e.to_string())? {
            if hint.next_try_ms > now_ms() {
                continue;
            }
            let peer_hex = hex(&hint.peer);
            let cached = d.links.lock().unwrap().get(&hint.peer).copied();
            let link = match cached {
                Some(l) => l,
                None => {
                    let peer = parse_destination(&peer_hex).expect("stored peer id");
                    match async { transport.ensure_path(peer).await?; transport.link(peer).await }.await {
                        Ok(l) => {
                            d.links.lock().unwrap().insert(hint.peer, l);
                            l
                        }
                        Err(e) => {
                            eprintln!("seeker: {peer_hex} unreachable: {e}");
                            store.hint_result(&root, &hint.peer, false, now_ms()).map_err(|e| e.to_string())?;
                            continue;
                        }
                    }
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
                let round = match seek_round(&transport, link, &pairs, d.private_requests, Duration::from_secs(60)).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("seeker: {peer_hex}: {e}");
                        d.links.lock().unwrap().remove(&hint.peer);
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
