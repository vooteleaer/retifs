//! retifsd (prototype): the retifs shared instance.
//!
//!     retifsd [--store DIR] [--public] [--put FILE]...
//!
//! - Owns the slab store (default: libretifs::default_store_dir()).
//! - Attaches to the local prnsd as a shared-instance client and serves chunks
//!   to other nodes at `/retifs/get`.
//! - Serves the local API (ADR-0004) to apps via libretifs: put, get, status.
//!
//! `--put` imports files at startup (kept for scripting); normally use
//! `retifs put` while the daemon runs.

use std::{path::PathBuf, sync::Arc, time::{Duration, Instant}};

use libretifs::{read_frame, write_frame, Envelope, GetStats, Request, Response, Status, PROTOCOL_VERSION};
use personal_rns::prelude::*;
use retifs_core::{
    manifest::{self, decode_node, NodeEntry},
    open, ConvergenceSecret, FileRef,
};
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{self, attach, block_on, destination, destination_hex, load_or_create_identity, parse_destination},
    protocol::{decode_request, encode_response, GET_ENDPOINT},
    transport::PrnsTransport,
};
use retifs_store::{CacheTier, PinnedTier, SlabStore};
use tokio::io::{AsyncRead, AsyncWrite};

struct Get;
impl RequestEndpoint<Arc<SlabStore>> for Get {
    const ENDPOINT_ID: &'static str = GET_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<SlabStore>>) -> Result<(), Decline> {
        let Ok(cids) = decode_request(context.data) else {
            return Err(Decline::Ignore);
        };
        // Ciphertext only; a corrupt local copy is reported as missing.
        let items: Vec<Option<Vec<u8>>> = cids.iter().map(|c| context.state.fetch(c).ok().flatten()).collect();
        context.respond(encode_response(&items))
    }
}

struct Args {
    store: PathBuf,
    public: bool,
    put: Vec<PathBuf>,
}

fn args() -> Args {
    let mut a = Args { store: libretifs::default_store_dir(), public: false, put: Vec::new() };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => a.store = it.next().expect("--store DIR").into(),
            "--put" => a.put.push(it.next().expect("--put FILE").into()),
            "--public" => a.public = true,
            "-h" | "--help" => {
                println!("retifsd [--store DIR] [--public] [--put FILE]...");
                std::process::exit(0);
            }
            other => panic!("unknown argument {other}"),
        }
    }
    a
}

fn secret(public: bool) -> ConvergenceSecret {
    if public {
        ConvergenceSecret::public()
    } else {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).expect("OS entropy");
        ConvergenceSecret::personal(random)
    }
}

fn main() {
    let args = args();
    std::fs::create_dir_all(&args.store).expect("create store dir");
    let store = match SlabStore::open(&args.store) {
        Ok(s) => s,
        Err(retifs_store::StoreError::Db(e)) if matches!(*e, redb::Error::DatabaseAlreadyOpen) => {
            eprintln!("retifsd: another retifsd is already using {}", args.store.display());
            std::process::exit(1);
        }
        Err(e) => panic!("open slab store {}: {e}", args.store.display()),
    };
    for path in &args.put {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let file = manifest::write(&mut PinnedTier(&store), &secret(args.public), &data).expect("store file");
        println!("put {}  {}", path.display(), file);
    }
    let identity = load_or_create_identity(&args.store.join("node_identity")).expect("node identity");
    let endpoint = libretifs::endpoint(&args.store);
    let store = Arc::new(store);
    block_on(move || serve(store, identity, endpoint));
}

struct Daemon {
    store: Arc<SlabStore>,
    transport: PrnsTransport,
    node_hex: String,
}

async fn serve(store: Arc<SlabStore>, identity: node::IdentitySecret, endpoint: String) {
    let dest = destination(identity, true);
    let dest_hash = dest.destination_hash().expect("valid destination");
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [dest],
        app_state: store.clone(),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    let handle = node.handle();
    let of = attach(&handle).await.unwrap_or_else(|e| panic!("{e}"));
    let daemon = Arc::new(Daemon {
        store: store.clone(),
        transport: PrnsTransport::new(handle.clone()),
        node_hex: destination_hex(&dest_hash),
    });
    println!("attached to shared instance {of}");
    println!("serving {} chunks as retifs.node <{}>", store.len().unwrap_or(0), daemon.node_hex);
    println!("local API at {endpoint}");

    tokio::spawn(local_api(endpoint, daemon));

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
        Request::Ping => Ok(Response::Pong { node: d.node_hex.clone(), chunks: d.store.len().map_err(|e| e.to_string())? }),

        Request::Put { data, public } => {
            let store = d.store.clone();
            let file = tokio::task::spawn_blocking(move || manifest::write(&mut PinnedTier(&store), &secret(public), &data))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
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
            Ok(Response::Status(local_status(&d.store, &cap)))
        }
    }
}

/// Walks the manifest using only the local store.
fn local_status(store: &SlabStore, file: &FileRef) -> Status {
    let mut status = Status { size: file.size, total_chunks: Some(0), ..Default::default() };
    let mut level = vec![NodeEntry { cid: file.root, seed: file.seed, span: file.size }];
    while !level.is_empty() {
        let mut next = Vec::new();
        for e in level {
            let node = store
                .fetch(&e.cid)
                .ok()
                .flatten()
                .and_then(|ct| open(&e.cid, &e.seed, &ct).ok())
                .and_then(|pt| decode_node(&pt, e.span).ok());
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
