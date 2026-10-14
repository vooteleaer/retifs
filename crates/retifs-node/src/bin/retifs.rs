//! retifs CLI (prototype).
//!
//!     retifs get READ-CAP --from NODE [--from NODE]... [-o OUT]
//!                [--links N] [--batch N] [--inflight N] [--timeout SECS] [--cache DIR]
//!
//! Attaches to the local prnsd, opens N links to each NODE (a retifsd
//! destination hash), and fetches the file behind READ-CAP: local cache first,
//! then batched requests spread over all links. Chunks one node lacks are
//! taken from another. Every chunk is verified; the plaintext is written to OUT.

use std::{path::PathBuf, time::Instant};

use personal_rns::prelude::*;
use retifs_core::FileRef;
use retifs_net::{
    fetch::{fetch_file, FetchOpts, NoCache},
    node::{attach, block_on, destination, new_identity, parse_destination},
    transport::{PrnsTransport, Transport},
};
use retifs_store::{CacheTier, SlabStore};

struct Args {
    cap: FileRef,
    from: Vec<DestinationHash>,
    out: PathBuf,
    links_per_node: usize,
    cache: Option<PathBuf>,
    opts: FetchOpts,
}

fn usage() -> ! {
    eprintln!("retifs get READ-CAP --from NODE [--from NODE]... [-o OUT] [--links N] [--batch N] [--inflight N] [--timeout SECS] [--cache DIR]");
    std::process::exit(2);
}

fn args() -> Args {
    let mut it = std::env::args().skip(1);
    if it.next().as_deref() != Some("get") {
        usage();
    }
    let cap: FileRef = it.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|e| panic!("{e}"));
    let mut a = Args { cap, from: Vec::new(), out: "retifs.out".into(), links_per_node: 1, cache: None, opts: FetchOpts::default() };
    while let Some(arg) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--from" => a.from.push(parse_destination(&value()).expect("NODE is a 32-hex-digit destination hash")),
            "-o" | "--out" => a.out = value().into(),
            "--links" => a.links_per_node = value().parse().expect("--links N"),
            "--batch" => a.opts.batch = value().parse().expect("--batch N"),
            "--inflight" => a.opts.inflight_per_link = value().parse().expect("--inflight N"),
            "--cache" => a.cache = Some(value().into()),
            "--timeout" => a.opts.timeout = std::time::Duration::from_secs_f64(value().parse().expect("--timeout SECS")),
            _ => usage(),
        }
    }
    if a.from.is_empty() {
        usage();
    }
    a
}

fn main() {
    let args = args();
    block_on(move || get(args));
}

async fn get(args: Args) {
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [destination(new_identity(), false)],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    let handle = node.handle();
    let of = attach(&handle).await.unwrap_or_else(|e| panic!("{e}"));
    eprintln!("attached to {of}");

    let work = async {
        let transport = PrnsTransport::new(handle.clone());
        let t0 = Instant::now();
        let mut links = Vec::new();
        for peer in &args.from {
            for _ in 0..args.links_per_node {
                match transport.connect(*peer).await {
                    Ok(link) => links.push(link),
                    Err(e) => eprintln!("link to {}: {e}", hex(peer)),
                }
            }
        }
        if links.is_empty() {
            panic!("could not link to any node");
        }
        let t_links = t0.elapsed();

        let t1 = Instant::now();
        let result = match &args.cache {
            Some(dir) => {
                let mut store = SlabStore::open(dir).expect("open cache store");
                store.set_sync(false); // a cache can always be refetched
                fetch_file(&transport, &links, &args.cap, args.opts, &mut CacheTier(&mut store)).await
            }
            None => fetch_file(&transport, &links, &args.cap, args.opts, &mut NoCache).await,
        };
        let (data, stats) = result.unwrap_or_else(|e| panic!("{e}"));
        let secs = t1.elapsed().as_secs_f64();
        std::fs::write(&args.out, &data).unwrap_or_else(|e| panic!("{}: {e}", args.out.display()));

        println!("{} link(s) to {} node(s) in {:?}", links.len(), args.from.len(), t_links);
        println!(
            "fetched {} bytes in {:.2} s = {:.2} Mbps ({} chunks, {} tree levels, {} requests, {} retries, {} from cache, {} network bytes; batch {} x {} in flight per link)",
            data.len(), secs, data.len() as f64 * 8.0 / secs / 1e6,
            stats.chunks, stats.tree_levels, stats.requests, stats.retries, stats.cache_hits, stats.network_bytes,
            args.opts.batch, args.opts.inflight_per_link,
        );
        println!("verified and written to {}", args.out.display());
    };

    tokio::select! {
        () = work => {}
        r = node.run() => eprintln!("node stopped: {r:?}"),
    }
}

fn hex(d: &DestinationHash) -> String {
    d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
