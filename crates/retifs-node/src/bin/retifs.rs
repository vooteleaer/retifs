//! retifs CLI (prototype).
//!
//!     retifs get READ-CAP --from NODE [-o OUT] [--batch N] [--inflight N]
//!
//! Attaches to the local prnsd, finds a path to NODE (a retifsd destination
//! hash), fetches the file behind READ-CAP with batched, pipelined requests,
//! verifies every chunk and writes the plaintext.

use std::{path::PathBuf, time::{Duration, Instant}};

use personal_rns::prelude::*;
use retifs_core::FileRef;
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{attach, block_on, destination, new_identity, parse_destination},
};

struct Args {
    cap: FileRef,
    from: DestinationHash,
    out: PathBuf,
    opts: FetchOpts,
}

fn usage() -> ! {
    eprintln!("retifs get READ-CAP --from NODE [-o OUT] [--batch N] [--inflight N]");
    std::process::exit(2);
}

fn args() -> Args {
    let mut it = std::env::args().skip(1);
    if it.next().as_deref() != Some("get") {
        usage();
    }
    let cap: FileRef = it.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|e| panic!("{e}"));
    let (mut from, mut out, mut opts) = (None, PathBuf::from("retifs.out"), FetchOpts::default());
    while let Some(arg) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--from" => from = Some(parse_destination(&value()).expect("NODE is a 32-hex-digit destination hash")),
            "-o" | "--out" => out = value().into(),
            "--batch" => opts.batch = value().parse().expect("--batch N"),
            "--inflight" => opts.inflight = value().parse().expect("--inflight N"),
            _ => usage(),
        }
    }
    Args { cap, from: from.unwrap_or_else(|| usage()), out, opts }
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
    eprintln!("attached to {of}; requesting path");

    let work = async {
        let t0 = Instant::now();
        let path = tokio::time::timeout(Duration::from_secs(60), handle.request_path(args.from))
            .await
            .expect("no path to node within 60 s")
            .unwrap_or_else(|e| panic!("path request failed: {e:?}"));
        let t_path = t0.elapsed();
        eprintln!("path found in {t_path:?} ({:?} hops); linking", path.hops);
        let link = handle.establish_link(args.from).await.unwrap_or_else(|e| panic!("link failed: {e:?}"));
        let t_link = t0.elapsed() - t_path;
        eprintln!("link up in {t_link:?}; fetching");

        let t1 = Instant::now();
        let (data, stats) = fetch_file(&handle, link, &args.cap, args.opts).await.unwrap_or_else(|e| panic!("{e}"));
        let secs = t1.elapsed().as_secs_f64();
        std::fs::write(&args.out, &data).unwrap_or_else(|e| panic!("{}: {e}", args.out.display()));

        println!("path {:?} ({:?} hops), link {:?}", t_path, path.hops, t_link);
        println!(
            "fetched {} bytes in {:.2} s = {:.2} Mbps plaintext ({} chunks, {} requests, {} tree levels, {} ciphertext bytes; batch {} x {} in flight)",
            data.len(), secs, data.len() as f64 * 8.0 / secs / 1e6,
            stats.chunks, stats.requests, stats.tree_levels, stats.ciphertext_bytes,
            args.opts.batch, args.opts.inflight,
        );
        println!("verified and written to {}", args.out.display());
    };

    tokio::select! {
        () = work => {}
        r = node.run() => eprintln!("node stopped: {r:?}"),
    }
}
