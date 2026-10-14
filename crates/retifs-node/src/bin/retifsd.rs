//! retifsd (prototype): imports files into the slab store and serves their
//! chunks over Reticulum at `/retifs/get`.
//!
//!     retifsd [--store DIR] [--public] [--put FILE]...
//!
//! Attaches to the local prnsd as a shared-instance client, prints a read-cap
//! for each imported file and its own destination hash, then serves until
//! stopped. The store is opened exclusively, so `--put` happens here, at
//! startup, until the local API (ADR-0004) exists.

use std::{path::PathBuf, sync::Arc, time::Duration};

use personal_rns::prelude::*;
use retifs_core::{manifest, ConvergenceSecret};
use retifs_net::{
    node::{self, attach, block_on, destination, destination_hex, load_or_create_identity},
    protocol::{decode_request, encode_response, GET_ENDPOINT},
};
use retifs_store::SlabStore;

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
    let mut a = Args { store: PathBuf::from("retifs-store"), public: false, put: Vec::new() };
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

fn main() {
    let args = args();
    let mut store = SlabStore::open(&args.store).expect("open slab store");

    for path in &args.put {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let secret = if args.public {
            ConvergenceSecret::public()
        } else {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).expect("OS entropy");
            ConvergenceSecret::personal(random)
        };
        let file = manifest::write(&mut store, &secret, &data).expect("store file");
        println!("put {}  {}", path.display(), file);
    }

    let identity = load_or_create_identity(&args.store.join("node_identity")).expect("node identity");
    let store = Arc::new(store);
    block_on(move || serve(store, identity));
}

async fn serve(store: Arc<SlabStore>, identity: node::IdentitySecret) {
    let dest = destination(identity, true);
    let dest_hash = dest.destination_hash().expect("valid destination");
    let chunks = store.len().unwrap_or(0);
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [dest],
        app_state: store,
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    let handle = node.handle();
    let of = attach(&handle).await.unwrap_or_else(|e| panic!("{e}"));
    println!("attached to shared instance {of}");
    println!("serving {chunks} chunks as retifs.node <{}>", destination_hex(&dest_hash));

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let cmd = PrnsCommand::AnnounceNow(AnnounceNow {
                destination: dest_hash,
                target: AnnounceTarget::AllInterfaces,
                app_data: AnnounceAppData::Registered,
            });
            if handle.issue(cmd).is_none() {
                return;
            }
        }
    });

    if let Err(e) = node.run().await {
        eprintln!("node stopped: {e}");
    }
}
