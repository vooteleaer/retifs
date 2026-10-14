//! Minimal reproduction: concurrent Resource-sized request responses on one
//! Prns Link (personal-rns 0.3.7) can fail to settle.
//!
//! Two nodes attach to the local prnsd. The server answers every request with
//! 256 KiB. The client sends K requests at once on ONE link, then K requests
//! spread over K links, and counts how many settle within 20 s.
//!
//!     cargo run --release -p retifs-net --example inflight_stall [BLOCK_MS] [REQUEST_BYTES]
//!
//! BLOCK_MS (default 0) makes the handler block its thread that long before
//! responding, like a handler doing synchronous disk reads (retifsd does).
//! REQUEST_BYTES (default 1) sets the request body size; above the link MDU
//! the request itself travels as a Resource (retifsd's 32-CID batches: 1056 B).

use std::time::{Duration, Instant};

use personal_rns::prelude::*;
use retifs_net::node::{attach, block_on, destination, new_identity};

const EP: &str = "/stall/blob";
const SIZE: usize = 256 * 1024;

struct Blob;
impl RequestEndpoint for Blob {
    const ENDPOINT_ID: &'static str = EP;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;
    async fn handle(mut context: RequestContext<'_, ()>) -> Result<(), Decline> {
        let tag = context.data.first().copied().unwrap_or(0);
        let block_ms: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(0);
        std::thread::sleep(Duration::from_millis(block_ms));
        context.respond(vec![tag; SIZE])
    }
}

fn main() {
    block_on(run);
}

async fn run() {
    let server_dest = destination(new_identity(), true);
    let server_hash = server_dest.destination_hash().expect("valid destination");
    let server = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [server_dest],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Blob],
        on_event: |_e, _s| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    let client = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [destination(new_identity(), false)],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![],
        on_event: |_e, _s| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
    });
    attach(&server.handle()).await.expect("server attach");
    attach(&client.handle()).await.expect("client attach");
    let announcer = server.handle();
    tokio::spawn(async move {
        loop {
            announcer.issue(PrnsCommand::AnnounceNow(AnnounceNow {
                destination: server_hash,
                target: AnnounceTarget::AllInterfaces,
                app_data: AnnounceAppData::Registered,
            }));
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let h = client.handle();
    let work = async {
        tokio::time::timeout(Duration::from_secs(30), h.request_path(server_hash)).await.expect("path").expect("path");
        let block_ms = std::env::args().nth(1).unwrap_or_else(|| "0".into());
        let req = std::env::args().nth(2).unwrap_or_else(|| "1".into());
        println!("personal-rns 0.3.7, request {req} B, response {} KiB, handler blocks {block_ms} ms, timeout 20 s per request", SIZE / 1024);
        for k in [1usize, 2, 4, 8] {
            for spread in [false, true] {
                let links: Vec<_> = if spread {
                    let mut v = Vec::new();
                    for _ in 0..k {
                        v.push(h.establish_link(server_hash).await.expect("link"));
                    }
                    v
                } else {
                    vec![h.establish_link(server_hash).await.expect("link"); k]
                };
                let t = Instant::now();
                let mut tasks = Vec::new();
                for (i, link) in links.into_iter().enumerate() {
                    let h = h.clone();
                    tasks.push(tokio::spawn(async move {
                        let req_bytes: usize = std::env::args().nth(2).and_then(|a| a.parse().ok()).unwrap_or(1);
                        let body = vec![i as u8; req_bytes.max(1)];
                        let r = tokio::time::timeout(Duration::from_secs(20), h.request(link, RequestEndpointId::of(EP), &body)).await;
                        matches!(r, Ok(Ok((ref resp, _))) if resp.as_slice() == vec![i as u8; SIZE].as_slice())
                    }));
                }
                let mut ok = 0;
                for t in tasks {
                    ok += t.await.unwrap_or(false) as usize;
                }
                println!(
                    "{k} concurrent requests on {:<7}: {ok}/{k} settled correctly in {:?}",
                    if spread { format!("{k} links") } else { "1 link".into() },
                    t.elapsed()
                );
            }
        }
    };
    tokio::select! {
        () = work => {}
        r = server.run() => println!("server stopped: {r:?}"),
        r = client.run() => println!("client stopped: {r:?}"),
    }
}
