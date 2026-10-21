//! Spike: embed Prns (personal-rns 0.3.7) as a client of the running prnsd.
//!
//! Two nodes in one process both attach to the local prnsd shared instance as
//! clients. The responder serves `/retifs/get` with growing replies; the
//! requester hears its announce through prnsd, links to it and fetches 1, 4
//! and 16 "chunks" of 16 KiB, which need Resource transfer.
//!
//!     cargo run -p retifs-net --example join_smoke
//!
//! Attaching as a client needs only the bus port: no RPC key, no transport identity.

use std::time::{Duration, Instant};

use personal_rns::interfaces::shared_instance::configured_policy;
use personal_rns::prelude::*;
use personal_rns::shared_instance::{
    SharedInstanceClientIntent, SharedInstanceRole, SharedInstanceTransport, connect_existing_shared_instance,
};

const GET: &str = "/retifs/get";
const CHUNK: usize = 16 * 1024;
const BUS_PORT: u16 = 37428;

struct Get;
impl RequestEndpoint for Get {
    const ENDPOINT_ID: &'static str = GET;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, ()>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let n = context.data.first().copied().unwrap_or(1) as usize;
        context.respond(body(n))
    }
}

fn body(n: usize) -> Vec<u8> {
    (0..n * CHUNK).map(|i| (i % 251) as u8).collect()
}

fn client_intent() -> SharedInstanceClientIntent {
    #[cfg(target_os = "linux")]
    let transport = SharedInstanceTransport::AbstractUnix { socket_path: "rns/default".into() };
    #[cfg(not(target_os = "linux"))]
    let transport = SharedInstanceTransport::Tcp;
    SharedInstanceClientIntent { bus_port: BUS_PORT, transport, policy: configured_policy(Default::default()) }
}

fn destination(serve: bool) -> PreConfiguredDestination<'static> {
    PreConfiguredDestination::Single {
        request_endpoints: if serve { ServeMyRequestEndpoints::Yes } else { ServeMyRequestEndpoints::No },
        resource_strategy: ResourceStrategy::Accept { max_uncompressed_bytes: 1 << 22, accept_compressed: true },
        maximum_request_bytes: Default::default(),
        app_name: "retifs",
        aspects: if serve { &["smoke", "server"] } else { &["smoke", "client"] },
        identity: try_generate_identity_secret().expect("identity generation"),
        announce_app_data: b"",
        proof: ProofStrategy::ProveAll,
        link_requests: LinkRequestPolicy::AcceptAll,
        ratchet: RatchetPolicy::NoRatchets,
    }
}

/// Prns node futures are large; Windows gives the main thread only 1 MB of stack.
fn main() {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .expect("tokio runtime")
                .block_on(run())
        })
        .expect("spawn main thread")
        .join()
        .expect("main thread");
}

async fn run() {
    let server_dest = destination(true);
    let server_hash = server_dest.destination_hash().expect("valid destination");
    let server = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [server_dest],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
        remote_control: personal_rns::remote_control::RemoteControlService::Unavailable.into(),
    });

    let (heard_tx, mut heard_rx) = tokio::sync::mpsc::unbounded_channel();
    let client = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [destination(false)],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![],
        on_event: move |event, _state| {
            if let PrnsEvent::Diagnostic(Diagnostic::AnnounceHeard { destination, hops, .. }) = event {
                let _ = heard_tx.send((destination, hops));
            }
        },
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
        remote_control: personal_rns::remote_control::RemoteControlService::Unavailable.into(),
    });

    for (name, handle) in [("server", server.handle()), ("client", client.handle())] {
        match connect_existing_shared_instance(&handle, client_intent()).await {
            Ok(SharedInstanceRole::JoinedAsClient { of }) => println!("{name}: attached to prnsd at {of}"),
            Ok(other) => panic!("{name}: unexpected role {other:?}"),
            Err(e) => panic!("{name}: no shared instance: {e:?}"),
        }
    }

    let announcer = server.handle();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            let cmd = PrnsCommand::AnnounceNow(AnnounceNow {
                destination: server_hash,
                target: AnnounceTarget::AllInterfaces,
                app_data: AnnounceAppData::Registered,
            });
            if announcer.issue(cmd).is_none() {
                return;
            }
        }
    });

    let client_handle = client.handle();
    let exchange = async {
        loop {
            let (dest, hops) = heard_rx.recv().await.expect("announce stream open");
            if dest == server_hash {
                println!("heard server announce via prnsd ({hops} hops)");
                break;
            }
        }
        let t = Instant::now();
        let link = client_handle.establish_link(server_hash).await.expect("link establishes");
        println!("link up in {:?}", t.elapsed());
        for n in [1u8, 4, 16] {
            let t = Instant::now();
            match client_handle.request(link, RequestEndpointId::of(GET), &[n]).await {
                Ok((resp, rtt)) => {
                    let ok = resp.as_slice() == body(n as usize).as_slice();
                    println!("get {n:>2} x 16 KiB: {:>7} bytes in {:?} (rtt {rtt:?}) {}",
                             resp.len(), t.elapsed(), if ok { "verified" } else { "WRONG BYTES" });
                }
                Err(e) => println!("get {n:>2} x 16 KiB: FAILED {e:?}"),
            }
        }
    };

    tokio::select! {
        r = tokio::time::timeout(Duration::from_secs(60), exchange) => {
            if r.is_err() { println!("timed out after 60 s") } else { println!("done") }
        }
        r = server.run() => println!("server stopped: {r:?}"),
        r = client.run() => println!("client stopped: {r:?}"),
    }
}
