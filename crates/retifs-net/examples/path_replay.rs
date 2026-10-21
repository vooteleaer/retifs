//! Reproduction: `request_path` for a destination whose route is already known
//! doesn't settle until the destination announces again.
//!
//! Three nodes in one process attach to the local prnsd as clients. The server
//! announces once. Client A hears that announce, then asks for a path to the
//! server; the shared instance answers with the announce A already has, A
//! rejects it as a known-route replay, and the request times out. Client B
//! attaches only after the announce, so the same answer is a first sighting
//! for B and settles at once. A link from A over its known route works
//! without any path request. Finally the server announces again while A has a
//! request pending, which settles it.
//!
//!     cargo run -p retifs-net --example path_replay

use std::time::{Duration, Instant};

use personal_rns::interfaces::shared_instance::configured_policy;
use personal_rns::node_introspection::NodeIntrospection;
use personal_rns::prelude::*;
use personal_rns::shared_instance::{
    SharedInstanceClientIntent, SharedInstanceRole, SharedInstanceTransport, connect_existing_shared_instance,
};

const BUS_PORT: u16 = 37428;

fn client_intent() -> SharedInstanceClientIntent {
    #[cfg(target_os = "linux")]
    let transport = SharedInstanceTransport::AbstractUnix { socket_path: "default".into() };
    #[cfg(not(target_os = "linux"))]
    let transport = SharedInstanceTransport::Tcp;
    SharedInstanceClientIntent { bus_port: BUS_PORT, transport, policy: configured_policy(Default::default()) }
}

fn destination(aspect: &'static str) -> PreConfiguredDestination<'static> {
    PreConfiguredDestination::Single {
        request_endpoints: ServeMyRequestEndpoints::No,
        resource_strategy: ResourceStrategy::AcceptNone,
        maximum_request_bytes: Default::default(),
        app_name: "retifs",
        aspects: if aspect == "server" { &["replay", "server"] } else { &["replay", "client"] },
        identity: try_generate_identity_secret().expect("identity generation"),
        announce_app_data: b"",
        proof: ProofStrategy::ProveAll,
        link_requests: LinkRequestPolicy::AcceptAll,
        ratchet: RatchetPolicy::NoRatchets,
    }
}

/// Starts a client node and returns its handle.
fn client_node() -> PrnsNodeHandle {
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [destination("client")],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
        remote_control: personal_rns::remote_control::RemoteControlService::Unavailable.into(),
    });
    let handle = node.handle();
    tokio::task::spawn_local(async move { node.run().await });
    handle
}

fn main() {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .expect("tokio runtime")
                .block_on(tokio::task::LocalSet::new().run_until(run()))
        })
        .expect("spawn main thread")
        .join()
        .expect("main thread");
}

async fn attach(name: &str, handle: &PrnsNodeHandle) {
    match connect_existing_shared_instance(handle, client_intent()).await {
        Ok(SharedInstanceRole::JoinedAsClient { .. }) => {}
        other => panic!("{name}: no shared instance: {other:?}"),
    }
}

async fn timed_path(name: &str, handle: &PrnsNodeHandle, dest: DestinationHash) -> bool {
    let t = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(20), handle.request_path(dest)).await;
    let ok = matches!(r, Ok(Ok(_)));
    println!("{name}: request_path -> {:?} after {:.1} s", r.map(|r| r.map(|_| "found")), t.elapsed().as_secs_f64());
    ok
}

async fn run() {
    let server_dest = destination("server");
    let server_hash = server_dest.destination_hash().expect("valid destination");
    let server = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: [server_dest],
        app_state: (),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![],
        on_event: |_event, _state| {},
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
        remote_control: personal_rns::remote_control::RemoteControlService::Unavailable.into(),
    });
    let sh = server.handle();
    tokio::task::spawn_local(async move { server.run().await });
    let ah = client_node();
    attach("server", &sh).await;
    attach("A", &ah).await;

    let announce = || {
        sh.issue(PrnsCommand::AnnounceNow(AnnounceNow {
            destination: server_hash,
            target: AnnounceTarget::AllInterfaces,
            app_data: AnnounceAppData::Registered,
        }))
    };
    announce();

    // A hears the announce (its route table gets the server).
    let t = Instant::now();
    while ah.route(server_hash).await.is_none() {
        assert!(t.elapsed() < Duration::from_secs(10), "A never heard the announce");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("A: route known after {:.1} s ({} hops)", t.elapsed().as_secs_f64(), ah.route(server_hash).await.unwrap().hops);

    // 1. Known route: the path request is answered with the same announce, rejected as a replay.
    let replayed = timed_path("A (route known)", &ah, server_hash).await;

    // 2. Control: a client that attached after the announce gets the same answer as a first sighting.
    let bh = client_node();
    attach("B", &bh).await;
    let fresh = timed_path("B (no route yet)", &bh, server_hash).await;

    // 3. A link over the known route works without a path request.
    let t = Instant::now();
    match tokio::time::timeout(Duration::from_secs(10), ah.establish_link(server_hash)).await {
        Ok(Ok(_)) => println!("A: link over known route, no path request: ok after {:.2} s", t.elapsed().as_secs_f64()),
        other => println!("A: link failed: {other:?}"),
    }

    // 4. A fresh announce settles a pending request.
    let pending = tokio::spawn({
        let ah = ah.clone();
        async move { timed_path("A (pending, server re-announces after 2 s)", &ah, server_hash).await }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    announce();
    let settled = pending.await.unwrap();

    println!(
        "\nsummary: known route {} | first sighting {} | after re-announce {}",
        if replayed { "settled" } else { "TIMED OUT" },
        if fresh { "settled" } else { "TIMED OUT" },
        if settled { "settled" } else { "TIMED OUT" },
    );
}
