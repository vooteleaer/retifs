//! Prns node helpers shared by retifsd and the retifs CLI.

use std::{future::Future, io, path::Path};

use personal_rns::identity::{IDENTITY_SECRET_KEY_LEN, Zeroizing};
use personal_rns::interfaces::shared_instance::configured_policy;
use personal_rns::prelude::*;
use personal_rns::shared_instance::{
    SharedInstanceClientIntent, SharedInstanceRole, SharedInstanceTransport, connect_existing_shared_instance,
};

pub const APP_NAME: &str = "retifs";
pub const SHARED_INSTANCE_PORT: u16 = 37428;

pub type IdentitySecret = Zeroizing<[u8; IDENTITY_SECRET_KEY_LEN]>;

/// Runs the future made by `make` on a multi-threaded runtime with large
/// stacks. Prns node futures overflow Windows' 1 MB default main-thread stack,
/// and `PrnsNode::run` isn't `Send`, so the future is created on the runtime thread.
pub fn block_on<T, Fut>(make: impl FnOnce() -> Fut + Send + 'static) -> T
where
    T: Send + 'static,
    Fut: Future<Output = T>,
{
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .expect("tokio runtime")
                .block_on(make())
        })
        .expect("spawn runtime thread")
        .join()
        .expect("runtime thread panicked")
}

/// Attaches the node to the local prnsd (or Python rnsd) shared instance as a
/// client. Needs only the bus port: no RPC key, no transport identity.
/// On Linux the abstract Unix socket is tried first, then TCP (daemons
/// configured with `shared_instance_type = tcp`, e.g. in containers).
pub async fn attach(handle: &PrnsNodeHandle) -> Result<String, String> {
    let transports = [
        // Instance name only: Prns connects to the abstract name "rns/<socket_path>".
        #[cfg(target_os = "linux")]
        SharedInstanceTransport::AbstractUnix { socket_path: "default".into() },
        SharedInstanceTransport::Tcp,
    ];

    let mut errors = Vec::new();
    for transport in transports {
        let intent = SharedInstanceClientIntent {
            bus_port: SHARED_INSTANCE_PORT,
            transport,
            policy: configured_policy(Default::default()),
        };
        match connect_existing_shared_instance(handle, intent).await {
            Ok(SharedInstanceRole::JoinedAsClient { of }) => return Ok(of),
            Ok(other) => return Err(format!("unexpected shared-instance role {other:?}")),
            Err(e) => errors.push(format!("{e:?}")),
        }
    }
    Err(format!("no Reticulum shared instance running ({}); start prnsd first", errors.join("; ")))
}

/// Loads the node identity, creating it on first use, so the node keeps one address.
pub fn load_or_create_identity(path: &Path) -> io::Result<IdentitySecret> {
    if let Ok(raw) = std::fs::read(path) {
        let bytes: [u8; IDENTITY_SECRET_KEY_LEN] = raw
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "identity file has the wrong length"))?;
        return Ok(Zeroizing::new(bytes));
    }
    let secret = new_identity();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, &secret[..])?;
    Ok(secret)
}

pub fn new_identity() -> IdentitySecret {
    try_generate_identity_secret().expect("OS entropy for identity generation")
}

/// The node's destination: `retifs.node` (serving) or `retifs.client`,
/// announcing the default interval.
pub fn destination(identity: IdentitySecret, serve: bool) -> PreConfiguredDestination<'static> {
    destination_announcing(identity, serve, retifs_core::announce::DEFAULT_ANNOUNCE_S, None, true)
}

/// The node's destination, its announces saying it announces every
/// `announce_s` seconds, its site if it has one, and whether it holds
/// others' copies (ADR-0014).
pub fn destination_announcing(identity: IdentitySecret, serve: bool, announce_s: u32, site: Option<retifs_core::announce::SiteTag>, holds: bool) -> PreConfiguredDestination<'static> {
    // Once per process: the destination needs it for the process's life.
    let app_data: &'static [u8] = Box::leak(retifs_core::announce::node_app_data(announce_s, site, holds).into_boxed_slice());
    PreConfiguredDestination::Single {
        request_endpoints: if serve { ServeMyRequestEndpoints::Yes } else { ServeMyRequestEndpoints::No },
        resource_strategy: ResourceStrategy::Accept { max_uncompressed_bytes: 32 << 20, accept_compressed: false },
        maximum_request_bytes: Default::default(),
        app_name: APP_NAME,
        aspects: if serve { &["node"] } else { &["client"] },
        identity,
        announce_app_data: app_data,
        proof: ProofStrategy::ProveAll,
        link_requests: LinkRequestPolicy::AcceptAll,
        ratchet: RatchetPolicy::NoRatchets,
    }
}

/// The node's `retifs.library` destination: it announces the node's public
/// libraries, one per announce, each with its own app data (ADR-0029). It
/// serves nothing; joining goes to the library's holders.
pub fn library_destination(identity: IdentitySecret) -> PreConfiguredDestination<'static> {
    PreConfiguredDestination::Single {
        request_endpoints: ServeMyRequestEndpoints::No,
        resource_strategy: ResourceStrategy::Accept { max_uncompressed_bytes: 0, accept_compressed: false },
        maximum_request_bytes: Default::default(),
        app_name: APP_NAME,
        aspects: &["library"],
        identity,
        announce_app_data: b"",
        proof: ProofStrategy::ProveAll,
        link_requests: LinkRequestPolicy::AcceptAll,
        ratchet: RatchetPolicy::NoRatchets,
    }
}

pub fn parse_destination(hex_str: &str) -> Option<DestinationHash> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches('<').trim_end_matches('>')).ok()?;
    DestinationHash::from_slice(&bytes)
}

pub fn destination_hex(hash: &DestinationHash) -> String {
    hex::encode(hash.as_bytes())
}
