//! retifsd (prototype): the retifs shared instance.
//!
//!     retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE]
//!             [--private-requests] [--hold-for-others SIZE] [--db-cache SIZE] [--lease-term DURATION] [--loss-target P]
//!             [--public] [--put FILE]...
//!
//! SIZE: bytes, or with a K/M/G/T suffix (powers of 1024). Defaults (ADR-0012):
//! store limit 50 % of the volume, reserve max(10 %, 5 GiB), cache 20 % of the limit.
//! `--hold-for-others`: hold leased data for others up to SIZE (default: up to the
//! store limit; 0 opts out). Every node is a storage node by default (ADR-0014).
//! `--slow-link-budget`: the most a file may take over a slow link (LoRa class) before
//! only its manifest is fetched and the rest waits for a faster path (default 10m).
//! `--treat-as-slow NODE`: testing only; plan as if NODE were behind LoRa.
//! `--stamp-cost`: proof of work (bits, LXMF stamps) asked of every lease offer to this
//! node (default 20 bits: about 0.1 s per lease on a desktop, a few seconds on a Pi;
//! 0: none). `--max-stamp-cost`: the most this node pays when offering leases (default 24).
//! A solver reuses the hash state after the workblock, so each try costs one small hash.
//! `--nomadnet NS [--nomadnet-name NAME]`: also run a NomadNet node serving namespace NS
//! (own or a followed channel's `ch-…`): a record with `path=/x.mu` is the page
//! `/page/x.mu`; without an `/index.mu`, an index of the pages is generated.
//! `--loss-target`: keep adding nearby holders for each needed file until the
//! estimated chance of losing every copy is below P (default 0.001).
//! `--min-copies`: and until there are at least N copies, this node's own
//! included (default 3: two elsewhere), whatever the estimate says.
//! `--site NAME`: where this node is ("prangli-home"); its announces carry a
//! tag of it, and of the copies of this node's files, at least one is kept at
//! another site.
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

use libretifs::{
    read_frame, write_frame, AppInfo, AttrValue, ChannelInfo, Envelope, FollowInfo, GetStats, HistoryEntry, NsView, RecordView,
    Request, Response, Status, TxStep,
    PROTOCOL_VERSION,
};
use personal_rns::prelude::*;
use retifs_core::{
    channel::{key_id, ChannelAddr, ChannelKey, Commit, Head, NsId},
    index,
    lease::{self, node_destination, node_destination_of, Lease, LeaseId, LeaseKey, Receipt, Renewal},
    stamp,
    manifest::{self, decode_node, decode_root, NodeEntry},
    keywrap,
    checkpoint::{state_secret, Checkpoint, Frontier},
    ops::{self, Op, OpsFile, Right, State, WriterCommit, MAX_CLOCK_AHEAD_MS},
    prolly,
    invite::{self, Invitation},
    record::{Record, RecordId, Snapshot, Value},
    share,
    open, ChunkToken, Cid, ConvergenceSecret, FileRef,
};
use personal_rns::node_introspection::DestinationIdentityQuery;
use personal_rns::routing::request_handlers::{RequestPathHash, RequestPolicy};
use personal_rns::routing::links::LinkId;
use retifs_net::{
    fetch::{fetch_file, FetchOpts},
    node::{self, attach, block_on, destination_hex, load_or_create_identity, parse_destination},
    protocol::{
        decode_have, decode_lease_request, decode_lease_status, decode_lease_statuses, decode_prove, decode_prove_reply,
        decode_receipt_replies, decode_receipt_request, encode_receipt_replies, encode_receipt_request, MAX_BUNDLE,
        decode_request, encode_bitmap, encode_lease_request, encode_prove, encode_prove_reply,
        encode_lease_status, encode_response, LeaseRequest, LeaseStatus, ReceiptReply, GET_ENDPOINT, HAVE_ENDPOINT, LEASE_ENDPOINT,
        PROVE_ENDPOINT, RECEIPT_ENDPOINT, decode_bitmap, decode_put, encode_have, encode_put, HAVE_PREFIX, MAX_HAVE,
        MAX_PUT, PUT_ENDPOINT, HEAD_ENDPOINT, API_ENDPOINT, MAX_QUERY_TOKENS, QUERY_ENDPOINT, INVITE_ENDPOINT,
    },
    seek::{pull_round, seek_round},
    transport::{PrnsTransport, Transport},
};
use retifs_store::{tier, Accept, MadeInvite, OwnLease, PeerId, ProofState, Want};
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
    /// Bits of proof of work asked of every lease offer (0: none).
    stamp_cost: u8,
    /// Requests from own devices over a Link, answered by the daemon (ADR-0019).
    api: mpsc::UnboundedSender<ApiCall>,
    invites: mpsc::UnboundedSender<InviteCall>,
}

/// `/retifs/query`: blind index search (ADR-0019). Answers only for an index
/// held here, and only to an asker that proves the search secret on this
/// link; otherwise the same empty answer as "no such index".
struct QueryEndpoint;
impl RequestEndpoint<Arc<Shared>> for QueryEndpoint {
    const ENDPOINT_ID: &'static str = QUERY_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let data = context.data;
        let n = data.len().saturating_sub(48) / 16;
        if data.len() < 64 || !(data.len() - 48).is_multiple_of(16) || n > MAX_QUERY_TOKENS {
            return Err(Decline::Ignore);
        }
        let id: NsId = data[..16].try_into().unwrap();
        let proof: [u8; 32] = data[16..48].try_into().unwrap();
        let tokens: Vec<index::Token> = data[48..].chunks(16).map(|t| t.try_into().unwrap()).collect();
        let nonce = context.respond_token().link_id.as_bytes().to_vec();
        let answer = held_index(&context.state.store, &id)
            .filter(|(_, search)| index::query_proof(search, &nonce) == proof)
            .and_then(|(desc, _)| search_answer(&context.state.store, &desc, &tokens))
            .unwrap_or_default();
        context.respond(answer)
    }
}

/// The latest index this node holds for index channel `id` (followed, or
/// its own), with that channel's search secret.
fn held_index(store: &SlabStore, id: &NsId) -> Option<(index::Descriptor, ConvergenceSecret)> {
    let (file, key) = match store.followed(id).ok().flatten() {
        Some(f) => (f.current?, f.addr.read_key),
        None => {
            let c = store
                .own_channels()
                .ok()?
                .into_iter()
                .find(|c| c.name.starts_with("idx:") && ChannelKey::from_secrets(c.signing_seed, c.read_key).addr().ns_id() == *id)?;
            let (cid, seed) = c.last?;
            let addr = ChannelKey::from_secrets(c.signing_seed, c.read_key).addr();
            let ct = store.fetch(&cid).ok()??;
            (Commit::decode(&open(&cid, &seed, &ct).ok()?, &addr).ok()?.root, c.read_key)
        }
    };
    let desc = index::Descriptor::decode(&manifest::read_all(store, &file).ok()?).ok()?;
    Some((desc, ConvergenceSecret::personal(key)))
}

/// `time (u64) ‖ state len (u16) ‖ state ‖ (count (u32) ‖ entry (16)*)` per token.
fn search_answer(store: &SlabStore, desc: &index::Descriptor, tokens: &[index::Token]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&desc.time_ms.to_be_bytes());
    out.extend_from_slice(&u16::try_from(desc.state.len()).ok()?.to_be_bytes());
    out.extend_from_slice(&desc.state);
    for t in tokens {
        let entries = match &desc.index {
            Some(root) => index::lookup(store, root, t).ok()?,
            None => Vec::new(),
        };
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for e in entries {
            out.extend_from_slice(&e);
        }
    }
    Some(out)
}

/// Splits a search answer: time, sealed state, entries per token.
fn parse_search_answer(b: &[u8], tokens: usize) -> Option<(u64, Vec<u8>, Vec<Vec<index::Entry>>)> {
    let time = u64::from_be_bytes(b.get(..8)?.try_into().ok()?);
    let n = u16::from_be_bytes(b.get(8..10)?.try_into().ok()?) as usize;
    let state = b.get(10..10 + n)?.to_vec();
    let mut at = 10 + n;
    let mut lists = Vec::new();
    for _ in 0..tokens {
        let count = u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4;
        let raw = b.get(at..at.checked_add(count.checked_mul(16)?)?)?;
        lists.push(raw.chunks(16).map(|e| e.try_into().unwrap()).collect());
        at += count * 16;
    }
    (at == b.len()).then_some((time, state, lists))
}

/// A local API request that arrived over a Link, to answer later.
struct ApiCall {
    requester: Option<[u8; 16]>,
    body: Vec<u8>,
    token: RespondToken,
}

/// `/retifs/api`: the local API for the user's own nodes (ADR-0019). The
/// requester must identify; the daemon checks it against its devices and
/// answers from another task, since a request may wait on the network.
struct ApiEndpoint;
impl RequestEndpoint<Arc<Shared>> for ApiEndpoint {
    const ENDPOINT_ID: &'static str = API_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let call = ApiCall {
            requester: context.requester.map(|r| *r.as_bytes()),
            body: context.data.to_vec(),
            token: context.respond_token(),
        };
        let _ = context.state.api.send(call);
        Err(Decline::Ignore) // answered by `api_server`
    }
}

/// An invitation redemption that arrived over a Link (ADR-0020), to answer
/// once the grant is written.
struct InviteCall {
    link_id: Vec<u8>,
    body: Vec<u8>,
    token: RespondToken,
}

/// `/retifs/invite`: anyone may redeem an invitation; the proof (bound to
/// this Link) is what counts.
struct InviteEndpoint;
impl RequestEndpoint<Arc<Shared>> for InviteEndpoint {
    const ENDPOINT_ID: &'static str = INVITE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let token = context.respond_token();
        let call = InviteCall { link_id: token.link_id.as_bytes().to_vec(), body: context.data.to_vec(), token };
        let _ = context.state.invites.send(call);
        Err(Decline::Ignore) // answered by `invite_server`
    }
}

struct Get;
impl RequestEndpoint<Arc<Shared>> for Get {
    const ENDPOINT_ID: &'static str = GET_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    /// Anonymous requesters prove, per item, that they know the chunk's seed;
    /// published chunks need no proof. Anything else gets the same answer as
    /// "don't have" (holder privacy, ADR-0010). Fetched/cached chunks are never
    /// in the serving index, so they're never served.
    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
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

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
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

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let s = context.state.clone();
        let renew = |r: &Renewal| match s.store.held_lease(&r.id) {
            Ok(Some(_)) if s.store.renew_lease(r).unwrap_or(false) => LeaseStatus::Accepted,
            Ok(Some(_)) => LeaseStatus::Invalid,
            _ => LeaseStatus::Unknown,
        };
        let status = match decode_lease_request(context.data) {
            Ok(LeaseRequest::RenewMany(rs)) => return context.respond(rs.iter().map(|r| renew(r).byte()).collect::<Vec<u8>>()),
            Err(_) => LeaseStatus::Invalid,
            Ok(LeaseRequest::Offer { lease, .. }) if lease.expires <= now_s() => LeaseStatus::Invalid,
            // Proof of work against junk leases (ADR-0014), checked before anything is stored.
            Ok(LeaseRequest::Offer { lease, stamp, .. })
                if s.stamp_cost > 0
                    && !stamp.is_some_and(|st| stamp::valid(&stamp::workblock(&stamp::lease_material(&lease)), &st, s.stamp_cost)) =>
            {
                LeaseStatus::StampRequired(s.stamp_cost)
            }
            Ok(LeaseRequest::Offer { lease, sources, .. }) => match s.store.accept_lease(&lease, &sources, s.hold_limit()) {
                Ok(Accept::Accepted) => {
                    println!("lease {}: keeping {} chunk(s) for someone until {}", hex(&lease.id), lease.entries.len(), lease.expires);
                    s.pull_wake.notify_one();
                    LeaseStatus::Accepted
                }
                Ok(Accept::NoRoom) => LeaseStatus::NoRoom,
                Ok(Accept::Conflict) | Err(_) => LeaseStatus::Invalid,
            },
            Ok(LeaseRequest::Renew(r)) => renew(&r),
        };
        context.respond(encode_lease_status(status))
    }
}

/// `/retifs/receipt`: per lease asked about (up to 64 at once), a signed
/// receipt once every chunk is held, else progress.
struct ReceiptEndpoint;
impl RequestEndpoint<Arc<Shared>> for ReceiptEndpoint {
    const ENDPOINT_ID: &'static str = RECEIPT_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let Ok(ids) = decode_receipt_request(context.data) else {
            return Err(Decline::Ignore);
        };
        let s = context.state.clone();
        let replies: Vec<ReceiptReply> = ids
            .iter()
            .map(|id| match s.store.held_lease(id) {
                Ok(Some(h)) if h.held == h.lease.entries.len() => ReceiptReply::Receipt(Receipt::sign(&s.identity, &h.lease, h.expires)),
                Ok(Some(h)) => ReceiptReply::Progress { held: h.held as u16, total: h.lease.entries.len() as u16 },
                _ => ReceiptReply::Unknown,
            })
            .collect();
        context.respond(encode_receipt_replies(&replies))
    }
}

/// `/retifs/prove`: storage proofs for chunks of a held lease (fresh nonce each time).
struct ProveEndpoint;
impl RequestEndpoint<Arc<Shared>> for ProveEndpoint {
    const ENDPOINT_ID: &'static str = PROVE_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
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

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
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

/// `/retifs/head`: the latest head this node knows for a namespace (its own
/// channels and those it follows), or nothing. Heads are signed and say only
/// which commit is latest; the commit's seed is encrypted to readers (ADR-0015).
struct HeadEndpoint;
impl RequestEndpoint<Arc<Shared>> for HeadEndpoint {
    const ENDPOINT_ID: &'static str = HEAD_ENDPOINT;
    const POLICY: RequestEndpointPolicy = RequestEndpointPolicy::AllowAll;

    async fn handle(mut context: RequestContext<'_, Arc<Shared>>, _node: &impl PrnsNodeApi) -> Result<(), Decline> {
        let store = &context.state.store;
        let head = match context.data.len() {
            16 => store.head_for(context.data.try_into().unwrap()).ok().flatten().unwrap_or_default(),
            // ns_id ‖ writer: one writer's head of a multi-writer namespace (ADR-0017).
            48 => writer_head_bytes(store, context.data[..16].try_into().unwrap(), context.data[16..].try_into().unwrap()),
            // ns_id ‖ writer ‖ key id: that writer's latest head under a given read key,
            // so members can cross a key rotation.
            64 => store
                .key_head(
                    context.data[..16].try_into().unwrap(),
                    context.data[16..48].try_into().unwrap(),
                    context.data[48..].try_into().unwrap(),
                )
                .ok()
                .flatten()
                .unwrap_or_default(),
            _ => return Err(Decline::Ignore),
        };
        context.respond(head)
    }
}

/// The latest head of `writer` in namespace `ns`: our own (as creator or
/// member), or one we hold for another writer.
fn writer_head_bytes(store: &SlabStore, ns: &[u8; 16], writer: &[u8; 32]) -> Vec<u8> {
    for c in store.own_channels().unwrap_or_default() {
        if c.head.is_empty() {
            continue;
        }
        let key = match store.member_channel(&c.name).ok().flatten() {
            Some(id) => ChannelKey::member(c.signing_seed, c.read_key, id),
            None => ChannelKey::from_secrets(c.signing_seed, c.read_key),
        };
        if key.ns_id() == *ns && key.writer() == *writer {
            return c.head;
        }
    }
    store.writer_head(ns, writer).ok().flatten().map(|h| h.head).unwrap_or_default()
}

impl Shared {
    /// What's already held for others plus what still fits (within the store
    /// limit and above the free-space reserve), capped by `--hold-for-others`:
    /// a lease the disk can't take is never accepted.
    fn hold_limit(&self) -> u64 {
        let (Ok(u), Ok(l)) = (self.store.usage(), self.store.limits()) else { return 0 };
        let fits = u.leased + l.room().min(l.hard_max.saturating_sub(u.hard()));
        self.hold_limit.map_or(fits, |cap| cap.min(fits))
    }
}

struct Args {
    store: PathBuf,
    /// The store index's page cache in RAM (`--db-cache`, default 64 MiB).
    db_cache: usize,
    public: bool,
    put: Vec<PathBuf>,
    budget: retifs_store::Budget,
    private_requests: bool,
    hold_limit: Option<u64>,
    /// How often to announce `retifs.node` (seconds; the announces say so).
    announce_s: u32,
    lease_term: u64,
    loss_target: f64,
    min_copies: usize,
    /// No data of its own kept on the device (ADR-0031).
    no_storage: bool,
    /// Compact the index file before starting (gives freed space back).
    compact: bool,
    site: Option<String>,
    slow_budget: u64,
    treat_as_slow: Vec<PeerId>,
    stamp_cost: u8,
    max_stamp_cost: u8,
    nomadnet: Option<String>,
    nomadnet_name: String,
    /// This device's name for keep tags and rules (ADR-0005).
    device: String,
}

/// The machine's name, lower case: the default device name for keep tags.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this-device".into())
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

#[path = "retifsd/settings.rs"]
mod settings;

fn args() -> Args {
    let mut a = Args {
        store: libretifs::default_store_dir(),
        public: false,
        put: Vec::new(),
        budget: Default::default(),
        private_requests: false,
        hold_limit: None,
        announce_s: retifs_core::announce::DEFAULT_ANNOUNCE_S,
        db_cache: retifs_store::DEFAULT_DB_CACHE,
        lease_term: 30 * 86_400,
        loss_target: 1e-3,
        min_copies: 3,
        no_storage: false,
        compact: false,
        site: None,
        slow_budget: 600,
        treat_as_slow: Vec::new(),
        stamp_cost: 20,
        max_stamp_cost: 24,
        nomadnet: None,
        nomadnet_name: "retifs site".into(),
        device: hostname(),
    };
    // The store's settings file first, then the command line: a flag given
    // there overrides the file (the last value of a flag counts).
    let cli: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = cli.iter().position(|a| a == "--store") {
        a.store = cli.get(i + 1).expect("--store DIR").into();
    }
    let (settings_path, from_file) = settings::flags(&a.store).unwrap_or_else(|e| {
        eprintln!("retifsd: settings: {e}");
        std::process::exit(2);
    });
    if !cli.iter().any(|a| a == "-h" || a == "--help") {
        println!("settings: {} ({})", settings_path.display(), if from_file.is_empty() { "all defaults".to_string() } else { format!("{} set", from_file.join(" ")) });
    }
    let mut it = from_file.into_iter().chain(cli);
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
            "--db-cache" => a.db_cache = size(&it.next().expect("--db-cache SIZE")) as usize,
            "--slow-link-budget" => a.slow_budget = duration_secs(&it.next().expect("--slow-link-budget DURATION")),
            "--treat-as-slow" => a.treat_as_slow.push(*parse_destination(&it.next().expect("--treat-as-slow NODE")).expect("node hash").as_bytes()),
            "--stamp-cost" => a.stamp_cost = it.next().and_then(|v| v.parse().ok()).expect("--stamp-cost BITS"),
            "--max-stamp-cost" => a.max_stamp_cost = it.next().and_then(|v| v.parse().ok()).expect("--max-stamp-cost BITS"),
            "--nomadnet" => a.nomadnet = Some(it.next().expect("--nomadnet NAMESPACE")),
            "--nomadnet-name" => a.nomadnet_name = it.next().expect("--nomadnet-name NAME"),
            "--loss-target" => a.loss_target = it.next().and_then(|v| v.parse().ok()).expect("--loss-target P (e.g. 0.001)"),
            "--site" => a.site = Some(it.next().filter(|s| !s.trim().is_empty()).expect("--site NAME")),
            "--compact" => a.compact = true,
            "--no-storage" => a.no_storage = true,
            "--min-copies" => a.min_copies = it.next().and_then(|v| v.parse().ok()).filter(|n| *n >= 1).expect("--min-copies N (1 or more)"),
            "--lease-term" => a.lease_term = duration_secs(&it.next().expect("--lease-term DURATION")).max(60),
            "--device" => a.device = it.next().expect("--device NAME").to_lowercase(),
            "--announce-every" => a.announce_s = (duration_secs(&it.next().expect("--announce-every DURATION")) as u32).max(60),
            "-h" | "--help" => {
                println!(
                    "retifsd [--store DIR] [--max-store SIZE] [--min-free SIZE] [--cache-max SIZE] [--private-requests]
                             [--hold-for-others SIZE] [--db-cache SIZE] [--lease-term DURATION] [--loss-target P] [--min-copies N] [--compact] [--no-storage] [--site NAME] [--slow-link-budget DURATION]\n        \
                     [--stamp-cost BITS] [--max-stamp-cost BITS] [--announce-every DURATION]\n        \
                     [--nomadnet NAMESPACE [--nomadnet-name NAME]] [--device NAME] [--public] [--put FILE]..."
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
    let mut args = args();
    if args.no_storage {
        // Holds nothing for others, and only a cache of what it reads.
        args.hold_limit = Some(0);
        args.budget.cache_max.get_or_insert(128 << 20);
        println!("no storage: nothing of its own kept here beyond a cache of {} MB (ADR-0031)", args.budget.cache_max.unwrap_or(0) >> 20);
    }
    std::fs::create_dir_all(&args.store).expect("create store dir");
    // A storage-less node (ADR-0031): its index and slabs in memory (a RAM
    // folder for the slabs), only the keyring and settings on disk.
    let ram = args.no_storage.then(|| ram_dir(&args.store));
    // Turned storage-less with a store on disk: its keyring first, then the
    // data goes (only the keyring and settings stay on disk).
    if ram.is_some() && !args.store.join("keyring").exists() && args.store.join("index.redb").exists() {
        match SlabStore::open_with_cache(&args.store, args.db_cache) {
            Ok(old) => {
                let leaving: std::collections::BTreeSet<String> = std::fs::read_to_string(args.store.join("leaving")).unwrap_or_default().lines().map(String::from).collect();
                write_keyring(&old, &leaving, &args.store.join("keyring"));
                drop(old);
                let _ = std::fs::remove_file(args.store.join("index.redb"));
                let _ = std::fs::remove_dir_all(args.store.join("slabs"));
                let _ = std::fs::remove_file(args.store.join("leaving"));
                println!("storage-less now: the keyring kept, the data on disk removed");
            }
            Err(e) => eprintln!("the store on disk can't be read for a keyring: {e}"),
        }
    }
    let opened = match &ram {
        Some(dir) => {
            let _ = std::fs::remove_dir_all(dir);
            std::fs::create_dir_all(dir).expect("RAM folder");
            // The key leases are signed with must outlive a restart.
            let _ = std::fs::copy(args.store.join("namespace_key"), dir.join("namespace_key"));
            SlabStore::open_in_memory(dir, args.db_cache)
        }
        None => SlabStore::open_with_cache(&args.store, args.db_cache),
    };
    let store = match opened {
        Ok(mut s) => {
            s.set_budget(args.budget.clone());
            if args.compact {
                let before = std::fs::metadata(args.store.join("index.redb")).map(|m| m.len()).unwrap_or(0);
                match s.compact() {
                    Ok(_) => println!("index compacted: {} MB to {} MB", before >> 20, std::fs::metadata(args.store.join("index.redb")).map(|m| m.len()).unwrap_or(0) >> 20),
                    Err(e) => eprintln!("compacting the index: {e}"),
                }
            }
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
    if ram.is_some() {
        let restored = restore_keyring(&store, &args.store.join("keyring"));
        println!("in memory: the index and data; {restored} librar(ies) restored from the keyring");
        let _ = namespace_key(&store);
        let _ = std::fs::copy(store.root().join("namespace_key"), args.store.join("namespace_key"));
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
    /// This node's RNS identity hash: what it reveals on links to own nodes.
    identity_hash: [u8; 16],
    /// Serialises channel publishing (see `publish_channel`).
    publishing: tokio::sync::Mutex<()>,
    /// The checkpoint each namespace's published blind index describes.
    indexed: Mutex<HashMap<String, Cid>>,
    /// Links this node has identified itself on.
    identified: Mutex<std::collections::HashSet<LinkId>>,
    /// Derives per-lease signing keys (prototype: one namespace per store).
    namespace_key: [u8; 32],
    lease_term: u64,
    /// Wakes lease upkeep (receipts, renewals, proofs, placement) after new leases or needs.
    upkeep_wake: Notify,
    loss_target: f64,
    /// Copies of each needed file, this node's own included, whatever the estimate.
    min_copies: usize,
    /// Keeps no data of its own (ADR-0031): its own copies don't count, and
    /// stay only as cache once enough copies are elsewhere.
    no_storage: bool,
    /// A storage-less node's keyring on disk (its store is in memory): the
    /// libraries and their keys, written as they change.
    keyring: Option<std::path::PathBuf>,
    /// This node's site, if its owner named one: then one copy is kept elsewhere.
    site: Option<retifs_core::announce::SiteTag>,
    slow_budget: u64,
    treat_as_slow: Vec<PeerId>,
    /// Files whose rest waits for a faster path, with the estimate over the slow link.
    deferred: Mutex<HashMap<Cid, u64>>,
    /// Stamp cost each holder asked for, so later offers carry a stamp at once.
    stamp_costs: Mutex<HashMap<PeerId, u8>>,
    max_stamp_cost: u8,
    /// Wakes the follower loop (a channel was followed).
    follow_wake: Notify,
    /// Wakes namespace sync (joined, granted).
    ns_wake: Notify,
    /// Per library, its merge state: each behind a lock of its own, so long
    /// work on one (walking 77,000 operations, writing 38,000 records) doesn't
    /// stop the others, nor every tokio worker waiting on one global lock.
    ns_cache: Mutex<HashMap<String, Arc<Mutex<NsCache>>>>,
    /// Joined namespaces still looking for a checkpoint to start from.
    ns_seeking: Mutex<std::collections::HashSet<String>>,
    /// When a storage-less node last tried to fetch its own chain back, per
    /// library: tried again only after a while (an old chain whose commits
    /// were never placed can't come back).
    own_tried: Mutex<HashMap<String, Instant>>,
    /// Peers announced since the seeker last looked (a set: each at most once).
    announced: Mutex<std::collections::HashSet<PeerId>>,
    announced_wake: Notify,
    /// This device's name for keep tags and rules (ADR-0005).
    device: String,
    /// Per namespace, how often its records changed here (for `watch`).
    changes: Mutex<HashMap<String, u64>>,
    changed: Notify,
    /// Open write sessions (the local API's WriteBegin … WriteCommit).
    sessions: Mutex<HashMap<u64, WriteSession>>,
    /// Commits of write sessions, by session, for an hour: a commit asked
    /// again (its answer timed out over a Link while a large file was being
    /// stored) gets the same result instead of "no such write session".
    commits: Mutex<HashMap<u64, PendingCommit>>,
    next_session: std::sync::atomic::AtomicU64,
    /// Public libraries heard announced (ADR-0029), by address (or, for an
    /// announce too new to read, by the announcing destination and version).
    heard_libs: Mutex<HashMap<Vec<u8>, HeardLib>>,
    /// Woken when the libraries this node announces change.
    lib_wake: Notify,
    /// Libraries being left (`leaving` in the store): hidden, their data
    /// removed in the background by `leaver`.
    leaving: Mutex<std::collections::BTreeSet<String>>,
    leave_wake: Notify,
}

/// A storage-less node's RAM folder for its slabs: in /dev/shm where there is
/// one (Linux), else the temp folder; one per store.
fn ram_dir(store: &std::path::Path) -> std::path::PathBuf {
    let tag = hex(&<sha2::Sha256 as sha2::Digest>::digest(store.to_string_lossy().as_bytes())[..6]);
    let base = std::path::Path::new("/dev/shm");
    let base = if base.is_dir() { base.to_path_buf() } else { std::env::temp_dir() };
    base.join(format!("retifs-ram-{tag}"))
}

/// Writes a storage-less node's keyring (ADR-0031): per library its creator,
/// read keys, writer identity, peers and keep mode; per own channel its keys
/// and how far it has published. Everything else is fetched again.
fn save_keyring(d: &Daemon) {
    let Some(path) = &d.keyring else { return };
    let leaving = d.leaving.lock().unwrap().clone();
    write_keyring(&d.store, &leaving, path);
}

fn write_keyring(store: &SlabStore, leaving: &std::collections::BTreeSet<String>, path: &std::path::Path) {
    let d = Keyring { store };
    let mut libs = toml::Table::new();
    for ns in d.store.ns_names().unwrap_or_default() {
        if leaving.contains(&ns) {
            continue;
        }
        let Ok(Some((creator, _))) = d.store.ns_info(&ns) else { continue };
        let mut e = toml::Table::new();
        e.insert("creator".into(), hex(&creator).into());
        let keys: Vec<toml::Value> = d.store.ns_keys(&ns).unwrap_or_default().iter().map(|k| hex(k).into()).collect();
        e.insert("keys".into(), keys.into());
        if let Ok(Some(id)) = d.store.ns_identity(&ns) {
            e.insert("identity".into(), hex(&id).into());
        }
        let peers: Vec<toml::Value> = d.store.ns_peers(&ns).unwrap_or_default().iter().map(|p| hex(p).into()).collect();
        e.insert("peers".into(), peers.into());
        e.insert("keep_by_rules".into(), d.store.ns_keep_by_rules(&ns).unwrap_or(true).into());
        // Made here (this node writes as its creator): held whole again after
        // a restart, its state fetched back from the nodes holding its files.
        let made_here = d.store.own_channel(&ns_channel(&ns)).ok().flatten().is_some_and(|c| channel_key_in(d.store, &c).writer() == creator);
        e.insert("made_here".into(), made_here.into());
        libs.insert(ns, e.into());
    }
    let mut channels = toml::Table::new();
    for c in d.store.own_channels().unwrap_or_default() {
        let mut e = toml::Table::new();
        e.insert("signing_seed".into(), hex(&c.signing_seed).into());
        e.insert("read_key".into(), hex(&c.read_key).into());
        e.insert("seq".into(), (c.seq as i64).into());
        if let Some((cid, seed)) = c.last {
            e.insert("last".into(), hex(cid.as_bytes()).into());
            e.insert("last_seed".into(), hex(&seed.0).into());
        }
        e.insert("head".into(), hex(&c.head).into());
        channels.insert(c.name, e.into());
    }
    let mut all = toml::Table::new();
    all.insert("library".into(), libs.into());
    all.insert("channel".into(), channels.into());
    let tmp = path.with_extension("new");
    if std::fs::write(&tmp, all.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
    // Where its own data is kept: its leases are renewed after a restart.
    if let Ok(bytes) = d.store.export_placement() {
        let (p, tmp) = (path.with_file_name("placement"), path.with_file_name("placement.new"));
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

/// What a keyring is written from.
struct Keyring<'a> {
    store: &'a SlabStore,
}

/// Puts a keyring's libraries, own channels and placement into a fresh
/// (in-memory) store, those joined held lazily; returns how many libraries.
fn restore_keyring(store: &SlabStore, path: &std::path::Path) -> usize {
    let Some(all) = std::fs::read_to_string(path).ok().and_then(|t| t.parse::<toml::Table>().ok()) else { return 0 };
    let unhex = |h: &str| -> Option<Vec<u8>> { (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect() };
    let bytes = |v: Option<&toml::Value>| v.and_then(|x| x.as_str()).and_then(unhex);
    let mut n = 0;
    for (ns, e) in all.get("library").and_then(|l| l.as_table()).cloned().unwrap_or_default() {
        let creator: Option<[u8; 32]> = bytes(e.get("creator")).and_then(|b| b.try_into().ok());
        let keys: Vec<[u8; 32]> = e.get("keys").and_then(|k| k.as_array()).map(|a| a.iter().filter_map(|k| bytes(Some(k)).and_then(|b| b.try_into().ok())).collect()).unwrap_or_default();
        let (Some(creator), Some(first)) = (creator, keys.first()) else { continue };
        let _ = store.set_ns_info(&ns, &creator, first);
        for k in &keys[1..] {
            let _ = store.add_ns_key(&ns, k);
        }
        if let Some(id) = bytes(e.get("identity")).and_then(|b| <[u8; 64]>::try_from(b).ok()) {
            let _ = store.set_ns_identity(&ns, &id);
        }
        let peers: Vec<PeerId> = e.get("peers").and_then(|p| p.as_array()).map(|a| a.iter().filter_map(|p| bytes(Some(p)).and_then(|b| b.try_into().ok())).collect()).unwrap_or_default();
        let _ = store.add_ns_peers(&ns, &peers);
        let made_here = e.get("made_here").and_then(|b| b.as_bool()).unwrap_or(false);
        let _ = store.set_ns_lazy(&ns, !made_here);
        let _ = store.set_ns_keep_by_rules(&ns, e.get("keep_by_rules").and_then(|b| b.as_bool()).unwrap_or(true));
        n += 1;
    }
    if let Ok(bytes) = std::fs::read(path.with_file_name("placement")) {
        let _ = store.import_placement(&bytes);
    }
    for (name, e) in all.get("channel").and_then(|l| l.as_table()).cloned().unwrap_or_default() {
        let (Some(seed), Some(key)) = (bytes(e.get("signing_seed")).and_then(|b| b.try_into().ok()), bytes(e.get("read_key")).and_then(|b| b.try_into().ok())) else { continue };
        let last = match (bytes(e.get("last")), bytes(e.get("last_seed")).and_then(|b| <[u8; 32]>::try_from(b).ok())) {
            (Some(c), Some(s)) => <[u8; 33]>::try_from(c).ok().and_then(Cid::from_bytes).map(|c| (c, retifs_core::chunk::Seed(s))),
            _ => None,
        };
        let _ = store.update_own_channel(&retifs_store::OwnChannel {
            name,
            signing_seed: seed,
            read_key: key,
            seq: e.get("seq").and_then(|v| v.as_integer()).unwrap_or(0) as u64,
            last,
            head: bytes(e.get("head")).unwrap_or_default(),
        });
    }
    n
}

/// Library `ns`'s cache entry (made if missing); lock it for as short as can be.
fn ns_entry(d: &Daemon, ns: &str) -> Arc<Mutex<NsCache>> {
    d.ns_cache.lock().unwrap().entry(ns.to_string()).or_default().clone()
}

/// Library `ns`'s cache entry, if it has one.
fn ns_entry_get(d: &Daemon, ns: &str) -> Option<Arc<Mutex<NsCache>>> {
    d.ns_cache.lock().unwrap().get(ns).cloned()
}

/// Marks library `ns` as being left (or done), in memory and in the store's
/// `leaving` file, so a restart carries on with it.
fn mark_leaving(d: &Daemon, ns: &str, on: bool) -> Result<(), String> {
    let mut leaving = d.leaving.lock().unwrap();
    if on {
        leaving.insert(ns.to_string());
    } else {
        leaving.remove(ns);
    }
    let text: String = leaving.iter().map(|n| format!("{n}\n")).collect();
    std::fs::write(d.store.root().join("leaving"), text).map_err(|e| e.to_string())
}

/// The libraries here, less those being left.
fn visible_namespaces(d: &Daemon) -> Result<Vec<String>, String> {
    let leaving = d.leaving.lock().unwrap().clone();
    Ok(d.store.namespaces().map_err(|e| e.to_string())?.into_iter().filter(|n| !leaving.contains(n)).collect())
}

/// A stalled daemon, found and named: a heartbeat from the async runtime,
/// and every lock tried from a thread of its own. A lock held for over a
/// minute is logged by name; a runtime that hasn't run for five minutes
/// (every worker blocked, as seen on the testbed) aborts the process, which
/// leaves a core where the system keeps them and lets the service manager
/// start it again.
fn watchdog(d: Arc<Daemon>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static BEAT: AtomicU64 = AtomicU64::new(0);
    BEAT.store(now_ms(), Ordering::Relaxed);
    tokio::spawn(async {
        loop {
            BEAT.store(now_ms(), Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    let _ = std::thread::Builder::new().name("watchdog".into()).spawn(move || {
        let mut held: HashMap<String, u64> = HashMap::new();
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let now = now_ms();
            let free = |name: &str, ok: bool, held: &mut HashMap<String, u64>| {
                if ok {
                    held.remove(name);
                } else {
                    let since = *held.entry(name.to_string()).or_insert(now);
                    let secs = (now - since) / 1000;
                    if secs >= 60 {
                        eprintln!("watchdog: lock {name} held for {secs} s");
                    }
                }
            };
            free("links", d.links.try_lock().is_ok(), &mut held);
            free("indexed", d.indexed.try_lock().is_ok(), &mut held);
            free("identified", d.identified.try_lock().is_ok(), &mut held);
            free("deferred", d.deferred.try_lock().is_ok(), &mut held);
            free("stamp_costs", d.stamp_costs.try_lock().is_ok(), &mut held);
            free("ns_cache", d.ns_cache.try_lock().is_ok(), &mut held);
            free("ns_seeking", d.ns_seeking.try_lock().is_ok(), &mut held);
            free("own_tried", d.own_tried.try_lock().is_ok(), &mut held);
            free("announced", d.announced.try_lock().is_ok(), &mut held);
            free("changes", d.changes.try_lock().is_ok(), &mut held);
            free("sessions", d.sessions.try_lock().is_ok(), &mut held);
            free("commits", d.commits.try_lock().is_ok(), &mut held);
            free("heard_libs", d.heard_libs.try_lock().is_ok(), &mut held);
            free("leaving", d.leaving.try_lock().is_ok(), &mut held);
            // Each library's merge state (the global map's lock just taken and given back).
            let entries: Vec<(String, Arc<Mutex<NsCache>>)> = match d.ns_cache.try_lock() {
                Ok(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                Err(_) => Vec::new(),
            };
            for (ns, e) in entries {
                free(&format!("ns_cache[{ns}]"), e.try_lock().is_ok(), &mut held);
            }
            let quiet = (now - BEAT.load(Ordering::Relaxed)) / 1000;
            if quiet >= 60 {
                eprintln!("watchdog: the async runtime hasn't run for {quiet} s (every worker blocked); locks held: {:?}", held.keys().collect::<Vec<_>>());
            }
            if quiet >= 300 {
                eprintln!("watchdog: stalled for {quiet} s: aborting, to be started again");
                std::process::abort();
            }
        }
    });
}

/// Removes the data of libraries being left, one at a time.
async fn leaver(d: Arc<Daemon>) {
    loop {
        let next = d.leaving.lock().unwrap().iter().next().cloned();
        let Some(ns) = next else {
            d.leave_wake.notified().await;
            continue;
        };
        let d2 = d.clone();
        let ns2 = ns.clone();
        let done = tokio::task::spawn_blocking(move || leave_now(&d2, &ns2)).await;
        match done {
            Ok(Ok(n)) => println!("left {ns}: {n} file(s) no longer needed here"),
            Ok(Err(e)) => eprintln!("leaving {ns}: {e}"),
            Err(e) => eprintln!("leaving {ns}: {e}"),
        }
        let _ = mark_leaving(&d, &ns, false);
        save_keyring(&d);
    }
}

/// Leaving's work: the files only this library used are forgotten, then its
/// records, index, keys and settings go.
fn leave_now(d: &Daemon, ns: &str) -> Result<usize, String> {
    let mut files: Vec<FileRef> = d.store.records(ns).map_err(|e| e.to_string())?.into_iter().flat_map(|r| r.blocks).collect();
    files.extend(d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?);
    files.extend(d.store.ns_kept(ns).map_err(|e| e.to_string())?);
    let others: std::collections::HashSet<Cid> = d
        .store
        .namespaces()
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|n| n.as_str() != ns)
        .flat_map(|n| d.store.records(n).unwrap_or_default())
        .flat_map(|r| r.blocks.into_iter().map(|b| b.root))
        .collect();
    let mut seen = std::collections::HashSet::new();
    files.retain(|f| !others.contains(&f.root) && seen.insert(f.root));
    forget_all(d, &files)?;
    // Joined again meanwhile: the leave is off, the library stays.
    if !d.leaving.lock().unwrap().contains(ns) {
        return Ok(0);
    }
    d.store.leave_namespace(ns).map_err(|e| e.to_string())?;
    d.ns_cache.lock().unwrap().remove(ns);
    d.ns_seeking.lock().unwrap().remove(ns);
    d.changes.lock().unwrap().remove(ns);
    Ok(files.len())
}

/// A library announce heard.
struct HeardLib {
    lib: Option<retifs_core::announce::LibraryAnnounce>,
    v: u32,
    node: PeerId,
    hops: u8,
    heard_ms: u64,
}

/// The most library announces kept: the oldest heard go first.
const HEARD_LIBS_MAX: usize = 500;

/// The libraries this node announces (`announce.toml` in the store): local
/// name → the name and description others see.
fn announced_libraries(store: &SlabStore) -> Vec<(String, String, String)> {
    let Ok(text) = std::fs::read_to_string(store.root().join("announce.toml")) else { return Vec::new() };
    let Ok(table) = text.parse::<toml::Table>() else { return Vec::new() };
    table
        .iter()
        .map(|(ns, v)| {
            let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let name = get("name");
            (ns.clone(), if name.is_empty() { ns.clone() } else { name }, get("about"))
        })
        .collect()
}

fn set_announced(store: &SlabStore, ns: &str, entry: Option<(String, String)>) -> Result<(), String> {
    let path = store.root().join("announce.toml");
    let mut table = std::fs::read_to_string(&path).ok().and_then(|t| t.parse::<toml::Table>().ok()).unwrap_or_default();
    match entry {
        Some((name, about)) => {
            let mut e = toml::Table::new();
            e.insert("name".into(), toml::Value::String(name));
            e.insert("about".into(), toml::Value::String(about));
            table.insert(ns.into(), toml::Value::Table(e));
        }
        None => {
            table.remove(ns);
        }
    }
    std::fs::write(&path, table.to_string()).map_err(|e| e.to_string())
}

/// What a library's announce says about it now: what it holds by type, its
/// area (a map's bounds, else where its places are), its version.
fn library_announce_now(d: &Daemon, ns: &str, name: &str, about: &str) -> Result<retifs_core::announce::LibraryAnnounce, String> {
    let addr = current_addr(d, ns)?;
    let mut types: HashMap<String, u64> = HashMap::new();
    let (mut bounds, mut extent): (Option<[f64; 4]>, Option<[f64; 4]>) = (None, None);
    for r in d.store.records(ns).map_err(|e| e.to_string())? {
        if let Some(Value::Str(t)) = r.attrs.get("type") {
            *types.entry(t.clone()).or_default() += 1;
        }
        if let Some(Value::List(b)) = r.attrs.get("bounds") {
            let f: Vec<f64> = b.iter().filter_map(|x| if let Value::Float(f) = x { Some(*f) } else { None }).collect();
            if f.len() == 4 {
                bounds = Some([f[0], f[1], f[2], f[3]]);
            }
        }
        if let Some(Value::List(g)) = r.attrs.get("geo") {
            if let [Value::Float(lat), Value::Float(lon)] = g.as_slice() {
                let e = extent.get_or_insert([*lon, *lat, *lon, *lat]);
                *e = [e[0].min(*lon), e[1].min(*lat), e[2].max(*lon), e[3].max(*lat)];
            }
        }
    }
    let mut has: Vec<(String, u64)> = types.into_iter().collect();
    has.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let seq = d.changes.lock().unwrap().get(ns).copied().unwrap_or(0);
    Ok(retifs_core::announce::LibraryAnnounce {
        name: name.into(),
        about: about.into(),
        writer: addr.writer,
        read_key: addr.read_key,
        fmt: retifs_core::announce::LIBRARY_FMT,
        has,
        bounds: bounds.or(extent),
        seq,
        node: Some(d.node_id),
    })
}

/// A record's content being written in place: written ranges are spooled to
/// a sparse file; the rest is the record's current content (`base`, up to
/// `base_len` after truncations), then zeros.
struct WriteSession {
    ns: String,
    id: RecordId,
    base: Option<FileRef>,
    base_len: u64,
    spool: std::fs::File,
    path: PathBuf,
    /// Written ranges, start → end, merged.
    extents: std::collections::BTreeMap<u64, u64>,
    size: u64,
    started: Instant,
}

/// Where a part of a session's content comes from.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Piece {
    Spool,
    Base,
    Zero,
}

impl WriteSession {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.spool.seek(SeekFrom::Start(offset))?;
        self.spool.write_all(data)?;
        let (mut a, mut b) = (offset, offset + data.len() as u64);
        let touching: Vec<(u64, u64)> = self.extents.range(..=b).filter(|(_, e)| **e >= a).map(|(s, e)| (*s, *e)).collect();
        for (s, e) in touching {
            a = a.min(s);
            b = b.max(e);
            self.extents.remove(&s);
        }
        self.extents.insert(a, b);
        self.size = self.size.max(offset + data.len() as u64);
        Ok(())
    }

    fn truncate(&mut self, size: u64) {
        self.extents = self.extents.iter().filter(|(s, _)| **s < size).map(|(s, e)| (*s, (*e).min(size))).collect();
        self.base_len = self.base_len.min(size);
        self.size = size;
    }

    /// `range` split by where its bytes come from.
    fn pieces(&self, range: std::ops::Range<u64>) -> Vec<(std::ops::Range<u64>, Piece)> {
        let end = range.end.min(self.size);
        let mut out = Vec::new();
        let mut pos = range.start.min(end);
        while pos < end {
            if let Some((_, e)) = self.extents.range(..=pos).next_back().filter(|(_, e)| **e > pos) {
                let to = (*e).min(end);
                out.push((pos..to, Piece::Spool));
                pos = to;
                continue;
            }
            let gap_end = self.extents.range(pos..).next().map_or(end, |(s, _)| (*s).min(end));
            if pos < self.base_len {
                let to = gap_end.min(self.base_len);
                out.push((pos..to, Piece::Base));
                pos = to;
            } else {
                out.push((pos..gap_end, Piece::Zero));
                pos = gap_end;
            }
        }
        out
    }
}

/// A session's content as one stream (for committing): spooled ranges, the
/// base's (already local), zeros.
struct SessionReader {
    pieces: std::collections::VecDeque<(std::ops::Range<u64>, Piece)>,
    spool: std::fs::File,
    base: Option<FileRef>,
    store: Arc<SlabStore>,
}

impl std::io::Read for SessionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Seek, SeekFrom};
        let Some((range, piece)) = self.pieces.front().cloned() else { return Ok(0) };
        let n = (range.end - range.start).min(buf.len() as u64).min(1 << 20) as usize;
        match piece {
            Piece::Spool => {
                self.spool.seek(SeekFrom::Start(range.start))?;
                self.spool.read_exact(&mut buf[..n])?;
            }
            Piece::Zero => buf[..n].fill(0),
            Piece::Base => {
                let base = self.base.as_ref().ok_or_else(|| std::io::Error::other("no base content"))?;
                let data = manifest::read_range(&*self.store, base, range.start..range.start + n as u64).map_err(std::io::Error::other)?;
                buf[..n].copy_from_slice(&data);
            }
        }
        if range.start + n as u64 >= range.end {
            self.pieces.pop_front();
        } else {
            self.pieces.front_mut().unwrap().0.start += n as u64;
        }
        Ok(n)
    }
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
        // The shared instance may know a path this client's own route table
        // doesn't, and a client's path request for it may never settle (seen
        // over LoRa: Python's rnpath got the path in under a second, Prns
        // never did). So a failed path check doesn't stop the attempt: the
        // link request goes to the shared instance, which routes it.
        let path = t.ensure_path(dest).await;
        let attempt = |t: &PrnsTransport| {
            let t = t.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(90), t.link_with_rtt(dest))
                    .await
                    .unwrap_or_else(|_| Err("link: timed out".into()))
            }
        };
        let (link, rtt) = match attempt(&t).await {
            Ok(l) => l,
            // The known route may be stale: ask for a fresh path and try once more.
            Err(e) if path.is_ok() => {
                t.request_path(dest).await.map_err(|p| format!("{e}; {p}"))?;
                attempt(&t).await?
            }
            Err(e) => return Err(format!("{}; {e}", path.unwrap_err())),
        };
        let _ = self.store.record_rtt(peer, rtt);
        self.links.lock().unwrap().insert(*peer, link);
        Ok(link)
    }

    /// What this node knows of the path to `peer` (measured; see LinkQuality).
    fn quality(&self, peer: &PeerId) -> retifs_store::LinkQuality {
        let mut q = self.store.link_quality(peer).unwrap_or_default();
        if self.treat_as_slow.contains(peer) {
            q.rtt_ms = q.rtt_ms.max(retifs_store::SLOW_RTT_MS * 2);
            q.rate_bps = retifs_store::SLOW_DEFAULT_RATE as u32;
        }
        q
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
    let lib_dest = node::library_destination(identity.clone());
    let lib_hash = lib_dest.destination_hash().expect("valid destination");
    let dest = node::destination_announcing(identity, true, args.announce_s, args.site.as_deref().map(retifs_core::announce::site_tag), args.hold_limit != Some(0));
    if let Some(site) = &args.site {
        println!("site: {site} (one copy of this node's files is kept at another site)");
    }
    let dest_hash = dest.destination_hash().expect("valid destination");
    // Receipts are signed with the node identity and checked against the node's
    // address, so the identity layout must be RNS's (X25519 ‖ Ed25519).
    if node_destination(&lease::identity_public(&identity_bytes)) != *dest_hash.as_bytes() {
        eprintln!("warning: node identity layout differs from RNS; receipts from this node won't verify");
    }
    let (api_tx, api_rx) = mpsc::unbounded_channel::<ApiCall>();
    let (invite_tx, invite_rx) = mpsc::unbounded_channel::<InviteCall>();
    let shared = Arc::new(Shared {
        store: store.clone(),
        identity: identity_bytes,
        hold_limit: args.hold_limit,
        pull_wake: Notify::new(),
        stamp_cost: args.stamp_cost,
        api: api_tx,
        invites: invite_tx,
    });
    // Announces from the whole network arrive here: bounded, and an announce
    // dropped when it's full is harmless (nodes announce again). An unbounded
    // queue grew without limit on a busy transport node while passes waited
    // on the network (found by the overnight soak test).
    let (heard_tx, mut heard_rx) = mpsc::channel::<(PeerId, u8, retifs_core::announce::NodeAnnounce)>(4096);
    let (lib_tx, mut lib_rx) = mpsc::channel::<(PeerId, u8, u32, Option<retifs_core::announce::LibraryAnnounce>)>(1024);
    // Optionally a NomadNet node (its own identity and destination) serving a namespace.
    let nomadnet = args.nomadnet.as_ref().map(|_| {
        let id = load_or_create_identity(&store.root().join("nomadnet_identity")).expect("nomadnet identity");
        let name: &'static [u8] = Box::leak(args.nomadnet_name.clone().into_bytes().into_boxed_slice());
        nomadnet::destination(id, name)
    });
    let nn_hash = nomadnet.as_ref().map(|d| d.destination_hash().expect("valid destination"));
    let (nn_tx, nn_rx) = mpsc::unbounded_channel::<(RequestPathHash, RespondToken)>();
    let mut destinations = vec![dest, lib_dest];
    destinations.extend(nomadnet);
    let node = PrnsNode::new(PrnsNodeRecipe {
        transport_identity: None,
        pre_configured_destinations: destinations,
        app_state: shared.clone(),
        storage: GrowableHeap,
        request_endpoints: request_endpoints![Get, Have, LeaseEndpoint, ReceiptEndpoint, ProveEndpoint, PutEndpoint, HeadEndpoint, ApiEndpoint, QueryEndpoint, InviteEndpoint],
        on_event: move |event, _state| {
            match event {
                PrnsEvent::Diagnostic(Diagnostic::AnnounceHeard { destination, hops, app_data, .. }) => {
                    match retifs_core::announce::library_announce(app_data) {
                        Some((v, lib)) => {
                            let _ = lib_tx.try_send((*destination.as_bytes(), hops, v, lib));
                        }
                        None => {
                            let _ = heard_tx.try_send((*destination.as_bytes(), hops, retifs_core::announce::node_announce(app_data)));
                        }
                    }
                }
                // Page requests to the NomadNet destination (dynamically registered paths).
                PrnsEvent::Message(Message::Request { destination, link_id, request_id, path_hash, rtt, .. })
                    if Some(destination) == nn_hash =>
                {
                    let _ = nn_tx.send((path_hash, RespondToken { link_id, request_id, rtt }));
                }
                _ => {}
            }
        },
        interfaces: ManuallyAttached,
        persistence: NoPersistence,
        remote_control: personal_rns::remote_control::RemoteControlService::Unavailable.into(),
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
        identity_hash: <sha2::Sha256 as sha2::Digest>::digest(lease::identity_public(&identity_bytes))[..16].try_into().unwrap(),
        identified: Mutex::new(std::collections::HashSet::new()),
        indexed: Mutex::new(HashMap::new()),
        publishing: tokio::sync::Mutex::new(()),
        namespace_key: namespace_key(&store),
        lease_term: args.lease_term,
        upkeep_wake: Notify::new(),
        loss_target: args.loss_target,
        min_copies: args.min_copies,
        no_storage: args.no_storage,
        keyring: args.no_storage.then(|| args.store.join("keyring")),
        site: args.site.as_deref().map(retifs_core::announce::site_tag),
        slow_budget: args.slow_budget,
        treat_as_slow: args.treat_as_slow.clone(),
        deferred: Mutex::new(HashMap::new()),
        stamp_costs: Mutex::new(HashMap::new()),
        max_stamp_cost: args.max_stamp_cost,
        follow_wake: Notify::new(),
        ns_wake: Notify::new(),
        ns_cache: Mutex::new(HashMap::new()),
        own_tried: Mutex::new(HashMap::new()),
        ns_seeking: Mutex::new(if args.no_storage { store.ns_names().unwrap_or_default().into_iter().collect() } else { std::collections::HashSet::new() }),
        announced: Mutex::new(std::collections::HashSet::new()),
        announced_wake: Notify::new(),
        device: args.device.clone(),
        changes: Mutex::new(HashMap::new()),
        changed: Notify::new(),
        sessions: Mutex::new(HashMap::new()),
        commits: Mutex::new(HashMap::new()),
        next_session: std::sync::atomic::AtomicU64::new(1),
        heard_libs: Mutex::new(HashMap::new()),
        lib_wake: Notify::new(),
        // Left before a restart and not finished: carried on.
        leaving: Mutex::new(
            std::fs::read_to_string(store.root().join("leaving")).unwrap_or_default().lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect(),
        ),
        leave_wake: Notify::new(),
    });
    println!("attached to shared instance {of}");
    println!("serving {} chunks as retifs.node <{}>", store.len().unwrap_or(0), daemon.node_hex);
    println!("local API at {endpoint}");
    println!("device name for keep tags and rules: {}", args.device);

    match args.hold_limit {
        Some(0) => println!("not holding data for others"),
        Some(n) => println!("holding up to {n} bytes for others"),
        None => println!("holding data for others up to the store limit"),
    }

    // Public libraries heard announced (ADR-0029): the latest of each, the
    // oldest dropped beyond HEARD_LIBS_MAX.
    let listener = daemon.clone();
    tokio::spawn(async move {
        while let Some((from, hops, v, lib)) = lib_rx.recv().await {
            if from == *lib_hash.as_bytes() {
                continue;
            }
            // The announcing node's retifs.node address (its identity's other
            // destination): where joining asks first.
            // The announce says (`node`); else from the announcing identity.
            let Some(dest) = parse_destination(&hex(&from)) else { continue };
            let node = match lib.as_ref().and_then(|l| l.node) {
                Some(n) => n,
                None => match listener.transport.handle.destination_identity(DestinationIdentityQuery::Destination(dest)).await {
                    Some(id) => node_destination(id.public.as_bytes()),
                    None => from,
                },
            };
            let key = match &lib {
                Some(l) => [l.writer, l.read_key].concat(),
                None => [node.as_slice(), &v.to_be_bytes()].concat(),
            };
            let mut heard = listener.heard_libs.lock().unwrap();
            let new = !heard.contains_key(&key);
            if let (true, Some(l)) = (new, &lib) {
                println!("library heard: \"{}\" from <{}>, {hops} hop(s) away", l.name, hex(&node));
            }
            heard.insert(key, HeardLib { lib, v, node, hops, heard_ms: now_ms() });
            if heard.len() > HEARD_LIBS_MAX {
                if let Some(oldest) = heard.iter().min_by_key(|(_, h)| h.heard_ms).map(|(k, _)| k.clone()) {
                    heard.remove(&oldest);
                }
            }
        }
    });
    // This node's announced libraries, one announce each, every announce
    // interval and when the list changes.
    let lib_announcer = daemon.clone();
    let lib_handle = handle.clone();
    let lib_every = Duration::from_secs(args.announce_s.max(60) as u64);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            for (ns, name, about) in announced_libraries(&lib_announcer.store) {
                let d = lib_announcer.clone();
                let made = tokio::task::spawn_blocking(move || library_announce_now(&d, &ns, &name, &about).map(|l| (ns, l))).await;
                let (ns, lib) = match made {
                    Ok(Ok(x)) => x,
                    Ok(Err(e)) => {
                        eprintln!("announce: {e}");
                        continue;
                    }
                    Err(_) => continue,
                };
                let data = retifs_core::announce::library_app_data(&lib);
                let Ok(bytes) = personal_rns::routing::announce::emit::AnnounceAppDataBytes::from_slice(&data) else {
                    eprintln!("announce {ns}: {} bytes don't fit an announce", data.len());
                    continue;
                };
                if lib_handle
                    .issue(PrnsCommand::AnnounceNow(AnnounceNow { destination: lib_hash, target: AnnounceTarget::AllInterfaces, app_data: AnnounceAppData::Data(bytes) }))
                    .is_none()
                {
                    return;
                }
                println!("announced library {ns} as \"{}\" ({} bytes)", lib.name, data.len());
                // Spaced, so transport nodes' announce limits don't drop them.
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            tokio::select! {
                _ = tokio::time::sleep(lib_every) => {}
                _ = lib_announcer.lib_wake.notified() => {}
            }
        }
    });
    let daemon_for_nn = daemon.clone();
    tokio::spawn(local_api(endpoint, daemon.clone(), false));
    tokio::spawn(local_api(libretifs::app_endpoint(&args.store), daemon.clone(), true));
    tokio::spawn(api_server(daemon.clone(), handle.clone(), api_rx));
    tokio::spawn(invite_server(daemon.clone(), handle.clone(), invite_rx));
    tokio::spawn(lease_puller(daemon.clone(), shared.clone()));
    tokio::spawn(lease_upkeep(daemon.clone()));
    tokio::spawn(follower(daemon.clone()));
    tokio::spawn(ns_sync(daemon.clone()));
    tokio::spawn(share_keeper(daemon.clone()));
    tokio::spawn(leaver(daemon.clone()));
    watchdog(daemon.clone());
    if daemon.keyring.is_some() {
        let keeper = daemon.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                save_keyring(&keeper);
            }
        });
    }
    let redeemer = daemon.clone();
    tokio::spawn(async move {
        // Invitations whose creator's node wasn't reachable (ADR-0020).
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            redeem_pending(&redeemer).await;
        }
    });
    let watcher = daemon.clone();
    tokio::spawn(async move {
        // Every retifs node is a storage node (ADR-0014), recognised by its
        // identity (older nodes' app data says only `retifs/v0`); the app
        // data, when it says, gives how often it announces.
        let mut not_retifs = std::collections::HashSet::new();
        while let Some((peer, hops, said)) = heard_rx.recv().await {
            let every = said.announce_s;
            if watcher.announced.lock().unwrap().insert(peer) {
                watcher.announced_wake.notify_one();
            }
            if peer == watcher.node_id || not_retifs.contains(&peer) {
                continue;
            }
            if not_retifs.len() > 100_000 {
                not_retifs.clear(); // a very large network: forget and re-learn
            }
            let dest = parse_destination(&hex(&peer)).expect("destination hash");
            match watcher.transport.handle.destination_identity(DestinationIdentityQuery::Destination(dest)).await {
                // It holds nothing for others: not a candidate, and one it was is set aside.
                Some(id) if node_destination(id.public.as_bytes()) == peer && said.holds_nothing => {
                    if watcher.store.storage_nodes().map(|n| n.iter().any(|n| n.peer == peer && n.avoid_until_ms < now_ms())).unwrap_or(false) {
                        let _ = watcher.store.avoid_storage_node(&peer, now_ms() + FORGET_SILENT_MS);
                    }
                }
                Some(id) if node_destination(id.public.as_bytes()) == peer => {
                    let known = watcher.store.storage_nodes().map(|n| n.iter().any(|n| n.peer == peer)).unwrap_or(true);
                    if watcher.store.heard_storage_node(&peer, hops, every, said.site, now_ms()).is_ok() && !known {
                        let every = every.map_or("an older node: interval unsaid".to_string(), |s| format!("announces every {s} s"));
                        println!("storage node <{}> heard, {hops} hop(s) away ({every})", hex(&peer));
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
    tokio::spawn(seeker(daemon));

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

    if let (Some(ns), Some(nn)) = (args.nomadnet.clone(), nn_hash) {
        println!("NomadNet node \"{}\" <{}> serving namespace {ns}", args.nomadnet_name, destination_hex(&nn));
        tokio::spawn(nomadnet::serve(daemon_for_nn.clone(), handle.clone(), nn, ns, args.nomadnet_name.clone(), nn_rx));
    }

    let announcer = handle.clone();
    let announce_every = args.announce_s;
    tokio::spawn(async move {
        // Once at start (the first tick is immediate), then every ten minutes:
        // announces travel the whole network, LoRa links included.
        let mut tick = tokio::time::interval(Duration::from_secs(announce_every as u64));
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
async fn local_api(endpoint: String, daemon: Arc<Daemon>, apps: bool) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(&endpoint); // stale socket from a previous run
    let listener = tokio::net::UnixListener::bind(&endpoint).unwrap_or_else(|e| panic!("bind {endpoint}: {e}"));
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600)).expect("socket permissions");
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // On the app socket: which program connected (its token is pinned to it).
                let exe = apps.then(|| {
                    stream
                        .peer_cred()
                        .ok()
                        .and_then(|c| c.pid())
                        .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).ok())
                        .map(|p| p.to_string_lossy().into_owned())
                });
                // Read with recvmsg, so descriptors sent with PutFd arrive.
                let stream = libretifs::fdpass::FdStream::new(stream);
                let fds = Some(stream.fds.clone());
                tokio::spawn(connection(stream, daemon.clone(), exe, fds));
            }
            Err(e) => eprintln!("local API accept: {e}"),
        }
    }
}

#[cfg(windows)]
async fn local_api(endpoint: String, daemon: Arc<Daemon>, apps: bool) {
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
        tokio::spawn(connection(connected, daemon.clone(), apps.then_some(None), None));
    }
}

/// What an application may do on the app socket (ADR-0004).
struct AppScope {
    name: String,
    namespaces: Vec<String>,
    write: bool,
    /// The app's limits on attribute keys (an app with `keys` set).
    app: retifs_store::App,
}

/// A local API connection. `app`: `None` for the owner's socket (everything
/// allowed); `Some(exe)` for the app socket, where the first message must be
/// `Hello` with a token, and every request is checked against its scope.
/// Descriptors received on a connection (Unix sockets; none on Windows pipes).
type FdQueue = std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<std::fs::File>>>;

async fn connection(mut stream: impl AsyncRead + AsyncWrite + Unpin, daemon: Arc<Daemon>, app: Option<Option<String>>, fds: Option<FdQueue>) {
    let mut scope: Option<AppScope> = None;
    loop {
        let req: Envelope<Request> = match read_frame(&mut stream).await {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                eprintln!("local API read: {e}");
                return;
            }
        };
        let msg = match (&app, &scope) {
            (None, _) => match req.msg {
                Request::PutFd { public, compress, publish, record } => {
                    let file = fds.as_ref().and_then(|q| q.lock().unwrap().pop_front());
                    match file {
                        Some(f) => put_file(&daemon, f, public, compress, publish, record).await,
                        None => Err("PutFd came without a descriptor".into()),
                    }
                    .unwrap_or_else(|message| Response::Error { message })
                }
                other => handle(&daemon, other).await.unwrap_or_else(|message| Response::Error { message }),
            },
            (Some(exe), None) => match hello(&daemon, req.msg, exe.as_deref()) {
                Ok(s) => {
                    scope = Some(s);
                    Response::Done
                }
                Err(message) => {
                    let _ = write_frame(&mut stream, &Envelope { v: PROTOCOL_VERSION, id: req.id, msg: Response::Error { message } }).await;
                    return; // no second try on one connection
                }
            },
            (Some(_), Some(s)) => match authorize(&daemon, s, &req.msg) {
                Ok(()) => {
                    let names_only = matches!(req.msg, Request::Namespaces);
                    match handle(&daemon, req.msg).await {
                        // An app sees only its own namespaces.
                        Ok(Response::Names { names }) if names_only => {
                            Response::Names { names: names.into_iter().filter(|n| s.namespaces.contains(n)).collect() }
                        }
                        Ok(r) => r,
                        Err(message) => Response::Error { message },
                    }
                }
                Err(message) => Response::Error { message },
            },
        };
        if let Err(e) = write_frame(&mut stream, &Envelope { v: PROTOCOL_VERSION, id: req.id, msg }).await {
            eprintln!("local API write: {e}");
            return;
        }
    }
}

/// A write session's commit, shared by its repeats: when, which namespace
/// (for an app's scope), and its result once done.
struct PendingCommit {
    at: Instant,
    ns: Option<String>,
    result: Arc<tokio::sync::OnceCell<Result<Vec<RecordView>, String>>>,
}

/// Checks an app's token (the first message on the app socket). On Linux a
/// token is pinned to the executable that first uses it; another program
/// presenting it later is refused.
fn hello(d: &Daemon, req: Request, exe: Option<&str>) -> Result<AppScope, String> {
    let Request::Hello { token } = req else { return Err("the app socket needs Hello with a token first".into()) };
    let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()).into();
    let mut app = d
        .store
        .apps()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|a| a.token_hash == hash)
        .ok_or("unknown app token")?;
    match (&app.exe, exe) {
        (Some(pinned), Some(now)) if pinned != now => {
            return Err(format!("this token belongs to {pinned}, not {now}"));
        }
        (None, Some(now)) => {
            app.exe = Some(now.to_string());
            d.store.put_app(&app).map_err(|e| e.to_string())?;
        }
        _ => {}
    }
    Ok(AppScope { name: app.name.clone(), namespaces: app.namespaces.clone(), write: app.write, app })
}

/// Whether an app may make this request: reads in its namespaces, writes
/// there if it may write, nothing else (no grants, keys, files or placement).
fn authorize(d: &Daemon, s: &AppScope, req: &Request) -> Result<(), String> {
    let deny = |what: &str| Err(format!("app {} may not {what}", s.name));
    let ns_ok = |ns: &str| s.namespaces.iter().any(|n| n == ns);
    let read = |ns: &str| if ns_ok(ns) { Ok(()) } else { deny(&format!("use namespace {ns}")) };
    let write = |ns: &str| {
        if !s.write {
            deny("write")
        } else {
            read(ns)
        }
    };
    // A session being committed (a repeat of its commit) is in `commits`.
    let session_ns = |session: u64| {
        d.sessions.lock().unwrap().get(&session).map(|x| x.ns.clone()).or_else(|| d.commits.lock().unwrap().get(&session).and_then(|c| c.ns.clone()))
    };
    // Its key limit (ADR-0023): every key it sets or unsets, content, deleting
    // and new records each named.
    let keys_ok = |attrs: &[(String, AttrValue)], unset: &[String], content: bool| {
        let bad = attrs
            .iter()
            .map(|(k, _)| k.as_str())
            .chain(unset.iter().map(String::as_str))
            .chain(content.then_some(ops::CONTENT_KEY))
            .find(|k| !s.app.may_write_key(k));
        match bad {
            Some(k) => deny(&format!("write {k}")),
            None => Ok(()),
        }
    };
    let create_ok = || if s.app.may_write_key("@create") { Ok(()) } else { deny("create records") };
    let delete_ok = || if s.app.may_write_key(ops::DELETE_KEY) { Ok(()) } else { deny("delete records") };
    match req {
        Request::RecordCreate { ns, attrs, data } => write(ns).and_then(|_| create_ok()).and_then(|_| keys_ok(attrs, &[], data.is_some())),
        Request::RecordSet { ns, attrs, unset, data, .. } => write(ns).and_then(|_| keys_ok(attrs, unset, data.is_some())),
        Request::RecordDelete { ns, .. } => write(ns).and_then(|_| delete_ok()),
        // Storing content not yet in a record (a thumbnail, ADR-0026): an app
        // that may write content.
        Request::Put { .. } if s.write && s.app.may_write_key(ops::CONTENT_KEY) => Ok(()),
        Request::WriteBegin { ns, .. } => write(ns).and_then(|_| keys_ok(&[], &[], true)),
        Request::Transaction { ns, steps } => {
            write(ns)?;
            for step in steps {
                match step {
                    TxStep::Create { attrs, data } => create_ok().and_then(|_| keys_ok(attrs, &[], data.is_some()))?,
                    TxStep::Set { attrs, unset, data, blocks, .. } => keys_ok(attrs, unset, data.is_some() || blocks.is_some())?,
                    TxStep::Delete { .. } => delete_ok()?,
                }
            }
            Ok(())
        }
        Request::Ping | Request::Namespaces | Request::HeardLibraries => Ok(()),
        Request::RecordGet { ns, .. } | Request::Query { ns, .. } | Request::SearchQuery { ns, .. } | Request::RecordHistory { ns, .. } | Request::NsInfo { ns } | Request::Watch { ns, .. } => read(ns),
        Request::ReadRange { ns: Some(ns), .. } => read(ns),
        Request::WriteAt { session, .. }
        | Request::WriteRead { session, .. }
        | Request::WriteTruncate { session, .. }
        | Request::WriteCommit { session, .. }
        | Request::WriteAbort { session } => match session_ns(*session) {
            Some(ns) => write(&ns),
            None => Err("no such write session".into()),
        },
        _ => deny("make this request"),
    }
}

/// The most a range read over a Link returns in one answer.
const REMOTE_MAX_RANGE: u64 = 1 << 20;
/// The longest a watch over a Link waits (below the requester's 60 s timeout).
const REMOTE_MAX_WATCH_MS: u64 = 45_000;

/// Answers local API requests from own devices over Links (ADR-0019).
async fn api_server(d: Arc<Daemon>, handle: PrnsNodeHandle, mut calls: mpsc::UnboundedReceiver<ApiCall>) {
    while let Some(call) = calls.recv().await {
        let d = d.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            let resp = remote_call(&d, call.requester, &call.body).await.unwrap_or_else(|message| Response::Error { message });
            let bytes = rmp_serde::to_vec_named(&resp).unwrap_or_default();
            handle.respond_owned_packed(call.token, bytes);
        });
    }
}

/// Answers invitation redemptions (ADR-0020).
async fn invite_server(d: Arc<Daemon>, handle: PrnsNodeHandle, mut calls: mpsc::UnboundedReceiver<InviteCall>) {
    while let Some(call) = calls.recv().await {
        let d = d.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            let out = match redeem_here(&d, &call.link_id, &call.body).await {
                Ok(msg) => [&[0u8][..], msg.as_bytes()].concat(),
                Err(e) => {
                    eprintln!("invitation: refused: {e}");
                    [&[1u8][..], e.as_bytes()].concat()
                }
            };
            handle.respond_owned_packed(call.token, out);
        });
    }
}

/// Redeems one of this node's invitations: pending, unexpired, the proof
/// good for this Link; then the grant is written and the invitation spent.
async fn redeem_here(d: &Daemon, link_id: &[u8], body: &[u8]) -> Result<String, String> {
    let invite::Redemption { id, writer, node, proof } = invite::parse_redeem(body).ok_or("malformed redemption")?;
    let made = d.store.invite(&id).map_err(|e| e.to_string())?.ok_or("no such invitation here")?;
    let inv = &made.invitation;
    if !invite::verify(&inv.secret, link_id, &writer, &node, &proof) {
        return Err("the proof doesn't match".into());
    }
    if made.spent {
        return Err("this invitation was used already".into());
    }
    if inv.expires < now_ms() {
        return Err("this invitation has expired".into());
    }
    // Spent before the grant, so two redemptions at once can't both win.
    d.store.put_invite(&MadeInvite { spent: true, ..made.clone() }).map_err(|e| e.to_string())?;
    let rights = if inv.grant { vec![Right::Write, Right::Grant] } else { vec![Right::Write] };
    let limits = retifs_core::ops::Limits { keys: (!inv.keys.is_empty()).then(|| inv.keys.iter().cloned().collect()), until: inv.until };
    let op = if limits.is_none() { Op::Grant(writer, rights) } else { Op::GrantLimited(writer, rights, limits) };
    if let Err(e) = write_ops(d, &made.ns, vec![op]).await {
        d.store.put_invite(&made).map_err(|e| e.to_string())?;
        return Err(e);
    }
    d.store.add_ns_peers(&made.ns, &[node]).map_err(|e| e.to_string())?;
    d.ns_wake.notify_one();
    eprintln!("invitation to {}: granted to writer {}… (node <{}>)", made.ns, &hex(&writer)[..12], hex(&node));
    Ok(format!("granted: you may write to {}", made.ns))
}

/// Redeems an invitation this node was given, with its creator's node over
/// a Link. Done: the invitation is forgotten; refused for good (used,
/// expired, unknown): too; unreachable: kept for the next sync.
async fn redeem_there(d: &Daemon, ns: &str, inv: &Invitation) -> Result<String, String> {
    let (_, writer, _) = chains(d, ns, false)?;
    let node: [u8; 16] = parse_peers(std::slice::from_ref(&d.node_hex))?[0];
    let link = d.link_to(&inv.node).await?;
    let body = invite::redeem_request(&inv.secret, link.as_bytes(), &writer, &node);
    let answer = match d.ask(link, INVITE_ENDPOINT, body).await {
        Ok(a) => a,
        Err(e) => {
            d.drop_link(&inv.node);
            return Err(e);
        }
    };
    let message = String::from_utf8_lossy(answer.get(1..).unwrap_or_default()).into_owned();
    d.store.remove_redeem(ns).map_err(|e| e.to_string())?;
    match answer.first() {
        Some(0) => {
            d.ns_wake.notify_one();
            Ok(message)
        }
        _ => Err(format!("the invitation was refused: {message}")),
    }
}

/// Retries the invitations this node still has to redeem (their creators
/// were unreachable), forgetting expired ones.
async fn redeem_pending(d: &Daemon) {
    for (ns, inv) in d.store.redeems().unwrap_or_default() {
        if inv.expires < now_ms() {
            eprintln!("invitation to {ns}: expired before its creator's node could be reached");
            let _ = d.store.remove_redeem(&ns);
            continue;
        }
        match redeem_there(d, &ns, &inv).await {
            Ok(m) => eprintln!("invitation to {ns}: {m}"),
            Err(e) => eprintln!("invitation to {ns}: {e}"),
        }
    }
}

/// One request from another node: it must have identified as one of this
/// user's devices, and the request must fit that device's scope.
async fn remote_call(d: &Daemon, requester: Option<[u8; 16]>, body: &[u8]) -> Result<Response, String> {
    let who = requester.ok_or("identify first: only this user's own nodes may ask")?;
    let node = node_destination_of(&who);
    let app = d
        .store
        .apps()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|a| a.device == Some(node))
        .ok_or_else(|| format!("node <{}> isn't one of this node's devices (retifs app add NAME --ns NS --device ADDRESS)", hex(&node)))?;
    let req: Request = rmp_serde::from_slice(body).map_err(|e| format!("bad request: {e}"))?;
    let scope = AppScope { name: app.name.clone(), namespaces: app.namespaces.clone(), write: app.write, app };
    authorize(d, &scope, &req)?;
    let req = match req {
        Request::ReadRange { len, .. } if len > REMOTE_MAX_RANGE => {
            return Err(format!("over a Link, read at most {REMOTE_MAX_RANGE} bytes at a time"));
        }
        Request::Watch { ns, since, timeout_ms } => Request::Watch { ns, since, timeout_ms: timeout_ms.min(REMOTE_MAX_WATCH_MS) },
        r => r,
    };
    let names_only = matches!(req, Request::Namespaces);
    match Box::pin(handle(d, req)).await? {
        Response::Names { names } if names_only => Ok(Response::Names { names: names.into_iter().filter(|n| scope.namespaces.contains(n)).collect() }),
        r => Ok(r),
    }
}

/// Sends `req` to own node `peer` over a Link, identifying this node first.
async fn remote_request(d: &Daemon, peer: &PeerId, req: &Request) -> Result<Response, String> {
    let body = rmp_serde::to_vec_named(req).map_err(|e| e.to_string())?;
    for attempt in 0..2 {
        let link = d.link_to(peer).await?;
        if !d.identified.lock().unwrap().contains(&link) {
            d.transport.identify(link, d.identity_hash).await?;
            d.identified.lock().unwrap().insert(link);
        }
        match d.ask(link, API_ENDPOINT, body.clone()).await {
            Ok(bytes) => return rmp_serde::from_slice(&bytes).map_err(|e| format!("bad answer from <{}>: {e}", hex(peer))),
            // A cached link may have gone stale: once more on a new one.
            Err(e) if attempt == 0 => {
                eprintln!("remote <{}>: {e}; retrying on a new link", hex(peer));
                d.drop_link(peer);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

async fn handle(d: &Daemon, req: Request) -> Result<Response, String> {
    match req {
        Request::Hello { .. } => Ok(Response::Done), // the owner needs no token

        Request::AppAdd { name, namespaces, write, device, keys } => {
            if name.is_empty() || namespaces.is_empty() {
                return Err("an app needs a name and at least one namespace".into());
            }
            let device = match device {
                Some(addr) => Some(
                    *parse_destination(&addr).ok_or_else(|| format!("{addr} isn't a node address (retifs ping shows it)"))?.as_bytes(),
                ),
                None => None,
            };
            // A device gets no token: its hash is of a token never issued.
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).expect("OS entropy");
            let token = format!("rta_{}", hex(&raw));
            let token_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()).into();
            d.store
                .put_app(&retifs_store::App { name, token_hash, namespaces, write, exe: None, device, keys })
                .map_err(|e| e.to_string())?;
            Ok(if device.is_some() { Response::Done } else { Response::AppToken { token } })
        }

        Request::NsSearch { ns } => {
            writable(&ns)?;
            match publish_index(d, &ns, true).await? {
                Some(address) => Ok(Response::Channel { address }),
                None => Err(format!(
                    "{ns} declares no searchable keys: add a record type={} keys=KEY[,KEY] (prefix:* for a family)",
                    index::SETTINGS_TYPE
                )),
            }
        }

        Request::SearchQuery { ns, node, terms } => search_query(d, &ns, &node, &terms).await,

        Request::Remote { node, req } => {
            if matches!(*req, Request::Remote { .. }) {
                return Err("one hop only".into());
            }
            let peer = *parse_destination(&node).ok_or_else(|| format!("{node} isn't a node address"))?.as_bytes();
            remote_request(d, &peer, &req).await
        }

        Request::StorageNodes => Ok(Response::StorageNodes {
            nodes: d
                .store
                .storage_nodes()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|n| {
                    let q = d.store.link_quality(&n.peer).unwrap_or_default();
                    let s = d.store.holder_stats(&n.peer).unwrap_or_default();
                    libretifs::StorageNodeInfo {
                        node: hex(&n.peer),
                        hops: n.hops,
                        last_heard_ms: n.last_heard_ms,
                        announce_s: n.announce_s,
                        avoid_until_ms: n.avoid_until_ms,
                        rtt_ms: q.rtt_ms,
                        rate_bps: q.rate_bps,
                        slow: q.rtt_ms > 0 && q.slow(),
                        same_site: d.site.is_some() && n.site == d.site,
                        ok: s.ok,
                        fail: s.fail,
                    }
                })
                .collect(),
        }),

        Request::AppList => Ok(Response::Apps {
            apps: d
                .store
                .apps()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|a| AppInfo { name: a.name, namespaces: a.namespaces, write: a.write, exe: a.exe, device: a.device.map(|d| hex(&d)), keys: a.keys })
                .collect(),
        }),

        Request::AppRemove { name } => {
            if d.store.remove_app(&name).map_err(|e| e.to_string())? {
                Ok(Response::Done)
            } else {
                Err(format!("no app {name}"))
            }
        }

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

        Request::PutFd { .. } => Err("PutFd needs the owner's Unix socket (the descriptor travels with the frame)".into()),

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
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::Replicate { cap, to } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let chunks = file_chunks(&d.store, &cap)?;
            // The holders pull from this node with the chunks' tokens.
            d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
            for h in &to {
                let peer = *parse_destination(h).ok_or_else(|| format!("bad node hash {h}"))?.as_bytes();
                // Also name this node as a source, so the holder can pull what a push missed.
                let roots: HashMap<Cid, Vec<Cid>> = chunks.iter().map(|(c, _)| (*c, vec![cap.root])).collect();
                match lease_to(d, &peer, &sorted(&chunks), &roots, &[d.node_id]).await.map_err(|e| format!("{h}: {e}"))? {
                    true => println!("replicate: leased {} chunk(s) of {} to <{h}>", chunks.len(), cap.root),
                    false => return Err(format!("{h} refused the lease: NoRoom")),
                }
            }
            d.upkeep_wake.notify_one();
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::Forget { cap } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            forget(d, &cap)?;
            Ok(Response::Status(full_status(d, &cap)))
        }

        Request::ChannelCreate { name } => {
            let mut secrets = [0u8; 64];
            getrandom::fill(&mut secrets).expect("OS entropy");
            d.store
                .create_channel(&name, secrets[..32].try_into().unwrap(), secrets[32..].try_into().unwrap())
                .map_err(|e| e.to_string())?;
            let c = d.store.own_channel(&name).map_err(|e| e.to_string())?.expect("just created");
            Ok(Response::Channel { address: ChannelKey::from_secrets(c.signing_seed, c.read_key).addr().to_string() })
        }

        Request::ChannelPublish { name, data, compress } => {
            let (seq, file) = publish_channel(d, &name, data, compress, 0).await?;
            Ok(Response::Published { seq, cap: file.to_string() })
        }

        Request::ChannelPublishNs { name, ns } => {
            let snap = Snapshot::new(d.store.records(&ns).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            println!("channel {name}: snapshot of {ns}, {} record(s)", snap.records.len());
            let (seq, file) = publish_channel(d, &name, snap.encode(), true, 0).await?;
            Ok(Response::Published { seq, cap: file.to_string() })
        }

        Request::Follow { address, from } => {
            let addr: ChannelAddr = address.parse().map_err(|e: retifs_core::channel::ChannelError| e.to_string())?;
            let peers: Vec<PeerId> = from
                .iter()
                .map(|h| parse_destination(h).map(|d| *d.as_bytes()).ok_or_else(|| format!("bad node hash {h}")))
                .collect::<Result<_, _>>()?;
            d.store.follow(&addr, &peers).map_err(|e| e.to_string())?;
            d.follow_wake.notify_one();
            channels(d)
        }

        Request::Channels => channels(d),

        Request::Namespaces => Ok(Response::Names { names: visible_namespaces(d)? }),

        Request::RecordCreate { ns, attrs, data } => {
            let records = transaction(d, &ns, vec![TxStep::Create { attrs, data }]).await?;
            Ok(Response::Records { records })
        }

        Request::RecordSet { ns, id, attrs, unset, data } => {
            let records = transaction(d, &ns, vec![TxStep::Set { id, attrs, unset, data, blocks: None }]).await?;
            Ok(Response::Records { records })
        }

        Request::RecordGet { ns, id } => {
            let rid = parse_record_id(&id)?;
            if d.store.get_record(&ns, &rid).map_err(|e| e.to_string())?.is_none() && d.store.ns_lazy(&ns).map_err(|e| e.to_string())? {
                fetch_paths(d, &ns, &[rid], &[], false).await?;
                materialize(d, &ns)?;
            }
            let rec = d.store.get_record(&ns, &rid).map_err(|e| e.to_string())?.ok_or("no such record")?;
            Ok(Response::Records { records: vec![view(&rec)] })
        }

        Request::RecordDelete { ns, id } => {
            transaction(d, &ns, vec![TxStep::Delete { id }]).await?;
            Ok(Response::Records { records: Vec::new() })
        }

        Request::Watch { ns, since, timeout_ms } => {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms.min(600_000));
            loop {
                // Registered before looking, so a change in between isn't missed.
                let notified = d.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let count = d.changes.lock().unwrap().get(&ns).copied().unwrap_or(0);
                if count != since {
                    return Ok(Response::Changed { count });
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    return Ok(Response::Changed { count });
                }
            }
        }

        Request::WriteBegin { ns, id, truncate } => {
            writable(&ns)?;
            let rid = parse_record_id(&id)?;
            let rec = d.store.get_record(&ns, &rid).map_err(|e| e.to_string())?.ok_or("no such record")?;
            let base = if truncate { None } else { rec.blocks.first().copied() };
            let base_len = base.map_or(0, |f| f.size);
            let dir = d.store.root().join("spool");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            // Sessions left open for a day (a client that died) are dropped.
            d.sessions.lock().unwrap().retain(|_, s| {
                let keep = s.started.elapsed() < Duration::from_secs(86_400);
                if !keep {
                    let _ = std::fs::remove_file(&s.path);
                }
                keep
            });
            let session = d.next_session.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = dir.join(format!("{session}-{}", hex(&rid)));
            let spool = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).map_err(|e| e.to_string())?;
            let s = WriteSession { ns, id: rid, base, base_len, spool, path, extents: Default::default(), size: base_len, started: Instant::now() };
            d.sessions.lock().unwrap().insert(session, s);
            Ok(Response::Session { session, size: base_len })
        }

        Request::WriteAt { session, offset, data } => {
            let mut sessions = d.sessions.lock().unwrap();
            let s = sessions.get_mut(&session).ok_or("no such write session")?;
            s.write_at(offset, &data).map_err(|e| e.to_string())?;
            Ok(Response::Done)
        }

        Request::WriteTruncate { session, size } => {
            let mut sessions = d.sessions.lock().unwrap();
            sessions.get_mut(&session).ok_or("no such write session")?.truncate(size);
            Ok(Response::Done)
        }

        Request::WriteRead { session, offset, len } => {
            let (pieces, spool, base, ns) = {
                let sessions = d.sessions.lock().unwrap();
                let s = sessions.get(&session).ok_or("no such write session")?;
                (s.pieces(offset..offset.saturating_add(len)), s.spool.try_clone().map_err(|e| e.to_string())?, s.base, s.ns.clone())
            };
            let mut data = Vec::new();
            for (range, piece) in pieces {
                match piece {
                    Piece::Base => {
                        let base = base.as_ref().ok_or("no base content")?;
                        data.extend(read_range_fetching(d, base, range, Some(&ns), Duration::from_secs(30)).await?);
                    }
                    other => {
                        let mut r = SessionReader { pieces: [(range, other)].into(), spool: spool.try_clone().map_err(|e| e.to_string())?, base: None, store: d.store.clone() };
                        std::io::Read::read_to_end(&mut r, &mut data).map_err(|e| e.to_string())?;
                    }
                }
            }
            Ok(Response::Range { data })
        }

        Request::WriteAbort { session } => {
            if let Some(s) = d.sessions.lock().unwrap().remove(&session) {
                let _ = std::fs::remove_file(&s.path);
            }
            Ok(Response::Done)
        }

        Request::WriteCommit { session, attrs } => {
            // One commit per session however often it's asked: a repeat waits
            // for the first and answers with its result.
            let cell = {
                let ns = d.sessions.lock().unwrap().get(&session).map(|s| s.ns.clone());
                let mut commits = d.commits.lock().unwrap();
                commits.retain(|_, c| c.at.elapsed() < Duration::from_secs(3600));
                commits.entry(session).or_insert_with(|| PendingCommit { at: Instant::now(), ns, result: Arc::new(tokio::sync::OnceCell::new()) }).result.clone()
            };
            let result = cell
                .get_or_init(|| async {
                    let Some(s) = d.sessions.lock().unwrap().remove(&session) else { return Err("no such write session".to_string()) };
                    let result = commit_session(d, &s, attrs).await;
                    let _ = std::fs::remove_file(&s.path);
                    result
                })
                .await
                .clone();
            Ok(Response::Records { records: result? })
        }

        Request::Transaction { ns, steps } => {
            let records = transaction(d, &ns, steps).await?;
            Ok(Response::Records { records })
        }

        Request::NsAddress { ns } => {
            writable(&ns)?;
            ensure_namespace(d, &ns)?;
            Ok(Response::Channel { address: current_addr(d, &ns)?.to_string() })
        }
        Request::NsAnnounce { ns, on, name, about } => {
            if on {
                current_addr(d, &ns)?;
                let name = name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| ns.clone());
                set_announced(&d.store, &ns, Some((name, about.unwrap_or_default())))?;
            } else {
                set_announced(&d.store, &ns, None)?;
            }
            d.lib_wake.notify_one();
            Ok(Response::Done)
        }
        Request::NsLeave { ns, mine } => {
            if ns.starts_with("ch-") {
                return Err(format!("{ns} is a followed channel, not a joined library"));
            }
            let (creator, _) = d.store.ns_info(&ns).map_err(|e| e.to_string())?.ok_or_else(|| format!("no library {ns}"))?;
            let (_, own, _) = chains(d, &ns, false)?;
            if creator == own && !mine {
                return Err(format!("{ns} was created here: leaving it deletes it unless someone else holds it (repeat with --mine)"));
            }
            // Gone from view at once; its data is removed in the background
            // (a map's 95,000 files take minutes), even across a restart.
            set_announced(&d.store, &ns, None)?;
            mark_leaving(d, &ns, true)?;
            d.leave_wake.notify_one();
            Ok(Response::Done)
        }
        Request::HeardLibraries => {
            // Which heard ones are here already: our own and joined ones, by address.
            let here: HashMap<String, String> = visible_namespaces(d)?
                .into_iter()
                .filter_map(|n| current_addr(d, &n).ok().map(|a| (a.to_string(), n)))
                .collect();
            let heard = d.heard_libs.lock().unwrap();
            let mut libraries: Vec<libretifs::HeardLibrary> = heard
                .values()
                .map(|h| {
                    let addr = h.lib.as_ref().map(|l| ChannelAddr { writer: l.writer, read_key: l.read_key }.to_string()).unwrap_or_default();
                    let l = h.lib.clone();
                    libretifs::HeardLibrary {
                        name: l.as_ref().map(|l| l.name.clone()).unwrap_or_default(),
                        about: l.as_ref().map(|l| l.about.clone()).unwrap_or_default(),
                        has: l.as_ref().map(|l| l.has.clone()).unwrap_or_default(),
                        bounds: l.as_ref().and_then(|l| l.bounds),
                        seq: l.as_ref().map(|l| l.seq).unwrap_or(0),
                        fmt: l.as_ref().map(|l| l.fmt).unwrap_or(0),
                        readable: l.as_ref().is_some_and(|l| l.fmt <= retifs_core::announce::LIBRARY_FMT),
                        v: h.v,
                        here: here.get(&addr).cloned(),
                        address: addr,
                        node: hex(&h.node),
                        hops: h.hops,
                        heard_ms: h.heard_ms,
                    }
                })
                .collect();
            libraries.sort_by(|a, b| b.heard_ms.cmp(&a.heard_ms));
            Ok(Response::Heard { libraries })
        }

        Request::NsJoin { ns, address, from, lazy } => {
            writable(&ns)?;
            if d.store.ns_info(&ns).map_err(|e| e.to_string())?.is_some() {
                // Joined again while being left: the leave is called off and
                // it's back; what was forgotten is fetched again as it's read.
                let same = current_addr(d, &ns).map(|a| a.to_string() == address.trim()).unwrap_or(false);
                if same && d.leaving.lock().unwrap().contains(&ns) {
                    mark_leaving(d, &ns, false)?;
                    d.store.add_ns_peers(&ns, &parse_peers(&from)?).map_err(|e| e.to_string())?;
                    d.ns_wake.notify_one();
                    println!("{ns}: joined again while being left; the leave is called off");
                    save_keyring(d);
                    return Ok(Response::Namespace(ns_view(d, &ns)?));
                }
                return Err(format!("{ns} already exists here"));
            }
            let addr: ChannelAddr = address.parse().map_err(|e: retifs_core::channel::ChannelError| e.to_string())?;
            // This node's writer identity in the namespace (X25519 ‖ Ed25519): others
            // wrap rotated read keys to it.
            let mut identity = [0u8; 64];
            getrandom::fill(&mut identity).expect("OS entropy");
            let seed: [u8; 32] = identity[32..].try_into().unwrap();
            d.store.create_channel(&ns_channel(&ns), seed, addr.read_key).map_err(|e| e.to_string())?;
            d.store.set_member_channel(&ns_channel(&ns), &addr.ns_id()).map_err(|e| e.to_string())?;
            d.store.set_ns_info(&ns, &addr.writer, &addr.read_key).map_err(|e| e.to_string())?;
            d.store.set_ns_identity(&ns, &identity).map_err(|e| e.to_string())?;
            d.store.add_ns_peers(&ns, &parse_peers(&from)?).map_err(|e| e.to_string())?;
            if lazy || d.no_storage {
                d.store.set_ns_lazy(&ns, true).map_err(|e| e.to_string())?;
                // Lazy means content too: kept by rules (tags, what's read),
                // not all of it pulled (a map's 95,000 tiles).
                d.store.set_ns_keep_by_rules(&ns, true).map_err(|e| e.to_string())?;
            }
            write_ops(d, &ns, vec![Op::Identity(keywrap::public(&identity))]).await?;
            d.ns_seeking.lock().unwrap().insert(ns.clone());
            save_keyring(d);
            d.ns_wake.notify_one();
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::NsGrant { ns, writer, grant, from, keys, until } => {
            writable(&ns)?;
            let w = parse_writer(&writer)?;
            let rights = if grant { vec![Right::Write, Right::Grant] } else { vec![Right::Write] };
            let limits = retifs_core::ops::Limits { keys: (!keys.is_empty()).then(|| keys.into_iter().collect()), until };
            let op = if limits.is_none() { Op::Grant(w, rights) } else { Op::GrantLimited(w, rights, limits) };
            write_ops(d, &ns, vec![op]).await?;
            d.store.add_ns_peers(&ns, &parse_peers(&from)?).map_err(|e| e.to_string())?;
            d.ns_wake.notify_one();
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::NsRevoke { ns, writer } => {
            writable(&ns)?;
            let revoked = parse_writer(&writer)?;
            // A new read key for everyone else, wrapped to each remaining writer's
            // identity (RNS Identity.encrypt), committed with the revoke under the
            // old key; later versions use the new one (ADR-0017).
            let merged = materialize(d, &ns)?;
            let mut new_key = [0u8; 32];
            getrandom::fill(&mut new_key).expect("OS entropy");
            let mut entries = Vec::new();
            let mut unreachable = 0;
            for (w, rights) in &merged.writers {
                if *w == revoked || !rights.contains(&Right::Write) {
                    continue;
                }
                match merged.identities.get(w) {
                    Some(public) => {
                        let mut rnd = [0u8; 48];
                        getrandom::fill(&mut rnd).expect("OS entropy");
                        let wrapped = keywrap::wrap(public, &new_key, rnd[..32].try_into().unwrap(), rnd[32..].try_into().unwrap());
                        entries.push((*w, wrapped));
                    }
                    None => unreachable += 1,
                }
            }
            let epoch = d.store.ns_keys(&ns).map_err(|e| e.to_string())?.len() as u64;
            let n = entries.len();
            write_ops(d, &ns, vec![Op::Revoke(revoked), Op::Rekey(epoch, entries)]).await?;
            use_key(d, &ns, &new_key)?;
            println!("ns {ns}: revoked {}…, read key rotated to epoch {epoch} for {n} writer(s){}", &writer[..12.min(writer.len())],
                if unreachable > 0 { format!(", {unreachable} without a known identity left out") } else { String::new() });
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::NsInfo { ns } => {
            // Asking about a name isn't making a namespace of it.
            if d.store.ns_info(&ns).map_err(|e| e.to_string())?.is_none() {
                return Err(format!("no namespace {ns}"));
            }
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::NsVerify { ns } => {
            if d.store.ns_lazy(&ns).map_err(|e| e.to_string())? {
                return Err(format!("{ns} is held lazily (part of its state): nothing whole to verify"));
            }
            ns_entry(d, &ns).lock().unwrap().fetch_whole = true;
            sync_ns(d, &ns).await?;
            let (ok, detail) = verify_checkpoint(d, &ns)?;
            Ok(Response::Verified { ok, detail })
        }

        Request::NsKeep { ns, mode } => {
            let by_rules = match mode.as_str() {
                "all" => false,
                "rules" => true,
                _ => return Err("keep mode is all or rules".into()),
            };
            d.store.set_ns_keep_by_rules(&ns, by_rules).map_err(|e| e.to_string())?;
            materialize(d, &ns)?;
            apply_keep(d, &ns, &d.store.records(&ns).map_err(|e| e.to_string())?)?;
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::ShareCreate { source, name, terms, ids, omit } => {
            writable(&source)?;
            writable(&name)?;
            if source == name {
                return Err("a share is a namespace of its own".into());
            }
            if d.store.ns_info(&name).map_err(|e| e.to_string())?.is_some() {
                return Err(format!("{name} already exists here"));
            }
            if terms.is_empty() && ids.is_empty() {
                return Err("a share needs a selection: query terms or record IDs".into());
            }
            for t in &terms {
                retifs_store::Term::parse(t)?;
            }
            for id in &ids {
                parse_record_id(id)?;
            }
            if d.store.ns_info(&source).map_err(|e| e.to_string())?.is_none() {
                return Err(format!("no namespace {source}"));
            }
            ensure_namespace(d, &name)?;
            let mut attrs = vec![
                ("type".to_string(), AttrValue::Str(share::DEFINITION_TYPE.into())),
                ("name".to_string(), AttrValue::Str(name.clone())),
                ("share".to_string(), AttrValue::Str(current_addr(d, &name)?.to_string())),
            ];
            if !terms.is_empty() {
                attrs.push(("select".to_string(), AttrValue::Str(terms.join(", "))));
            }
            if !ids.is_empty() {
                attrs.push(("ids".to_string(), AttrValue::List(ids.into_iter().map(AttrValue::Str).collect())));
            }
            if !omit.is_empty() {
                attrs.push(("omit".to_string(), AttrValue::List(omit.into_iter().map(AttrValue::Str).collect())));
            }
            let def = transaction(d, &source, vec![TxStep::Create { attrs, data: None }]).await?;
            let def = d.store.get_record(&source, &parse_record_id(&def[0].id)?).map_err(|e| e.to_string())?.ok_or("the share's definition isn't visible")?;
            sync_share(d, &source, &def).await?;
            Ok(Response::Namespace(ns_view(d, &name)?))
        }

        Request::ShareDelete { source, id } => {
            writable(&source)?;
            let rec = d.store.get_record(&source, &parse_record_id(&id)?).map_err(|e| e.to_string())?.ok_or_else(|| format!("no such record {id}"))?;
            if rec.attrs.get("type") != Some(&Value::Str(share::DEFINITION_TYPE.into())) {
                return Err(format!("{id} isn't a share of {source}"));
            }
            transaction(d, &source, vec![TxStep::Delete { id }]).await?;
            Ok(Response::Done)
        }

        Request::InviteCreate { ns, grant, keys, until, expires_ms, q, label } => {
            writable(&ns)?;
            if d.store.ns_info(&ns).map_err(|e| e.to_string())?.is_none() {
                return Err(format!("no namespace {ns}"));
            }
            let merged = materialize(d, &ns)?;
            let (_, own, _) = chains(d, &ns, false)?;
            if !merged.writers.get(&own).is_some_and(|r| r.contains(&Right::Grant)) {
                return Err(format!("this node may not grant in {ns}, so it can't invite"));
            }
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).expect("OS entropy");
            let inv = Invitation {
                ns: current_addr(d, &ns)?,
                node: parse_peers(std::slice::from_ref(&d.node_hex))?[0],
                secret,
                grant,
                keys,
                until,
                expires: now_ms() + expires_ms.unwrap_or(24 * 3600 * 1000),
                q,
            };
            d.store.put_invite(&MadeInvite { ns: ns.clone(), invitation: inv.clone(), spent: false }).map_err(|e| e.to_string())?;
            let link = libretifs::link::Link { kind: "invite".into(), what: inv.to_text(), params: vec![("name".into(), label.unwrap_or(ns))] };
            Ok(Response::Link { link: link.to_string() })
        }

        Request::InviteList { ns } => {
            writable(&ns)?;
            let invites = d
                .store
                .invites()
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|m| m.ns == ns)
                .map(|m| libretifs::InviteInfo {
                    id: hex(&m.invitation.id()),
                    grant: m.invitation.grant,
                    keys: m.invitation.keys.clone(),
                    until: m.invitation.until,
                    expires: m.invitation.expires,
                    spent: m.spent,
                })
                .collect();
            Ok(Response::Invites { invites })
        }

        Request::InviteCancel { ns, id } => {
            writable(&ns)?;
            let id = parse_writer(&id).map_err(|_| "an invitation ID is 64 hex digits".to_string())?;
            match d.store.invite(&id).map_err(|e| e.to_string())? {
                Some(m) if m.ns == ns => {
                    d.store.remove_invite(&id).map_err(|e| e.to_string())?;
                    Ok(Response::Done)
                }
                _ => Err(format!("no such invitation for {ns}")),
            }
        }

        Request::InviteAccept { ns, link } => {
            writable(&ns)?;
            let l = libretifs::link::Link::parse(&link)?;
            if l.kind != "invite" {
                return Err(format!("a retifs:{} link isn't an invitation", l.kind));
            }
            let inv = Invitation::from_text(&l.what).map_err(|e| format!("not a valid invitation: {e}"))?;
            if inv.expires < now_ms() {
                return Err("this invitation has expired".into());
            }
            // Joined first: the address reads at once, whatever the grant does.
            if d.store.ns_info(&ns).map_err(|e| e.to_string())?.is_none() {
                let join = Request::NsJoin { ns: ns.clone(), address: inv.ns.to_string(), from: vec![hex(&inv.node)], lazy: false };
                Box::pin(handle(d, join)).await?;
            } else if current_addr(d, &ns)?.writer != inv.ns.writer {
                return Err(format!("{ns} here is another namespace"));
            }
            d.store.put_redeem(&ns, &inv).map_err(|e| e.to_string())?;
            match redeem_there(d, &ns, &inv).await {
                Ok(m) => {
                    eprintln!("invitation to {ns}: {m}");
                    // The grant is in the creator's chain: fetched now, so the
                    // answer can say this node may write.
                    if let Err(e) = sync_ns(d, &ns).await {
                        eprintln!("ns {ns}: {e}");
                    }
                }
                Err(e) if e.starts_with("the invitation was refused") => return Err(e),
                Err(e) => eprintln!("invitation to {ns}: {e}; trying again on the next sync"),
            }
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::NsCheckpoint { ns } => {
            writable(&ns)?;
            ns_entry(d, &ns).lock().unwrap().since_checkpoint = CHECKPOINT_EVERY;
            materialize(d, &ns)?;
            publish_checkpoint(d, &ns).await?;
            Ok(Response::Namespace(ns_view(d, &ns)?))
        }

        Request::Query { ns, terms: texts, at } => {
            let terms: Vec<retifs_store::Term> = texts.iter().map(|t| retifs_store::Term::parse(t)).collect::<Result<_, _>>()?;
            let found = match at {
                None => {
                    // Held lazily: the whole answer, as of now, whatever is
                    // here. A peer that holds it all is asked through its
                    // blind index (ADR-0019) every time; what it finds is
                    // fetched, and what's here (perhaps newer) is merged in.
                    if d.store.ns_lazy(&ns).unwrap_or(false) {
                        if let Some(mut records) = lazy_search(d, &ns, &texts).await {
                            let here = d.store.query(&ns, &terms).map_err(|e| e.to_string())?;
                            let mut seen: std::collections::HashSet<String> = records.iter().map(|r| r.id.clone()).collect();
                            records.retain(|r| here.iter().all(|h| hex(&h.id) != r.id));
                            records.extend(here.iter().map(view));
                            seen.clear();
                            records.retain(|r| seen.insert(r.id.clone()));
                            return Ok(Response::Records { records });
                        }
                    }
                    d.store.query(&ns, &terms).map_err(|e| e.to_string())?
                }
                Some(seq) => {
                    let mut at = None;
                    versions(d, &ns, |v, _, st| {
                        if v == seq {
                            at = Some(st.records());
                        }
                    })?;
                    let records = at.ok_or_else(|| format!("version {seq} of {ns} isn't held here"))?;
                    records.into_iter().filter(|r| terms.iter().all(|t| t.matches(r))).collect()
                }
            };
            Ok(Response::Records { records: found.iter().map(view).collect() })
        }

        Request::ReadRange { cap, ns, offset, len, wait_ms } => {
            let file: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let end = offset.saturating_add(len).min(file.size);
            let range = offset.min(end)..end;
            let data = read_range_fetching(d, &file, range, ns.as_deref(), Duration::from_millis(wait_ms)).await?;
            Ok(Response::Range { data })
        }

        Request::RecordHistory { ns, id } => {
            let id = parse_record_id(&id)?;
            let mut entries = Vec::new();
            versions(d, &ns, |version, time_ms, st| {
                entries.push(HistoryEntry { version, time_ms, record: st.record(&id).as_ref().map(view) });
            })?;
            entries.reverse(); // newest first
            Ok(Response::History { entries })
        }

        Request::Want { cap, from } => {
            let cap: FileRef = cap.parse().map_err(|e: retifs_core::ManifestError| e.to_string())?;
            let peers: Vec<PeerId> = from
                .iter()
                .map(|h| parse_destination(h).map(|d| *d.as_bytes()).ok_or_else(|| format!("bad node hash {h}")))
                .collect::<Result<_, _>>()?;
            d.store.want_file(&cap, &peers).map_err(|e| e.to_string())?;
            d.wake.notify_one();
            Ok(Response::Status(full_status(d, &cap)))
        }
    }
}

/// Writes `data` as pinned own data and registers it for serving: to holders
/// of its read-cap (serve token), and to anyone if `publish`.
/// `PutFd`: stores a file the client handed over as a descriptor, read and
/// chunked as a stream (the same file, and read-cap, as `Put` with its bytes).
async fn put_file(d: &Daemon, file: std::fs::File, public: bool, compress: bool, publish: bool, record: Option<String>) -> Result<Response, String> {
    let store = d.store.clone();
    let opts = manifest::WriteOpts {
        compression: if compress { retifs_core::Compression::Zstd } else { retifs_core::Compression::Off },
        ..Default::default()
    };
    let file = tokio::task::spawn_blocking(move || -> Result<FileRef, String> {
        let secret = secret(&store, public, record.as_deref());
        let opts = manifest::WriteOpts { stable_padding: record.is_some() && !public, ..opts };
        let mut pinned = retifs_store::TrackedPinned::new(&store);
        let (file, blobs) = match manifest::write_reader(&mut pinned, &secret, std::io::BufReader::with_capacity(1 << 20, file), opts)
            .map_err(|e| e.to_string())
            .and_then(|w| pinned.flush().map(|_| w).map_err(|e| e.to_string()))
        {
            Ok(written) => written,
            Err(e) => {
                let _ = pinned.roll_back();
                return Err(e);
            }
        };
        let tokens: Vec<_> = blobs.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
        store.register_serving(&tokens).map_err(|e| e.to_string())?;
        if publish {
            store.publish(&blobs.iter().map(|(c, _)| *c).collect::<Vec<_>>()).map_err(|e| e.to_string())?;
        }
        Ok(file)
    })
    .await
    .map_err(|e| e.to_string())??;
    d.store.need_file(&file).map_err(|e| e.to_string())?;
    d.upkeep_wake.notify_one();
    Ok(Response::Put { cap: file.to_string() })
}

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
    let (file, blobs) = match manifest::write_tracked(&mut pinned, &secret, data, opts)
        .map_err(|e| e.to_string())
        .and_then(|w| pinned.flush().map(|_| w).map_err(|e| e.to_string()))
    {
        Ok(written) => written,
        Err(e) => {
            // Don't leave half a file pinned (and eating the budget).
            let _ = pinned.roll_back();
            return Err(e);
        }
    };
    let tokens: Vec<_> = blobs.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
    store.register_serving(&tokens).map_err(|e| e.to_string())?;
    if publish {
        store.publish(&blobs.iter().map(|(c, _)| *c).collect::<Vec<_>>()).map_err(|e| e.to_string())?;
    }
    Ok(file)
}

fn full_status(d: &Daemon, cap: &FileRef) -> Status {
    let store = &d.store;
    let mut s = local_status(store, cap);
    s.slow_link_wait_secs = d.deferred.lock().unwrap().get(&cap.root).copied();
    s.seeking = store.is_wanted(&cap.root).unwrap_or(false);
    s.holders_known = store.hints(&cap.root).map(|h| h.len()).unwrap_or(0);
    let own = store.own_leases().unwrap_or_default();
    let holders: std::collections::BTreeSet<PeerId> = own.iter().filter(|o| o.roots.contains(&cap.root)).map(|o| o.holder).collect();
    let confirmed = store.confirmed_holders(&cap.root, now_s()).unwrap_or_default();
    let sites = node_sites(d);
    s.leased_to = holders.len();
    s.replicas = confirmed.len();
    s.holders = holders
        .iter()
        .map(|h| libretifs::FileHolder { node: hex(h), confirmed: confirmed.contains(h), same_site: same_site(d, &sites, h) })
        .collect();
    s
}

/// Stores `data` as the channel's next version: a commit linking the last one,
/// and a new signed head (ADR-0015).
/// `not_before`: the commit's time is at least this (ms), whatever the clock says.
async fn publish_channel(d: &Daemon, name: &str, data: Vec<u8>, compress: bool, not_before: u64) -> Result<(u64, FileRef), String> {
    // One write at a time: each reads the channel's last version and stores
    // the next. Two at once took the same sequence number and one commit was
    // lost (found by the scale test: 131 of 300 concurrent writes vanished).
    let _one_at_a_time = d.publishing.lock().await;
    let mut c = d.store.own_channel(name).map_err(|e| e.to_string())?.ok_or_else(|| format!("no channel {name}"))?;
    let store = d.store.clone();
    let opts = manifest::WriteOpts {
        compression: if compress { retifs_core::Compression::Zstd } else { retifs_core::Compression::Off },
        ..Default::default()
    };
    // One record per channel: versions dedup against each other.
    let record = format!("retifs-channel/{name}");
    let file = tokio::task::spawn_blocking(move || store_file(&store, &data, false, false, Some(&record), opts))
        .await
        .map_err(|e| e.to_string())??;
    let key = channel_key(d, &c);
    let (_, sealed) = Commit::create(&key, c.seq + 1, now_ms().max(not_before), c.last, file);
    d.store.insert(&sealed.cid, &sealed.ciphertext, tier::PINNED).map_err(|e| e.to_string())?;
    d.store.register_serving(&[(sealed.cid, ChunkToken::for_seed(&sealed.seed))]).map_err(|e| e.to_string())?;
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("OS entropy");
    let head = Head::sign(&key, c.seq + 1, now_s(), sealed.cid, &sealed.seed, iv);
    if name.starts_with("ns:") {
        d.store.set_key_head(&key.ns_id(), &key.writer(), &key_id(&c.read_key), &head.encode()).map_err(|e| e.to_string())?;
    }
    c.seq += 1;
    c.last = Some((sealed.cid, sealed.seed));
    c.head = head.encode().to_vec();
    d.store.update_own_channel(&c).map_err(|e| e.to_string())?;
    // The commit is kept elsewhere with the file it names: the chain can then
    // be fetched back from the file's holders (ADR-0031).
    d.store.need_file_with(&file, &[(sealed.cid, sealed.seed)]).map_err(|e| e.to_string())?;
    // A storage-less node's head is only in its keyring: written at once, or
    // a restart would go back to an older head and reuse its numbers.
    save_keyring(d);
    d.upkeep_wake.notify_one();
    println!("channel {name}: published version {} ({file})", c.seq);
    Ok((c.seq, file))
}

/// The local namespace a followed channel's snapshots are rebuilt into.
fn channel_ns(addr: &ChannelAddr) -> String {
    format!("ch-{}", hex(&addr.ns_id()[..8]))
}

/// A version's snapshot, if the file is one and is local.
fn read_snapshot(store: &SlabStore, f: &FileRef) -> Option<Snapshot> {
    let bytes = manifest::read_all(store, f).ok()?;
    Snapshot::is_snapshot(&bytes).then(|| Snapshot::decode(&bytes).ok()).flatten()
}

/// Every file a version consists of: the version itself and, for a snapshot,
/// its records' content blocks.
fn version_files(store: &SlabStore, f: &FileRef) -> Vec<FileRef> {
    let mut files = vec![*f];
    if let Some(snap) = read_snapshot(store, f) {
        files.extend(snap.records.iter().flat_map(|r| r.blocks.iter().copied()));
    }
    files
}

fn parse_peers(from: &[String]) -> Result<Vec<PeerId>, String> {
    from.iter()
        .map(|h| parse_destination(h).map(|d| *d.as_bytes()).ok_or_else(|| format!("bad node hash {h}")))
        .collect()
}

fn parse_writer(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let bytes: Option<Vec<u8>> = (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
    bytes.and_then(|b| b.try_into().ok()).ok_or_else(|| format!("bad writer key {s} (64 hex digits)"))
}

fn ns_view(d: &Daemon, ns: &str) -> Result<NsView, String> {
    let merged = materialize(d, ns)?;
    let (_, own, _) = chains(d, ns, false)?;
    Ok(NsView {
        name: ns.to_string(),
        address: current_addr(d, ns)?.to_string(),
        own_writer: hex(&own),
        writers: merged
            .writers
            .iter()
            .map(|(w, rights)| {
                let mut shown: Vec<String> = rights.iter().map(|r| if *r == Right::Grant { "grant" } else { "write" }.to_string()).collect();
                if let Some(l) = merged.limits.get(w) {
                    if let Some(keys) = &l.keys {
                        shown.push(format!("keys={}", keys.iter().cloned().collect::<Vec<_>>().join("|")));
                    }
                    if let Some(u) = l.until {
                        shown.push(format!("until={u}{}", if u <= now_ms() { " (expired)" } else { "" }));
                    }
                }
                (hex(w), shown)
            })
            .collect(),
        records: d.store.records(ns).map_err(|e| e.to_string())?.len(),
        peers: d.store.ns_peers(ns).map_err(|e| e.to_string())?.len(),
        checkpoint: d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?.map(|f| f.to_string()),
        device: d.device.clone(),
        keep: if d.store.ns_keep_by_rules(ns).map_err(|e| e.to_string())? { "rules" } else { "all" }.into(),
        kept: d.store.ns_kept(ns).map_err(|e| e.to_string())?.len(),
        lazy: d.store.ns_lazy(ns).map_err(|e| e.to_string())?,
    })
}

/// Keeps joined and own namespaces in sync with their other members (ADR-0017):
/// asks each peer for each known writer's head, fetches the commits and
/// operations files missing here (pinned and served on, so members can sync
/// from each other), merges, and seeks record content not held yet.
async fn ns_sync(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = d.ns_wake.notified() => {}
            _ = tick.tick() => {}
        }
        for ns in d.store.ns_names().unwrap_or_default() {
            // A storage-less node's own chain after a restart: back from the
            // nodes holding its files first. Until then, nothing is merged
            // (or checkpointed) from the part of it that is here.
            if own_chain_missing(&d, &ns) {
                let due = d.own_tried.lock().unwrap().get(&ns).is_none_or(|t| t.elapsed() > Duration::from_secs(600));
                if due && let Err(e) = restore_own(&d, &ns).await {
                    d.own_tried.lock().unwrap().insert(ns.clone(), Instant::now());
                    eprintln!("ns {ns}: own chain: {e}");
                }
                if own_chain_missing(&d, &ns) && d.store.ns_peers(&ns).unwrap_or_default().is_empty() {
                    continue;
                }
            }
            if let Err(e) = publish_checkpoint(&d, &ns).await {
                eprintln!("ns {ns}: checkpoint: {e}");
            }
            if let Err(e) = publish_index(&d, &ns, false).await {
                eprintln!("ns {ns}: index: {e}");
            }
            if let Err(e) = sync_ns(&d, &ns).await {
                eprintln!("ns {ns}: {e}");
            }
            if let Err(e) = member_nodes(&d, &ns).await {
                eprintln!("ns {ns}: member nodes: {e}");
            }
        }
    }
}

/// This node's `retifs.node` address.
fn own_node(d: &Daemon) -> Result<PeerId, String> {
    Ok(parse_peers(std::slice::from_ref(&d.node_hex))?[0])
}

/// Members know each other's nodes (ADR-0022): this node's address is in the
/// namespace (written once it may write, and again if it changed), and every
/// member's node is a peer to sync with, not just the one this node joined
/// through. A member whose only peer loses its path still syncs through the
/// others.
async fn member_nodes(d: &Daemon, ns: &str) -> Result<(), String> {
    let merged = materialize(d, ns)?;
    let (_, own, _) = chains(d, ns, false)?;
    let node = own_node(d)?;
    if merged.writers.get(&own).is_some_and(|r| r.contains(&Right::Write)) && merged.nodes.get(&own) != Some(&node) {
        write_ops(d, ns, vec![Op::Node(node)]).await?;
    }
    let known = d.store.ns_peers(ns).map_err(|e| e.to_string())?;
    let new: Vec<PeerId> = merged
        .nodes
        .iter()
        .filter(|(w, n)| **w != own && **n != node && !known.contains(n) && merged.writers.contains_key(*w))
        .map(|(_, n)| *n)
        .collect();
    if !new.is_empty() {
        d.store.add_ns_peers(ns, &new).map_err(|e| e.to_string())?;
        eprintln!("ns {ns}: {} more member node(s) to sync with", new.len());
    }
    Ok(())
}

async fn sync_ns(d: &Daemon, ns: &str) -> Result<(), String> {
    let peers = d.store.ns_peers(ns).map_err(|e| e.to_string())?;
    if peers.is_empty() {
        return Ok(());
    }
    let (addr, own, _) = chains(d, ns, false)?;
    let ns_id = addr.ns_id();
    let mut changed = false;
    // A member that joined starts from the latest checkpoint of a writer
    // holding `grant` (ADR-0018): the creator's chain is searched first, other
    // grant holders once the merged grants show them. Chains are then fetched
    // back only to the checkpoint's frontier, the history before it only if
    // a rebuild (or verification) needs it.
    let mut seeking = d.ns_seeking.lock().unwrap().contains(ns) && d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?.is_none();
    let mut searched: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let (whole, verify) = ns_entry_get(d, ns).map_or((false, false), |e| {
        let e = e.lock().unwrap();
        (e.needs_history || e.fetch_whole, e.needs_history && !e.fetch_whole)
    });
    let mut floors = if whole { HashMap::new() } else { checkpoint_floors(d, ns) };
    for peer in peers {
        let link = match d.link_to(&peer).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ns {ns}: <{}> unreachable: {e}", hex(&peer));
                continue;
            }
        };
        // Writers known so far: the creator, the merged grants, heads already held.
        let merged = materialize(d, ns)?;
        let mut writers: std::collections::BTreeSet<[u8; 32]> = merged.writers.keys().copied().collect();
        writers.insert(addr.writer);
        writers.extend(d.store.writer_heads(&ns_id).map_err(|e| e.to_string())?.iter().map(|h| h.writer));
        writers.remove(&own);
        // The creator first, then other grant holders, then the rest.
        let holds_grant = |w: &[u8; 32]| *w == addr.writer || merged.writers.get(w).is_some_and(|r| r.contains(&Right::Grant));
        let mut writers: Vec<[u8; 32]> = writers.into_iter().collect();
        writers.sort_by_key(|w| (*w != addr.writer, !holds_grant(w)));
        let gaps = chains_with_gaps(d, ns);
        for w in writers {
            let raw = match d.ask(link, HEAD_ENDPOINT, [ns_id.as_slice(), &w].concat()).await {
                Ok(r) => r,
                Err(e) => {
                    d.drop_link(&peer);
                    eprintln!("ns {ns}: <{}>: {e}", hex(&peer));
                    break;
                }
            };
            // No head here: an empty reply (Prns may deliver it as a short placeholder).
            if raw.len() != retifs_core::channel::HEAD_LEN {
                continue;
            }
            let mut head = Head::decode(&raw).map_err(|e| format!("bad head: {e}"))?;
            let mut raw = raw;
            if head.ns_id != ns_id || head.writer != w {
                continue;
            }
            let known = d.store.writer_head(&ns_id, &w).map_err(|e| e.to_string())?;
            let known_seq = known.as_ref().and_then(|k| Head::decode(&k.head).ok()).map(|k| k.seq);
            if known_seq.is_some_and(|k| k >= head.seq) && !whole && !gaps.contains(&w) {
                continue; // nothing newer (and never go back)
            }
            let keys = d.store.ns_keys(ns).map_err(|e| e.to_string())?;
            let open_with = |h: &Head| keys.iter().rev().find_map(|k| h.commit_seed(&ChannelAddr { writer: addr.writer, read_key: *k }).ok().map(|s| (s, *k)));
            let mut opened = open_with(&head);
            if opened.is_none() {
                // The latest version is under a key not held here: ask for this
                // writer's latest head under a key that is. A rotation's rekey is
                // in the last commit under the old key (ADR-0017).
                for k in keys.iter().rev() {
                    let Ok(r) = d.ask(link, HEAD_ENDPOINT, [ns_id.as_slice(), &w, &key_id(k)].concat()).await else { break };
                    let Some(h) = (r.len() == retifs_core::channel::HEAD_LEN).then(|| Head::decode(&r).ok()).flatten() else { continue };
                    if h.ns_id == ns_id && h.writer == w && known_seq.is_none_or(|s| h.seq > s) && let Some(o) = open_with(&h) {
                        (head, raw, opened) = (h, r, Some(o));
                        break;
                    }
                }
            }
            let Some((seed, used_key)) = opened else {
                eprintln!("ns {ns}: can't read writer {}…'s version {}: its read key wasn't given to this node (revoked?)", &hex(&w)[..12], head.seq);
                continue;
            };
            d.store.set_key_head(&ns_id, &w, &key_id(&used_key), &raw).map_err(|e| e.to_string())?;
            let walk = if whole {
                Walk::Whole
            } else if seeking && holds_grant(&w) {
                Walk::ToCheckpoint
            } else {
                Walk::ToHeld
            };
            // A peer may relay a writer's chain without holding its checkpoint:
            // then try the next writer, and this one again from the next peer.
            let held_to = if gaps.contains(&w) { None } else { known.as_ref().map(|k| k.commit.0) };
            if gaps.contains(&w) {
                println!("ns {ns}: writer {}…'s chain here has a gap; fetching it again", &hex(&w)[..12]);
            }
            let got = match fetch_chain(d, link, &addr, (head.commit, seed), &w, floors.get(&w).copied(), held_to, walk).await {
                Ok(got) => got,
                Err(e) => {
                    eprintln!("ns {ns}: writer {}… from <{}>: {e}", &hex(&w)[..12], hex(&peer));
                    continue;
                }
            };
            if walk == Walk::ToCheckpoint {
                searched.insert(w);
            }
            if let Some(cp) = got.checkpoint {
                if let Err(e) = install_checkpoint(d, ns, link, &cp).await {
                    eprintln!("ns {ns}: checkpoint {cp} from <{}>: {e}", hex(&peer));
                    searched.remove(&w);
                    continue;
                }
                let by = if w == addr.writer { "the creator".to_string() } else { format!("grant holder {}…", &hex(&w)[..12]) };
                println!("ns {ns}: starting from the checkpoint of {by}: {cp}");
                seeking = false;
                d.ns_seeking.lock().unwrap().remove(ns);
                floors = checkpoint_floors(d, ns);
                d.ns_wake.notify_one(); // the checkpoint names the other writers: fetch them next
            }
            d.store
                .set_writer_head(&ns_id, &retifs_store::WriterHead { writer: w, head: raw, commit: (head.commit, seed) })
                .map_err(|e| e.to_string())?;
            println!(
                "ns {ns}: writer {}… at version {} from <{}> ({} commit(s) fetched; walk ended {})",
                &hex(&w)[..12],
                head.seq,
                hex(&peer),
                got.commits,
                got.stopped
            );
            changed = true;
        }
    }
    if seeking {
        // Every grant holder known after this round has been searched: no
        // checkpoint to start from, the whole history it is.
        let merged = materialize(d, ns)?;
        let holders: Vec<[u8; 32]> = merged.writers.iter().filter(|(_, r)| r.contains(&Right::Grant)).map(|(w, _)| *w).collect();
        if holders.iter().all(|w| searched.contains(w) || *w == own) && searched.contains(&addr.writer) {
            d.ns_seeking.lock().unwrap().remove(ns);
            println!("ns {ns}: no grant holder has named a checkpoint; using the whole history");
        } else if !searched.is_empty() {
            d.ns_wake.notify_one(); // grant holders learned this round: search their chains next
        }
    }
    if whole {
        // The history is here now (as far as peers had it): check the
        // checkpoint against it, then rebuild from it.
        // (`ns verify` checks on its own and reports the result.)
        if verify && d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?.is_some() {
            match verify_checkpoint(d, ns) {
                Ok((_, detail)) => println!("ns {ns}: {detail}"),
                Err(e) => println!("ns {ns}: checkpoint not verified: {e}"),
            }
        }
        if let Some(e) = ns_entry_get(d, ns) {
            let mut e = e.lock().unwrap();
            e.needs_history = false;
            e.fetch_whole = false;
            e.state = None;
        }
        changed = true;
    }
    if changed && d.store.ns_lazy(ns).map_err(|e| e.to_string())? {
        let n = fill_lazy(d, ns).await?;
        if n > 0 {
            println!("ns {ns}: fetched {n} state node(s) for records changed since the checkpoint");
        }
    }
    if changed {
        let keys_before = d.store.ns_keys(ns).map_err(|e| e.to_string())?.len();
        let merged = materialize(d, ns)?;
        if d.store.ns_keys(ns).map_err(|e| e.to_string())?.len() > keys_before {
            d.ns_wake.notify_one(); // a new read key: newer versions may be readable now
        }
        // Content kept on this device: pulled now, released when no longer kept.
        let records = d.store.records(ns).map_err(|e| e.to_string())?;
        apply_keep(d, ns, &records)?;
        println!("ns {ns}: merged, {} record(s), {} writer(s)", records.len(), merged.writers.len());
    }
    Ok(())
}

/// Writers whose chain held here has a gap: it doesn't reach back to its
/// start or to the checkpoint's frontier (an interrupted fetch, or one by an
/// older version that trusted any held commit). Their next fetch ignores the
/// last head marker and walks back until the gap is filled.
fn chains_with_gaps(d: &Daemon, ns: &str) -> std::collections::HashSet<[u8; 32]> {
    ns_entry_get(d, ns).map(|e| e.lock().unwrap().gaps.clone()).unwrap_or_default()
}

/// Where the local checkpoint's frontier is, per writer: chain walks stop there.
fn checkpoint_floors(d: &Daemon, ns: &str) -> HashMap<[u8; 32], Cid> {
    d.store
        .ns_checkpoint(ns)
        .ok()
        .flatten()
        .and_then(|f| manifest::read_all(&*d.store, &f).ok())
        .and_then(|b| Checkpoint::decode(&b).ok())
        .map(|cp| cp.frontier.iter().map(|f| (f.writer, f.commit)).collect())
        .unwrap_or_default()
}

/// Checks the namespace's checkpoint against its history (ADR-0018):
/// replays every chain up to the checkpoint's frontier and compares the
/// result with the checkpoint, exactly. A checkpoint that doesn't match is
/// dropped and the namespace rebuilt from the history. Needs the history
/// up to the frontier here (`retifs ns verify` fetches it).
fn verify_checkpoint(d: &Daemon, ns: &str) -> Result<(bool, String), String> {
    let Some(file) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else {
        return Ok((true, "no checkpoint here: the state is replayed from the whole history".into()));
    };
    let (creator, _) = d.store.ns_info(ns).map_err(|e| e.to_string())?.ok_or_else(|| format!("no namespace {ns}"))?;
    let cp = manifest::read_all(&*d.store, &file)
        .map_err(|e| e.to_string())
        .and_then(|b| Checkpoint::decode(&b).map_err(|e| e.to_string()))?;
    chains(d, ns, true)?;
    let walked = ns_entry_get(d, ns).map(|e| e.lock().unwrap().chains.clone()).unwrap_or_default();
    let mut upto: std::collections::BTreeMap<[u8; 32], Vec<WriterCommit>> = std::collections::BTreeMap::new();
    let mut problem = None;
    for f in &cp.frontier {
        let short = &hex(&f.writer)[..12];
        let chain = walked.get(&f.writer).map(Vec::as_slice).unwrap_or_default();
        if chain.first().map(|(seq, _, _)| *seq) != Some(1) {
            return Err(format!("writer {short}…'s history isn't all here yet"));
        }
        let Some(at) = chain.iter().position(|(seq, _, _)| *seq == f.seq) else {
            return Err(format!("writer {short}…'s chain here doesn't reach version {}", f.seq));
        };
        if chain[at].1 != f.commit {
            problem = Some("a frontier commit differs from the chain's");
        }
        upto.insert(f.writer, chain[..=at].iter().map(|(_, _, c)| c.clone()).collect());
    }
    let commits: usize = upto.values().map(Vec::len).sum();
    if problem.is_none() {
        problem = cp.check(&*d.store, &creator, &upto, now_ms()).map_err(|e| e.to_string())?;
    }
    match problem {
        None => Ok((true, format!("checkpoint {file} matches the history: {commits} commit(s) replayed"))),
        Some(p) => {
            // Don't use it: rebuild from the history, and make a checkpoint of our own.
            d.store.remove_ns_checkpoint(ns).map_err(|e| e.to_string())?;
            let entry = ns_entry(d, ns);
            let mut e = entry.lock().unwrap();
            e.state = None;
            e.floors.clear();
            Ok((false, format!("checkpoint {file} does NOT match the history ({p}); dropped, rebuilding from the history")))
        }
    }
}

/// How far back a chain walk goes.
#[derive(Clone, Copy, PartialEq)]
enum Walk {
    /// Back to the writer's last head fetched completely (`held_to`), or to
    /// its start. Commits already held are walked through, not trusted: an
    /// interrupted fetch leaves newer commits here without the older ones.
    ToHeld,
    /// Like `ToHeld`, but on the first checkpoint operation found, fetch the
    /// checkpoint and go back only to its frontier for this writer.
    ToCheckpoint,
    /// Through held commits too, to the start (history skipped by a checkpoint).
    Whole,
}

struct ChainFetch {
    commits: usize,
    checkpoint: Option<FileRef>,
    /// Why the walk ended (for the log).
    stopped: String,
}

/// Fetches a writer's commits (and their operations files) back from `last`,
/// as far as `walk` says, never past `floor` (a checkpoint's frontier) or
/// `held_to` (the head last fetched completely: everything before it is here).
/// Kept pinned and served to other members.
#[allow(clippy::too_many_arguments)]
async fn fetch_chain(
    d: &Daemon,
    link: LinkId,
    addr: &ChannelAddr,
    last: (Cid, retifs_core::Seed),
    writer: &[u8; 32],
    mut floor: Option<Cid>,
    held_to: Option<Cid>,
    walk: Walk,
) -> Result<ChainFetch, String> {
    let mut next = Some(last);
    let mut out = ChainFetch { commits: 0, checkpoint: None, stopped: "at the chain's start".into() };
    let mut seq = None;
    while let Some((cid, seed)) = next {
        if walk != Walk::Whole && (Some(cid) == floor || Some(cid) == held_to) {
            let at = if Some(cid) == floor { "checkpoint frontier" } else { "last complete head" };
            out.stopped = format!("at the {at}, below version {}", seq.map_or("?".into(), |s: u64| s.to_string()));
            break;
        }
        let ct = match d.store.fetch(&cid).map_err(|e| e.to_string())? {
            Some(ct) => {
                // Held already, but older commits may not be (an interrupted
                // fetch): walk through it. Still looking for a checkpoint: look
                // at it too (an earlier peer may have lacked the checkpoint file).
                let c = Commit::decode(&open(&cid, &seed, &ct).map_err(|e| e.to_string())?, addr).map_err(|e| e.to_string())?;
                seq = Some(c.seq);
                if manifest::read_all(&*d.store, &c.root).is_ok() && !(walk == Walk::ToCheckpoint && out.checkpoint.is_none()) {
                    next = c.prev;
                    continue;
                }
                ct
            }
            None => {
                let round = seek_round(&d.transport, link, &[(cid, seed)], false, Duration::from_secs(60)).await?;
                round.got.into_iter().next().map(|(_, ct, _)| ct).ok_or("peer lacks a commit of this chain")?
            }
        };
        let commit = Commit::decode(&open(&cid, &seed, &ct).map_err(|e| e.to_string())?, addr).map_err(|e| e.to_string())?;
        if commit.writer != *writer {
            return Err("commit by another writer in this chain".into());
        }
        if manifest::read_all(&*d.store, &commit.root).is_err() {
            fetch_file(&d.transport, &[link], &commit.root, FetchOpts::default(), &mut CacheTier(&d.store))
                .await
                .map_err(|e| e.to_string())?;
        }
        // Keep this writer's history here and pass it on to other members.
        d.store.insert(&cid, &ct, tier::PINNED).map_err(|e| e.to_string())?;
        let mut keep = vec![(cid, ChunkToken::for_seed(&seed))];
        keep.extend(file_chunks(&d.store, &commit.root)?);
        for (c, _) in &keep {
            if let Some(t) = d.store.tier(c).map_err(|e| e.to_string())? {
                d.store.set_tier(c, t | tier::PINNED).map_err(|e| e.to_string())?;
            }
        }
        d.store.register_serving(&keep).map_err(|e| e.to_string())?;
        out.commits += 1;
        if walk == Walk::ToCheckpoint && out.checkpoint.is_none() {
            let ops = manifest::read_all(&*d.store, &commit.root).ok().and_then(|b| OpsFile::decode(&b).ok());
            if let Some(f) = ops.and_then(|o| o.ops.iter().rev().find_map(|op| if let Op::Checkpoint(f) = op { Some(*f) } else { None })) {
                if manifest::read_all(&*d.store, &f).is_err() {
                    fetch_file(&d.transport, &[link], &f, FetchOpts::default(), &mut CacheTier(&d.store))
                        .await
                        .map_err(|e| e.to_string())?;
                }
                let cp = manifest::read_all(&*d.store, &f)
                    .map_err(|e| e.to_string())
                    .and_then(|b| Checkpoint::decode(&b).map_err(|e| format!("bad checkpoint: {e}")))?;
                floor = cp.frontier.iter().find(|x| x.writer == *writer).map(|x| x.commit);
                out.checkpoint = Some(f);
            }
        }
        next = commit.prev;
    }
    Ok(out)
}

/// Takes a fetched checkpoint as this node's starting point: fetches its
/// state tree, checks that it loads, keeps it and resumes from it.
async fn install_checkpoint(d: &Daemon, ns: &str, link: LinkId, file: &FileRef) -> Result<(), String> {
    let (creator, _) = d.store.ns_info(ns).map_err(|e| e.to_string())?.ok_or_else(|| format!("no namespace {ns}"))?;
    let cp = manifest::read_all(&*d.store, file)
        .map_err(|e| e.to_string())
        .and_then(|b| Checkpoint::decode(&b).map_err(|e| e.to_string()))?;
    let lazy = d.store.ns_lazy(ns).map_err(|e| e.to_string())?;
    if let Some(root) = cp.state.filter(|_| !lazy) {
        loop {
            let missing = prolly::missing(&*d.store, &root).map_err(|e| e.to_string())?;
            if missing.is_empty() {
                break;
            }
            let round = seek_round(&d.transport, link, &missing, false, Duration::from_secs(60)).await?;
            if round.got.is_empty() {
                return Err("peer lacks part of the checkpoint's state".into());
            }
            for (i, ct, _) in round.got {
                d.store.insert(&missing[i].0, &ct, tier::PINNED).map_err(|e| e.to_string())?;
            }
        }
    }
    if !lazy {
        cp.load(&*d.store, &creator).map_err(|e| format!("checkpoint doesn't load: {e}"))?;
    }
    let chunks = if lazy { manifest_chunks(&d.store, file)? } else { file_chunks(&d.store, file)? };
    for (c, _) in &chunks {
        if let Some(t) = d.store.tier(c).map_err(|e| e.to_string())? {
            d.store.set_tier(c, t | tier::PINNED).map_err(|e| e.to_string())?;
        }
    }
    d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
    d.store.set_ns_checkpoint(ns, file).map_err(|e| e.to_string())?;
    d.ns_cache.lock().unwrap().remove(ns);
    Ok(())
}

/// Builds the blind index of `ns`'s declared keys and publishes it on the
/// namespace's index channel (ADR-0019), when the checkpoint changed since
/// the last one (or `force`). Returns the search capability, or None if the
/// namespace declares no searchable keys.
async fn publish_index(d: &Daemon, ns: &str, force: bool) -> Result<Option<String>, String> {
    if ns.starts_with("ch-") || d.store.ns_lazy(ns).map_err(|e| e.to_string())? {
        return Ok(None);
    }
    if force {
        ns_entry(d, ns).lock().unwrap().since_checkpoint = CHECKPOINT_EVERY;
        materialize(d, ns)?;
    }
    let Some(checkpoint) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else { return Ok(None) };
    let records = d.store.records(ns).map_err(|e| e.to_string())?;
    let attrs: Vec<(RecordId, Vec<(String, Value)>)> =
        records.iter().map(|r| (r.id, r.attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect())).collect();
    let declared = index::declared_keys(attrs.iter().map(|(_, a)| a.as_slice()));
    if declared.is_empty() {
        return Ok(None);
    }
    let read_key = current_addr(d, ns)?.read_key;
    let key = index::channel_key(&read_key);
    let capability = key.addr().to_string();
    let name = format!("idx:{ns}:{}", hex(&key_id(&read_key)[..4]));
    if !force && d.indexed.lock().unwrap().get(ns) == Some(&checkpoint.root) {
        return Ok(Some(capability));
    }
    let keys = index::IndexKeys::derive(&read_key);
    let search = index::search_secret(&read_key);
    let tree_keys = index::index_keys(&keys, attrs.iter().map(|(id, a)| (*id, a.as_slice())), &declared);
    let entries = tree_keys.len();
    let store = d.store.clone();
    let root = tokio::task::spawn_blocking(move || -> Result<Option<prolly::Root>, String> {
        let root = index::build(&mut retifs_store::PinnedTier(&store), &search, tree_keys).map_err(|e| e.to_string())?;
        if let Some(r) = &root {
            let nodes = prolly::nodes(&*store, r).map_err(|e| e.to_string())?;
            let tokens: Vec<_> = nodes.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
            store.register_serving(&tokens).map_err(|e| e.to_string())?;
        }
        Ok(root)
    })
    .await
    .map_err(|e| e.to_string())??;
    d.store.create_channel(&name, key.signing_seed(), *index::search_secret(&read_key).as_bytes()).map_err(|e| e.to_string())?;
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("OS entropy");
    let desc = index::Descriptor { index: root, state: keys.seal_state(&checkpoint, iv), time_ms: now_ms() };
    publish_channel(d, &name, desc.encode(), false, 0).await?;
    d.indexed.lock().unwrap().insert(ns.to_string(), checkpoint.root);
    println!("ns {ns}: blind index of {} key(s), {entries} entr(ies), published for search nodes", declared.len());
    Ok(Some(capability))
}

/// Fetches the index tree a followed index channel's current version names,
/// from the channel's hints, and serves it on (a search node, ADR-0019).
async fn fetch_index(d: &Daemon, f: &retifs_store::Follow) -> Result<(), String> {
    let Some(cur) = f.current else { return Ok(()) };
    let Ok(bytes) = manifest::read_all(&*d.store, &cur) else { return Ok(()) };
    let Ok(desc) = index::Descriptor::decode(&bytes) else { return Ok(()) };
    let Some(root) = desc.index else { return Ok(()) };
    let mut missing = prolly::missing(&*d.store, &root).map_err(|e| e.to_string())?;
    if missing.is_empty() {
        return Ok(());
    }
    for hint in &f.hints {
        let Ok(link) = d.link_to(hint).await else { continue };
        while !missing.is_empty() {
            let round = seek_round(&d.transport, link, &missing, false, Duration::from_secs(60)).await?;
            if round.got.is_empty() {
                break;
            }
            let mut tokens = Vec::new();
            for (i, ct, _) in round.got {
                d.store.insert(&missing[i].0, &ct, tier::PINNED).map_err(|e| e.to_string())?;
                tokens.push((missing[i].0, ChunkToken::for_seed(&missing[i].1)));
            }
            d.store.register_serving(&tokens).map_err(|e| e.to_string())?;
            missing = prolly::missing(&*d.store, &root).map_err(|e| e.to_string())?;
        }
        if missing.is_empty() {
            let n = prolly::nodes(&*d.store, &root).map(|n| n.len()).unwrap_or(0);
            println!("search: index <{}> complete ({n} node(s)), answering queries", hex(&f.addr.ns_id()));
            return Ok(());
        }
    }
    Err(format!("index <{}>: {} node(s) still missing", hex(&f.addr.ns_id()), missing.len()))
}

/// A member's blind index query against search node `node`: tokens for the
/// `key=value` terms, entries opened and intersected, matches resolved
/// against the records held here and checked against every term.
async fn search_query(d: &Daemon, ns: &str, node: &str, terms: &[String]) -> Result<Response, String> {
    let parsed: Vec<retifs_store::Term> = terms.iter().map(|t| retifs_store::Term::parse(t)).collect::<Result<_, _>>()?;
    let held: HashMap<RecordId, Record> = d.store.records(ns).map_err(|e| e.to_string())?.into_iter().map(|r| (r.id, r)).collect();
    // Where the settings are held here, only declared keys go to the search
    // node; the other terms are checked on the matches here.
    let attrs: Vec<Vec<(String, Value)>> = held.values().map(|r| r.attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).collect();
    let declared = index::declared_keys(attrs.iter().map(|a| a.as_slice()));
    let eq: Vec<(String, Value)> = parsed
        .iter()
        .filter_map(|t| match t {
            retifs_store::Term::Eq(k, v) if declared.is_empty() || index::declared(k, &declared) => Some((k.clone(), v.clone())),
            _ => None,
        })
        .collect();
    if eq.is_empty() || eq.len() > MAX_QUERY_TOKENS {
        return Err(format!(
            "a search needs 1 to {MAX_QUERY_TOKENS} key=value terms on searchable keys{}",
            if declared.is_empty() { String::new() } else { format!(" ({})", declared.join(", ")) }
        ));
    }
    let read_key = current_addr(d, ns)?.read_key;
    let keys = index::IndexKeys::derive(&read_key);
    let search = index::search_secret(&read_key);
    let tokens: Vec<index::Token> = eq.iter().map(|(k, v)| keys.token(k, v)).collect();
    let peer = *parse_destination(node).ok_or_else(|| format!("{node} isn't a node address"))?.as_bytes();
    let link = d.link_to(&peer).await?;
    let proof = index::query_proof(&search, &d.transport.link_nonce(link));
    let mut body = index::channel_key(&read_key).ns_id().to_vec();
    body.extend_from_slice(&proof);
    for t in &tokens {
        body.extend_from_slice(t);
    }
    let answer = d.ask(link, QUERY_ENDPOINT, body).await?;
    let (as_of_ms, _state, lists) =
        parse_search_answer(&answer, tokens.len()).ok_or_else(|| format!("<{node}> doesn't hold this namespace's index"))?;
    let mut ids: Option<std::collections::BTreeSet<RecordId>> = None;
    for (t, entries) in tokens.iter().zip(lists) {
        let these: std::collections::BTreeSet<RecordId> = entries.iter().map(|e| keys.open_entry(t, e)).collect();
        ids = Some(match ids {
            None => these,
            Some(acc) => acc.intersection(&these).copied().collect(),
        });
    }
    let ids = ids.unwrap_or_default();
    let mut held = held;
    if d.store.ns_lazy(ns).map_err(|e| e.to_string())? {
        let missing: Vec<RecordId> = ids.iter().filter(|id| !held.contains_key(*id)).copied().collect();
        if !missing.is_empty() && fetch_paths(d, ns, &missing, &[], false).await? > 0 {
            materialize(d, ns)?;
            held = d.store.records(ns).map_err(|e| e.to_string())?.into_iter().map(|r| (r.id, r)).collect();
        }
    }
    let mut records = Vec::new();
    let mut unresolved = Vec::new();
    for id in ids {
        match held.get(&id) {
            // Checked against every term: the index may be older than what's here.
            Some(r) if parsed.iter().all(|t| t.matches(r)) => records.push(view(r)),
            Some(_) => {}
            None => unresolved.push(hex(&id)),
        }
    }
    Ok(Response::Searched { records, unresolved, as_of_ms })
}

/// A query on a lazily held library, asked of its peers in turn (the first
/// that answers): their blind index for the exact terms, the matches fetched
/// here. None when no peer could answer (no index, unreachable, other terms).
async fn lazy_search(d: &Daemon, ns: &str, terms: &[String]) -> Option<Vec<RecordView>> {
    for peer in d.store.ns_peers(ns).ok()? {
        match search_query(d, ns, &hex(&peer), terms).await {
            Ok(Response::Searched { records, .. }) => return Some(records),
            Ok(_) => {}
            Err(e) => eprintln!("ns {ns}: searching at <{}>: {e}", hex(&peer)),
        }
    }
    None
}

/// Fetches the state tree paths to `ids` from the checkpoint held here, from
/// the namespace's peers (and `extra`): a lazy member's records on demand.
/// Each leaf fetched is complete, so its records merge exactly; the state is
/// reloaded from the checkpoint with them. Returns the nodes fetched.
///
/// `pin`: the paths of records changed since the checkpoint must stay (their
/// merge needs them), so they're pinned, also where already held. Records
/// fetched only to be read go to the cache: evicted under disk pressure,
/// fetched again when asked for.
async fn fetch_paths(d: &Daemon, ns: &str, ids: &[RecordId], extra: &[PeerId], pin: bool) -> Result<usize, String> {
    let Some(file) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else { return Ok(0) };
    let cp = manifest::read_all(&*d.store, &file)
        .map_err(|e| e.to_string())
        .and_then(|b| Checkpoint::decode(&b).map_err(|e| e.to_string()))?;
    let Some(root) = cp.state else { return Ok(0) };
    let mut peers = d.store.ns_peers(ns).map_err(|e| e.to_string())?;
    peers.extend_from_slice(extra);
    let mut pending: Vec<RecordId> = Vec::new();
    for id in ids {
        if prolly::missing_on_path(&*d.store, &root, id).map_err(|e| e.to_string())?.is_some() {
            pending.push(*id);
        }
    }
    let mut fetched = 0;
    for peer in peers {
        if pending.is_empty() {
            break;
        }
        let Ok(link) = d.link_to(&peer).await else { continue };
        // One round per tree level: every pending path's next missing node.
        loop {
            let mut wanted: Vec<(Cid, retifs_core::Seed)> = Vec::new();
            for id in &pending {
                if let Some(n) = prolly::missing_on_path(&*d.store, &root, id).map_err(|e| e.to_string())?
                    && !wanted.contains(&n)
                {
                    wanted.push(n);
                }
            }
            if wanted.is_empty() {
                pending.clear();
                break;
            }
            let round = seek_round(&d.transport, link, &wanted, false, Duration::from_secs(60)).await?;
            if round.got.is_empty() {
                break; // this peer lacks them: the next one
            }
            let mut tokens = Vec::new();
            for (i, ct, _) in round.got {
                d.store.insert(&wanted[i].0, &ct, if pin { tier::PINNED } else { tier::CACHE }).map_err(|e| e.to_string())?;
                tokens.push((wanted[i].0, ChunkToken::for_seed(&wanted[i].1)));
                fetched += 1;
            }
            // Read-only fetches are reading history: never served on (holder privacy rule 2).
            if pin {
                d.store.register_serving(&tokens).map_err(|e| e.to_string())?;
            }
        }
    }
    if pin {
        let mut upgraded = Vec::new();
        for id in ids {
            for (cid, seed) in prolly::path_held(&*d.store, &root, id).map_err(|e| e.to_string())? {
                if let Some(t) = d.store.tier(&cid).map_err(|e| e.to_string())?
                    && t & tier::PINNED == 0
                {
                    d.store.set_tier(&cid, t | tier::PINNED).map_err(|e| e.to_string())?;
                    upgraded.push((cid, ChunkToken::for_seed(&seed)));
                }
            }
        }
        d.store.register_serving(&upgraded).map_err(|e| e.to_string())?;
    }
    if fetched > 0 {
        // Reload: the records of the new leaves come from the checkpoint,
        // then every commit since applies on top.
        if let Some(e) = ns_entry_get(d, ns) {
            e.lock().unwrap().state = None;
        }
    }
    Ok(fetched)
}

/// A lazy member's sync: the records changed since the checkpoint need their
/// checkpoint entries to merge exactly, so their paths are fetched first.
async fn fill_lazy(d: &Daemon, ns: &str) -> Result<usize, String> {
    let Some(file) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else { return Ok(0) };
    let Ok(cp) = manifest::read_all(&*d.store, &file).map_err(|e| e.to_string()).and_then(|b| Checkpoint::decode(&b).map_err(|e| e.to_string())) else {
        return Ok(0);
    };
    let frontier: HashMap<[u8; 32], u64> = cp.frontier.iter().map(|f| (f.writer, f.seq)).collect();
    let (_, _, chains) = chains(d, ns, false)?;
    let mut ids: std::collections::BTreeSet<RecordId> = std::collections::BTreeSet::new();
    for (w, chain) in &chains {
        let after = frontier.get(w).copied().unwrap_or(0);
        for (_, c) in chain.iter().filter(|(seq, _)| *seq > after) {
            for op in &c.ops {
                match op {
                    Op::Set(id, ..) | Op::Unset(id, _) | Op::Blocks(id, _) | Op::Delete(id) => {
                        ids.insert(*id);
                    }
                    _ => {}
                }
            }
        }
    }
    fetch_paths(d, ns, &ids.into_iter().collect::<Vec<_>>(), &[], true).await
}

/// Whether this node's own chain in `ns` is not all here: a storage-less
/// node's, after a restart (its head is in the keyring, its commits
/// elsewhere). Merged without it, the namespace would lack this node's own
/// operations, and write them again on every round.
fn own_chain_missing(d: &Daemon, ns: &str) -> bool {
    if !d.no_storage {
        return false;
    }
    let Some(c) = d.store.own_channel(&ns_channel(ns)).ok().flatten() else { return false };
    let Some((last, _)) = c.last else { return false };
    if d.store.fetch(&last).ok().flatten().is_none() {
        return true;
    }
    let own = channel_key(d, &c).writer();
    chains(d, ns, false).is_ok() && ns_entry_get(d, ns).is_some_and(|e| e.lock().unwrap().gaps.contains(&own))
}

/// Fetches a storage-less node's own chain in `ns` back from the nodes
/// holding its files (ADR-0031): its commits went there with the operations
/// files, and its latest checkpoint with its state. The walk stops at that
/// checkpoint's frontier; a library made here then starts from it.
async fn restore_own(d: &Daemon, ns: &str) -> Result<(), String> {
    let Some(c) = d.store.own_channel(&ns_channel(ns)).map_err(|e| e.to_string())? else { return Ok(()) };
    let Some(last) = c.last else { return Ok(()) };
    let own = channel_key(d, &c).writer();
    let addr = current_addr(d, ns)?;
    let mut holders: Vec<PeerId> = Vec::new();
    for o in d.store.own_leases().map_err(|e| e.to_string())? {
        if !holders.contains(&o.holder) {
            holders.push(o.holder);
        }
    }
    if holders.is_empty() {
        return Err("no node is known to hold this node's files".into());
    }
    let seeking = d.ns_seeking.lock().unwrap().contains(ns) && d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?.is_none();
    let walk = if seeking && own == addr.writer { Walk::ToCheckpoint } else { Walk::ToHeld };
    let mut last_err = String::new();
    for h in holders {
        let link = match d.link_to(&h).await {
            Ok(l) => l,
            Err(e) => {
                last_err = format!("<{}>: {e}", hex(&h));
                continue;
            }
        };
        let got = match fetch_chain(d, link, &addr, last, &own, None, None, walk).await {
            Ok(got) => got,
            Err(e) => {
                last_err = format!("<{}>: {e}", hex(&h));
                continue;
            }
        };
        if let Some(cp) = got.checkpoint {
            install_checkpoint(d, ns, link, &cp).await?;
            // Named by this node already: not named again.
            d.store.set_ns_checkpoint_published(ns, &cp.root).map_err(|e| e.to_string())?;
            println!("ns {ns}: own chain back from <{}> ({} commit(s)), starting from its checkpoint {cp}", hex(&h), got.commits);
        } else {
            println!("ns {ns}: own chain back from <{}> ({} commit(s), {})", hex(&h), got.commits, got.stopped);
        }
        d.ns_seeking.lock().unwrap().remove(ns);
        if let Some(e) = ns_entry_get(d, ns) {
            let mut e = e.lock().unwrap();
            e.state = None;
            e.gaps.remove(&own);
        }
        let merged = materialize(d, ns)?;
        println!("ns {ns}: merged, {} record(s), {} writer(s)", d.store.records(ns).map_err(|e| e.to_string())?.len(), merged.writers.len());
        d.ns_wake.notify_one();
        return Ok(());
    }
    Err(format!("no holder gave it back yet ({last_err})"))
}

/// Names this node's latest checkpoint in its chain, if it holds `grant`
/// and hasn't named this one yet (ADR-0018). The checkpoint file (with its
/// state tree) is then needed and placed like the history.
async fn publish_checkpoint(d: &Daemon, ns: &str) -> Result<(), String> {
    if ns.starts_with("ch-") || d.store.ns_lazy(ns).map_err(|e| e.to_string())? {
        return Ok(());
    }
    let Some(file) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else { return Ok(()) };
    let published = d.store.ns_checkpoint_published(ns).map_err(|e| e.to_string())?;
    if published == Some(file.root) || d.store.own_channel(&ns_channel(ns)).map_err(|e| e.to_string())?.is_none() {
        return Ok(());
    }
    let merged = materialize(d, ns)?;
    let (_, own, _) = chains(d, ns, false)?;
    if !merged.writers.get(&own).is_some_and(|r| r.contains(&Right::Grant)) {
        return Ok(());
    }
    if let Some(old) = published.and_then(|root| d.store.needed_files().ok()?.into_iter().find(|f| f.root == root)) {
        d.store.unneed_file(&old.root).map_err(|e| e.to_string())?;
    }
    d.store.need_file(&file).map_err(|e| e.to_string())?;
    d.store.set_ns_checkpoint_published(ns, &file.root).map_err(|e| e.to_string())?;
    write_ops(d, ns, vec![Op::Checkpoint(file)]).await?;
    println!("ns {ns}: checkpoint {file} named in this node's chain");
    Ok(())
}

/// Reads `range` of `file`, fetching what it needs and isn't here: only the
/// chunks the range covers (and the manifest nodes above them), from the
/// namespace's peers and the file's hinted holders, in rounds (each round's
/// nodes reveal the next level). Gives up at `wait` instead of hanging, and
/// at once when no peer is reachable; a peer over a slow link is used only if
/// the transfer fits the slow-link budget (ADR-0013). Fetched chunks go to
/// the cache tier: evictable, never served to others.
async fn read_range_fetching(d: &Daemon, file: &FileRef, range: std::ops::Range<u64>, ns: Option<&str>, wait: Duration) -> Result<Vec<u8>, String> {
    ensure_local(d, file, range.clone(), ns, wait).await?;
    manifest::read_range(&*d.store, file, range).map_err(|e| e.to_string())
}

/// Makes sure every chunk `range` of `file` needs is here (see
/// [`read_range_fetching`]) without reading it.
async fn ensure_local(d: &Daemon, file: &FileRef, range: std::ops::Range<u64>, ns: Option<&str>, wait: Duration) -> Result<(), String> {
    let deadline = Instant::now() + wait;
    let mut peers: Vec<PeerId> = match ns {
        Some(ns) => d.store.ns_peers(ns).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    for h in d.store.hints(&file.root).unwrap_or_default() {
        if !peers.contains(&h.peer) {
            peers.push(h.peer);
        }
    }
    // This node's own file: the nodes holding it for this node (a
    // storage-less node's only copies).
    for o in d.store.own_leases_for(&file.root).unwrap_or_default() {
        if !peers.contains(&o.holder) {
            peers.push(o.holder);
        }
    }
    loop {
        let missing = manifest::missing_for_range(&*d.store, file, range.clone()).map_err(|e| e.to_string())?;
        if missing.is_empty() {
            return Ok(());
        }
        if peers.is_empty() {
            return Err(format!("{}: not here, and no peer known to ask", file.root));
        }
        let mut progressed = false;
        let mut too_slow = false;
        for peer in &peers {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let q = d.quality(peer);
            // Chunks are at most 256 KiB; most are far smaller. A rough upper bound.
            if q.slow() && q.transfer_secs(missing.len() as u64 * 64 * 1024) > d.slow_budget as f64 {
                too_slow = true;
                continue;
            }
            let link = match tokio::time::timeout(left, d.link_to(peer)).await {
                Ok(Ok(l)) => l,
                _ => continue,
            };
            let t0 = Instant::now();
            let round = match seek_round(&d.transport, link, &missing, d.private_requests, left).await {
                Ok(r) => r,
                Err(_) => {
                    d.drop_link(peer);
                    continue;
                }
            };
            let bytes: u64 = round.got.iter().map(|(_, ct, _)| ct.len() as u64).sum();
            let _ = d.store.record_transfer(peer, bytes, t0.elapsed().as_millis() as u64);
            for (i, ct, _) in round.got {
                d.store.insert(&missing[i].0, &ct, tier::CACHE).map_err(|e| e.to_string())?;
                progressed = true;
            }
            if progressed {
                break; // look again: fetched nodes may reveal more chunks
            }
        }
        // Nobody has it yet (a member may still be pulling it from its
        // writer): look again within the wait, as the mount promises.
        if !progressed && !too_slow && Instant::now() + Duration::from_secs(2) < deadline {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        if !progressed {
            return Err(if Instant::now() >= deadline {
                format!("{}: timed out fetching {} chunk(s)", file.root, missing.len())
            } else if too_slow {
                format!("{}: only reachable over a slow link, and this read doesn't fit its budget", file.root)
            } else {
                format!("{}: no reachable peer has the {} chunk(s) this read needs", file.root, missing.len())
            });
        }
    }
}

/// Followed channels' namespaces belong to their writer.
fn writable(ns: &str) -> Result<(), String> {
    if ns.starts_with("ch-") {
        return Err(format!("{ns} is a followed channel's namespace: read-only here"));
    }
    Ok(())
}

/// The channel a namespace's own writes go to (separate from channels that
/// publish snapshots, like `channel publish-ns`).
fn ns_channel(ns: &str) -> String {
    format!("ns:{ns}")
}

/// The namespace's identity (creator, read key); created on first write, with
/// this node as its creator (ADR-0017).
fn ensure_namespace(d: &Daemon, ns: &str) -> Result<ChannelAddr, String> {
    if let Some((creator, read_key)) = d.store.ns_info(ns).map_err(|e| e.to_string())? {
        return Ok(ChannelAddr { writer: creator, read_key });
    }
    // The creator's writer identity (X25519 ‖ Ed25519) and the first read key.
    let mut identity = [0u8; 64];
    let mut read_key = [0u8; 32];
    getrandom::fill(&mut identity).expect("OS entropy");
    getrandom::fill(&mut read_key).expect("OS entropy");
    let seed: [u8; 32] = identity[32..].try_into().unwrap();
    d.store.create_channel(&ns_channel(ns), seed, read_key).map_err(|e| e.to_string())?;
    let creator = ChannelKey::from_secrets(seed, read_key).writer();
    d.store.set_ns_identity(ns, &identity).map_err(|e| e.to_string())?;
    d.store.set_ns_info(ns, &creator, &read_key).map_err(|e| e.to_string())?;
    Ok(ChannelAddr { writer: creator, read_key })
}

/// The namespace's address with its newest read key known here.
fn current_addr(d: &Daemon, ns: &str) -> Result<ChannelAddr, String> {
    let (creator, _) = d.store.ns_info(ns).map_err(|e| e.to_string())?.ok_or_else(|| format!("no namespace {ns}"))?;
    let keys = d.store.ns_keys(ns).map_err(|e| e.to_string())?;
    Ok(ChannelAddr { writer: creator, read_key: *keys.last().expect("a namespace has a key") })
}

/// Makes `key` this node's current read key for the namespace: later commits
/// and heads are encrypted with it.
fn use_key(d: &Daemon, ns: &str, key: &[u8; 32]) -> Result<(), String> {
    d.store.add_ns_key(ns, key).map_err(|e| e.to_string())?;
    if let Some(mut c) = d.store.own_channel(&ns_channel(ns)).map_err(|e| e.to_string())?
        && c.read_key != *key
    {
        c.read_key = *key;
        d.store.update_own_channel(&c).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The signing key of an own channel: its own namespace, or a member's key
/// writing to another's (ADR-0017).
fn channel_key(d: &Daemon, c: &retifs_store::OwnChannel) -> ChannelKey {
    channel_key_in(&d.store, c)
}

fn channel_key_in(store: &SlabStore, c: &retifs_store::OwnChannel) -> ChannelKey {
    match store.member_channel(&c.name).ok().flatten() {
        Some(ns_id) => ChannelKey::member(c.signing_seed, c.read_key, ns_id),
        None => ChannelKey::from_secrets(c.signing_seed, c.read_key),
    }
}

/// Stores a write session's content and commits it (with `attrs`) as one
/// version. The base content the new one keeps is fetched first if it isn't
/// here; then the content is streamed into the store, never whole in memory.
async fn commit_session(d: &Daemon, s: &WriteSession, attrs: Vec<(String, AttrValue)>) -> Result<Vec<RecordView>, String> {
    let pieces = s.pieces(0..s.size);
    if let Some(base) = &s.base {
        for (range, piece) in &pieces {
            if *piece == Piece::Base {
                ensure_local(d, base, range.clone(), Some(&s.ns), Duration::from_secs(120)).await?;
            }
        }
    }
    let reader = SessionReader { pieces: pieces.into(), spool: s.spool.try_clone().map_err(|e| e.to_string())?, base: s.base, store: d.store.clone() };
    let store = d.store.clone();
    let record = format!("retifs-record/{}/{}", s.ns, hex(&s.id));
    let file = tokio::task::spawn_blocking(move || -> Result<FileRef, String> {
        let secret = secret(&store, false, Some(&record));
        let opts = manifest::WriteOpts { stable_padding: true, ..Default::default() };
        let mut pinned = retifs_store::TrackedPinned::new(&store);
        let (file, blobs) = match manifest::write_reader(&mut pinned, &secret, reader, opts)
            .map_err(|e| e.to_string())
            .and_then(|w| pinned.flush().map(|_| w).map_err(|e| e.to_string()))
        {
            Ok(w) => w,
            Err(e) => {
                let _ = pinned.roll_back();
                return Err(e);
            }
        };
        let tokens: Vec<_> = blobs.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
        store.register_serving(&tokens).map_err(|e| e.to_string())?;
        Ok(file)
    })
    .await
    .map_err(|e| e.to_string())??;
    d.store.need_file(&file).map_err(|e| e.to_string())?;
    d.upkeep_wake.notify_one();
    transaction(d, &s.ns, vec![TxStep::Set { id: hex(&s.id), attrs, unset: Vec::new(), data: None, blocks: Some(vec![file.to_string()]) }]).await
}

/// Stores content for record `id` under the record's own secret (its
/// versions dedup against each other) and keeps it placed.
async fn store_content(d: &Daemon, ns: &str, id: &RecordId, data: Vec<u8>) -> Result<FileRef, String> {
    let store = d.store.clone();
    let secret_name = format!("retifs-record/{ns}/{}", hex(id));
    let file = tokio::task::spawn_blocking(move || store_file(&store, &data, false, false, Some(&secret_name), manifest::WriteOpts::default()))
        .await
        .map_err(|e| e.to_string())??;
    d.store.need_file(&file).map_err(|e| e.to_string())?;
    d.upkeep_wake.notify_one();
    Ok(file)
}

/// Applies `steps` as one commit (one version, ADR-0006): content is stored
/// first, then every step's operations are written together, so other
/// members see all of them or none. Returns the created and changed records,
/// in step order. Content replaced or deleted stops being kept elsewhere
/// (earlier versions stay here as history).
async fn transaction(d: &Daemon, ns: &str, steps: Vec<TxStep>) -> Result<Vec<RecordView>, String> {
    writable(ns)?;
    if steps.is_empty() {
        return Err("an empty transaction".into());
    }
    let mut ops = Vec::new();
    let mut touched: Vec<RecordId> = Vec::new();
    let mut replaced: Vec<FileRef> = Vec::new();
    let mut deleted: Vec<FileRef> = Vec::new();
    let mut seen: std::collections::HashSet<RecordId> = std::collections::HashSet::new();
    for step in steps {
        let (id, attrs, unset, data) = match step {
            TxStep::Create { attrs, data } => {
                let mut id: RecordId = [0; 16];
                getrandom::fill(&mut id).expect("OS entropy");
                (id, attrs, Vec::new(), data)
            }
            TxStep::Set { id, attrs, unset, data, blocks } => {
                let id = parse_record_id(&id)?;
                if !seen.contains(&id) {
                    let before = d.store.get_record(ns, &id).map_err(|e| e.to_string())?.ok_or_else(|| format!("no such record {}", hex(&id)))?;
                    if data.is_some() || blocks.is_some() {
                        replaced.extend(before.blocks);
                    }
                }
                if let Some(caps) = blocks {
                    let refs: Vec<FileRef> = caps
                        .iter()
                        .map(|c| c.parse().map_err(|e: retifs_core::ManifestError| e.to_string()))
                        .collect::<Result<_, _>>()?;
                    if !attrs.iter().any(|(k, _)| k == "size") {
                        ops.push(Op::Set(id, "size".into(), Value::Int(refs.iter().map(|f| f.size).sum::<u64>() as i64)));
                    }
                    for f in &refs {
                        d.store.need_file(f).map_err(|e| e.to_string())?;
                    }
                    ops.push(Op::Blocks(id, refs));
                }
                (id, attrs, unset, data)
            }
            TxStep::Delete { id } => {
                let id = parse_record_id(&id)?;
                if let Some(rec) = d.store.get_record(ns, &id).map_err(|e| e.to_string())? {
                    deleted.extend(rec.blocks);
                } else if !seen.contains(&id) {
                    return Err(format!("no such record {}", hex(&id)));
                }
                ops.push(Op::Delete(id));
                touched.retain(|t| *t != id);
                continue;
            }
        };
        seen.insert(id);
        ops.extend(unset.into_iter().map(|k| Op::Unset(id, k)));
        let has_size = attrs.iter().any(|(k, _)| k == "size");
        for (k, v) in attrs {
            ops.push(Op::Set(id, k, to_value(&v)?));
        }
        if let Some(data) = data {
            if !has_size {
                ops.push(Op::Set(id, "size".into(), Value::Int(data.len() as i64)));
            }
            ops.push(Op::Blocks(id, vec![store_content(d, ns, &id, data).await?]));
        }
        if !touched.contains(&id) {
            touched.push(id);
        }
    }
    write_ops(d, ns, ops).await?;
    // Content no record uses any more: no longer kept elsewhere; deleted
    // records' content also becomes evictable here.
    // (Reads every record of every namespace: only when something was replaced
    // or deleted. An import of new records skipped it after the scale test
    // found every write getting slower with the namespace's size.)
    let still_used: std::collections::HashSet<Cid> = if replaced.is_empty() && deleted.is_empty() {
        Default::default()
    } else {
        d.store
            .namespaces()
            .map_err(|e| e.to_string())?
            .iter()
            .flat_map(|n| d.store.records(n).unwrap_or_default())
            .flat_map(|r| r.blocks.into_iter().map(|b| b.root))
            .collect()
    };
    for old in replaced.iter().filter(|b| !still_used.contains(&b.root)) {
        d.store.unneed_file(&old.root).map_err(|e| e.to_string())?;
    }
    let gone: Vec<FileRef> = deleted.iter().filter(|b| !still_used.contains(&b.root)).cloned().collect();
    forget_all(d, &gone)?;
    let mut out = Vec::new();
    for id in touched {
        let rec = d.store.get_record(ns, &id).map_err(|e| e.to_string())?.ok_or("record not visible after writing")?;
        out.push(view(&rec));
    }
    Ok(out)
}

/// One modification of a namespace (ADR-0006, ADR-0017): its operations are
/// committed to this node's writer chain, then the namespace is rebuilt by
/// merging every writer chain held here.
async fn write_ops(d: &Daemon, ns: &str, mut ops: Vec<Op>) -> Result<u64, String> {
    // A storage-less node writes on top of its own chain: back first.
    if own_chain_missing(d, ns) {
        restore_own(d, ns).await.map_err(|e| format!("{ns}: this node's own changes aren't back yet after the restart: {e}"))?;
    }
    let new = d.store.ns_info(ns).map_err(|e| e.to_string())?.is_none();
    ensure_namespace(d, ns)?;
    if new && let Some(identity) = d.store.ns_identity(ns).map_err(|e| e.to_string())? {
        ops.insert(0, Op::Identity(keywrap::public(&identity)));
        ops.insert(1, Op::Node(own_node(d)?));
    }
    // A hybrid logical clock (ADR-0017): a commit is never stamped before one
    // already merged here. Otherwise a writer whose clock is behind the granter's
    // would stamp its first writes before its own grant, and every reader
    // would ignore them.
    let not_before = if new {
        0
    } else {
        let merged = materialize(d, ns)?;
        // Writes before this node's grant has arrived would never count (they'd
        // be stamped before it): refuse them clearly instead of losing them.
        let (_, own, _) = chains(d, ns, false)?;
        let writes_data = ops.iter().any(|op| matches!(op, Op::Set(..) | Op::Unset(..) | Op::Blocks(..) | Op::Delete(_)));
        if writes_data && !merged.writers.get(&own).is_some_and(|r| r.contains(&Right::Write)) {
            return Err(format!(
                "this node may not write to {ns} yet: its grant hasn't reached it (writer {}…; try again after the next sync)",
                &hex(&own)[..12]
            ));
        }
        ns_entry_get(d, ns).and_then(|e| e.lock().unwrap().applied.values().map(|(_, t, _)| t + 1).max()).unwrap_or(0)
    };
    // Only a change to keep tags or rules, or a deletion, can change what's
    // kept: own new content is kept anyway (deciding it read every record on
    // each write; the scale test's import got slower with every record).
    let keep_may_change = ops.iter().any(|op| match op {
        Op::Set(_, k, v) => k == "keep" || k.starts_with("keep:") || (k == "type" && *v == Value::Str("keep-rule".into())) || k == "query" || k == "device",
        Op::Unset(_, k) => k == "keep" || k.starts_with("keep:") || k == "query" || k == "device",
        Op::Delete(_) => true,
        _ => false,
    });
    let (seq, _) = publish_channel(d, &ns_channel(ns), OpsFile { ops }.encode(), false, not_before).await?;
    materialize(d, ns)?;
    if keep_may_change {
        apply_keep(d, ns, &d.store.records(ns).map_err(|e| e.to_string())?)?;
    }
    Ok(seq)
}

/// Whether this device keeps `r`'s content (ADR-0005): its `keep` or
/// `keep:<device>` attribute is true, or a keep rule for this device (or for
/// every device) matches it; in `all` mode, every record.
fn kept(r: &Record, device: &str, all: bool, rules: &[Vec<retifs_store::Term>]) -> bool {
    let tagged = |k: &str| matches!(r.attrs.get(k), Some(Value::Bool(true)));
    all || tagged("keep") || tagged(&format!("keep:{device}")) || rules.iter().any(|terms| terms.iter().all(|t| t.matches(r)))
}

/// The keep rules of a namespace that apply to this device: records with
/// `type = "keep-rule"`, a `query` of comma-separated terms (as `retifs query`
/// takes them) and an optional `device`.
fn keep_rules(records: &[Record], device: &str) -> Vec<Vec<retifs_store::Term>> {
    let s = |r: &Record, k: &str| match r.attrs.get(k) {
        Some(Value::Str(v)) => Some(v.clone()),
        _ => None,
    };
    records
        .iter()
        .filter(|r| s(r, "type").as_deref() == Some("keep-rule"))
        .filter(|r| s(r, "device").is_none_or(|d| d.eq_ignore_ascii_case(device)))
        .filter_map(|r| {
            let q = s(r, "query")?;
            let terms: Vec<_> = q.split(',').map(str::trim).filter(|t| !t.is_empty()).map(retifs_store::Term::parse).collect::<Result<_, _>>().ok()?;
            (!terms.is_empty()).then_some(terms)
        })
        .collect()
}

/// A share's definition (ADR-0021), from its record in the source namespace.
struct ShareDef {
    addr: ChannelAddr,
    terms: Vec<retifs_store::Term>,
    ids: Vec<RecordId>,
    omit: Vec<String>,
}

fn share_def(r: &Record) -> Option<ShareDef> {
    let strs = |k: &str| match r.attrs.get(k) {
        Some(Value::List(items)) => items.iter().filter_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).collect(),
        _ => Vec::new(),
    };
    let addr = match r.attrs.get("share") {
        Some(Value::Str(a)) => a.parse().ok()?,
        _ => return None,
    };
    let terms = match r.attrs.get("select") {
        Some(Value::Str(q)) => q.split(',').map(str::trim).filter(|t| !t.is_empty()).map(retifs_store::Term::parse).collect::<Result<_, _>>().ok()?,
        _ => Vec::new(),
    };
    let ids: Vec<RecordId> = strs("ids").iter().filter_map(|i| parse_record_id(i).ok()).collect();
    (!terms.is_empty() || !ids.is_empty()).then_some(ShareDef { addr, terms, ids, omit: strs("omit") })
}

/// Brings a share up to date with its source (ADR-0021): every selected
/// record copied (attributes but the omitted ones, content by reference)
/// under its derived ID, changed copies changed, copies no longer selected
/// deleted, in one commit. Does nothing on a node that doesn't hold the
/// share namespace or may not write to it yet. Returns how many records
/// changed.
async fn sync_share(d: &Daemon, source: &str, def: &Record) -> Result<usize, String> {
    let Some(sd) = share_def(def) else { return Ok(0) };
    let mut target = None;
    for ns in d.store.ns_names().map_err(|e| e.to_string())? {
        if d.store.ns_info(&ns).map_err(|e| e.to_string())?.is_some_and(|(creator, _)| creator == sd.addr.writer) {
            target = Some(ns);
        }
    }
    let Some(target) = target else { return Ok(0) };
    let ns_id = sd.addr.ns_id();
    let skip = |r: &Record| matches!(r.attrs.get("type"), Some(Value::Str(t)) if t == share::DEFINITION_TYPE || t == "keep-rule");
    let selected: Vec<Record> = if sd.ids.is_empty() {
        d.store.query(source, &sd.terms).map_err(|e| e.to_string())?
    } else {
        sd.ids.iter().filter_map(|id| d.store.get_record(source, id).ok().flatten()).collect()
    };
    let mut want: HashMap<RecordId, (std::collections::BTreeMap<String, Value>, Vec<FileRef>)> = HashMap::new();
    for r in selected.iter().filter(|r| !skip(r)) {
        want.insert(share::record_id(&r.id, &ns_id), (share::copy_attrs(&r.attrs, &sd.omit), r.blocks.clone()));
    }
    let have: HashMap<RecordId, Record> = d.store.records(&target).map_err(|e| e.to_string())?.into_iter().map(|r| (r.id, r)).collect();
    let mut ops = Vec::new();
    let mut changed = 0;
    for (id, (attrs, blocks)) in &want {
        let before = have.get(id);
        let n = ops.len();
        if let Some(b) = before {
            ops.extend(b.attrs.keys().filter(|k| !attrs.contains_key(*k)).map(|k| Op::Unset(*id, k.clone())));
        }
        for (k, v) in attrs {
            if before.and_then(|b| b.attrs.get(k)) != Some(v) {
                ops.push(Op::Set(*id, k.clone(), v.clone()));
            }
        }
        let roots = |bs: &[FileRef]| bs.iter().map(|b| b.root).collect::<Vec<_>>();
        if !blocks.is_empty() && before.is_none_or(|b| roots(&b.blocks) != roots(blocks)) {
            ops.push(Op::Blocks(*id, blocks.clone()));
        }
        changed += usize::from(ops.len() > n);
    }
    for id in have.keys().filter(|id| !want.contains_key(*id)) {
        ops.push(Op::Delete(*id));
        changed += 1;
    }
    if ops.is_empty() {
        return Ok(0);
    }
    match write_ops(d, &target, ops).await {
        Ok(_) => Ok(changed),
        // Another owner node's share, its grant not here yet: next time.
        Err(e) if e.contains("may not write") => Ok(0),
        Err(e) => Err(e),
    }
}

/// Keeps every share whose source changed here up to date (ADR-0021), and
/// all of them once a minute (for shares whose namespace or grant arrived
/// later).
async fn share_keeper(d: Arc<Daemon>) {
    let mut seen: HashMap<String, u64> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    let def_term = retifs_store::Term::parse(&format!("type={}", share::DEFINITION_TYPE)).expect("a valid term");
    loop {
        tokio::select! {
            _ = d.changed.notified() => {}
            _ = tick.tick() => seen.clear(),
        }
        // A burst of writes (an import) is one update.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let counts = d.changes.lock().unwrap().clone();
        for ns in d.store.ns_names().unwrap_or_default() {
            let count = counts.get(&ns).copied().unwrap_or(0);
            if seen.insert(ns.clone(), count) == Some(count) {
                continue;
            }
            for def in d.store.query(&ns, std::slice::from_ref(&def_term)).unwrap_or_default() {
                match sync_share(&d, &ns, &def).await {
                    Ok(0) => {}
                    Ok(n) => eprintln!("share of {ns}: {n} record(s) updated"),
                    Err(e) => eprintln!("share of {ns}: {e}"),
                }
            }
        }
    }
}

/// Content kept here for a namespace is served to its members, like the
/// namespace's commits and operations: a member whose only peer is another
/// member gets content a third member wrote through it (the four-node soak:
/// reads of RTR-2's files failed on rtr-4, whose only peer was cafa-cloud,
/// which held them but wouldn't serve them). Requests still prove the
/// content's seed, which only members have; the cache tier (reading
/// history) stays unserved.
fn serve_if_kept(d: &Daemon, file: &FileRef) -> Result<(), String> {
    let kept = d
        .store
        .ns_names()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|ns| d.store.ns_kept(ns).map(|k| k.iter().any(|f| f.root == file.root)).unwrap_or(false));
    if kept {
        let chunks = file_chunks(&d.store, file)?;
        d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Pulls the content of the records this device keeps and pins it; content it
/// pulled for records no longer kept (or for replaced versions) becomes
/// evictable again. Content this node wrote is never released here.
fn apply_keep(d: &Daemon, ns: &str, records: &[Record]) -> Result<(), String> {
    // Followed channels keep by version; a storage-less node keeps nothing.
    if ns.starts_with("ch-") || d.no_storage {
        return Ok(());
    }
    let all = !d.store.ns_keep_by_rules(ns).map_err(|e| e.to_string())?;
    let rules = keep_rules(records, &d.device);
    let peers = d.store.ns_peers(ns).map_err(|e| e.to_string())?;
    let mut keep: std::collections::HashSet<Cid> = std::collections::HashSet::new();
    let mut already: std::collections::HashSet<Cid> = d.store.ns_kept(ns).map_err(|e| e.to_string())?.iter().map(|f| f.root).collect();
    let mut pulled = 0;
    for r in records.iter().filter(|r| kept(r, &d.device, all, &rules)) {
        for b in &r.blocks {
            keep.insert(b.root);
            if !already.insert(b.root) {
                continue; // already kept
            }
            if d.store.is_needed(&b.root).map_err(|e| e.to_string())? && !d.store.is_wanted(&b.root).unwrap_or(false) {
                continue; // this node's own content (or kept for another reason): not ours to release
            }
            d.store.set_ns_kept(ns, b, true).map_err(|e| e.to_string())?;
            pulled += 1;
            if complete(&d.store, b) {
                // Already here (read before, so in the cache tier): pin it.
                for (c, _) in file_chunks(&d.store, b)? {
                    if let Some(t) = d.store.tier(&c).map_err(|e| e.to_string())? {
                        d.store.set_tier(&c, (t & !tier::CACHE) | tier::PINNED).map_err(|e| e.to_string())?;
                    }
                }
                d.store.need_file(b).map_err(|e| e.to_string())?;
                serve_if_kept(d, b)?;
            } else if !d.store.is_wanted(&b.root).unwrap_or(false) {
                d.store.want_file(b, &peers).map_err(|e| e.to_string())?;
                d.wake.notify_one();
            }
        }
    }
    let dropped: Vec<FileRef> = d.store.ns_kept(ns).map_err(|e| e.to_string())?.into_iter().filter(|f| !keep.contains(&f.root)).collect();
    forget_all(d, &dropped)?;
    for f in &dropped {
        d.store.set_ns_kept(ns, f, false).map_err(|e| e.to_string())?;
    }
    let released = dropped.len();
    if pulled > 0 || released > 0 {
        let how = if all { "everything".to_string() } else { format!("by tags and {} rule(s) for {}", rules.len(), d.device) };
        println!("ns {ns}: keeping {how}: {pulled} file(s) newly kept, {released} no longer kept");
    }
    Ok(())
}

/// One walked commit of a writer chain.
type Walked = (u64, Cid, WriterCommit);
/// A commit chunk by CID and seed.
type CommitRef = (Cid, retifs_core::Seed);

/// What's been walked and merged per namespace, so a write only reads the
/// new commits and writes the records that changed (chains are append-only).
#[derive(Default)]
struct NsCache {
    chains: HashMap<[u8; 32], Vec<Walked>>,
    /// The store's record view matches the state (else it's rewritten whole).
    view_built: bool,
    /// The merged state as a CRDT, and how far each writer's chain is applied
    /// (sequence number, commit time, commit): new commits apply one by one.
    state: Option<State>,
    applied: HashMap<[u8; 32], (u64, u64, Cid)>,
    /// Resumed from a checkpoint: chains are walked back only to these
    /// commits (the history before them is read only when a rebuild needs it).
    floors: HashMap<[u8; 32], Cid>,
    /// Commits applied since the last checkpoint.
    since_checkpoint: usize,
    /// A rebuild needs history a checkpoint let this node skip: the state
    /// stays as it was until sync has fetched it.
    needs_history: bool,
    /// Fetch every chain whole on the next sync (to verify the checkpoint).
    fetch_whole: bool,
    /// Writers whose chain here has a missing commit below its head.
    gaps: std::collections::HashSet<[u8; 32]>,
}

/// A checkpoint is written after this many new commits (ADR-0018).
const CHECKPOINT_EVERY: usize = 64;

/// A writer's chain, oldest first, as far back as its commits and operations
/// files are local. Only commits newer than `cached` are read from the store.
/// The second value says whether the walk is complete (reached the chain's
/// start, the checkpoint or the cached part). An incomplete one is only what's
/// contiguous to the head: a commit below it is missing here.
fn walk_ops_chain(
    d: &Daemon,
    addr: &ChannelAddr,
    last: Option<(Cid, retifs_core::Seed)>,
    cached: &[Walked],
    floor: Option<Cid>,
) -> (Vec<Walked>, bool) {
    let stop = cached.last().map(|(_, cid, _)| *cid).or(floor);
    let mut newer = Vec::new();
    let mut next = last;
    let mut reached_cache = false;
    while let Some((cid, seed)) = next {
        if Some(cid) == stop {
            reached_cache = true;
            break;
        }
        let Some(commit) = d
            .store
            .fetch(&cid)
            .ok()
            .flatten()
            .and_then(|ct| open(&cid, &seed, &ct).ok())
            .and_then(|pt| Commit::decode(&pt, addr).ok())
        else {
            break;
        };
        let Some(ops) = manifest::read_all(&*d.store, &commit.root)
            .ok()
            .filter(|b| OpsFile::is_ops(b))
            .and_then(|b| OpsFile::decode(&b).ok())
        else {
            break;
        };
        newer.push((commit.seq, cid, WriterCommit { seq: commit.seq, time_ms: commit.time_ms, ops: ops.ops }));
        next = commit.prev;
    }
    newer.reverse();
    if reached_cache || next.is_none() {
        let mut out = if reached_cache { cached.to_vec() } else { Vec::new() };
        out.extend(newer);
        (out, true)
    } else {
        (newer, false) // the walk stopped early (missing history): only what's contiguous to the head
    }
}

type Chains = std::collections::BTreeMap<[u8; 32], Vec<(u64, WriterCommit)>>;

/// Every writer chain of a namespace held here: this node's and the others'.
/// Resumed from a checkpoint, only commits after it, unless `full`.
fn chains(d: &Daemon, ns: &str, full: bool) -> Result<(ChannelAddr, [u8; 32], Chains), String> {
    // Reading never makes a namespace (writes do, in write_ops): a read of one
    // just left made a new, empty one of the same name.
    let addr = current_addr(d, ns)?;
    let mut heads: Vec<([u8; 32], Option<CommitRef>)> = Vec::new();
    let mut own_writer = addr.writer;
    if let Some(c) = d.store.own_channel(&ns_channel(ns)).map_err(|e| e.to_string())? {
        own_writer = channel_key(d, &c).writer();
        heads.push((own_writer, c.last));
    }
    for h in d.store.writer_heads(&addr.ns_id()).map_err(|e| e.to_string())? {
        if h.writer != own_writer {
            heads.push((h.writer, Some(h.commit)));
        }
    }
    let arc = ns_entry(d, ns);
    let mut cache = arc.lock().unwrap();
    let entry = &mut *cache;
    if full && !entry.floors.is_empty() {
        entry.floors.clear();
        entry.chains.clear();
    }
    let mut out = Chains::new();
    for (writer, last) in heads {
        let cached = entry.chains.get(&writer).cloned().unwrap_or_default();
        let (walked, complete) = walk_ops_chain(d, &addr, last, &cached, entry.floors.get(&writer).copied());
        out.insert(writer, walked.iter().map(|(seq, _, c)| (*seq, c.clone())).collect());
        // Only a complete walk is kept to build on; after a gap, walk again next time.
        if complete {
            entry.gaps.remove(&writer);
            entry.chains.insert(writer, walked);
        } else {
            entry.gaps.insert(writer);
            entry.chains.insert(writer, Vec::new());
        }
    }
    Ok((addr, own_writer, out))
}

/// Writes the records that changed since the last merge (all of them the first time).
fn apply_view(d: &Daemon, ns: &str) -> Result<(), String> {
    let arc = ns_entry(d, ns);
    let mut cache = arc.lock().unwrap();
    let entry = &mut *cache;
    let changed;
    let dirty = entry.state.as_mut().map(|s| s.take_dirty()).unwrap_or_default();
    if let (true, Some(st)) = (entry.view_built, entry.state.as_ref()) {
        // Only the records the state says changed: no copy of every record,
        // no comparison of everything on each write.
        let mut changes = Vec::new();
        for id in dirty {
            let now = st.record(&id);
            if now != d.store.get_record(ns, &id).map_err(|e| e.to_string())? {
                changes.push((id, now));
            }
        }
        changed = !changes.is_empty();
        d.store.apply_records(ns, &changes).map_err(|e| e.to_string())?;
    } else {
        // First time (or after a rebuild): the view is rewritten from the state.
        let records = entry.state.as_ref().map(|s| s.records()).unwrap_or_default();
        d.store.replace_namespace(ns, &records).map_err(|e| e.to_string())?;
        entry.view_built = entry.state.is_some();
        changed = true;
        drop(records);
        trim_memory();
    }
    drop(cache);
    if changed {
        ns_changed(d, ns);
    }
    Ok(())
}

/// Wakes `watch`es of `ns`: its records changed here.
fn ns_changed(d: &Daemon, ns: &str) {
    *d.changes.lock().unwrap().entry(ns.to_string()).or_insert(0) += 1;
    d.changed.notify_waiters();
}

/// Resumes a namespace from its local checkpoint, if the cache is empty
/// (after a restart): the state and the point each chain was applied to.
fn resume(d: &Daemon, ns: &str) -> Result<(), String> {
    if ns_entry_get(d, ns).is_some_and(|e| e.lock().unwrap().state.is_some()) {
        return Ok(());
    }
    let Some(file) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())? else { return Ok(()) };
    let Some((creator, _)) = d.store.ns_info(ns).map_err(|e| e.to_string())? else { return Ok(()) };
    let loaded = manifest::read_all(&*d.store, &file)
        .map_err(|e| e.to_string())
        .and_then(|b| Checkpoint::decode(&b).map_err(|e| e.to_string()))
        .and_then(|cp| {
            let st = if d.store.ns_lazy(ns).map_err(|e| e.to_string())? { cp.load_present(&*d.store, &creator) } else { cp.load(&*d.store, &creator) };
            st.map(|st| (cp, st)).map_err(|e| e.to_string())
        });
    let (cp, state) = match loaded {
        Ok(x) => x,
        Err(e) => {
            println!("ns {ns}: checkpoint unusable ({e}); replaying the chains");
            return Ok(());
        }
    };
    let arc = ns_entry(d, ns);
    let mut cache = arc.lock().unwrap();
    let entry = &mut *cache;
    entry.applied = cp.frontier.iter().map(|f| (f.writer, (f.seq, f.time_ms, f.commit))).collect();
    entry.floors = cp.frontier.iter().map(|f| (f.writer, f.commit)).collect();
    entry.chains.clear();
    entry.state = Some(state);
    entry.view_built = false;
    entry.since_checkpoint = 0;
    println!("ns {ns}: resumed from checkpoint ({} writer(s))", cp.frontier.len());
    drop(cache);
    trim_memory();
    Ok(())
}

/// Stores the namespace's state as a checkpoint (ADR-0018): its records as a
/// Prolly tree under the state secret, and the checkpoint file. The previous
/// checkpoint's chunks that the new one doesn't share become evictable.
fn save_checkpoint(d: &Daemon, ns: &str, state: &State, frontier: Vec<Frontier>) -> Result<FileRef, String> {
    let addr = current_addr(d, ns)?;
    let secret = state_secret(&addr.read_key);
    let mut pinned = retifs_store::TrackedPinned::new(&d.store);
    let cp = Checkpoint::save(&mut pinned, &secret, state, frontier).map_err(|e| e.to_string())?;
    let (file, blobs) = manifest::write_tracked(&mut pinned, &secret, &cp.encode(), manifest::WriteOpts::default())
        .map_err(|e| e.to_string())?;
    pinned.flush().map_err(|e| e.to_string())?; // the tree's nodes are read back just below
    let new_nodes = match &cp.state {
        Some(root) => prolly::nodes(&*d.store, root).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    let mut tokens: Vec<_> = blobs.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))).collect();
    tokens.extend(new_nodes.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))));
    d.store.register_serving(&tokens).map_err(|e| e.to_string())?;
    if let Some(old) = d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?
        && old.root != file.root
    {
        let keep: std::collections::HashSet<Cid> = tokens.iter().map(|(c, _)| *c).collect();
        let mut gone: Vec<Cid> = file_chunks(&d.store, &old).unwrap_or_default().into_iter().map(|(c, _)| c).collect();
        if let Some(old_root) = manifest::read_all(&*d.store, &old).ok().and_then(|b| Checkpoint::decode(&b).ok()).and_then(|c| c.state) {
            gone.extend(prolly::nodes(&*d.store, &old_root).unwrap_or_default().into_iter().map(|(c, _)| c));
        }
        gone.retain(|c| !keep.contains(c));
        if d.store.ns_checkpoint_published(ns).map_err(|e| e.to_string())? != Some(old.root) {
            d.store.release_chunks(&gone).map_err(|e| e.to_string())?;
        }
    }
    d.store.set_ns_checkpoint(ns, &file).map_err(|e| e.to_string())?;
    Ok(file)
}

/// Rebuilds a namespace's local view by merging every writer chain held here.
/// The result's `records` is empty: the records are in the store's view
/// (`d.store.records(ns)`), updated here from what changed.
fn materialize(d: &Daemon, ns: &str) -> Result<retifs_core::ops::Merged, String> {
    resume(d, ns)?;
    let lazy = d.store.ns_lazy(ns).map_err(|e| e.to_string())?;
    let (addr, _, mut chains) = chains(d, ns, false)?;
    let now = now_ms();
    let mut checkpoint = None;
    let merged = loop {
        let arc = ns_entry(d, ns);
        let mut cache = arc.lock().unwrap();
        let entry = &mut *cache;
        if entry.needs_history
            && let Some(st) = &entry.state
        {
            break st.merged_meta(); // as it was, until sync brings the history
        }
        // Apply only the new commits, unless one is misdated or brings a
        // control operation older than data already applied: then rebuild
        // from every chain (whole, if resumed from a checkpoint).
        let mut rebuild = entry.state.is_none();
        let mut new = Vec::new();
        let mut held_back = false;
        if !rebuild {
            for (w, chain) in &chains {
                let (done, last_time, _) = entry.applied.get(w).copied().unwrap_or((0, 0, Cid::of(b"")));
                // Commits after a missing one wait for it: applying them would
                // move this writer's mark past it, and it would never apply.
                if chain.iter().any(|(seq, _)| *seq > done) && !chain.iter().any(|(seq, _)| *seq == done + 1) {
                    held_back = true;
                    continue;
                }
                for (seq, c) in chain.iter().filter(|(seq, _)| *seq > done) {
                    if c.time_ms < last_time || c.time_ms > now + MAX_CLOCK_AHEAD_MS {
                        rebuild = true;
                    }
                    new.push((*w, *seq, c));
                }
            }
            if !rebuild {
                let commits: Vec<([u8; 32], &WriterCommit)> = new.iter().map(|(w, _, c)| (*w, *c)).collect();
                rebuild = !entry.state.as_mut().expect("checked").apply_commits(&commits);
            }
        }
        if rebuild && !entry.floors.is_empty() {
            // The history before the checkpoint is needed: walk the chains whole.
            entry.state = None;
            drop(cache);
            chains = self::chains(d, ns, true)?.2;
            continue;
        }
        let from_start = chains.values().all(|c| c.first().is_none_or(|(seq, _)| *seq == 1));
        // (Once only: if the checkpoint doesn't load either, build from what's here.)
        if rebuild && !from_start && !entry.needs_history && d.store.ns_checkpoint(ns).map_err(|e| e.to_string())?.is_some() {
            // This node started from a checkpoint and doesn't hold the history
            // before it: go back to the checkpoint until sync fetches it.
            entry.state = None;
            entry.needs_history = true;
            drop(cache);
            println!("ns {ns}: a late grant or revoke needs the history before the checkpoint; fetching it");
            resume(d, ns)?;
            d.ns_wake.notify_one();
            continue;
        }
        let cids: HashMap<[u8; 32], Cid> =
            entry.chains.iter().filter_map(|(w, c)| c.last().map(|(_, cid, _)| (*w, *cid))).collect();
        if rebuild {
            // A writer whose chain has a gap is left out until it's filled (its
            // later commits alone would mark it applied past the missing ones).
            let complete = |w: &[u8; 32]| !entry.gaps.contains(w);
            let plain = chains
                .iter()
                .filter(|(w, _)| complete(w))
                .map(|(w, c)| (*w, c.iter().map(|(_, c)| c.clone()).collect()))
                .collect();
            entry.state = Some(State::build(&addr.writer, &plain, now));
            entry.view_built = false;
            entry.applied = chains
                .iter()
                .filter(|(w, _)| complete(w))
                .filter_map(|(w, c)| c.last().and_then(|(seq, wc)| cids.get(w).map(|cid| (*w, (*seq, wc.time_ms, *cid)))))
                .collect();
            entry.since_checkpoint += chains.values().map(Vec::len).sum::<usize>();
        } else {
            entry.since_checkpoint += new.len();
            for (w, seq, c) in new {
                // (No cached chain after an incomplete walk: keep the old commit;
                // checkpoints wait until the gap is filled anyway.)
                let cid = cids.get(&w).copied().or_else(|| entry.applied.get(&w).map(|a| a.2)).unwrap_or(Cid::of(b""));
                entry.applied.insert(w, (seq, c.time_ms, cid));
            }
        }
        let state = entry.state.as_ref().expect("built above");
        if entry.since_checkpoint >= CHECKPOINT_EVERY && !held_back && entry.gaps.is_empty() && !lazy {
            entry.since_checkpoint = 0;
            let frontier: Vec<Frontier> = entry
                .applied
                .iter()
                .map(|(w, (seq, time_ms, commit))| Frontier { writer: *w, seq: *seq, time_ms: *time_ms, commit: *commit })
                .collect();
            // The same tombstones the checkpoint leaves out go from memory too.
            let reach: Vec<([u8; 32], u64, u64)> = entry.applied.iter().map(|(w, (seq, t, _))| (*w, *seq, *t)).collect();
            let st = entry.state.as_mut().expect("built above");
            let gone = st.prunable(&reach);
            if !gone.is_empty() {
                st.prune(&gone);
                println!("ns {ns}: pruned {} tombstone(s)", gone.len());
            }
            checkpoint = Some((st.clone(), frontier));
            break st.merged_meta();
        }
        break state.merged_meta();
    };
    if let Some((state, frontier)) = checkpoint {
        let reach: Vec<([u8; 32], u64, Cid)> = frontier.iter().map(|f| (f.writer, f.seq, f.commit)).collect();
        match save_checkpoint(d, ns, &state, frontier) {
            Ok(file) => {
                println!("ns {ns}: checkpoint {file}");
                trim_memory();
                // The commits it covers needn't stay in memory: chains are walked
                // back only to it from now on, like after resuming from it, and
                // a rebuild reads the history from the store.
                let arc = ns_entry_get(d, ns);
                if let Some(mut e) = arc.as_ref().map(|a| a.lock().unwrap()) {
                    for (w, seq, commit) in &reach {
                        e.floors.insert(*w, *commit);
                        if let Some(c) = e.chains.get_mut(w) {
                            c.retain(|(s, _, _)| s > seq);
                        }
                    }
                }
            }
            Err(e) => println!("ns {ns}: checkpoint failed: {e}"),
        }
    }
    apply_view(d, ns)?;
    // Rotated read keys wrapped to this node: take them, newest last.
    if let Some(identity) = d.store.ns_identity(ns).map_err(|e| e.to_string())? {
        let me: [u8; 32] = keywrap::public(&identity)[32..].try_into().unwrap();
        let known = d.store.ns_keys(ns).map_err(|e| e.to_string())?;
        for ev in &merged.rekeys {
            let Some((_, wrapped)) = ev.entries.iter().find(|(w, _)| *w == me) else { continue };
            let Some(key) = keywrap::unwrap(&identity, wrapped).and_then(|k| <[u8; 32]>::try_from(k).ok()) else { continue };
            if !known.contains(&key) {
                println!("ns {ns}: new read key, epoch {}, from {}…", ev.epoch, &hex(&ev.by)[..12]);
            }
            use_key(d, ns, &key)?;
        }
    }
    Ok(merged)
}

/// The namespace as of each of this node's versions, oldest first: `visit`
/// sees (version, time, state). A version includes every writer's
/// operations up to its time. One replay for the whole history: rebuilding
/// each version from scratch made `rec history` quadratic in time and memory
/// (found by the overnight soak test: 184 MB after 400 versions).
fn versions(d: &Daemon, ns: &str, visit: impl FnMut(u64, u64, &State)) -> Result<(), String> {
    if ns.starts_with("ch-") || d.store.ns_info(ns).map_err(|e| e.to_string())?.is_none() {
        return Err(format!("{ns} has no version history here"));
    }
    let (addr, own, chains) = chains(d, ns, true)?;
    let plain: std::collections::BTreeMap<[u8; 32], Vec<WriterCommit>> =
        chains.into_iter().map(|(w, c)| (w, c.into_iter().map(|(_, wc)| wc).collect())).collect();
    retifs_core::ops::versions(&addr.writer, &plain, &own, now_ms(), visit);
    Ok(())
}

fn to_value(v: &AttrValue) -> Result<Value, String> {
    Ok(match v {
        AttrValue::Null => Value::Null,
        AttrValue::Bool(b) => Value::Bool(*b),
        AttrValue::Int(i) => Value::Int(*i),
        AttrValue::Float(f) if f.is_nan() => return Err("NaN has no canonical form".into()),
        AttrValue::Float(f) => Value::Float(*f),
        AttrValue::Str(s) => Value::Str(s.clone()),
        AttrValue::Bytes(b) => Value::Bytes(b.clone()),
        AttrValue::List(items) => Value::List(items.iter().map(to_value).collect::<Result<_, _>>()?),
    })
}

fn from_value(v: &Value) -> AttrValue {
    match v {
        Value::Null => AttrValue::Null,
        Value::Bool(b) => AttrValue::Bool(*b),
        Value::Int(i) => AttrValue::Int(*i),
        Value::Float(f) => AttrValue::Float(*f),
        Value::Str(s) => AttrValue::Str(s.clone()),
        Value::Bytes(b) => AttrValue::Bytes(b.clone()),
        Value::List(items) => AttrValue::List(items.iter().map(from_value).collect()),
    }
}

fn view(r: &Record) -> RecordView {
    RecordView {
        id: hex(&r.id),
        attrs: r.attrs.iter().map(|(k, v)| (k.clone(), from_value(v))).collect(),
        blocks: r.blocks.iter().map(|b| b.to_string()).collect(),
    }
}

fn parse_record_id(s: &str) -> Result<RecordId, String> {
    let s = s.trim();
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect();
    bytes.and_then(|b| b.try_into().ok()).ok_or_else(|| format!("bad record id {s}"))
}

/// Ends this node's need for `cap` (ADR-0014): leases run out, own copies of
/// chunks no other needed file uses become evictable.
fn forget(d: &Daemon, cap: &FileRef) -> Result<(), String> {
    forget_all(d, std::slice::from_ref(cap))
}

/// [`forget`] for many files at once: the chunks every other needed file
/// uses are gathered once, not once per file (deleting thousands of records
/// in one transaction was quadratic).
fn forget_all(d: &Daemon, caps: &[FileRef]) -> Result<(), String> {
    if caps.is_empty() {
        return Ok(());
    }
    let going: std::collections::HashSet<Cid> = caps.iter().map(|c| c.root).collect();
    // Chunks other needed files still use stay (versions share most of theirs).
    let mut keep = std::collections::HashSet::new();
    for other in d.store.needed_files().map_err(|e| e.to_string())? {
        if !going.contains(&other.root) {
            keep.extend(file_chunks(&d.store, &other).unwrap_or_default().into_iter().map(|(c, _)| c));
        }
    }
    // One durable commit for the lot, not several per file (leaving a
    // library of 95,000 tiles took about an hour of fsyncs otherwise).
    d.store
        .bulk(|| -> Result<(), String> {
            for cap in caps {
                let all: Vec<Cid> = file_chunks(&d.store, cap).unwrap_or_default().into_iter().map(|(c, _)| c).collect();
                let shared = all.iter().filter(|c| keep.contains(c)).count();
                let mine: Vec<Cid> = all.into_iter().filter(|c| !keep.contains(c)).collect();
                let leases = d.store.forget_file(&cap.root).map_err(|e| e.to_string())?;
                let released = d.store.release_chunks(&mine).map_err(|e| e.to_string())?;
                d.deferred.lock().unwrap().remove(&cap.root);
                if caps.len() == 1 {
                    println!(
                        "forget {}: {leases} lease(s) no longer serve it, {released} chunk(s) evictable, {shared} kept (other needed files use them)",
                        cap.root
                    );
                }
            }
            Ok(())
        })
        .map_err(|e| e.to_string())??;
    if caps.len() > 1 {
        println!("forget: {} files no longer needed here", caps.len());
    }
    Ok(())
}

fn channels(d: &Daemon) -> Result<Response, String> {
    let own = d
        .store
        .own_channels()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| ChannelInfo {
            address: ChannelKey::from_secrets(c.signing_seed, c.read_key).addr().to_string(),
            name: c.name,
            seq: c.seq,
        })
        .collect();
    let follows = d
        .store
        .follows()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|f| FollowInfo {
            address: f.addr.to_string(),
            seq: f.seq,
            complete: f.current.is_some_and(|c| version_files(&d.store, &c).iter().all(|x| complete(&d.store, x))),
            namespace: f.current.and_then(|c| read_snapshot(&d.store, &c)).map(|_| channel_ns(&f.addr)),
            current: f.current.map(|c| c.to_string()),
        })
        .collect();
    Ok(Response::Channels { own, follows })
}

/// Completely local and no longer sought.
fn complete(store: &SlabStore, f: &FileRef) -> bool {
    !store.is_wanted(&f.root).unwrap_or(true) && local_status(store, f).complete()
}

/// Keeps followed channels at their latest version (ADR-0015): asks the hints
/// for the head, accepts only a valid head with a higher sequence number
/// (rollback protection), fetches its commit and seeks the new tree. Once a new
/// version is complete, the one it replaced is forgotten. Woken by new follows,
/// else every 30 s.
async fn follower(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = d.follow_wake.notified() => {}
            _ = tick.tick() => {}
        }
        for f in d.store.follows().unwrap_or_default() {
            if let Err(e) = follow_pass(&d, f).await {
                eprintln!("follow: {e}");
            }
        }
    }
}

async fn follow_pass(d: &Daemon, mut f: retifs_store::Follow) -> Result<(), String> {
    let ns = hex(&f.addr.ns_id());
    // A followed index channel (a search capability): fetch its index tree.
    if let Some(cur) = f.current
        && complete(&d.store, &cur)
        && let Err(e) = fetch_index(d, &f).await
    {
        eprintln!("follow {ns}: {e}");
    }
    // A snapshot version is rebuilt into a local namespace (queryable), and
    // its records' content blocks are sought too (ADR-0016).
    if let Some(cur) = f.current
        && complete(&d.store, &cur)
        && let Some(snap) = read_snapshot(&d.store, &cur)
    {
        d.store.replace_namespace(&channel_ns(&f.addr), &snap.records).map_err(|e| e.to_string())?;
        ns_changed(d, &channel_ns(&f.addr));
        for b in snap.records.iter().flat_map(|r| r.blocks.iter()) {
            if !complete(&d.store, b) && !d.store.is_wanted(&b.root).unwrap_or(false) {
                d.store.want_file(b, &f.hints).map_err(|e| e.to_string())?;
                d.wake.notify_one();
            }
        }
    }
    let files = f.current.map(|c| version_files(&d.store, &c)).unwrap_or_default();
    let version_complete = !files.is_empty() && files.iter().all(|x| complete(&d.store, x));
    // A complete version is kept here and served to other followers (who prove
    // its chunks' seeds): following a channel passes it on, like an app mirror.
    if version_complete && d.store.tier(&files[0].root).ok().flatten().is_some_and(|t| t & tier::PINNED == 0) {
        for x in &files {
            let chunks = file_chunks(&d.store, x)?;
            for (cid, _) in &chunks {
                if let Some(t) = d.store.tier(cid).map_err(|e| e.to_string())? {
                    d.store.set_tier(cid, t | tier::PINNED).map_err(|e| e.to_string())?;
                }
            }
            d.store.register_serving(&chunks).map_err(|e| e.to_string())?;
        }
        println!(
            "follow {ns}: version {} complete ({} file(s)), kept and served to other followers",
            f.seq,
            files.len()
        );
    }
    // The new version is complete: what only the one it replaced had is no longer needed here.
    if let Some(prev) = f.previous
        && version_complete
    {
        let keep: std::collections::HashSet<Cid> = files.iter().map(|x| x.root).collect();
        let old: Vec<FileRef> = version_files(&d.store, &prev).into_iter().filter(|x| !keep.contains(&x.root)).collect();
        forget_all(d, &old)?;
        f.previous = None;
        d.store.update_follow(&f).map_err(|e| e.to_string())?;
    }
    for hint in f.hints.clone() {
        let link = match d.link_to(&hint).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("follow {ns}: <{}> unreachable: {e}", hex(&hint));
                continue;
            }
        };
        let raw = match d.ask(link, HEAD_ENDPOINT, f.addr.ns_id().to_vec()).await {
            Ok(r) => r,
            Err(e) => {
                d.drop_link(&hint);
                eprintln!("follow {ns}: <{}>: {e}", hex(&hint));
                continue;
            }
        };
        // No head here: an empty reply (Prns may deliver it as a short placeholder).
        if raw.len() != retifs_core::channel::HEAD_LEN {
            continue;
        }
        let head = Head::decode(&raw).map_err(|e| format!("bad head from <{}>: {e}", hex(&hint)))?;
        if head.writer != f.addr.writer || head.seq <= f.seq {
            continue; // another channel, or not newer: never go back
        }
        let seed = head.commit_seed(&f.addr).map_err(|e| e.to_string())?;
        let ct = match d.store.fetch(&head.commit).map_err(|e| e.to_string())? {
            Some(ct) => ct,
            None => {
                let round = seek_round(&d.transport, link, &[(head.commit, seed)], false, Duration::from_secs(60)).await?;
                match round.got.into_iter().next() {
                    Some((_, ct, _)) => ct,
                    None => continue, // this hint has the head but not the commit
                }
            }
        };
        let commit = Commit::decode(&open(&head.commit, &seed, &ct).map_err(|e| e.to_string())?, &f.addr)
            .map_err(|e| e.to_string())?;
        if commit.seq != head.seq || commit.writer != head.writer {
            return Err(format!("head {} points at another commit ({} by another writer?)", head.seq, commit.seq));
        }
        // Keep the commit and pass it on to other followers (they prove its seed).
        d.store.insert(&head.commit, &ct, tier::PINNED).map_err(|e| e.to_string())?;
        d.store.register_serving(&[(head.commit, ChunkToken::for_seed(&seed))]).map_err(|e| e.to_string())?;
        if f.current.map(|c| c.root) != Some(commit.root.root) {
            match f.current {
                // A version that never completed is simply replaced.
                Some(cur) if !complete(&d.store, &cur) => forget(d, &cur)?,
                Some(cur) => f.previous = Some(cur),
                None => {}
            }
            f.current = Some(commit.root);
            d.store.want_file(&commit.root, &f.hints).map_err(|e| e.to_string())?;
            d.wake.notify_one();
        }
        println!("follow {ns}: version {} from <{}>, seeking {}", head.seq, hex(&hint), commit.root.root);
        f.seq = head.seq;
        f.head = raw;
        d.store.update_follow(&f).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Gives memory freed after a large operation (loading or saving a
/// checkpoint) back to the system. glibc's allocator otherwise keeps the
/// peak: a daemon that resumed a 100,000-record namespace stayed at 457 MiB
/// with 108 MiB of state live.
fn trim_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim only returns free memory to the OS.
    unsafe {
        libc::malloc_trim(0);
    }
}

fn now_s() -> u64 {
    now_ms() / 1000
}

/// Every chunk of a file (manifest nodes, data and padding) with its access
/// token, from the local store: what a lease for the whole file lists.
fn file_chunks(store: &SlabStore, file: &FileRef) -> Result<Vec<(Cid, ChunkToken)>, String> {
    let mut out = manifest_chunks(store, file)?;
    // With it, chunks attached to it (a channel commit with its file).
    out.extend(store.attached(&file.root).unwrap_or_default().iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))));
    // A checkpoint file comes with its state tree (ADR-0018).
    if file.size <= 1 << 20
        && let Some(root) = manifest::read_all(store, file).ok().and_then(|b| Checkpoint::decode(&b).ok()).and_then(|c| c.state)
    {
        let nodes = prolly::nodes(store, &root).map_err(|_| "not all of the checkpoint's state is local".to_string())?;
        out.extend(nodes.iter().map(|(c, s)| (*c, ChunkToken::for_seed(s))));
    }
    Ok(out)
}

/// A file's own chunks (manifest nodes, data, padding), without a
/// checkpoint's state tree.
fn manifest_chunks(store: &SlabStore, file: &FileRef) -> Result<Vec<(Cid, ChunkToken)>, String> {
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

/// A storage node that missed this many of its announces (at the interval
/// its announces state) gets no new leases: it's likely gone. Its present
/// leases are checked by upkeep as ever, and its next announce brings it back.
const MISSED_ANNOUNCES: u64 = 5;
/// Silent for a day (and ten of its intervals): forgotten until heard again.
const FORGET_SILENT_MS: u64 = 24 * 3_600_000;

/// How often the owner checks each holder still has the data.
const PROOF_INTERVAL: Duration = Duration::from_secs(600);

/// Owner side: collects receipts, renews leases at half-term, and checks
/// storage proofs. Woken after new leases, else every 30 s.
async fn lease_upkeep(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    let mut proved: HashMap<PeerId, Instant> = HashMap::new();
    loop {
        tokio::select! {
            _ = d.upkeep_wake.notified() => {}
            _ = tick.tick() => {}
        }
        let Ok(leases) = d.store.own_leases() else { continue };
        let mut by_holder: std::collections::BTreeMap<PeerId, Vec<OwnLease>> = Default::default();
        for o in leases {
            by_holder.entry(o.holder).or_default().push(o);
        }
        // One exchange per holder however many leases it keeps (ADR-0014).
        for (holder, mut leases) in by_holder {
            match upkeep_holder(&d, &holder, &mut leases, &mut proved).await {
                Ok(Some(ok)) => {
                    let _ = d.store.holder_result(&holder, ok, now_ms());
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("upkeep <{}>: {e}", hex(&holder));
                    let _ = d.store.holder_result(&holder, false, now_ms());
                    d.drop_link(&holder);
                }
            }
        }
        if let Err(e) = place_all(&d).await {
            eprintln!("placement: {e}");
        }
    }
}

/// Estimated chance of losing every copy of `file` (ADR-0014): the local copy
/// times each holder's loss estimate from its record. A holder whose receipt
/// ran out counts as lost; one that is only unreachable just gets a worse
/// record (lazy repair: it may come back with the data).
/// Returns (local copy's estimate, holders, product of all).
/// `leases`: the own leases keeping `file`.
fn loss_now(d: &Daemon, file: &FileRef, leases: &[OwnLease]) -> (f64, Vec<retifs_store::HolderView>, f64) {
    let pinned = d.store.tier(&file.root).ok().flatten().is_some_and(|f| f & tier::PINNED != 0);
    let local = if pinned { 0.1 } else { 0.5 };
    let now = now_s();
    let hops: HashMap<PeerId, u8> =
        d.store.storage_nodes().unwrap_or_default().into_iter().map(|n| (n.peer, n.hops)).collect();
    let mut by_holder: std::collections::BTreeMap<PeerId, retifs_store::HolderView> = Default::default();
    for o in leases {
        let lapsed = o.receipt_until > 0 && o.receipt_until < now;
        let p = if lapsed || o.proof == ProofState::Failed {
            1.0
        } else {
            d.store.holder_stats(&o.holder).map(|s| s.loss()).unwrap_or(1.0)
        };
        let v = by_holder.entry(o.holder).or_insert(retifs_store::HolderView {
            peer: o.holder,
            loss: 0.0,
            hops: hops.get(&o.holder).copied().unwrap_or(0),
            confirmed: true,
        });
        // A holder is as good as its worst lease for this file.
        v.loss = v.loss.max(p);
        v.confirmed &= o.receipt_until >= now && !lapsed;
    }
    let holders: Vec<_> = by_holder.into_values().collect();
    let risk = local * holders.iter().map(|h| h.loss).product::<f64>();
    (local, holders, risk)
}

/// Whether a loss estimate meets the target. A relative tolerance keeps
/// rounding (0.1 × 0.1 × 0.1 = 0.0010000000000000002) from costing an extra copy.
fn met(risk: f64, target: f64) -> bool {
    risk <= target * (1.0 + 1e-9)
}

/// Keeps every needed file at or below the loss target (ADR-0014), in one
/// planned pass: each file picks the holders it lacks from one ranking of
/// candidates, then everything bound for a holder goes out together, packed
/// into mixed leases sorted by CID, so a holder sees neither file boundaries
/// nor chunk order. Data goes by push, so readers' copies (cache, never
/// served) can be placed too, and holders don't learn who sent it.
async fn place_all(d: &Daemon) -> Result<(), String> {
    // Silent for a day: gone (test nodes, replaced identities). Otherwise
    // they pile up as candidates, each costing a 20 s link attempt.
    if let Ok(n) = d.store.forget_silent_storage_nodes(now_ms(), |s| FORGET_SILENT_MS.max(10 * s.announce_s as u64 * 1000))
        && n > 0
    {
        println!("placement: forgot {n} storage node(s) silent for a day");
    }
    let mut plan: std::collections::BTreeMap<PeerId, Vec<FileRef>> = Default::default();
    let mut ranked: Option<Vec<(f64, retifs_store::StorageNode)>> = None;
    let mut short = 0;
    let wanted = copies_wanted(d);
    let sites = node_sites(d);
    // Read once: per file, this was every lease for every file (minutes with
    // the map libraries, the runtime starved meanwhile).
    let by_root = d.store.own_leases_by_root().map_err(|e| e.to_string())?;
    for (i, file) in d.store.needed_files().map_err(|e| e.to_string())?.into_iter().enumerate() {
        // A pass over many files is long: let the runtime's other work in.
        if i % 64 == 63 {
            tokio::task::yield_now().await;
        }
        let want = wanted.get(&file.root).map_or(Copies::Default, |&n| Copies::Exactly(n));
        let leases = by_root.get(&file.root).map_or(&[][..], |l| &l[..]);
        let Some(Need { mut risk, holders, own, mut elsewhere }) = review(d, &file, want, &sites, leases)? else { continue };
        // Not all here (a storage-less node's file, only cached and evicted):
        // nothing to place from; its holders keep it meanwhile.
        if file_chunks(&d.store, &file).is_err() {
            continue;
        }
        if ranked.is_none() {
            ranked = Some(rank_candidates(d).await?);
        }
        let mut copies = holders.len() + 1;
        let floor = want.floor(d, own);
        let mut chosen: Vec<PeerId> = Vec::new();
        // First the rule as a whole: the last copy the count asks for goes to
        // another site if none is there yet. If no node at another site can be
        // had now, then the count at least, at this site: three copies in one
        // place beat two; the one elsewhere follows when such a node is heard
        // (and a surplus copy here is trimmed then).
        for pass in 0..2 {
            for (_, n) in ranked.as_deref().unwrap_or_default() {
                let count_met = copies >= floor && (matches!(want, Copies::Exactly(_)) || met(risk, d.loss_target));
                if (pass == 0 && want.enough(d, risk, copies, own, elsewhere)) || (pass == 1 && count_met) {
                    break;
                }
                if holders.contains(&n.peer) || chosen.contains(&n.peer) {
                    continue;
                }
                let other_site = !same_site(d, &sites, &n.peer);
                if pass == 0 && own && d.site.is_some() && !elsewhere && !other_site && copies + 1 >= floor {
                    continue;
                }
                plan.entry(n.peer).or_default().push(file);
                chosen.push(n.peer);
                risk *= d.store.holder_stats(&n.peer).map(|s| s.loss()).unwrap_or(1.0);
                copies += 1;
                elsewhere |= other_site;
            }
            if copies >= floor || want.enough(d, risk, copies, own, elsewhere) {
                break;
            }
        }
        if !want.enough(d, risk, copies, own, elsewhere) && (copies < floor || (own && d.site.is_some() && !elsewhere)) {
            short += 1;
        }
    }
    if short > 0 {
        let site = if d.site.is_some() { ", or none at another site" } else { "" };
        println!("placement: {short} file(s) below their number of copies{site}: not enough storage nodes reachable now");
    }
    for (peer, files) in plan {
        // Union of the files' chunks: shared chunks (versions) are listed once.
        let mut roots: HashMap<Cid, Vec<Cid>> = HashMap::new();
        let mut chunks: Vec<(Cid, ChunkToken)> = Vec::new();
        for f in &files {
            for (cid, token) in file_chunks(&d.store, f)? {
                let r = roots.entry(cid).or_default();
                if r.is_empty() {
                    chunks.push((cid, token));
                }
                r.push(f.root);
            }
        }
        let hops = d.store.storage_nodes().unwrap_or_default().iter().find(|n| n.peer == peer).map_or(0, |n| n.hops);
        match lease_to(d, &peer, &sorted(&chunks), &roots, &[]).await {
            Ok(true) => println!(
                "placement: {} file(s), {} chunk(s) kept at <{}> ({hops} hop(s)) in mixed lease(s)",
                files.len(),
                chunks.len(),
                hex(&peer)
            ),
            Ok(false) => d.store.avoid_storage_node(&peer, now_ms() + 3_600_000).map_err(|e| e.to_string())?,
            Err(e) => {
                eprintln!("placement: <{}>: {e}", hex(&peer));
                d.store.avoid_storage_node(&peer, now_ms() + avoid_after_failure(d, &peer)).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// How long placement leaves a node alone after a link or a lease to it
/// failed: ten minutes, but two for a holder with a good record. Paths over
/// several hops of the internet come and go; with only a few real holders,
/// avoiding each for ten minutes after one timeout left placement with none.
fn avoid_after_failure(d: &Daemon, peer: &PeerId) -> u64 {
    match d.store.holder_stats(peer) {
        Ok(s) if s.ok > 0 && s.ok >= s.fail => 120_000,
        _ => 600_000,
    }
}

/// Chunks in CID order: a lease then says nothing about file order or boundaries.
fn sorted(chunks: &[(Cid, ChunkToken)]) -> Vec<(Cid, ChunkToken)> {
    let mut v = chunks.to_vec();
    v.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    v.dedup_by(|a, b| a.0 == b.0);
    v
}

/// Brings one file's holders up to date: forgets holders whose lease ran
/// out, trims a surplus copy. Returns the loss estimate and current holders
/// if the file needs more.
/// The copies each file's namespaces ask for (`retifs.placement` records),
/// where they ask: the most any of its namespaces asks.
fn copies_wanted(d: &Daemon) -> HashMap<Cid, usize> {
    let mut out: HashMap<Cid, usize> = HashMap::new();
    for ns in d.store.ns_names().unwrap_or_default() {
        let Ok(records) = d.store.records(&ns) else { continue };
        let wanted = records.iter().find_map(|r| {
            (r.attrs.get("type") == Some(&Value::Str(libretifs::PLACEMENT_TYPE.into()))).then(|| match r.attrs.get("copies") {
                Some(Value::Int(n)) if *n >= 1 => Some(*n as usize),
                _ => None,
            })?
        });
        let Some(n) = wanted else { continue };
        for b in records.iter().flat_map(|r| r.blocks.iter()) {
            let e = out.entry(b.root).or_insert(n);
            *e = (*e).max(n);
        }
    }
    out
}

/// How many copies a file gets: a namespace's own number (exactly that), or
/// the node's rule (the loss target, and at least `min_copies`). The floor
/// and the site rule are for the file's own copies (its writer's, or one kept
/// here); a reader's node places copies near itself by the estimate alone,
/// for availability, so a widely read file doesn't gain two copies a reader.
#[derive(Clone, Copy)]
enum Copies {
    Default,
    Exactly(usize),
}

impl Copies {
    fn floor(self, d: &Daemon, own: bool) -> usize {
        match self {
            Copies::Default if own => d.min_copies,
            Copies::Default => 1,
            Copies::Exactly(n) => n,
        }
    }

    /// Whether `copies` copies (this node's own included) with loss estimate
    /// `risk` will do; `elsewhere`: one of them is at another site.
    fn enough(self, d: &Daemon, risk: f64, copies: usize, own: bool, elsewhere: bool) -> bool {
        let sited = !own || d.site.is_none() || elsewhere || self.floor(d, own) <= 1;
        match self {
            Copies::Default => met(risk, d.loss_target) && copies >= self.floor(d, own) && sited,
            Copies::Exactly(n) => copies >= n && sited,
        }
    }
}

/// Whether the store is short of room for its own copies: pinned and leased
/// data at nine tenths of the store's limit or more (ADR-0031).
fn short_of_space(d: &Daemon) -> bool {
    match (d.store.usage(), d.store.limits()) {
        (Ok(u), Ok(l)) => (u.pinned + u.leased) * 10 >= l.hard_max * 9,
        _ => false,
    }
}

/// Each storage node's site, as its announces say.
fn node_sites(d: &Daemon) -> HashMap<PeerId, Option<retifs_core::announce::SiteTag>> {
    d.store.storage_nodes().unwrap_or_default().into_iter().map(|n| (n.peer, n.site)).collect()
}

/// Whether `peer` is at this node's site. A node that names no site counts
/// as elsewhere: it's most likely someone else's.
fn same_site(d: &Daemon, sites: &HashMap<PeerId, Option<retifs_core::announce::SiteTag>>, peer: &PeerId) -> bool {
    d.site.is_some() && sites.get(peer).copied().flatten() == d.site
}

/// A file that needs more copies: its loss estimate, holders, whether it's
/// this node's own (pinned) copy, and whether a holder is at another site.
struct Need {
    risk: f64,
    holders: std::collections::BTreeSet<PeerId>,
    own: bool,
    elsewhere: bool,
}

/// `leases`: the own leases keeping `file`, as read at the start of the pass.
fn review(
    d: &Daemon,
    file: &FileRef,
    want: Copies,
    sites: &HashMap<PeerId, Option<retifs_core::announce::SiteTag>>,
    leases: &[OwnLease],
) -> Result<Option<Need>, String> {
    // A lease that ran out unrenewed means the holder dropped the copy: forget
    // that holder for this file instead of re-offering to it later (a minute of
    // grace for clocks). One that's only away but still within its lease counts
    // on, with a worse record (lazy repair).
    let now = now_s();
    let lapsed: std::collections::BTreeSet<PeerId> =
        leases.iter().filter(|o| o.expires + 60 < now).map(|o| o.holder).collect();
    for h in &lapsed {
        d.store.drop_holder(&file.root, h).map_err(|e| e.to_string())?;
        println!("placement: {}: lease at <{}> ran out unrenewed, its copy is gone", file.root, hex(h));
    }
    // Dropping changed this file's leases: read them again.
    let reread;
    let leases = if lapsed.is_empty() {
        leases
    } else {
        reread = d.store.own_leases_for(&file.root).map_err(|e| e.to_string())?;
        &reread[..]
    };
    let (local, views, risk) = loss_now(d, file, leases);
    // Short of room (a small store, or none at all: ADR-0031): this node's
    // own files are still its own once only cached here.
    let short = d.no_storage || short_of_space(d);
    let own = local <= 0.1 || (short && d.store.is_needed(&file.root).unwrap_or(false));
    let elsewhere_without = |drop: Option<&PeerId>| views.iter().any(|h| Some(&h.peer) != drop && !same_site(d, sites, &h.peer));
    let elsewhere = elsewhere_without(None);
    // Its own copy not counted: enough copies elsewhere, all confirmed?
    let risk_elsewhere = views.iter().map(|h| h.loss).product::<f64>();
    let safe_elsewhere = !views.is_empty() && views.iter().all(|h| h.confirmed) && want.enough(d, risk_elsewhere, views.len(), true, elsewhere);
    if short && local <= 0.1 && safe_elsewhere {
        // Then the copy here is only a cache: evictable when room is needed.
        let chunks: Vec<Cid> = file_chunks(&d.store, file).unwrap_or_default().into_iter().map(|(c, _)| c).collect();
        let n = d.store.release_chunks(&chunks).map_err(|e| e.to_string())?;
        println!("placement: {}: enough copies elsewhere; kept here only as cache now ({n} chunk(s))", file.root);
    }
    // The copy here counts only when it's really kept here: pinned, on a node
    // with storage. A storage-less node's, or one only cached, doesn't (or
    // trimming would take one too many and placement would add it again).
    let here_counts = !d.no_storage && local <= 0.1;
    let local_f = if here_counts { local } else { 1.0 };
    let (copies, risk) = if here_counts { (views.len() + 1, risk) } else { (views.len(), risk_elsewhere) };
    if want.enough(d, risk, copies, own, elsewhere) {
        // Surplus after a repair (the absent holder came back): stop renewing
        // the worst copy once the target holds well without it, never below
        // the floor; with a namespace's own number, whatever is over it.
        // The last copy at another site is never trimmed, nor offered for it.
        let protected = |p: &PeerId| own && d.site.is_some() && elsewhere && !elsewhere_without(Some(p));
        let all_confirmed = views.iter().all(|h| h.confirmed);
        // The worst copy that may go, at this site first.
        let worst = views
            .iter()
            .filter(|h| !protected(&h.peer))
            .max_by(|a, b| same_site(d, sites, &a.peer).cmp(&same_site(d, sites, &b.peer)).then(a.loss.total_cmp(&b.loss)).then(a.hops.cmp(&b.hops)));
        let drop = match want {
            Copies::Default if copies > want.floor(d, own) => retifs_store::surplus_holder(local_f, &views, d.loss_target).filter(|p| !protected(p)).or_else(|| {
                // Over the count (a copy elsewhere came on top of three here):
                // the worst one, if the rest still meet the target without it.
                let worst = worst.filter(|_| all_confirmed)?;
                let without = local_f * views.iter().filter(|h| h.peer != worst.peer).map(|h| h.loss).product::<f64>();
                met(without, d.loss_target).then_some(worst.peer)
            }),
            Copies::Exactly(n) if copies > n && all_confirmed => worst.map(|h| h.peer),
            _ => None,
        };
        if let Some(drop) = drop {
            let n = d.store.drop_holder(&file.root, &drop).map_err(|e| e.to_string())?;
            let without = local_f * views.iter().filter(|h| h.peer != drop).map(|h| h.loss).product::<f64>();
            println!(
                "placement: {} trimmed at <{}> ({n} lease(s) no longer serve it), loss estimate without it {without:.1e}",
                file.root,
                hex(&drop)
            );
        }
        return Ok(None);
    }
    Ok(Some(Need { risk, holders: views.iter().map(|h| h.peer).collect(), own, elsewhere }))
}

/// The nearest few storage nodes by hops, measured by linking (RTT) and
/// earlier transfers, ranked by estimated transfer time. Placement is never
/// worth a slow link: copies for durability don't cross LoRa (ADR-0013/0014).
///
/// Nodes that kept data for this one before are asked first, by their
/// record; then the rest, nearest and most recently heard first. A pass
/// tries at most `MAX_LINK_ATTEMPTS` links: many announced nodes may be gone
/// (test nodes, a crowded network), and each failed link costs 20 s.
async fn rank_candidates(d: &Daemon) -> Result<Vec<(f64, retifs_store::StorageNode)>, String> {
    const MAX_LINK_ATTEMPTS: usize = 12;
    let mut nodes = d.store.storage_nodes().map_err(|e| e.to_string())?;
    let record = |n: &retifs_store::StorageNode| d.store.holder_stats(&n.peer).ok().filter(|s| s.ok > 0).map(|s| s.loss());
    // Stable: within each group the store's order (hops, then recency) stays.
    nodes.sort_by(|a, b| match (record(a), record(b)) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let mut candidates = Vec::new();
    let mut attempts = 0;
    for n in nodes {
        if candidates.len() == 8 || attempts == MAX_LINK_ATTEMPTS {
            break;
        }
        if n.peer == d.node_id || n.avoid_until_ms > now_ms() {
            continue;
        }
        // Missed its last few announces: likely gone, so not worth a link
        // attempt (which would also bring back its old announce from a
        // transport node's cache and make it look heard).
        if n.last_heard_ms + MISSED_ANNOUNCES * n.announce_s as u64 * 1000 < now_ms() {
            continue;
        }
        attempts += 1;
        if let Err(e) = d.link_to(&n.peer).await {
            eprintln!("placement: <{}>: {e}", hex(&n.peer));
            d.store.avoid_storage_node(&n.peer, now_ms() + avoid_after_failure(d, &n.peer)).map_err(|e| e.to_string())?;
            continue;
        }
        let q = d.quality(&n.peer);
        if q.slow() {
            println!("placement: <{}> is behind a slow link ({} ms, ~{:.0} B/s): not placing there", hex(&n.peer), q.rtt_ms, q.rate());
            d.store.avoid_storage_node(&n.peer, now_ms() + 6 * 3_600_000).map_err(|e| e.to_string())?;
            continue;
        }
        candidates.push((q.transfer_secs(1 << 20), n));
    }
    candidates.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.hops.cmp(&b.1.hops)));
    Ok(candidates)
}

/// Offers a lease, with a stamp if the holder asks for one (or asked before).
/// A holder asking more than `--max-stamp-cost` is treated as having no room.
async fn offer(d: &Daemon, link: LinkId, peer: &PeerId, l: &Lease, sources: &[PeerId]) -> Result<LeaseStatus, String> {
    let mut cost = d.stamp_costs.lock().unwrap().get(peer).copied().unwrap_or(0);
    for _ in 0..2 {
        let stamp = if cost > 0 {
            let material = stamp::lease_material(l);
            let t0 = Instant::now();
            let st = tokio::task::spawn_blocking(move || stamp::generate(&material, cost)).await.map_err(|e| e.to_string())?;
            println!("lease {}: stamp of {cost} bits for <{}> in {:.2} s", hex(&l.id), hex(peer), t0.elapsed().as_secs_f64());
            Some(st)
        } else {
            None
        };
        let req = LeaseRequest::Offer { lease: l.clone(), sources: sources.to_vec(), stamp };
        match decode_lease_status(&d.ask(link, LEASE_ENDPOINT, encode_lease_request(&req)).await?).map_err(|e| e.to_string())? {
            LeaseStatus::StampRequired(c) if c > d.max_stamp_cost => {
                println!("lease {}: <{}> asks a stamp of {c} bits, more than {}: not offering there", hex(&l.id), hex(peer), d.max_stamp_cost);
                return Ok(LeaseStatus::NoRoom);
            }
            LeaseStatus::StampRequired(c) if c != cost => {
                d.stamp_costs.lock().unwrap().insert(*peer, c);
                cost = c;
            }
            other => return Ok(other),
        }
    }
    Err("holder keeps refusing the stamp".into())
}

/// Offers `peer` leases over `chunks` (≤ 1024 per lease, in the given order)
/// and pushes what it lacks. `roots` says which files each chunk belongs to,
/// so each lease records the files it serves. Ok(false): it has no room.
async fn lease_to(
    d: &Daemon,
    peer: &PeerId,
    chunks: &[(Cid, ChunkToken)],
    roots: &HashMap<Cid, Vec<Cid>>,
    sources: &[PeerId],
) -> Result<bool, String> {
    let link = d.link_to(peer).await?;
    for part in chunks.chunks(lease::MAX_CHUNKS) {
        let mut id = [0u8; lease::ID_LEN];
        getrandom::fill(&mut id).expect("OS entropy");
        let l = d.sign_lease(id, now_s() + d.lease_term, part.to_vec());
        let mut served: Vec<Cid> = part.iter().flat_map(|(c, _)| roots.get(c).cloned().unwrap_or_default()).collect();
        served.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        served.dedup();
        match offer(d, link, peer, &l, sources).await {
            Ok(LeaseStatus::Accepted) => {
                d.store.record_own_lease(&l, peer, &served).map_err(|e| e.to_string())?;
                match push(d, link, &l, Some(peer)).await {
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
async fn push(d: &Daemon, link: LinkId, l: &Lease, peer: Option<&PeerId>) -> Result<usize, String> {
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
    // Start with full batches; on a timeout (slow or long paths), halve the
    // batch and resend the same chunks, down to one chunk per request.
    let (mut sent, mut at, mut batch) = (0, 0, MAX_PUT);
    while at < missing.len() {
        let end = (at + batch).min(missing.len());
        let cts: Vec<Vec<u8>> = missing[at..end].iter().filter_map(|c| d.store.fetch(c).ok().flatten()).collect();
        if !cts.is_empty() {
            let t0 = Instant::now();
            match d.ask(link, PUT_ENDPOINT, encode_put(&l.id, &cts)).await {
                Ok(reply) => {
                    if let Some(peer) = peer {
                        let bytes = cts.iter().map(|c| c.len() as u64).sum();
                        let _ = d.store.record_transfer(peer, bytes, t0.elapsed().as_millis() as u64);
                    }
                    sent += decode_bitmap(&reply, cts.len()).map_err(|e| e.to_string())?.iter().filter(|&&b| b).count()
                }
                Err(e) if batch > 1 && (e.contains("Timeout") || e.contains("timed out")) => {
                    batch /= 2;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        at = end;
    }
    Ok(sent)
}

/// Renews, collects receipts and samples a storage proof for all leases one
/// holder keeps, in bundles. Ok(None): nothing was due; Ok(Some(ok)): the
/// holder was contacted, and whether it behaved.
async fn upkeep_holder(
    d: &Daemon,
    holder: &PeerId,
    leases: &mut [OwnLease],
    proved: &mut HashMap<PeerId, Instant>,
) -> Result<Option<bool>, String> {
    let now = now_s();
    let renew: Vec<usize> = (0..leases.len()).filter(|&i| leases[i].expires < now + d.lease_term / 2).collect();
    let proof_due = leases.iter().any(|o| o.receipt_until > 0) && proved.get(holder).is_none_or(|t| t.elapsed() > PROOF_INTERVAL);
    if renew.is_empty() && !proof_due && leases.iter().all(|o| o.receipt_until >= o.expires) {
        return Ok(None);
    }
    let link = d.link_to(holder).await?;
    let before: Vec<_> = leases.iter().map(|o| (o.expires, o.receipt_until, o.proof)).collect();
    let mut behaved = true;

    // Stale leases (a file they served is no longer kept here) are repacked
    // instead of renewed: a new lease with only the chunks still needed, which
    // the holder already has, while the old one runs out.
    let mut gone = std::collections::HashSet::new();
    let (stale, renew): (Vec<usize>, Vec<usize>) = renew.into_iter().partition(|&i| leases[i].stale);
    for i in stale {
        if repack(d, holder, &leases[i]).await? {
            gone.insert(i);
        }
    }

    // Renewals, up to 64 per request.
    for batch in renew.chunks(MAX_BUNDLE) {
        let expires = now + d.lease_term;
        let rs: Vec<Renewal> = batch
            .iter()
            .map(|&i| Renewal::sign(&LeaseKey::derive(&d.namespace_key, &leases[i].lease.id), leases[i].lease.id, expires))
            .collect();
        let reply = d.ask(link, LEASE_ENDPOINT, encode_lease_request(&LeaseRequest::RenewMany(rs))).await?;
        let statuses = decode_lease_statuses(&reply, batch.len()).map_err(|e| e.to_string())?;
        let mut renewed = 0;
        for (&i, status) in batch.iter().zip(statuses) {
            match status {
                LeaseStatus::Accepted => {
                    leases[i].expires = expires;
                    renewed += 1;
                }
                LeaseStatus::Unknown => reoffer(d, link, &mut leases[i], expires).await?,
                other => {
                    eprintln!("lease {}: renewal refused by <{}>: {other:?}", hex(&leases[i].lease.id), hex(holder));
                    behaved = false;
                }
            }
        }
        if renewed > 0 {
            println!("upkeep <{}>: renewed {renewed} lease(s) until {expires} in one request", hex(holder));
        }
    }

    // Receipts for leases not yet covered, up to 64 per request.
    let need: Vec<usize> = (0..leases.len()).filter(|&i| !gone.contains(&i) && leases[i].receipt_until < leases[i].expires).collect();
    for batch in need.chunks(MAX_BUNDLE) {
        let ids: Vec<LeaseId> = batch.iter().map(|&i| leases[i].lease.id).collect();
        let reply = d.ask(link, RECEIPT_ENDPOINT, encode_receipt_request(&ids)).await?;
        for (&i, r) in batch.iter().zip(decode_receipt_replies(&reply, ids.len()).map_err(|e| e.to_string())?) {
            let o = &mut leases[i];
            let id = o.lease.id;
            match r {
                ReceiptReply::Receipt(r) => {
                    if r.lease_id != id || r.lease_digest != o.lease.digest() || node_destination(&r.holder) != *holder {
                        eprintln!("lease {}: bad receipt from <{}>", hex(&id), hex(holder));
                        behaved = false;
                        continue;
                    }
                    o.receipt_until = r.holds_until.min(o.expires);
                    println!("lease {}: receipt from <{}>, held until {}", hex(&id), hex(holder), o.receipt_until);
                }
                ReceiptReply::Progress { held, total } => {
                    let sent = push(d, link, &o.lease, Some(holder)).await?;
                    println!("lease {}: <{}> had {held}/{total}, pushed {sent}", hex(&id), hex(holder));
                    if sent == 0 {
                        // It answers but takes nothing (full, or broken): its loss
                        // estimate should rise so placement looks elsewhere.
                        behaved = false;
                    }
                }
                ReceiptReply::Unknown => {
                    println!("lease {}: <{}> lost the lease, offering it again", hex(&id), hex(holder));
                    let expires = o.expires.max(now + d.lease_term / 2);
                    reoffer(d, link, o, expires).await?;
                }
            }
        }
    }

    // One storage proof per holder per interval, on a random lease with a receipt.
    let receipted: Vec<usize> = (0..leases.len()).filter(|&i| !gone.contains(&i) && leases[i].receipt_until > 0).collect();
    if proof_due && !receipted.is_empty() {
        let mut rnd = [0u8; 16 + 8 + 2];
        getrandom::fill(&mut rnd).expect("OS entropy");
        let o = &mut leases[receipted[u16::from_be_bytes([rnd[24], rnd[25]]) as usize % receipted.len()]];
        let n = o.lease.entries.len();
        let nonce: [u8; 16] = rnd[..16].try_into().unwrap();
        let indices: Vec<u16> = rnd[16..24].chunks(2).map(|b| (u16::from_be_bytes([b[0], b[1]]) as usize % n) as u16).collect();
        let mut expected = Vec::new();
        for &i in &indices {
            let ct = d.store.fetch(&o.lease.entries[i as usize].0).map_err(|e| e.to_string())?;
            expected.push(ct.map(|ct| lease::prove(&nonce, &ct)));
        }
        let reply = d.ask(link, PROVE_ENDPOINT, encode_prove(&o.lease.id, &nonce, &indices)).await?;
        let answers = decode_prove_reply(&reply, indices.len()).map_err(|e| e.to_string())?;
        // Only chunks this node still has can be checked.
        let checked: Vec<bool> = expected.iter().zip(&answers).filter_map(|(e, a)| e.map(|e| Some(e) == *a)).collect();
        if !checked.is_empty() {
            o.proof = if checked.iter().all(|&ok| ok) { ProofState::Passed } else { ProofState::Failed };
            behaved &= o.proof == ProofState::Passed;
            println!("lease {}: storage proof from <{}>: {:?} ({} chunk(s))", hex(&o.lease.id), hex(holder), o.proof, checked.len());
        }
        proved.insert(*holder, Instant::now());
    }

    for (i, (o, b)) in leases.iter().zip(before).enumerate() {
        if !gone.contains(&i) && (o.expires, o.receipt_until, o.proof) != b {
            d.store.update_own_lease(o).map_err(|e| e.to_string())?;
        }
    }
    Ok(Some(behaved))
}

/// Replaces a stale lease with one over only the chunks its remaining files
/// still need (the holder has them: nothing is pushed). The old lease isn't
/// renewed and runs out. Ok(true): the old lease is no longer tracked.
async fn repack(d: &Daemon, holder: &PeerId, o: &OwnLease) -> Result<bool, String> {
    let needed: HashMap<Cid, FileRef> =
        d.store.needed_files().map_err(|e| e.to_string())?.into_iter().map(|f| (f.root, f)).collect();
    let in_lease: std::collections::HashSet<Cid> = o.lease.entries.iter().map(|(c, _)| *c).collect();
    let mut roots: HashMap<Cid, Vec<Cid>> = HashMap::new();
    let mut keep = Vec::new();
    for root in &o.roots {
        let Some(f) = needed.get(root) else { continue };
        for (cid, token) in file_chunks(&d.store, f)? {
            if in_lease.contains(&cid) {
                let r = roots.entry(cid).or_default();
                if r.is_empty() {
                    keep.push((cid, token));
                }
                r.push(*root);
            }
        }
    }
    if keep.is_empty() || lease_to(d, holder, &sorted(&keep), &roots, &[]).await? {
        println!(
            "lease {}: repacked at <{}>: {} of {} chunk(s) still needed",
            hex(&o.lease.id),
            hex(holder),
            keep.len(),
            o.lease.entries.len()
        );
        d.store.remove_own_lease(&o.lease.id).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

/// The holder lost a lease (restart without it, expiry): offer it again under
/// the same ID, with a fresh expiry, and wait for a new receipt.
async fn reoffer(d: &Daemon, link: LinkId, o: &mut OwnLease, expires: u64) -> Result<(), String> {
    let l = d.sign_lease(o.lease.id, expires, o.lease.entries.clone());
    match offer(d, link, &o.holder, &l, &[d.node_id]).await? {
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
async fn seeker(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        let forced = tokio::select! {
            _ = d.wake.notified() => true,
            _ = tick.tick() => true,
            _ = d.announced_wake.notified() => false,
        };
        // Peers announced meanwhile (each once): those we wait for are tried again now.
        let announced: Vec<PeerId> = d.announced.lock().unwrap().drain().collect();
        let mut woke = false;
        for peer in announced {
            woke |= d.store.wake_peer(&peer).unwrap_or(false);
        }
        if !forced && !woke {
            continue; // only peers we aren't waiting for
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
            d.deferred.lock().unwrap().remove(&root);
            store.need_file(&file).map_err(|e| e.to_string())?;
            serve_if_kept(d, &file)?;
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
            // Over a slow link (LoRa class), fetch it all only if it fits the budget;
            // otherwise only manifest nodes (the file is browsable, small parts
            // cross), and the rest waits for a faster path (ADR-0014).
            let q = d.quality(&hint.peer);
            let local = local_status(store, &file).local_chunks as u64 * 16 * 1024;
            let est = q.transfer_secs(file.size.saturating_sub(local));
            let nodes_only = q.slow() && est > d.slow_budget as f64;
            if nodes_only {
                if d.deferred.lock().unwrap().insert(root, est as u64).is_none() {
                    println!("seeker: {root}: ~{est:.0} s over the slow link to <{peer_hex}>; fetching the manifest only, the rest waits for a faster path");
                }
            } else {
                d.deferred.lock().unwrap().remove(&root);
            }
            // Rounds until this peer has nothing more for us (nodes reveal more wants).
            let mut progressed = false;
            for _ in 0..64 {
                let mut wants = store.wants(&root, 512).map_err(|e| e.to_string())?;
                if nodes_only {
                    wants.retain(|w| w.node);
                }
                if wants.is_empty() {
                    break;
                }
                let t0 = Instant::now();
                let pairs: Vec<(retifs_core::Cid, retifs_core::Seed)> = wants.iter().map(|w| (w.cid, w.seed)).collect();
                let round = match seek_round(&d.transport, link, &pairs, d.private_requests, Duration::from_secs(60)).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("seeker: {peer_hex}: {e}");
                        d.drop_link(&hint.peer);
                        break;
                    }
                };
                let bytes: u64 = round.got.iter().map(|(_, ct, _)| ct.len() as u64).sum();
                let _ = store.record_transfer(&hint.peer, bytes, t0.elapsed().as_millis() as u64);
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
                d.deferred.lock().unwrap().remove(&root);
                store.need_file(&file).map_err(|e| e.to_string())?;
                serve_if_kept(d, &file)?;
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

/// A NomadNet node serving a retifs namespace (ADR-0016): any node holding a
/// site (its author, or a follower of its channel) can serve it to unmodified
/// NomadNet clients, so the site stays reachable while its author is offline.
mod nomadnet {
    use super::*;

    /// `nomadnetwork.node`, announced with the node's name as app data, as NomadNet does.
    pub fn destination(identity: node::IdentitySecret, name: &'static [u8]) -> PreConfiguredDestination<'static> {
        PreConfiguredDestination::Single {
            request_endpoints: ServeMyRequestEndpoints::No,
            resource_strategy: ResourceStrategy::AcceptNone,
            maximum_request_bytes: Default::default(),
            app_name: "nomadnetwork",
            aspects: &["node"],
            identity,
            announce_app_data: name,
            proof: ProofStrategy::ProveAll,
            link_requests: LinkRequestPolicy::AcceptAll,
            ratchet: RatchetPolicy::NoRatchets,
        }
    }

    /// The NomadNet request path for a record's `path` attribute: `/x.mu` and `/page/x.mu` both serve as `/page/x.mu`.
    pub fn page_path(path: &str) -> Option<String> {
        let rel = path.strip_prefix("/page/").or_else(|| path.strip_prefix('/'))?;
        (rel.ends_with(".mu") && !rel.is_empty()).then(|| format!("/page/{rel}"))
    }

    fn str_attr<'a>(r: &'a Record, key: &str) -> Option<&'a str> {
        match r.attrs.get(key) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Pages of the namespace: request path → record.
    fn pages(store: &SlabStore, ns: &str) -> HashMap<String, Record> {
        store
            .records(ns)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| str_attr(&r, "path").and_then(page_path).map(|p| (p, r)))
            .collect()
    }

    /// A generated index when the site has none: one micron link per page.
    fn index(name: &str, pages: &HashMap<String, Record>) -> Vec<u8> {
        let mut out = format!(">{name}\n\nServed from retifs: every reader of this site can serve it.\n\n");
        if pages.is_empty() {
            out.push_str("This node is still fetching the site, or it has no pages yet. Try again shortly.\n");
        }
        let mut paths: Vec<&String> = pages.keys().collect();
        paths.sort();
        for p in paths {
            let title = str_attr(&pages[p], "title").or_else(|| str_attr(&pages[p], "name")).unwrap_or(p);
            out.push_str(&format!("`[{title}`:{p}]\n"));
        }
        out.into_bytes()
    }

    pub async fn serve(
        d: Arc<Daemon>,
        handle: PrnsNodeHandle,
        dest: DestinationHash,
        ns: String,
        site_name: String,
        mut requests: mpsc::UnboundedReceiver<(RequestPathHash, RespondToken)>,
    ) {
        let mut registered: std::collections::HashSet<String> = Default::default();
        let mut by_hash: HashMap<[u8; 16], String> = HashMap::new();
        let mut sync = tokio::time::interval(Duration::from_secs(15));
        let mut announce = tokio::time::interval(Duration::from_secs(600));
        loop {
            tokio::select! {
                _ = sync.tick() => {
                    // Register every page's path (and the index); drop paths that went away.
                    let mut want: std::collections::HashSet<String> = pages(&d.store, &ns).into_keys().collect();
                    want.insert("/page/index.mu".into());
                    for p in want.difference(&registered).cloned().collect::<Vec<_>>() {
                        match handle.register_request_path(dest, &p, RequestPolicy::AllowAll).await {
                            Ok(()) => {
                                by_hash.insert(*RequestPathHash::of(&p).as_bytes(), p.clone());
                                registered.insert(p);
                            }
                            Err(e) => eprintln!("nomadnet: register {p}: {e:?}"),
                        }
                    }
                    for p in registered.difference(&want).cloned().collect::<Vec<_>>() {
                        let _ = handle.unregister_request_path(dest, &p).await;
                        by_hash.remove(RequestPathHash::of(&p).as_bytes());
                        registered.remove(&p);
                    }
                }
                _ = announce.tick() => {
                    let _ = handle.issue(PrnsCommand::AnnounceNow(AnnounceNow {
                        destination: dest,
                        target: AnnounceTarget::AllInterfaces,
                        app_data: AnnounceAppData::Registered,
                    }));
                }
                Some((hash, token)) = requests.recv() => {
                    let Some(path) = by_hash.get(hash.as_bytes()).cloned() else { continue };
                    let store = d.store.clone();
                    let ns = ns.clone();
                    let name = site_name.clone();
                    let body = tokio::task::spawn_blocking(move || page_body(&store, &ns, &path, &name)).await.unwrap_or_default();
                    println!("nomadnet: served {} bytes", body.len());
                    handle.respond_owned_bytes(token, body);
                }
            }
        }
    }

    fn page_body(store: &SlabStore, ns: &str, path: &str, name: &str) -> Vec<u8> {
        let pages = pages(store, ns);
        match pages.get(path) {
            Some(r) => match r.blocks.first() {
                Some(b) => manifest::read_all(store, b).unwrap_or_else(|_| b"`!This page isn't available on this node yet.`!".to_vec()),
                None => b"(empty page)".to_vec(),
            },
            None if path == "/page/index.mu" => index(name, &pages),
            None => b"`!No such page.`!".to_vec(),
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn record_paths_map_to_nomadnet_pages() {
            assert_eq!(super::page_path("/index.mu").as_deref(), Some("/page/index.mu"));
            assert_eq!(super::page_path("/page/about.mu").as_deref(), Some("/page/about.mu"));
            assert_eq!(super::page_path("/blog/2026/one.mu").as_deref(), Some("/page/blog/2026/one.mu"));
            assert_eq!(super::page_path("/boat.jpg"), None);
            assert_eq!(super::page_path("relative.mu"), None);
        }
    }
}


#[cfg(test)]
mod write_session_tests {
    use super::*;

    fn session(base_len: u64) -> WriteSession {
        let path = std::env::temp_dir().join(format!("retifs-spool-test-{}-{base_len}", std::process::id()));
        let spool = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        WriteSession {
            ns: "t".into(),
            id: [0; 16],
            base: None,
            base_len,
            spool,
            path,
            extents: Default::default(),
            size: base_len,
            started: Instant::now(),
        }
    }

    /// Overlapping and adjacent writes merge; unwritten parts come from the
    /// base up to its (possibly truncated) end, then zeros.
    #[test]
    fn pieces_follow_writes_and_truncation() {
        let mut s = session(100);
        s.write_at(10, &[1; 10]).unwrap();
        s.write_at(15, &[2; 10]).unwrap(); // overlaps
        s.write_at(25, &[3; 5]).unwrap(); // adjacent
        assert_eq!(s.extents.iter().map(|(a, b)| (*a, *b)).collect::<Vec<_>>(), [(10, 30)]);
        assert_eq!(s.pieces(0..100), [(0..10, Piece::Base), (10..30, Piece::Spool), (30..100, Piece::Base)]);
        s.write_at(150, &[4; 10]).unwrap(); // past the end: a hole of zeros
        assert_eq!(s.size, 160);
        assert_eq!(
            s.pieces(90..160),
            [(90..100, Piece::Base), (100..150, Piece::Zero), (150..160, Piece::Spool)]
        );
        s.truncate(20); // cuts the base and the write
        assert_eq!(s.pieces(0..1000), [(0..10, Piece::Base), (10..20, Piece::Spool)]);
        s.write_at(40, &[5; 2]).unwrap(); // grows again: no base bytes come back
        assert_eq!(s.pieces(0..42), [(0..10, Piece::Base), (10..20, Piece::Spool), (20..40, Piece::Zero), (40..42, Piece::Spool)]);
        // The stream gives exactly those bytes.
        let mut r = SessionReader {
            pieces: s.pieces(10..42).into(),
            spool: s.spool.try_clone().unwrap(),
            base: None,
            store: Arc::new(SlabStore::open(std::env::temp_dir().join(format!("retifs-spool-store-{}", std::process::id()))).unwrap()),
        };
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        let mut want = vec![1u8; 5];
        want.extend([2u8; 5]);
        want.extend([0u8; 20]);
        want.extend([5u8; 2]);
        assert_eq!(out, want);
        let _ = std::fs::remove_file(&s.path);
    }
}
