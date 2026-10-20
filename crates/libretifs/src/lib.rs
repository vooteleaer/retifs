//! Client library for the retifs local API (ADR-0004, prototype).
//!
//! `retifsd` is the shared instance: it owns keys, the local store and the
//! network. Applications talk to it through this crate, over a local endpoint:
//!
//! - Unix: a socket at `<store>/retifs.sock`
//! - Windows: a named pipe `\\.\pipe\retifs-<hash of the store path>`
//!
//! Framing: `u32_be length ‖ msgpack(Envelope)`. Bulk data travels inside the
//! message for now (≤ [`MAX_FRAME`]); fd passing and per-app capabilities
//! (ADR-0004) come later.
//!
//! This crate has no Reticulum dependency, so applications stay small.

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 0;
pub const MAX_FRAME: usize = 256 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub v: u8,
    pub id: u32,
    pub msg: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Daemon identity and store size.
    Ping,
    /// The first message on the app socket: the app's token. Its requests are
    /// then limited to what the token allows (ADR-0004).
    Hello { token: String },
    /// Owner only: lets an application use the app socket with a new token
    /// (answered once, never stored), limited to `namespaces`, read-only
    /// unless `write`.
    AppAdd { name: String, namespaces: Vec<String>, write: bool },
    AppList,
    AppRemove { name: String },
    /// Chunk, encrypt and pin `data`; returns its read-cap.
    Put {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Convergent public scheme (network-wide dedup) instead of a fresh personal secret.
        public: bool,
        /// Compress data chunks before encryption (reveals compressibility via size class).
        #[serde(default)]
        compress: bool,
        /// Serve to anyone without proof (like hosting a micron page). Otherwise only
        /// holders of the read-cap can fetch it from this node.
        #[serde(default)]
        publish: bool,
        /// Record this file is a version of (ADR-0008: one secret per record, so
        /// versions dedup and different records never share CIDs). None: one-off.
        #[serde(default)]
        record: Option<String>,
    },
    /// Read the file behind `cap`: local store first, then the given nodes.
    Get {
        cap: String,
        /// retifsd destination hashes (hex). Empty: local store only.
        from: Vec<String>,
        links_per_node: usize,
        batch: usize,
    },
    /// What of `cap` is held locally.
    Status { cap: String },
    /// Bytes `offset..offset + len` of `cap` (clamped to the file). Chunks the
    /// range needs that aren't here are fetched from the peers of namespace
    /// `ns` and the file's known holders, for at most `wait_ms`; then it fails
    /// rather than hang (offline semantics, ADR-0002).
    ReadRange {
        cap: String,
        #[serde(default)]
        ns: Option<String>,
        offset: u64,
        len: u64,
        wait_ms: u64,
    },
    /// Seek `cap` in the background until it's complete (ADR-0010): ask the
    /// given nodes now, and again whenever they announce, with back-off.
    Want {
        cap: String,
        /// retifsd destination hashes (hex) to ask.
        from: Vec<String>,
    },
    /// Keep own file `cap` on other nodes (ADR-0011): offer each a signed
    /// lease over its chunks; they pull the chunks and return receipts. The
    /// daemon renews the leases and checks storage proofs from then on.
    Replicate {
        cap: String,
        /// retifsd destination hashes (hex) of the holders.
        to: Vec<String>,
    },
    /// This node no longer needs `cap` kept (ADR-0014): stop seeking it, stop
    /// renewing its leases (holders release it when they run out), and make
    /// its local chunks evictable, except those other needed files share.
    Forget { cap: String },
    /// Creates a channel this node writes (ADR-0015); returns its address.
    ChannelCreate { name: String },
    /// Publishes `data` as the channel's next version: followers update to it.
    ChannelPublish {
        name: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        #[serde(default)]
        compress: bool,
    },
    /// Publishes a snapshot of namespace `ns` as the channel's next version
    /// (ADR-0016): followers rebuild the namespace and fetch its content.
    ChannelPublishNs { name: String, ns: String },
    /// Follows a channel: keeps its latest version here, asking these nodes for updates.
    Follow { address: String, from: Vec<String> },
    /// Channels written and followed here.
    Channels,
    /// The namespaces with records here (own, joined and followed).
    Namespaces,
    /// Creates a record in namespace `ns` (ADR-0016); `data` becomes its content block.
    RecordCreate {
        ns: String,
        attrs: Vec<(String, AttrValue)>,
        #[serde(default, with = "serde_bytes")]
        data: Option<Vec<u8>>,
    },
    /// Sets and unsets attributes of a record; `data`, if given, replaces its
    /// content (and `size`), in the same commit.
    RecordSet {
        ns: String,
        id: String,
        attrs: Vec<(String, AttrValue)>,
        unset: Vec<String>,
        #[serde(default, with = "serde_bytes")]
        data: Option<Vec<u8>>,
    },
    RecordGet { ns: String, id: String },
    RecordDelete { ns: String, id: String },
    /// Waits until namespace `ns` changes (a local write, or other members'
    /// writes merged in), for at most `timeout_ms`. `since` is the change
    /// count from the previous answer (0 at first: answers at once). The
    /// answer is the current count; equal to `since` means nothing changed.
    Watch { ns: String, since: u64, timeout_ms: u64 },
    /// Starts writing record `id`'s content in place, without sending it whole:
    /// a write session (`WriteAt`, `WriteRead`, `WriteTruncate`, then
    /// `WriteCommit` or `WriteAbort`). The daemon spools written ranges to
    /// disk; unwritten ranges keep the record's current content (or none, with
    /// `truncate`). Answers with the session and the content's current size.
    WriteBegin { ns: String, id: String, truncate: bool },
    WriteAt {
        session: u64,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// Reads the session's content as it would be committed now.
    WriteRead { session: u64, offset: u64, len: u64 },
    WriteTruncate { session: u64, size: u64 },
    /// Stores the new content (streamed, never whole in memory) and commits
    /// it with `attrs` as one version.
    WriteCommit { session: u64, attrs: Vec<(String, AttrValue)> },
    WriteAbort { session: u64 },
    /// Several changes as one commit (one version): other members see all of
    /// them or none. Returns the created and changed records, in step order.
    Transaction { ns: String, steps: Vec<TxStep> },
    /// Records matching every term (`key=value`, `key>n`, `key^=prefix`, `has:key`, …),
    /// now or as of version `at` of the namespace.
    Query {
        ns: String,
        terms: Vec<String>,
        #[serde(default)]
        at: Option<u64>,
    },
    /// Every version of a record, newest first (ADR-0006: every modification is a version).
    RecordHistory { ns: String, id: String },
    /// The namespace's address: lets others read it, and join it if granted (ADR-0017).
    NsAddress { ns: String },
    /// Joins another's namespace under local name `ns`, with a new writer key
    /// (returned; the creator grants it). `from`: other members' nodes.
    NsJoin { ns: String, address: String, from: Vec<String> },
    /// Grants a writer key `write` (and `grant` if asked); `from`: its node, to sync with.
    /// `keys` limits the writer to those attribute keys (`@content`,
    /// `@delete` for content and deletion); `until` (ms since the epoch) ends
    /// the grant. Both empty: no limits.
    NsGrant {
        ns: String,
        writer: String,
        grant: bool,
        from: Vec<String>,
        #[serde(default)]
        keys: Vec<String>,
        #[serde(default)]
        until: Option<u64>,
    },
    NsRevoke { ns: String, writer: String },
    NsInfo { ns: String },
    /// What this node keeps of the namespace's content (ADR-0005): `all`, or
    /// `rules` (records tagged `keep`/`keep:<device>` or matched by a keep rule).
    NsKeep { ns: String, mode: String },
    /// Writes a checkpoint of the namespace now and, if this node holds
    /// `grant`, names it in its chain for new members (ADR-0018).
    NsCheckpoint { ns: String },
    /// Fetches the namespace's whole history and checks the checkpoint this
    /// node started from against it (ADR-0018).
    NsVerify { ns: String },
}

/// An attribute value (ADR-0016).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttrValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
    List(Vec<AttrValue>),
}

impl std::fmt::Display for AttrValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttrValue::Null => f.write_str("null"),
            AttrValue::Bool(b) => write!(f, "{b}"),
            AttrValue::Int(i) => write!(f, "{i}"),
            AttrValue::Float(x) => write!(f, "{x:?}"),
            AttrValue::Str(s) => write!(f, "{s:?}"),
            AttrValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            AttrValue::List(items) => {
                f.write_str("[")?;
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
        }
    }
}

/// An application allowed on the app socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppInfo {
    pub name: String,
    pub namespaces: Vec<String>,
    pub write: bool,
    /// The executable its token is pinned to (Linux), once used.
    pub exe: Option<String>,
}

/// One step of a [`Request::Transaction`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum TxStep {
    Create {
        attrs: Vec<(String, AttrValue)>,
        #[serde(default, with = "serde_bytes")]
        data: Option<Vec<u8>>,
    },
    Set {
        id: String,
        attrs: Vec<(String, AttrValue)>,
        unset: Vec<String>,
        #[serde(default, with = "serde_bytes")]
        data: Option<Vec<u8>>,
        /// New content by reference (read capabilities of files already
        /// stored), instead of `data`: e.g. another record's content.
        #[serde(default)]
        blocks: Option<Vec<String>>,
    },
    Delete {
        id: String,
    },
}

/// A multi-writer namespace as this node sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NsView {
    pub name: String,
    pub address: String,
    /// This node's writer key for it (64 hex digits).
    pub own_writer: String,
    /// Writers with their rights ("grant", "write"), from the merged grants.
    pub writers: Vec<(String, Vec<String>)>,
    pub records: usize,
    pub peers: usize,
    /// The latest checkpoint kept here (a read capability), if any.
    #[serde(default)]
    pub checkpoint: Option<String>,
    /// This device's name for keep tags and rules.
    #[serde(default)]
    pub device: String,
    /// "all" or "rules".
    #[serde(default)]
    pub keep: String,
    /// Files pulled here because they're kept.
    #[serde(default)]
    pub kept: usize,
}

/// One version of a namespace as seen by one record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntry {
    pub version: u64,
    pub time_ms: u64,
    /// The record at that version; None: it didn't exist (or was deleted).
    pub record: Option<RecordView>,
}

/// A record as the API shows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordView {
    /// 32 hex digits.
    pub id: String,
    pub attrs: Vec<(String, AttrValue)>,
    /// Read-caps of its content blocks.
    pub blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong {
        node: String,
        chunks: u64,
        #[serde(default)]
        usage: Option<StoreUsage>,
    },
    Put {
        cap: String,
    },
    Get {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        stats: GetStats,
    },
    Status(Status),
    Channel {
        address: String,
    },
    Published {
        seq: u64,
        cap: String,
    },
    Channels {
        own: Vec<ChannelInfo>,
        follows: Vec<FollowInfo>,
    },
    Records {
        records: Vec<RecordView>,
    },
    History {
        entries: Vec<HistoryEntry>,
    },
    Namespace(NsView),
    Range {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Changed {
        /// The namespace's change count on this node.
        count: u64,
    },
    Session {
        session: u64,
        size: u64,
    },
    Names {
        names: Vec<String>,
    },
    Done,
    AppToken {
        token: String,
    },
    Apps {
        apps: Vec<AppInfo>,
    },
    Verified {
        ok: bool,
        detail: String,
    },
    Error {
        message: String,
    },
}

/// A channel this node writes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelInfo {
    pub name: String,
    pub address: String,
    pub seq: u64,
}

/// A channel this node follows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FollowInfo {
    pub address: String,
    pub seq: u64,
    /// Read-cap of the version kept here.
    pub current: Option<String>,
    /// That version is completely local.
    pub complete: bool,
    /// The local namespace a snapshot version is rebuilt into.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// Disk usage per tier and the resolved budget (ADR-0012), in bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreUsage {
    pub pinned: u64,
    pub leased: u64,
    pub cache: u64,
    pub spare: u64,
    pub store_limit: u64,
    pub reserve: u64,
    pub cache_max: u64,
    pub disk_total: u64,
    pub disk_available: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetStats {
    pub chunks: usize,
    pub from_local: usize,
    pub requests: usize,
    pub retries: usize,
    pub network_bytes: u64,
    pub links: usize,
    /// Time spent finding paths and opening links.
    pub connect_millis: u64,
    /// Time spent fetching (local store and network).
    pub millis: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub size: u64,
    /// Data chunks held locally.
    pub local_chunks: usize,
    /// Total data chunks, if every manifest node is held locally.
    pub total_chunks: Option<usize>,
    /// Manifest nodes needed to see the whole tree but not held locally.
    pub missing_nodes: usize,
    /// Still being sought in the background.
    #[serde(default)]
    pub seeking: bool,
    /// Peers known to ask for it.
    #[serde(default)]
    pub holders_known: usize,
    /// Nodes this daemon leased the file to.
    #[serde(default)]
    pub leased_to: usize,
    /// Of those, nodes with a valid receipt for every lease and no failed
    /// storage proof: confirmed copies besides this one.
    #[serde(default)]
    pub replicas: usize,
    /// The only known holders are behind slow links (LoRa) and the rest would
    /// take about this many seconds over them: only manifest nodes are fetched,
    /// the rest waits for a faster path (ADR-0014).
    #[serde(default)]
    pub slow_link_wait_secs: Option<u64>,
}

impl Status {
    pub fn complete(&self) -> bool {
        self.total_chunks == Some(self.local_chunks)
    }
}

/// Where the daemon keeps its store (and endpoint) unless told otherwise:
/// `$RETIFS_STORE`, else `$XDG_DATA_HOME/retifs` or `~/.local/share/retifs`
/// (Unix), `%LOCALAPPDATA%\retifs` (Windows).
pub fn default_store_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("RETIFS_STORE") {
        return dir.into();
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| ".".into());
        base.join("retifs")
    }
    #[cfg(not(windows))]
    {
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(data).join("retifs");
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| ".".into());
        home.join(".local/share/retifs")
    }
}

/// The local endpoint for the daemon owning `store`.
/// The app socket: applications connect here with a token (`Hello`) and get
/// only what it allows (ADR-0004). The owner's endpoint is [`endpoint`].
pub fn app_endpoint(store: &Path) -> String {
    #[cfg(windows)]
    {
        endpoint(store).replace(r"\\.\pipe\retifs-", r"\\.\pipe\retifs-apps-")
    }
    #[cfg(not(windows))]
    {
        store.join("apps.sock").to_string_lossy().into_owned()
    }
}

pub fn endpoint(store: &Path) -> String {
    #[cfg(windows)]
    {
        let abs = std::path::absolute(store).unwrap_or_else(|_| store.to_path_buf());
        let key = abs.to_string_lossy().to_lowercase();
        // FNV-1a: stable across processes and Rust versions.
        let hash = key.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3));
        format!(r"\\.\pipe\retifs-{hash:016x}")
    }
    #[cfg(not(windows))]
    {
        store.join("retifs.sock").to_string_lossy().into_owned()
    }
}

pub async fn write_frame<T: Serialize>(w: &mut (impl AsyncWrite + Unpin), msg: &T) -> io::Result<()> {
    let body = rmp_serde::to_vec_named(msg).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "message exceeds MAX_FRAME"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Reads one frame; `Ok(None)` on a clean end of stream.
pub async fn read_frame<T: for<'de> Deserialize<'de>>(r: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds MAX_FRAME"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    rmp_serde::from_slice(&body).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(not(windows))]
type Stream = tokio::net::UnixStream;

/// A connection to the local retifsd.
pub struct Client {
    stream: Stream,
    next_id: u32,
}

#[derive(Debug)]
pub enum ClientError {
    /// No daemon at the endpoint (not running, or another store).
    NotRunning(String, io::Error),
    Io(io::Error),
    Daemon(String),
    Unexpected,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::NotRunning(at, e) => write!(f, "no retifsd at {at} ({e}); start it first"),
            ClientError::Io(e) => write!(f, "local API: {e}"),
            ClientError::Daemon(m) => write!(f, "retifsd: {m}"),
            ClientError::Unexpected => f.write_str("unexpected response from retifsd"),
        }
    }
}

impl std::error::Error for ClientError {}

impl Client {
    /// Connects to the daemon owning `store` (see [`default_store_dir`]).
    pub async fn connect(store: &Path) -> Result<Self, ClientError> {
        let at = endpoint(store);
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(&at);
        #[cfg(not(windows))]
        let stream = tokio::net::UnixStream::connect(&at).await;
        let stream = stream.map_err(|e| ClientError::NotRunning(at, e))?;
        Ok(Client { stream, next_id: 1 })
    }

    /// Connects to the app socket as an application with `token`: requests
    /// are limited to what the token allows.
    pub async fn connect_app(store: &Path, token: &str) -> Result<Self, ClientError> {
        let at = app_endpoint(store);
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(&at);
        #[cfg(not(windows))]
        let stream = tokio::net::UnixStream::connect(&at).await;
        let stream = stream.map_err(|e| ClientError::NotRunning(at, e))?;
        let mut client = Client { stream, next_id: 1 };
        match client.call(Request::Hello { token: token.to_string() }).await? {
            Response::Done => Ok(client),
            Response::Error { message } => Err(ClientError::Daemon(message)),
            _ => Err(ClientError::Daemon("unexpected answer to Hello".into())),
        }
    }

    pub async fn call(&mut self, msg: Request) -> Result<Response, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        write_frame(&mut self.stream, &Envelope { v: PROTOCOL_VERSION, id, msg }).await.map_err(ClientError::Io)?;
        let reply: Envelope<Response> = read_frame(&mut self.stream)
            .await
            .map_err(ClientError::Io)?
            .ok_or_else(|| ClientError::Io(io::ErrorKind::UnexpectedEof.into()))?;
        match reply.msg {
            Response::Error { message } => Err(ClientError::Daemon(message)),
            other if reply.id == id => Ok(other),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn ping(&mut self) -> Result<(String, u64, Option<StoreUsage>), ClientError> {
        match self.call(Request::Ping).await? {
            Response::Pong { node, chunks, usage } => Ok((node, chunks, usage)),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn put(
        &mut self,
        data: Vec<u8>,
        public: bool,
        compress: bool,
        publish: bool,
        record: Option<String>,
    ) -> Result<String, ClientError> {
        match self.call(Request::Put { data, public, compress, publish, record }).await? {
            Response::Put { cap } => Ok(cap),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn get(
        &mut self,
        cap: &str,
        from: &[String],
        links_per_node: usize,
        batch: usize,
    ) -> Result<(Vec<u8>, GetStats), ClientError> {
        let req = Request::Get { cap: cap.into(), from: from.to_vec(), links_per_node, batch };
        match self.call(req).await? {
            Response::Get { data, stats } => Ok((data, stats)),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn want(&mut self, cap: &str, from: &[String]) -> Result<Status, ClientError> {
        match self.call(Request::Want { cap: cap.into(), from: from.to_vec() }).await? {
            Response::Status(s) => Ok(s),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn status(&mut self, cap: &str) -> Result<Status, ClientError> {
        match self.call(Request::Status { cap: cap.into() }).await? {
            Response::Status(s) => Ok(s),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn channel_create(&mut self, name: &str) -> Result<String, ClientError> {
        match self.call(Request::ChannelCreate { name: name.into() }).await? {
            Response::Channel { address } => Ok(address),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn channel_publish(&mut self, name: &str, data: Vec<u8>, compress: bool) -> Result<(u64, String), ClientError> {
        match self.call(Request::ChannelPublish { name: name.into(), data, compress }).await? {
            Response::Published { seq, cap } => Ok((seq, cap)),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn follow(&mut self, address: &str, from: &[String]) -> Result<(Vec<ChannelInfo>, Vec<FollowInfo>), ClientError> {
        match self.call(Request::Follow { address: address.into(), from: from.to_vec() }).await? {
            Response::Channels { own, follows } => Ok((own, follows)),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn channels(&mut self) -> Result<(Vec<ChannelInfo>, Vec<FollowInfo>), ClientError> {
        match self.call(Request::Channels).await? {
            Response::Channels { own, follows } => Ok((own, follows)),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn records(&mut self, req: Request) -> Result<Vec<RecordView>, ClientError> {
        match self.call(req).await? {
            Response::Records { records } => Ok(records),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn forget(&mut self, cap: &str) -> Result<Status, ClientError> {
        match self.call(Request::Forget { cap: cap.into() }).await? {
            Response::Status(s) => Ok(s),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn replicate(&mut self, cap: &str, to: &[String]) -> Result<Status, ClientError> {
        match self.call(Request::Replicate { cap: cap.into(), to: to.to_vec() }).await? {
            Response::Status(s) => Ok(s),
            _ => Err(ClientError::Unexpected),
        }
    }
}
