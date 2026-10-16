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
    /// Follows a channel: keeps its latest version here, asking these nodes for updates.
    Follow { address: String, from: Vec<String> },
    /// Channels written and followed here.
    Channels,
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
