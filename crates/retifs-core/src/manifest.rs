//! Manifests: a Merkle tree mapping byte ranges to chunks (ADR-0009, proposed).
//!
//! Nodes are sealed exactly like content chunks (same construction, same
//! convergence secret), so storage nodes can't tell them apart.
//!
//! ```text
//! node      = version (0x01) ‖ kind ‖ u16_be n ‖ body
//!   kind 0  leaf:      n entries of cid (33) ‖ seed (32) ‖ u32_be data length   (69 B each)
//!   kind 1  internal:  n entries of cid (33) ‖ seed (32) ‖ u64_be span          (73 B each)
//!   kind 2  inline:    n bytes of file data (only as the root, n ≤ INLINE_MAX)
//! ```
//! Inline roots make a tiny file one blob and one fetch instead of two (ADR-0013).
//!
//! **Padding (PADMÉ over the chunk count, ADR-0008):** writers add padding
//! chunks until the number of data chunks reaches the next PADMÉ value, so
//! chunk and node counts reveal only a coarse size bucket. Padding chunks are
//! full 16 KiB pieces of keyed pseudo-random data, indistinguishable from real
//! ones. The tree then covers more than the file; `FileRef::size` is the true
//! size, and readers stop there. Only the root's span may exceed the file
//! size; inner nodes are checked exactly.
//! A fixed binary layout is canonical by construction: equal trees give equal
//! bytes, and so equal CIDs.

use std::{fmt, ops::Range, str::FromStr};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    chunk::{self, ChunkError, Compression, Seed, FRAME_HEADER, MAX_DATA, OVERHEAD},
    chunker,
    cid::{Cid, CID_LEN},
    secret::ConvergenceSecret,
    seal, seal_with,
};

const VERSION: u8 = 0x01;
const KIND_LEAF: u8 = 0;
const KIND_INTERNAL: u8 = 1;
const KIND_INLINE: u8 = 2;
const HEADER: usize = 4;

/// Largest file stored inline in its root node: the node then fits the 1 KiB class.
pub const INLINE_MAX: usize = 1024 - OVERHEAD - FRAME_HEADER - HEADER;
const LEAF_ENTRY: usize = CID_LEN + 32 + 4;
const INTERNAL_ENTRY: usize = CID_LEN + 32 + 8;

/// Writer policy v1: entries per node. Not part of the format (readers accept
/// any count), but writers must agree on it for public content to converge.
/// 64 internal entries = 4 676 bytes, which seals into the 8 KiB class.
pub const FANOUT: usize = 64;

/// Where chunks live. The real implementation is the slab store (ADR-0007).
pub trait Store {
    type Error: std::error::Error;
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), Self::Error>;
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Wraps a store and records every CID written through it (to register what a
/// node serves for a file, e.g. under its serve token).
pub struct Recording<'a, S: Store> {
    pub inner: &'a mut S,
    pub cids: Vec<Cid>,
}

impl<'a, S: Store> Recording<'a, S> {
    pub fn new(inner: &'a mut S) -> Self {
        Recording { inner, cids: Vec::new() }
    }
}

impl<S: Store> Store for Recording<'_, S> {
    type Error = S::Error;
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), S::Error> {
        self.cids.push(cid);
        self.inner.put(cid, ciphertext)
    }
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, S::Error> {
        self.inner.get(cid)
    }
}

/// A file's read capability: everything needed to read it, and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileRef {
    pub root: Cid,
    pub seed: Seed,
    pub size: u64,
}

/// Text form of a read capability (draft, not yet an accepted format):
/// `retifs:1:<root cid hex>:<root seed hex>:<size>`.
impl fmt::Display for FileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "retifs:1:{}:{}:{}", self.root, hex::encode(self.seed.0), self.size)
    }
}

impl FromStr for FileRef {
    type Err = ManifestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = ManifestError::Malformed("read-cap must be retifs:1:<cid>:<seed>:<size>");
        let parts: Vec<&str> = s.trim().split(':').collect();
        let ["retifs", "1", root, seed, size] = parts.as_slice() else { return Err(bad) };
        let root: [u8; CID_LEN] = hex::decode(root).ok().and_then(|b| b.try_into().ok()).ok_or(bad.clone())?;
        let seed: [u8; 32] = hex::decode(seed).ok().and_then(|b| b.try_into().ok()).ok_or(bad.clone())?;
        Ok(FileRef {
            root: Cid::from_bytes(root).ok_or(bad.clone())?,
            seed: Seed(seed),
            size: size.parse().map_err(|_| bad)?,
        })
    }
}

/// One decoded manifest node, for fetchers that walk the tree themselves
/// (e.g. breadth-first over the network, many requests in flight).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub leaf: bool,
    pub entries: Vec<NodeEntry>,
    /// The whole file, for an inline root (then `leaf` is true and `entries` is empty).
    pub inline: Option<Vec<u8>>,
}

/// A child of a node: a data chunk (in a leaf) or another node (internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEntry {
    pub cid: Cid,
    pub seed: Seed,
    /// Data bytes (leaf entry) or bytes below the child (internal entry).
    pub span: u64,
}

/// Decodes and validates an opened inner manifest node: its children must
/// add up to `expected_span`, the span its parent claimed.
pub fn decode_node(plaintext: &[u8], expected_span: u64) -> Result<Node, ManifestError> {
    decode_checked(plaintext, expected_span, false)
}

/// Decodes and validates a root node for a file of `file_size` bytes. A
/// padded tree may cover more than the file (padding chunks at the end).
pub fn decode_root(plaintext: &[u8], file_size: u64) -> Result<Node, ManifestError> {
    decode_checked(plaintext, file_size, true)
}

fn decode_checked(plaintext: &[u8], expected_span: u64, root: bool) -> Result<Node, ManifestError> {
    match decode(plaintext)? {
        Decoded::Inline(data) => {
            if data.len() as u64 != expected_span {
                return Err(ManifestError::Malformed("inline data length differs from the file size"));
            }
            Ok(Node { leaf: true, entries: Vec::new(), inline: Some(data) })
        }
        Decoded::Entries(kind, entries) => {
            let sum = entries.iter().map(|e| e.span).sum::<u64>();
            if sum != expected_span && !(root && sum > expected_span) {
                return Err(ManifestError::Malformed("spans don't add up to the parent's span"));
            }
            Ok(Node {
                leaf: kind == KIND_LEAF,
                entries: entries.into_iter().map(|e| NodeEntry { cid: e.cid, seed: e.seed, span: e.span }).collect(),
                inline: None,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Missing(Cid),
    Chunk(Cid, ChunkError),
    Malformed(&'static str),
    OutOfRange,
    Store(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Missing(c) => write!(f, "chunk {c} not available"),
            ManifestError::Chunk(c, e) => write!(f, "chunk {c}: {e}"),
            ManifestError::Malformed(why) => write!(f, "malformed manifest: {why}"),
            ManifestError::OutOfRange => f.write_str("range outside the file"),
            ManifestError::Store(e) => write!(f, "store: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

#[derive(Clone, Copy)]
struct Entry {
    cid: Cid,
    seed: Seed,
    /// Data bytes in a leaf entry; bytes below the child in an internal entry.
    span: u64,
}

/// Options for [`write_opts`].
#[derive(Debug, Clone, Copy)]
pub struct WriteOpts {
    /// Compress data chunks before encryption (off by default: a compressed
    /// chunk's size class reveals compressibility). Manifest nodes are never compressed.
    pub compression: Compression,
    /// Pad the chunk count up to the next PADMÉ value (on by default).
    pub pad: bool,
}

impl Default for WriteOpts {
    fn default() -> Self {
        WriteOpts { compression: Compression::Off, pad: true }
    }
}

/// PADMÉ (Nikitin et al., PETS 2019): rounds `n` up so that only about
/// log2(log2 n) + 1 significant bits remain. Overhead ≤ 12 %; the value leaks
/// O(log log n) bits instead of O(log n).
pub fn padme(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let e = 63 - n.leading_zeros() as u64; // floor(log2 n)
    let s = (63 - e.leading_zeros() as u64) + 1; // floor(log2 e) + 1
    let z = e.saturating_sub(s);
    let mask = (1u64 << z) - 1;
    (n + mask) & !mask
}

/// The `index`-th padding piece of a file: keyed pseudo-random bytes, distinct
/// per file and index (distinct CIDs), and deterministic for the same data and
/// secret (so equal public files still converge).
fn padding_piece(secret: &ConvergenceSecret, digest: &[u8; 32], index: u64, len: usize) -> Vec<u8> {
    let mut k = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    k.update(b"retifs/v1/pad");
    k.update(digest);
    k.update(&index.to_be_bytes());
    let key = k.finalize().into_bytes();
    let mut out = Vec::with_capacity(len + 32);
    let mut block = 0u64;
    while out.len() < len {
        let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
        m.update(&block.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
        block += 1;
    }
    out.truncate(len);
    out
}

/// Chunks, seals and stores `data`, and returns its read capability.
pub fn write(store: &mut impl Store, secret: &ConvergenceSecret, data: &[u8]) -> Result<FileRef, ManifestError> {
    write_opts(store, secret, data, WriteOpts::default())
}

pub fn write_opts(
    store: &mut impl Store,
    secret: &ConvergenceSecret,
    data: &[u8],
    opts: WriteOpts,
) -> Result<FileRef, ManifestError> {
    write_tracked(store, secret, data, opts).map(|(file, _)| file)
}

/// Like [`write_opts`], but also returns the CID and seed of every blob written
/// (data, padding and nodes), e.g. to register per-chunk access tokens.
pub fn write_tracked(
    store: &mut impl Store,
    secret: &ConvergenceSecret,
    data: &[u8],
    opts: WriteOpts,
) -> Result<(FileRef, Vec<(Cid, Seed)>), ManifestError> {
    let mut blobs = Vec::new();
    let file = write_with_fanout(store, secret, data, FANOUT, opts, &mut blobs)?;
    Ok((file, blobs))
}

fn write_with_fanout(
    store: &mut impl Store,
    secret: &ConvergenceSecret,
    data: &[u8],
    fanout: usize,
    opts: WriteOpts,
    blobs: &mut Vec<(Cid, Seed)>,
) -> Result<FileRef, ManifestError> {
    let mut put = |store: &mut _, s: chunk::Sealed| -> Result<(Cid, Seed), ManifestError> {
        Store::put(store, s.cid, s.ciphertext).map_err(store_err)?;
        blobs.push((s.cid, s.seed));
        Ok((s.cid, s.seed))
    };

    if data.len() <= INLINE_MAX {
        let mut node = vec![VERSION, KIND_INLINE];
        node.extend_from_slice(&(data.len() as u16).to_be_bytes());
        node.extend_from_slice(data);
        let (cid, seed) = put(store, seal(secret, &node).expect("an inline node fits the 1 KiB class"))?;
        return Ok(FileRef { root: cid, seed, size: data.len() as u64 });
    }

    let mut level = Vec::new();
    for piece in chunker::split(data) {
        let (cid, seed) = put(store, seal_with(secret, piece, opts.compression).expect("chunker output fits a chunk"))?;
        level.push(Entry { cid, seed, span: piece.len() as u64 });
    }

    if opts.pad {
        let real = level.len() as u64;
        let mut h = Sha256::new();
        for e in &level {
            h.update(e.cid.as_bytes());
        }
        let digest: [u8; 32] = h.finalize().into();
        for i in 0..padme(real) - real {
            let piece = padding_piece(secret, &digest, i, chunker::MAX_SIZE as usize);
            let (cid, seed) = put(store, seal(secret, &piece).expect("a padding piece fits a chunk"))?;
            level.push(Entry { cid, seed, span: piece.len() as u64 });
        }
    }

    let mut kind = KIND_LEAF;
    loop {
        let groups: Vec<&[Entry]> = level.chunks(fanout).collect();
        let mut parents = Vec::with_capacity(groups.len());
        for group in groups {
            let (cid, seed) = put(store, seal(secret, &encode(kind, group)).expect("a node fits a chunk"))?;
            parents.push(Entry { cid, seed, span: group.iter().map(|e| e.span).sum() });
        }
        if parents.len() == 1 {
            let root = parents[0];
            return Ok(FileRef { root: root.cid, seed: root.seed, size: data.len() as u64 });
        }
        level = parents;
        kind = KIND_INTERNAL;
    }
}

/// Reads `range` of the file, fetching only the nodes and chunks it covers.
pub fn read_range(store: &impl Store, file: &FileRef, range: Range<u64>) -> Result<Vec<u8>, ManifestError> {
    if range.start > range.end || range.end > file.size {
        return Err(ManifestError::OutOfRange);
    }
    let mut out = Vec::with_capacity((range.end - range.start) as usize);
    if range.start < range.end {
        read_node(store, file.root, file.seed, file.size, true, 0, &range, &mut out)?;
    }
    Ok(out)
}

pub fn read_all(store: &impl Store, file: &FileRef) -> Result<Vec<u8>, ManifestError> {
    read_range(store, file, 0..file.size)
}

#[allow(clippy::too_many_arguments)]
fn read_node(
    store: &impl Store,
    cid: Cid,
    seed: Seed,
    expected_span: u64,
    root: bool,
    base: u64,
    want: &Range<u64>,
    out: &mut Vec<u8>,
) -> Result<(), ManifestError> {
    let (kind, entries) = match decode(&fetch(store, &cid, &seed)?)? {
        Decoded::Inline(data) => {
            if data.len() as u64 != expected_span || base != 0 {
                return Err(ManifestError::Malformed("inline node outside the root, or wrong length"));
            }
            out.extend_from_slice(&data[want.start as usize..want.end as usize]);
            return Ok(());
        }
        Decoded::Entries(kind, entries) => (kind, entries),
    };
    let sum = entries.iter().map(|e| e.span).sum::<u64>();
    if sum != expected_span && !(root && sum > expected_span) {
        return Err(ManifestError::Malformed("spans don't add up to the parent's span"));
    }
    let mut start = base;
    for e in entries {
        let end = start + e.span;
        if end > want.start && start < want.end {
            if kind == KIND_LEAF {
                let data = fetch(store, &e.cid, &e.seed)?;
                if data.len() as u64 != e.span {
                    return Err(ManifestError::Malformed("chunk length differs from its entry"));
                }
                let from = want.start.saturating_sub(start) as usize;
                let to = (want.end.min(end) - start) as usize;
                out.extend_from_slice(&data[from..to]);
            } else {
                read_node(store, e.cid, e.seed, e.span, false, start, want, out)?;
            }
        }
        if end >= want.end {
            break;
        }
        start = end;
    }
    Ok(())
}

fn fetch(store: &impl Store, cid: &Cid, seed: &Seed) -> Result<Vec<u8>, ManifestError> {
    let ct = store.get(cid).map_err(store_err)?.ok_or(ManifestError::Missing(*cid))?;
    chunk::open(cid, seed, &ct).map_err(|e| ManifestError::Chunk(*cid, e))
}

fn store_err(e: impl std::error::Error) -> ManifestError {
    ManifestError::Store(e.to_string())
}

fn encode(kind: u8, entries: &[Entry]) -> Vec<u8> {
    let width = if kind == KIND_LEAF { LEAF_ENTRY } else { INTERNAL_ENTRY };
    let count = u16::try_from(entries.len()).expect("fanout fits u16");
    let mut out = Vec::with_capacity(HEADER + entries.len() * width);
    out.extend_from_slice(&[VERSION, kind]);
    out.extend_from_slice(&count.to_be_bytes());
    for e in entries {
        out.extend_from_slice(e.cid.as_bytes());
        out.extend_from_slice(&e.seed.0);
        if kind == KIND_LEAF {
            out.extend_from_slice(&(e.span as u32).to_be_bytes());
        } else {
            out.extend_from_slice(&e.span.to_be_bytes());
        }
    }
    debug_assert!(out.len() <= MAX_DATA);
    out
}

enum Decoded {
    Entries(u8, Vec<Entry>),
    Inline(Vec<u8>),
}

fn decode(node: &[u8]) -> Result<Decoded, ManifestError> {
    let (header, body) = node.split_first_chunk::<HEADER>().ok_or(ManifestError::Malformed("short node"))?;
    let [version, kind, c0, c1] = *header;
    if version != VERSION {
        return Err(ManifestError::Malformed("unknown node version"));
    }
    if kind == KIND_INLINE {
        let len = u16::from_be_bytes([c0, c1]) as usize;
        if body.len() != len || len > INLINE_MAX {
            return Err(ManifestError::Malformed("inline node length mismatch"));
        }
        return Ok(Decoded::Inline(body.to_vec()));
    }
    let width = match kind {
        KIND_LEAF => LEAF_ENTRY,
        KIND_INTERNAL => INTERNAL_ENTRY,
        _ => return Err(ManifestError::Malformed("unknown node kind")),
    };
    let count = u16::from_be_bytes([c0, c1]) as usize;
    if body.len() != count * width {
        return Err(ManifestError::Malformed("node length doesn't match its count"));
    }
    if kind == KIND_INTERNAL && count == 0 {
        return Err(ManifestError::Malformed("empty internal node"));
    }
    body.chunks_exact(width)
        .map(|raw| {
            let cid = Cid::from_bytes(raw[..CID_LEN].try_into().unwrap())
                .ok_or(ManifestError::Malformed("unknown CID version"))?;
            let seed = Seed(raw[CID_LEN..CID_LEN + 32].try_into().unwrap());
            let tail = &raw[CID_LEN + 32..];
            let span = if kind == KIND_LEAF {
                u32::from_be_bytes(tail.try_into().unwrap()) as u64
            } else {
                u64::from_be_bytes(tail.try_into().unwrap())
            };
            Ok(Entry { cid, seed, span })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|entries| Decoded::Entries(kind, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::HashMap};

    #[derive(Default)]
    struct CountingStore {
        chunks: HashMap<Cid, Vec<u8>>,
        gets: Cell<usize>,
    }

    impl Store for CountingStore {
        type Error = std::convert::Infallible;
        fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), Self::Error> {
            self.chunks.insert(cid, ciphertext);
            Ok(())
        }
        fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
            self.gets.set(self.gets.get() + 1);
            Ok(self.chunks.get(cid).cloned())
        }
    }

    fn noise(len: usize, mut s: u64) -> Vec<u8> {
        (0..len).map(|_| { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s as u8 }).collect()
    }

    #[test]
    fn deep_tree_roundtrip_and_ranges() {
        // Fanout 2 forces a deep tree from a small file.
        let data = noise(600_000, 42);
        let mut store = CountingStore::default();
        let f = write_with_fanout(&mut store, &ConvergenceSecret::personal([1; 32]), &data, 2, WriteOpts::default(), &mut Vec::new()).unwrap();
        assert_eq!(read_all(&store, &f).unwrap(), data);
        for (a, b) in [(0, 1), (12_345, 99_999), (299_000, 300_001), (599_999, 600_000)] {
            assert_eq!(read_range(&store, &f, a..b).unwrap(), &data[a as usize..b as usize]);
        }
    }

    #[test]
    fn one_byte_read_touches_one_path() {
        let data = noise(600_000, 7);
        let mut store = CountingStore::default();
        let f = write_with_fanout(&mut store, &ConvergenceSecret::personal([2; 32]), &data, 2, WriteOpts::default(), &mut Vec::new()).unwrap();
        let chunks = chunker::split(&data).count();
        let depth = (chunks as f64).log2().ceil() as usize + 1; // node levels incl. leaves
        store.gets.set(0);
        read_range(&store, &f, 300_000..300_001).unwrap();
        assert!(store.gets.get() <= depth + 1, "{} gets for depth {depth}", store.gets.get());
    }

    #[test]
    fn rejects_inconsistent_spans() {
        let data = noise(100_000, 3);
        let mut store = CountingStore::default();
        let mut f = write(&mut store, &ConvergenceSecret::public(), &data).unwrap();
        f.size += 1;
        assert_eq!(read_range(&store, &f, 0..1).unwrap_err(),
                   ManifestError::Malformed("spans don't add up to the parent's span"));
    }
}
