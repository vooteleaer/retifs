//! Manifests: a Merkle tree mapping byte ranges to chunks (ADR-0009, proposed).
//!
//! Nodes are sealed exactly like content chunks (same construction, same
//! convergence secret), so storage nodes can't tell them apart.
//!
//! ```text
//! node      = version (0x01) ‖ kind (0 leaf, 1 internal) ‖ u16_be count ‖ entries
//! leaf      = cid (33) ‖ seed (32) ‖ u32_be data length          69 bytes
//! internal  = cid (33) ‖ seed (32) ‖ u64_be span (bytes below)   73 bytes
//! ```
//! A fixed binary layout is canonical by construction: equal trees give equal
//! bytes, and so equal CIDs.

use std::{fmt, ops::Range, str::FromStr};

use crate::{
    chunk::{self, ChunkError, Seed, MAX_DATA},
    chunker,
    cid::{Cid, CID_LEN},
    secret::ConvergenceSecret,
    seal,
};

const VERSION: u8 = 0x01;
const KIND_LEAF: u8 = 0;
const KIND_INTERNAL: u8 = 1;
const HEADER: usize = 4;
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
}

/// A child of a node: a data chunk (in a leaf) or another node (internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEntry {
    pub cid: Cid,
    pub seed: Seed,
    /// Data bytes (leaf entry) or bytes below the child (internal entry).
    pub span: u64,
}

/// Decodes and validates an opened manifest node. `expected_span` is the
/// span its parent claimed (the file size for the root).
pub fn decode_node(plaintext: &[u8], expected_span: u64) -> Result<Node, ManifestError> {
    let (kind, entries) = decode(plaintext)?;
    if entries.iter().map(|e| e.span).sum::<u64>() != expected_span {
        return Err(ManifestError::Malformed("spans don't add up to the parent's span"));
    }
    Ok(Node {
        leaf: kind == KIND_LEAF,
        entries: entries.into_iter().map(|e| NodeEntry { cid: e.cid, seed: e.seed, span: e.span }).collect(),
    })
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

/// Chunks, seals and stores `data`, and returns its read capability.
pub fn write(store: &mut impl Store, secret: &ConvergenceSecret, data: &[u8]) -> Result<FileRef, ManifestError> {
    write_with_fanout(store, secret, data, FANOUT)
}

fn write_with_fanout(
    store: &mut impl Store,
    secret: &ConvergenceSecret,
    data: &[u8],
    fanout: usize,
) -> Result<FileRef, ManifestError> {
    let mut level = Vec::new();
    for piece in chunker::split(data) {
        let s = seal(secret, piece).expect("chunker output fits a chunk");
        store.put(s.cid, s.ciphertext).map_err(store_err)?;
        level.push(Entry { cid: s.cid, seed: s.seed, span: piece.len() as u64 });
    }

    let mut kind = KIND_LEAF;
    loop {
        let groups: Vec<&[Entry]> = if level.is_empty() { vec![&[]] } else { level.chunks(fanout).collect() };
        let mut parents = Vec::with_capacity(groups.len());
        for group in groups {
            let s = seal(secret, &encode(kind, group)).expect("a node fits a chunk");
            store.put(s.cid, s.ciphertext).map_err(store_err)?;
            parents.push(Entry { cid: s.cid, seed: s.seed, span: group.iter().map(|e| e.span).sum() });
        }
        if parents.len() == 1 {
            let root = parents[0];
            return Ok(FileRef { root: root.cid, seed: root.seed, size: root.span });
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
        read_node(store, file.root, file.seed, file.size, 0, &range, &mut out)?;
    }
    Ok(out)
}

pub fn read_all(store: &impl Store, file: &FileRef) -> Result<Vec<u8>, ManifestError> {
    read_range(store, file, 0..file.size)
}

fn read_node(
    store: &impl Store,
    cid: Cid,
    seed: Seed,
    expected_span: u64,
    base: u64,
    want: &Range<u64>,
    out: &mut Vec<u8>,
) -> Result<(), ManifestError> {
    let (kind, entries) = decode(&fetch(store, &cid, &seed)?)?;
    if entries.iter().map(|e| e.span).sum::<u64>() != expected_span {
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
                read_node(store, e.cid, e.seed, e.span, start, want, out)?;
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

fn decode(node: &[u8]) -> Result<(u8, Vec<Entry>), ManifestError> {
    let (header, body) = node.split_first_chunk::<HEADER>().ok_or(ManifestError::Malformed("short node"))?;
    let [version, kind, c0, c1] = *header;
    if version != VERSION {
        return Err(ManifestError::Malformed("unknown node version"));
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
        .map(|entries| (kind, entries))
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
        let f = write_with_fanout(&mut store, &ConvergenceSecret::personal([1; 32]), &data, 2).unwrap();
        assert_eq!(read_all(&store, &f).unwrap(), data);
        for (a, b) in [(0, 1), (12_345, 99_999), (299_000, 300_001), (599_999, 600_000)] {
            assert_eq!(read_range(&store, &f, a..b).unwrap(), &data[a as usize..b as usize]);
        }
    }

    #[test]
    fn one_byte_read_touches_one_path() {
        let data = noise(600_000, 7);
        let mut store = CountingStore::default();
        let f = write_with_fanout(&mut store, &ConvergenceSecret::personal([2; 32]), &data, 2).unwrap();
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
