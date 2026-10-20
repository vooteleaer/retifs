//! Prolly trees (ADR-0018): a sorted map from fixed-length keys (record IDs
//! for namespace state; token ‖ entry for the blind index, ADR-0019) to
//! canonical bytes, stored as sealed chunks, whose shape depends only on the keys.
//!
//! ```text
//! leaf     = { "entries": [ [ key (bin K), value (canonical msgpack, embedded) ], … ], "level": 0 }
//! internal = { "children": [ [ first key (bin K), cid (bin 33), seed (bin 32) ], … ], "level": n }
//! a node ends after the entry (child) with key k at level L if
//!     u32_be(SHA-256("retifs/v1/prolly" ‖ L ‖ k)[0..4]) < 2^32 / FANOUT,
//! or once it holds MAX_NODE bytes of entries
//! ```
//! - Equal key sets give equal shapes, so two versions of a namespace share
//!   every subtree that didn't change, and a diff skips those by CID.
//! - Nodes are sealed like any chunk (ADR-0008) under the caller's
//!   convergence secret, so holders stay blind.

use sha2::{Digest, Sha256};

use crate::{
    chunk::{open, seal, Seed},
    cid::Cid,
    manifest::Store,
    record::{write_array_len, write_bin, write_int, write_map_len, write_str, Reader, RecordError, RecordId, Value},
    secret::ConvergenceSecret,
};

/// Average entries (children) per node.
pub const FANOUT: u32 = 32;
/// A node is closed once its entries reach this many bytes (well under a chunk).
pub const MAX_NODE: usize = 64 * 1024;
const LABEL: &[u8] = b"retifs/v1/prolly";

/// A tree's root node.
pub type Root = (Cid, Seed);
/// Entries by key: record ID and its canonical msgpack value.
pub type Entries = Vec<(RecordId, Vec<u8>)>;
/// Entries with keys of another length (e.g. the blind index's 32 bytes).
pub type KeyedEntries<const K: usize> = Vec<([u8; K], Vec<u8>)>;
/// Entries as raw keys and values (prefix scans).
pub type RawEntries = Vec<(Vec<u8>, Vec<u8>)>;
/// The longest key a node may carry.
const MAX_KEY: usize = 64;

#[derive(Debug)]
pub enum TreeError<E> {
    Store(E),
    Missing(Cid),
    Corrupt(&'static str),
}

impl<E: std::fmt::Display> std::fmt::Display for TreeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::Store(e) => write!(f, "store: {e}"),
            TreeError::Missing(c) => write!(f, "tree node {c} isn't here"),
            TreeError::Corrupt(m) => write!(f, "tree node: {m}"),
        }
    }
}

fn boundary(level: u8, key: &[u8]) -> bool {
    let h = Sha256::digest([LABEL, &[level], key].concat());
    (u32::from_be_bytes(h[..4].try_into().unwrap()) as u64) < (1u64 << 32) / FANOUT as u64
}

/// Splits items into nodes by the boundary rule.
fn chunk<T, const K: usize>(level: u8, items: Vec<([u8; K], T)>, size: impl Fn(&T) -> usize) -> Vec<Vec<([u8; K], T)>> {
    let mut nodes = Vec::new();
    let mut cur = Vec::new();
    let mut bytes = 0;
    for (k, v) in items {
        bytes += size(&v) + K;
        cur.push((k, v));
        if boundary(level, &k) || bytes >= MAX_NODE {
            nodes.push(std::mem::take(&mut cur));
            bytes = 0;
        }
    }
    if !cur.is_empty() {
        nodes.push(cur);
    }
    nodes
}

fn encode_leaf<const K: usize>(entries: &[([u8; K], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, 2);
    write_str(&mut out, "entries");
    write_array_len(&mut out, entries.len());
    for (k, v) in entries {
        write_array_len(&mut out, 2);
        write_bin(&mut out, k);
        out.extend_from_slice(v);
    }
    write_str(&mut out, "level");
    write_int(&mut out, 0);
    out
}

fn encode_internal<const K: usize>(level: u8, children: &[([u8; K], Root)]) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, 2);
    write_str(&mut out, "children");
    write_array_len(&mut out, children.len());
    for (k, (cid, seed)) in children {
        write_array_len(&mut out, 3);
        write_bin(&mut out, k);
        write_bin(&mut out, cid.as_bytes());
        write_bin(&mut out, &seed.0);
    }
    write_str(&mut out, "level");
    write_int(&mut out, level as i64);
    out
}

/// Builds the tree of `entries` (sorted by key, unique). Returns its root, or
/// None for an empty map. Values must be canonical msgpack.
pub fn build<S: Store, const K: usize>(
    store: &mut S,
    secret: &ConvergenceSecret,
    entries: KeyedEntries<K>,
) -> Result<Option<Root>, TreeError<S::Error>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut put = |bytes: Vec<u8>| -> Result<Root, TreeError<S::Error>> {
        let sealed = seal(secret, &bytes).map_err(|_| TreeError::Corrupt("node too large"))?;
        store.put(sealed.cid, sealed.ciphertext).map_err(TreeError::Store)?;
        Ok((sealed.cid, sealed.seed))
    };
    let mut level: Vec<([u8; K], Root)> = Vec::new();
    for node in chunk(0, entries, |v| v.len()) {
        let first = node[0].0;
        level.push((first, put(encode_leaf(&node))?));
    }
    let mut height = 0u8;
    while level.len() > 1 {
        height += 1;
        let mut next = Vec::new();
        for node in chunk(height, level, |_| K + 65) {
            let first = node[0].0;
            next.push((first, put(encode_internal(height, &node))?));
        }
        level = next;
    }
    Ok(Some(level[0].1))
}

/// A decoded node; keys of any length up to `MAX_KEY` (the typed API checks K).
enum Node {
    Leaf(Vec<(Vec<u8>, Vec<u8>)>),
    Internal(Vec<(Vec<u8>, Root)>),
}

fn read_node<S: Store>(store: &S, root: &Root) -> Result<Node, TreeError<S::Error>> {
    let (cid, seed) = root;
    let ct = store.get(cid).map_err(TreeError::Store)?.ok_or(TreeError::Missing(*cid))?;
    let pt = open(cid, seed, &ct).map_err(|_| TreeError::Corrupt("doesn't open"))?;
    decode_node(&pt).map_err(|_| TreeError::Corrupt("malformed"))
}

fn decode_node(bytes: &[u8]) -> Result<Node, RecordError> {
    let mut r = Reader(bytes);
    if r.map_len()? != 2 {
        return Err(RecordError::Malformed("node fields"));
    }
    let node = match r.str()?.as_str() {
        "entries" => {
            let n = r.array_len()?;
            let mut entries = Vec::with_capacity(n.min(1 << 12));
            for _ in 0..n {
                if r.array_len()? != 2 {
                    return Err(RecordError::Malformed("entry"));
                }
                let k = key(&r.bin()?)?;
                entries.push((k, any_value(&mut r)?.to_vec()));
            }
            Node::Leaf(entries)
        }
        "children" => {
            let n = r.array_len()?;
            let mut children = Vec::with_capacity(n.min(1 << 12));
            for _ in 0..n {
                if r.array_len()? != 3 {
                    return Err(RecordError::Malformed("child"));
                }
                let k = key(&r.bin()?)?;
                let cid = Cid::from_bytes(r.bin()?.try_into().map_err(|_| RecordError::Malformed("cid"))?)
                    .ok_or(RecordError::Malformed("CID version"))?;
                let seed = Seed(r.bin()?.try_into().map_err(|_| RecordError::Malformed("seed"))?);
                children.push((k, (cid, seed)));
            }
            Node::Internal(children)
        }
        _ => return Err(RecordError::Malformed("node kind")),
    };
    if r.str()? != "level" {
        return Err(RecordError::Malformed("node level"));
    }
    let leaf = matches!(node, Node::Leaf(_));
    match r.value(0)? {
        Value::Int(0) if leaf => {}
        Value::Int(l) if !leaf && (1..=255).contains(&l) => {}
        _ => return Err(RecordError::Malformed("node level")),
    }
    if !r.0.is_empty() {
        return Err(RecordError::Malformed("trailing bytes"));
    }
    Ok(node)
}

fn key(b: &[u8]) -> Result<Vec<u8>, RecordError> {
    if b.is_empty() || b.len() > MAX_KEY {
        return Err(RecordError::Malformed("key"));
    }
    Ok(b.to_vec())
}

/// Reads one msgpack value of any kind, maps included (stamped records are
/// maps; `Reader::value` reads only attribute values), returning its bytes.
fn any_value<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], RecordError> {
    let start = r.0;
    skip_any(r, 0)?;
    Ok(&start[..start.len() - r.0.len()])
}

fn skip_any(r: &mut Reader, depth: usize) -> Result<(), RecordError> {
    if depth > 32 {
        return Err(RecordError::Malformed("nesting too deep"));
    }
    let t = *r.0.first().ok_or(RecordError::Malformed("truncated"))?;
    match t {
        0x80..=0x8f | 0xde | 0xdf => {
            let n = r.map_len()?;
            for _ in 0..n {
                skip_any(r, depth + 1)?;
                skip_any(r, depth + 1)?;
            }
        }
        0x90..=0x9f | 0xdc | 0xdd => {
            let n = r.array_len()?;
            for _ in 0..n {
                skip_any(r, depth + 1)?;
            }
        }
        _ => {
            r.value(depth)?;
        }
    }
    Ok(())
}

/// The value stored under `key`, if any.
pub fn get<S: Store, const K: usize>(store: &S, root: &Root, key: &[u8; K]) -> Result<Option<Vec<u8>>, TreeError<S::Error>> {
    let mut node = read_node(store, root)?;
    loop {
        match node {
            Node::Leaf(entries) => return Ok(entries.into_iter().find(|(k, _)| k.as_slice() == key.as_slice()).map(|(_, v)| v)),
            Node::Internal(children) => {
                let Some((_, child)) = children.iter().rev().find(|(first, _)| first.as_slice() <= key.as_slice()) else { return Ok(None) };
                node = read_node(store, child)?;
            }
        }
    }
}

/// Every entry, by key.
pub fn read_all<S: Store, const K: usize>(store: &S, root: &Root) -> Result<KeyedEntries<K>, TreeError<S::Error>> {
    let mut out = Vec::new();
    for leaf in leaves(store, root)? {
        if let Node::Leaf(entries) = read_node(store, &leaf)? {
            for (k, v) in entries {
                out.push((k.as_slice().try_into().map_err(|_| TreeError::Corrupt("key length"))?, v));
            }
        }
    }
    Ok(out)
}

/// The first node on `key`'s path from the root that isn't in the store, if
/// any: fetching it and asking again walks the path down (partial state,
/// a member that holds only the records it needs, ADR-0018).
pub fn missing_on_path<S: Store>(store: &S, root: &Root, key: &[u8]) -> Result<Option<Root>, TreeError<S::Error>> {
    let mut at = *root;
    loop {
        if store.get(&at.0).map_err(TreeError::Store)?.is_none() {
            return Ok(Some(at));
        }
        match read_node(store, &at)? {
            Node::Leaf(_) => return Ok(None),
            Node::Internal(children) => {
                let Some((_, child)) = children.iter().rev().find(|(first, _)| first.as_slice() <= key).or(children.first()) else {
                    return Ok(None);
                };
                at = *child;
            }
        }
    }
}

/// Every entry in the leaves held here, skipping subtrees that aren't (a
/// partial state: each leaf held is complete, so its records are exact).
pub fn read_present<S: Store, const K: usize>(store: &S, root: &Root) -> Result<KeyedEntries<K>, TreeError<S::Error>> {
    let mut out: KeyedEntries<K> = Vec::new();
    let mut stack = vec![*root];
    while let Some(n) = stack.pop() {
        if store.get(&n.0).map_err(TreeError::Store)?.is_none() {
            continue;
        }
        match read_node(store, &n)? {
            Node::Leaf(entries) => {
                for (k, v) in entries {
                    out.push((k.as_slice().try_into().map_err(|_| TreeError::Corrupt("key length"))?, v));
                }
            }
            Node::Internal(children) => stack.extend(children.into_iter().rev().map(|(_, c)| c)),
        }
    }
    out.sort_by_key(|(k, _)| *k);
    Ok(out)
}

/// Every entry whose key starts with `prefix`, by key, reading only the
/// nodes that can hold such keys (a blind index lookup, ADR-0019).
pub fn scan_prefix<S: Store>(store: &S, root: &Root, prefix: &[u8]) -> Result<RawEntries, TreeError<S::Error>> {
    let mut out = Vec::new();
    let mut stack = vec![*root];
    while let Some(n) = stack.pop() {
        match read_node(store, &n)? {
            Node::Leaf(entries) => out.extend(entries.into_iter().filter(|(k, _)| k.starts_with(prefix))),
            Node::Internal(children) => {
                // Child i holds keys from its first key up to the next child's.
                let mut take = Vec::new();
                for (i, (first, child)) in children.iter().enumerate() {
                    let starts_before_end = first.starts_with(prefix) || first.as_slice() < prefix;
                    let ends_after_start = children.get(i + 1).is_none_or(|(next, _)| next.as_slice() > prefix);
                    if starts_before_end && ends_after_start {
                        take.push(*child);
                    }
                }
                stack.extend(take.into_iter().rev());
            }
        }
    }
    Ok(out)
}

/// Every node of the tree (its chunks), root first.
pub fn nodes<S: Store>(store: &S, root: &Root) -> Result<Vec<Root>, TreeError<S::Error>> {
    let mut out = vec![*root];
    let mut i = 0;
    while i < out.len() {
        if let Node::Internal(children) = read_node(store, &out[i])? {
            out.extend(children.into_iter().map(|(_, c)| c));
        }
        i += 1;
    }
    Ok(out)
}

/// Nodes not in `store` whose parent is (or the root): what to fetch next to
/// hold the whole tree.
pub fn missing<S: Store>(store: &S, root: &Root) -> Result<Vec<Root>, TreeError<S::Error>> {
    let mut out = Vec::new();
    let mut stack = vec![*root];
    while let Some(n) = stack.pop() {
        if store.get(&n.0).map_err(TreeError::Store)?.is_none() {
            out.push(n);
        } else if let Node::Internal(children) = read_node(store, &n)? {
            stack.extend(children.into_iter().map(|(_, c)| c));
        }
    }
    Ok(out)
}

/// The leaf nodes under `root`, in key order (reads only internal nodes).
fn leaves<S: Store>(store: &S, root: &Root) -> Result<Vec<Root>, TreeError<S::Error>> {
    match read_node(store, root)? {
        Node::Leaf(_) => Ok(vec![*root]),
        Node::Internal(children) => {
            let mut out = Vec::new();
            for (_, c) in children {
                out.extend(leaves(store, &c)?);
            }
            Ok(out)
        }
    }
}

/// Keys whose entries differ between two trees (added, removed or changed).
/// Leaves both trees share (same CID) aren't read at all.
pub fn diff<S: Store>(store: &S, a: Option<&Root>, b: Option<&Root>) -> Result<Vec<RecordId>, TreeError<S::Error>> {
    let la = a.map(|r| leaves(store, r)).transpose()?.unwrap_or_default();
    let lb = b.map(|r| leaves(store, r)).transpose()?.unwrap_or_default();
    let ca: std::collections::HashSet<Cid> = la.iter().map(|(c, _)| *c).collect();
    let cb: std::collections::HashSet<Cid> = lb.iter().map(|(c, _)| *c).collect();
    let mut ea = std::collections::BTreeMap::new();
    let mut eb = std::collections::BTreeMap::new();
    for leaf in la.iter().filter(|(c, _)| !cb.contains(c)) {
        if let Node::Leaf(entries) = read_node(store, leaf)? {
            ea.extend(entries);
        }
    }
    for leaf in lb.iter().filter(|(c, _)| !ca.contains(c)) {
        if let Node::Leaf(entries) = read_node(store, leaf)? {
            eb.extend(entries);
        }
    }
    let mut keys: Vec<Vec<u8>> = ea.keys().chain(eb.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| ea.get(k) != eb.get(k))
        .map(|k| k.as_slice().try_into().map_err(|_| TreeError::Corrupt("key length")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem(HashMap<Cid, Vec<u8>>, usize);
    impl Store for Mem {
        type Error = std::convert::Infallible;
        fn put(&mut self, cid: Cid, ct: Vec<u8>) -> Result<(), Self::Error> {
            if self.0.insert(cid, ct).is_none() {
                self.1 += 1;
            }
            Ok(())
        }
        fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(cid).cloned())
        }
    }

    fn entries(n: u32, salt: u8) -> Entries {
        let mut v: Entries = (0..n)
            .map(|i| {
                let mut k = [0u8; 16];
                k[..4].copy_from_slice(&i.to_be_bytes());
                let k: RecordId = Sha256::digest(k)[..16].try_into().unwrap();
                let mut val = Vec::new();
                crate::record::write_value(&mut val, &Value::Str(format!("value {i} {salt}")));
                (k, val)
            })
            .collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    #[test]
    fn a_path_fetched_on_demand_gives_exact_records() {
        let secret = ConvergenceSecret::for_record(&[6; 32], b"tree");
        let mut full = Mem::default();
        let all = entries(3000, 1);
        let root = build(&mut full, &secret, all.clone()).unwrap().unwrap();
        let mut part = Mem::default();
        let want = all[1777].0;
        let mut fetched = 0;
        while let Some((cid, _)) = missing_on_path(&part, &root, &want).unwrap() {
            part.put(cid, full.0[&cid].clone()).unwrap();
            fetched += 1;
        }
        assert!((2..=4).contains(&fetched), "root to leaf: {fetched}");
        assert_eq!(get(&part, &root, &want).unwrap(), Some(all[1777].1.clone()));
        let present: Entries = read_present(&part, &root).unwrap();
        assert!(present.contains(&all[1777]));
        assert!(present.len() < 200, "one leaf's worth, not the tree: {}", present.len());
        assert!(present.iter().all(|e| all.contains(e)));
    }

    #[test]
    fn build_get_read_and_diff() {
        let secret = ConvergenceSecret::for_record(&[5; 32], b"tree");
        let mut st = Mem::default();
        let a = entries(3000, 0);
        let root = build(&mut st, &secret, a.clone()).unwrap().unwrap();
        assert_eq!(read_all(&st, &root).unwrap(), a);
        assert_eq!(get(&st, &root, &a[1234].0).unwrap(), Some(a[1234].1.clone()));
        assert_eq!(get(&st, &root, &[0xee; 16]).unwrap(), None);

        // Change one value: only that leaf and its ancestors are new.
        let mut b = a.clone();
        let mut v = Vec::new();
        crate::record::write_value(&mut v, &Value::Int(7));
        b[1234].1 = v;
        let before = st.1;
        let root_b = build(&mut st, &secret, b.clone()).unwrap().unwrap();
        let new_nodes = st.1 - before;
        assert!(new_nodes <= 4, "one leaf plus its path: {new_nodes}");
        assert_eq!(diff(&st, Some(&root), Some(&root_b)).unwrap(), vec![a[1234].0]);

        // Same entries, same root; deleting an entry changes only around it.
        assert_eq!(build(&mut st, &secret, a.clone()).unwrap().unwrap(), root);
        let mut c = a.clone();
        let gone = c.remove(10).0;
        let root_c = build(&mut st, &secret, c).unwrap().unwrap();
        assert_eq!(diff(&st, Some(&root), Some(&root_c)).unwrap(), vec![gone]);
        assert_eq!(build(&mut st, &secret, Entries::new()).unwrap(), None);
    }
}
