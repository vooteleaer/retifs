//! Want-list and holder hints (ADR-0010), persisted in the store's index.
//!
//! ```text
//! WANT_FILES  root CID → seed (32) ‖ size (8)                  files being sought
//! WANTS       root CID ‖ CID → seed (32) ‖ span (8) ‖ node (1)  missing chunks, per file
//! HINTS       root CID ‖ peer (16) → next_try_ms (8) ‖ backoff_ms (8) ‖ ok (4) ‖ fail (4)
//! ```
//! A file is sought until it has no wants left. Wants carry their seed and
//! span so an arriving manifest node can be opened and expanded into its
//! children. Hints are where to ask, with back-off per (file, peer); an
//! announce from a peer resets its back-off.

use redb::{ReadableTable, TableDefinition};
use retifs_core::{cid::CID_LEN, manifest::FileRef, Cid, Seed};

use crate::{SlabStore, StoreError};

const WANT_FILES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("want_files");
const WANTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("wants");
const HINTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("hints");

pub type PeerId = [u8; 16];

const BACKOFF_MIN_MS: u64 = 30_000;
const BACKOFF_MAX_MS: u64 = 30 * 60_000;

/// A missing chunk of a sought file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Want {
    pub cid: Cid,
    pub seed: Seed,
    pub span: u64,
    /// A manifest node (expands into children when it arrives) rather than data.
    pub node: bool,
}

/// Where to ask for a file, and when next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint {
    pub peer: PeerId,
    pub next_try_ms: u64,
    pub backoff_ms: u64,
    pub ok: u32,
    pub fail: u32,
}

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(WANT_FILES)?;
    w.open_table(WANTS)?;
    w.open_table(HINTS)?;
    Ok(())
}

fn pair(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}

fn want_value(w: &Want) -> [u8; 41] {
    let mut v = [0u8; 41];
    v[..32].copy_from_slice(&w.seed.0);
    v[32..40].copy_from_slice(&w.span.to_be_bytes());
    v[40] = w.node as u8;
    v
}

fn hint_value(h: &Hint) -> [u8; 24] {
    let mut v = [0u8; 24];
    v[..8].copy_from_slice(&h.next_try_ms.to_be_bytes());
    v[8..16].copy_from_slice(&h.backoff_ms.to_be_bytes());
    v[16..20].copy_from_slice(&h.ok.to_be_bytes());
    v[20..24].copy_from_slice(&h.fail.to_be_bytes());
    v
}

fn parse_hint(peer: PeerId, v: &[u8]) -> Hint {
    let u64_at = |i: usize| u64::from_be_bytes(v[i..i + 8].try_into().unwrap());
    let u32_at = |i: usize| u32::from_be_bytes(v[i..i + 4].try_into().unwrap());
    Hint { peer, next_try_ms: u64_at(0), backoff_ms: u64_at(8), ok: u32_at(16), fail: u32_at(20) }
}

/// Keys of a table that start with `prefix`.
fn range_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    end.push(0xff);
    end.extend_from_slice(&[0xff; CID_LEN]);
    end
}

impl SlabStore {
    /// Starts seeking `file` (until it's complete), asking `hints` first.
    pub fn want_file(&self, file: &FileRef, hints: &[PeerId]) -> Result<(), StoreError> {
        let root = file.root.as_bytes();
        let w = self.db.begin_write()?;
        {
            let mut v = file.seed.0.to_vec();
            v.extend_from_slice(&file.size.to_be_bytes());
            w.open_table(WANT_FILES)?.insert(root.as_slice(), v.as_slice())?;
            let root_want = Want { cid: file.root, seed: file.seed, span: file.size, node: true };
            w.open_table(WANTS)?.insert(pair(root, root).as_slice(), want_value(&root_want).as_slice())?;
            let mut h = w.open_table(HINTS)?;
            for peer in hints {
                let key = pair(root, peer);
                if h.get(key.as_slice())?.is_none() {
                    let fresh = Hint { peer: *peer, next_try_ms: 0, backoff_ms: 0, ok: 0, fail: 0 };
                    h.insert(key.as_slice(), hint_value(&fresh).as_slice())?;
                }
            }
        }
        w.commit()?;
        Ok(())
    }

    pub fn wanted_files(&self) -> Result<Vec<FileRef>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(WANT_FILES)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            let root = Cid::from_bytes(k.value().try_into().expect("root CID")).expect("CID version");
            let v = v.value();
            out.push(FileRef {
                root,
                seed: Seed(v[..32].try_into().unwrap()),
                size: u64::from_be_bytes(v[32..40].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    pub fn is_wanted(&self, root: &Cid) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(WANT_FILES)?.get(root.as_bytes().as_slice())?.is_some())
    }

    /// Up to `limit` missing chunks of a sought file, manifest nodes first.
    pub fn wants(&self, root: &Cid, limit: usize) -> Result<Vec<Want>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(WANTS)?;
        let start = root.as_bytes().to_vec();
        let end = range_end(&start);
        let mut out = Vec::new();
        for e in t.range(start.as_slice()..end.as_slice())? {
            let (k, v) = e?;
            let k = k.value();
            if k.len() != 2 * CID_LEN {
                continue;
            }
            let cid = Cid::from_bytes(k[CID_LEN..].try_into().unwrap()).expect("CID version");
            let v = v.value();
            out.push(Want {
                cid,
                seed: Seed(v[..32].try_into().unwrap()),
                span: u64::from_be_bytes(v[32..40].try_into().unwrap()),
                node: v[40] != 0,
            });
        }
        out.sort_by_key(|w| !w.node); // nodes first: they reveal the rest of the tree
        out.truncate(limit);
        Ok(out)
    }

    /// Adds wants for a file (e.g. the children of an arrived node).
    pub fn add_wants(&self, root: &Cid, wants: &[Want]) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(WANTS)?;
            for want in wants {
                t.insert(pair(root.as_bytes(), want.cid.as_bytes()).as_slice(), want_value(want).as_slice())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// A wanted chunk arrived (or was found locally).
    pub fn satisfied(&self, root: &Cid, cid: &Cid) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(WANTS)?.remove(pair(root.as_bytes(), cid.as_bytes()).as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Stops seeking a file (complete, or given up): drops its wants and hints.
    pub fn finish_file(&self, root: &Cid) -> Result<(), StoreError> {
        let start = root.as_bytes().to_vec();
        let end = range_end(&start);
        let w = self.db.begin_write()?;
        {
            w.open_table(WANT_FILES)?.remove(start.as_slice())?;
            for table in [WANTS, HINTS] {
                let mut t = w.open_table(table)?;
                let keys: Vec<Vec<u8>> = t
                    .range(start.as_slice()..end.as_slice())?
                    .map(|e| e.map(|(k, _)| k.value().to_vec()))
                    .collect::<Result<_, _>>()?;
                for k in keys {
                    t.remove(k.as_slice())?;
                }
            }
        }
        w.commit()?;
        Ok(())
    }

    pub fn hints(&self, root: &Cid) -> Result<Vec<Hint>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(HINTS)?;
        let start = root.as_bytes().to_vec();
        let end = range_end(&start);
        let mut out = Vec::new();
        for e in t.range(start.as_slice()..end.as_slice())? {
            let (k, v) = e?;
            let k = k.value();
            if k.len() == CID_LEN + 16 {
                out.push(parse_hint(k[CID_LEN..].try_into().unwrap(), v.value()));
            }
        }
        Ok(out)
    }

    /// Records the outcome of asking `peer` for `root`: success resets the
    /// back-off; failure (unreachable, or nothing new) doubles it (30 s … 30 min).
    pub fn hint_result(&self, root: &Cid, peer: &PeerId, ok: bool, now_ms: u64) -> Result<(), StoreError> {
        let key = pair(root.as_bytes(), peer);
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(HINTS)?;
            let mut h = t
                .get(key.as_slice())?
                .map(|v| parse_hint(*peer, v.value()))
                .unwrap_or(Hint { peer: *peer, next_try_ms: 0, backoff_ms: 0, ok: 0, fail: 0 });
            if ok {
                h.ok += 1;
                h.backoff_ms = 0;
                h.next_try_ms = now_ms;
            } else {
                h.fail += 1;
                h.backoff_ms = (h.backoff_ms * 2).clamp(BACKOFF_MIN_MS, BACKOFF_MAX_MS);
                h.next_try_ms = now_ms + h.backoff_ms;
            }
            t.insert(key.as_slice(), hint_value(&h).as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    /// A peer announced itself: try it again right away for every file it's hinted for.
    pub fn wake_peer(&self, peer: &PeerId) -> Result<bool, StoreError> {
        let w = self.db.begin_write()?;
        let woke = {
            let mut t = w.open_table(HINTS)?;
            let hits: Vec<(Vec<u8>, Hint)> = t
                .iter()?
                .filter_map(|e| e.ok())
                .filter(|(k, _)| k.value().len() == CID_LEN + 16 && &k.value()[CID_LEN..] == peer.as_slice())
                .map(|(k, v)| (k.value().to_vec(), parse_hint(*peer, v.value())))
                .collect();
            for (k, mut h) in hits.iter().cloned() {
                h.next_try_ms = 0;
                t.insert(k.as_slice(), hint_value(&h).as_slice())?;
            }
            !hits.is_empty()
        };
        w.commit()?;
        Ok(woke)
    }

    /// Whether `prefix` (the first bytes of a CID) is served under `token_id`.
    pub fn served_prefix(&self, token_id: &[u8; 16], prefix: &[u8]) -> Result<bool, StoreError> {
        let start = pair(token_id, prefix);
        let end = range_end(&start);
        let r = self.db.begin_read()?;
        let t = r.open_table(crate::SERVE)?;
        let hit = t.range(start.as_slice()..end.as_slice())?.next().is_some();
        Ok(hit)
    }
}
