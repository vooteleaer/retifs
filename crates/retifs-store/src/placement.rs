//! Placement state (ADR-0014): storage nodes heard, how holders have behaved,
//! and which files this node needs kept.
//!
//! ```text
//! STORAGE_NODES  peer (16) → hops (1) ‖ last_heard_ms (8) ‖ avoid_until_ms (8)
//! HOLDER_STATS   peer (16) → ok (4) ‖ fail (4) ‖ last_ok_ms (8)
//! NEEDED         root CID → seed (32) ‖ size (8)
//! ```
//! A file is needed by its writer and by every reader that sought it; each
//! needer keeps copies near itself, and need ends when it stops renewing.

use redb::{ReadableTable, TableDefinition};
use retifs_core::{manifest::FileRef, Cid, Seed};

use crate::{wants::PeerId, SlabStore, StoreError};

const STORAGE_NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("storage_nodes");
const HOLDER_STATS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("holder_stats");
const NEEDED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("needed");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(STORAGE_NODES)?;
    w.open_table(HOLDER_STATS)?;
    w.open_table(NEEDED)?;
    Ok(())
}

/// A node that can hold data for others, as last heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageNode {
    pub peer: PeerId,
    pub hops: u8,
    pub last_heard_ms: u64,
    /// Don't offer it leases before this (it refused, or was unreachable).
    pub avoid_until_ms: u64,
}

/// How a holder has answered upkeep (receipts, renewals, proofs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HolderStats {
    pub ok: u32,
    pub fail: u32,
    pub last_ok_ms: u64,
}

impl HolderStats {
    /// Estimated chance this holder's copy is lost before repair notices:
    /// a Beta(1, 9) prior (a new holder counts as 10 %), sharpened by its record.
    pub fn loss(&self) -> f64 {
        (self.fail as f64 + 1.0) / (self.ok as f64 + self.fail as f64 + 10.0)
    }
}

fn parse_node(peer: PeerId, v: &[u8]) -> StorageNode {
    StorageNode {
        peer,
        hops: v[0],
        last_heard_ms: u64::from_be_bytes(v[1..9].try_into().unwrap()),
        avoid_until_ms: u64::from_be_bytes(v[9..17].try_into().unwrap()),
    }
}

fn node_value(n: &StorageNode) -> Vec<u8> {
    [&[n.hops][..], &n.last_heard_ms.to_be_bytes(), &n.avoid_until_ms.to_be_bytes()].concat()
}

fn parse_stats(v: &[u8]) -> HolderStats {
    HolderStats {
        ok: u32::from_be_bytes(v[..4].try_into().unwrap()),
        fail: u32::from_be_bytes(v[4..8].try_into().unwrap()),
        last_ok_ms: u64::from_be_bytes(v[8..16].try_into().unwrap()),
    }
}

impl SlabStore {
    /// A `retifs.node` announce was heard `hops` away.
    pub fn heard_storage_node(&self, peer: &PeerId, hops: u8, now_ms: u64) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(STORAGE_NODES)?;
            let old = t.get(peer.as_slice())?.map(|v| parse_node(*peer, v.value()));
            let n = StorageNode { peer: *peer, hops, last_heard_ms: now_ms, avoid_until_ms: old.map_or(0, |o| o.avoid_until_ms) };
            t.insert(peer.as_slice(), node_value(&n).as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    /// Storage nodes, nearest first (then most recently heard).
    pub fn storage_nodes(&self) -> Result<Vec<StorageNode>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(STORAGE_NODES)?;
        let mut out: Vec<StorageNode> = t
            .iter()?
            .map(|e| e.map(|(k, v)| parse_node(k.value().try_into().unwrap(), v.value())))
            .collect::<Result<_, _>>()?;
        out.sort_by_key(|n| (n.hops, std::cmp::Reverse(n.last_heard_ms)));
        Ok(out)
    }

    /// Don't offer `peer` leases until `until_ms` (no room, unreachable).
    pub fn avoid_storage_node(&self, peer: &PeerId, until_ms: u64) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(STORAGE_NODES)?;
            let old = t.get(peer.as_slice())?.map(|v| parse_node(*peer, v.value()));
            if let Some(mut n) = old {
                n.avoid_until_ms = until_ms;
                t.insert(peer.as_slice(), node_value(&n).as_slice())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Records one upkeep contact with a holder.
    pub fn holder_result(&self, peer: &PeerId, ok: bool, now_ms: u64) -> Result<HolderStats, StoreError> {
        let w = self.db.begin_write()?;
        let s = {
            let mut t = w.open_table(HOLDER_STATS)?;
            let mut s = t.get(peer.as_slice())?.map(|v| parse_stats(v.value())).unwrap_or_default();
            if ok {
                s.ok = s.ok.saturating_add(1);
                s.last_ok_ms = now_ms;
            } else {
                s.fail = s.fail.saturating_add(1);
            }
            let v = [&s.ok.to_be_bytes()[..], &s.fail.to_be_bytes(), &s.last_ok_ms.to_be_bytes()].concat();
            t.insert(peer.as_slice(), v.as_slice())?;
            s
        };
        w.commit()?;
        Ok(s)
    }

    pub fn holder_stats(&self, peer: &PeerId) -> Result<HolderStats, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(HOLDER_STATS)?.get(peer.as_slice())?.map(|v| parse_stats(v.value())).unwrap_or_default())
    }

    /// This node needs `file` kept (it wrote or sought it).
    pub fn need_file(&self, file: &FileRef) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let v = [&file.seed.0[..], &file.size.to_be_bytes()].concat();
            w.open_table(NEEDED)?.insert(file.root.as_bytes().as_slice(), v.as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    pub fn needed_files(&self) -> Result<Vec<FileRef>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(NEEDED)?;
        t.iter()?
            .map(|e| {
                let (k, v) = e?;
                let v = v.value();
                Ok(FileRef {
                    root: Cid::from_bytes(k.value().try_into().expect("root CID")).expect("CID version"),
                    seed: Seed(v[..32].try_into().unwrap()),
                    size: u64::from_be_bytes(v[32..40].try_into().unwrap()),
                })
            })
            .collect()
    }
}
