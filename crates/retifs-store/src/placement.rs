//! Placement state (ADR-0014): storage nodes heard, how holders have behaved,
//! and which files this node needs kept.
//!
//! ```text
//! STORAGE_NODES  peer (16) → hops (1) ‖ last_heard_ms (8) ‖ avoid_until_ms (8) [‖ announce_s (4) [‖ site (8)]]
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
/// peer (16) → rtt_ms (4) ‖ rate_bps (4) ‖ samples (4)
const LINK_QUALITY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("link_quality");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(STORAGE_NODES)?;
    w.open_table(HOLDER_STATS)?;
    w.open_table(NEEDED)?;
    w.open_table(LINK_QUALITY)?;
    Ok(())
}

/// A link that takes this long to set up is treated as slow (LoRa-class)
/// until transfers show otherwise.
pub const SLOW_RTT_MS: u32 = 1500;
/// Measured throughput below this is slow.
pub const SLOW_RATE: f64 = 2048.0;
/// Assumed for a slow link before anything was measured: about what LoRa
/// carries within a 10 % duty cycle (~0.5 MB per hour).
pub const SLOW_DEFAULT_RATE: f64 = 150.0;
/// Assumed for other links before anything was measured.
pub const FAST_DEFAULT_RATE: f64 = 50_000.0;

/// One holder of a file, as placement sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HolderView {
    pub peer: PeerId,
    /// Estimated chance its copy is lost (1.0: counted as gone).
    pub loss: f64,
    pub hops: u8,
    /// It has a valid receipt now.
    pub confirmed: bool,
}

/// Trim only when the estimate without the holder is at most this share of
/// the target: adding happens above the target, so copies don't flip back and forth.
pub const TRIM_MARGIN: f64 = 0.5;

/// The holder whose copy is surplus, if any (ADR-0014): without it the loss
/// estimate is still at most `target × TRIM_MARGIN`. Nothing is trimmed while
/// any holder is unconfirmed (a placement in progress). The worst record goes
/// first; on a tie, the farthest.
pub fn surplus_holder(local: f64, holders: &[HolderView], target: f64) -> Option<PeerId> {
    if !holders.iter().all(|h| h.confirmed) {
        return None;
    }
    let mut order: Vec<&HolderView> = holders.iter().collect();
    order.sort_by(|a, b| b.loss.total_cmp(&a.loss).then(b.hops.cmp(&a.hops)));
    order.into_iter().map(|h| h.peer).find(|&drop| {
        local * holders.iter().filter(|h| h.peer != drop).map(|h| h.loss).product::<f64>() <= target * TRIM_MARGIN
    })
}

/// What this node has seen of the path to a peer (ADR-0014: link cost). A
/// client of the shared instance can't see the interfaces behind it, so
/// quality is measured: link setup RTT, and throughput of real transfers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkQuality {
    /// Last link setup round trip (0: never linked).
    pub rtt_ms: u32,
    /// Moving average of measured throughput in bytes per second (0: none yet).
    pub rate_bps: u32,
    pub samples: u32,
}

impl LinkQuality {
    /// Throughput to plan with: measured if there is any, else a guess from the RTT.
    pub fn rate(&self) -> f64 {
        if self.rate_bps > 0 {
            self.rate_bps as f64
        } else if self.rtt_ms >= SLOW_RTT_MS {
            SLOW_DEFAULT_RATE
        } else {
            FAST_DEFAULT_RATE
        }
    }

    pub fn slow(&self) -> bool {
        self.rate() < SLOW_RATE
    }

    /// Estimated seconds to move `bytes` over this path.
    pub fn transfer_secs(&self, bytes: u64) -> f64 {
        self.rtt_ms as f64 / 1000.0 + bytes as f64 / self.rate()
    }
}

/// A node that can hold data for others, as last heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageNode {
    pub peer: PeerId,
    pub hops: u8,
    pub last_heard_ms: u64,
    /// Don't offer it leases before this (it refused, or was unreachable).
    pub avoid_until_ms: u64,
    /// How often it says it announces (seconds; the default if it doesn't).
    pub announce_s: u32,
    /// The site its announces name, if any.
    pub site: Option<[u8; 8]>,
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
        // Entries written before the interval was kept have none.
        announce_s: v.get(17..21).map_or(retifs_core::announce::DEFAULT_ANNOUNCE_S, |b| u32::from_be_bytes(b.try_into().unwrap())),
        site: v.get(21..29).map(|b| b.try_into().unwrap()),
    }
}

fn node_value(n: &StorageNode) -> Vec<u8> {
    let site: &[u8] = n.site.as_ref().map_or(&[], |s| s.as_slice());
    [&[n.hops][..], &n.last_heard_ms.to_be_bytes(), &n.avoid_until_ms.to_be_bytes(), &n.announce_s.to_be_bytes(), site].concat()
}

fn parse_quality(v: &[u8]) -> LinkQuality {
    let u32_at = |i: usize| u32::from_be_bytes(v[i..i + 4].try_into().unwrap());
    LinkQuality { rtt_ms: u32_at(0), rate_bps: u32_at(4), samples: u32_at(8) }
}

fn parse_stats(v: &[u8]) -> HolderStats {
    HolderStats {
        ok: u32::from_be_bytes(v[..4].try_into().unwrap()),
        fail: u32::from_be_bytes(v[4..8].try_into().unwrap()),
        last_ok_ms: u64::from_be_bytes(v[8..16].try_into().unwrap()),
    }
}

impl SlabStore {
    /// A `retifs.node` announce was heard `hops` away, saying it announces
    /// every `announce_s` seconds (None: it didn't say).
    pub fn heard_storage_node(&self, peer: &PeerId, hops: u8, announce_s: Option<u32>, site: Option<[u8; 8]>, now_ms: u64) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(STORAGE_NODES)?;
            let old = t.get(peer.as_slice())?.map(|v| parse_node(*peer, v.value()));
            let n = StorageNode {
                peer: *peer,
                hops,
                last_heard_ms: now_ms,
                avoid_until_ms: old.map_or(0, |o| o.avoid_until_ms),
                announce_s: announce_s.unwrap_or(retifs_core::announce::DEFAULT_ANNOUNCE_S),
                site,
            };
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

    /// Forgets storage nodes silent for longer than `silent(node)` ms at
    /// `now_ms` (gone test nodes, replaced identities). Returns how many.
    pub fn forget_silent_storage_nodes(&self, now_ms: u64, silent: impl Fn(&StorageNode) -> u64) -> Result<usize, StoreError> {
        let w = self.db.begin_write()?;
        let mut n = 0;
        {
            let mut t = w.open_table(STORAGE_NODES)?;
            let old: Vec<PeerId> = t
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, v)| parse_node(k.value().try_into().unwrap(), v.value()))
                .filter(|s| s.last_heard_ms.saturating_add(silent(s)) < now_ms)
                .map(|s| s.peer)
                .collect();
            for p in old {
                t.remove(p.as_slice())?;
                n += 1;
            }
        }
        w.commit()?;
        Ok(n)
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

    pub fn link_quality(&self, peer: &PeerId) -> Result<LinkQuality, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(LINK_QUALITY)?.get(peer.as_slice())?.map(|v| parse_quality(v.value())).unwrap_or_default())
    }

    /// A link to `peer` was set up in `rtt_ms`.
    pub fn record_rtt(&self, peer: &PeerId, rtt_ms: u64) -> Result<(), StoreError> {
        self.update_quality(peer, |q| q.rtt_ms = rtt_ms.min(u32::MAX as u64) as u32)
    }

    /// `bytes` moved to or from `peer` in `millis`: folds into the moving average.
    /// Tiny transfers are dominated by round trips and say little about throughput.
    pub fn record_transfer(&self, peer: &PeerId, bytes: u64, millis: u64) -> Result<(), StoreError> {
        if bytes < 4096 {
            return Ok(());
        }
        let sample = bytes as f64 * 1000.0 / millis.max(1) as f64;
        self.update_quality(peer, |q| {
            let avg = if q.samples == 0 { sample } else { 0.7 * q.rate_bps as f64 + 0.3 * sample };
            q.rate_bps = avg.clamp(1.0, u32::MAX as f64) as u32;
            q.samples = q.samples.saturating_add(1);
        })
    }

    fn update_quality(&self, peer: &PeerId, f: impl FnOnce(&mut LinkQuality)) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(LINK_QUALITY)?;
            let mut q = t.get(peer.as_slice())?.map(|v| parse_quality(v.value())).unwrap_or_default();
            f(&mut q);
            let v = [&q.rtt_ms.to_be_bytes()[..], &q.rate_bps.to_be_bytes(), &q.samples.to_be_bytes()].concat();
            t.insert(peer.as_slice(), v.as_slice())?;
        }
        w.commit()?;
        Ok(())
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

    /// Stops keeping `root` at one holder: its leases there stop serving it
    /// (dropped, or stale if they also serve other files). Returns how many.
    pub fn drop_holder(&self, root: &Cid, holder: &PeerId) -> Result<usize, StoreError> {
        self.unlist_root(root, Some(holder))
    }

    /// This node no longer needs `root` kept: it leaves the needed and wanted
    /// lists, and its own leases are dropped, so they're no longer renewed and
    /// holders release the chunks when the leases run out. Returns how many
    /// leases were dropped. Chunks stay where they are; see `release_chunks`.
    pub fn forget_file(&self, root: &Cid) -> Result<usize, StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(NEEDED)?.remove(root.as_bytes().as_slice())?;
        w.commit()?;
        let n = self.unlist_root(root, None)?;
        if self.is_wanted(root)? {
            self.finish_file(root)?;
        }
        Ok(n)
    }

    /// Stops keeping `root` elsewhere (no longer needed, leases run out) but
    /// leaves the local copy as it is: an older version kept here as history.
    pub fn unneed_file(&self, root: &Cid) -> Result<usize, StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(NEEDED)?.remove(root.as_bytes().as_slice())?;
        w.commit()?;
        self.unlist_root(root, None)
    }

    /// Makes these chunks of a forgotten file evictable: own (pinned) copies
    /// move to the cache tier and stop being served. Chunks held for others
    /// (leases) are untouched. The caller leaves out chunks other needed files
    /// still use (versions of a record share most of theirs).
    pub fn release_chunks(&self, cids: &[Cid]) -> Result<usize, StoreError> {
        let mut released = Vec::new();
        for cid in cids {
            if let Some(flags) = self.tier(cid)?
                && flags & crate::tier::PINNED != 0
            {
                self.set_tier(cid, (flags & !crate::tier::PINNED) | crate::tier::CACHE)?;
                if flags & crate::tier::SERVING == 0 {
                    released.push(*cid);
                }
            }
        }
        let w = self.db.begin_write()?;
        {
            let mut serve = w.open_table(crate::SERVE)?;
            let mut published = w.open_table(crate::PUBLISHED)?;
            for cid in &released {
                serve.remove(cid.as_bytes().as_slice())?;
                published.remove(cid.as_bytes().as_slice())?;
            }
        }
        w.commit()?;
        Ok(released.len())
    }

    /// Whether this node needs `root` kept (it wrote or sought it).
    pub fn is_needed(&self, root: &Cid) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NEEDED)?.get(root.as_bytes().as_slice())?.is_some())
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
