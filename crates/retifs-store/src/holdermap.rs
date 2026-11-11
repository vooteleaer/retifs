//! Holder map (ADR-0010): who has been seen holding what, kept in memory,
//! local only, bounded and aged.
//!
//! A file's holders are recorded per file (holders usually have whole files:
//! leases, members, readers keeping a library), with what each `have` answer
//! said: how many of the asked chunks it holds. Sources rank by what's known:
//! a holder confirmed by a receipt or seen holding everything asked first,
//! then holders seen holding some, then peers not asked yet, then peers that
//! said they hold nothing, and peers that just failed last; within a rank, by
//! the estimated transfer time over their link. Stale entries are harmless:
//! every chunk is checked against its CID, so a wrong holder costs one request.

use std::collections::{HashMap, VecDeque};

use retifs_core::Cid;

use crate::PeerId;

/// Holders remembered per file; others seen are only counted.
pub const HOLDERS_PER_FILE: usize = 8;
/// Files remembered; the least recently touched one goes first.
pub const HOLDER_FILES: usize = 4096;
/// A sighting older than this is no longer trusted (but still counted).
pub const SIGHTING_FRESH_MS: u64 = 60 * 60_000;
/// A failed peer is tried after others for this long.
pub const FAIL_COOL_MS: u64 = 2 * 60_000;

/// What's known about one peer and one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    pub peer: PeerId,
    /// Chunks asked about in the last answer, and how many it held.
    pub asked: u32,
    pub held: u32,
    /// When it last answered (ms; 0: never).
    pub seen_ms: u64,
    /// When it last failed (unreachable, timed out; ms; 0: never).
    pub failed_ms: u64,
    pub fails: u32,
}

/// How a source ranks: lower first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// A receipt, or the last answer held everything asked.
    Holds = 0,
    /// The last answer held some of what was asked.
    HoldsSome = 1,
    /// Never asked about this file, or asked long ago.
    Unknown = 2,
    /// The last answer held nothing (it may have pulled since).
    HoldsNone = 3,
    /// Failed just now.
    Failed = 4,
}

#[derive(Debug, Default)]
struct FileHolders {
    peers: Vec<Sighting>,
    /// Holders seen but not kept (beyond [`HOLDERS_PER_FILE`]).
    others: u32,
}

/// The holder map.
#[derive(Debug, Default)]
pub struct HolderMap {
    files: HashMap<Cid, FileHolders>,
    order: VecDeque<Cid>,
}

impl Sighting {
    fn new(peer: PeerId) -> Self {
        Sighting { peer, asked: 0, held: 0, seen_ms: 0, failed_ms: 0, fails: 0 }
    }

    fn rank(&self, now_ms: u64) -> Rank {
        if self.failed_ms > self.seen_ms && now_ms < self.failed_ms + FAIL_COOL_MS {
            return Rank::Failed;
        }
        if self.seen_ms == 0 || now_ms > self.seen_ms + SIGHTING_FRESH_MS || self.asked == 0 {
            return Rank::Unknown;
        }
        if self.held >= self.asked {
            Rank::Holds
        } else if self.held > 0 {
            Rank::HoldsSome
        } else {
            Rank::HoldsNone
        }
    }
}

impl HolderMap {
    pub fn new() -> Self {
        Self::default()
    }

    fn touch(&mut self, root: &Cid) -> &mut FileHolders {
        if let Some(pos) = self.order.iter().position(|r| r == root) {
            self.order.remove(pos);
        } else if self.order.len() >= HOLDER_FILES
            && let Some(old) = self.order.pop_front()
        {
            self.files.remove(&old);
        }
        self.order.push_back(*root);
        self.files.entry(*root).or_default()
    }

    fn entry(&mut self, root: &Cid, peer: &PeerId, now_ms: u64) -> Option<&mut Sighting> {
        let f = self.touch(root);
        if let Some(i) = f.peers.iter().position(|s| s.peer == *peer) {
            return Some(&mut f.peers[i]);
        }
        if f.peers.len() >= HOLDERS_PER_FILE {
            // Make room by dropping the worst one, if it's worse than unknown.
            let worst = f.peers.iter().enumerate().max_by_key(|(_, s)| (s.rank(now_ms), u64::MAX - s.seen_ms)).map(|(i, s)| (i, s.rank(now_ms)));
            match worst {
                Some((i, r)) if r > Rank::Unknown => {
                    f.peers.swap_remove(i);
                }
                _ => {
                    f.others = f.others.saturating_add(1);
                    return None;
                }
            }
        }
        f.peers.push(Sighting::new(*peer));
        f.peers.last_mut()
    }

    /// `peer` answered a `have` for `asked` chunks of `root`, holding `held`.
    pub fn saw(&mut self, root: &Cid, peer: &PeerId, asked: usize, held: usize, now_ms: u64) {
        if let Some(s) = self.entry(root, peer, now_ms) {
            s.asked = asked as u32;
            s.held = held as u32;
            s.seen_ms = now_ms;
            s.fails = 0;
        }
    }

    /// `peer` couldn't be reached, or a request to it failed.
    pub fn failed(&mut self, root: &Cid, peer: &PeerId, now_ms: u64) {
        if let Some(s) = self.entry(root, peer, now_ms) {
            s.failed_ms = now_ms;
            s.fails = s.fails.saturating_add(1);
        }
    }

    /// What's known about `root`'s holders.
    pub fn sightings(&self, root: &Cid) -> Vec<Sighting> {
        self.files.get(root).map(|f| f.peers.clone()).unwrap_or_default()
    }

    /// Peers seen holding some or all of `root` recently, and how many more
    /// were seen than are remembered.
    pub fn seen_holding(&self, root: &Cid, now_ms: u64) -> (Vec<PeerId>, u32) {
        match self.files.get(root) {
            Some(f) => (
                f.peers.iter().filter(|s| s.rank(now_ms) <= Rank::HoldsSome).map(|s| s.peer).collect(),
                f.others,
            ),
            None => (Vec::new(), 0),
        }
    }

    /// The rank of `peer` as a source of `root`; `confirmed` peers (a valid
    /// receipt) hold it unless they just failed.
    pub fn rank_of(&self, root: &Cid, peer: &PeerId, confirmed: bool, now_ms: u64) -> Rank {
        let r = self
            .files
            .get(root)
            .and_then(|f| f.peers.iter().find(|s| s.peer == *peer))
            .map(|s| s.rank(now_ms))
            .unwrap_or(Rank::Unknown);
        if confirmed && r != Rank::Failed { Rank::Holds } else { r }
    }

    /// Orders `candidates` as sources of `root`: by rank, then by `cost`
    /// (estimated seconds over the link), then as given.
    pub fn rank(&self, root: &Cid, candidates: &[PeerId], confirmed: &[PeerId], now_ms: u64, cost: impl Fn(&PeerId) -> f64) -> Vec<(PeerId, Rank)> {
        let mut out: Vec<(usize, PeerId, Rank, f64)> = candidates
            .iter()
            .enumerate()
            .map(|(i, p)| (i, *p, self.rank_of(root, p, confirmed.contains(p), now_ms), cost(p)))
            .collect();
        out.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.total_cmp(&b.3)).then(a.0.cmp(&b.0)));
        out.into_iter().map(|(_, p, r, _)| (p, r)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> Cid {
        let mut b = [0u8; 33];
        b[0] = 1;
        b[1] = n;
        Cid::from_bytes(b).unwrap()
    }

    fn peer(n: u8) -> PeerId {
        [n; 16]
    }

    #[test]
    fn ranks_holders_before_unknown_and_failed() {
        let mut m = HolderMap::new();
        let f = cid(1);
        m.saw(&f, &peer(1), 10, 0, 1_000);
        m.saw(&f, &peer(2), 10, 10, 1_000);
        m.saw(&f, &peer(3), 10, 4, 1_000);
        m.failed(&f, &peer(4), 1_500);
        let order = m.rank(&f, &[peer(4), peer(1), peer(5), peer(3), peer(2)], &[], 2_000, |_| 1.0);
        let peers: Vec<u8> = order.iter().map(|(p, _)| p[0]).collect();
        assert_eq!(peers, vec![2, 3, 5, 1, 4]);
    }

    #[test]
    fn cost_breaks_ties_and_receipts_count() {
        let m = HolderMap::new();
        let f = cid(1);
        let order = m.rank(&f, &[peer(1), peer(2), peer(3)], &[peer(3)], 0, |p| if p[0] == 1 { 5.0 } else { 1.0 });
        let peers: Vec<u8> = order.iter().map(|(p, _)| p[0]).collect();
        assert_eq!(peers, vec![3, 2, 1]);
        assert_eq!(order[0].1, Rank::Holds);
    }

    #[test]
    fn failures_cool_down_and_sightings_age() {
        let mut m = HolderMap::new();
        let f = cid(1);
        m.saw(&f, &peer(1), 4, 4, 1_000);
        m.failed(&f, &peer(1), 2_000);
        assert_eq!(m.rank_of(&f, &peer(1), true, 3_000), Rank::Failed);
        assert_eq!(m.rank_of(&f, &peer(1), false, 2_000 + FAIL_COOL_MS + 1), Rank::Holds);
        assert_eq!(m.rank_of(&f, &peer(1), false, 1_000 + SIGHTING_FRESH_MS + 1), Rank::Unknown);
        // A fresh answer after a failure wins.
        m.saw(&f, &peer(1), 4, 4, 2_500);
        assert_eq!(m.rank_of(&f, &peer(1), false, 3_000), Rank::Holds);
    }

    #[test]
    fn bounded_per_file_and_in_files() {
        let mut m = HolderMap::new();
        let f = cid(1);
        for n in 0..HOLDERS_PER_FILE as u8 {
            m.saw(&f, &peer(n), 4, 4, 1_000);
        }
        m.saw(&f, &peer(100), 4, 4, 1_000);
        let (seen, others) = m.seen_holding(&f, 1_000);
        assert_eq!(seen.len(), HOLDERS_PER_FILE);
        assert_eq!(others, 1);
        // A holder that holds nothing gives way to one that holds.
        let g = cid(2);
        for n in 0..HOLDERS_PER_FILE as u8 {
            m.saw(&g, &peer(n), 4, 0, 1_000);
        }
        m.saw(&g, &peer(100), 4, 4, 1_000);
        assert!(m.seen_holding(&g, 1_000).0.contains(&peer(100)));

        let mut m = HolderMap::new();
        for n in 0..=HOLDER_FILES {
            let mut b = [0u8; 33];
            b[0] = 1;
            b[1..9].copy_from_slice(&(n as u64).to_be_bytes());
            m.saw(&Cid::from_bytes(b).unwrap(), &peer(1), 1, 1, 1);
        }
        assert_eq!(m.files.len(), HOLDER_FILES);
        assert!(m.sightings(&cid(0)).is_empty());
    }
}
