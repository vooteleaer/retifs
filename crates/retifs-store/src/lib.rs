//! Local slab store (ADR-0007) with a disk budget (ADR-0012), prototype.
//!
//! ```text
//! <root>/slabs/c<N>k/seg-000000 …   fixed-size slots, one directory per size class
//! <root>/index.redb                 CID → (class, segment, slot, tier); free slots; counters;
//!                                   per-tier usage; serving index; last access
//! ```
//! Write order is content first, then reference: the slot is written (and
//! fsynced) inside the same redb transaction that records it, so a crash
//! before commit leaves only a free slot with garbage in it.
//!
//! All operations take `&self`: redb serialises write transactions and slot
//! allocation happens inside them, so one store can be shared (e.g. in an
//! `Arc`) by the daemon's serving, import and cache paths.
//!
//! **Disk budget (ADR-0012).** Hard tiers (pinned, leased) are bounded by the
//! store limit and never evicted. Elastic tiers (cache, spare) use free space
//! down to the reserve and are evicted (spare first, then cache, least
//! recently used first) when room is needed or other programs fill the disk.
//! Freed slots are reused, and their disk space is returned to the OS by
//! punching holes (Linux `fallocate`, Windows sparse files).

use std::{
    collections::HashMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod apps;
mod channels;
mod db;
mod leases;
mod namespaces;
mod placement;
mod wants;
pub use leases::{Accept, BlindWants, HeldLease, OwnLease, ProofState, LEASE_CHUNK_ESTIMATE};
pub use apps::App;
pub use channels::{Follow, OwnChannel};
pub use db::{parse_value, Term};
pub use namespaces::WriterHead;
pub use placement::{surplus_holder, HolderStats, HolderView, LinkQuality, StorageNode, SLOW_DEFAULT_RATE, SLOW_RTT_MS, TRIM_MARGIN};
pub use wants::{Hint, PeerId, Want};

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use retifs_core::{chunk::CLASSES, ChunkToken, Cid, Store};

/// CID → (class index, segment, slot, tier flags)
const INDEX: TableDefinition<&[u8], (u8, u32, u32, u8)> = TableDefinition::new("index");
/// Reusable slots: (class index, segment, slot)
const FREE: TableDefinition<(u8, u32, u32), ()> = TableDefinition::new("free");
/// Next never-used slot number per class index
const NEXT: TableDefinition<u8, u64> = TableDefinition::new("next");
/// Serving index: CID → chunk access token. Only chunks registered here (own
/// writes) are served, to requesters proving the chunk's seed; fetched/cached
/// chunks never are (holder privacy, ADR-0010).
pub(crate) const SERVE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("serve");
/// Published CIDs: served to anyone without proof.
pub(crate) const PUBLISHED: TableDefinition<&[u8], ()> = TableDefinition::new("published");
/// Effective tier → bytes stored in it.
const USAGE: TableDefinition<u8, u64> = TableDefinition::new("usage");
/// CID → last access (ms since epoch), for LRU eviction of elastic tiers.
const ACCESS: TableDefinition<&[u8], u64> = TableDefinition::new("access");

pub const SLOTS_PER_SEGMENT: u64 = 256;
const GIB: u64 = 1 << 30;

/// Tier flags (ADR-0005, ADR-0012). A chunk may carry several; its effective
/// tier is the most protected one.
pub mod tier {
    /// Own data: never evicted.
    pub const PINNED: u8 = 1;
    /// Fetched for own reading: evictable, never served to others.
    pub const CACHE: u8 = 2;
    /// Held for others under a promise (leases, own-node pool): never evicted.
    pub const SERVING: u8 = 4;
    /// Held for the network without a promise: evicted first.
    pub const SPARE: u8 = 8;
}

/// Effective tier of a chunk, most protected first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Pinned = 0,
    Leased = 1,
    Cache = 2,
    Spare = 3,
}

impl Tier {
    pub fn of(flags: u8) -> Tier {
        if flags & tier::PINNED != 0 {
            Tier::Pinned
        } else if flags & tier::SERVING != 0 {
            Tier::Leased
        } else if flags & tier::SPARE != 0 && flags & tier::CACHE == 0 {
            Tier::Spare
        } else {
            Tier::Cache
        }
    }

    /// Hard tiers carry a promise and are never evicted.
    pub fn hard(self) -> bool {
        matches!(self, Tier::Pinned | Tier::Leased)
    }
}

/// Bytes stored per effective tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub pinned: u64,
    pub leased: u64,
    pub cache: u64,
    pub spare: u64,
}

impl Usage {
    pub fn hard(&self) -> u64 {
        self.pinned + self.leased
    }
    pub fn total(&self) -> u64 {
        self.pinned + self.leased + self.cache + self.spare
    }
    pub fn of(&self, t: Tier) -> u64 {
        match t {
            Tier::Pinned => self.pinned,
            Tier::Leased => self.leased,
            Tier::Cache => self.cache,
            Tier::Spare => self.spare,
        }
    }
}

/// Disk budget settings (ADR-0012). `None` means the default.
#[derive(Debug, Clone, Default)]
pub struct Budget {
    /// Hard tiers (pinned + leased) may use at most this. Default: 50 % of the volume.
    pub max_store: Option<u64>,
    /// Never take the volume's free space below this. Default: max(10 % of the volume, 5 GiB).
    pub min_free: Option<u64>,
    /// Cache tier cap. Default: 20 % of the store limit.
    pub cache_max: Option<u64>,
    /// Testing: pretend the volume had this much free space before the store
    /// (available = this − bytes stored), instead of asking the OS.
    pub simulate_free: Option<u64>,
}

/// Resolved limits and the current disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub hard_max: u64,
    pub reserve: u64,
    pub cache_max: u64,
    pub disk_total: u64,
    pub disk_available: u64,
}

impl Limits {
    /// Bytes the store may still take from the volume.
    pub fn room(&self) -> u64 {
        self.disk_available.saturating_sub(self.reserve)
    }
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Db(Box<redb::Error>),
    NotAClassSize(usize),
    /// Stored or offered bytes don't hash to the CID. Drop and refetch.
    Corrupt(Cid),
    /// The disk budget doesn't allow this write.
    Full(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Db(e) => write!(f, "index: {e}"),
            StoreError::NotAClassSize(n) => write!(f, "{n} bytes is not a chunk size class"),
            StoreError::Corrupt(c) => write!(f, "chunk {c} does not match its CID"),
            StoreError::Full(why) => write!(f, "disk budget reached: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self { StoreError::Db(Box::new(e.into())) }
        }
    )*};
}
from_redb!(redb::Error, redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub struct SlabStore {
    root: PathBuf,
    pub(crate) db: Database,
    sync: bool,
    budget: RwLock<Budget>,
    /// Recent accesses not yet written to the ACCESS table.
    touched: Mutex<HashMap<Cid, u64>>,
    /// Last volume sample: (when, total, available, store bytes at that time).
    /// Asking the OS costs ~2 ms on Windows, so it's sampled at most once per
    /// DISK_SAMPLE and adjusted by what the store wrote or freed since.
    disk: Mutex<Option<(Instant, u64, u64, u64)>>,
}

const DISK_SAMPLE: Duration = Duration::from_secs(1);

impl SlabStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("slabs"))?;
        let db = Database::create(root.join("index.redb"))?;
        let w = db.begin_write()?;
        w.open_table(INDEX)?;
        w.open_table(FREE)?;
        w.open_table(NEXT)?;
        w.open_table(SERVE)?;
        w.open_table(PUBLISHED)?;
        w.open_table(USAGE)?;
        w.open_table(ACCESS)?;
        wants::open_tables(&w)?;
        leases::open_tables(&w)?;
        placement::open_tables(&w)?;
        channels::open_tables(&w)?;
        db::open_tables(&w)?;
        namespaces::open_tables(&w)?;
        apps::open_tables(&w)?;
        w.commit()?;
        Ok(SlabStore {
            root,
            db,
            sync: true,
            budget: RwLock::new(Budget::default()),
            touched: Mutex::new(HashMap::new()),
            disk: Mutex::new(None),
        })
    }

    /// fsync each pinned slot (default on). Cache and serving tiers are never
    /// fsynced, since they can be refetched. Off only for tests and benchmarks.
    pub fn set_sync(&mut self, on: bool) {
        self.sync = on;
    }

    /// The directory the store lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn set_budget(&self, budget: Budget) {
        *self.budget.write().unwrap() = budget;
    }

    /// Stores a chunk. Returns false if it was already present (its tier
    /// flags are merged). Rejects bytes that don't match the CID, and writes
    /// the disk budget doesn't allow (after evicting what it may).
    pub fn insert(&self, cid: &Cid, ciphertext: &[u8], tier: u8) -> Result<bool, StoreError> {
        let class = class_index(ciphertext.len())?;
        if !cid.verify(ciphertext) {
            return Err(StoreError::Corrupt(*cid));
        }
        let key = cid.as_bytes().as_slice();
        let t = Tier::of(tier);

        if let Some((c, seg, slot, flags)) = self.lookup(cid)? {
            // Already stored: merge flags, moving its bytes between tiers if needed.
            if flags | tier != flags {
                let w = self.db.begin_write()?;
                {
                    w.open_table(INDEX)?.insert(key, (c, seg, slot, flags | tier))?;
                    move_usage(&w, Tier::of(flags), Tier::of(flags | tier), CLASSES[c as usize] as u64)?;
                }
                w.commit()?;
            }
            if !Tier::of(flags | tier).hard() {
                self.touch(cid);
            }
            return Ok(false);
        }

        self.admit(t, class, ciphertext.len() as u64)?;

        // Only pinned data (own writes) must survive a crash; cached and served
        // chunks can be fetched again, so they skip fsync of both slot and index.
        let durable = self.sync && tier & tier::PINNED != 0;
        let mut w = self.db.begin_write()?;
        if !durable {
            w.set_durability(redb::Durability::None);
        }
        {
            let (seg, slot) = allocate(&w, class)?;
            self.write_slot(class, seg, slot, ciphertext, durable)?;
            w.open_table(INDEX)?.insert(key, (class, seg, slot, tier))?;
            add_usage(&w, t, ciphertext.len() as i64)?;
        }
        w.commit()?;
        if !t.hard() {
            self.touch(cid);
        }
        Ok(true)
    }

    /// Reads and verifies a chunk. `Err(Corrupt)` means the stored copy is bad.
    pub fn fetch(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        let Some((class, seg, slot, flags)) = self.lookup(cid)? else {
            return Ok(None);
        };
        let size = CLASSES[class as usize];
        let mut f = File::open(self.segment_path(class, seg))?;
        f.seek(SeekFrom::Start(slot as u64 * size as u64))?;
        let mut buf = vec![0u8; size];
        f.read_exact(&mut buf)?;
        if !cid.verify(&buf) {
            return Err(StoreError::Corrupt(*cid));
        }
        if !Tier::of(flags).hard() {
            self.touch(cid);
        }
        Ok(Some(buf))
    }

    /// Removes a chunk, frees its slot for reuse and returns its disk space to the OS.
    pub fn remove(&self, cid: &Cid) -> Result<bool, StoreError> {
        let removed = self.remove_many(&[*cid])?;
        Ok(removed > 0)
    }

    pub fn tier(&self, cid: &Cid) -> Result<Option<u8>, StoreError> {
        Ok(self.lookup(cid)?.map(|v| v.3))
    }

    /// Replaces a chunk's tier flags. Moving between tiers copies no bytes.
    pub fn set_tier(&self, cid: &Cid, tier: u8) -> Result<bool, StoreError> {
        let w = self.db.begin_write()?;
        let found = {
            let mut index = w.open_table(INDEX)?;
            let key = cid.as_bytes().as_slice();
            let old = index.get(key)?.map(|g| g.value());
            if let Some((c, seg, slot, flags)) = old {
                index.insert(key, (c, seg, slot, tier))?;
                drop(index);
                move_usage(&w, Tier::of(flags), Tier::of(tier), CLASSES[c as usize] as u64)?;
            }
            old.is_some()
        };
        w.commit()?;
        Ok(found)
    }

    /// Bytes stored per effective tier.
    pub fn usage(&self) -> Result<Usage, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(USAGE)?;
        let get = |k: Tier| -> Result<u64, StoreError> { Ok(t.get(k as u8)?.map(|g| g.value()).unwrap_or(0)) };
        Ok(Usage { pinned: get(Tier::Pinned)?, leased: get(Tier::Leased)?, cache: get(Tier::Cache)?, spare: get(Tier::Spare)? })
    }

    /// The budget resolved against the volume the store lives on.
    pub fn limits(&self) -> Result<Limits, StoreError> {
        let usage = self.usage()?;
        self.limits_for(&usage)
    }

    fn limits_for(&self, usage: &Usage) -> Result<Limits, StoreError> {
        let b = self.budget.read().unwrap().clone();
        let (total, available) = match b.simulate_free {
            Some(free) => (free.max(1), free.saturating_sub(usage.total())),
            None => self.disk_sample(usage.total())?,
        };
        let hard_max = b.max_store.unwrap_or(total / 2);
        Ok(Limits {
            hard_max,
            reserve: b.min_free.unwrap_or((total / 10).max(5 * GIB)),
            cache_max: b.cache_max.unwrap_or(hard_max / 5),
            disk_total: total,
            disk_available: available,
        })
    }

    /// Volume (total, available), sampled at most once per DISK_SAMPLE and
    /// adjusted by the store's own growth or shrinkage since the sample.
    fn disk_sample(&self, store_bytes: u64) -> Result<(u64, u64), StoreError> {
        let mut disk = self.disk.lock().unwrap();
        match *disk {
            Some((at, total, avail, at_bytes)) if at.elapsed() < DISK_SAMPLE => {
                let avail = if store_bytes >= at_bytes {
                    avail.saturating_sub(store_bytes - at_bytes)
                } else {
                    avail + (at_bytes - store_bytes)
                };
                Ok((total, avail))
            }
            _ => {
                let (total, avail) = (fs4::total_space(&self.root)?, fs4::available_space(&self.root)?);
                *disk = Some((Instant::now(), total, avail, store_bytes));
                Ok((total, avail))
            }
        }
    }

    /// Brings the store back within budget: trims the cache to its cap and, if
    /// other programs took the volume below the reserve, evicts spare and then
    /// cache. Never touches hard tiers. Returns the bytes freed.
    pub fn enforce(&self) -> Result<u64, StoreError> {
        self.flush_access()?;
        let usage = self.usage()?;
        let lim = self.limits_for(&usage)?;
        let mut freed = 0;
        if usage.cache > lim.cache_max {
            freed += self.evict(&[Tier::Cache], usage.cache - lim.cache_max, None)?;
        }
        let lim = self.limits()?;
        if lim.disk_available < lim.reserve {
            freed += self.evict(&[Tier::Spare, Tier::Cache], lim.reserve - lim.disk_available, None)?;
        }
        Ok(freed)
    }

    /// Writes recent accesses to the index (non-durable: losing them only
    /// makes LRU slightly less accurate).
    pub fn flush_access(&self) -> Result<(), StoreError> {
        let touched = std::mem::take(&mut *self.touched.lock().unwrap());
        if touched.is_empty() {
            return Ok(());
        }
        let mut w = self.db.begin_write()?;
        w.set_durability(redb::Durability::None);
        {
            let index = w.open_table(INDEX)?;
            let mut access = w.open_table(ACCESS)?;
            for (cid, at) in touched {
                if index.get(cid.as_bytes().as_slice())?.is_some() {
                    access.insert(cid.as_bytes().as_slice(), at)?;
                }
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Serves these chunks to anyone proving their seed (own writes).
    pub fn register_serving(&self, chunks: &[(Cid, ChunkToken)]) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut serve = w.open_table(SERVE)?;
            for (cid, token) in chunks {
                serve.insert(cid.as_bytes().as_slice(), token.0.as_slice())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Serves `cids` to anyone, without proof (deliberate publishing, like a micron page).
    pub fn publish(&self, cids: &[Cid]) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        {
            let mut published = w.open_table(PUBLISHED)?;
            for cid in cids {
                published.insert(cid.as_bytes().as_slice(), ())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// The access token under which `cid` is served, if it is.
    pub fn serving_token(&self, cid: &Cid) -> Result<Option<ChunkToken>, StoreError> {
        let r = self.db.begin_read()?;
        let serve = r.open_table(SERVE)?;
        Ok(serve.get(cid.as_bytes().as_slice())?.and_then(|g| g.value().try_into().ok()).map(ChunkToken))
    }

    /// For each CID: its access token (if served) and whether it's published,
    /// in one read transaction (the serving hot path).
    pub fn serving_info(&self, cids: &[Cid]) -> Result<Vec<(Option<ChunkToken>, bool)>, StoreError> {
        let r = self.db.begin_read()?;
        let serve = r.open_table(SERVE)?;
        let published = r.open_table(PUBLISHED)?;
        cids.iter()
            .map(|c| {
                let key = c.as_bytes().as_slice();
                let token = serve.get(key)?.and_then(|g| g.value().try_into().ok()).map(ChunkToken);
                Ok((token, published.get(key)?.is_some()))
            })
            .collect()
    }

    pub fn is_published(&self, cid: &Cid) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(PUBLISHED)?.get(cid.as_bytes().as_slice())?.is_some())
    }

    pub fn len(&self) -> Result<u64, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(INDEX)?.len()?)
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    // ---------------------------------------------------------------- budget

    /// Makes room for a new chunk of `bytes` in tier `t`, evicting what the
    /// tier may displace; fails if the budget still doesn't allow it.
    fn admit(&self, t: Tier, class: u8, bytes: u64) -> Result<(), StoreError> {
        let usage = self.usage()?;
        let lim = self.limits_for(&usage)?;
        if t.hard() && usage.hard() + bytes > lim.hard_max {
            return Err(StoreError::Full("store limit for own and promised data"));
        }
        if t == Tier::Cache && usage.cache + bytes > lim.cache_max {
            self.flush_access()?;
            self.evict(&[Tier::Cache], usage.cache + bytes - lim.cache_max, Some(class))?;
        }
        if self.has_free_slot(class)? {
            return Ok(()); // reuses a freed slot of this class: no new disk needed
        }
        let room = self.limits()?.room();
        if room >= bytes {
            return Ok(());
        }
        // Spare yields to everything; cache and hard tiers may displace spare, then cache.
        let order: &[Tier] = if t == Tier::Spare { &[Tier::Spare] } else { &[Tier::Spare, Tier::Cache] };
        self.flush_access()?;
        self.evict(order, bytes - room, Some(class))?;
        if self.has_free_slot(class)? || self.limits()?.room() >= bytes {
            Ok(())
        } else {
            Err(StoreError::Full("free-space reserve reached and nothing evictable left"))
        }
    }

    /// Evicts chunks of the given tiers (in that order; within a tier, chunks
    /// of `prefer_class` first, then least recently used) until `bytes` are
    /// freed. Returns the bytes freed.
    fn evict(&self, order: &[Tier], bytes: u64, prefer_class: Option<u8>) -> Result<u64, StoreError> {
        let mut candidates = Vec::new();
        {
            let r = self.db.begin_read()?;
            let index = r.open_table(INDEX)?;
            let access = r.open_table(ACCESS)?;
            for entry in index.iter()? {
                let (k, v) = entry?;
                let (class, _, _, flags) = v.value();
                let Some(rank) = order.iter().position(|&o| o == Tier::of(flags)) else { continue };
                let cid = Cid::from_bytes(k.value().try_into().expect("index keys are CIDs")).expect("CID version");
                let at = access.get(k.value())?.map(|g| g.value()).unwrap_or(0);
                candidates.push((rank, prefer_class.is_some_and(|p| p != class), at, cid, CLASSES[class as usize] as u64));
            }
        }
        candidates.sort_by_key(|c| (c.0, c.1, c.2));
        let mut victims = Vec::new();
        let mut freed = 0;
        for (_, _, _, cid, size) in candidates {
            if freed >= bytes {
                break;
            }
            victims.push(cid);
            freed += size;
        }
        self.remove_many(&victims)?;
        Ok(freed)
    }

    fn remove_many(&self, cids: &[Cid]) -> Result<u64, StoreError> {
        if cids.is_empty() {
            return Ok(0);
        }
        let mut holes = Vec::new();
        let w = self.db.begin_write()?;
        {
            let mut index = w.open_table(INDEX)?;
            let mut free = w.open_table(FREE)?;
            let mut access = w.open_table(ACCESS)?;
            for cid in cids {
                let key = cid.as_bytes().as_slice();
                if let Some((class, seg, slot, flags)) = index.remove(key)?.map(|g| g.value()) {
                    free.insert((class, seg, slot), ())?;
                    access.remove(key)?;
                    holes.push((class, seg, slot, Tier::of(flags)));
                }
            }
        }
        for &(class, _, _, t) in &holes {
            add_usage(&w, t, -(CLASSES[class as usize] as i64))?;
        }
        w.commit()?;
        let mut touched = self.touched.lock().unwrap();
        for cid in cids {
            touched.remove(cid);
        }
        drop(touched);
        for (class, seg, slot, _) in &holes {
            let size = CLASSES[*class as usize] as u64;
            // Best effort: a failed punch only means the OS keeps the bytes until reuse.
            let _ = punch_hole(&self.segment_path(*class, *seg), *slot as u64 * size, size);
        }
        Ok(holes.len() as u64)
    }

    fn has_free_slot(&self, class: u8) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        let free = r.open_table(FREE)?;
        Ok(free.range((class, 0u32, 0u32)..=(class, u32::MAX, u32::MAX))?.next().is_some())
    }

    fn touch(&self, cid: &Cid) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        self.touched.lock().unwrap().insert(*cid, now);
    }

    fn lookup(&self, cid: &Cid) -> Result<Option<(u8, u32, u32, u8)>, StoreError> {
        let r = self.db.begin_read()?;
        let index = r.open_table(INDEX)?;
        Ok(index.get(cid.as_bytes().as_slice())?.map(|g| g.value()))
    }

    fn segment_path(&self, class: u8, seg: u32) -> PathBuf {
        self.root
            .join("slabs")
            .join(format!("c{}k", CLASSES[class as usize] / 1024))
            .join(format!("seg-{seg:06}"))
    }

    fn write_slot(&self, class: u8, seg: u32, slot: u32, bytes: &[u8], durable: bool) -> Result<(), StoreError> {
        let path = self.segment_path(class, seg);
        fs::create_dir_all(path.parent().expect("segment has a parent dir"))?;
        let mut f = OpenOptions::new().create(true).truncate(false).write(true).open(path)?;
        f.seek(SeekFrom::Start(slot as u64 * bytes.len() as u64))?;
        f.write_all(bytes)?;
        if durable {
            f.sync_data()?;
        }
        Ok(())
    }
}

impl Store for SlabStore {
    type Error = StoreError;

    /// Own writes land in the pinned tier (ADR-0005).
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), StoreError> {
        self.insert(&cid, &ciphertext, tier::PINNED).map(|_| ())
    }

    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.fetch(cid)
    }
}

fn add_usage(w: &redb::WriteTransaction, t: Tier, delta: i64) -> Result<(), StoreError> {
    let mut usage = w.open_table(USAGE)?;
    let cur = usage.get(t as u8)?.map(|g| g.value()).unwrap_or(0);
    usage.insert(t as u8, cur.saturating_add_signed(delta))?;
    Ok(())
}

fn move_usage(w: &redb::WriteTransaction, from: Tier, to: Tier, bytes: u64) -> Result<(), StoreError> {
    if from != to {
        add_usage(w, from, -(bytes as i64))?;
        add_usage(w, to, bytes as i64)?;
    }
    Ok(())
}

fn class_index(len: usize) -> Result<u8, StoreError> {
    CLASSES.iter().position(|&c| c == len).map(|i| i as u8).ok_or(StoreError::NotAClassSize(len))
}

/// Takes a free slot of this class, or the next never-used one.
fn allocate(w: &redb::WriteTransaction, class: u8) -> Result<(u32, u32), StoreError> {
    let mut free = w.open_table(FREE)?;
    let reusable = free
        .range((class, 0u32, 0u32)..=(class, u32::MAX, u32::MAX))?
        .next()
        .transpose()?
        .map(|(k, _)| k.value());
    if let Some(k) = reusable {
        free.remove(k)?;
        return Ok((k.1, k.2));
    }
    let mut next = w.open_table(NEXT)?;
    let n = next.get(class)?.map(|g| g.value()).unwrap_or(0);
    next.insert(class, n + 1)?;
    Ok(((n / SLOTS_PER_SEGMENT) as u32, (n % SLOTS_PER_SEGMENT) as u32))
}

/// Returns a freed slot's disk space to the OS without changing the file size.
#[cfg(target_os = "linux")]
fn punch_hole(path: &Path, offset: u64, len: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let f = OpenOptions::new().write(true).open(path)?;
    let r = unsafe {
        libc::fallocate(f.as_raw_fd(), libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, offset as i64, len as i64)
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Returns a freed slot's disk space to the OS: marks the segment sparse and
/// zeroes the range, which deallocates it (FSCTL_SET_ZERO_DATA).
#[cfg(windows)]
fn punch_hole(path: &Path, offset: u64, len: u64) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::{
        Ioctl::{FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA},
        IO::DeviceIoControl,
    };
    let f = OpenOptions::new().write(true).open(path)?;
    let h = f.as_raw_handle() as _;
    let mut returned = 0u32;
    let zero = FILE_ZERO_DATA_INFORMATION { FileOffset: offset as i64, BeyondFinalZero: (offset + len) as i64 };
    unsafe {
        if DeviceIoControl(h, FSCTL_SET_SPARSE, std::ptr::null(), 0, std::ptr::null_mut(), 0, &mut returned, std::ptr::null_mut()) == 0 {
            return Err(io::Error::last_os_error());
        }
        if DeviceIoControl(
            h,
            FSCTL_SET_ZERO_DATA,
            &zero as *const _ as *const _,
            std::mem::size_of::<FILE_ZERO_DATA_INFORMATION>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn punch_hole(_path: &Path, _offset: u64, _len: u64) -> io::Result<()> {
    Ok(()) // the slot is still reused; the OS keeps the bytes until then
}

/// A view of the store whose writes land in the pinned tier: own writes (ADR-0005).
pub struct PinnedTier<'a>(pub &'a SlabStore);

impl Store for PinnedTier<'_> {
    type Error = StoreError;

    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), StoreError> {
        self.0.insert(&cid, &ciphertext, tier::PINNED).map(|_| ())
    }

    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.fetch(cid)
    }
}

/// A view of the store whose writes land in the cache tier (evictable),
/// for chunks fetched from the network rather than written locally.
pub struct CacheTier<'a>(pub &'a SlabStore);

impl Store for CacheTier<'_> {
    type Error = StoreError;

    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), StoreError> {
        match self.0.insert(&cid, &ciphertext, tier::CACHE) {
            // A cache that can't grow is not an error for the reader: the data
            // was fetched and verified, it just isn't kept.
            Err(StoreError::Full(_)) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.fetch(cid)
    }
}

/// Pinned writes that remember which chunks they newly added, so a write
/// that fails half-way (e.g. on the disk budget) can be rolled back without
/// touching chunks that were already there (dedup).
pub struct TrackedPinned<'a> {
    pub store: &'a SlabStore,
    pub added: Vec<Cid>,
}

impl<'a> TrackedPinned<'a> {
    pub fn new(store: &'a SlabStore) -> Self {
        TrackedPinned { store, added: Vec::new() }
    }

    /// Removes every chunk this writer added.
    pub fn roll_back(self) -> Result<(), StoreError> {
        for cid in &self.added {
            self.store.remove(cid)?;
        }
        Ok(())
    }
}

impl Store for TrackedPinned<'_> {
    type Error = StoreError;

    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), StoreError> {
        if self.store.insert(&cid, &ciphertext, tier::PINNED)? {
            self.added.push(cid);
        }
        Ok(())
    }

    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.fetch(cid)
    }
}
